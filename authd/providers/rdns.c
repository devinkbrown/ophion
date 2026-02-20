/* authd/providers/rdns.c - rDNS lookup provider for authd
 * Copyright (c) 2016 Elizabeth Myers <elizabeth@interlinked.me>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice is present in all copies.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "stdinc.h"
#include "rb_commio.h"
#include "authd.h"
#include "provider.h"
#include "notice.h"
#include "res.h"
#include "dns.h"

#define SELF_PID (rdns_provider.id)

/* rDNS result cache: maps IP → hostname (or "" when no hostname resolves).
 * Entries are reused until they expire, avoiding repeated DNS RTTs for
 * clients from the same address (NAT, reconnects, stress loads). */
#define RDNS_CACHE_TTL  300	/* seconds before a cache entry expires */
#define RDNS_CACHE_MAX  4096	/* max entries; evict oldest beyond this */

struct rdns_cache_entry
{
	char ip[HOSTIPLEN + 1];		/* key — owned by entry for stable pointer */
	char hostname[HOSTLEN + 1];	/* resolved hostname, or "" to use IP */
	time_t expires;
	rb_dlink_node node;		/* insertion-order list for LRU eviction */
};

static rb_dictionary *rdns_cache;
static rb_dlink_list  rdns_cache_list;

struct user_query
{
	struct dns_query *query;
};

static void client_fail(struct auth_client *auth);
static void client_success(struct auth_client *auth);
static void dns_answer_callback(const char *res, bool status, query_type type, void *data);

static int rdns_timeout = RDNS_TIMEOUT_DEFAULT;
static bool rdns_enabled = true;

/* ---------- cache helpers ------------------------------------------------ */

static struct rdns_cache_entry *
rdns_cache_get(const char *ip)
{
	struct rdns_cache_entry *entry = rb_dictionary_retrieve(rdns_cache, ip);

	if(entry == NULL)
		return NULL;

	if(entry->expires < rb_current_time())
	{
		rb_dlinkDelete(&entry->node, &rdns_cache_list);
		rb_dictionary_delete(rdns_cache, entry->ip);
		rb_free(entry);
		return NULL;
	}

	return entry;
}

static void
rdns_cache_put(const char *ip, const char *hostname)
{
	struct rdns_cache_entry *entry;

	/* Replace existing entry if present */
	entry = rb_dictionary_retrieve(rdns_cache, ip);
	if(entry != NULL)
	{
		rb_dlinkDelete(&entry->node, &rdns_cache_list);
		rb_dictionary_delete(rdns_cache, entry->ip);
		rb_free(entry);
	}
	else if(rb_dlink_list_length(&rdns_cache_list) >= RDNS_CACHE_MAX)
	{
		/* Evict oldest entry to stay within the cap */
		struct rdns_cache_entry *oldest = rdns_cache_list.head->data;
		rb_dlinkDelete(&oldest->node, &rdns_cache_list);
		rb_dictionary_delete(rdns_cache, oldest->ip);
		rb_free(oldest);
	}

	entry = rb_malloc(sizeof(struct rdns_cache_entry));
	rb_strlcpy(entry->ip, ip, sizeof(entry->ip));
	rb_strlcpy(entry->hostname, hostname != NULL ? hostname : "", sizeof(entry->hostname));
	entry->expires = rb_current_time() + RDNS_CACHE_TTL;

	/* Use entry->ip as the dictionary key — stable for the entry's lifetime */
	rb_dictionary_add(rdns_cache, entry->ip, entry);
	rb_dlinkAddTail(entry, &entry->node, &rdns_cache_list);
}

static void
rdns_cache_apply(struct auth_client *auth, const struct rdns_cache_entry *entry)
{
	if(entry->hostname[0] != '\0')
	{
		rb_strlcpy(auth->hostname, entry->hostname, sizeof(auth->hostname));
		notice_client(auth->cid, "*** Found your hostname: %s", auth->hostname);
	}
	/* else: auth->hostname already holds the client IP */
	provider_done(auth, SELF_PID);
}

/* ---------- DNS callback and client state -------------------------------- */

static void
dns_answer_callback(const char *res, bool status, query_type type, void *data)
{
	struct auth_client *auth = data;

	if(res != NULL && strlen(res) <= HOSTLEN)
	{
		rdns_cache_put(auth->c_ip, res);
		rb_strlcpy(auth->hostname, res, HOSTLEN + 1);
		client_success(auth);
	}
	else
	{
		/* DNS failure, timeout, hostname too long, or fcrdns mismatch —
		 * cache the negative so future clients from this IP skip the wait. */
		rdns_cache_put(auth->c_ip, NULL);
		client_fail(auth);
	}
}

static void
client_fail(struct auth_client *auth)
{
	struct user_query *query = get_provider_data(auth, SELF_PID);

	lrb_assert(query != NULL);

	cancel_query(query->query);
	rb_free(query);

	set_provider_data(auth, SELF_PID, NULL);
	set_provider_timeout_absolute(auth, SELF_PID, 0);
	provider_done(auth, SELF_PID);

	auth_client_unref(auth);
}

static void
client_success(struct auth_client *auth)
{
	struct user_query *query = get_provider_data(auth, SELF_PID);

	lrb_assert(query != NULL);

	notice_client(auth->cid, "*** Found your hostname: %s", auth->hostname);
	cancel_query(query->query);
	rb_free(query);

	set_provider_data(auth, SELF_PID, NULL);
	set_provider_timeout_absolute(auth, SELF_PID, 0);
	provider_done(auth, SELF_PID);

	auth_client_unref(auth);
}

/* ---------- provider lifecycle ------------------------------------------ */

static bool
rdns_init(void)
{
	rdns_cache = rb_dictionary_create("rdns cache", strcasecmp);
	return true;
}

static void
rdns_destroy(void)
{
	struct auth_client *auth;
	rb_dictionary_iter iter;

	RB_DICTIONARY_FOREACH(auth, &iter, auth_clients)
	{
		if(get_provider_data(auth, SELF_PID) != NULL)
			client_fail(auth);
	}

	rb_dlink_node *ptr, *nptr;
	RB_DLINK_FOREACH_SAFE(ptr, nptr, rdns_cache_list.head)
	{
		struct rdns_cache_entry *entry = ptr->data;
		rb_dlinkDelete(ptr, &rdns_cache_list);
		rb_free(entry);
	}
	rb_dictionary_destroy(rdns_cache, NULL, NULL);
	rdns_cache = NULL;
}

static bool
rdns_start(struct auth_client *auth)
{
	/* Default hostname to the client IP; success overrides it. */
	rb_strlcpy(auth->hostname, auth->c_ip, sizeof(auth->hostname));

	if(!rdns_enabled)
	{
		provider_done(auth, SELF_PID);
		return true;
	}

	const struct rdns_cache_entry *cached = rdns_cache_get(auth->c_ip);
	if(cached != NULL)
	{
		rdns_cache_apply(auth, cached);
		return true;
	}

	struct user_query *query = rb_malloc(sizeof(struct user_query));

	auth_client_ref(auth);
	set_provider_data(auth, SELF_PID, query);
	set_provider_timeout_relative(auth, SELF_PID, rdns_timeout);

	query->query = lookup_hostname(auth->c_ip, dns_answer_callback, auth);

	return true;
}

static void
rdns_cancel(struct auth_client *auth)
{
	if(get_provider_data(auth, SELF_PID) != NULL)
		client_fail(auth);
}

/* ---------- config handlers --------------------------------------------- */

static void
add_conf_dns_timeout(const char *key, int parc, const char **parv)
{
	int timeout = atoi(parv[0]);

	if(timeout < 0)
	{
		warn_opers(L_CRIT, "rDNS: DNS timeout < 0 (value: %d)", timeout);
		exit(EX_PROVIDER_ERROR);
	}

	rdns_timeout = timeout;
}

static void
set_rdns_enabled(const char *key, int parc, const char **parv)
{
	rdns_enabled = atoi(parv[0]) != 0;
}

struct auth_opts_handler rdns_options[] =
{
	{ "rdns_timeout", 1, add_conf_dns_timeout },
	{ "rdns_enabled", 1, set_rdns_enabled },
	{ NULL, 0, NULL },
};

struct auth_provider rdns_provider =
{
	.name = "rdns",
	.letter = 'R',
	.init = rdns_init,
	.destroy = rdns_destroy,
	.start = rdns_start,
	.cancel = rdns_cancel,
	.timeout = rdns_cancel,
	.opt_handlers = rdns_options,
};
