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

/* ---------- result cache ------------------------------------------------
 * Keyed by IP string.  Entries survive RDNS_CACHE_TTL seconds; excess
 * entries are evicted LRU-style.  A hostname of "" means "use the raw IP".
 * The cache is written on EVERY exit path (success, failure, timeout) so
 * that a second connection from the same IP is never blocked waiting for
 * DNS. */

#define RDNS_CACHE_TTL  300
#define RDNS_CACHE_MAX  4096

struct rdns_cache_entry
{
	char ip[HOSTIPLEN + 1];		/* dictionary key — stable pointer */
	char hostname[HOSTLEN + 1];	/* "" → use IP */
	time_t expires;
	rb_dlink_node node;
};

static rb_dictionary *rdns_cache;
static rb_dlink_list  rdns_cache_list;

struct user_query
{
	struct dns_query *query;
};

static int rdns_timeout = RDNS_TIMEOUT_DEFAULT;
static bool rdns_enabled = true;

/* ---------- cache -------------------------------------------------------- */

static struct rdns_cache_entry *
rdns_cache_get(const char *ip)
{
	struct rdns_cache_entry *e = rb_dictionary_retrieve(rdns_cache, ip);

	if(e == NULL)
		return NULL;

	if(e->expires < rb_current_time())
	{
		rb_dlinkDelete(&e->node, &rdns_cache_list);
		rb_dictionary_delete(rdns_cache, e->ip);
		rb_free(e);
		return NULL;
	}

	return e;
}

/* Write (or update) a cache entry.  hostname=NULL → negative (use IP). */
static void
rdns_cache_put(const char *ip, const char *hostname)
{
	struct rdns_cache_entry *e;

	e = rb_dictionary_retrieve(rdns_cache, ip);
	if(e != NULL)
	{
		rb_dlinkDelete(&e->node, &rdns_cache_list);
		rb_dictionary_delete(rdns_cache, e->ip);
		rb_free(e);
	}
	else if(rb_dlink_list_length(&rdns_cache_list) >= RDNS_CACHE_MAX)
	{
		struct rdns_cache_entry *oldest = rdns_cache_list.head->data;
		rb_dlinkDelete(&oldest->node, &rdns_cache_list);
		rb_dictionary_delete(rdns_cache, oldest->ip);
		rb_free(oldest);
	}

	e = rb_malloc(sizeof(*e));
	rb_strlcpy(e->ip, ip, sizeof(e->ip));
	rb_strlcpy(e->hostname, hostname != NULL ? hostname : "", sizeof(e->hostname));
	e->expires = rb_current_time() + RDNS_CACHE_TTL;

	rb_dictionary_add(rdns_cache, e->ip, e);
	rb_dlinkAddTail(e, &e->node, &rdns_cache_list);
}

/* ---------- resolution finish ------------------------------------------- */

/* Finish with a known good hostname (may be cached or freshly resolved). */
static void
rdns_finish_host(struct auth_client *auth, const char *hostname)
{
	rb_strlcpy(auth->hostname, hostname, sizeof(auth->hostname));
	notice_client(auth->cid, "*** Found your hostname: %s", hostname);
}

/* Complete the provider, optionally freeing a pending query. */
static void
rdns_finish(struct auth_client *auth, struct user_query *query)
{
	if(query != NULL)
	{
		cancel_query(query->query);
		rb_free(query);
		set_provider_data(auth, SELF_PID, NULL);
		set_provider_timeout_absolute(auth, SELF_PID, 0);
		auth_client_unref(auth);	/* paired with ref in rdns_start */
	}

	provider_done(auth, SELF_PID);
}

/* DNS answer callback — called by the resolver for both hits and misses. */
static void
dns_answer_callback(const char *res, bool status __unused, query_type type __unused, void *data)
{
	struct auth_client *auth = data;
	struct user_query *query = get_provider_data(auth, SELF_PID);

	if(res != NULL && *res != '\0' && strlen(res) <= HOSTLEN)
	{
		/* Success: cache and apply the hostname. */
		rdns_cache_put(auth->c_ip, res);
		rdns_finish_host(auth, res);
	}
	else
	{
		/* Failure / fcrdns mismatch / name too long: cache negative,
		 * hostname stays as the raw IP (set in rdns_start). */
		rdns_cache_put(auth->c_ip, NULL);
	}

	rdns_finish(auth, query);
}

/* Timeout or cancel: cache a negative entry so the next connection from
 * this IP skips the wait entirely. */
static void
rdns_cancel(struct auth_client *auth)
{
	struct user_query *query = get_provider_data(auth, SELF_PID);

	if(query == NULL)
		return;

	rdns_cache_put(auth->c_ip, NULL);
	rdns_finish(auth, query);
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
	rb_dlink_node *ptr, *nptr;

	RB_DICTIONARY_FOREACH(auth, &iter, auth_clients)
	{
		rdns_cancel(auth);
	}

	RB_DLINK_FOREACH_SAFE(ptr, nptr, rdns_cache_list.head)
	{
		struct rdns_cache_entry *e = ptr->data;
		rb_dlinkDelete(ptr, &rdns_cache_list);
		rb_free(e);
	}

	rb_dictionary_destroy(rdns_cache, NULL, NULL);
	rdns_cache = NULL;
}

static bool
rdns_start(struct auth_client *auth)
{
	/* Default hostname to the client IP; a successful lookup overrides it. */
	rb_strlcpy(auth->hostname, auth->c_ip, sizeof(auth->hostname));

	if(!rdns_enabled)
	{
		provider_done(auth, SELF_PID);
		return true;
	}

	/* Fast path: serve from cache (hits and negative entries alike). */
	const struct rdns_cache_entry *cached = rdns_cache_get(auth->c_ip);
	if(cached != NULL)
	{
		if(cached->hostname[0] != '\0')
			rdns_finish_host(auth, cached->hostname);
		provider_done(auth, SELF_PID);
		return true;
	}

	/* Slow path: issue the DNS lookup. */
	struct user_query *query = rb_malloc(sizeof(*query));
	auth_client_ref(auth);
	set_provider_data(auth, SELF_PID, query);
	set_provider_timeout_relative(auth, SELF_PID, rdns_timeout);
	query->query = lookup_hostname(auth->c_ip, dns_answer_callback, auth);
	return true;
}

/* ---------- config handlers --------------------------------------------- */

static void
add_conf_dns_timeout(const char *key __unused, int parc __unused, const char **parv)
{
	int t = atoi(parv[0]);

	if(t < 0)
	{
		warn_opers(L_CRIT, "rDNS: DNS timeout < 0 (value: %d)", t);
		exit(EX_PROVIDER_ERROR);
	}

	rdns_timeout = t;
}

static void
set_rdns_enabled(const char *key __unused, int parc __unused, const char **parv)
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
	.name    = "rdns",
	.letter  = 'R',
	.init    = rdns_init,
	.destroy = rdns_destroy,
	.start   = rdns_start,
	.cancel  = rdns_cancel,
	.timeout = rdns_cancel,
	.opt_handlers = rdns_options,
};
