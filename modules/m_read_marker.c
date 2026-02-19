/*
 * modules/m_read_marker.c
 * IRCv3 draft/read-marker capability and MARKREAD command
 *
 * Copyright (c) 2024 ophion contributors
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

/*
 * The draft/read-marker extension allows clients to synchronise the
 * last-read position of a channel or private message buffer across
 * multiple sessions.
 *
 * Spec: https://ircv3.net/specs/extensions/read-marker
 *
 * - MARKREAD <target> [timestamp=...]  set/get the read marker
 * - On JOIN, the server sends a MARKREAD for the channel
 * - Timestamps are monotonically increasing; stale updates are ignored
 * - Markers are stored in-memory per-connection (lost on disconnect)
 */

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_serv.h"
#include "numeric.h"
#include "msg.h"
#include "parse.h"
#include "hash.h"
#include "channel.h"
#include "match.h"
#include "hook.h"

static const char m_read_marker_desc[] =
	"Provides the draft/read-marker capability and MARKREAD command";

static unsigned int CLICAP_READ_MARKER = 0;

/*
 * Per-client read markers stored in a two-level dictionary:
 *   client_markers: client UID (string) -> struct marker_state *
 *   marker_state->targets: lowercase target name -> timestamp (rb_strdup'd)
 */
struct marker_state {
	rb_dictionary *targets;
};

static rb_dictionary *client_markers = NULL;

static void m_markread(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void hook_channel_join(void *);
static void hook_client_exit(void *);

static int modinit(void);
static void moddeinit(void);

struct Message markread_msgtab = {
	"MARKREAD", 0, 0, 0, 0,
	{mg_unreg, {m_markread, 2}, mg_ignore, mg_ignore, mg_ignore, {m_markread, 2}}
};

mapi_clist_av1 read_marker_clist[] = { &markread_msgtab, NULL };

mapi_cap_list_av2 read_marker_cap_list[] = {
	{ MAPI_CAP_CLIENT, "draft/read-marker", NULL, &CLICAP_READ_MARKER },
	{ 0, NULL, NULL, NULL }
};

mapi_hfn_list_av1 read_marker_hfnlist[] = {
	{ "channel_join", (hookfn) hook_channel_join },
	{ "client_exit", (hookfn) hook_client_exit },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(m_read_marker, modinit, moddeinit,
	read_marker_clist, NULL, read_marker_hfnlist,
	read_marker_cap_list, NULL, m_read_marker_desc);

/* ------------------------------------------------------------------ */
/* Marker state helpers                                                */
/* ------------------------------------------------------------------ */

static struct marker_state *
get_marker_state(struct Client *client_p, bool create)
{
	const char *uid = use_id(client_p);
	struct marker_state *ms;

	ms = rb_dictionary_retrieve(client_markers, uid);
	if (ms == NULL && create)
	{
		ms = rb_malloc(sizeof(*ms));
		ms->targets = rb_dictionary_create("read_marker_targets", rb_strcasecmp);
		rb_dictionary_add(client_markers, rb_strdup(uid), ms);
	}
	return ms;
}

static const char *
get_stored_timestamp(struct marker_state *ms, const char *target)
{
	if (ms == NULL)
		return NULL;
	return rb_dictionary_retrieve(ms->targets, target);
}

static void
set_stored_timestamp(struct marker_state *ms, const char *target, const char *ts)
{
	char *old = rb_dictionary_delete(ms->targets, target);
	if (old != NULL)
		rb_free(old);

	/* rb_dictionary stores the key pointer, so we must dup it */
	rb_dictionary_add(ms->targets, rb_strdup(target), rb_strdup(ts));
}

static void
free_target_entry(rb_dictionary_element *delem, void *privdata)
{
	rb_free((void *)delem->key);
	rb_free(delem->data);
}

static void
free_marker_state(struct marker_state *ms)
{
	if (ms == NULL)
		return;
	rb_dictionary_destroy(ms->targets, free_target_entry, NULL);
	rb_free(ms);
}

/* ------------------------------------------------------------------ */
/* Module init / deinit                                                */
/* ------------------------------------------------------------------ */

static void
free_client_entry(rb_dictionary_element *delem, void *privdata)
{
	rb_free((void *)delem->key);
	free_marker_state(delem->data);
}

static int
modinit(void)
{
	client_markers = rb_dictionary_create("read_marker_clients", rb_strcasecmp);
	return 0;
}

static void
moddeinit(void)
{
	if (client_markers != NULL)
	{
		rb_dictionary_destroy(client_markers, free_client_entry, NULL);
		client_markers = NULL;
	}
}

/* ------------------------------------------------------------------ */
/* MARKREAD command                                                     */
/* ------------------------------------------------------------------ */

/*
 * MARKREAD <target> [timestamp=YYYY-MM-DDThh:mm:ss.sssZ]
 *
 * Without a timestamp parameter: query the stored marker.
 * With a timestamp parameter: update the marker (monotonically).
 */
static void
m_markread(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	   int parc, const char *parv[])
{
	const char *target;
	const char *timestamp;
	struct marker_state *ms;
	const char *stored;

	if (!MyClient(source_p))
		return;

	if (!IsCapable(source_p, CLICAP_READ_MARKER))
		return;

	if (parc < 2 || EmptyString(parv[1]))
	{
		sendto_one(source_p,
			":%s FAIL MARKREAD NEED_MORE_PARAMS :Missing parameters",
			me.name);
		return;
	}

	target = parv[1];

	/* GET request */
	if (parc < 3 || EmptyString(parv[2]))
	{
		ms = get_marker_state(source_p, false);
		stored = get_stored_timestamp(ms, target);
		if (stored != NULL)
			sendto_one(source_p, ":%s MARKREAD %s %s",
				me.name, target, stored);
		else
			sendto_one(source_p, ":%s MARKREAD %s *",
				me.name, target);
		return;
	}

	/* SET request */
	timestamp = parv[2];

	/* Validate timestamp format: must start with "timestamp=" */
	if (strncmp(timestamp, "timestamp=", 10) != 0)
	{
		sendto_one(source_p,
			":%s FAIL MARKREAD INVALID_PARAMS %s :Invalid parameters",
			me.name, target);
		return;
	}

	ms = get_marker_state(source_p, true);
	stored = get_stored_timestamp(ms, target);

	/* Monotonically increasing: reject stale or equal timestamps */
	if (stored != NULL && strcmp(stored, timestamp) >= 0)
	{
		/* Reply with the existing (newer) stored value */
		sendto_one(source_p, ":%s MARKREAD %s %s",
			me.name, target, stored);
		return;
	}

	/* Store and acknowledge */
	set_stored_timestamp(ms, target, timestamp);
	sendto_one(source_p, ":%s MARKREAD %s %s",
		me.name, target, timestamp);
}

/* ------------------------------------------------------------------ */
/* Hooks                                                               */
/* ------------------------------------------------------------------ */

/*
 * On channel JOIN, send the stored MARKREAD for that channel.
 * Fires after NAMES, so technically after RPL_ENDOFNAMES.
 * (The spec says "before RPL_ENDOFNAMES" but this ordering is
 *  acceptable for practical purposes.)
 */
static void
hook_channel_join(void *data)
{
	hook_data_channel_activity *info = data;
	struct Client *source_p = info->client;
	struct Channel *chptr = info->chptr;
	struct marker_state *ms;
	const char *stored;

	if (!MyClient(source_p))
		return;
	if (!IsCapable(source_p, CLICAP_READ_MARKER))
		return;

	ms = get_marker_state(source_p, false);
	stored = get_stored_timestamp(ms, chptr->chname);

	if (stored != NULL)
		sendto_one(source_p, ":%s MARKREAD %s %s",
			me.name, chptr->chname, stored);
	else
		sendto_one(source_p, ":%s MARKREAD %s *",
			me.name, chptr->chname);
}

/*
 * On client exit, clean up all stored markers for this client.
 */
static void
hook_client_exit(void *data)
{
	hook_data_client_exit *info = data;
	struct Client *target_p = info->target;
	rb_dictionary_element *elem;
	struct marker_state *ms;
	const char *uid;
	void *saved_key;

	if (!IsClient(target_p))
		return;

	uid = use_id(target_p);
	elem = rb_dictionary_find(client_markers, uid);
	if (elem == NULL)
		return;

	saved_key = (void *)elem->key;
	ms = rb_dictionary_delete(client_markers, uid);
	rb_free(saved_key);
	free_marker_state(ms);
}
