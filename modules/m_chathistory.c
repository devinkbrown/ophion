/*
 * modules/m_chathistory.c
 * IRCv3 draft/chathistory capability and CHATHISTORY command
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
 * IRCv3 chathistory (draft) – in-memory message history for channels and
 * direct messages.
 *
 * Capabilities provided:
 *   draft/chathistory  – the CHATHISTORY command
 *   msgid              – unique message identifiers on PRIVMSG/NOTICE
 *
 * ISUPPORT:
 *   CHATHISTORY=<max>  – advertises the per-request message limit
 *   MSGREFTYPES=timestamp – supported reference types
 *
 * Hooks:
 *   h_privmsg_channel  – capture channel messages into history
 *   h_privmsg_user     – capture direct messages into history
 *   outbound_msgbuf    – inject the msgid tag on outgoing messages
 *
 * Subcommands:
 *   CHATHISTORY LATEST  <target> <* | timestamp=T> <limit>
 *   CHATHISTORY BEFORE  <target> <timestamp=T>     <limit>
 *   CHATHISTORY AFTER   <target> <timestamp=T>     <limit>
 *   CHATHISTORY AROUND  <target> <timestamp=T>     <limit>
 *   CHATHISTORY BETWEEN <target> <timestamp=T> <timestamp=T> <limit>
 *   CHATHISTORY TARGETS <timestamp=T> <timestamp=T> <limit>
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "s_serv.h"
#include "s_user.h"
#include "supported.h"
#include "channel.h"
#include "hash.h"
#include "numeric.h"
#include "msg.h"
#include "parse.h"
#include "msgbuf.h"
#include "match.h"
#include "inline/stringops.h"

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

/* Maximum messages stored per target (channel or DM conversation) */
#define HISTORY_MAX_MESSAGES	100

/* Maximum messages a single CHATHISTORY request may return */
#define CHATHISTORY_LIMIT	100

/* Length of a generated msgid (base-62 encoded) */
#define MSGID_LEN		16

static const char m_chathistory_desc[] =
	"Provides the draft/chathistory capability, CHATHISTORY command, and msgid tags";

/* ------------------------------------------------------------------ */
/* Capability bits                                                     */
/* ------------------------------------------------------------------ */

static unsigned int CLICAP_CHATHISTORY = 0;
static unsigned int CLICAP_MSGID = 0;

/* ------------------------------------------------------------------ */
/* History entry                                                       */
/* ------------------------------------------------------------------ */

struct history_entry {
	char nick[NICKLEN + 1];
	char user[USERLEN + 1];
	char host[HOSTLEN + 1];
	char msgid[MSGID_LEN + 1];
	char *text;                   /* heap-allocated */
	time_t timestamp;
	int msec;                     /* millisecond part of timestamp */
	enum message_type msgtype;    /* MESSAGE_TYPE_PRIVMSG or MESSAGE_TYPE_NOTICE */
};

/* ------------------------------------------------------------------ */
/* Ring buffer per target                                              */
/* ------------------------------------------------------------------ */

struct history_ring {
	struct history_entry *entries; /* array of HISTORY_MAX_MESSAGES */
	int head;                     /* next write position */
	int count;                    /* number of valid entries */
	char *name;                   /* canonical target name (heap-alloc) */
};

/* ------------------------------------------------------------------ */
/* Storage dictionaries                                                */
/* ------------------------------------------------------------------ */

/*
 * channel_history: keyed by lowercased channel name
 * dm_history:      keyed by "lower(nick1):lower(nick2)" with nick1 < nick2
 */
static rb_dictionary *channel_history;
static rb_dictionary *dm_history;

/* ------------------------------------------------------------------ */
/* Global msgid state                                                  */
/* ------------------------------------------------------------------ */

/*
 * Monotonic counter for generating unique msgids.  Combined with the
 * server name this produces sortable, unique identifiers.
 */
static uint64_t msgid_counter;

/*
 * The current msgid being attached to outgoing messages.  Set in the
 * privmsg hooks, consumed in the outbound_msgbuf hook, and cleared
 * after dispatch.  Since IRC is single-threaded, this is safe.
 */
static char current_msgid[MSGID_LEN + 1];

/*
 * Track which dispatch cycle the current_msgid belongs to, so we can
 * detect stale values.  We use the g_client_msgbuf pointer as a proxy.
 */
static const struct MsgBuf *current_dispatch;

/* ------------------------------------------------------------------ */
/* ISUPPORT value                                                      */
/* ------------------------------------------------------------------ */

static int chathistory_limit = CHATHISTORY_LIMIT;

static const char *
isupport_chathistory(const void *ptr)
{
	static char buf[16];
	snprintf(buf, sizeof(buf), "%d", *(const int *)ptr);
	return buf;
}

/* ------------------------------------------------------------------ */
/* Forward declarations                                                */
/* ------------------------------------------------------------------ */

static void m_chathistory(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void hook_privmsg_channel(void *data);
static void hook_privmsg_user(void *data);
static void hook_outbound_msgbuf(void *data);
static int chathistory_modinit(void);
static void chathistory_moddeinit(void);

/* ------------------------------------------------------------------ */
/* Module tables                                                       */
/* ------------------------------------------------------------------ */

struct Message chathistory_msgtab = {
	"CHATHISTORY", 0, 0, 0, 0,
	{mg_unreg, {m_chathistory, 3}, mg_ignore, mg_ignore, mg_ignore, {m_chathistory, 3}}
};

mapi_clist_av1 chathistory_clist[] = { &chathistory_msgtab, NULL };

mapi_hfn_list_av1 chathistory_hfnlist[] = {
	{ "privmsg_channel",  (hookfn) hook_privmsg_channel },
	{ "privmsg_user",     (hookfn) hook_privmsg_user },
	{ "outbound_msgbuf",  (hookfn) hook_outbound_msgbuf },
	{ NULL, NULL }
};

mapi_cap_list_av2 chathistory_cap_list[] = {
	{ MAPI_CAP_CLIENT, "draft/chathistory", NULL, &CLICAP_CHATHISTORY },
	{ MAPI_CAP_CLIENT, "draft/event-playback", NULL, NULL },
	{ MAPI_CAP_CLIENT, "msgid", NULL, &CLICAP_MSGID },
	{ 0, NULL, NULL, NULL }
};

DECLARE_MODULE_AV2(m_chathistory, chathistory_modinit, chathistory_moddeinit,
		   chathistory_clist, NULL, chathistory_hfnlist,
		   chathistory_cap_list, NULL, m_chathistory_desc);

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/*
 * Generate a base-62 encoded msgid from the monotonic counter.
 */
static void
generate_msgid(char *buf, size_t buflen)
{
	static const char b62[] =
		"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	uint64_t val = ++msgid_counter;
	char tmp[MSGID_LEN + 1];
	int i = 0;

	do {
		tmp[i++] = b62[val % 62];
		val /= 62;
	} while (val > 0 && i < MSGID_LEN);

	/* reverse into buf */
	int j;
	for (j = 0; j < i && (size_t)j < buflen - 1; j++)
		buf[j] = tmp[i - 1 - j];
	buf[j] = '\0';
}

/*
 * Build a canonical DM conversation key: "lower(a):lower(b)" where a < b.
 */
static void
make_dm_key(char *buf, size_t buflen, const char *nick1, const char *nick2)
{
	char low1[NICKLEN + 1], low2[NICKLEN + 1];
	rb_strlcpy(low1, nick1, sizeof(low1));
	rb_strlcpy(low2, nick2, sizeof(low2));

	/* lowercase both */
	for (char *p = low1; *p; p++) *p = irctolower(*p);
	for (char *p = low2; *p; p++) *p = irctolower(*p);

	if (irccmp(low1, low2) < 0)
		snprintf(buf, buflen, "%s:%s", low1, low2);
	else
		snprintf(buf, buflen, "%s:%s", low2, low1);
}

/*
 * Get or create a history ring for a given dictionary + key.
 */
static struct history_ring *
get_ring(rb_dictionary *dict, const char *key, bool create)
{
	struct history_ring *ring = rb_dictionary_retrieve(dict, key);
	if (ring != NULL)
		return ring;
	if (!create)
		return NULL;

	ring = rb_malloc(sizeof(*ring));
	ring->entries = rb_malloc(sizeof(struct history_entry) * HISTORY_MAX_MESSAGES);
	memset(ring->entries, 0, sizeof(struct history_entry) * HISTORY_MAX_MESSAGES);
	ring->head = 0;
	ring->count = 0;
	ring->name = rb_strdup(key);
	rb_dictionary_add(dict, ring->name, ring);
	return ring;
}

/*
 * Get the i-th oldest entry from a ring (0 = oldest).
 */
static struct history_entry *
ring_entry(struct history_ring *ring, int i)
{
	int idx;
	if (i < 0 || i >= ring->count)
		return NULL;
	if (ring->count < HISTORY_MAX_MESSAGES)
		idx = i;
	else
		idx = (ring->head + i) % HISTORY_MAX_MESSAGES;
	return &ring->entries[idx];
}

/*
 * Append a message to a ring buffer.
 */
static void
ring_append(struct history_ring *ring, const char *nick, const char *user,
	    const char *host, const char *msgid, const char *text,
	    time_t ts, int msec, enum message_type msgtype)
{
	struct history_entry *ent = &ring->entries[ring->head];

	/* Free old text if overwriting */
	if (ent->text != NULL) {
		rb_free(ent->text);
		ent->text = NULL;
	}

	rb_strlcpy(ent->nick, nick, sizeof(ent->nick));
	rb_strlcpy(ent->user, user, sizeof(ent->user));
	rb_strlcpy(ent->host, host, sizeof(ent->host));
	rb_strlcpy(ent->msgid, msgid, sizeof(ent->msgid));
	ent->text = rb_strdup(text);
	ent->timestamp = ts;
	ent->msec = msec;
	ent->msgtype = msgtype;

	ring->head = (ring->head + 1) % HISTORY_MAX_MESSAGES;
	if (ring->count < HISTORY_MAX_MESSAGES)
		ring->count++;
}

/*
 * Format a timestamp in ISO 8601 for the time= tag.
 */
static void
format_timestamp(char *buf, size_t buflen, time_t ts, int msec)
{
	struct tm *tm;

	buf[0] = '\0';
	tm = gmtime(&ts);
	if (tm == NULL)
		return;
	if (strftime(buf, buflen, "%Y-%m-%dT%H:%M:%S.", tm) == 0)
	{
		buf[0] = '\0';
		return;
	}
	rb_snprintf_append(buf, buflen, "%03dZ", msec);
}

/*
 * Parse a "timestamp=YYYY-MM-DDThh:mm:ss.sssZ" reference into epoch time.
 * Returns true on success.
 */
static bool
parse_timestamp_ref(const char *ref, time_t *ts_out, int *msec_out)
{
	int year, month, day, hour, min, sec;

	if (strncmp(ref, "timestamp=", 10) != 0)
		return false;
	ref += 10;

	/* Parse YYYY-MM-DDThh:mm:ss manually */
	if (sscanf(ref, "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &min, &sec) != 6)
		return false;

	struct tm tm;
	memset(&tm, 0, sizeof(tm));
	tm.tm_year = year - 1900;
	tm.tm_mon = month - 1;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min = min;
	tm.tm_sec = sec;
	tm.tm_isdst = 0;

	/* Convert to UTC epoch – use mktime and adjust for local timezone */
	time_t local = mktime(&tm);
	if (local == (time_t)-1)
		return false;

	/* Adjust for UTC: mktime interprets as local, so compute offset */
	struct tm *gm = gmtime(&local);
	struct tm gm_copy;
	if (gm == NULL)
		return false;
	gm_copy = *gm;
	time_t utc_as_local = mktime(&gm_copy);
	*ts_out = local + (local - utc_as_local);

	*msec_out = 0;

	/* Advance past the parsed portion to find optional .sss */
	const char *p = ref;
	/* skip past YYYY-MM-DDThh:mm:ss */
	while (*p && *p != '.' && *p != 'Z') p++;
	if (*p == '.') {
		p++;
		*msec_out = atoi(p);
	}

	return true;
}

/*
 * Parse a "msgid=xxx" reference and find its index in a ring.
 * Returns the index (0-based, oldest=0) or -1 if not found.
 */
static int
find_msgid_in_ring(struct history_ring *ring, const char *ref)
{
	if (strncmp(ref, "msgid=", 6) != 0)
		return -1;
	const char *id = ref + 6;

	for (int i = 0; i < ring->count; i++) {
		struct history_entry *ent = ring_entry(ring, i);
		if (ent != NULL && strcmp(ent->msgid, id) == 0)
			return i;
	}
	return -1;
}

/*
 * Find the index of the first entry at or after the given timestamp.
 * Returns ring->count if all entries are before the timestamp.
 */
static int
find_timestamp_index(struct history_ring *ring, time_t ts, int msec)
{
	for (int i = 0; i < ring->count; i++) {
		struct history_entry *ent = ring_entry(ring, i);
		if (ent == NULL) continue;
		if (ent->timestamp > ts || (ent->timestamp == ts && ent->msec >= msec))
			return i;
	}
	return ring->count;
}

/*
 * Parse a reference (timestamp= or msgid=) and find the corresponding
 * index in a ring.  For timestamp, returns the index of the first entry
 * at or after that time.  For msgid, returns the exact match index.
 * Returns -2 on parse error.
 */
static int
resolve_ref(struct history_ring *ring, const char *ref)
{
	if (strncmp(ref, "timestamp=", 10) == 0) {
		time_t ts;
		int msec;
		if (!parse_timestamp_ref(ref, &ts, &msec))
			return -2;
		return find_timestamp_index(ring, ts, msec);
	}
	if (strncmp(ref, "msgid=", 6) == 0) {
		return find_msgid_in_ring(ring, ref);
	}
	return -2;
}

/*
 * Generate a random batch reference ID.
 */
static void
generate_batch_id(char *buf, size_t buflen)
{
	static const char chars[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	uint32_t r = (uint32_t)rb_current_time() ^ (uint32_t)(uintptr_t)buf;
	r ^= (uint32_t)msgid_counter;

	size_t i;
	for (i = 0; i < buflen - 1 && i < 12; i++) {
		r = r * 1103515245 + 12345;
		buf[i] = chars[(r >> 16) % (sizeof(chars) - 1)];
	}
	buf[i] = '\0';
}

/* ------------------------------------------------------------------ */
/* Playback: send history entries to a client inside a BATCH           */
/* ------------------------------------------------------------------ */

static void
send_history_batch(struct Client *target_p, const char *target_name,
		   struct history_ring *ring, int start, int end, int limit)
{
	char batch_id[16];
	char timebuf[64];
	int count = 0;

	if (start < 0) start = 0;
	if (end > ring->count) end = ring->count;

	generate_batch_id(batch_id, sizeof(batch_id));

	/* BATCH start */
	if (IsCapable(target_p, CLICAP_BATCH))
		sendto_one(target_p, ":%s BATCH +%s chathistory %s",
			   me.name, batch_id, target_name);

	for (int i = start; i < end && count < limit; i++, count++) {
		struct history_entry *ent = ring_entry(ring, i);
		if (ent == NULL) continue;

		format_timestamp(timebuf, sizeof(timebuf), ent->timestamp, ent->msec);

		const char *cmd = (ent->msgtype == MESSAGE_TYPE_NOTICE) ? "NOTICE" : "PRIVMSG";

		if (IsCapable(target_p, CLICAP_BATCH))
			sendto_one(target_p,
				   "@batch=%s;time=%s;msgid=%s :%s!%s@%s %s %s :%s",
				   batch_id, timebuf, ent->msgid,
				   ent->nick, ent->user, ent->host,
				   cmd, target_name, ent->text);
		else
			sendto_one(target_p,
				   "@time=%s;msgid=%s :%s!%s@%s %s %s :%s",
				   timebuf, ent->msgid,
				   ent->nick, ent->user, ent->host,
				   cmd, target_name, ent->text);
	}

	/* BATCH end */
	if (IsCapable(target_p, CLICAP_BATCH))
		sendto_one(target_p, ":%s BATCH -%s", me.name, batch_id);
}

/*
 * send_history_batch_reverse: like send_history_batch but iterates
 * from (end-1) down to start, then the client sees them in chronological
 * order because we collect the newest N and send oldest-first.
 *
 * Actually, for BEFORE we want the N messages before a point, returned in
 * ascending order.  So we find the range, cap it, and send ascending.
 */
static void
send_history_range(struct Client *target_p, const char *target_name,
		   struct history_ring *ring, int start, int end, int limit)
{
	/* Clamp the range and take at most 'limit' entries from the end */
	if (start < 0) start = 0;
	if (end > ring->count) end = ring->count;
	int total = end - start;
	if (total > limit)
		start = end - limit;
	send_history_batch(target_p, target_name, ring, start, end, limit);
}

/* ------------------------------------------------------------------ */
/* CHATHISTORY TARGETS subcommand                                      */
/* ------------------------------------------------------------------ */

struct target_activity {
	const char *name;
	time_t latest_ts;
	int latest_msec;
};

static void
send_targets_batch(struct Client *source_p, time_t ts_from, int msec_from,
		   time_t ts_to, int msec_to, int limit)
{
	char batch_id[16];
	char timebuf[64];
	struct target_activity targets[CHATHISTORY_LIMIT];
	int ntargets = 0;

	/* Collect channel targets the user is a member of */
	rb_dictionary_iter iter;
	struct history_ring *ring;

	RB_DICTIONARY_FOREACH(ring, &iter, channel_history) {
		if (ring->count == 0) continue;

		/* Check if user is a member of this channel */
		struct Channel *chptr = find_channel(ring->name);
		if (chptr == NULL) continue;
		if (find_channel_membership(chptr, source_p) == NULL) continue;

		/* Get the latest message timestamp */
		struct history_entry *latest = ring_entry(ring, ring->count - 1);
		if (latest == NULL) continue;

		/* Check if it falls within the time range */
		if (latest->timestamp < ts_from || (latest->timestamp == ts_from && latest->msec < msec_from))
			continue;
		if (latest->timestamp > ts_to || (latest->timestamp == ts_to && latest->msec > msec_to))
			continue;

		if (ntargets < CHATHISTORY_LIMIT) {
			targets[ntargets].name = ring->name;
			targets[ntargets].latest_ts = latest->timestamp;
			targets[ntargets].latest_msec = latest->msec;
			ntargets++;
		}
	}

	/* Sort by latest timestamp descending (most recent first) */
	for (int i = 0; i < ntargets - 1; i++) {
		for (int j = i + 1; j < ntargets; j++) {
			if (targets[j].latest_ts > targets[i].latest_ts ||
			    (targets[j].latest_ts == targets[i].latest_ts &&
			     targets[j].latest_msec > targets[i].latest_msec)) {
				struct target_activity tmp = targets[i];
				targets[i] = targets[j];
				targets[j] = tmp;
			}
		}
	}

	generate_batch_id(batch_id, sizeof(batch_id));

	if (IsCapable(source_p, CLICAP_BATCH))
		sendto_one(source_p, ":%s BATCH +%s draft/chathistory-targets",
			   me.name, batch_id);

	int sent = 0;
	for (int i = 0; i < ntargets && sent < limit; i++, sent++) {
		format_timestamp(timebuf, sizeof(timebuf),
				 targets[i].latest_ts, targets[i].latest_msec);

		if (IsCapable(source_p, CLICAP_BATCH))
			sendto_one(source_p, "@batch=%s;time=%s :%s PRIVMSG %s :***",
				   batch_id, timebuf, me.name, targets[i].name);
		else
			sendto_one(source_p, "@time=%s :%s PRIVMSG %s :***",
				   timebuf, me.name, targets[i].name);
	}

	if (IsCapable(source_p, CLICAP_BATCH))
		sendto_one(source_p, ":%s BATCH -%s", me.name, batch_id);
}

/* ------------------------------------------------------------------ */
/* CHATHISTORY command handler                                         */
/* ------------------------------------------------------------------ */

static void
m_chathistory(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	      int parc, const char *parv[])
{
	const char *subcmd;
	const char *target;
	int limit;

	if (!MyClient(source_p))
		return;

	if (!IsCapable(source_p, CLICAP_CHATHISTORY)) {
		sendto_one(source_p, ":%s FAIL CHATHISTORY NEED_REGISTRATION :You must negotiate the draft/chathistory capability",
			   me.name);
		return;
	}

	subcmd = parv[1];

	/* --- TARGETS subcommand --- */
	if (irccmp(subcmd, "TARGETS") == 0) {
		if (parc < 5) {
			sendto_one(source_p,
				   ":%s FAIL CHATHISTORY INVALID_PARAMS TARGETS :Insufficient parameters",
				   me.name);
			return;
		}

		time_t ts_from, ts_to;
		int msec_from, msec_to;

		if (!parse_timestamp_ref(parv[2], &ts_from, &msec_from) ||
		    !parse_timestamp_ref(parv[3], &ts_to, &msec_to)) {
			sendto_one(source_p,
				   ":%s FAIL CHATHISTORY INVALID_PARAMS TARGETS :Invalid timestamp",
				   me.name);
			return;
		}

		limit = atoi(parv[4]);
		if (limit <= 0 || limit > chathistory_limit)
			limit = chathistory_limit;

		send_targets_batch(source_p, ts_from, msec_from, ts_to, msec_to, limit);
		return;
	}

	/* --- All other subcommands require a target --- */
	if (parc < 4) {
		sendto_one(source_p,
			   ":%s FAIL CHATHISTORY INVALID_PARAMS %s :Insufficient parameters",
			   me.name, subcmd);
		return;
	}

	target = parv[2];

	/* Determine history ring */
	struct history_ring *ring = NULL;

	if (IsChanPrefix(*target)) {
		/* Channel target */
		struct Channel *chptr = find_channel(target);
		if (chptr == NULL || find_channel_membership(chptr, source_p) == NULL) {
			sendto_one(source_p,
				   ":%s FAIL CHATHISTORY INVALID_TARGET %s %s :Messages could not be retrieved",
				   me.name, subcmd, target);
			return;
		}

		/* Lookup using lowercase channel name */
		char lowkey[LOC_CHANNELLEN + 1];
		rb_strlcpy(lowkey, chptr->chname, sizeof(lowkey));
		for (char *p = lowkey; *p; p++) *p = irctolower(*p);
		ring = get_ring(channel_history, lowkey, false);
	} else {
		/* DM target – look up conversation ring */
		char dmkey[NICKLEN * 2 + 2];
		make_dm_key(dmkey, sizeof(dmkey), source_p->name, target);
		ring = get_ring(dm_history, dmkey, false);
	}

	/* No history at all – send empty batch */
	if (ring == NULL || ring->count == 0) {
		char batch_id[16];
		generate_batch_id(batch_id, sizeof(batch_id));
		if (IsCapable(source_p, CLICAP_BATCH)) {
			sendto_one(source_p, ":%s BATCH +%s chathistory %s",
				   me.name, batch_id, target);
			sendto_one(source_p, ":%s BATCH -%s", me.name, batch_id);
		}
		return;
	}

	/* --- LATEST --- */
	if (irccmp(subcmd, "LATEST") == 0) {
		limit = atoi(parv[parc - 1]);
		if (limit <= 0 || limit > chathistory_limit)
			limit = chathistory_limit;

		const char *ref = parv[3];
		int start;

		if (strcmp(ref, "*") == 0) {
			/* Return the latest N messages */
			start = ring->count - limit;
			if (start < 0) start = 0;
		} else {
			int ref_idx = resolve_ref(ring, ref);
			if (ref_idx == -2) {
				sendto_one(source_p,
					   ":%s FAIL CHATHISTORY INVALID_PARAMS LATEST %s :Invalid reference",
					   me.name, ref);
				return;
			}
			/* Messages after ref_idx */
			start = ref_idx + 1;
			if (ring->count - start > limit)
				start = ring->count - limit;
		}

		send_history_batch(source_p, target, ring, start, ring->count, limit);
	}
	/* --- BEFORE --- */
	else if (irccmp(subcmd, "BEFORE") == 0) {
		limit = atoi(parv[parc - 1]);
		if (limit <= 0 || limit > chathistory_limit)
			limit = chathistory_limit;

		int ref_idx = resolve_ref(ring, parv[3]);
		if (ref_idx == -2) {
			sendto_one(source_p,
				   ":%s FAIL CHATHISTORY INVALID_PARAMS BEFORE %s :Invalid reference",
				   me.name, parv[3]);
			return;
		}

		int end = ref_idx;
		int start = end - limit;
		if (start < 0) start = 0;
		send_history_batch(source_p, target, ring, start, end, limit);
	}
	/* --- AFTER --- */
	else if (irccmp(subcmd, "AFTER") == 0) {
		limit = atoi(parv[parc - 1]);
		if (limit <= 0 || limit > chathistory_limit)
			limit = chathistory_limit;

		int ref_idx = resolve_ref(ring, parv[3]);
		if (ref_idx == -2) {
			sendto_one(source_p,
				   ":%s FAIL CHATHISTORY INVALID_PARAMS AFTER %s :Invalid reference",
				   me.name, parv[3]);
			return;
		}

		int start = ref_idx + 1;
		int end = start + limit;
		if (end > ring->count) end = ring->count;
		send_history_batch(source_p, target, ring, start, end, limit);
	}
	/* --- AROUND --- */
	else if (irccmp(subcmd, "AROUND") == 0) {
		limit = atoi(parv[parc - 1]);
		if (limit <= 0 || limit > chathistory_limit)
			limit = chathistory_limit;

		int ref_idx = resolve_ref(ring, parv[3]);
		if (ref_idx == -2) {
			sendto_one(source_p,
				   ":%s FAIL CHATHISTORY INVALID_PARAMS AROUND %s :Invalid reference",
				   me.name, parv[3]);
			return;
		}

		int half = limit / 2;
		int start = ref_idx - half;
		int end = start + limit;
		if (start < 0) { start = 0; end = limit; }
		if (end > ring->count) { end = ring->count; start = end - limit; }
		if (start < 0) start = 0;
		send_history_batch(source_p, target, ring, start, end, limit);
	}
	/* --- BETWEEN --- */
	else if (irccmp(subcmd, "BETWEEN") == 0) {
		if (parc < 6) {
			sendto_one(source_p,
				   ":%s FAIL CHATHISTORY INVALID_PARAMS BETWEEN :Insufficient parameters",
				   me.name);
			return;
		}

		limit = atoi(parv[5]);
		if (limit <= 0 || limit > chathistory_limit)
			limit = chathistory_limit;

		int ref1 = resolve_ref(ring, parv[3]);
		int ref2 = resolve_ref(ring, parv[4]);
		if (ref1 == -2 || ref2 == -2) {
			sendto_one(source_p,
				   ":%s FAIL CHATHISTORY INVALID_PARAMS BETWEEN :Invalid reference",
				   me.name);
			return;
		}

		int start, end;
		if (ref1 < ref2) {
			start = ref1 + 1;
			end = ref2;
		} else {
			start = ref2 + 1;
			end = ref1;
		}

		send_history_range(source_p, target, ring, start, end, limit);
	}
	else {
		sendto_one(source_p,
			   ":%s FAIL CHATHISTORY INVALID_PARAMS %s :Unknown command",
			   me.name, subcmd);
	}
}

/* ------------------------------------------------------------------ */
/* Hooks                                                               */
/* ------------------------------------------------------------------ */

/*
 * Capture channel PRIVMSG/NOTICE into history.
 */
static void
hook_privmsg_channel(void *data)
{
	hook_data_privmsg_channel *hdata = data;

	/* Only capture PRIVMSG and NOTICE */
	if (hdata->msgtype != MESSAGE_TYPE_PRIVMSG &&
	    hdata->msgtype != MESSAGE_TYPE_NOTICE)
		return;

	if (hdata->chptr == NULL || hdata->source_p == NULL || hdata->text == NULL)
		return;

	/* Don't capture if the hook already rejected the message */
	if (hdata->approved != 0)
		return;

	struct Client *source_p = hdata->source_p;
	struct Channel *chptr = hdata->chptr;

	/* Build the channel key */
	char lowkey[LOC_CHANNELLEN + 1];
	rb_strlcpy(lowkey, chptr->chname, sizeof(lowkey));
	for (char *p = lowkey; *p; p++) *p = irctolower(*p);

	/* Generate msgid */
	struct timeval tv;
	rb_gettimeofday(&tv, NULL);
	generate_msgid(current_msgid, sizeof(current_msgid));
	current_dispatch = g_client_msgbuf;

	struct history_ring *ring = get_ring(channel_history, lowkey, true);
	ring_append(ring, source_p->name, source_p->username, source_p->host,
		    current_msgid, hdata->text, tv.tv_sec, (int)(tv.tv_usec / 1000),
		    hdata->msgtype);
}

/*
 * Capture direct messages into history.
 */
static void
hook_privmsg_user(void *data)
{
	hook_data_privmsg_user *hdata = data;

	if (hdata->msgtype != MESSAGE_TYPE_PRIVMSG &&
	    hdata->msgtype != MESSAGE_TYPE_NOTICE)
		return;

	if (hdata->source_p == NULL || hdata->target_p == NULL || hdata->text == NULL)
		return;

	if (hdata->approved != 0)
		return;

	struct Client *source_p = hdata->source_p;
	struct Client *target_p = hdata->target_p;

	/* Build conversation key */
	char dmkey[NICKLEN * 2 + 2];
	make_dm_key(dmkey, sizeof(dmkey), source_p->name, target_p->name);

	/* Generate msgid */
	struct timeval tv;
	rb_gettimeofday(&tv, NULL);
	generate_msgid(current_msgid, sizeof(current_msgid));
	current_dispatch = g_client_msgbuf;

	struct history_ring *ring = get_ring(dm_history, dmkey, true);
	ring_append(ring, source_p->name, source_p->username, source_p->host,
		    current_msgid, hdata->text, tv.tv_sec, (int)(tv.tv_usec / 1000),
		    hdata->msgtype);
}

/*
 * Inject msgid tag on outgoing messages when we have one from
 * the current dispatch cycle.
 */
static void
hook_outbound_msgbuf(void *data)
{
	hook_data *hdata = data;
	struct MsgBuf *msgbuf = hdata->arg1;

	/* Only inject if we have a valid msgid from this dispatch cycle */
	if (current_msgid[0] == '\0')
		return;

	/* Verify we're still in the same dispatch cycle */
	if (g_client_msgbuf == NULL || g_client_msgbuf != current_dispatch)
		return;

	msgbuf_append_tag(msgbuf, "msgid", current_msgid, CLICAP_MSGID);
}

/* ------------------------------------------------------------------ */
/* Module init / deinit                                                */
/* ------------------------------------------------------------------ */

static void
free_ring(struct history_ring *ring)
{
	if (ring == NULL) return;
	for (int i = 0; i < HISTORY_MAX_MESSAGES; i++) {
		if (ring->entries[i].text != NULL)
			rb_free(ring->entries[i].text);
	}
	rb_free(ring->entries);
	rb_free(ring->name);
	rb_free(ring);
}

static void
destroy_dict_cb(rb_dictionary_element *delem, void *privdata)
{
	(void)privdata;
	free_ring(delem->data);
}

static int
chathistory_modinit(void)
{
	channel_history = rb_dictionary_create("chathistory_channels",
					       (DCF)irccmp);
	dm_history = rb_dictionary_create("chathistory_dms",
					  (DCF)irccmp);

	add_isupport("CHATHISTORY", isupport_chathistory, &chathistory_limit);
	add_isupport("MSGREFTYPES", isupport_string, "timestamp");

	current_msgid[0] = '\0';
	current_dispatch = NULL;

	/* Seed counter with something somewhat unique */
	struct timeval tv;
	rb_gettimeofday(&tv, NULL);
	msgid_counter = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

	return 0;
}

static void
chathistory_moddeinit(void)
{
	delete_isupport("CHATHISTORY");
	delete_isupport("MSGREFTYPES");

	rb_dictionary_destroy(channel_history, destroy_dict_cb, NULL);
	rb_dictionary_destroy(dm_history, destroy_dict_cb, NULL);
}
