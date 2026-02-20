/*
 * modules/m_multiline.c
 * IRCv3 draft/multiline capability
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
 * The draft/multiline extension allows clients to send messages spanning
 * multiple protocol lines, grouped inside a BATCH of type draft/multiline.
 *
 * Spec: https://ircv3.net/specs/extensions/multiline
 *
 * Client sends:
 *   BATCH +ref draft/multiline <target>
 *   @batch=ref PRIVMSG <target> :line1
 *   @batch=ref PRIVMSG <target> :line2
 *   BATCH -ref
 *
 * Server relays:
 * - To multiline-capable clients: wrapped in BATCH with batch= tags
 * - To non-multiline clients: individual PRIVMSGs (blank lines dropped,
 *   concat lines merged)
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
#include "msgbuf.h"
#include "packet.h"
#include "tgchange.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "inline/stringops.h"

static const char m_multiline_desc[] =
	"Provides the draft/multiline capability for multi-line messages";

#define MULTILINE_MAX_BYTES	40000
#define MULTILINE_MAX_LINES	100

static unsigned int CLICAP_MULTILINE = 0;

/* Stringify helper (must precede the cap list which uses it) */
#define OPHION_STRINGIFY2(x) #x
#define OPHION_STRINGIFY(x) OPHION_STRINGIFY2(x)

/* ------------------------------------------------------------------ */
/* Per-client batch state                                              */
/* ------------------------------------------------------------------ */

struct ml_line {
	char *text;		/* message text (rb_strdup'd) */
	bool concat;		/* draft/multiline-concat tag was present */
};

struct ml_batch {
	struct Client *client_p;
	char ref[32];			/* client-assigned reference tag */
	char target[CHANNELLEN + 1];	/* target channel or nick */
	enum message_type msgtype;	/* MESSAGE_TYPE_PRIVMSG or MESSAGE_TYPE_NOTICE */
	bool msgtype_set;		/* has the first message line been seen? */
	int nlines;
	int total_bytes;
	struct ml_line lines[MULTILINE_MAX_LINES];
	struct ml_batch *next;
};

static struct ml_batch *open_batches = NULL;

/* Globals for injecting batch/concat tags via the outbound_msgbuf hook */
static const char *g_ml_batch_ref = NULL;
static bool g_ml_concat = false;

/* ------------------------------------------------------------------ */
/* Forward declarations                                                */
/* ------------------------------------------------------------------ */

static int modinit(void);
static void moddeinit(void);
static int batch_handler(struct MsgBuf *msgbuf_p, struct Client *client_p,
			 struct Client *from);
static void hook_outbound_msgbuf(void *data);
static void hook_client_exit(void *data);

/* ------------------------------------------------------------------ */
/* Module declaration                                                  */
/* ------------------------------------------------------------------ */

mapi_cap_list_av2 multiline_cap_list[] = {
	{ MAPI_CAP_CLIENT, "draft/multiline",
	  "max-bytes=" OPHION_STRINGIFY(MULTILINE_MAX_BYTES)
	  ",max-lines=" OPHION_STRINGIFY(MULTILINE_MAX_LINES),
	  &CLICAP_MULTILINE },
	{ 0, NULL, NULL, NULL }
};

mapi_hfn_list_av1 multiline_hfnlist[] = {
	{ "outbound_msgbuf", (hookfn) hook_outbound_msgbuf },
	{ "client_exit", (hookfn) hook_client_exit },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(m_multiline, modinit, moddeinit,
	NULL, NULL, multiline_hfnlist,
	multiline_cap_list, NULL, m_multiline_desc);

/* ------------------------------------------------------------------ */
/* Batch state helpers                                                 */
/* ------------------------------------------------------------------ */

static struct ml_batch *
find_batch(struct Client *client_p)
{
	struct ml_batch *b;
	for (b = open_batches; b != NULL; b = b->next)
		if (b->client_p == client_p)
			return b;
	return NULL;
}

static struct ml_batch *
create_batch(struct Client *client_p, const char *ref, const char *target)
{
	struct ml_batch *b = rb_malloc(sizeof(*b));
	memset(b, 0, sizeof(*b));
	b->client_p = client_p;
	rb_strlcpy(b->ref, ref, sizeof(b->ref));
	rb_strlcpy(b->target, target, sizeof(b->target));
	b->next = open_batches;
	open_batches = b;
	return b;
}

static void
destroy_batch(struct ml_batch *batch)
{
	struct ml_batch **pp;
	int i;

	for (pp = &open_batches; *pp != NULL; pp = &(*pp)->next)
	{
		if (*pp == batch)
		{
			*pp = batch->next;
			break;
		}
	}

	for (i = 0; i < batch->nlines; i++)
		rb_free(batch->lines[i].text);

	rb_free(batch);
}

/* ------------------------------------------------------------------ */
/* Batch reference ID generator                                        */
/* ------------------------------------------------------------------ */

static unsigned int batch_id_counter = 0;

static void
generate_batch_id(char *buf, size_t buflen)
{
	static const char chars[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	uint32_t r = (uint32_t)rb_current_time() ^ (uint32_t)(uintptr_t)buf;
	r ^= ++batch_id_counter;

	size_t i;
	for (i = 0; i < buflen - 1 && i < 12; i++)
	{
		r = r * 1103515245 + 12345;
		buf[i] = chars[(r >> 16) % (sizeof(chars) - 1)];
	}
	buf[i] = '\0';
}

/* ------------------------------------------------------------------ */
/* Outbound msgbuf hook: inject @batch= and multiline-concat tags      */
/* ------------------------------------------------------------------ */

static void
hook_outbound_msgbuf(void *data)
{
	hook_data *hdata = data;
	struct MsgBuf *msgbuf = hdata->arg1;

	if (g_ml_batch_ref != NULL)
	{
		msgbuf_append_tag(msgbuf, "batch", g_ml_batch_ref,
			CLICAP_MULTILINE);
	}

	if (g_ml_concat)
	{
		msgbuf_append_tag(msgbuf, "draft/multiline-concat", NULL,
			CLICAP_MULTILINE);
	}
}

/* ------------------------------------------------------------------ */
/* Client exit hook: clean up any open batch                           */
/* ------------------------------------------------------------------ */

static void
hook_client_exit(void *data)
{
	hook_data_client_exit *info = data;
	struct Client *target_p = info->target;
	struct ml_batch *b;

	if (!IsClient(target_p))
		return;

	b = find_batch(target_p);
	if (b != NULL)
		destroy_batch(b);
}

/* ------------------------------------------------------------------ */
/* Multiline dispatch: send assembled batch to channel                 */
/* ------------------------------------------------------------------ */

/*
 * Build the fallback lines for non-multiline clients.
 * Merges concat lines and skips blank lines.
 * Returns the number of merged lines. Caller must rb_free each entry.
 */
static int
build_fallback_lines(struct ml_batch *batch, char **out, int max)
{
	int n = 0;
	size_t buflen = MULTILINE_MAX_BYTES + 512;
	char *buf = rb_malloc(buflen);
	size_t pos = 0;
	int i;

	for (i = 0; i < batch->nlines; i++)
	{
		const char *text = batch->lines[i].text;
		size_t len = strlen(text);

		if (i > 0 && !batch->lines[i].concat)
		{
			/* Flush accumulated line */
			if (pos > 0 && n < max)
			{
				buf[pos] = '\0';
				out[n++] = rb_strdup(buf);
			}
			pos = 0;
		}

		/* Append text to buffer */
		if (pos + len < buflen - 1)
		{
			memcpy(buf + pos, text, len);
			pos += len;
		}
	}

	/* Flush last line */
	if (pos > 0 && n < max)
	{
		buf[pos] = '\0';
		out[n++] = rb_strdup(buf);
	}

	rb_free(buf);
	return n;
}

static void
dispatch_channel(struct Client *source_p, struct ml_batch *batch)
{
	struct Channel *chptr;
	int result;
	char batch_id[16];
	const char *cmdname;
	char *fallback[MULTILINE_MAX_LINES];
	int nfallback;
	int i;

	chptr = find_channel(batch->target);
	if (chptr == NULL)
	{
		if (batch->msgtype != MESSAGE_TYPE_NOTICE)
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
				form_str(ERR_NOSUCHNICK), batch->target);
		return;
	}

	/* Permission check */
	result = can_send(chptr, source_p, NULL);
	if (!result)
	{
		if (chptr->mode.mode & MODE_OPMODERATE &&
		    (!(chptr->mode.mode & MODE_NOPRIVMSGS) ||
		     IsMember(source_p, chptr)))
		{
			/* opmod: not handled for multiline, send error */
		}
		if (batch->msgtype != MESSAGE_TYPE_NOTICE)
			sendto_one_numeric(source_p, ERR_CANNOTSENDTOCHAN,
				form_str(ERR_CANNOTSENDTOCHAN), chptr->chname);
		return;
	}

	/* Target change check */
	if (result != CAN_SEND_OPV && MyClient(source_p) &&
	    !IsOperGeneral(source_p) &&
	    !add_channel_target(source_p, chptr))
	{
		sendto_one(source_p, form_str(ERR_TARGCHANGE),
			me.name, source_p->name, chptr->chname);
		return;
	}

	/* Flood check */
	if (result != CAN_SEND_OPV &&
	    flood_attack_channel(batch->msgtype, source_p, chptr))
		return;

	/* Reset idle time */
	if (MyClient(source_p) && batch->msgtype != MESSAGE_TYPE_NOTICE)
		source_p->localClient->last = rb_current_time();

	cmdname = (batch->msgtype == MESSAGE_TYPE_NOTICE) ? "NOTICE" : "PRIVMSG";

	generate_batch_id(batch_id, sizeof(batch_id));

	/* --- Send to multiline-capable local members --- */

	/* BATCH + (tags built from source_p, includes server-time/msgid) */
	sendto_channel_local_with_capability_butone(source_p, ALL_MEMBERS,
		CLICAP_MULTILINE, 0, chptr,
		":%s!%s@%s BATCH +%s draft/multiline %s",
		source_p->name, source_p->username, source_p->host,
		batch_id, chptr->chname);

	/* Individual lines with @batch= tag (injected via outbound hook) */
	for (i = 0; i < batch->nlines; i++)
	{
		g_ml_batch_ref = batch_id;
		g_ml_concat = batch->lines[i].concat;

		sendto_channel_local_with_capability_butone(source_p, ALL_MEMBERS,
			CLICAP_MULTILINE, 0, chptr,
			":%s!%s@%s %s %s :%s",
			source_p->name, source_p->username, source_p->host,
			cmdname, chptr->chname, batch->lines[i].text);

		g_ml_batch_ref = NULL;
		g_ml_concat = false;
	}

	/* BATCH - */
	sendto_channel_local_with_capability_butone(source_p, ALL_MEMBERS,
		CLICAP_MULTILINE, 0, chptr,
		":%s BATCH -%s", me.name, batch_id);

	/* --- Send fallback to non-multiline local members --- */

	nfallback = build_fallback_lines(batch, fallback, MULTILINE_MAX_LINES);
	for (i = 0; i < nfallback; i++)
	{
		sendto_channel_local_with_capability_butone(source_p, ALL_MEMBERS,
			0, CLICAP_MULTILINE, chptr,
			":%s!%s@%s %s %s :%s",
			source_p->name, source_p->username, source_p->host,
			cmdname, chptr->chname, fallback[i]);
	}

	/* --- Send fallback to remote servers --- */
	for (i = 0; i < nfallback; i++)
	{
		sendto_server(source_p, chptr, 0, 0,
			":%s %s %s :%s",
			use_id(source_p), cmdname, chptr->chname, fallback[i]);
	}

	/* --- Echo to sender (echo-message) --- */
	if (MyClient(source_p) && IsCapable(source_p, CLICAP_ECHO_MESSAGE))
	{
		if (IsCapable(source_p, CLICAP_MULTILINE) &&
		    IsCapable(source_p, CLICAP_BATCH))
		{
			char echo_batch_id[16];
			generate_batch_id(echo_batch_id, sizeof(echo_batch_id));

			sendto_one(source_p,
				":%s!%s@%s BATCH +%s draft/multiline %s",
				source_p->name, source_p->username, source_p->host,
				echo_batch_id, chptr->chname);

			for (i = 0; i < batch->nlines; i++)
			{
				if (batch->lines[i].concat)
					sendto_one(source_p,
						"@batch=%s;draft/multiline-concat :%s!%s@%s %s %s :%s",
						echo_batch_id,
						source_p->name, source_p->username, source_p->host,
						cmdname, chptr->chname, batch->lines[i].text);
				else
					sendto_one(source_p,
						"@batch=%s :%s!%s@%s %s %s :%s",
						echo_batch_id,
						source_p->name, source_p->username, source_p->host,
						cmdname, chptr->chname, batch->lines[i].text);
			}

			sendto_one(source_p, ":%s BATCH -%s",
				me.name, echo_batch_id);
		}
		else
		{
			for (i = 0; i < nfallback; i++)
				sendto_one(source_p,
					":%s!%s@%s %s %s :%s",
					source_p->name, source_p->username, source_p->host,
					cmdname, chptr->chname, fallback[i]);
		}
	}

	/* Free fallback lines */
	for (i = 0; i < nfallback; i++)
		rb_free(fallback[i]);
}

/* ------------------------------------------------------------------ */
/* Multiline dispatch: send assembled batch to user                    */
/* ------------------------------------------------------------------ */

static void
dispatch_user(struct Client *source_p, struct ml_batch *batch)
{
	struct Client *target_p;
	const char *cmdname;
	char batch_id[16];
	char *fallback[MULTILINE_MAX_LINES];
	int nfallback;
	int i;

	if (MyClient(source_p))
		target_p = find_named_person(batch->target);
	else
		target_p = find_person(batch->target);

	if (target_p == NULL)
	{
		if (batch->msgtype != MESSAGE_TYPE_NOTICE)
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
				form_str(ERR_NOSUCHNICK), batch->target);
		return;
	}

	cmdname = (batch->msgtype == MESSAGE_TYPE_NOTICE) ? "NOTICE" : "PRIVMSG";

	/* Reset idle time */
	if (MyClient(source_p) && batch->msgtype != MESSAGE_TYPE_NOTICE)
		source_p->localClient->last = rb_current_time();

	/* Target change check */
	if (MyClient(source_p) && !IsOperGeneral(source_p) &&
	    !find_allowing_channel(source_p, target_p))
	{
		if ((batch->msgtype != MESSAGE_TYPE_NOTICE ||
		     batch->lines[0].text[0] != '\001') &&
		    ConfigFileEntry.target_change)
		{
			if (!add_target(source_p, target_p))
			{
				sendto_one(source_p, form_str(ERR_TARGCHANGE),
					me.name, source_p->name, target_p->name);
				return;
			}
		}
	}

	/* Away notice */
	if (MyConnect(source_p) && batch->msgtype != MESSAGE_TYPE_NOTICE &&
	    target_p->user && target_p->user->away)
		sendto_one_numeric(source_p, RPL_AWAY, form_str(RPL_AWAY),
			target_p->name, target_p->user->away);

	nfallback = build_fallback_lines(batch, fallback, MULTILINE_MAX_LINES);

	if (MyClient(target_p))
	{
		if (IsCapable(target_p, CLICAP_MULTILINE) &&
		    IsCapable(target_p, CLICAP_BATCH))
		{
			generate_batch_id(batch_id, sizeof(batch_id));

			sendto_one(target_p,
				":%s!%s@%s BATCH +%s draft/multiline %s",
				source_p->name, source_p->username, source_p->host,
				batch_id, target_p->name);

			for (i = 0; i < batch->nlines; i++)
			{
				if (batch->lines[i].concat)
					sendto_one(target_p,
						"@batch=%s;draft/multiline-concat :%s!%s@%s %s %s :%s",
						batch_id,
						source_p->name, source_p->username, source_p->host,
						cmdname, target_p->name, batch->lines[i].text);
				else
					sendto_one(target_p,
						"@batch=%s :%s!%s@%s %s %s :%s",
						batch_id,
						source_p->name, source_p->username, source_p->host,
						cmdname, target_p->name, batch->lines[i].text);
			}

			sendto_one(target_p, ":%s BATCH -%s",
				me.name, batch_id);
		}
		else
		{
			/* Non-multiline local target: send individual lines */
			for (i = 0; i < nfallback; i++)
				sendto_anywhere(target_p, source_p, cmdname,
					":%s", fallback[i]);
		}
	}
	else
	{
		/* Remote target: send individual fallback lines */
		for (i = 0; i < nfallback; i++)
			sendto_anywhere(target_p, source_p, cmdname,
				":%s", fallback[i]);
	}

	/* Echo to sender */
	if (MyClient(source_p) && IsCapable(source_p, CLICAP_ECHO_MESSAGE) &&
	    target_p != source_p)
	{
		if (IsCapable(source_p, CLICAP_MULTILINE) &&
		    IsCapable(source_p, CLICAP_BATCH))
		{
			char echo_batch_id[16];
			generate_batch_id(echo_batch_id, sizeof(echo_batch_id));

			sendto_one(source_p,
				":%s!%s@%s BATCH +%s draft/multiline %s",
				source_p->name, source_p->username, source_p->host,
				echo_batch_id, target_p->name);

			for (i = 0; i < batch->nlines; i++)
			{
				if (batch->lines[i].concat)
					sendto_one(source_p,
						"@batch=%s;draft/multiline-concat :%s!%s@%s %s %s :%s",
						echo_batch_id,
						source_p->name, source_p->username, source_p->host,
						cmdname, target_p->name, batch->lines[i].text);
				else
					sendto_one(source_p,
						"@batch=%s :%s!%s@%s %s %s :%s",
						echo_batch_id,
						source_p->name, source_p->username, source_p->host,
						cmdname, target_p->name, batch->lines[i].text);
			}

			sendto_one(source_p, ":%s BATCH -%s",
				me.name, echo_batch_id);
		}
		else
		{
			for (i = 0; i < nfallback; i++)
				sendto_anywhere_echo(target_p, source_p, cmdname,
					":%s", fallback[i]);
		}
	}

	for (i = 0; i < nfallback; i++)
		rb_free(fallback[i]);
}

/* ------------------------------------------------------------------ */
/* Dispatch assembled multiline batch                                  */
/* ------------------------------------------------------------------ */

static void
dispatch_batch(struct Client *source_p, struct ml_batch *batch)
{
	/* Validate: batch must have at least one non-blank line */
	bool has_content = false;
	int i;

	for (i = 0; i < batch->nlines; i++)
	{
		if (batch->lines[i].text[0] != '\0')
		{
			has_content = true;
			break;
		}
	}

	if (!has_content)
	{
		sendto_one(source_p,
			":%s FAIL BATCH MULTILINE_INVALID :Invalid blank-only batch",
			me.name);
		return;
	}

	if (IsChanPrefix(batch->target[0]))
		dispatch_channel(source_p, batch);
	else
		dispatch_user(source_p, batch);
}

/* ------------------------------------------------------------------ */
/* Client batch handler (called from parse.c)                          */
/* ------------------------------------------------------------------ */

/*
 * Handle BATCH + (open), BATCH - (close), and messages within a batch.
 * Returns 1 if consumed, 0 to let normal dispatch proceed.
 */
static int
batch_handler(struct MsgBuf *msgbuf_p, struct Client *client_p,
	      struct Client *from)
{
	struct ml_batch *batch;

	/* Check for @batch= tagged messages (lines within a batch) */
	const char *batch_tag = NULL;
	for (size_t i = 0; i < msgbuf_p->n_tags; i++)
	{
		if (strcmp(msgbuf_p->tags[i].key, "batch") == 0)
		{
			batch_tag = msgbuf_p->tags[i].value;
			break;
		}
	}

	if (batch_tag != NULL)
	{
		/* Message within a batch */
		batch = find_batch(from);
		if (batch == NULL || strcmp(batch->ref, batch_tag) != 0)
			return 0; /* not our batch, let normal dispatch proceed */

		/* Must be PRIVMSG or NOTICE */
		if (strcasecmp(msgbuf_p->cmd, "PRIVMSG") != 0 &&
		    strcasecmp(msgbuf_p->cmd, "NOTICE") != 0)
			return 0; /* not a message command, let normal dispatch handle */

		/* Check message type consistency */
		enum message_type mt = (strcasecmp(msgbuf_p->cmd, "NOTICE") == 0)
			? MESSAGE_TYPE_NOTICE : MESSAGE_TYPE_PRIVMSG;

		if (!batch->msgtype_set)
		{
			batch->msgtype = mt;
			batch->msgtype_set = true;
		}
		else if (batch->msgtype != mt)
		{
			sendto_one(from,
				":%s FAIL BATCH MULTILINE_INVALID :Invalid mixed commands",
				me.name);
			destroy_batch(batch);
			return 1;
		}

		/* Validate target matches */
		if (msgbuf_p->n_para < 3)
		{
			sendto_one(from,
				":%s FAIL BATCH MULTILINE_INVALID :Missing parameters",
				me.name);
			destroy_batch(batch);
			return 1;
		}

		if (irccmp(msgbuf_p->para[1], batch->target) != 0)
		{
			sendto_one(from,
				":%s FAIL BATCH MULTILINE_INVALID_TARGET %s %s",
				me.name, batch->target, msgbuf_p->para[1]);
			destroy_batch(batch);
			return 1;
		}

		/* Check line limit */
		if (batch->nlines >= MULTILINE_MAX_LINES)
		{
			sendto_one(from,
				":%s FAIL BATCH MULTILINE_MAX_LINES %d",
				me.name, MULTILINE_MAX_LINES);
			destroy_batch(batch);
			return 1;
		}

		/* Get message text (para[2] or empty) */
		const char *text = (msgbuf_p->n_para >= 3 && msgbuf_p->para[2] != NULL)
			? msgbuf_p->para[2] : "";

		/* Check byte limit */
		int text_len = strlen(text);
		if (batch->total_bytes + text_len > MULTILINE_MAX_BYTES)
		{
			sendto_one(from,
				":%s FAIL BATCH MULTILINE_MAX_BYTES %d",
				me.name, MULTILINE_MAX_BYTES);
			destroy_batch(batch);
			return 1;
		}

		/* Check for concat tag */
		bool has_concat = false;
		for (size_t i = 0; i < msgbuf_p->n_tags; i++)
		{
			if (strcmp(msgbuf_p->tags[i].key, "draft/multiline-concat") == 0)
			{
				has_concat = true;
				break;
			}
		}

		/* Blank line must not have concat */
		if (has_concat && text[0] == '\0')
		{
			sendto_one(from,
				":%s FAIL BATCH MULTILINE_INVALID :Invalid concatenated blank",
				me.name);
			destroy_batch(batch);
			return 1;
		}

		/* Buffer the line */
		batch->lines[batch->nlines].text = rb_strdup(text);
		batch->lines[batch->nlines].concat = has_concat;
		batch->nlines++;
		batch->total_bytes += text_len;

		return 1; /* consumed */
	}

	/* BATCH command handling */
	if (strcasecmp(msgbuf_p->cmd, "BATCH") != 0)
		return 0; /* not a BATCH command, let normal dispatch proceed */

	if (msgbuf_p->n_para < 2 || EmptyString(msgbuf_p->para[1]))
		return 0; /* malformed, let cap_batch handle/ignore */

	const char *ref = msgbuf_p->para[1];

	if (ref[0] == '+')
	{
		/* BATCH +ref draft/multiline target */
		const char *refid = ref + 1;
		const char *type = (msgbuf_p->n_para >= 3) ? msgbuf_p->para[2] : "";
		const char *target = (msgbuf_p->n_para >= 4) ? msgbuf_p->para[3] : "";

		/* Only handle draft/multiline type */
		if (strcasecmp(type, "draft/multiline") != 0)
			return 0; /* not our batch type, let normal dispatch */

		/* Client must have draft/multiline capability */
		if (!IsCapable(from, CLICAP_MULTILINE))
			return 0;

		/* Check for existing open batch */
		if (find_batch(from) != NULL)
		{
			sendto_one(from,
				":%s FAIL BATCH MULTILINE_INVALID :Batch already open",
				me.name);
			return 1;
		}

		if (EmptyString(target))
		{
			sendto_one(from,
				":%s FAIL BATCH MULTILINE_INVALID :Missing target",
				me.name);
			return 1;
		}

		create_batch(from, refid, target);
		return 1; /* consumed */
	}
	else if (ref[0] == '-')
	{
		/* BATCH -ref */
		const char *refid = ref + 1;

		batch = find_batch(from);
		if (batch == NULL || strcmp(batch->ref, refid) != 0)
			return 0; /* not our batch, let normal dispatch */

		if (batch->nlines == 0)
		{
			sendto_one(from,
				":%s FAIL BATCH MULTILINE_INVALID :Empty batch",
				me.name);
			destroy_batch(batch);
			return 1;
		}

		/* Dispatch the completed batch */
		dispatch_batch(from, batch);
		destroy_batch(batch);
		return 1; /* consumed */
	}

	return 0; /* unknown BATCH form, let normal dispatch */
}

/* ------------------------------------------------------------------ */
/* Module init / deinit                                                */
/* ------------------------------------------------------------------ */

static int
modinit(void)
{
	client_batch_handler = batch_handler;
	return 0;
}

static void
moddeinit(void)
{
	/* Clean up all open batches */
	while (open_batches != NULL)
		destroy_batch(open_batches);

	client_batch_handler = NULL;
}
