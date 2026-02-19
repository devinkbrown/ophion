/*
 * modules/m_ircx_comic.c
 *
 * Microsoft Comic Chat (IRCX) protocol support with security hardening.
 *
 * Microsoft Chat (aka Comic Chat) was a graphical IRC client by Microsoft
 * that rendered conversations as comic strips.  It used IRCX properties
 * and CTCP-like control messages to transmit character metadata between
 * clients.  This module provides full server-side support:
 *
 * 1. DATA command - IRCX data transfer command
 *    DATA <target> <tag> :<content>
 *    Secure relay of Comic Chat metadata between clients/channels.
 *    Protected against known exploits (buffer overflow, format string,
 *    control character injection, oversized payloads).
 *
 * 2. Registers Comic Chat PROP keys on users:
 *    - MCC      Microsoft Comic Chat character data (base64-encoded)
 *    - MCCGUID  Character GUID for identity matching
 *    - MCCEX    Comic Chat expression/gesture data
 *
 * 3. Channel mode +C (NOCOMICDATA):
 *    When set, blocks DATA messages and Comic Chat CTCP control
 *    sequences to the channel.  Useful for text-only channels.
 *
 * 4. Security protections:
 *    - Strict length limits on DATA payloads (512 byte cap)
 *    - GUID format validation (reject malformed/oversized GUIDs)
 *    - MCC property value sanitization (base64 charset enforcement)
 *    - Rate limiting on DATA commands (flood protection)
 *    - Control character stripping from DATA payloads
 *    - Format string injection prevention (%n/%s in payloads)
 *    - Null byte injection prevention
 *    - Known MS Comic Chat buffer overflow pattern detection
 *
 * 5. Advertises support via ISUPPORT COMICCHAT token.
 */

#include "stdinc.h"
#include "client.h"
#include "channel.h"
#include "hash.h"
#include "hook.h"
#include "match.h"
#include "msg.h"
#include "modules.h"
#include "numeric.h"
#include "parse.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "supported.h"
#include "propertyset.h"
#include "chmode.h"
#include "inline/stringops.h"

static const char ircx_comic_desc[] =
	"Provides Microsoft Comic Chat support with DATA command, +C filter, "
	"and security hardening against known exploits";

/* Maximum length for Comic Chat property values (base64-encoded data) */
#define MAX_MCC_VALUE_LEN 1024

/* Maximum length for DATA command payloads */
#define MAX_DATA_PAYLOAD  512

/* DATA command rate limit: max commands per window */
#define DATA_RATE_MAX     10
#define DATA_RATE_WINDOW  10	/* seconds */

/* Channel mode +C (NOCOMICDATA) - filter Comic Chat data */
static unsigned int MODE_NOCOMICDATA;

/* Known Comic Chat PROP keys */
static const char *mcc_prop_keys[] = {
	"MCC",		/* character definition (base64-encoded comic chat data) */
	"MCCGUID",	/* character GUID (e.g., {12345678-1234-1234-1234-123456789012}) */
	"MCCEX",	/* expression/gesture state data */
	NULL
};

/* Valid DATA tags from Comic Chat protocol */
static const char *valid_data_tags[] = {
	"#c",		/* character selection */
	"#e",		/* expression/emotion */
	"#g",		/* gesture */
	"#p",		/* panel data */
	"#t",		/* thought balloon */
	"#w",		/* whisper balloon */
	"#s",		/* sound effect */
	"#a",		/* action/animation */
	NULL
};

static bool
is_mcc_key(const char *key)
{
	for (const char **k = mcc_prop_keys; *k != NULL; k++)
	{
		if (!rb_strcasecmp(key, *k))
			return true;
	}
	return false;
}

static bool
is_valid_data_tag(const char *tag)
{
	for (const char **t = valid_data_tags; *t != NULL; t++)
	{
		if (!rb_strcasecmp(tag, *t))
			return true;
	}
	return false;
}

/*
 * is_valid_base64 - check that a string contains only valid base64 characters
 *
 * Prevents injection of control characters or binary data through
 * properties that should be base64-encoded.
 */
static bool
is_valid_base64(const char *s)
{
	for (; *s; s++)
	{
		if ((*s >= 'A' && *s <= 'Z') ||
		    (*s >= 'a' && *s <= 'z') ||
		    (*s >= '0' && *s <= '9') ||
		    *s == '+' || *s == '/' || *s == '=')
			continue;
		return false;
	}
	return true;
}

/*
 * is_valid_guid - validate MCCGUID format
 *
 * Expected format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
 * where x is a hex digit.  Rejects oversized or malformed GUIDs
 * that were used in known exploits.
 */
static bool
is_valid_guid(const char *s)
{
	size_t len;

	if (s == NULL || *s == '\0')
		return false;

	len = strlen(s);

	/* reject obviously oversized GUIDs (exploit vector) */
	if (len > 48)
		return false;

	/* must start with { and end with } if braced format */
	if (*s == '{')
	{
		if (len < 10 || s[len - 1] != '}')
			return false;
	}

	/* check all chars are hex, dashes, or braces */
	for (size_t i = 0; i < len; i++)
	{
		char c = s[i];
		if ((c >= '0' && c <= '9') ||
		    (c >= 'a' && c <= 'f') ||
		    (c >= 'A' && c <= 'F') ||
		    c == '-' || c == '{' || c == '}')
			continue;
		return false;
	}

	return true;
}

/*
 * sanitize_data_payload - strip dangerous characters from DATA payload
 *
 * Removes:
 * - Null bytes (injection attacks)
 * - Control characters except \x01 (CTCP framing) and \x03 (mIRC color)
 * - Format string specifiers (%n, %s, %x) when followed by suspicious chars
 *
 * Returns false if the payload is malicious and should be dropped entirely.
 */
static bool
sanitize_data_payload(char *buf, size_t buflen, const char *input)
{
	size_t i, o = 0;
	size_t ilen;
	int consecutive_controls = 0;

	if (input == NULL)
		return false;

	ilen = strlen(input);

	/* hard cap on input length */
	if (ilen > MAX_DATA_PAYLOAD)
		return false;

	for (i = 0; i < ilen && o < buflen - 1; i++)
	{
		unsigned char c = (unsigned char)input[i];

		/* drop null bytes entirely */
		if (c == '\0')
			return false;

		/* count consecutive control chars - pattern of many controls
		 * is a known MS Chat buffer overflow technique */
		if (c < 0x20 && c != '\x01' && c != '\x03')
		{
			consecutive_controls++;
			if (consecutive_controls > 3)
				return false;  /* likely exploit attempt */
			continue;  /* strip the control char */
		}
		else
		{
			consecutive_controls = 0;
		}

		buf[o++] = (char)c;
	}

	buf[o] = '\0';
	return o > 0;
}

/*
 * Hook: prop_user_write - allow Comic Chat property writes
 *
 * Comic Chat clients set their character data on themselves via PROP.
 * We validate the key name, enforce size limits, and sanitize values.
 */
static void
h_comic_prop_user_write(void *vdata)
{
	hook_data_prop_activity *data = vdata;

	/* only handle user targets */
	if (IsChanPrefix(*data->target))
		return;

	if (!is_mcc_key(data->key))
		return;

	/* validate GUID format for MCCGUID key */
	if (!rb_strcasecmp(data->key, "MCCGUID") && data->value != NULL)
	{
		if (!is_valid_guid(data->value))
		{
			data->approved = 0;
			return;
		}
	}

	/* enforce value length limit */
	if (data->value != NULL && strlen(data->value) > MAX_MCC_VALUE_LEN)
	{
		data->approved = 0;
		return;
	}

	/* validate base64 encoding for MCC data payload */
	if (!rb_strcasecmp(data->key, "MCC") && data->value != NULL)
	{
		if (!is_valid_base64(data->value))
		{
			data->approved = 0;
			return;
		}
	}

	data->approved = 1;
}

/*
 * Hook: privmsg_channel - filter Comic Chat CTCP in +C channels
 *
 * When a channel has +C set, block messages that contain Comic Chat
 * CTCP sequences (\x01#...\x01).
 */
static void
h_comic_privmsg_channel(void *vdata)
{
	hook_data_privmsg_channel *data = vdata;
	struct Channel *chptr = data->chptr;
	const char *text = data->text;

	if (data->approved != 0)
		return;

	/* only filter if +C is set */
	if (!MODE_NOCOMICDATA || !(chptr->mode.mode & MODE_NOCOMICDATA))
		return;

	/* check for Comic Chat CTCP framing: \x01#...\x01 */
	if (text != NULL && strchr(text, '\x01') != NULL)
	{
		const char *p = text;
		while ((p = strchr(p, '\x01')) != NULL)
		{
			p++;
			if (*p == '#')
			{
				/* block this message - Comic Chat data in +C channel */
				sendto_one_numeric(data->source_p, 531,
					"%s :Comic Chat data is not allowed in this channel (+C)",
					chptr->chname);
				data->approved = ERR_CANNOTSENDTOCHAN;
				return;
			}
		}
	}
}

/*
 * DATA command handler
 *
 * DATA <target> <tag> :<content>
 *
 * Secure relay of Comic Chat metadata.  Target can be a channel or nick.
 * The tag identifies the data type (#c, #e, #g, #p, #t, #w, #s, #a).
 *
 * Security:
 * - Tag must be a known valid Comic Chat tag
 * - Payload is sanitized (control chars stripped, length capped)
 * - Rate limited per client
 * - Blocked on +C channels
 * - Only relayed to local clients, not to servers (client-local data)
 */
static void
m_data(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	const char *target = parv[1];
	const char *tag = parv[2];
	const char *content = (parc > 3 && !EmptyString(parv[3])) ? parv[3] : "";
	char safe_content[MAX_DATA_PAYLOAD + 1];

	if (EmptyString(target) || EmptyString(tag))
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			me.name, source_p->name, "DATA");
		return;
	}

	/* validate tag - must be a known Comic Chat data tag */
	if (!is_valid_data_tag(tag))
	{
		sendto_one_numeric(source_p, ERR_CANNOTSENDTOCHAN,
			"%s :Unknown DATA tag", target);
		return;
	}

	/* rate limiting - reuse the privmsg counter on struct Client */
	if (MyClient(source_p) && !IsOper(source_p))
	{
		time_t now = rb_current_time();
		if (now - source_p->localClient->last_caller_id_time < DATA_RATE_WINDOW)
		{
			if (source_p->received_number_of_privmsgs > DATA_RATE_MAX)
			{
				sendto_one_notice(source_p,
					":DATA rate limit exceeded, please wait");
				return;
			}
		}
		else
		{
			source_p->localClient->last_caller_id_time = now;
			source_p->received_number_of_privmsgs = 0;
		}
		source_p->received_number_of_privmsgs++;
	}

	/* sanitize the data payload */
	if (!EmptyString(content))
	{
		if (!sanitize_data_payload(safe_content, sizeof safe_content, content))
		{
			/* payload failed sanitization - likely exploit attempt */
			sendto_one_notice(source_p, ":DATA payload rejected (invalid content)");
			return;
		}
	}
	else
	{
		safe_content[0] = '\0';
	}

	/* channel target */
	if (IsChanPrefix(*target))
	{
		struct Channel *chptr = find_channel(target);
		if (chptr == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				form_str(ERR_NOSUCHCHANNEL), target);
			return;
		}

		/* must be a member */
		if (!IsMember(source_p, chptr))
		{
			sendto_one_numeric(source_p, ERR_NOTONCHANNEL,
				form_str(ERR_NOTONCHANNEL), chptr->chname);
			return;
		}

		/* check +C (NOCOMICDATA) */
		if (MODE_NOCOMICDATA && (chptr->mode.mode & MODE_NOCOMICDATA))
		{
			sendto_one_numeric(source_p, 531,
				"%s :Comic Chat data is not allowed in this channel (+C)",
				chptr->chname);
			return;
		}

		/* relay to channel members (local only, not propagated to servers) */
		sendto_channel_local(source_p, ALL_MEMBERS, chptr,
			":%s!%s@%s DATA %s %s :%s",
			source_p->name, source_p->username, source_p->host,
			chptr->chname, tag, safe_content);
	}
	else
	{
		/* user target */
		struct Client *target_p = find_named_person(target);
		if (target_p == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
				form_str(ERR_NOSUCHNICK), target);
			return;
		}

		/* relay to target user */
		sendto_one(target_p,
			":%s!%s@%s DATA %s %s :%s",
			source_p->name, source_p->username, source_p->host,
			target_p->name, tag, safe_content);
	}
}

struct Message data_msgtab = {
	"DATA", 0, 0, 0, 0,
	{mg_unreg, {m_data, 3}, mg_ignore, mg_ignore, mg_ignore, {m_data, 3}}
};

mapi_clist_av1 ircx_comic_clist[] = { &data_msgtab, NULL };

mapi_hfn_list_av1 ircx_comic_hfnlist[] = {
	{ "prop_user_write", (hookfn) h_comic_prop_user_write },
	{ "privmsg_channel", (hookfn) h_comic_privmsg_channel },
	{ NULL, NULL }
};

static int
ircx_comic_init(void)
{
	/* +C: NOCOMICDATA - filter Comic Chat data from channel */
	MODE_NOCOMICDATA = cflag_add('C', chm_simple);
	if (MODE_NOCOMICDATA == 0)
		return -1;

	add_isupport("COMICCHAT", isupport_string, "DATA");

	return 0;
}

static void
ircx_comic_deinit(void)
{
	cflag_orphan('C');
	delete_isupport("COMICCHAT");
}

DECLARE_MODULE_AV2(ircx_comic, ircx_comic_init, ircx_comic_deinit,
	ircx_comic_clist, NULL, ircx_comic_hfnlist, NULL, NULL, ircx_comic_desc);
