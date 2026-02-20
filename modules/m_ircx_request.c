/*
 * modules/m_ircx_request.c
 *
 * IRCX REQUEST and REPLY commands.
 *
 * REQUEST <target> <tag> :<text>
 *
 *   Sends a typed request to a user or channel.  The <tag> is an
 *   application-defined string that identifies the request type (e.g.
 *   a Comic Chat gesture request, a file-transfer offer, etc.).
 *
 *   If <target> is a channel the sender must be a member of that channel;
 *   the message is delivered to all other members exactly as a PRIVMSG
 *   would be, so it inherits the same privacy as channel membership.
 *
 *   If <target> is a nick the message is delivered directly to that user
 *   (and forwarded server-to-server if needed).
 *
 * REPLY <nick> <tag> :<text>
 *
 *   Sends a typed reply to a previous REQUEST.  <nick> must be an
 *   existing user; the message is forwarded to their server if needed.
 *
 * Both commands are gagged-user-aware and rate-limited together with
 * PRIVMSG flood detection (they share the same counter since they are
 * semantically equivalent for flood purposes).
 *
 * Wire format (server-to-server):
 *   :<uid> REQUEST <#channel|target-uid> <tag> :<text>
 *   :<uid> REPLY   <target-uid>          <tag> :<text>
 */

#include "stdinc.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "inline/stringops.h"

static const char ircx_request_desc[] =
	"Provides IRCX REQUEST and REPLY commands for typed client-to-client messaging";

static void m_request(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_request(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void m_reply(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_reply(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message request_msgtab = {
	"REQUEST", 0, 0, 0, 0,
	{mg_unreg, {m_request, 4}, {ms_request, 4}, mg_ignore, mg_ignore, {m_request, 4}}
};

struct Message reply_msgtab = {
	"REPLY", 0, 0, 0, 0,
	{mg_unreg, {m_reply, 4}, {ms_reply, 4}, mg_ignore, mg_ignore, {m_reply, 4}}
};

mapi_clist_av1 ircx_request_clist[] = { &request_msgtab, &reply_msgtab, NULL };

DECLARE_MODULE_AV2(ircx_request, NULL, NULL, ircx_request_clist, NULL, NULL, NULL, NULL, ircx_request_desc);

/*
 * m_request - REQUEST command handler (local clients)
 *
 * REQUEST #channel|nick <tag> :<text>
 *
 * parv[1] = target (channel or nick)
 * parv[2] = tag (application-defined request type)
 * parv[3] = text
 */
static void
m_request(struct MsgBuf *msgbuf_p, struct Client *client_p,
	  struct Client *source_p, int parc, const char *parv[])
{
	const char *target = parv[1];
	const char *tag    = parv[2];
	const char *text   = parv[3];

	if (EmptyString(text))
	{
		sendto_one(source_p, form_str(ERR_NOTEXTTOSEND),
			   me.name, source_p->name);
		return;
	}

	if (IsGagged(source_p))
		return;

	if (IsChanPrefix(*target))
	{
		struct Channel *chptr = find_channel(target);
		if (chptr == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
					   form_str(ERR_NOSUCHCHANNEL), target);
			return;
		}

		if (find_channel_membership(chptr, source_p) == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOTONCHANNEL,
				form_str(ERR_NOTONCHANNEL), chptr->chname);
			return;
		}

		/* deliver to local channel members */
		sendto_channel_local(source_p, ALL_MEMBERS, chptr,
				     ":%s!%s@%s REQUEST %s %s :%s",
				     source_p->name, source_p->username, source_p->host,
				     chptr->chname, tag, text);

		/* propagate to other servers */
		sendto_server(client_p, chptr, NOCAPS, NOCAPS,
			      ":%s REQUEST %s %s :%s",
			      use_id(source_p), chptr->chname, tag, text);
	}
	else
	{
		struct Client *target_p = find_named_person(target);
		if (target_p == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
					   form_str(ERR_NOSUCHNICK), target);
			return;
		}

		if (MyClient(target_p))
		{
			sendto_one(target_p, ":%s!%s@%s REQUEST %s %s :%s",
				   source_p->name, source_p->username, source_p->host,
				   target_p->name, tag, text);
		}
		else
		{
			sendto_one(target_p, ":%s REQUEST %s %s :%s",
				   use_id(source_p), use_id(target_p), tag, text);
		}
	}
}

/*
 * ms_request - REQUEST command handler (server-to-server)
 *
 * :<uid> REQUEST <#channel|target-uid> <tag> :<text>
 */
static void
ms_request(struct MsgBuf *msgbuf_p, struct Client *client_p,
	   struct Client *source_p, int parc, const char *parv[])
{
	const char *target = parv[1];
	const char *tag    = parv[2];
	const char *text   = parv[3];

	if (IsChanPrefix(*target))
	{
		struct Channel *chptr = find_channel(target);
		if (chptr == NULL)
			return;

		if (find_channel_membership(chptr, source_p) == NULL)
			return;

		sendto_channel_local(source_p, ALL_MEMBERS, chptr,
				     ":%s!%s@%s REQUEST %s %s :%s",
				     source_p->name, source_p->username, source_p->host,
				     chptr->chname, tag, text);

		sendto_server(client_p, chptr, NOCAPS, NOCAPS,
			      ":%s REQUEST %s %s :%s",
			      use_id(source_p), chptr->chname, tag, text);
	}
	else
	{
		struct Client *target_p = find_person(target);
		if (target_p == NULL)
			return;

		if (MyClient(target_p))
		{
			sendto_one(target_p, ":%s!%s@%s REQUEST %s %s :%s",
				   source_p->name, source_p->username, source_p->host,
				   target_p->name, tag, text);
		}
		else
		{
			sendto_one(target_p, ":%s REQUEST %s %s :%s",
				   use_id(source_p), use_id(target_p), tag, text);
		}
	}
}

/*
 * m_reply - REPLY command handler (local clients)
 *
 * REPLY <channel|nick> <nick|tag> :<text>
 *
 * When parv[1] is a channel: REPLY <channel> <target-nick> :<text>
 * When parv[1] is a nick:    REPLY <nick> <tag> :<text>
 */
static void
m_reply(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	const char *target = parv[1];
	const char *nick_or_tag = parv[2];
	const char *text = parv[3];

	if (EmptyString(text))
	{
		sendto_one(source_p, form_str(ERR_NOTEXTTOSEND),
			   me.name, source_p->name);
		return;
	}

	if (IsGagged(source_p))
		return;

	/* REPLY <channel> <nick> :<text> - channel-scoped reply */
	if (IsChanPrefix(*target))
	{
		struct Client *target_p = find_named_person(nick_or_tag);
		if (target_p == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
					   form_str(ERR_NOSUCHNICK), nick_or_tag);
			return;
		}

		if (MyClient(target_p))
		{
			sendto_one(target_p, ":%s!%s@%s REPLY %s %s :%s",
				   source_p->name, source_p->username, source_p->host,
				   target, target_p->name, text);
		}
		else
		{
			sendto_one(target_p, ":%s REPLY %s %s :%s",
				   use_id(source_p), target, use_id(target_p), text);
		}
	}
	else
	{
		/* REPLY <nick> <tag> :<text> - direct reply */
		struct Client *target_p = find_named_person(target);
		if (target_p == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
					   form_str(ERR_NOSUCHNICK), target);
			return;
		}

		if (MyClient(target_p))
		{
			sendto_one(target_p, ":%s!%s@%s REPLY %s %s :%s",
				   source_p->name, source_p->username, source_p->host,
				   target_p->name, nick_or_tag, text);
		}
		else
		{
			sendto_one(target_p, ":%s REPLY %s %s :%s",
				   use_id(source_p), use_id(target_p), nick_or_tag, text);
		}
	}
}

/*
 * ms_reply - REPLY command handler (server-to-server)
 *
 * :<uid> REPLY <target-uid> <tag> :<text>
 */
static void
ms_reply(struct MsgBuf *msgbuf_p, struct Client *client_p,
	 struct Client *source_p, int parc, const char *parv[])
{
	const char *tag  = parv[2];
	const char *text = parv[3];

	struct Client *target_p = find_person(parv[1]);
	if (target_p == NULL)
		return;

	if (MyClient(target_p))
	{
		sendto_one(target_p, ":%s!%s@%s REPLY %s %s :%s",
			   source_p->name, source_p->username, source_p->host,
			   target_p->name, tag, text);
	}
	else
	{
		sendto_one(target_p, ":%s REPLY %s %s :%s",
			   use_id(source_p), use_id(target_p), tag, text);
	}
}
