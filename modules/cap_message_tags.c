/*
 * modules/cap_message_tags.c
 * IRCv3 message-tags capability and TAGMSG command
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

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "s_serv.h"
#include "s_newconf.h"
#include "channel.h"
#include "hash.h"
#include "numeric.h"
#include "msg.h"
#include "parse.h"
#include "msgbuf.h"
#include "tgchange.h"
#include "inline/stringops.h"

static const char cap_message_tags_desc[] =
	"Provides the message-tags client capability and TAGMSG command";

static void cap_message_tags_outbound(hook_data *);
static void m_tagmsg(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message tagmsg_msgtab = {
	"TAGMSG", 0, 0, 0, 0,
	{mg_unreg, {m_tagmsg, 2}, mg_ignore, mg_ignore, mg_ignore, {m_tagmsg, 2}}
};

mapi_clist_av1 cap_message_tags_clist[] = { &tagmsg_msgtab, NULL };

mapi_hfn_list_av1 cap_message_tags_hfnlist[] = {
	{ "outbound_msgbuf", (hookfn) cap_message_tags_outbound },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(cap_message_tags, NULL, NULL, cap_message_tags_clist, NULL,
		   cap_message_tags_hfnlist, NULL, NULL, cap_message_tags_desc);

/*
 * cap_message_tags_outbound
 *
 * Called for every outgoing message.  When there is an active client
 * command (g_client_msgbuf != NULL), relay any client-only tags
 * (names starting with '+') from the incoming message to the outgoing
 * one so that recipients with message-tags see them.
 */
static void
cap_message_tags_outbound(hook_data *data)
{
	struct MsgBuf *msgbuf = data->arg1;

	if (g_client_msgbuf == NULL)
		return;

	for (size_t i = 0; i < g_client_msgbuf->n_tags; i++)
	{
		const char *key = g_client_msgbuf->tags[i].key;

		/* Only relay client-only tags (prefixed with '+') */
		if (key == NULL || key[0] != '+')
			continue;

		msgbuf_append_tag(msgbuf, key, g_client_msgbuf->tags[i].value,
				  CLICAP_MESSAGE_TAGS);
	}
}

/*
 * m_tagmsg
 *
 * TAGMSG <target>
 *
 * Routes a tag-only message to a channel or user.  The actual payload
 * is entirely in the message tags; there is no text body.
 *
 * Servers MUST NOT relay TAGMSG to clients that have not negotiated
 * the message-tags capability.
 */
static void
m_tagmsg(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	 int parc, const char *parv[])
{
	int result;

	if (parc < 2 || EmptyString(parv[1]))
	{
		sendto_one(source_p, form_str(ERR_NORECIPIENT),
			   me.name, source_p->name, "TAGMSG");
		return;
	}

	if (!MyClient(source_p))
		return;

	if (!IsCapable(source_p, CLICAP_MESSAGE_TAGS))
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			   me.name, source_p->name, "TAGMSG");
		return;
	}

	if (!IsFloodDone(source_p))
		flood_endgrace(source_p);

	const char *target = parv[1];

	if (IsChanPrefix(*target))
	{
		struct Channel *chptr = find_channel(target);

		if (chptr == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
					   form_str(ERR_NOSUCHNICK), target);
			return;
		}

		/* Enforce can_send() – same checks as PRIVMSG/NOTICE */
		if ((result = can_send(chptr, source_p, NULL)))
		{
			if (result != CAN_SEND_OPV &&
			    !IsOperGeneral(source_p) &&
			    !add_channel_target(source_p, chptr))
			{
				sendto_one(source_p, form_str(ERR_TARGCHANGE),
					   me.name, source_p->name, chptr->chname);
				return;
			}

			if (result == CAN_SEND_OPV ||
			    !flood_attack_channel(MESSAGE_TYPE_PRIVMSG, source_p, chptr, chptr->chname))
			{
				sendto_channel_local_with_capability_butone(source_p, ALL_MEMBERS,
					CLICAP_MESSAGE_TAGS, NOCAPS, chptr,
					":%s!%s@%s TAGMSG %s",
					source_p->name, source_p->username, source_p->host,
					chptr->chname);

				/* Notify other subsystems (e.g. Discord bridge) */
				hook_data_channel_activity hdata = {
					.client = source_p,
					.chptr  = chptr,
					.key    = NULL,
				};
				call_hook(h_tagmsg_channel, &hdata);
			}
		}
		else
		{
			sendto_one_numeric(source_p, ERR_CANNOTSENDTOCHAN,
					   form_str(ERR_CANNOTSENDTOCHAN), chptr->chname);
			return;
		}

		/* Echo back to sender if they have echo-message */
		if (IsCapable(source_p, CLICAP_ECHO_MESSAGE))
			sendto_one(source_p, ":%s!%s@%s TAGMSG %s",
				   source_p->name, source_p->username, source_p->host,
				   chptr->chname);
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

		/* Target change tracking */
		if (ConfigFileEntry.target_change && !IsOperGeneral(source_p) &&
		    !find_allowing_channel(source_p, target_p) &&
		    !add_target(source_p, target_p))
		{
			sendto_one(source_p, form_str(ERR_TARGCHANGE),
				   me.name, source_p->name, target_p->name);
			return;
		}

		if (MyClient(target_p))
		{
			/* Only deliver if target has message-tags */
			if (IsCapable(target_p, CLICAP_MESSAGE_TAGS))
			{
				add_reply_target(target_p, source_p);
				sendto_one(target_p, ":%s!%s@%s TAGMSG %s",
					   source_p->name, source_p->username, source_p->host,
					   target_p->name);
			}
		}
		else
		{
			/* Forward to remote server; remote server will decide delivery */
			sendto_one_prefix(target_p, source_p, "TAGMSG", "");
		}

		/* Echo back to sender if they have echo-message and it's not self */
		if (IsCapable(source_p, CLICAP_ECHO_MESSAGE) && target_p != source_p)
			sendto_anywhere_echo(target_p, source_p, "TAGMSG", ":%s",
					     target_p->name);
	}
}
