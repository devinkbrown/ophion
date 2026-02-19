/*
 * modules/m_ircx_whisper.c
 * Copyright (c) 2020 Ariadne Conill <ariadne@dereferenced.org>
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
#include "chmode.h"

static const char ircx_whisper_desc[] =
	"Provides IRCX WHISPER command and +w (no whisper) channel mode";

/* WHISPER rate limit: max commands per window */
#define WHISPER_RATE_MAX     10
#define WHISPER_RATE_WINDOW  10	/* seconds */

static unsigned int MODE_NOWHISPER;

static void m_whisper(struct MsgBuf *msgbuf_p, struct Client *client_p,
		      struct Client *source_p, int parc, const char *parv[]);
static void ms_whisper(struct MsgBuf *msgbuf_p, struct Client *client_p,
		       struct Client *source_p, int parc, const char *parv[]);

struct Message whisper_msgtab = {
	"WHISPER", 0, 0, 0, 0,
	{mg_unreg, {m_whisper, 4}, {ms_whisper, 4}, mg_ignore, mg_ignore, {m_whisper, 4}}
};

mapi_clist_av1 ircx_whisper_clist[] = { &whisper_msgtab, NULL };

static int
modinit(void)
{
	MODE_NOWHISPER = cflag_add('w', chm_simple);
	if (MODE_NOWHISPER == 0)
		return -1;

	return 0;
}

static void
moddeinit(void)
{
	cflag_orphan('w');
}

DECLARE_MODULE_AV2(ircx_whisper, modinit, moddeinit, ircx_whisper_clist, NULL, NULL, NULL, NULL, ircx_whisper_desc);

/*
 * m_whisper - WHISPER command handler (local clients)
 *
 * WHISPER #channel nick :message
 *
 * Sends a private message to a specific user within the context of a channel.
 * Both sender and target must be members of the channel.  The channel must
 * not have mode +w (NOWHISPER) set.
 */
static void
m_whisper(struct MsgBuf *msgbuf_p, struct Client *client_p,
	  struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr;
	struct Client *target_p;
	struct membership *msptr_source;
	struct membership *msptr_target;
	const char *chname = parv[1];
	const char *nick = parv[2];
	const char *text = parv[3];

	if (EmptyString(text))
	{
		sendto_one(source_p, form_str(ERR_NOTEXTTOSEND),
			   me.name, source_p->name);
		return;
	}

	/* gagged users cannot send WHISPER */
	if (IsGagged(source_p))
		return;

	/* dedicated rate limiting for WHISPER (not shared with PRIVMSG) */
	if (MyClient(source_p) && !IsOper(source_p))
	{
		time_t now = rb_current_time();
		if (now - source_p->localClient->last_whisper_time < WHISPER_RATE_WINDOW)
		{
			if (source_p->localClient->whisper_count > WHISPER_RATE_MAX)
			{
				sendto_one_notice(source_p,
					":WHISPER rate limit exceeded, please wait");
				return;
			}
		}
		else
		{
			source_p->localClient->last_whisper_time = now;
			source_p->localClient->whisper_count = 0;
		}
		source_p->localClient->whisper_count++;
	}

	chptr = find_channel(chname);
	if (chptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				   form_str(ERR_NOSUCHCHANNEL), chname);
		return;
	}

	/* sender must be on the channel */
	msptr_source = find_channel_membership(chptr, source_p);
	if (msptr_source == NULL)
	{
		sendto_one(source_p, form_str(ERR_NOTONCHANNEL),
			   me.name, source_p->name, chptr->chname);
		return;
	}

	/* channel must not have +w (NOWHISPER) */
	if (chptr->mode.mode & MODE_NOWHISPER)
	{
		sendto_one_numeric(source_p, ERR_CANNOTSENDTOCHAN,
				   form_str(ERR_CANNOTSENDTOCHAN), chptr->chname);
		return;
	}

	target_p = find_named_person(nick);
	if (target_p == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK,
				   form_str(ERR_NOSUCHNICK), nick);
		return;
	}

	/* target must be on the channel */
	msptr_target = find_channel_membership(chptr, target_p);
	if (msptr_target == NULL)
	{
		sendto_one_numeric(source_p, ERR_USERNOTINCHANNEL,
				   form_str(ERR_USERNOTINCHANNEL),
				   target_p->name, chptr->chname);
		return;
	}

	/* deliver to the target */
	if (MyClient(target_p))
	{
		sendto_one(target_p, ":%s!%s@%s WHISPER %s %s :%s",
			   source_p->name, source_p->username, source_p->host,
			   chptr->chname, target_p->name, text);
	}
	else
	{
		sendto_one(target_p, ":%s WHISPER %s %s :%s",
			   use_id(source_p), chptr->chname,
			   use_id(target_p), text);
	}
}

/*
 * ms_whisper - WHISPER command handler (server-to-server)
 *
 * :<uid> WHISPER #channel <target-uid> :message
 *
 * Both sender and target must be members of the channel.
 * The channel must not have +w (NOWHISPER) set.
 */
static void
ms_whisper(struct MsgBuf *msgbuf_p, struct Client *client_p,
	   struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr;
	struct Client *target_p;
	const char *chname = parv[1];
	const char *text = parv[3];

	chptr = find_channel(chname);
	if (chptr == NULL)
		return;

	/* sender must be in the channel */
	if (find_channel_membership(chptr, source_p) == NULL)
		return;

	/* channel must not have +w */
	if (chptr->mode.mode & MODE_NOWHISPER)
		return;

	target_p = find_person(parv[2]);
	if (target_p == NULL)
		return;

	/* target must be in the channel */
	if (find_channel_membership(chptr, target_p) == NULL)
		return;

	if (MyClient(target_p))
	{
		sendto_one(target_p, ":%s!%s@%s WHISPER %s %s :%s",
			   source_p->name, source_p->username, source_p->host,
			   chptr->chname, target_p->name, text);
	}
	else
	{
		sendto_one(target_p, ":%s WHISPER %s %s :%s",
			   use_id(source_p), chptr->chname,
			   use_id(target_p), text);
	}
}
