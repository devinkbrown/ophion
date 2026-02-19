/*
 * modules/m_ircx_create.c
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

/*
 * IRCX CREATE command
 *
 * CREATE #channel [modes]
 *
 * Creates a channel and joins the user to it as an owner.
 * Fails with ERR_TOOMANYCHANNELS if at limit, or with
 * ERR_NOSUCHCHANNEL if the channel already exists.
 * Optional modes are applied after creation.
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
#include "hook.h"
#include "ratelimit.h"

static const char ircx_create_desc[] = "Provides IRCX CREATE command for channel creation";

static void m_create(struct MsgBuf *msgbuf_p, struct Client *client_p,
		     struct Client *source_p, int parc, const char *parv[]);

struct Message create_msgtab = {
	"CREATE", 0, 0, 0, 0,
	{mg_unreg, {m_create, 2}, mg_ignore, mg_ignore, mg_ignore, {m_create, 2}}
};

mapi_clist_av1 ircx_create_clist[] = { &create_msgtab, NULL };

DECLARE_MODULE_AV2(ircx_create, NULL, NULL, ircx_create_clist, NULL, NULL, NULL, NULL, ircx_create_desc);

static void
m_create(struct MsgBuf *msgbuf_p, struct Client *client_p,
	 struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr;
	const char *name = parv[1];
	const char *modes;

	if (!IsChannelName(name) || !check_channel_name(name) || strlen(name) > LOC_CHANNELLEN)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				   form_str(ERR_NOSUCHCHANNEL), name);
		return;
	}

	/* channel must not already exist */
	chptr = find_channel(name);
	if (chptr != NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				   form_str(ERR_NOSUCHCHANNEL), name);
		return;
	}

	/* check channel limits */
	if ((rb_dlink_list_length(&source_p->user->channel) >=
	     (unsigned long)ConfigChannel.max_chans_per_user) &&
	    (!IsExtendChans(source_p) ||
	     (rb_dlink_list_length(&source_p->user->channel) >=
	      (unsigned long)ConfigChannel.max_chans_per_user_large)))
	{
		sendto_one(source_p, form_str(ERR_TOOMANYCHANNELS),
			   me.name, source_p->name, name);
		return;
	}

	/* check can_create_channel hook */
	{
		hook_data_client_approval moduledata;

		moduledata.client = source_p;
		moduledata.approved = 0;

		call_hook(register_hook("can_create_channel"), &moduledata);

		if (moduledata.approved != 0)
		{
			if (moduledata.approved != ERR_CUSTOM)
				sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
						   form_str(ERR_NOSUCHCHANNEL), name);
			return;
		}
	}

	chptr = get_or_create_channel(source_p, name, NULL);
	if (chptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				   form_str(ERR_NOSUCHCHANNEL), name);
		return;
	}

	/* add user as channel admin/owner */
	add_user_to_channel(chptr, source_p, CHFL_ADMIN);

	chptr->channelts = rb_current_time();
	chptr->mode.mode |= ConfigChannel.autochanmodes;

	credit_client_join(source_p);

	send_channel_join(chptr, source_p);

	modes = channel_modes(chptr, &me);

	sendto_channel_local(&me, ONLY_CHANOPS, chptr, ":%s MODE %s %s",
			     me.name, chptr->chname, modes);

	sendto_server(client_p, chptr, CAP_TS6, NOCAPS,
		      ":%s SJOIN %ld %s %s :@%s",
		      me.id, (long)chptr->channelts,
		      chptr->chname, modes, source_p->id);

	/* apply modes from the CREATE command if provided */
	if (parc > 2 && !EmptyString(parv[2]))
	{
		struct membership *msptr = find_channel_membership(chptr, source_p);
		/* build a parv array for set_channel_mode */
		const char *mode_parv[MAXMODEPARAMSSERV + 2];
		int mode_parc = 0;

		/* tokenise mode string + optional parameters */
		char *modecopy = LOCAL_COPY(parv[2]);
		char *p = NULL;
		char *tok;

		for (tok = rb_strtok_r(modecopy, " ", &p);
		     tok && mode_parc < MAXMODEPARAMSSERV + 2;
		     tok = rb_strtok_r(NULL, " ", &p))
		{
			mode_parv[mode_parc++] = tok;
		}

		/* also pick up any remaining parv entries */
		for (int i = 3; i < parc && mode_parc < MAXMODEPARAMSSERV + 2; i++)
			mode_parv[mode_parc++] = parv[i];

		if (mode_parc > 0)
			set_channel_mode(client_p, source_p, chptr, msptr, mode_parc, mode_parv);
	}

	channel_member_names(chptr, source_p, 1);

	/* fire channel_join hook */
	{
		hook_data_channel_activity hook_info;
		hook_info.client = source_p;
		hook_info.chptr = chptr;
		hook_info.key = NULL;
		call_hook(register_hook("channel_join"), &hook_info);
	}
}
