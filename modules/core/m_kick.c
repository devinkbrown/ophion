/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_kick.c: Kicks a user from a channel.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 */

#include "stdinc.h"
#include "channel.h"
#include "client.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "msg.h"
#include "modules.h"
#include "parse.h"
#include "hash.h"
#include "packet.h"
#include "s_serv.h"
#include "hook.h"
#include "s_conf.h"

static const char kick_desc[] = "Provides the KICK command to remove a user from a channel";

static void m_kick(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
#define mg_kick { m_kick, 3 }

struct Message kick_msgtab = {
	"KICK", 0, 0, 0, 0,
	{mg_unreg, mg_kick, mg_kick, mg_kick, mg_ignore, mg_kick}
};

mapi_clist_av1 kick_clist[] = { &kick_msgtab, NULL };

DECLARE_MODULE_AV2(kick, NULL, NULL, kick_clist, NULL, NULL, NULL, NULL, kick_desc);

/*
** m_kick
**      parv[1] = channel
**      parv[2] = client to kick
**      parv[3] = kick comment
*/
static void
m_kick(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct membership *msptr;
	struct Client *who;
	struct Channel *chptr;
	int chasing = 0;
	char *comment;
	const char *name;
	char *p = NULL;
	const char *user;
	static char buf[BUFSIZE];

	if(MyClient(source_p) && !IsFloodDone(source_p))
		flood_endgrace(source_p);

	*buf = '\0';
	if((p = strchr(parv[1], ',')))
		*p = '\0';

	name = parv[1];

	chptr = find_channel(name);
	if(chptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL, form_str(ERR_NOSUCHCHANNEL), name);
		return;
	}

	if(!IsServer(source_p))
	{
		msptr = find_channel_membership(chptr, source_p);

		if((msptr == NULL) && MyConnect(source_p))
		{
			sendto_one_numeric(source_p, ERR_NOTONCHANNEL,
					   form_str(ERR_NOTONCHANNEL), name);
			return;
		}

		if(get_channel_access(source_p, chptr, msptr, MODE_ADD, NULL) < CHFL_CHANOP)
		{
			if(MyConnect(source_p))
			{
				sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
					   me.name, source_p->name, name);
				return;
			}

			/* If its a TS 0 channel, do it the old way */
			if(chptr->channelts == 0)
			{
				sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
					   get_id(&me, source_p), get_id(source_p, source_p), name);
				return;
			}
		}

	}

	/*
	 * Iterate over comma-separated target list in parv[2].
	 * For local clients, the number of targets is capped by
	 * general::max_mode_params (default 6, matches ISUPPORT MODES=).
	 * For remote/server sources there is no cap (servers are trusted).
	 * This preserves the old single-target behaviour when only one nick
	 * is given and adds multi-target support when a comma-separated list
	 * is provided.
	 */
	{
		static char targets_buf[BUFSIZE];
		char *target_ptr;
		char *target_tok;
		int kick_count = 0;
		int max_kicks = MyClient(source_p) ? ConfigFileEntry.max_mode_params : INT_MAX;

		rb_strlcpy(targets_buf, parv[2], sizeof(targets_buf));
		target_ptr = targets_buf;

		while ((target_tok = rb_strtok_r(target_ptr, ",", &target_ptr)) != NULL)
		{
			if(kick_count >= max_kicks)
				break;
			kick_count++;

			user = target_tok;

			if(!(who = find_chasing(source_p, user, &chasing)))
				continue;

			msptr = find_channel_membership(chptr, who);

			if(msptr == NULL)
			{
				if(MyClient(source_p))
					sendto_one_numeric(source_p, ERR_USERNOTINCHANNEL,
							   form_str(ERR_USERNOTINCHANNEL),
							   user, name);
				continue;
			}

			if(MyClient(source_p) && IsService(who))
			{
				sendto_one(source_p, form_str(ERR_ISCHANSERVICE),
					   me.name, source_p->name, who->name, chptr->chname);
				continue;
			}

			/*
			 * Oper kick protection — applies to ALL sources, including
			 * services (e.g. ChanServ AKICK / RESTRICTED mode kicks).
			 *
			 * When oper_kick_protection is enabled in ircd.conf:
			 *   - O-lined users (IRC operators and admins) cannot be kicked
			 *     from any channel by a non-oper source.
			 *   - An IRC oper CAN still kick another IRC oper.
			 *   - This is enforced here (not just via h_can_kick) so that
			 *     server-sourced KICK commands from services are also blocked.
			 *
			 * A notice is sent back to local sources; remote sources (e.g.
			 * ChanServ) are silently rejected (the kick is not applied).
			 */
			if(!IsServer(source_p) &&
			   ConfigFileEntry.oper_kick_protection &&
			   (IsOper(who) || IsAdmin(who)) &&
			   !(IsOper(source_p) || IsAdmin(source_p)))
			{
				if(MyClient(source_p))
					sendto_one_numeric(source_p, ERR_ISCHANSERVICE,
						"%s %s :IRC operators cannot be kicked from channels.",
						who->name, chptr->chname);
				sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
					"%s attempted to kick oper %s from %s (blocked: oper_kick_protection)",
					source_p->name, who->name, chptr->chname);
				continue;
			}

			if(MyClient(source_p))
			{
				hook_data_channel_approval hookdata;

				hookdata.client = source_p;
				hookdata.chptr = chptr;
				hookdata.msptr = msptr;
				hookdata.target = who;
				hookdata.approved = 1;
				hookdata.dir = MODE_ADD;

				call_hook(h_can_kick, &hookdata);

				if(!hookdata.approved)
					continue;
			}

			comment = LOCAL_COPY((EmptyString(parv[3])) ? who->name : parv[3]);
			if(strlen(comment) > (size_t) REASONLEN)
				comment[REASONLEN] = '\0';

			if(IsServer(source_p))
				sendto_channel_local(source_p, ALL_MEMBERS, chptr,
						     ":%s KICK %s %s :%s",
						     source_p->name, name, who->name, comment);
			else
				sendto_channel_local(source_p, ALL_MEMBERS, chptr,
						     ":%s!%s@%s KICK %s %s :%s",
						     source_p->name, source_p->username,
						     source_p->host, name, who->name, comment);

			sendto_server(client_p, chptr, CAP_TS6, NOCAPS,
				      ":%s KICK %s %s :%s",
				      use_id(source_p), chptr->chname, use_id(who), comment);
			remove_user_from_channel(msptr);
		}
	}
}
