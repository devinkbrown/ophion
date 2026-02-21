/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_oper.c: Makes a user an IRC Operator.
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
 *
 * -----------------------------------------------------------------------
 * NOTE: The OPER command no longer performs oper authentication.
 *
 * Oper authentication has moved to SASL, which runs during connection
 * registration before the client is visible on the network.  Use one of:
 *
 *   Standard SASL (RFC 4616 / draft-mitchel-irc-sasl):
 *     CAP REQ :sasl
 *     AUTHENTICATE PLAIN
 *     AUTHENTICATE <base64(\0<opername>\0<password>)>
 *
 *   IRCX AUTH shorthand (single command):
 *     AUTH PLAIN I :<base64(\0<opername>\0<password>)>
 *
 *   Certificate-based (no password):
 *     AUTHENTICATE EXTERNAL  then  AUTHENTICATE =
 *     — or —
 *     AUTH EXTERNAL I
 *
 * Server-to-server OPER propagation (mc_oper) is retained unchanged.
 * -----------------------------------------------------------------------
 */

#include "stdinc.h"
#include "client.h"
#include "ircd.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "privilege.h"
#include "logger.h"
#include "snomask.h"

static const char oper_desc[] =
	"Provides the OPER command stub — oper authentication has moved to SASL (/AUTH)";

static void m_oper(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void mc_oper(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message oper_msgtab = {
	"OPER", 0, 0, 0, 0,
	{mg_unreg, {m_oper, 3}, {mc_oper, 3}, mg_ignore, mg_ignore, {m_oper, 3}}
};

mapi_clist_av1 oper_clist[] = { &oper_msgtab, NULL };

DECLARE_MODULE_AV2(oper, NULL, NULL, oper_clist, NULL, NULL, NULL, NULL, oper_desc);

/*
 * m_oper — stub
 *
 * The OPER command no longer authenticates.  Clients that try to use it
 * receive a clear notice explaining how to use SASL instead, along with
 * the IRCX AUTH shorthand that many clients already support.
 */
static void
m_oper(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if(IsOper(source_p))
	{
		sendto_one(source_p, form_str(RPL_YOUREOPER), me.name, source_p->name);
		return;
	}

	sendto_one_notice(source_p,
		":The OPER command has been replaced by SASL authentication. "
		"Authenticate as an IRC operator during connection registration "
		"using AUTHENTICATE PLAIN / AUTHENTICATE EXTERNAL (standard SASL) "
		"or AUTH PLAIN I / AUTH EXTERNAL I (IRCX shorthand). "
		"See your IRC client documentation for SASL configuration.");
}

/*
 * mc_oper — server-to-server OPER propagation
 *
 * Retained unchanged: when a client opers up via SASL on one server the
 * oper_up() call emits this message so remote servers learn of the new oper.
 *
 *   parv[1] = opername
 *   parv[2] = privset name
 */
static void
mc_oper(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct PrivilegeSet *privset;
	sendto_server(client_p, NULL, CAP_TS6, NOCAPS, ":%s OPER %s %s", use_id(source_p), parv[1], parv[2]);

	privset = privilegeset_get(parv[2]);
	if(privset == NULL)
	{
		/* if we don't have a matching privset, create an empty placeholder
		 * marked illegal so it gets picked up on the next rehash */
		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE, "Received OPER for %s with unknown privset %s", source_p->name, parv[2]);
		privset = privilegeset_set_new(parv[2], "", 0);
		privset->status |= CONF_ILLEGAL;
	}

	privset = privilegeset_ref(privset);
	if (source_p->user->privset != NULL)
		privilegeset_unref(source_p->user->privset);

	source_p->user->privset = privset;
	source_p->user->opername = rb_strdup(parv[1]);
}
