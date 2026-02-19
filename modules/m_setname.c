/*
 * modules/m_setname.c
 * IRCv3 setname capability and SETNAME command
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
#include "ircd_defs.h"
#include "send.h"
#include "s_conf.h"
#include "s_serv.h"
#include "numeric.h"
#include "msg.h"
#include "parse.h"
#include "inline/stringops.h"

static const char m_setname_desc[] =
	"Provides the setname client capability and SETNAME command";

static void m_setname(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void me_setname(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message setname_msgtab = {
	"SETNAME", 0, 0, 0, 0,
	{mg_unreg, {m_setname, 2}, mg_ignore, mg_ignore, {me_setname, 2}, {m_setname, 2}}
};

mapi_clist_av1 setname_clist[] = { &setname_msgtab, NULL };

DECLARE_MODULE_AV2(m_setname, NULL, NULL, setname_clist, NULL, NULL, NULL, NULL, m_setname_desc);

/*
 * m_setname
 *
 * SETNAME <realname>
 *
 * Allows a client to change their realname (GECOS) field.  The change
 * is broadcast to all users sharing a channel with the sender who have
 * the setname capability.
 *
 * Per the IRCv3 spec, clients MUST have negotiated the setname capability
 * before sending this command.
 */
static void
m_setname(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	  int parc, const char *parv[])
{
	if (!MyClient(source_p) || !IsPerson(source_p))
		return;

	if (!IsCapable(source_p, CLICAP_SETNAME))
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			   me.name, source_p->name, "SETNAME");
		return;
	}

	if (parc < 2 || EmptyString(parv[1]))
	{
		sendto_one_numeric(source_p, ERR_NEEDMOREPARAMS,
				   form_str(ERR_NEEDMOREPARAMS), "SETNAME");
		return;
	}

	const char *new_realname = parv[1];

	/* Validate: must not be empty after stripping leading whitespace,
	 * and must fit within REALLEN. */
	if (strlen(new_realname) > REALLEN)
	{
		sendto_one(source_p,
			   ":%s FAIL SETNAME INVALID_REALNAME :Realname is too long",
			   me.name);
		return;
	}

	/* Update the client's realname */
	rb_strlcpy(source_p->info, new_realname, sizeof(source_p->info));

	/* Propagate to other servers via ENCAP */
	sendto_server(client_p, NULL, CAP_TS6, NOCAPS,
		      ":%s ENCAP * SETNAME :%s",
		      use_id(source_p), source_p->info);

	/* Notify the sender (echo) */
	sendto_one(source_p, ":%s!%s@%s SETNAME :%s",
		   source_p->name, source_p->username, source_p->host,
		   source_p->info);

	/* Notify all users sharing a channel who have the setname capability */
	sendto_common_channels_local_butone(source_p, CLICAP_SETNAME, NOCAPS,
		":%s!%s@%s SETNAME :%s",
		source_p->name, source_p->username, source_p->host,
		source_p->info);
}

/*
 * me_setname
 *
 * ENCAP handler for SETNAME from a remote server.
 * Updates the source client's realname and broadcasts to local users.
 *
 * parv[1] = new realname
 */
static void
me_setname(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	   int parc, const char *parv[])
{
	if (!IsPerson(source_p))
		return;

	if (parc < 2 || EmptyString(parv[1]))
		return;

	const char *new_realname = parv[1];

	if (strlen(new_realname) > REALLEN)
		return;

	rb_strlcpy(source_p->info, new_realname, sizeof(source_p->info));

	/* Broadcast to local users sharing a channel with this remote user */
	sendto_common_channels_local(source_p, CLICAP_SETNAME, NOCAPS,
		":%s!%s@%s SETNAME :%s",
		source_p->name, source_p->username, source_p->host,
		source_p->info);
}
