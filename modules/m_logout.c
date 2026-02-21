/*
 * modules/m_logout.c — Services LOGOUT command
 *
 * Log out of the current services account.
 *
 * Syntax: LOGOUT
 *
 * Clears the client's account association and notifies the network.
 * Oper status is intentionally NOT revoked: oper privileges are managed
 * separately from services identification.
 *
 * Copyright (c) 2026 Ophion development team. GPL v2.
 */

#include "stdinc.h"
#include "client.h"
#include "hash.h"
#include "modules.h"
#include "msg.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "services.h"
#include "services_db.h"
#include "services_sync.h"

static const char logout_desc[] =
	"Services LOGOUT command — logs the client out of their current account";

static void m_logout(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message logout_msgtab = {
	"LOGOUT", 0, 0, 0, 0,
	{mg_unreg, {m_logout, 1}, mg_ignore, mg_ignore, mg_ignore, {m_logout, 1}}
};

mapi_clist_av1 logout_clist[] = { &logout_msgtab, NULL };

DECLARE_MODULE_AV2(m_logout, NULL, NULL, logout_clist, NULL, NULL, NULL, NULL, logout_desc);

/* ---- command handler ---------------------------------------------------- */

/*
 * m_logout — LOGOUT
 *
 * No parameters required.
 */
static void
m_logout(struct MsgBuf *msgbuf_p, struct Client *client_p,
	 struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;
	(void)parc;
	(void)parv;

	/* Services must be enabled. */
	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "LOGOUT");
		return;
	}

	if(!IsPerson(source_p))
		return;

	/* Must currently be identified. */
	if(EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "Services",
			"You are not identified to any account.");
		return;
	}

	char old_account[NICKLEN + 1];
	rb_strlcpy(old_account, source_p->user->suser, sizeof(old_account));

	/* Clear the account field. */
	source_p->user->suser[0] = '\0';

	/* Propagate logout to other servers — LOGIN * clears account. */
	sendto_server(NULL, NULL, CAP_ENCAP, NOCAPS,
		":%s ENCAP * LOGIN *",
		use_id(source_p));

	/* RPL_LOGGEDOUT (901). */
	sendto_one(source_p, form_str(RPL_LOGGEDOUT),
		me.name, source_p->name,
		source_p->name, source_p->username, source_p->host);

	svc_notice(source_p, "Services",
		"You have been logged out of account \2%s\2.", old_account);
}
