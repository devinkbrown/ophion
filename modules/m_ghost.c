/*
 * modules/m_ghost.c — Services GHOST and REGAIN commands
 *
 * GHOST: Disconnect another session that is using the same account.
 *
 *   Syntax: GHOST <nick> [password]
 *
 *   - If no password is given, the sender must be identified and the target
 *     must be logged into the same account.
 *   - If a password is given, it is checked against the account owning the
 *     target nick (or the target nick itself if the target is not identified).
 *
 * REGAIN: Like GHOST, but also changes the sender's nick to the freed nick
 *   after the target is killed.
 *
 *   Syntax: REGAIN <nick> [password]
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
#include "s_newconf.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"
#include "services.h"
#include "services_db.h"
#include "services_sync.h"
#include "whowas.h"
#include "monitor.h"

static const char ghost_desc[] =
	"Services GHOST and REGAIN commands — disconnect a nick session";

static void m_ghost(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void m_regain(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message ghost_msgtab = {
	"GHOST", 0, 0, 0, 0,
	{mg_unreg, {m_ghost, 2}, mg_ignore, mg_ignore, mg_ignore, {m_ghost, 2}}
};

struct Message regain_msgtab = {
	"REGAIN", 0, 0, 0, 0,
	{mg_unreg, {m_regain, 2}, mg_ignore, mg_ignore, mg_ignore, {m_regain, 2}}
};

mapi_clist_av1 ghost_clist[] = { &ghost_msgtab, &regain_msgtab, NULL };

DECLARE_MODULE_AV2(m_ghost, NULL, NULL, ghost_clist, NULL, NULL, NULL, NULL, ghost_desc);

/* ---- shared ghost logic ------------------------------------------------- */

/*
 * do_ghost — shared implementation for GHOST and REGAIN.
 *
 * Returns true if the target was successfully killed, false otherwise.
 * If change_nick is true and the kill succeeds, the sender's nick is
 * changed to the freed nick.
 */
static bool
do_ghost(struct Client *source_p, const char *target_nick,
	 const char *password, bool change_nick)
{
	/* Find the target client. */
	struct Client *target_p = find_named_person(target_nick);
	if(target_p == NULL)
	{
		svc_notice(source_p, "Services",
			"No such nick: \2%s\2.", target_nick);
		return false;
	}

	/* Cannot ghost yourself. */
	if(target_p == source_p)
	{
		svc_notice(source_p, "Services",
			"That is your own nick — you cannot ghost yourself.");
		return false;
	}

	bool authorized = false;

	if(!EmptyString(password))
	{
		/*
		 * Password supplied: authenticate against the account that owns
		 * the target nick.  Prefer the account the target is identified
		 * to; fall back to looking up the registered account for the
		 * target's nick name.
		 */
		const char *acct_name = NULL;

		if(!EmptyString(target_p->user->suser))
			acct_name = target_p->user->suser;
		else
			acct_name = target_nick;

		struct svc_account *acct   = NULL;
		struct oper_conf   *oper_p = NULL;

		authorized = svc_authenticate_password(acct_name, password,
						       &acct, &oper_p);
		(void)oper_p; /* not used here */
	}
	else
	{
		/*
		 * No password: sender must be identified, and target must be
		 * logged into the same account.
		 */
		if(EmptyString(source_p->user->suser))
		{
			svc_notice(source_p, "Services",
				"You must be identified or supply the account "
				"password to ghost \2%s\2.", target_nick);
			return false;
		}

		if(EmptyString(target_p->user->suser) ||
		   irccmp(source_p->user->suser, target_p->user->suser) != 0)
		{
			svc_notice(source_p, "Services",
				"\2%s\2 is not logged into your account.",
				target_nick);
			return false;
		}

		authorized = true;
	}

	if(!authorized)
	{
		svc_notice(source_p, "Services",
			"Invalid account name or password.");
		return false;
	}

	/* ---- Kill the target session ---- */

	char kill_reason[BUFSIZE];
	snprintf(kill_reason, sizeof(kill_reason),
		"Killed by services (GHOST from %s)", source_p->name);

	/* Notify the target locally. */
	if(MyClient(target_p))
		sendto_one(target_p, ":%s KILL %s :%s",
			me.name, target_p->name, kill_reason);

	target_p->flags |= FLAGS_KILLED;

	/* Propagate the kill to servers. */
	kill_client_serv_butone(NULL, target_p, "%s (%s)",
		me.name, kill_reason);

	sendto_realops_snomask(SNO_SKILL, L_ALL,
		"GHOST: %s killed by %s (services)",
		target_p->name, source_p->name);

	char exit_reason[BUFSIZE];
	snprintf(exit_reason, sizeof(exit_reason), "Killed (%s (%s))",
		me.name, kill_reason);
	exit_client(NULL, target_p, &me, exit_reason);

	svc_notice(source_p, "Services",
		"Ghost with nick \2%s\2 has been killed.", target_nick);

	/* ---- REGAIN: change sender's nick to the freed nick ---- */
	if(change_nick && irccmp(source_p->name, target_nick) != 0)
	{
		/* Make sure the nick is truly free now. */
		if(find_named_person(target_nick) != NULL)
		{
			svc_notice(source_p, "Services",
				"Could not regain nick \2%s\2 — still in use.",
				target_nick);
			return true; /* ghost still succeeded */
		}

		monitor_signoff(source_p);
		invalidate_bancache_user(source_p);

		sendto_realops_snomask(SNO_NCHANGE, L_ALL,
			"Nick change: From %s to %s [%s@%s]",
			source_p->name, target_nick,
			source_p->username, source_p->host);

		sendto_common_channels_local(source_p, NOCAPS, NOCAPS,
			":%s!%s@%s NICK :%s",
			source_p->name, source_p->username,
			source_p->host, target_nick);

		whowas_add_history(source_p, 1);

		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s NICK %s :%ld",
			use_id(source_p), target_nick,
			(long)source_p->tsinfo);

		del_from_client_hash(source_p->name, source_p);
		rb_strlcpy(source_p->name, target_nick, NICKLEN);
		add_to_client_hash(source_p->name, source_p);

		monitor_signon(source_p);
		del_all_accepts(source_p);

		svc_notice(source_p, "Services",
			"Your nick has been changed to \2%s\2.", target_nick);
	}

	return true;
}

/* ---- GHOST handler ------------------------------------------------------ */

static void
m_ghost(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "GHOST");
		return;
	}

	if(!IsPerson(source_p))
		return;

	const char *password = (parc >= 3) ? parv[2] : NULL;
	do_ghost(source_p, parv[1], password, false);
}

/* ---- REGAIN handler ----------------------------------------------------- */

static void
m_regain(struct MsgBuf *msgbuf_p, struct Client *client_p,
	 struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "REGAIN");
		return;
	}

	if(!IsPerson(source_p))
		return;

	const char *password = (parc >= 3) ? parv[2] : NULL;
	do_ghost(source_p, parv[1], password, true);
}
