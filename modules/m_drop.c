/*
 * modules/m_drop.c — DROP command (account self-drop and oper-forced drop)
 *
 * User syntax:   DROP <password>
 *   Permanently deletes the caller's own account.  Password is required as
 *   confirmation.  The caller must be identified.
 *
 * Oper syntax:   DROP <account>
 *   Force-drop another account without a password.  Opers may not drop
 *   accounts that are linked to an oper block with higher privileges than
 *   their own (i.e. a regular oper cannot drop an admin-linked account;
 *   an admin oper cannot drop another admin-linked account unless they
 *   are the account holder).
 *
 * In both cases, all grouped nicks, certfps, and the account record itself
 * are removed from the DB and synced network-wide via SVCSDROP.  Any
 * currently-identified clients are logged out.
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
#include "send.h"
#include "privilege.h"
#include "logger.h"
#include "services.h"
#include "services_db.h"
#include "services_sync.h"

static const char drop_desc[] =
	"Services DROP command — permanently delete an account";

static void m_drop(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message drop_msgtab = {
	"DROP", 0, 0, 0, 0,
	{mg_unreg, {m_drop, 2}, mg_ignore, mg_ignore, mg_ignore, {m_drop, 2}}
};

mapi_clist_av1 drop_clist[] = { &drop_msgtab, NULL };

DECLARE_MODULE_AV2(m_drop, NULL, NULL, drop_clist, NULL, NULL, NULL, NULL, drop_desc);

/* -------------------------------------------------------------------------
 * Helper: look up an oper_conf by name from the global list.
 * ------------------------------------------------------------------------- */
static struct oper_conf *
find_oper_conf_by_name(const char *name)
{
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, oper_conf_list.head)
	{
		struct oper_conf *o = ptr->data;
		if (irccmp(o->name, name) == 0)
			return o;
	}
	return NULL;
}

/* -------------------------------------------------------------------------
 * Helper: return true if the oper_conf block has admin-level privilege.
 * ------------------------------------------------------------------------- */
static bool
oper_conf_is_admin(struct oper_conf *oconf)
{
	if (oconf == NULL || oconf->privset == NULL)
		return false;
	return (privilegeset_in_set(oconf->privset, "oper:admin") ||
		privilegeset_in_set(oconf->privset, "oper:hidden_admin"));
}

/* -------------------------------------------------------------------------
 * Helper: log out all currently online clients identified to an account.
 * ------------------------------------------------------------------------- */
static void
logout_all_clients(const char *account_name)
{
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, lclient_list.head)
	{
		struct Client *c = ptr->data;
		if (!IsPerson(c))
			continue;
		if (irccmp(c->user->suser, account_name) != 0)
			continue;
		c->user->suser[0] = '\0';
		sendto_server(NULL, NULL, CAP_ENCAP, NOCAPS,
			":%s ENCAP * LOGOUT", use_id(c));
		svc_notice(c, "Services",
			"Your account has been dropped. You have been logged out.");
	}
}

/* -------------------------------------------------------------------------
 * Helper: remove all in-memory/DB/sync data for an account and free it.
 * Caller must NOT use acct after this returns.
 * ------------------------------------------------------------------------- */
static void
do_account_drop(struct svc_account *acct)
{
	char name[NICKLEN + 1];
	rb_strlcpy(name, acct->name, sizeof(name));

	/* Remove all grouped nicks */
	rb_dlink_node *ptr, *next;
	RB_DLINK_FOREACH_SAFE(ptr, next, acct->nicks.head)
	{
		struct svc_nick *sn = ptr->data;
		rb_radixtree_delete(svc_nick_dict, sn->nick);
		svc_db_nick_delete(sn->nick);
		svc_sync_nick_ungroup(sn->nick);
	}

	/* Propagate the drop before freeing */
	svc_sync_account_drop(name);

	/*
	 * Remove from DB and in-memory index.  svc_db_account_delete()
	 * handles radixtree removal and svc_account_free() internally;
	 * do not call either separately after this point.
	 */
	svc_db_account_delete(name);

	/* Log out any currently-online clients */
	logout_all_clients(name);
}

/* -------------------------------------------------------------------------
 * m_drop — DROP <password|account>
 *
 * Non-opers: parv[1] = password (self-drop, must be identified)
 * Opers:     parv[1] = account name (force-drop, no password)
 * ------------------------------------------------------------------------- */
static void
m_drop(struct MsgBuf *msgbuf_p, struct Client *client_p,
       struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if (!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "DROP");
		return;
	}

	if (!IsPerson(source_p))
		return;

	/* ---- Oper-forced drop -------------------------------------------- */
	if (IsOper(source_p))
	{
		const char *target_name = parv[1];
		struct svc_account *acct = svc_account_find(target_name);

		if (acct == NULL)
		{
			svc_notice(source_p, "Services",
				"Account \2%s\2 does not exist.", target_name);
			return;
		}

		/* Hierarchy check: opers cannot drop accounts linked to a
		 * higher-privilege oper block than their own. */
		if (!EmptyString(acct->oper_block))
		{
			struct oper_conf *target_oconf =
				find_oper_conf_by_name(acct->oper_block);

			if (oper_conf_is_admin(target_oconf) &&
			    irccmp(acct->name, source_p->user->suser) != 0)
			{
				/* Admin-linked account — only the account
				 * holder (identified and self-dropping) or an
				 * oper with a higher privilege may drop it.
				 * Since there is no privilege above admin, no
				 * other oper may force-drop an admin account. */
				svc_notice(source_p, "Services",
					"You cannot drop account \2%s\2: it is "
					"linked to an admin oper block.", target_name);
				return;
			}

			/* Non-admin oper block: regular opers can drop it,
			 * but only if they themselves are at least oper. */
		}

		char dropped_by[NICKLEN + 1];
		rb_strlcpy(dropped_by, source_p->name, sizeof(dropped_by));

		ilog(L_MAIN, "DROP %s forced by oper %s!%s@%s",
			acct->name,
			source_p->name, source_p->username, source_p->host);

		sendto_realops_snomask(SNO_GENERAL, L_ALL,
			"DROP: account \2%s\2 dropped by oper \2%s\2",
			acct->name, dropped_by);

		char dropped_name[NICKLEN + 1];
		rb_strlcpy(dropped_name, acct->name, sizeof(dropped_name));

		do_account_drop(acct);

		svc_notice(source_p, "Services",
			"Account \2%s\2 has been dropped.", dropped_name);
		return;
	}

	/* ---- Self-drop (password confirmation required) ------------------- */
	if (EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "Services",
			"You must be identified to use DROP. "
			"Syntax: DROP <password>");
		return;
	}

	struct svc_account *acct = svc_account_find(source_p->user->suser);
	if (acct == NULL)
	{
		svc_notice(source_p, "Services",
			"Internal error: could not find your account record.");
		return;
	}

	/* Verify password */
	struct svc_account *verified = NULL;
	struct oper_conf   *oper_p   = NULL;

	if (!svc_authenticate_password(acct->name, parv[1], &verified, &oper_p) ||
	    verified == NULL)
	{
		svc_notice(source_p, "Services",
			"Incorrect password. Account not dropped.");
		return;
	}

	char dropped_name[NICKLEN + 1];
	rb_strlcpy(dropped_name, acct->name, sizeof(dropped_name));

	ilog(L_MAIN, "DROP %s by self (%s!%s@%s)",
		dropped_name,
		source_p->name, source_p->username, source_p->host);

	do_account_drop(acct);

	svc_notice(source_p, "Services",
		"Account \2%s\2 has been permanently dropped.", dropped_name);
}
