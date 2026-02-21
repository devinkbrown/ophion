/*
 * modules/m_accountoper.c — Oper-only account management commands
 *
 * ACCOUNTOPER <account> <oper_block|->   — link/unlink oper block
 * SETACCOUNT  <nick> <account|->         — force-identify a client
 * SUSPEND     <account>                  — suspend an account
 * UNSUSPEND   <account>                  — unsuspend an account
 * FORBID      <nick|#channel>            — prevent registration
 * UNFORBID    <nick|#channel>            — remove a forbid
 * NOEXPIRE    <account> on|off           — toggle no-expiry flag
 * CHANNOEXPIRE <#channel> on|off         — toggle chanreg no-expiry
 *
 * Copyright (c) 2026 Ophion development team.  GPL v2.
 */

#include "stdinc.h"
#include "client.h"
#include "services.h"
#include "services_db.h"
#include "services_sync.h"
#include "msg.h"
#include "modules.h"
#include "send.h"
#include "numeric.h"
#include "channel.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "ircd.h"
#include "hash.h"
#include "s_serv.h"

static const char accountoper_desc[] =
	"Provides oper-only account management commands: "
	"ACCOUNTOPER SETACCOUNT SUSPEND UNSUSPEND FORBID UNFORBID NOEXPIRE CHANNOEXPIRE";

static void mo_accountoper  (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void mo_setaccount   (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void mo_suspend      (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void mo_unsuspend    (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void mo_forbid       (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void mo_unforbid     (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void mo_noexpire     (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void mo_channoexpire (struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message accountoper_msgtab = {
	"ACCOUNTOPER", 0, 0, 0, 0,
	{mg_unreg, {mo_accountoper, 3}, mg_ignore, mg_ignore, mg_ignore, {mo_accountoper, 3}}
};

struct Message setaccount_msgtab = {
	"SETACCOUNT", 0, 0, 0, 0,
	{mg_unreg, {mo_setaccount, 3}, mg_ignore, mg_ignore, mg_ignore, {mo_setaccount, 3}}
};

struct Message suspend_msgtab = {
	"SUSPEND", 0, 0, 0, 0,
	{mg_unreg, {mo_suspend, 2}, mg_ignore, mg_ignore, mg_ignore, {mo_suspend, 2}}
};

struct Message unsuspend_msgtab = {
	"UNSUSPEND", 0, 0, 0, 0,
	{mg_unreg, {mo_unsuspend, 2}, mg_ignore, mg_ignore, mg_ignore, {mo_unsuspend, 2}}
};

struct Message forbid_msgtab = {
	"FORBID", 0, 0, 0, 0,
	{mg_unreg, {mo_forbid, 2}, mg_ignore, mg_ignore, mg_ignore, {mo_forbid, 2}}
};

struct Message unforbid_msgtab = {
	"UNFORBID", 0, 0, 0, 0,
	{mg_unreg, {mo_unforbid, 2}, mg_ignore, mg_ignore, mg_ignore, {mo_unforbid, 2}}
};

struct Message noexpire_msgtab = {
	"NOEXPIRE", 0, 0, 0, 0,
	{mg_unreg, {mo_noexpire, 3}, mg_ignore, mg_ignore, mg_ignore, {mo_noexpire, 3}}
};

struct Message channoexpire_msgtab = {
	"CHANNOEXPIRE", 0, 0, 0, 0,
	{mg_unreg, {mo_channoexpire, 3}, mg_ignore, mg_ignore, mg_ignore, {mo_channoexpire, 3}}
};

mapi_clist_av1 accountoper_clist[] = {
	&accountoper_msgtab,
	&setaccount_msgtab,
	&suspend_msgtab,
	&unsuspend_msgtab,
	&forbid_msgtab,
	&unforbid_msgtab,
	&noexpire_msgtab,
	&channoexpire_msgtab,
	NULL
};

DECLARE_MODULE_AV2(accountoper, NULL, NULL, accountoper_clist, NULL, NULL, NULL, NULL, accountoper_desc);

/* -------------------------------------------------------------------------
 * Helper: find an oper_conf block by name only.
 * We iterate oper_conf_list (exported from s_newconf.c).
 * ------------------------------------------------------------------------- */
static struct oper_conf *
find_oper_by_name(const char *name)
{
	rb_dlink_node *ptr;
	struct oper_conf *oper_p;

	RB_DLINK_FOREACH(ptr, oper_conf_list.head)
	{
		oper_p = ptr->data;
		if (irccmp(oper_p->name, name) == 0)
			return oper_p;
	}
	return NULL;
}

/* -------------------------------------------------------------------------
 * Helper: find any currently online client identified to a given account.
 * Returns the first match or NULL.
 * ------------------------------------------------------------------------- */
static struct Client *
find_online_by_account(const char *account_name)
{
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, lclient_list.head)
	{
		struct Client *c = ptr->data;
		if (IsPerson(c) && irccmp(c->user->suser, account_name) == 0)
			return c;
	}
	return NULL;
}

/* -------------------------------------------------------------------------
 * Helper: propagate a login/logout for a client.
 * Sends ENCAP * LOGIN (or empty LOGIN) to other servers so they update
 * the suser field for remote copies of the client.
 * ------------------------------------------------------------------------- */
static void
propagate_account_login(struct Client *target_p, const char *account_name)
{
	if (account_name != NULL && *account_name != '\0')
	{
		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * LOGIN %s",
			use_id(target_p), account_name);
	}
	else
	{
		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * LOGIN *",
			use_id(target_p));
	}
}

/* -------------------------------------------------------------------------
 * ACCOUNTOPER <account> <oper_block|->
 * Link or unlink an account to an oper block.
 * ------------------------------------------------------------------------- */
static void
mo_accountoper(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *acct_name, *block_name;
	struct svc_account *acct;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	if (!services.enabled)
	{
		svc_notice(source_p, "OperServ", "Services are not enabled on this server.");
		return;
	}

	acct_name  = parv[1];
	block_name = parv[2];

	acct = svc_account_find(acct_name);
	if (acct == NULL)
	{
		svc_notice(source_p, "OperServ",
			"Account \2%s\2 does not exist.", acct_name);
		return;
	}

	if (strcmp(block_name, "-") == 0)
	{
		/* Unlink */
		acct->oper_block[0] = '\0';
		acct->flags &= ~ACCT_OPERATOR;
		svc_db_account_save(acct);
		svc_sync_account_oper(acct);
		svc_notice(source_p, "OperServ",
			"Unlinked account \2%s\2 from its oper block.", acct_name);
	}
	else
	{
		struct oper_conf *oper_p;

		oper_p = find_oper_by_name(block_name);
		if (oper_p == NULL)
		{
			svc_notice(source_p, "OperServ",
				"Oper block \2%s\2 not found in ircd.conf.", block_name);
			return;
		}

		rb_strlcpy(acct->oper_block, block_name, sizeof(acct->oper_block));
		acct->flags |= ACCT_OPERATOR;
		svc_db_account_save(acct);
		svc_sync_account_oper(acct);
		svc_notice(source_p, "OperServ",
			"Linked account \2%s\2 to oper block \2%s\2.",
			acct_name, block_name);
	}
}

/* -------------------------------------------------------------------------
 * SETACCOUNT <nick> <account|->
 * Force-identify (or deidentify) a client.
 * ------------------------------------------------------------------------- */
static void
mo_setaccount(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *nick, *account_name;
	struct Client *target_p;
	struct svc_account *acct = NULL;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	if (!services.enabled)
	{
		svc_notice(source_p, "OperServ", "Services are not enabled on this server.");
		return;
	}

	nick         = parv[1];
	account_name = parv[2];

	target_p = find_named_client(nick);
	if (target_p == NULL || !IsPerson(target_p))
	{
		svc_notice(source_p, "OperServ",
			"Client \2%s\2 not found.", nick);
		return;
	}

	if (strcmp(account_name, "-") == 0)
	{
		/* Clear account */
		target_p->user->suser[0] = '\0';
		propagate_account_login(target_p, NULL);
		sendto_one_numeric(target_p, RPL_LOGGEDOUT, form_str(RPL_LOGGEDOUT),
			target_p->name);
		svc_notice(source_p, "OperServ",
			"Cleared account for \2%s\2.", nick);
		invalidate_bancache_user(target_p);
	}
	else
	{
		acct = svc_account_find(account_name);
		if (acct == NULL)
		{
			svc_notice(source_p, "OperServ",
				"Account \2%s\2 does not exist.", account_name);
			return;
		}

		rb_strlcpy(target_p->user->suser, acct->name, sizeof(target_p->user->suser));
		propagate_account_login(target_p, acct->name);

		sendto_one_numeric(target_p, RPL_LOGGEDIN, form_str(RPL_LOGGEDIN),
			target_p->name, target_p->username, target_p->host,
			acct->name, acct->name);

		svc_notice(target_p, "OperServ",
			"You have been force-identified to account \2%s\2 by an IRC operator.",
			acct->name);
		svc_notice(source_p, "OperServ",
			"Force-identified \2%s\2 to account \2%s\2.", nick, acct->name);
		invalidate_bancache_user(target_p);
	}
}

/* -------------------------------------------------------------------------
 * SUSPEND <account>
 * Suspend a NickServ account and disconnect any online users.
 * ------------------------------------------------------------------------- */
static void
mo_suspend(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *acct_name;
	struct svc_account *acct;
	struct Client *online;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	if (!services.enabled)
	{
		svc_notice(source_p, "OperServ", "Services are not enabled on this server.");
		return;
	}

	acct_name = parv[1];
	acct = svc_account_find(acct_name);
	if (acct == NULL)
	{
		svc_notice(source_p, "OperServ",
			"Account \2%s\2 does not exist.", acct_name);
		return;
	}

	if (acct->flags & ACCT_SUSPENDED)
	{
		svc_notice(source_p, "OperServ",
			"Account \2%s\2 is already suspended.", acct_name);
		return;
	}

	acct->flags |= ACCT_SUSPENDED;
	svc_db_account_save(acct);
	svc_sync_account_reg(acct);

	/* Disconnect any online user identified to this account */
	online = find_online_by_account(acct->name);
	if (online != NULL && MyClient(online))
	{
		exit_client(online, online, &me, "Account suspended");
	}

	svc_notice(source_p, "OperServ",
		"Account \2%s\2 has been suspended.", acct_name);

	sendto_realops_snomask(SNO_GENERAL, L_ALL,
		"Account %s suspended by oper %s",
		acct_name, source_p->name);
}

/* -------------------------------------------------------------------------
 * UNSUSPEND <account>
 * ------------------------------------------------------------------------- */
static void
mo_unsuspend(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *acct_name;
	struct svc_account *acct;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	if (!services.enabled)
	{
		svc_notice(source_p, "OperServ", "Services are not enabled on this server.");
		return;
	}

	acct_name = parv[1];
	acct = svc_account_find(acct_name);
	if (acct == NULL)
	{
		svc_notice(source_p, "OperServ",
			"Account \2%s\2 does not exist.", acct_name);
		return;
	}

	if (!(acct->flags & ACCT_SUSPENDED))
	{
		svc_notice(source_p, "OperServ",
			"Account \2%s\2 is not suspended.", acct_name);
		return;
	}

	acct->flags &= ~ACCT_SUSPENDED;
	svc_db_account_save(acct);
	svc_sync_account_reg(acct);

	svc_notice(source_p, "OperServ",
		"Account \2%s\2 has been unsuspended.", acct_name);
}

/* -------------------------------------------------------------------------
 * FORBID <nick|#channel>
 * Prevent a nick or channel name from being registered.
 *
 * For nick: add a permanent nick RESV with a services tag.
 * For channel: drop any existing registration and add a channel RESV.
 * We also tag the target on a special "$forbidden" services account so
 * that the services layer knows about it independently of the RESV.
 * ------------------------------------------------------------------------- */
static void
mo_forbid(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *target;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	target = parv[1];

	if (IsChannelName(target))
	{
		struct svc_chanreg *reg;

		/* Drop any existing registration */
		reg = svc_chanreg_find(target);
		if (reg != NULL)
		{
			svc_db_chanreg_delete(reg->channel);
			svc_sync_chandrop(reg->channel);
			rb_radixtree_delete(svc_chanreg_dict, reg->channel);
			svc_chanreg_free(reg);
			svc_notice(source_p, "OperServ",
				"Dropped existing registration for \2%s\2.", target);
		}

		/* Store forbid in "$forbidden" services account metadata */
		struct svc_account *forbidden_acct = svc_account_find("$forbidden");
		if (forbidden_acct == NULL)
		{
			forbidden_acct = svc_account_create("$forbidden", "", "services@localhost");
			if (forbidden_acct != NULL)
				svc_db_account_save(forbidden_acct);
		}

		if (forbidden_acct != NULL)
		{
			struct svc_metadata *meta = rb_malloc(sizeof(*meta));
			rb_strlcpy(meta->key, "forbid_chan", sizeof(meta->key));
			rb_strlcpy(meta->value, target, sizeof(meta->value));
			rb_dlinkAddTail(meta, &meta->node, &forbidden_acct->metadata);
		}

		svc_notice(source_p, "OperServ",
			"Channel \2%s\2 is now forbidden from registration.", target);
	}
	else
	{
		/* Nick forbid: add a permanent nick RESV */
		struct ConfItem *aconf;

		if (find_nick_resv(target) != NULL)
		{
			svc_notice(source_p, "OperServ",
				"Nick \2%s\2 is already on the RESV list.", target);
			return;
		}

		aconf = make_conf();
		aconf->status = CONF_RESV_NICK;
		aconf->host = rb_strdup(target);
		aconf->passwd = rb_strdup("Forbidden by services");
		rb_dlinkAddAlloc(aconf, &resv_conf_list);

		svc_notice(source_p, "OperServ",
			"Nick \2%s\2 is now forbidden from registration.", target);
	}
}

/* -------------------------------------------------------------------------
 * UNFORBID <nick|#channel>
 * Remove a forbid.
 * ------------------------------------------------------------------------- */
static void
mo_unforbid(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *target;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	target = parv[1];

	if (IsChannelName(target))
	{
		struct svc_account *forbidden_acct = svc_account_find("$forbidden");
		bool found = false;

		if (forbidden_acct != NULL)
		{
			rb_dlink_node *ptr, *next_ptr;
			RB_DLINK_FOREACH_SAFE(ptr, next_ptr, forbidden_acct->metadata.head)
			{
				struct svc_metadata *meta = ptr->data;
				if (irccmp(meta->key, "forbid_chan") == 0 &&
				    irccmp(meta->value, target) == 0)
				{
					rb_dlinkDelete(ptr, &forbidden_acct->metadata);
					rb_free(meta);
					found = true;
					break;
				}
			}
		}

		if (found)
			svc_notice(source_p, "OperServ",
				"Removed channel forbid for \2%s\2.", target);
		else
			svc_notice(source_p, "OperServ",
				"No channel forbid found for \2%s\2.", target);
	}
	else
	{
		struct ConfItem *aconf = find_nick_resv(target);
		if (aconf == NULL)
		{
			svc_notice(source_p, "OperServ",
				"No RESV found for nick \2%s\2.", target);
			return;
		}

		rb_dlinkFindDestroy(aconf, &resv_conf_list);
		free_conf(aconf);

		svc_notice(source_p, "OperServ",
			"Nick RESV removed for \2%s\2.", target);
	}
}

/* -------------------------------------------------------------------------
 * NOEXPIRE <account> on|off
 * Toggle ACCT_NOEXPIRE flag.
 * ------------------------------------------------------------------------- */
static void
mo_noexpire(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *acct_name;
	struct svc_account *acct;
	int onoff;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	if (!services.enabled)
	{
		svc_notice(source_p, "OperServ", "Services are not enabled on this server.");
		return;
	}

	acct_name = parv[1];

	acct = svc_account_find(acct_name);
	if (acct == NULL)
	{
		svc_notice(source_p, "OperServ",
			"Account \2%s\2 does not exist.", acct_name);
		return;
	}

	if (irccmp(parv[2], "on") == 0 || irccmp(parv[2], "1") == 0)
		onoff = 1;
	else if (irccmp(parv[2], "off") == 0 || irccmp(parv[2], "0") == 0)
		onoff = 0;
	else
	{
		svc_notice(source_p, "OperServ",
			"Usage: NOEXPIRE <account> on|off");
		return;
	}

	if (onoff)
		acct->flags |= ACCT_NOEXPIRE;
	else
		acct->flags &= ~ACCT_NOEXPIRE;

	svc_db_account_save(acct);
	svc_sync_account_reg(acct);

	svc_notice(source_p, "OperServ",
		"NOEXPIRE for account \2%s\2 is now \2%s\2.",
		acct_name, onoff ? "ON" : "OFF");
}

/* -------------------------------------------------------------------------
 * CHANNOEXPIRE <#channel> on|off
 * Toggle CHANREG_NOEXPIRE on a channel registration.
 * ------------------------------------------------------------------------- */
static void
mo_channoexpire(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *chname;
	struct svc_chanreg *reg;
	int onoff;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	if (!services.enabled)
	{
		svc_notice(source_p, "OperServ", "Services are not enabled on this server.");
		return;
	}

	chname = parv[1];

	if (!IsChannelName(chname))
	{
		svc_notice(source_p, "OperServ", "%s is not a valid channel name.", chname);
		return;
	}

	reg = svc_chanreg_find(chname);
	if (reg == NULL)
	{
		svc_notice(source_p, "OperServ",
			"Channel %s is not registered.", chname);
		return;
	}

	if (irccmp(parv[2], "on") == 0 || irccmp(parv[2], "1") == 0)
		onoff = 1;
	else if (irccmp(parv[2], "off") == 0 || irccmp(parv[2], "0") == 0)
		onoff = 0;
	else
	{
		svc_notice(source_p, "OperServ",
			"Usage: CHANNOEXPIRE <#channel> on|off");
		return;
	}

	if (onoff)
		reg->flags |= CHANREG_NOEXPIRE;
	else
		reg->flags &= ~CHANREG_NOEXPIRE;

	svc_db_chanreg_save(reg);
	svc_sync_chanreg(reg);

	svc_notice(source_p, "OperServ",
		"NOEXPIRE for channel \2%s\2 is now \2%s\2.",
		chname, onoff ? "ON" : "OFF");
}
