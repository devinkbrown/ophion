/*
 * modules/m_identify.c — Unified IDENTIFY command
 *
 * Handles two distinct forms of IDENTIFY:
 *
 *   1. IRCX channel key IDENTIFY (always available, services on or off):
 *        IDENTIFY #channel <key>
 *      Checks channel OWNERKEY / OPKEY / MEMBERKEY PROPs and the live +k key.
 *      Grants the appropriate status mode (+q / +o / +v) in-channel.
 *
 *   2. Services account IDENTIFY (only when services are enabled):
 *        IDENTIFY <password>              — account = current nick
 *        IDENTIFY <account> <password>   — explicit account name
 *      Authenticates against the services account database; sets suser,
 *      applies vhost, ops the client if linked to an oper block, and
 *      delivers unread memo notification.
 *
 * When services are disabled, the first parameter must be a channel name
 * (#…); otherwise ERR_UNKNOWNCOMMAND is returned so the client knows this
 * syntax is unavailable without services.
 *
 * This module supersedes extensions/m_identify.c (channel key only) and
 * modules/sasl_account.c for the plain-text IDENTIFY path.
 *
 * Copyright (c) 2026 Ophion development team. GPL v2.
 */

#include "stdinc.h"
#include "auth_oper.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "modules.h"
#include "msg.h"
#include "numeric.h"
#include "propertyset.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"
#include "services.h"
#include "services_db.h"
#include "services_sync.h"

static const char identify_desc[] =
	"Unified IDENTIFY: IRCX channel key access (always) + "
	"services account authentication (when services enabled)";

static void m_identify(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message identify_msgtab = {
	"IDENTIFY", 0, 0, 0, 0,
	{mg_unreg, {m_identify, 2}, mg_ignore, mg_ignore, mg_ignore, {m_identify, 2}}
};

mapi_clist_av1 identify_clist[] = { &identify_msgtab, NULL };

DECLARE_MODULE_AV2(m_identify, NULL, NULL, identify_clist, NULL, NULL, NULL, NULL, identify_desc);

/* =========================================================================
 * IRCX channel key identify — IDENTIFY #channel <key>
 *
 * Mirrors m_ircx_identify.c; inlined here so we have one IDENTIFY handler
 * regardless of whether services are loaded.
 * ========================================================================= */

static void
m_identify_channel(struct Client *source_p, const char *channame,
                   const char *key)
{
	struct Channel   *chptr;
	struct membership *msptr;
	struct Property  *prop;

	chptr = find_channel(channame);
	if(chptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
		                   form_str(ERR_NOSUCHCHANNEL), channame);
		return;
	}

	msptr = find_channel_membership(chptr, source_p);
	if(msptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOTONCHANNEL,
		                   form_str(ERR_NOTONCHANNEL), chptr->chname);
		return;
	}

	/* OWNERKEY → +q (channel owner) */
	prop = propertyset_find(&chptr->prop_list, "OWNERKEY");
	if(prop != NULL && !rb_strcasecmp(prop->value, key))
	{
		if(is_admin(msptr))
		{
			sendto_one_notice(source_p,
			    ":You are already a channel owner on %s",
			    chptr->chname);
			return;
		}
		const char *para[] = {"+q", source_p->name};
		set_channel_mode(source_p, &me, chptr, NULL, 2, para);
		sendto_one_notice(source_p,
		    ":IDENTIFY successful — owner access granted on %s",
		    chptr->chname);
		return;
	}

	/* HOSTKEY / OPKEY → +o */
	prop = propertyset_find(&chptr->prop_list, "HOSTKEY");
	if(prop == NULL)
		prop = propertyset_find(&chptr->prop_list, "OPKEY");
	if(prop != NULL && !rb_strcasecmp(prop->value, key))
	{
		if(is_chanop(msptr))
		{
			sendto_one_notice(source_p,
			    ":You are already a channel operator on %s",
			    chptr->chname);
			return;
		}
		const char *para[] = {"+o", source_p->name};
		set_channel_mode(source_p, &me, chptr, NULL, 2, para);
		sendto_one_notice(source_p,
		    ":IDENTIFY successful — operator access granted on %s",
		    chptr->chname);
		return;
	}

	/* MEMBERKEY / live +k → +v */
	if(*chptr->mode.key && !rb_strcasecmp(chptr->mode.key, key))
	{
		if(is_voiced(msptr))
		{
			sendto_one_notice(source_p,
			    ":You are already voiced on %s", chptr->chname);
			return;
		}
		const char *para[] = {"+v", source_p->name};
		set_channel_mode(source_p, &me, chptr, NULL, 2, para);
		sendto_one_notice(source_p,
		    ":IDENTIFY successful — voice access granted on %s",
		    chptr->chname);
		return;
	}

	/* Registered founder bypass: if client is the registered founder and
	 * provided the ChanServ-saved key, grant them op even if the live
	 * channel key differs (someone changed it to lock them out). */
	if(services.enabled)
	{
		struct svc_chanreg *reg = svc_chanreg_find(chptr->chname);
		if(reg != NULL && reg->mlock_key[0] != '\0'
		   && !rb_strcasecmp(reg->mlock_key, key))
		{
			uint32_t ca = 0;
			rb_dlink_node *n;
			RB_DLINK_FOREACH(n, reg->access.head)
			{
				struct svc_chanaccess *ca_e = n->data;
				if(source_p->user
				   && rb_strcasecmp(ca_e->entity,
				                    source_p->user->suser) == 0)
				{
					ca |= ca_e->flags;
					break;
				}
			}
			if(ca & (CA_FOUNDER | CA_STAFF | CA_OP | CA_PROTECT | CA_OWNER))
			{
				const char *para[] = {"+o", source_p->name};
				set_channel_mode(source_p, &me, chptr, NULL, 2, para);
				sendto_one_notice(source_p,
				    ":IDENTIFY successful — operator access "
				    "restored via registered channel key on %s",
				    chptr->chname);
				/* Re-apply the correct key to the channel */
				svc_modelock_enforce(chptr, reg);
				return;
			}
		}
	}

	sendto_one_notice(source_p,
	    ":IDENTIFY failed — incorrect key for %s", chptr->chname);
}

/* =========================================================================
 * Services account identify — IDENTIFY [<account>] <password>
 * ========================================================================= */

static void
m_identify_account(struct Client *source_p, const char *account,
                   const char *password, bool noprivs)
{
	if(!IsPerson(source_p))
	{
		svc_notice(source_p, "Services",
		           "You must complete connection registration "
		           "before using IDENTIFY.");
		return;
	}

	/* Already identified? Re-send 900 to confirm, then return. */
	if(!EmptyString(source_p->user->suser))
	{
		sendto_one(source_p, form_str(RPL_LOGGEDIN),
		           me.name, source_p->name,
		           source_p->name, source_p->username, source_p->host,
		           source_p->user->suser, source_p->user->suser);
		svc_notice(source_p, "Services",
		           "You are already identified as \2%s\2.",
		           source_p->user->suser);
		return;
	}

	struct svc_account *acct   = NULL;
	struct oper_conf   *oper_p = NULL;

	if(!svc_authenticate_password(account, password, &acct, &oper_p)
	   || acct == NULL)
	{
		svc_notice(source_p, "Services",
		           "Invalid account name or password.");
		return;
	}

	if(acct->flags & ACCT_SUSPENDED)
	{
		svc_notice(source_p, "Services",
		           "This account has been suspended.");
		return;
	}

	if(acct->flags & ACCT_SASLONLY)
	{
		svc_notice(source_p, "Services",
		           "This account requires SASL authentication. "
		           "Please use SASL PLAIN instead of IDENTIFY.");
		return;
	}

	/* Mark client as identified */
	rb_strlcpy(source_p->user->suser, acct->name,
	           sizeof(source_p->user->suser));

	/* Propagate to other servers */
	sendto_server(NULL, NULL, CAP_ENCAP, NOCAPS,
	              ":%s ENCAP * LOGIN %s",
	              use_id(source_p), source_p->user->suser);

	/* RPL_LOGGEDIN (900) */
	sendto_one(source_p, form_str(RPL_LOGGEDIN),
	           me.name, source_p->name,
	           source_p->name, source_p->username, source_p->host,
	           acct->name, acct->name);

	/* Oper up if account links to an oper block, unless suppressed */
	if(oper_p != NULL && !noprivs)
		oper_up(source_p, oper_p);
	else if(oper_p != NULL && noprivs)
		svc_notice(source_p, "Services",
		           "Operator privileges suppressed. Use OPER to activate them.");

	/* Apply services vhost */
	if(!EmptyString(acct->vhost))
	{
		sendto_server(NULL, NULL, CAP_EUID | CAP_TS6, NOCAPS,
		              ":%s CHGHOST %s :%s",
		              use_id(&me), use_id(source_p), acct->vhost);
		sendto_server(NULL, NULL, CAP_TS6, CAP_EUID,
		              ":%s ENCAP * CHGHOST %s :%s",
		              use_id(&me), use_id(source_p), acct->vhost);
		change_nick_user_host(source_p,
		                      source_p->name, source_p->username,
		                      acct->vhost, 0, "Changing host");
		SetDynSpoof(source_p);
		sendto_one_numeric(source_p, RPL_HOSTHIDDEN,
		                   "%s :is now your hidden host (set by services)",
		                   source_p->host);
	}

	svc_memo_deliver_notice(source_p, acct);

	svc_notice(source_p, "Services",
	           "You are now identified as \2%s\2.", acct->name);
}

/* =========================================================================
 * Main dispatch
 * ========================================================================= */

static void
m_identify(struct MsgBuf *msgbuf_p, struct Client *client_p,
           struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if(!IsPerson(source_p))
		return;

	/*
	 * Route based on first parameter:
	 *   - Starts with '#' or '&' → IRCX channel key IDENTIFY
	 *   - Otherwise              → Services account IDENTIFY
	 *                             (requires services to be enabled)
	 */
	if(parc >= 2 && IsChanPrefix(parv[1][0]))
	{
		/* IRCX form: IDENTIFY #channel <key> */
		if(parc < 3)
		{
			sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			           me.name, source_p->name, "IDENTIFY");
			return;
		}
		m_identify_channel(source_p, parv[1], parv[2]);
		return;
	}

	/* Services account form */
	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
		           me.name, source_p->name, "IDENTIFY");
		return;
	}

	/* Optional trailing -noprivs flag suppresses automatic oper-up */
	bool noprivs = (parc >= 2 &&
	                !rb_strcasecmp(parv[parc - 1], "-noprivs"));
	int effective_parc = noprivs ? parc - 1 : parc;

	const char *account, *password;
	if(effective_parc >= 3)
	{
		account  = parv[1];
		password = parv[2];
	}
	else
	{
		account  = source_p->name;
		password = parv[1];
	}

	m_identify_account(source_p, account, password, noprivs);
}
