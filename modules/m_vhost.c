/*
 * modules/m_vhost.c — VHOST and VHOFFER commands (HostServ)
 *
 * VHOST REQUEST <vhost>   — request a vhost (notifies opers)
 * VHOST TAKE <vhost>      — take an offered vhost
 * VHOST OFF               — remove current vhost / restore original host
 *
 * VHOFFER <vhost>         — oper: add a vhost to the offer list
 * VHOFFERLIST             — list offered vhosts
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
#include "snomask.h"
#include "s_serv.h"
#include "s_user.h"

static const char vhost_desc[] =
	"Provides VHOST, VHOFFER, and VHOFFERLIST commands for virtual hostname management";

static void m_vhost      (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void mo_vhoffer   (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void m_vhofferlist(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message vhost_msgtab = {
	"VHOST", 0, 0, 0, 0,
	{mg_unreg, {m_vhost, 2}, mg_ignore, mg_ignore, mg_ignore, {m_vhost, 2}}
};

struct Message vhoffer_msgtab = {
	"VHOFFER", 0, 0, 0, 0,
	{mg_unreg, {mo_vhoffer, 2}, mg_ignore, mg_ignore, mg_ignore, {mo_vhoffer, 2}}
};

struct Message vhofferlist_msgtab = {
	"VHOFFERLIST", 0, 0, 0, 0,
	{mg_unreg, {m_vhofferlist, 1}, mg_ignore, mg_ignore, mg_ignore, {m_vhofferlist, 1}}
};

mapi_clist_av1 vhost_clist[] = {
	&vhost_msgtab, &vhoffer_msgtab, &vhofferlist_msgtab, NULL
};

DECLARE_MODULE_AV2(vhost, NULL, NULL, vhost_clist, NULL, NULL, NULL, NULL, vhost_desc);

/* -------------------------------------------------------------------------
 * Validate a vhost string.
 * Must match [a-zA-Z0-9.-]+ and must not be a bare IP address.
 * Returns true if valid.
 * ------------------------------------------------------------------------- */
static bool
valid_vhost(const char *vhost)
{
	const char *p;
	bool has_dot    = false;
	bool all_digits_or_dot = true;

	if (vhost == NULL || *vhost == '\0')
		return false;

	/* Must start and end with alnum */
	if (!isalnum((unsigned char) *vhost))
		return false;

	for (p = vhost; *p != '\0'; p++)
	{
		unsigned char c = (unsigned char) *p;

		if (!isalnum(c) && c != '.' && c != '-')
			return false;

		if (c == '.')
			has_dot = true;

		if (!isdigit(c) && c != '.')
			all_digits_or_dot = false;
	}

	/* Must contain at least one dot to look like a hostname */
	if (!has_dot)
		return false;

	/* Reject bare IP addresses (all digits and dots) */
	if (all_digits_or_dot)
		return false;

	/* Last char must be alnum */
	if (!isalnum((unsigned char) *(p - 1)))
		return false;

	return true;
}

/* -------------------------------------------------------------------------
 * Apply a vhost to a locally-connected client using the same pattern as
 * m_chghost.c: change_nick_user_host + CHGHOST (EUID) / ENCAP CHGHOST
 * (non-EUID) propagation.
 * ------------------------------------------------------------------------- */
static void
apply_vhost_to_client(struct Client *client_p, const char *new_host)
{
	if (!MyClient(client_p))
		return;

	change_nick_user_host(client_p, client_p->name, client_p->username,
		new_host, 0, "Changing vhost");

	if (irccmp(client_p->host, client_p->orighost))
	{
		SetDynSpoof(client_p);
		sendto_one_numeric(client_p, RPL_HOSTHIDDEN,
			"%s :is now your hidden host (set by services)",
			client_p->host);
	}
	else
	{
		ClearDynSpoof(client_p);
		sendto_one_numeric(client_p, RPL_HOSTHIDDEN,
			"%s :hostname reset by services", client_p->host);
	}

	/* Propagate CHGHOST to other servers */
	sendto_server(NULL, NULL, CAP_EUID | CAP_TS6, NOCAPS,
		":%s CHGHOST %s %s",
		use_id(&me), use_id(client_p), new_host);
	sendto_server(NULL, NULL, CAP_TS6, CAP_EUID,
		":%s ENCAP * CHGHOST %s :%s",
		use_id(&me), use_id(client_p), new_host);
}

/* -------------------------------------------------------------------------
 * VHOST REQUEST <vhost>
 * ------------------------------------------------------------------------- */
static void
vhost_request(struct Client *source_p, const char *vhost)
{
	struct svc_account *acct;

	if (!valid_vhost(vhost))
	{
		svc_notice(source_p, "HostServ",
			"\2%s\2 is not a valid virtual hostname.  "
			"Use only letters, digits, dots and hyphens.", vhost);
		return;
	}

	acct = svc_account_find(source_p->user->suser);
	if (acct == NULL)
	{
		svc_notice(source_p, "HostServ",
			"Could not locate your account.  Please re-identify.");
		return;
	}

	/* Notify opers */
	sendto_realops_snomask(SNO_GENERAL, L_OPER,
		"Vhost request from account \2%s\2 (nick: %s): \2%s\2",
		acct->name, source_p->name, vhost);

	svc_notice(source_p, "HostServ",
		"Your vhost request for \2%s\2 has been submitted for review. "
		"An IRC operator will process it shortly.", vhost);
}

/* -------------------------------------------------------------------------
 * VHOST TAKE <vhost>
 * Take a vhost that has been offered via VHOFFER.
 * ------------------------------------------------------------------------- */
static void
vhost_take(struct Client *source_p, const char *vhost)
{
	struct svc_account *acct;
	rb_dlink_list offers;
	rb_dlink_node *ptr, *next_ptr;
	bool found = false;

	acct = svc_account_find(source_p->user->suser);
	if (acct == NULL)
	{
		svc_notice(source_p, "HostServ",
			"Could not locate your account.  Please re-identify.");
		return;
	}

	memset(&offers, 0, sizeof(offers));
	if (!svc_db_vhost_offers_load(&offers))
	{
		svc_notice(source_p, "HostServ",
			"Could not load vhost offers (database error).");
		return;
	}

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, offers.head)
	{
		struct svc_vhost_offer *o = ptr->data;
		if (irccmp(o->vhost, vhost) == 0)
		{
			found = true;
			rb_dlinkDelete(ptr, &offers);
			rb_free(o);
			break;
		}
		else
		{
			rb_dlinkDelete(ptr, &offers);
			rb_free(o);
		}
	}

	/* Free remaining entries */
	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, offers.head)
	{
		struct svc_vhost_offer *o = ptr->data;
		rb_dlinkDelete(ptr, &offers);
		rb_free(o);
	}

	if (!found)
	{
		svc_notice(source_p, "HostServ",
			"\2%s\2 is not in the vhost offer list.  "
			"Use VHOFFERLIST to see available vhosts.", vhost);
		return;
	}

	/* Store in account */
	rb_strlcpy(acct->vhost, vhost, sizeof(acct->vhost));
	svc_db_account_save(acct);
	svc_sync_account_reg(acct);

	/* Remove offer from DB */
	svc_db_vhost_offer_delete(vhost);

	/* Apply to online client */
	apply_vhost_to_client(source_p, vhost);

	svc_notice(source_p, "HostServ",
		"Vhost \2%s\2 activated.", vhost);
}

/* -------------------------------------------------------------------------
 * VHOST OFF
 * Remove current vhost and restore original hostname.
 * ------------------------------------------------------------------------- */
static void
vhost_off(struct Client *source_p)
{
	struct svc_account *acct;

	acct = svc_account_find(source_p->user->suser);
	if (acct == NULL)
	{
		svc_notice(source_p, "HostServ",
			"Could not locate your account.  Please re-identify.");
		return;
	}

	if (acct->vhost[0] == '\0')
	{
		svc_notice(source_p, "HostServ",
			"You don't have a vhost to remove.");
		return;
	}

	acct->vhost[0] = '\0';
	svc_db_account_save(acct);
	svc_sync_account_reg(acct);

	/* Restore original host */
	apply_vhost_to_client(source_p, source_p->orighost);

	svc_notice(source_p, "HostServ",
		"Vhost removed.  Your original host has been restored.");
}

/* -------------------------------------------------------------------------
 * Main VHOST handler
 * ------------------------------------------------------------------------- */
static void
m_vhost(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *subcmd;

	if (!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "VHOST");
		return;
	}

	if (EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "HostServ",
			"You must be identified to an account to use VHOST.");
		return;
	}

	subcmd = parv[1];

	if (irccmp(subcmd, "REQUEST") == 0)
	{
		if (parc < 3 || EmptyString(parv[2]))
		{
			svc_notice(source_p, "HostServ", "Usage: VHOST REQUEST <vhost>");
			return;
		}
		vhost_request(source_p, parv[2]);
		return;
	}

	if (irccmp(subcmd, "TAKE") == 0)
	{
		if (parc < 3 || EmptyString(parv[2]))
		{
			svc_notice(source_p, "HostServ", "Usage: VHOST TAKE <vhost>");
			return;
		}
		vhost_take(source_p, parv[2]);
		return;
	}

	if (irccmp(subcmd, "OFF") == 0)
	{
		vhost_off(source_p);
		return;
	}

	svc_notice(source_p, "HostServ",
		"Unknown VHOST subcommand: \2%s\2.  Subcommands: REQUEST TAKE OFF", subcmd);
}

/* -------------------------------------------------------------------------
 * VHOFFER <vhost> — oper command: add a vhost to the offer list
 * ------------------------------------------------------------------------- */
static void
mo_vhoffer(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *vhost;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	if (!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "VHOFFER");
		return;
	}

	vhost = parv[1];

	if (!valid_vhost(vhost))
	{
		svc_notice(source_p, "HostServ",
			"\2%s\2 is not a valid vhost.  Use letters, digits, dots and hyphens only.",
			vhost);
		return;
	}

	if (!svc_db_vhost_offer_add(vhost, source_p->name))
	{
		svc_notice(source_p, "HostServ",
			"Failed to add vhost offer (database error).");
		return;
	}

	svc_notice(source_p, "HostServ",
		"Vhost \2%s\2 has been added to the offer list.", vhost);

	sendto_realops_snomask(SNO_GENERAL, L_OPER,
		"Vhost \2%s\2 offered by oper %s", vhost, source_p->name);
}

/* -------------------------------------------------------------------------
 * VHOFFERLIST — list all offered vhosts
 * ------------------------------------------------------------------------- */
static void
m_vhofferlist(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	rb_dlink_list offers;
	rb_dlink_node *ptr, *next_ptr;
	int n = 0;
	struct tm *tm_p;
	char datebuf[32];

	if (!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "VHOFFERLIST");
		return;
	}

	memset(&offers, 0, sizeof(offers));
	if (!svc_db_vhost_offers_load(&offers))
	{
		svc_notice(source_p, "HostServ",
			"Could not load vhost offers (database error).");
		return;
	}

	if (rb_dlink_length(&offers) == 0)
	{
		svc_notice(source_p, "HostServ", "There are no vhosts currently available.");
		return;
	}

	svc_notice(source_p, "HostServ", "Available vhosts:");

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, offers.head)
	{
		struct svc_vhost_offer *o = ptr->data;
		time_t ts = o->offered_ts;
		tm_p = gmtime(&ts);
		strftime(datebuf, sizeof(datebuf), "%Y-%m-%d", tm_p);

		svc_notice(source_p, "HostServ",
			"  %-40s  offered by %-20s on %s",
			o->vhost, o->offered_by, datebuf);

		rb_dlinkDelete(ptr, &offers);
		rb_free(o);
		n++;
	}

	svc_notice(source_p, "HostServ", "%d vhost(s) available.", n);
}
