/*
 * modules/m_certadd.c — Services certificate fingerprint management
 *
 * CERTADD: Add a TLS certificate fingerprint to the current account.
 *
 *   Syntax: CERTADD [<fingerprint>]
 *
 *   - If no fingerprint is given, the client's current connection
 *     fingerprint (client->certfp) is used.
 *   - The fingerprint must contain a ':' prefix (e.g. "cert_sha256:",
 *     "spki_sha256:", etc.).
 *   - The fingerprint must not already be on the account.
 *
 * CERTDEL: Remove a certificate fingerprint from the current account.
 *
 *   Syntax: CERTDEL <fingerprint>
 *
 *   - The fingerprint must currently exist on the account.
 *
 * CERTLIST: List all certificate fingerprints on the current account.
 *
 *   Syntax: CERTLIST
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

static const char certadd_desc[] =
	"Services CERTADD, CERTDEL, CERTLIST commands — manage account certificate fingerprints";

static void m_certadd(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void m_certdel(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void m_certlist(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message certadd_msgtab = {
	"CERTADD", 0, 0, 0, 0,
	{mg_unreg, {m_certadd, 1}, mg_ignore, mg_ignore, mg_ignore, {m_certadd, 1}}
};

struct Message certdel_msgtab = {
	"CERTDEL", 0, 0, 0, 0,
	{mg_unreg, {m_certdel, 2}, mg_ignore, mg_ignore, mg_ignore, {m_certdel, 2}}
};

struct Message certlist_msgtab = {
	"CERTLIST", 0, 0, 0, 0,
	{mg_unreg, {m_certlist, 1}, mg_ignore, mg_ignore, mg_ignore, {m_certlist, 1}}
};

mapi_clist_av1 certadd_clist[] = {
	&certadd_msgtab, &certdel_msgtab, &certlist_msgtab, NULL
};

DECLARE_MODULE_AV2(m_certadd, NULL, NULL, certadd_clist, NULL, NULL, NULL, NULL, certadd_desc);

/* ---- helpers ------------------------------------------------------------ */

/*
 * find_certfp_on_account — scan the account's certfp list for a match.
 * Returns the node pointer if found, NULL otherwise.
 */
static struct svc_certfp *
find_certfp_on_account(struct svc_account *acct, const char *fp)
{
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, acct->certfps.head)
	{
		struct svc_certfp *c = ptr->data;
		if(rb_strcasecmp(c->fingerprint, fp) == 0)
			return c;
	}

	return NULL;
}

/* ---- CERTADD handler ---------------------------------------------------- */

static void
m_certadd(struct MsgBuf *msgbuf_p, struct Client *client_p,
	  struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "CERTADD");
		return;
	}

	if(!IsPerson(source_p))
		return;

	/* Must be identified. */
	if(EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "Services",
			"You must be identified to use CERTADD.");
		return;
	}

	struct svc_account *acct = svc_account_find(source_p->user->suser);
	if(acct == NULL)
	{
		svc_notice(source_p, "Services",
			"Internal error: could not find your account record.");
		return;
	}

	/* Determine the fingerprint to add. */
	const char *fp;

	if(parc >= 2 && !EmptyString(parv[1]))
	{
		/* Caller-supplied fingerprint. */
		fp = parv[1];
	}
	else
	{
		/* Use the client's current connection fingerprint. */
		if(EmptyString(source_p->certfp))
		{
			svc_notice(source_p, "Services",
				"You are not connected with a TLS certificate. "
				"Provide a fingerprint explicitly: CERTADD <fingerprint>");
			return;
		}
		fp = source_p->certfp;
	}

	/* Validate: fingerprint must contain ':' (type prefix). */
	if(strchr(fp, ':') == NULL)
	{
		svc_notice(source_p, "Services",
			"Invalid fingerprint format. "
			"Expected a prefixed fingerprint such as "
			"\"cert_sha256:<hex>\" or \"spki_sha256:<hex>\".");
		return;
	}

	/* Must not already be on the account. */
	if(find_certfp_on_account(acct, fp) != NULL)
	{
		svc_notice(source_p, "Services",
			"That fingerprint is already listed on your account.");
		return;
	}

	/* Persist. */
	if(!svc_db_certfp_add(acct->name, fp))
	{
		svc_notice(source_p, "Services",
			"Internal error: could not add fingerprint.");
		return;
	}

	/* Propagate. */
	svc_sync_account_certfp(acct, fp, true);

	svc_notice(source_p, "Services",
		"Certificate fingerprint \2%s\2 has been added to your account.", fp);
}

/* ---- CERTDEL handler ---------------------------------------------------- */

static void
m_certdel(struct MsgBuf *msgbuf_p, struct Client *client_p,
	  struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "CERTDEL");
		return;
	}

	if(!IsPerson(source_p))
		return;

	if(EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "Services",
			"You must be identified to use CERTDEL.");
		return;
	}

	struct svc_account *acct = svc_account_find(source_p->user->suser);
	if(acct == NULL)
	{
		svc_notice(source_p, "Services",
			"Internal error: could not find your account record.");
		return;
	}

	const char *fp = parv[1];

	/* Verify the fingerprint exists on the account. */
	if(find_certfp_on_account(acct, fp) == NULL)
	{
		svc_notice(source_p, "Services",
			"Fingerprint \2%s\2 is not listed on your account.", fp);
		return;
	}

	/* Persist. */
	if(!svc_db_certfp_delete(acct->name, fp))
	{
		svc_notice(source_p, "Services",
			"Internal error: could not remove fingerprint.");
		return;
	}

	/* Propagate. */
	svc_sync_account_certfp(acct, fp, false);

	svc_notice(source_p, "Services",
		"Certificate fingerprint \2%s\2 has been removed from your account.", fp);
}

/* ---- CERTLIST handler --------------------------------------------------- */

static void
m_certlist(struct MsgBuf *msgbuf_p, struct Client *client_p,
	   struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;
	(void)parc;
	(void)parv;

	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "CERTLIST");
		return;
	}

	if(!IsPerson(source_p))
		return;

	if(EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "Services",
			"You must be identified to use CERTLIST.");
		return;
	}

	struct svc_account *acct = svc_account_find(source_p->user->suser);
	if(acct == NULL)
	{
		svc_notice(source_p, "Services",
			"Internal error: could not find your account record.");
		return;
	}

	if(rb_dlink_list_length(&acct->certfps) == 0)
	{
		svc_notice(source_p, "Services",
			"No certificate fingerprints are registered on your account.");
		return;
	}

	svc_notice(source_p, "Services",
		"Certificate fingerprints for account \2%s\2:", acct->name);

	rb_dlink_node *ptr;
	int n = 1;

	RB_DLINK_FOREACH(ptr, acct->certfps.head)
	{
		struct svc_certfp *c = ptr->data;
		svc_notice(source_p, "Services",
			"  %d. %s", n++, c->fingerprint);
	}

	svc_notice(source_p, "Services",
		"End of certificate fingerprint list.");
}
