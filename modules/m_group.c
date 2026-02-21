/*
 * modules/m_group.c — Services GROUP and UNGROUP commands
 *
 * GROUP: Associate the sender's current nick with their identified account.
 *
 *   Syntax: GROUP
 *
 *   - Sender must be identified.
 *   - Current nick must not already be a registered nick.
 *   - Account may not already have services.maxnicks grouped nicks.
 *
 * UNGROUP: Remove a nick from the sender's account group.
 *
 *   Syntax: UNGROUP <nick>
 *
 *   - Sender must be identified.
 *   - <nick> must be in the account's nick group.
 *   - The primary nick (same as account name) cannot be ungrouped.
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

static const char group_desc[] =
	"Services GROUP and UNGROUP commands — manage grouped nicks on an account";

static void m_group(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void m_ungroup(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message group_msgtab = {
	"GROUP", 0, 0, 0, 0,
	{mg_unreg, {m_group, 1}, mg_ignore, mg_ignore, mg_ignore, {m_group, 1}}
};

struct Message ungroup_msgtab = {
	"UNGROUP", 0, 0, 0, 0,
	{mg_unreg, {m_ungroup, 2}, mg_ignore, mg_ignore, mg_ignore, {m_ungroup, 2}}
};

mapi_clist_av1 group_clist[] = { &group_msgtab, &ungroup_msgtab, NULL };

DECLARE_MODULE_AV2(m_group, NULL, NULL, group_clist, NULL, NULL, NULL, NULL, group_desc);

/* ---- GROUP handler ------------------------------------------------------ */

/*
 * m_group — GROUP
 *
 * Group the sender's current nick to their identified account.
 */
static void
m_group(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;
	(void)parc;
	(void)parv;

	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "GROUP");
		return;
	}

	if(!IsPerson(source_p))
		return;

	/* Must be identified. */
	if(EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "Services",
			"You must be identified to use GROUP.");
		return;
	}

	struct svc_account *acct = svc_account_find(source_p->user->suser);
	if(acct == NULL)
	{
		svc_notice(source_p, "Services",
			"Internal error: could not find your account record.");
		return;
	}

	const char *nick = source_p->name;

	/* Nick must not already be registered. */
	if(svc_account_find(nick) != NULL || svc_account_find_nick(nick) != NULL)
	{
		svc_notice(source_p, "Services",
			"The nick \2%s\2 is already registered.", nick);
		return;
	}

	/* Check nick group limit. */
	if(services.maxnicks > 0 &&
	   (int)rb_dlink_list_length(&acct->nicks) >= services.maxnicks)
	{
		svc_notice(source_p, "Services",
			"Your account has reached the maximum number of "
			"grouped nicks (%d).", services.maxnicks);
		return;
	}

	/* Add the nick to the group. */
	time_t now = rb_current_time();
	if(!svc_db_nick_add(nick, acct->name))
	{
		svc_notice(source_p, "Services",
			"Internal error: could not add nick to group.");
		return;
	}

	/* Propagate just the nick add; no need to burst the full account. */
	svc_sync_nick_group(nick, acct->name, now);

	svc_notice(source_p, "Services",
		"Nick \2%s\2 has been added to your account group.", nick);
}

/* ---- UNGROUP handler ---------------------------------------------------- */

/*
 * m_ungroup — UNGROUP <nick>
 *
 * Remove a nick from the sender's account group.
 */
static void
m_ungroup(struct MsgBuf *msgbuf_p, struct Client *client_p,
	  struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "UNGROUP");
		return;
	}

	if(!IsPerson(source_p))
		return;

	/* Must be identified. */
	if(EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "Services",
			"You must be identified to use UNGROUP.");
		return;
	}

	const char *nick = parv[1];

	/* Cannot ungroup the primary nick. */
	if(irccmp(nick, source_p->user->suser) == 0)
	{
		svc_notice(source_p, "Services",
			"You cannot ungroup the primary nick of your account. "
			"Drop the account instead if you wish to free it.");
		return;
	}

	struct svc_account *acct = svc_account_find(source_p->user->suser);
	if(acct == NULL)
	{
		svc_notice(source_p, "Services",
			"Internal error: could not find your account record.");
		return;
	}

	/* Verify the nick belongs to this account. */
	bool found = false;
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, acct->nicks.head)
	{
		struct svc_nick *sn = ptr->data;
		if(irccmp(sn->nick, nick) == 0)
		{
			found = true;
			break;
		}
	}

	if(!found)
	{
		svc_notice(source_p, "Services",
			"Nick \2%s\2 is not grouped to your account.", nick);
		return;
	}

	/* Remove the nick. */
	if(!svc_db_nick_delete(nick))
	{
		svc_notice(source_p, "Services",
			"Internal error: could not remove nick from group.");
		return;
	}

	/* Propagate just the nick removal; leaves update their nick index. */
	svc_sync_nick_ungroup(nick);

	svc_notice(source_p, "Services",
		"Nick \2%s\2 has been removed from your account group.", nick);
}
