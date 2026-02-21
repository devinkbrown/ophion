/*
 * modules/m_cregister.c — CREGISTER and CDROP commands
 *
 * CREGISTER <#channel>  — register a channel
 * CDROP <#channel>      — drop a channel registration
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

static const char cregister_desc[] =
	"Provides CREGISTER and CDROP commands for channel registration";

static void m_cregister(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void m_cdrop(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message cregister_msgtab = {
	"CREGISTER", 0, 0, 0, 0,
	{mg_unreg, {m_cregister, 2}, mg_ignore, mg_ignore, mg_ignore, {m_cregister, 2}}
};

struct Message cdrop_msgtab = {
	"CDROP", 0, 0, 0, 0,
	{mg_unreg, {m_cdrop, 2}, mg_ignore, mg_ignore, mg_ignore, {m_cdrop, 2}}
};

mapi_clist_av1 cregister_clist[] = {
	&cregister_msgtab, &cdrop_msgtab, NULL
};

DECLARE_MODULE_AV2(cregister, NULL, NULL, cregister_clist, NULL, NULL, NULL, NULL, cregister_desc);

/*
 * m_cregister - CREGISTER <#channel>
 *
 * Register a channel.  The caller must be identified, a channel op or
 * higher in the (already-existing) channel, and the channel must not
 * already be registered.
 */
static void
m_cregister(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *chname;
	struct Channel *chptr;
	struct membership *msptr;
	struct svc_chanreg *reg;

	if (!services.enabled)
	{
		svc_notice(source_p, "ChanServ", "Services are not enabled on this server.");
		return;
	}

	/* Must be identified */
	if (EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "ChanServ",
			"You must be identified to an account to register a channel.");
		return;
	}

	chname = parv[1];

	if (!IsChannelName(chname))
	{
		svc_notice(source_p, "ChanServ", "%s is not a valid channel name.", chname);
		return;
	}

	chptr = find_channel(chname);
	if (chptr == NULL)
	{
		svc_notice(source_p, "ChanServ",
			"Channel %s does not exist; join it first.", chname);
		return;
	}

	/* Must be an op or higher */
	msptr = find_channel_membership(chptr, source_p);
	if (msptr == NULL || !is_chanop(msptr))
	{
		svc_notice(source_p, "ChanServ",
			"You must be a channel operator in %s to register it.", chname);
		return;
	}

	/* Must not be already registered */
	if (svc_chanreg_find(chptr->chname) != NULL)
	{
		svc_notice(source_p, "ChanServ",
			"Channel %s is already registered.", chptr->chname);
		return;
	}

	/* Create the registration */
	reg = svc_chanreg_create(chptr->chname, source_p->user->suser);
	if (reg == NULL)
	{
		svc_notice(source_p, "ChanServ",
			"An internal error occurred; please try again later.");
		return;
	}

	/* Copy current topic if any */
	if (chptr->topic != NULL && *chptr->topic != '\0')
	{
		rb_strlcpy(reg->topic, chptr->topic, sizeof(reg->topic));
		if (chptr->topic_info != NULL)
			rb_strlcpy(reg->topic_setter, chptr->topic_info, sizeof(reg->topic_setter));
		reg->topic_ts = chptr->topic_time;
	}

	reg->registered_ts = rb_current_time();

	svc_db_chanreg_save(reg);
	svc_sync_chanreg(reg);

	svc_notice(source_p, "ChanServ",
		"Channel %s has been registered to account \2%s\2.",
		chptr->chname, source_p->user->suser);
}

/*
 * m_cdrop - CDROP <#channel>
 *
 * Drop a channel registration.  The caller must be identified and must
 * be the channel founder, or an oper with oper:admin.
 */
static void
m_cdrop(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *chname;
	struct svc_chanreg *reg;
	struct svc_chanaccess *ca;
	rb_dlink_node *ptr;
	bool is_founder = false;

	if (!services.enabled)
	{
		svc_notice(source_p, "ChanServ", "Services are not enabled on this server.");
		return;
	}

	/* Must be identified */
	if (EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "ChanServ",
			"You must be identified to an account to drop a channel.");
		return;
	}

	chname = parv[1];

	if (!IsChannelName(chname))
	{
		svc_notice(source_p, "ChanServ", "%s is not a valid channel name.", chname);
		return;
	}

	reg = svc_chanreg_find(chname);
	if (reg == NULL)
	{
		svc_notice(source_p, "ChanServ",
			"Channel %s is not registered.", chname);
		return;
	}

	/* Check if founder */
	if (irccmp(reg->founder, source_p->user->suser) == 0)
	{
		is_founder = true;
	}
	else
	{
		/* Check access list for CA_FOUNDER */
		RB_DLINK_FOREACH(ptr, reg->access.head)
		{
			ca = ptr->data;
			if ((ca->flags & CA_FOUNDER) &&
			    irccmp(ca->entity, source_p->user->suser) == 0)
			{
				is_founder = true;
				break;
			}
		}
	}

	if (!is_founder && !IsOperAdmin(source_p))
	{
		svc_notice(source_p, "ChanServ",
			"You are not the founder of %s.", chname);
		return;
	}

	/* Warn and drop */
	svc_notice(source_p, "ChanServ",
		"Dropping registration for channel \2%s\2 (was registered to \2%s\2).",
		reg->channel, reg->founder);

	/* Remove from DB and propagate */
	svc_db_chanreg_delete(reg->channel);
	svc_sync_chandrop(reg->channel);

	/* Remove from in-memory dict */
	rb_radixtree_delete(svc_chanreg_dict, reg->channel);
	svc_chanreg_free(reg);
}
