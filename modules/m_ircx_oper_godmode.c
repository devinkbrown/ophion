/*
 * modules/m_ircx_oper_godmode.c
 *
 * God mode (+G) for IRC operators.  When enabled, the operator can:
 *
 *   - Join any channel, ignoring bans, keys, invite-only, limits, etc.
 *   - Change any channel mode even without being a member or op.
 *   - Kick any user from any channel.
 *   - Send to any channel regardless of moderation or bans.
 *   - Modify any channel PROP (property) from outside the channel.
 *   - Modify any channel ACCESS entry from outside the channel.
 *
 * Requires the "oper:god" privilege in the operator's privset.
 *
 * All god mode actions are logged to the oper snomask so they can be
 * audited.  God mode has no timeout -- it stays active until the oper
 * removes it or de-opers.
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "hash.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"
#include "privilege.h"
#include "s_newconf.h"
#include "channel.h"
#include "propertyset.h"

static const char godmode_desc[] =
	"Adds user mode +G (god mode): operator override for all channel operations; "
	"also provides automatic oper protection (kick immunity, auto-+q on join, and "
	"moderation bypass) for all O-lined users when enabled via ircd.conf";

static void h_godmode_umode_changed(void *data);
static void h_godmode_channel_access(void *data);
static void h_godmode_can_join(void *data);
static void h_godmode_can_kick(void *data);
static void h_godmode_can_send(void *data);
static void h_godmode_channel_join(void *data);
static void h_godmode_prop_chan_write(void *data);
static void h_godmode_prop_match(void *data);

mapi_hfn_list_av1 godmode_hfnlist[] = {
	{ "umode_changed",       (hookfn) h_godmode_umode_changed                   },
	{ "get_channel_access",  (hookfn) h_godmode_channel_access, HOOK_HIGHEST     },
	{ "can_join",            (hookfn) h_godmode_can_join,       HOOK_HIGHEST     },
	/* HOOK_HIGHEST so oper protection fires AFTER lower-priority hooks. */
	{ "can_kick",            (hookfn) h_godmode_can_kick,       HOOK_HIGHEST     },
	{ "can_send",            (hookfn) h_godmode_can_send,       HOOK_HIGHEST     },
	{ "channel_join",        (hookfn) h_godmode_channel_join                     },
	{ "prop_chan_write",     (hookfn) h_godmode_prop_chan_write, HOOK_HIGHEST     },
	{ "prop_match",          (hookfn) h_godmode_prop_match,     HOOK_HIGHEST     },
	{ NULL, NULL }
};

#define IsGodMode(x)	(user_modes['G'] && ((x)->umodes & user_modes['G']))

static void
h_godmode_umode_changed(void *vdata)
{
	hook_data_umode_changed *data = (hook_data_umode_changed *)vdata;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	/* de-oper clears god mode */
	if (data->oldumodes & UMODE_OPER && !IsOper(source_p))
		source_p->umodes &= ~user_modes['G'];

	/* setting +G requires oper:god privilege */
	if ((source_p->umodes & user_modes['G']) && !(data->oldumodes & user_modes['G']))
	{
		if (!HasPrivilege(source_p, "oper:god"))
		{
			sendto_one_notice(source_p, ":*** You need oper:god privilege for +G");
			source_p->umodes &= ~user_modes['G'];
			return;
		}

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s (%s@%s) has enabled god mode (+G)",
			source_p->name, source_p->username, source_p->host);
	}
	else if (!(source_p->umodes & user_modes['G']) && (data->oldumodes & user_modes['G']))
	{
		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s (%s@%s) has disabled god mode (-G)",
			source_p->name, source_p->username, source_p->host);
	}
}

/*
 * get_channel_access hook: grant CHFL_ADMIN level to god mode users.
 * This allows mode changes, topic changes, etc. even without membership.
 */
static void
h_godmode_channel_access(void *vdata)
{
	hook_data_channel_approval *data = (hook_data_channel_approval *)vdata;

	if (data->dir == MODE_QUERY)
		return;

	if (data->approved >= CHFL_ADMIN)
		return;

	if (!IsGodMode(data->client))
		return;

	data->approved = CHFL_ADMIN;

	if (data->modestr)
		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s is using god mode on %s (mode: %s)",
			get_oper_name(data->client), data->chptr->chname, data->modestr);
}

/*
 * can_join hook: bypass all join restrictions for god mode users.
 */
static void
h_godmode_can_join(void *vdata)
{
	hook_data_channel *data = (hook_data_channel *)vdata;

	if (data->approved == 0)
		return;

	if (!IsGodMode(data->client))
		return;

	data->approved = 0;

	sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
		"%s is using god mode on %s (join override)",
		get_oper_name(data->client), data->chptr->chname);
}

/*
 * can_kick hook — two responsibilities:
 *
 * 1. Oper kick protection (config flag):
 *    When oper_kick_protection is enabled in ircd.conf, IRC operators and
 *    admins (O-lined users) cannot be kicked from channels by non-opers.
 *    The kick is denied with a notice to the kicker, and the attempt is
 *    logged to the oper snomask.  An IRC oper CAN still kick another IRC
 *    oper (or god mode bypasses this).
 *
 * 2. God mode (explicit +G umode):
 *    God mode users can kick anyone, including other opers, ignoring the
 *    oper_kick_protection flag.  This is logged for audit purposes.
 *
 * Note: this hook fires only for local clients (MyClient check is in
 * m_kick.c).  Server-sourced kicks (e.g. from ChanServ) are blocked
 * by a direct check added to m_kick.c.
 */
static void
h_godmode_can_kick(void *vdata)
{
	hook_data_channel_approval *data = (hook_data_channel_approval *)vdata;

	/*
	 * Oper kick protection: a non-oper cannot kick an IRC operator or
	 * admin.  God mode overrides this (handled below).
	 */
	if (ConfigFileEntry.oper_kick_protection &&
	    (IsOper(data->target) || IsAdmin(data->target)) &&
	    !(IsOper(data->client) || IsAdmin(data->client)))
	{
		sendto_one_numeric(data->client, ERR_ISCHANSERVICE,
			"%s %s :IRC operators cannot be kicked from channels.",
			data->target->name, data->chptr->chname);
		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s attempted to kick oper %s from %s (blocked: oper_kick_protection)",
			data->client->name, data->target->name, data->chptr->chname);
		data->approved = 0;
		return;
	}

	/* God mode: allow the god mode user to kick anyone. */
	if (!IsGodMode(data->client))
		return;

	data->approved = 1;

	sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
		"%s is using god mode on %s (KICK %s)",
		get_oper_name(data->client), data->chptr->chname, data->target->name);
}

/*
 * can_send hook — two responsibilities:
 *
 * 1. Oper moderation bypass (config flag):
 *    When oper_kick_protection is enabled, all IRC opers and admins can
 *    send to any channel, overriding +m (moderated) and +n (no external
 *    messages) restrictions.  This gives opers "full protection in white"
 *    — they can always speak in any channel they are in or monitoring.
 *
 * 2. God mode (explicit +G umode):
 *    God mode users can always send to any channel (existing behaviour).
 */
static void
h_godmode_can_send(void *vdata)
{
	hook_data_channel_approval *data = (hook_data_channel_approval *)vdata;

	if (data->dir == MODE_QUERY)
		return;

	if (data->approved == CAN_SEND_NONOP || data->approved == CAN_SEND_OPV)
		return;

	/* God mode: unrestricted send. */
	if (IsGodMode(data->client))
	{
		data->approved = CAN_SEND_OPV;
		return;
	}

	/*
	 * Oper moderation bypass: when oper_kick_protection is set, all
	 * O-lined users can override channel send restrictions (+m, +n, etc.).
	 */
	if (ConfigFileEntry.oper_kick_protection &&
	    (IsOper(data->client) || IsAdmin(data->client)))
	{
		data->approved = CAN_SEND_OPV;
	}
}

/*
 * channel_join hook — auto-promote IRC operators on channel join.
 *
 * When oper_auto_op is enabled in ircd.conf, any O-lined user (IsOper or
 * IsAdmin) joining a channel is automatically granted channel-admin status
 * (+q / CHFL_ADMIN).  This applies only to local clients; remote opers'
 * status is propagated when their home server applies the same rule.
 *
 * Explicit god mode (+G) also triggers the auto-promotion regardless of the
 * config flag, since god mode operators should always have elevated status.
 */
static void
h_godmode_channel_join(void *vdata)
{
	hook_data_channel_activity *data = vdata;
	struct Channel *chptr = data->chptr;
	struct Client *source_p = data->client;
	struct membership *msptr;

	if (!MyClient(source_p))
		return;

	/* Only proceed if oper_auto_op is set or the user has god mode. */
	if (!ConfigFileEntry.oper_auto_op && !IsGodMode(source_p))
		return;

	/* Must be an O-lined user (god mode always implies oper). */
	if (!(IsOper(source_p) || IsAdmin(source_p)))
		return;

	msptr = find_channel_membership(chptr, source_p);
	if (msptr == NULL)
		return;

	if (is_admin(msptr))
		return; /* already has +q */

	/* All IRC operators receive +q (channel admin status) on join. */
	msptr->flags |= CHFL_ADMIN;

	sendto_channel_local(source_p, ALL_MEMBERS, chptr,
		":%s MODE %s +q %s",
		me.name, chptr->chname, source_p->name);
	sendto_server(NULL, chptr, CAP_TS6, NOCAPS,
		":%s TMODE %ld %s +q %s",
		me.id, (long)chptr->channelts,
		chptr->chname, use_id(source_p));
}

/*
 * prop_chan_write hook: allow god mode users to write any channel property.
 */
static void
h_godmode_prop_chan_write(void *vdata)
{
	hook_data_prop_activity *data = (hook_data_prop_activity *)vdata;

	if (data->approved)
		return;

	if (!IsGodMode(data->client))
		return;

	data->approved = 1;
}

/*
 * prop_match hook: for god mode users, override the access level and grant
 * write permission for channel properties even without channel membership.
 */
static void
h_godmode_prop_match(void *vdata)
{
	struct PropMatch *prop_match = (struct PropMatch *)vdata;

	if (!IsChanPrefix(*prop_match->target_name))
		return;

	if (!IsGodMode(prop_match->source_p))
		return;

	/* elevate access level to admin */
	prop_match->alevel = CHFL_ADMIN;

	/* grant write access if requested */
	if (prop_match->match_request == PROP_WRITE)
		prop_match->match_grant = PROP_WRITE;
}

static int
_modinit(void)
{
	user_modes['G'] = find_umode_slot();
	construct_umodebuf();

	return 0;
}

static void
_moddeinit(void)
{
	user_modes['G'] = 0;
	construct_umodebuf();
}

DECLARE_MODULE_AV2(ircx_oper_godmode, _modinit, _moddeinit, NULL, NULL,
			godmode_hfnlist, NULL, NULL, godmode_desc);
