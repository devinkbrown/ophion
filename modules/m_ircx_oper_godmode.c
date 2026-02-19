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
	"Adds user mode +G (god mode): operator override for all channel operations";

static void h_godmode_umode_changed(void *data);
static void h_godmode_channel_access(void *data);
static void h_godmode_can_join(void *data);
static void h_godmode_can_kick(void *data);
static void h_godmode_can_send(void *data);
static void h_godmode_prop_chan_write(void *data);
static void h_godmode_prop_match(void *data);

mapi_hfn_list_av1 godmode_hfnlist[] = {
	{ "umode_changed", (hookfn) h_godmode_umode_changed },
	{ "get_channel_access", (hookfn) h_godmode_channel_access, HOOK_HIGHEST },
	{ "can_join", (hookfn) h_godmode_can_join, HOOK_HIGHEST },
	{ "can_kick", (hookfn) h_godmode_can_kick, HOOK_HIGHEST },
	{ "can_send", (hookfn) h_godmode_can_send, HOOK_HIGHEST },
	{ "prop_chan_write", (hookfn) h_godmode_prop_chan_write, HOOK_HIGHEST },
	{ "prop_match", (hookfn) h_godmode_prop_match, HOOK_HIGHEST },
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
 * can_kick hook: allow god mode users to kick anyone.
 */
static void
h_godmode_can_kick(void *vdata)
{
	hook_data_channel_approval *data = (hook_data_channel_approval *)vdata;

	if (!IsGodMode(data->client))
		return;

	data->approved = 1;

	sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
		"%s is using god mode on %s (KICK %s)",
		get_oper_name(data->client), data->chptr->chname, data->target->name);
}

/*
 * can_send hook: allow god mode users to send to any channel.
 */
static void
h_godmode_can_send(void *vdata)
{
	hook_data_channel_approval *data = (hook_data_channel_approval *)vdata;

	if (data->dir == MODE_QUERY)
		return;

	if (data->approved == CAN_SEND_NONOP || data->approved == CAN_SEND_OPV)
		return;

	if (!IsGodMode(data->client))
		return;

	data->approved = CAN_SEND_OPV;
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
