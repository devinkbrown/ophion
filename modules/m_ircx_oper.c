/*
 * modules/m_ircx_oper.c
 *
 * Unified IRCX operator tools per draft-pfenning-irc-extensions-04.
 *
 * Provides:
 *   - GAG user mode (+z): silences a user globally (oper-only set/unset)
 *   - OPFORCE command: unified oper channel force command
 *     OPFORCE JOIN <channel>     - force-join a channel (replaces m_ojoin)
 *     OPFORCE OP <channel>       - force-op self on channel (replaces m_opme)
 *     OPFORCE KICK <chan> <nick>  - force-kick (replaces m_okick)
 *     OPFORCE MODE <chan> <modes> - force-mode (replaces m_omode)
 *   - Hooks into message sending to enforce GAG silently
 *   - Server-to-server propagation of GAG via user mode 'z'
 *
 * Per IRCX spec:
 *   - GAG mode is applied by sysop/sysop manager
 *   - User may NOT be notified when GAG is applied
 *   - Server discards all messages from gagged users
 */

#include "stdinc.h"
#include "client.h"
#include "channel.h"
#include "hash.h"
#include "hook.h"
#include "match.h"
#include "msg.h"
#include "modules.h"
#include "numeric.h"
#include "parse.h"
#include "privilege.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"

static const char ircx_oper_desc[] =
	"Provides IRCX operator tools: GAG mode (+z), OPFORCE commands";

static void hook_gag_privmsg_channel(void *vdata);
static void hook_gag_privmsg_user(void *vdata);
static void hook_gag_umode_changed(void *vdata);

mapi_hfn_list_av1 ircx_oper_hfnlist[] = {
	{ "privmsg_channel", (hookfn) hook_gag_privmsg_channel, HOOK_HIGHEST },
	{ "privmsg_user", (hookfn) hook_gag_privmsg_user, HOOK_HIGHEST },
	{ "umode_changed", (hookfn) hook_gag_umode_changed },
	{ NULL, NULL }
};

/*
 * GAG user mode (+z)
 *
 * Per IRCX spec: the server will discard all messages from a user
 * with GAG mode to any other user or to any channel.  The mode is
 * set by sysop/sysop manager (IRC oper) and may not be removed by
 * the user.  The user may not be notified when this mode is applied.
 */
static void
hook_gag_privmsg_channel(void *vdata)
{
	hook_data_privmsg_channel *data = vdata;

	if (IsGagged(data->source_p))
	{
		/* silently discard - per IRCX spec, user is not told */
		data->approved = ERR_CANNOTSENDTOCHAN;
	}
}

static void
hook_gag_privmsg_user(void *vdata)
{
	hook_data_privmsg_user *data = vdata;

	if (IsGagged(data->source_p))
	{
		/* silently discard */
		data->approved = ERR_CANNOTSENDTOUSER;
	}
}

/*
 * Enforce GAG mode restrictions:
 * - Only opers can set +zon others
 * - Non-opers cannot remove +zfrom themselves
 */
static void
hook_gag_umode_changed(void *vdata)
{
	hook_data_umode_changed *data = vdata;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	/* if user just had +zset and isn't an oper, disallow self-set */
	if ((source_p->umodes & user_modes['z']) && !IsOper(source_p))
	{
		/* check if the mode was already on before */
		if (!(data->oldumodes & user_modes['z']))
		{
			/* user tried to set +zon themselves without oper - remove it */
			source_p->umodes &= ~user_modes['z'];
		}
	}

	/* sync FLAGS_GAGGED with user mode */
	if (source_p->umodes & user_modes['z'])
		SetGagged(source_p);
	else if (!(source_p->umodes & user_modes['z']))
	{
		/* only allow oper to remove +z*/
		if ((data->oldumodes & user_modes['z']) && !IsOper(source_p))
		{
			/* re-apply +z, user can't remove it */
			source_p->umodes |= user_modes['z'];
		}
		else
		{
			ClearGagged(source_p);
		}
	}
}

/*
 * GAG command - opers can gag/ungag other users
 * GAG <nick>     - toggle gag on user
 * GAG <nick> ON  - gag user
 * GAG <nick> OFF - ungag user
 */
static void
m_gag(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;

	if (!IsOper(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVILEGES), me.name, source_p->name);
		return;
	}

	if (parc < 2 || EmptyString(parv[1]))
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			me.name, source_p->name, "GAG");
		return;
	}

	target_p = find_named_person(parv[1]);
	if (target_p == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK,
			form_str(ERR_NOSUCHNICK), parv[1]);
		return;
	}

	int set_gag;
	if (parc >= 3 && !rb_strcasecmp(parv[2], "OFF"))
		set_gag = 0;
	else if (parc >= 3 && !rb_strcasecmp(parv[2], "ON"))
		set_gag = 1;
	else
		set_gag = !IsGagged(target_p);	/* toggle */

	if (set_gag)
	{
		SetGagged(target_p);
		if (user_modes['z'])
			target_p->umodes |= user_modes['z'];

		/* propagate to other servers */
		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * GAG %s ON",
			use_id(source_p), use_id(target_p));

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s has gagged %s", get_oper_name(source_p), target_p->name);
		sendto_one_notice(source_p, ":%s is now gagged", target_p->name);
		/* per IRCX spec: user is NOT notified */
	}
	else
	{
		ClearGagged(target_p);
		if (user_modes['z'])
			target_p->umodes &= ~user_modes['z'];

		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * GAG %s OFF",
			use_id(source_p), use_id(target_p));

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s has ungagged %s", get_oper_name(source_p), target_p->name);
		sendto_one_notice(source_p, ":%s is no longer gagged", target_p->name);
	}
}

static void
me_gag(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;

	if (parc < 3)
		return;

	target_p = find_person(parv[1]);
	if (target_p == NULL)
		return;

	if (!rb_strcasecmp(parv[2], "ON"))
	{
		SetGagged(target_p);
		if (user_modes['z'])
			target_p->umodes |= user_modes['z'];
	}
	else
	{
		ClearGagged(target_p);
		if (user_modes['z'])
			target_p->umodes &= ~user_modes['z'];
	}
}

/*
 * OPFORCE - unified oper channel tools
 *
 * OPFORCE JOIN <channel>          - force-join channel
 * OPFORCE OP <channel>            - force-op self on channel
 * OPFORCE KICK <channel> <nick> [reason]  - force-kick user
 * OPFORCE MODE <channel> <modes>  - force set modes
 */
static void
m_opforce(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr;

	if (!IsOper(source_p) || !IsOperAdmin(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVILEGES), me.name, source_p->name);
		return;
	}

	if (parc < 3)
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			me.name, source_p->name, "OPFORCE");
		return;
	}

	if (!rb_strcasecmp(parv[1], "JOIN"))
	{
		/* OPFORCE JOIN <channel> */
		chptr = find_channel(parv[2]);
		if (chptr == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				form_str(ERR_NOSUCHCHANNEL), parv[2]);
			return;
		}

		if (IsMember(source_p, chptr))
		{
			sendto_one_notice(source_p, ":You are already in %s", chptr->chname);
			return;
		}

		add_user_to_channel(chptr, source_p, CHFL_CHANOP);
		send_channel_join(chptr, source_p);
		sendto_channel_local(source_p, ALL_MEMBERS, chptr,
			":%s MODE %s +o %s",
			me.name, chptr->chname, source_p->name);
		sendto_server(NULL, chptr, CAP_TS6, NOCAPS,
			":%s SJOIN %ld %s + :@%s",
			me.id, (long)chptr->channelts,
			chptr->chname, use_id(source_p));

		sendto_wallops_flags(UMODE_WALLOP, &me,
			"OPFORCE: %s force-joined %s",
			get_oper_name(source_p), chptr->chname);
		return;
	}

	if (!rb_strcasecmp(parv[1], "OP"))
	{
		/* OPFORCE OP <channel> */
		chptr = find_channel(parv[2]);
		if (chptr == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				form_str(ERR_NOSUCHCHANNEL), parv[2]);
			return;
		}

		struct membership *msptr = find_channel_membership(chptr, source_p);
		if (msptr == NULL)
		{
			sendto_one_notice(source_p, ":You are not in %s", chptr->chname);
			return;
		}

		if (is_chanop(msptr))
		{
			sendto_one_notice(source_p, ":You are already opped in %s", chptr->chname);
			return;
		}

		msptr->flags |= CHFL_CHANOP;
		sendto_channel_local(source_p, ALL_MEMBERS, chptr,
			":%s MODE %s +o %s",
			me.name, chptr->chname, source_p->name);
		sendto_server(NULL, chptr, CAP_TS6, NOCAPS,
			":%s TMODE %ld %s +o %s",
			me.id, (long)chptr->channelts,
			chptr->chname, use_id(source_p));

		sendto_wallops_flags(UMODE_WALLOP, &me,
			"OPFORCE: %s opped themselves on %s",
			get_oper_name(source_p), chptr->chname);
		return;
	}

	if (!rb_strcasecmp(parv[1], "KICK"))
	{
		/* OPFORCE KICK <channel> <nick> [reason] */
		if (parc < 4)
		{
			sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
				me.name, source_p->name, "OPFORCE KICK");
			return;
		}

		chptr = find_channel(parv[2]);
		if (chptr == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				form_str(ERR_NOSUCHCHANNEL), parv[2]);
			return;
		}

		struct Client *target_p = find_named_person(parv[3]);
		if (target_p == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
				form_str(ERR_NOSUCHNICK), parv[3]);
			return;
		}

		struct membership *target_msptr = find_channel_membership(chptr, target_p);
		if (target_msptr == NULL)
		{
			sendto_one_numeric(source_p, ERR_USERNOTINCHANNEL,
				form_str(ERR_USERNOTINCHANNEL),
				target_p->name, chptr->chname);
			return;
		}

		const char *reason = (parc >= 5 && !EmptyString(parv[4])) ?
			parv[4] : source_p->name;

		sendto_channel_local(source_p, ALL_MEMBERS, chptr,
			":%s KICK %s %s :%s",
			me.name, chptr->chname, target_p->name, reason);
		sendto_server(NULL, chptr, CAP_TS6, NOCAPS,
			":%s KICK %s %s :%s",
			me.id, chptr->chname, use_id(target_p), reason);
		remove_user_from_channel(target_msptr);

		sendto_wallops_flags(UMODE_WALLOP, &me,
			"OPFORCE: %s kicked %s from %s (%s)",
			get_oper_name(source_p), target_p->name,
			chptr->chname, reason);
		return;
	}

	if (!rb_strcasecmp(parv[1], "MODE"))
	{
		/* OPFORCE MODE <channel> <modes> [params] */
		if (parc < 4)
		{
			sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
				me.name, source_p->name, "OPFORCE MODE");
			return;
		}

		chptr = find_channel(parv[2]);
		if (chptr == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				form_str(ERR_NOSUCHCHANNEL), parv[2]);
			return;
		}

		/* pass remaining args to set_channel_mode */
		set_channel_mode(client_p, source_p, chptr, NULL,
			parc - 3, &parv[3]);

		sendto_wallops_flags(UMODE_WALLOP, &me,
			"OPFORCE: %s set modes on %s: %s",
			get_oper_name(source_p), chptr->chname, parv[3]);
		return;
	}

	sendto_one_notice(source_p, ":Usage: OPFORCE {JOIN|OP|KICK|MODE} <channel> [args]");
}

struct Message gag_msgtab = {
	"GAG", 0, 0, 0, 0,
	{mg_unreg, {m_gag, 2}, mg_ignore, mg_ignore, {me_gag, 3}, {m_gag, 2}}
};

struct Message opforce_msgtab = {
	"OPFORCE", 0, 0, 0, 0,
	{mg_unreg, {m_opforce, 3}, mg_ignore, mg_ignore, mg_ignore, {m_opforce, 3}}
};

mapi_clist_av1 ircx_oper_clist[] = { &gag_msgtab, &opforce_msgtab, NULL };

static int
ircx_oper_init(void)
{
	/* register GAG user mode (+z) per IRCX spec section 7.2 */
	user_modes['z'] = find_umode_slot();
	construct_umodebuf();

	return 0;
}

static void
ircx_oper_deinit(void)
{
	user_modes['z'] = 0;
	construct_umodebuf();
}

DECLARE_MODULE_AV2(ircx_oper, ircx_oper_init, ircx_oper_deinit,
	ircx_oper_clist, NULL, ircx_oper_hfnlist, NULL, NULL, ircx_oper_desc);
