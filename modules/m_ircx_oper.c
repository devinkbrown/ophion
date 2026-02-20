/*
 * modules/m_ircx_oper.c
 *
 * Unified IRCX operator tools per draft-pfenning-irc-extensions-04.
 *
 * Provides:
 *   - GAG user mode (+z): silences a user globally (oper-only set/unset)
 *   - OPFORCE command: unified oper channel force command
 *     OPFORCE JOIN <channel>     - force-join a channel
 *     OPFORCE OP <channel>       - force-op self on channel
 *     OPFORCE KICK <chan> <nick>  - force-kick a user
 *     OPFORCE MODE <chan> <modes> - force-set channel modes
 *   - Hooks into message sending to enforce GAG silently
 *   - Server-to-server propagation of GAG via user mode 'z'
 *
 * Per IRCX spec:
 *   - GAG mode is applied by sysop/sysop manager
 *   - User may NOT be notified when GAG is applied
 *   - Server discards all messages from gagged users
 */

#include "stdinc.h"
#include "bandbi.h"
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

/*
 * Persistent GAG list - stores user@host masks that persist across reconnects.
 * Per IRCX spec, gagged users have ALL messages silently discarded.
 */
struct gag_entry {
	char *mask;	/* user@host mask */
	char *setter;	/* who set the gag */
	time_t when;	/* when it was set */
	time_t hold;	/* expiry time (0 = permanent) */
	rb_dlink_node node;
};

static rb_dlink_list gag_list = { NULL, NULL, 0 };

static void hook_gag_privmsg_channel(void *vdata);
static void hook_gag_privmsg_user(void *vdata);
static void hook_gag_umode_changed(void *vdata);
static void hook_gag_new_local_user(void *vdata);
static void hook_gag_burst_finished(void *vdata);
static void hook_gag_bandb_restore(void *vdata);
static void hook_gag_bandb_restore_done(void *vdata);

mapi_hfn_list_av1 ircx_oper_hfnlist[] = {
	{ "privmsg_channel", (hookfn) hook_gag_privmsg_channel, HOOK_HIGHEST },
	{ "privmsg_user", (hookfn) hook_gag_privmsg_user, HOOK_HIGHEST },
	{ "umode_changed", (hookfn) hook_gag_umode_changed },
	{ "new_local_user", (hookfn) hook_gag_new_local_user },
	{ "burst_finished", (hookfn) hook_gag_burst_finished },
	{ "bandb_gag_restore", (hookfn) hook_gag_bandb_restore },
	{ "bandb_gag_restore_done", (hookfn) hook_gag_bandb_restore_done },
	{ NULL, NULL }
};

/* check if a client matches any persistent gag entry */
static struct gag_entry *
find_gag_match(struct Client *client_p)
{
	rb_dlink_node *ptr;
	char buf[USERLEN + HOSTLEN + 2];

	snprintf(buf, sizeof buf, "%s@%s", client_p->username, client_p->host);

	RB_DLINK_FOREACH(ptr, gag_list.head)
	{
		struct gag_entry *ge = ptr->data;

		/* skip expired entries */
		if (ge->hold && ge->hold <= rb_current_time())
			continue;

		if (match(ge->mask, buf))
			return ge;
	}

	/* also check against sockhost (IP) */
	snprintf(buf, sizeof buf, "%s@%s", client_p->username, client_p->sockhost);
	RB_DLINK_FOREACH(ptr, gag_list.head)
	{
		struct gag_entry *ge = ptr->data;

		if (ge->hold && ge->hold <= rb_current_time())
			continue;

		if (match(ge->mask, buf))
			return ge;
	}

	return NULL;
}

/*
 * add_gag_entry - add a gag to the in-memory list and optionally persist it.
 *
 * When persist is true, the entry is written to bandb so it survives a
 * full network restart.  Pass persist=false when restoring from bandb to
 * avoid writing the entry back unnecessarily.
 *
 * The setter name is stored in the bandb "reason" field; the hold timestamp
 * is appended after '|' (oper_reason) so it survives the round-trip through
 * the helper's list response.
 */
static void
add_gag_entry(struct Client *source_p, const char *mask, const char *setter,
              time_t hold, bool persist)
{
	struct gag_entry *ge;

	ge = rb_malloc(sizeof(struct gag_entry));
	ge->mask = rb_strdup(mask);
	ge->setter = rb_strdup(setter);
	ge->when = rb_current_time();
	ge->hold = hold;
	rb_dlinkAdd(ge, &ge->node, &gag_list);

	if(persist)
	{
		char hold_str[32];
		if(hold > 0)
			snprintf(hold_str, sizeof(hold_str), "%ld", (long)hold);
		/*
		 * mask1 = user@host, reason = setter name,
		 * oper_reason = hold timestamp (NULL for permanent).
		 * The "oper" column is populated by get_oper_name(source_p).
		 */
		bandb_add(BANDB_GAG, source_p, mask, NULL,
		          setter, hold > 0 ? hold_str : NULL, 0);
	}
}

static void
remove_gag_entry(const char *mask)
{
	rb_dlink_node *ptr, *next;

	RB_DLINK_FOREACH_SAFE(ptr, next, gag_list.head)
	{
		struct gag_entry *ge = ptr->data;

		if (!irccmp(ge->mask, mask))
		{
			bandb_del(BANDB_GAG, ge->mask, NULL);
			rb_dlinkDelete(&ge->node, &gag_list);
			rb_free(ge->mask);
			rb_free(ge->setter);
			rb_free(ge);
			return;
		}
	}
}

static void
expire_gag_entries(void *unused)
{
	rb_dlink_node *ptr, *next;

	RB_DLINK_FOREACH_SAFE(ptr, next, gag_list.head)
	{
		struct gag_entry *ge = ptr->data;

		if (ge->hold && ge->hold <= rb_current_time())
		{
			bandb_del(BANDB_GAG, ge->mask, NULL);
			rb_dlinkDelete(&ge->node, &gag_list);
			rb_free(ge->mask);
			rb_free(ge->setter);
			rb_free(ge);
		}
	}
}

static struct ev_entry *expire_gag_ev = NULL;

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
 * - Non-opers cannot set +z on themselves
 * - Non-opers cannot remove +z from themselves
 * - GAG flag is always synced with the user mode
 */
static void
hook_gag_umode_changed(void *vdata)
{
	hook_data_umode_changed *data = vdata;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	/* non-oper tried to set +z on themselves - disallow */
	if ((source_p->umodes & user_modes['z']) && !IsOper(source_p))
	{
		if (!(data->oldumodes & user_modes['z']))
		{
			source_p->umodes &= ~user_modes['z'];
			return;
		}
	}

	/* sync FLAGS_GAGGED with user mode */
	if (source_p->umodes & user_modes['z'])
		SetGagged(source_p);
	else if (!(source_p->umodes & user_modes['z']))
	{
		/* only allow oper to remove +z */
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
 * new_local_user hook: check persistent gag list on connect.
 * If a newly registered user matches a stored gag entry, re-apply +z.
 */
static void
hook_gag_new_local_user(void *vdata)
{
	struct Client *source_p = vdata;
	struct gag_entry *ge;

	ge = find_gag_match(source_p);
	if (ge != NULL)
	{
		SetGagged(source_p);
		if (user_modes['z'])
			source_p->umodes |= user_modes['z'];
	}
}

/*
 * GAG command - opers can gag/ungag other users
 * GAG <nick>       - toggle gag on user
 * GAG <nick> ON    - gag user
 * GAG <nick> OFF   - ungag user
 * GAG LIST         - show persistent gag list
 * GAG CLEAR        - clear all persistent gags and ungag all users
 *
 * Gagging is persistent: the user@host mask is stored and checked
 * on reconnect.  Operators cannot gag themselves.
 */
static void
m_gag(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	if (parc < 2 || EmptyString(parv[1]))
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			me.name, source_p->name, "GAG");
		return;
	}

	/* GAG LIST - show all persistent gag entries */
	if (!rb_strcasecmp(parv[1], "LIST"))
	{
		rb_dlink_node *ptr;

		sendto_one_notice(source_p, ":--- Persistent gag list ---");
		RB_DLINK_FOREACH(ptr, gag_list.head)
		{
			struct gag_entry *ge = ptr->data;

			if (ge->hold && ge->hold <= rb_current_time())
				continue;

			if (ge->hold)
				sendto_one_notice(source_p, ":%s (by %s, expires in %lds)",
					ge->mask, ge->setter, (long)(ge->hold - rb_current_time()));
			else
				sendto_one_notice(source_p, ":%s (by %s, permanent)",
					ge->mask, ge->setter);
		}
		sendto_one_notice(source_p, ":--- End of gag list ---");
		return;
	}

	/* GAG CLEAR - remove all persistent gags and ungag all affected users */
	if (!rb_strcasecmp(parv[1], "CLEAR"))
	{
		rb_dlink_node *ptr, *next;

		RB_DLINK_FOREACH_SAFE(ptr, next, gag_list.head)
		{
			struct gag_entry *ge = ptr->data;
			bandb_del(BANDB_GAG, ge->mask, NULL);
			rb_dlinkDelete(&ge->node, &gag_list);
			rb_free(ge->mask);
			rb_free(ge->setter);
			rb_free(ge);
		}

		/* ungag all currently gagged local users */
		RB_DLINK_FOREACH(ptr, lclient_list.head)
		{
			struct Client *client_p = ptr->data;
			if (IsGagged(client_p))
			{
				ClearGagged(client_p);
				if (user_modes['z'])
					client_p->umodes &= ~user_modes['z'];
			}
		}

		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * GAG_CLEAR",
			use_id(source_p));

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s has cleared all gags", get_oper_name(source_p));
		sendto_one_notice(source_p, ":All gags have been cleared");
		return;
	}

	target_p = find_named_person(parv[1]);
	if (target_p == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK,
			form_str(ERR_NOSUCHNICK), parv[1]);
		return;
	}

	/* operators cannot gag themselves */
	if (target_p == source_p)
	{
		sendto_one_notice(source_p, ":You cannot gag yourself");
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
		char mask[USERLEN + HOSTLEN + 2];

		SetGagged(target_p);
		if (user_modes['z'])
			target_p->umodes |= user_modes['z'];

		/* store persistent gag entry by user@host */
		snprintf(mask, sizeof mask, "%s@%s", target_p->username, target_p->host);
		add_gag_entry(source_p, mask, get_oper_name(source_p), 0, true);

		/* propagate to other servers: user mode + persistent entry */
		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * GAG %s ON",
			use_id(source_p), use_id(target_p));
		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * GAG_ADD %s %s 0",
			use_id(source_p), mask, get_oper_name(source_p));

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s has gagged %s (%s)", get_oper_name(source_p), target_p->name, mask);
		sendto_one_notice(source_p, ":%s is now gagged (persistent: %s)", target_p->name, mask);
		/* per IRCX spec: user is NOT notified */
	}
	else
	{
		char mask[USERLEN + HOSTLEN + 2];

		ClearGagged(target_p);
		if (user_modes['z'])
			target_p->umodes &= ~user_modes['z'];

		/* remove persistent gag entry */
		snprintf(mask, sizeof mask, "%s@%s", target_p->username, target_p->host);
		remove_gag_entry(mask);

		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * GAG %s OFF",
			use_id(source_p), use_id(target_p));
		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * GAG_DEL %s",
			use_id(source_p), mask);

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
		char mask[USERLEN + HOSTLEN + 2];

		SetGagged(target_p);
		if (user_modes['z'])
			target_p->umodes |= user_modes['z'];

		/* store persistent gag entry for reconnect enforcement */
		snprintf(mask, sizeof mask, "%s@%s", target_p->username, target_p->host);
		add_gag_entry(source_p, mask, source_p->name, 0, true);
	}
	else
	{
		char mask[USERLEN + HOSTLEN + 2];

		ClearGagged(target_p);
		if (user_modes['z'])
			target_p->umodes &= ~user_modes['z'];

		snprintf(mask, sizeof mask, "%s@%s", target_p->username, target_p->host);
		remove_gag_entry(mask);
	}
}

/* remote GAG_CLEAR: clear all gags on this server */
static void
me_gag_clear(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	rb_dlink_node *ptr, *next;

	/* clear the persistent list, removing each entry from bandb */
	RB_DLINK_FOREACH_SAFE(ptr, next, gag_list.head)
	{
		struct gag_entry *ge = ptr->data;
		bandb_del(BANDB_GAG, ge->mask, NULL);
		rb_dlinkDelete(&ge->node, &gag_list);
		rb_free(ge->mask);
		rb_free(ge->setter);
		rb_free(ge);
	}

	/* ungag all local users */
	RB_DLINK_FOREACH(ptr, lclient_list.head)
	{
		struct Client *cp = ptr->data;
		if (IsGagged(cp))
		{
			ClearGagged(cp);
			if (user_modes['z'])
				cp->umodes &= ~user_modes['z'];
		}
	}
}

/*
 * GAG_ADD ENCAP: sync a persistent gag entry to remote servers.
 * :source ENCAP * GAG_ADD <mask> <setter> <hold>
 */
static void
me_gag_add(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *mask, *setter;
	time_t hold = 0;

	if (parc < 3)
		return;

	mask = parv[1];
	setter = parv[2];
	if (parc >= 4)
		hold = atol(parv[3]);

	/* avoid duplicates */
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, gag_list.head)
	{
		struct gag_entry *ge = ptr->data;
		if (!irccmp(ge->mask, mask))
			return;
	}

	add_gag_entry(source_p, mask, setter, hold, true);
}

/*
 * GAG_DEL ENCAP: remove a persistent gag entry from remote servers.
 * :source ENCAP * GAG_DEL <mask>
 */
static void
me_gag_del(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if (parc < 2)
		return;

	remove_gag_entry(parv[1]);
}

/*
 * hook_gag_bandb_restore - fired once per GAG entry when bandb sends its list
 * in response to the W (bandb_rehash_gags) command.
 *
 * Adds the entry to gag_list without writing it back to bandb (persist=false).
 * Skips entries that have already expired.
 */
static void
hook_gag_bandb_restore(void *vdata)
{
	hook_data_bandb_gag *data = vdata;

	/* skip expired entries */
	if (data->hold > 0 && data->hold <= rb_current_time())
	{
		/* clean it out of bandb while we're here */
		bandb_del(BANDB_GAG, data->mask, NULL);
		return;
	}

	/* skip duplicates (e.g. if bandb_rehash_gags called more than once) */
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, gag_list.head)
	{
		struct gag_entry *ge = ptr->data;
		if (!irccmp(ge->mask, data->mask))
			return;
	}

	add_gag_entry(NULL, data->mask, data->setter, data->hold, false);
}

/*
 * hook_gag_bandb_restore_done - fired after the last GAG entry has been
 * restored from bandb.  At this point gag_list is fully populated from the
 * database, so re-apply GAG flags to any clients that are already connected
 * (relevant for runtime module loads; a no-op during server startup because
 * no clients exist yet).
 */
static void
hook_gag_bandb_restore_done(void *unused)
{
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, lclient_list.head)
	{
		struct Client *cp = ptr->data;

		if (!MyClient(cp) || IsGagged(cp))
			continue;

		if (find_gag_match(cp) != NULL)
		{
			SetGagged(cp);
			if (user_modes['z'])
				cp->umodes |= user_modes['z'];
		}
	}
}

/*
 * burst_finished hook: send all persistent gag entries to newly linked server.
 */
static void
hook_gag_burst_finished(void *vdata)
{
	hook_data_client *hclientinfo = vdata;
	struct Client *server_p = hclientinfo->client;
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, gag_list.head)
	{
		struct gag_entry *ge = ptr->data;

		/* skip expired entries */
		if (ge->hold && ge->hold <= rb_current_time())
			continue;

		sendto_one(server_p, ":%s ENCAP %s GAG_ADD %s %s %ld",
			use_id(&me), server_p->name,
			ge->mask, ge->setter, (long)ge->hold);
	}
}

/*
 * OPFORCE - unified oper channel tools
 *
 * OPFORCE JOIN <channel>          - force-join channel
 * OPFORCE OP <channel>            - force-op self on channel
 * OPFORCE KICK <channel> <nick> [reason]  - force-kick user
 * OPFORCE MODE <channel> <modes>  - force set modes
 * OPFORCE CLOSE <channel> [reason] - mass-kick and destroy channel
 *   If oper has +K (anonkill), kicks show as from "SYSTEM"
 */
static void
m_opforce(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr;

	if (!IsOper(source_p) || !IsOperAdmin(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
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

	if (!rb_strcasecmp(parv[1], "CLOSE"))
	{
		/* OPFORCE CLOSE <channel> [reason]
		 * Mass-kick all users from a channel and destroy it.
		 * Respects +K (anonymous kill mode): if the oper has +K set,
		 * the kick source shows as "SYSTEM" instead of the oper's name.
		 */
		if (parc < 3)
		{
			sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
				me.name, source_p->name, "OPFORCE CLOSE");
			return;
		}

		chptr = find_channel(parv[2]);
		if (chptr == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				form_str(ERR_NOSUCHCHANNEL), parv[2]);
			return;
		}

		const char *reason = (parc >= 4 && !EmptyString(parv[3])) ?
			parv[3] : "Channel closed by server administrator";

		/* determine kick source: anonymous if oper has +K */
		const char *kickfrom;
		const char *kickfrom_id;
		bool anonymous = false;

		if (user_modes['K'] && (source_p->umodes & user_modes['K']))
		{
			kickfrom = me.name;
			kickfrom_id = me.id;
			anonymous = true;
		}
		else
		{
			kickfrom = me.name;
			kickfrom_id = me.id;
		}

		/* kick all members */
		rb_dlink_node *ptr, *next_ptr;
		RB_DLINK_FOREACH_SAFE(ptr, next_ptr, chptr->members.head)
		{
			struct membership *msptr = ptr->data;
			struct Client *target_p = msptr->client_p;

			sendto_channel_local(source_p, ALL_MEMBERS, chptr,
				":%s KICK %s %s :Kicked by %s: %s",
				kickfrom, chptr->chname, target_p->name,
				anonymous ? "SYSTEM" : source_p->name, reason);
			sendto_server(NULL, chptr, CAP_TS6, NOCAPS,
				":%s KICK %s %s :Kicked by %s: %s",
				kickfrom_id, chptr->chname, use_id(target_p),
				anonymous ? "SYSTEM" : source_p->name, reason);
			remove_user_from_channel(msptr);
		}

		sendto_wallops_flags(UMODE_WALLOP, &me,
			"OPFORCE: %s closed channel %s (%s)%s",
			get_oper_name(source_p), parv[2], reason,
			anonymous ? " [anonymous]" : "");

		sendto_one_notice(source_p, ":Channel %s has been closed", parv[2]);
		return;
	}

	sendto_one_notice(source_p, ":Usage: OPFORCE {JOIN|OP|KICK|MODE|CLOSE} <channel> [args]");
}

struct Message gag_msgtab = {
	"GAG", 0, 0, 0, 0,
	{mg_unreg, {m_gag, 2}, mg_ignore, mg_ignore, {me_gag, 3}, {m_gag, 2}}
};

struct Message gag_clear_msgtab = {
	"GAG_CLEAR", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_gag_clear, 1}, mg_ignore}
};

struct Message gag_add_msgtab = {
	"GAG_ADD", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_gag_add, 3}, mg_ignore}
};

struct Message gag_del_msgtab = {
	"GAG_DEL", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_gag_del, 2}, mg_ignore}
};

struct Message opforce_msgtab = {
	"OPFORCE", 0, 0, 0, 0,
	{mg_unreg, {m_opforce, 3}, mg_ignore, mg_ignore, mg_ignore, {m_opforce, 3}}
};

mapi_clist_av1 ircx_oper_clist[] = { &gag_msgtab, &gag_clear_msgtab, &gag_add_msgtab, &gag_del_msgtab, &opforce_msgtab, NULL };

static int
ircx_oper_init(void)
{
	/* register GAG user mode (+z) per IRCX spec section 7.2 */
	user_modes['z'] = find_umode_slot();
	construct_umodebuf();

	expire_gag_ev = rb_event_add("expire_gag_entries", expire_gag_entries, NULL, 60);

	/*
	 * Request the bandb helper to resend all stored GAG entries.
	 * The helper responds with individual "G" lines (firing bandb_gag_restore
	 * for each) followed by "w" (firing bandb_gag_restore_done).
	 * This is a targeted load that does not disturb kline/dline/xline/resv state.
	 */
	bandb_rehash_gags();

	return 0;
}

static void
ircx_oper_deinit(void)
{
	rb_dlink_node *ptr, *next;

	user_modes['z'] = 0;
	construct_umodebuf();

	if (expire_gag_ev)
		rb_event_delete(expire_gag_ev);

	/* free all gag entries */
	RB_DLINK_FOREACH_SAFE(ptr, next, gag_list.head)
	{
		struct gag_entry *ge = ptr->data;
		rb_dlinkDelete(&ge->node, &gag_list);
		rb_free(ge->mask);
		rb_free(ge->setter);
		rb_free(ge);
	}
}

DECLARE_MODULE_AV2(ircx_oper, ircx_oper_init, ircx_oper_deinit,
	ircx_oper_clist, NULL, ircx_oper_hfnlist, NULL, NULL, ircx_oper_desc);
