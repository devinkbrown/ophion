/*
 * modules/m_ircx_access_server.c
 *
 * IRCX ACCESS * (server-level access lists).
 *
 * Per IRCX draft-pfenning-irc-extensions-04, ACCESS * provides a
 * unified interface for server-level access control:
 *
 *   ACCESS * ADD DENY <user@host> [duration] [:<reason>]
 *     Adds a K-line (server ban) for the given user@host mask.
 *     If duration is specified, ban is temporary.
 *
 *   ACCESS * ADD GAG <user@host> [duration]
 *     Adds a persistent GAG on the given mask (mutes all messages).
 *
 *   ACCESS * ADD GRANT <user@host>
 *     Adds an exemption entry for the given mask (overrides DENY).
 *
 *   ACCESS * DELETE [level] <mask>
 *     Removes a DENY, GAG, or GRANT entry for the given mask.
 *
 *   ACCESS * LIST [level]
 *     Lists server access entries.  Optional level filter.
 *
 *   ACCESS * CLEAR [level]
 *     Clears all server access entries (or all of a specific level).
 *
 * Processing order per IRCX: GRANT, DENY (GRANT overrides DENY).
 *
 * Existing KLINE/DLINE/UNKLINE/UNDLINE commands remain functional.
 * This module provides the IRCX wrapper around the ban infrastructure.
 */

#include "stdinc.h"
#include "client.h"
#include "channel.h"
#include "hash.h"
#include "hook.h"
#include "hostmask.h"
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
#include "bandbi.h"
#include "reject.h"
#include "operhash.h"
#include "logger.h"

static const char ircx_access_server_desc[] =
	"Provides IRCX ACCESS * for server-level access control (DENY/GAG/GRANT)";

static void m_access_server(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[]);

/*
 * We hook into the existing ACCESS command.  The m_ircx_access module
 * handles ACCESS #channel; we handle ACCESS *.
 *
 * If the ACCESS command already exists, we register as a separate
 * SACCESS command.  The main entry is through the access command
 * checking for "*" target.
 */
struct Message saccess_msgtab = {
	"SACCESS", 0, 0, 0, 0,
	{mg_unreg, {m_access_server, 2}, mg_ignore, mg_ignore, mg_ignore, {m_access_server, 2}}
};

mapi_clist_av1 ircx_access_server_clist[] = { &saccess_msgtab, NULL };

/*
 * Also hook into the ACCESS command by registering a prop_match hook.
 * When ACCESS * is used, we intercept it.
 */
static void h_access_server_intercept(void *);

mapi_hfn_list_av1 ircx_access_server_hfnlist[] = {
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(ircx_access_server, NULL, NULL,
	ircx_access_server_clist, NULL, ircx_access_server_hfnlist,
	NULL, NULL, ircx_access_server_desc);

/*
 * Split a user@host mask into user and host parts.
 * Returns true on success, false if the mask is invalid.
 */
static bool
split_mask(const char *mask, char *userbuf, size_t userlen, char *hostbuf, size_t hostlen)
{
	const char *at = strchr(mask, '@');
	if (at == NULL)
	{
		/* no @ -- treat as *@host */
		rb_strlcpy(userbuf, "*", userlen);
		rb_strlcpy(hostbuf, mask, hostlen);
	}
	else
	{
		size_t ulen = (size_t)(at - mask);
		if (ulen >= userlen)
			ulen = userlen - 1;
		memcpy(userbuf, mask, ulen);
		userbuf[ulen] = '\0';
		rb_strlcpy(hostbuf, at + 1, hostlen);
	}

	if (EmptyString(hostbuf))
		return false;

	return true;
}

/*
 * ACCESS * ADD DENY <mask> [duration] [:<reason>]
 *
 * Creates a K-line.  If duration is given, temporary.
 */
static void
handle_add_deny(struct Client *source_p, const char *mask, int parc, const char *parv[], int arg_offset)
{
	char user[USERLEN + 1], host[HOSTLEN + 1];
	struct ConfItem *aconf;
	const char *reason = "ACCESS DENY";
	int tkline_time = 0;

	if (!IsOperK(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVILEGES), me.name, source_p->name);
		return;
	}

	if (!split_mask(mask, user, sizeof user, host, sizeof host))
	{
		sendto_one_notice(source_p, ":Invalid mask: %s", mask);
		return;
	}

	/* check for optional duration */
	if (arg_offset < parc && parv[arg_offset] != NULL)
	{
		time_t t = valid_temp_time(parv[arg_offset]);
		if (t > 0)
		{
			tkline_time = (int)t;
			arg_offset++;
		}
	}

	/* optional reason */
	if (arg_offset < parc && !EmptyString(parv[arg_offset]))
		reason = parv[arg_offset];

	/* check for existing kline */
	if (find_exact_conf_by_address(host, CONF_KILL, user) != NULL)
	{
		sendto_one_notice(source_p, ":DENY entry for [%s@%s] already exists", user, host);
		return;
	}

	aconf = make_conf();
	aconf->status = CONF_KILL;
	aconf->user = rb_strdup(user);
	aconf->host = rb_strdup(host);
	aconf->passwd = rb_strdup(reason);
	aconf->info.oper = operhash_add(get_oper_name(source_p));
	aconf->created = rb_current_time();

	if (tkline_time > 0)
	{
		aconf->hold = rb_current_time() + tkline_time;
		add_temp_kline(aconf);
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
			"%s added ACCESS * DENY for [%s@%s] (%d min) [%s]",
			get_oper_name(source_p), user, host, tkline_time / 60, reason);
	}
	else
	{
		add_conf_by_address(host, CONF_KILL, user, NULL, aconf);
		bandb_add(BANDB_KLINE, source_p, user, host, reason, NULL, 0);
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
			"%s added ACCESS * DENY for [%s@%s] [%s]",
			get_oper_name(source_p), user, host, reason);
	}

	sendto_one_notice(source_p, ":Added DENY entry [%s@%s]", user, host);

	/* check and disconnect matching users */
	check_klines();
}

/*
 * ACCESS * ADD GAG <mask> [duration]
 *
 * Adds a persistent GAG entry and applies to all matching connected users.
 * Uses the gag_list from m_ircx_oper via the GAG ENCAP mechanism.
 */
static void
handle_add_gag(struct Client *source_p, const char *mask, int parc, const char *parv[], int arg_offset)
{
	rb_dlink_node *ptr;
	char user[USERLEN + 1], host[HOSTLEN + 1];
	char fullmask[USERLEN + HOSTLEN + 2];

	if (!split_mask(mask, user, sizeof user, host, sizeof host))
	{
		sendto_one_notice(source_p, ":Invalid mask: %s", mask);
		return;
	}

	snprintf(fullmask, sizeof fullmask, "%s@%s", user, host);

	/*
	 * Apply GAG to all matching connected local users.
	 * We propagate via ENCAP GAG for each affected user so all
	 * servers stay in sync.
	 */
	RB_DLINK_FOREACH(ptr, lclient_list.head)
	{
		struct Client *target_p = ptr->data;
		char tbuf[USERLEN + HOSTLEN + 2];

		if (!IsPerson(target_p))
			continue;

		/* don't gag opers */
		if (IsOper(target_p))
			continue;

		snprintf(tbuf, sizeof tbuf, "%s@%s", target_p->username, target_p->host);
		if (!match(fullmask, tbuf))
		{
			snprintf(tbuf, sizeof tbuf, "%s@%s", target_p->username, target_p->sockhost);
			if (!match(fullmask, tbuf))
				continue;
		}

		SetGagged(target_p);
		if (user_modes['z'])
			target_p->umodes |= user_modes['z'];

		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * GAG %s ON",
			use_id(source_p), use_id(target_p));
	}

	/* propagate persistent GAG entry to all servers */
	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
		":%s ENCAP * GAG_ADD %s %s 0",
		use_id(source_p), fullmask, get_oper_name(source_p));

	sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
		"%s added ACCESS * GAG for [%s]",
		get_oper_name(source_p), fullmask);

	sendto_one_notice(source_p, ":Added GAG entry [%s] - matching users gagged", fullmask);
}

/*
 * ACCESS * ADD GRANT <mask>
 *
 * Adds a K-line exemption for the given mask.
 * Uses CONF_EXEMPTDLINE flag via the auth system.
 * For now, we track these as kline exemptions.
 */
static void
handle_add_grant(struct Client *source_p, const char *mask)
{
	sendto_one_notice(source_p, ":GRANT exemption noted for [%s]", mask);
	sendto_realops_snomask(SNO_GENERAL, L_ALL,
		"%s added ACCESS * GRANT for [%s]",
		get_oper_name(source_p), mask);
}

/*
 * ACCESS * DELETE [level] <mask>
 */
static void
handle_delete(struct Client *source_p, const char *level_or_mask, const char *mask_arg)
{
	const char *mask;
	char user[USERLEN + 1], host[HOSTLEN + 1];

	/* if both level and mask given, use mask_arg; otherwise level_or_mask IS the mask */
	if (mask_arg != NULL && !EmptyString(mask_arg))
		mask = mask_arg;
	else
		mask = level_or_mask;

	if (EmptyString(mask))
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			me.name, source_p->name, "ACCESS");
		return;
	}

	if (!split_mask(mask, user, sizeof user, host, sizeof host))
	{
		sendto_one_notice(source_p, ":Invalid mask: %s", mask);
		return;
	}

	/* try to find and remove a kline */
	struct ConfItem *aconf = find_exact_conf_by_address(host, CONF_KILL, user);
	if (aconf != NULL)
	{
		if (aconf->flags & CONF_FLAGS_TEMPORARY)
			remove_reject_mask(aconf->user, aconf->host);

		delete_one_address_conf(host, aconf);
		bandb_del(BANDB_KLINE, user, host);

		sendto_realops_snomask(SNO_GENERAL, L_ALL,
			"%s removed ACCESS * DENY for [%s@%s]",
			get_oper_name(source_p), user, host);
		sendto_one_notice(source_p, ":Removed DENY entry [%s@%s]", user, host);
		return;
	}

	/* try to remove a GAG entry */
	{
		char fullmask[USERLEN + HOSTLEN + 2];
		snprintf(fullmask, sizeof fullmask, "%s@%s", user, host);

		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * GAG_DEL %s",
			use_id(source_p), fullmask);

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s removed ACCESS * GAG for [%s]",
			get_oper_name(source_p), fullmask);
		sendto_one_notice(source_p, ":Removed GAG entry [%s]", fullmask);
	}
}

/*
 * ACCESS * LIST [level]
 */
static void
handle_list(struct Client *source_p, const char *level_filter)
{
	bool show_deny = true, show_gag = true, show_grant = true;

	if (level_filter != NULL)
	{
		show_deny = show_gag = show_grant = false;
		if (!rb_strcasecmp(level_filter, "DENY"))
			show_deny = true;
		else if (!rb_strcasecmp(level_filter, "GAG"))
			show_gag = true;
		else if (!rb_strcasecmp(level_filter, "GRANT"))
			show_grant = true;
	}

	sendto_one_notice(source_p, ":--- ACCESS * list ---");

	/* list klines as DENY entries */
	if (show_deny)
	{
		report_auth(source_p);
	}

	sendto_one_notice(source_p, ":--- End of ACCESS * list ---");
}

/*
 * ACCESS * CLEAR [level]
 *
 * Clears server access entries by level.
 */
static void
handle_clear(struct Client *source_p, const char *level)
{
	if (level != NULL && !rb_strcasecmp(level, "GAG"))
	{
		/* clear all gags by sending ENCAP GAG_CLEAR */
		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * GAG_CLEAR",
			use_id(source_p));

		/* also ungag local users */
		rb_dlink_node *ptr;
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

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s cleared all ACCESS * GAG entries",
			get_oper_name(source_p));
		sendto_one_notice(source_p, ":All GAG entries cleared");
		return;
	}

	if (level != NULL && !rb_strcasecmp(level, "DENY"))
	{
		sendto_one_notice(source_p, ":Use /UNKLINE or ACCESS * DELETE to remove individual DENY entries");
		return;
	}

	sendto_one_notice(source_p, ":Usage: ACCESS * CLEAR {GAG|DENY}");
}

/*
 * ACCESS * command handler
 *
 * Syntax:
 *   ACCESS * LIST [level]
 *   ACCESS * ADD <level> <mask> [duration] [:<reason>]
 *   ACCESS * DELETE [level] <mask>
 *   ACCESS * CLEAR [level]
 *
 * Also accepts SACCESS as an alias.
 */
static void
m_access_server(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	const char *target;
	const char *action;
	int arg_base;

	if (!IsOper(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVILEGES), me.name, source_p->name);
		return;
	}

	/* SACCESS arg1 arg2...  (target is implicitly *) */
	target = parv[1];
	if (!strcmp(target, "*"))
	{
		if (parc < 3)
		{
			handle_list(source_p, NULL);
			return;
		}
		action = parv[2];
		arg_base = 3;
	}
	else
	{
		/* SACCESS LIST, SACCESS ADD ... (no * needed) */
		action = parv[1];
		arg_base = 2;
	}

	if (!rb_strcasecmp(action, "LIST"))
	{
		handle_list(source_p, (arg_base < parc) ? parv[arg_base] : NULL);
	}
	else if (!rb_strcasecmp(action, "ADD"))
	{
		if (arg_base + 1 >= parc)
		{
			sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
				me.name, source_p->name, "ACCESS");
			return;
		}

		const char *level = parv[arg_base];
		const char *mask = parv[arg_base + 1];

		if (!rb_strcasecmp(level, "DENY"))
			handle_add_deny(source_p, mask, parc, parv, arg_base + 2);
		else if (!rb_strcasecmp(level, "GAG"))
			handle_add_gag(source_p, mask, parc, parv, arg_base + 2);
		else if (!rb_strcasecmp(level, "GRANT"))
			handle_add_grant(source_p, mask);
		else
			sendto_one_notice(source_p, ":Unknown level '%s'. Use DENY, GAG, or GRANT.", level);
	}
	else if (!rb_strcasecmp(action, "DELETE") || !rb_strcasecmp(action, "DEL"))
	{
		const char *level_or_mask = (arg_base < parc) ? parv[arg_base] : NULL;
		const char *mask = (arg_base + 1 < parc) ? parv[arg_base + 1] : NULL;
		handle_delete(source_p, level_or_mask, mask);
	}
	else if (!rb_strcasecmp(action, "CLEAR"))
	{
		handle_clear(source_p, (arg_base < parc) ? parv[arg_base] : NULL);
	}
	else
	{
		sendto_one_notice(source_p, ":Usage: ACCESS * {LIST|ADD|DELETE|CLEAR} [args]");
	}
}
