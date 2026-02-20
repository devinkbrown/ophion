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
 *   ACCESS * ADD NOCHANNEL <pattern> [:<reason>]
 *     Blocks creation of channels matching the wildcard pattern.
 *     e.g., ACCESS * ADD NOCHANNEL #evil* :Not allowed
 *
 *   ACCESS * ADD NONICK <pattern> [:<reason>]
 *     Blocks use of nicknames matching the wildcard pattern.
 *     e.g., ACCESS * ADD NONICK badnick* :Reserved
 *
 *   ACCESS * DELETE [level] <mask>
 *     Removes a DENY, GAG, GRANT, NOCHANNEL, or NONICK entry.
 *
 *   ACCESS * LIST [level]
 *     Lists server access entries.  Optional level filter.
 *
 *   ACCESS * CLEAR [level]
 *     Clears all server access entries (or all of a specific level).
 *
 * NOCHANNEL and NONICK entries are enforced via hooks on channel
 * creation and nick changes.  Opers are exempt from these restrictions.
 *
 * Processing order per IRCX: GRANT, DENY (GRANT overrides DENY).
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
	"Provides IRCX ACCESS * for server-level access control "
	"(DENY/GAG/GRANT/NOCHANNEL/NONICK)";

static void m_access_server(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[]);
static void me_nochan_add(struct MsgBuf *, struct Client *, struct Client *, int, const char *[]);
static void me_nochan_del(struct MsgBuf *, struct Client *, struct Client *, int, const char *[]);
static void me_nochan_clr(struct MsgBuf *, struct Client *, struct Client *, int, const char *[]);
static void me_nonick_add(struct MsgBuf *, struct Client *, struct Client *, int, const char *[]);
static void me_nonick_del(struct MsgBuf *, struct Client *, struct Client *, int, const char *[]);
static void me_nonick_clr(struct MsgBuf *, struct Client *, struct Client *, int, const char *[]);
static void h_access_burst_finished(void *);
static void h_access_server_cmd(void *);

/*
 * Wildcard ban entries for channel names and nicknames.
 */
struct wildcard_ban {
	rb_dlink_node node;
	char *pattern;		/* wildcard pattern (e.g., #evil*, badnick*) */
	char *reason;		/* reason shown to user */
	char *setter;		/* who set it */
	time_t created;
};

static rb_dlink_list nochannel_list = { NULL, NULL, 0 };
static rb_dlink_list nonick_list = { NULL, NULL, 0 };

static struct wildcard_ban *
find_wildcard_ban(rb_dlink_list *list, const char *pattern)
{
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, list->head)
	{
		struct wildcard_ban *wb = ptr->data;
		if (!irccmp(wb->pattern, pattern))
			return wb;
	}
	return NULL;
}

static void
add_wildcard_ban(rb_dlink_list *list, const char *pattern,
	const char *reason, const char *setter)
{
	struct wildcard_ban *wb = rb_malloc(sizeof(*wb));
	wb->pattern = rb_strdup(pattern);
	wb->reason = rb_strdup(reason);
	wb->setter = rb_strdup(setter);
	wb->created = rb_current_time();
	rb_dlinkAdd(wb, &wb->node, list);
}

static void
del_wildcard_ban(rb_dlink_list *list, struct wildcard_ban *wb)
{
	rb_dlinkDelete(&wb->node, list);
	rb_free(wb->pattern);
	rb_free(wb->reason);
	rb_free(wb->setter);
	rb_free(wb);
}

static void
clear_wildcard_list(rb_dlink_list *list)
{
	rb_dlink_node *ptr, *next;
	RB_DLINK_FOREACH_SAFE(ptr, next, list->head)
	{
		struct wildcard_ban *wb = ptr->data;
		del_wildcard_ban(list, wb);
	}
}

/*
 * check_nochannel - check if a channel name matches a NOCHANNEL ban
 * Returns the ban entry if matched, NULL otherwise.
 */
static struct wildcard_ban *
check_nochannel(const char *name)
{
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, nochannel_list.head)
	{
		struct wildcard_ban *wb = ptr->data;
		if (match(wb->pattern, name))
			return wb;
	}
	return NULL;
}

/*
 * check_nonick - check if a nickname matches a NONICK ban
 * Returns the ban entry if matched, NULL otherwise.
 */
static struct wildcard_ban *
check_nonick(const char *nick)
{
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, nonick_list.head)
	{
		struct wildcard_ban *wb = ptr->data;
		if (match(wb->pattern, nick))
			return wb;
	}
	return NULL;
}

/*
 * Hook: channel_join - enforce NOCHANNEL on join-create
 *
 * This hook fires after a user joins.  If the channel was just
 * created (user is the only member and is chanop), check the ban.
 * If banned, kick the user and destroy the channel.
 */
static void
h_access_channel_join(void *vdata)
{
	hook_data_channel_activity *data = vdata;
	struct Client *source_p = data->client;
	struct Channel *chptr = data->chptr;
	struct wildcard_ban *wb;

	/* opers are exempt */
	if (IsOper(source_p))
		return;

	/* only check newly-created channels (single member who created it) */
	if (rb_dlink_list_length(&chptr->members) != 1)
		return;

	wb = check_nochannel(chptr->chname);
	if (wb == NULL)
		return;

	/* found a matching NOCHANNEL ban - kick the user out */
	sendto_one(source_p, form_str(ERR_UNAVAILRESOURCE),
		me.name, source_p->name, chptr->chname);

	/* remove the user from the channel (destroys the channel) */
	struct membership *msptr = find_channel_membership(chptr, source_p);
	if (msptr != NULL)
		remove_user_from_channel(msptr);
}

/*
 * Hook: local_nick_change - enforce NONICK restrictions
 *
 * Before a nick change is fully processed, check if the new nick
 * matches a NONICK ban.  If so, force the user back.
 */
static void
h_access_nick_change(void *vdata)
{
	hook_cdata *data = vdata;
	struct Client *source_p = data->client;
	const char *newnick = data->arg2;
	struct wildcard_ban *wb;

	if (!MyClient(source_p))
		return;

	/* opers are exempt */
	if (IsOper(source_p))
		return;

	wb = check_nonick(newnick);
	if (wb == NULL)
		return;

	/* The nick change is blocked by the RESV added when this NONICK entry
	 * was created (find_nick_resv() in m_nick.c returns non-NULL and the
	 * change is rejected before this hook fires).  This hook path is
	 * therefore only reached if the RESV is absent (e.g. after a server
	 * restart that reloaded NONICK entries but not their RESVs).  Notify
	 * the user; the change will still proceed in this edge case.
	 */
	sendto_one_notice(source_p,
		":Nickname '%s' is not allowed: %s",
		newnick, wb->reason);
}

struct Message saccess_msgtab = {
	"SACCESS", 0, 0, 0, 0,
	{mg_unreg, {m_access_server, 2}, mg_ignore, mg_ignore, mg_ignore, {m_access_server, 2}}
};

struct Message nochan_add_msgtab = {
	"NOCHAN_ADD", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_nochan_add, 3}, mg_ignore}
};

struct Message nochan_del_msgtab = {
	"NOCHAN_DEL", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_nochan_del, 2}, mg_ignore}
};

struct Message nochan_clr_msgtab = {
	"NOCHAN_CLR", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_nochan_clr, 1}, mg_ignore}
};

struct Message nonick_add_msgtab = {
	"NONICK_ADD", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_nonick_add, 3}, mg_ignore}
};

struct Message nonick_del_msgtab = {
	"NONICK_DEL", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_nonick_del, 2}, mg_ignore}
};

struct Message nonick_clr_msgtab = {
	"NONICK_CLR", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_nonick_clr, 1}, mg_ignore}
};

mapi_clist_av1 ircx_access_server_clist[] = {
	&saccess_msgtab,
	&nochan_add_msgtab, &nochan_del_msgtab, &nochan_clr_msgtab,
	&nonick_add_msgtab, &nonick_del_msgtab, &nonick_clr_msgtab,
	NULL
};

mapi_hfn_list_av1 ircx_access_server_hfnlist[] = {
	{ "channel_join", (hookfn) h_access_channel_join },
	{ "local_nick_change", (hookfn) h_access_nick_change },
	{ "burst_finished", (hookfn) h_access_burst_finished },
	{ "access_server", (hookfn) h_access_server_cmd },
	{ NULL, NULL }
};

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
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
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

	RB_DLINK_FOREACH(ptr, lclient_list.head)
	{
		struct Client *target_p = ptr->data;
		char tbuf[USERLEN + HOSTLEN + 2];

		if (!IsPerson(target_p))
			continue;

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
 * ACCESS * ADD NOCHANNEL <pattern> [:<reason>]
 *
 * Block creation of channels matching the wildcard pattern.
 * Opers are exempt.  Pattern supports * and ? wildcards.
 */
static void
handle_add_nochannel(struct Client *source_p, const char *pattern, int parc, const char *parv[], int arg_offset)
{
	const char *reason = "Channel blocked by server policy";

	if (EmptyString(pattern))
	{
		sendto_one_notice(source_p, ":Usage: ACCESS * ADD NOCHANNEL <pattern> [:<reason>]");
		return;
	}

	if (find_wildcard_ban(&nochannel_list, pattern) != NULL)
	{
		sendto_one_notice(source_p, ":NOCHANNEL entry for [%s] already exists", pattern);
		return;
	}

	if (arg_offset < parc && !EmptyString(parv[arg_offset]))
		reason = parv[arg_offset];

	add_wildcard_ban(&nochannel_list, pattern, reason, get_oper_name(source_p));

	/* propagate to all servers */
	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
		":%s ENCAP * NOCHAN_ADD %s %s :%s",
		use_id(source_p), pattern, get_oper_name(source_p), reason);

	sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
		"%s added ACCESS * NOCHANNEL for [%s] [%s]",
		get_oper_name(source_p), pattern, reason);

	sendto_one_notice(source_p, ":Added NOCHANNEL entry [%s]", pattern);
}

/*
 * ACCESS * ADD NONICK <pattern> [:<reason>]
 *
 * Block use of nicknames matching the wildcard pattern.
 * Opers are exempt.  Adds a nick reservation (RESV) under the hood.
 */
static void
handle_add_nonick(struct Client *source_p, const char *pattern, int parc, const char *parv[], int arg_offset)
{
	const char *reason = "Nickname blocked by server policy";

	if (EmptyString(pattern))
	{
		sendto_one_notice(source_p, ":Usage: ACCESS * ADD NONICK <pattern> [:<reason>]");
		return;
	}

	if (find_wildcard_ban(&nonick_list, pattern) != NULL)
	{
		sendto_one_notice(source_p, ":NONICK entry for [%s] already exists", pattern);
		return;
	}

	if (arg_offset < parc && !EmptyString(parv[arg_offset]))
		reason = parv[arg_offset];

	/* check for existing RESV to avoid conflicts */
	if (find_nick_resv(pattern) != NULL)
	{
		sendto_one_notice(source_p, ":A nick reservation for [%s] already exists (RESV conflict)", pattern);
		return;
	}

	add_wildcard_ban(&nonick_list, pattern, reason, get_oper_name(source_p));

	/* add a RESV to block at the nick validation level */
	struct ConfItem *aconf = make_conf();
	aconf->status = CONF_RESV_NICK;
	aconf->host = rb_strdup(pattern);
	aconf->passwd = rb_strdup(reason);
	aconf->info.oper = operhash_add(get_oper_name(source_p));
	add_to_resv_hash(aconf->host, aconf);

	/* propagate to all servers */
	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
		":%s ENCAP * NONICK_ADD %s %s :%s",
		use_id(source_p), pattern, get_oper_name(source_p), reason);

	sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
		"%s added ACCESS * NONICK for [%s] [%s]",
		get_oper_name(source_p), pattern, reason);

	sendto_one_notice(source_p, ":Added NONICK entry [%s]", pattern);
}

/*
 * ACCESS * DELETE [level] <mask>
 */
static void
handle_delete(struct Client *source_p, const char *level_or_mask, const char *mask_arg)
{
	const char *mask;
	char user[USERLEN + 1], host[HOSTLEN + 1];
	struct wildcard_ban *wb;

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

	/* try NOCHANNEL first */
	wb = find_wildcard_ban(&nochannel_list, mask);
	if (wb != NULL)
	{
		del_wildcard_ban(&nochannel_list, wb);

		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * NOCHAN_DEL %s",
			use_id(source_p), mask);

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s removed ACCESS * NOCHANNEL for [%s]",
			get_oper_name(source_p), mask);
		sendto_one_notice(source_p, ":Removed NOCHANNEL entry [%s]", mask);
		return;
	}

	/* try NONICK */
	wb = find_wildcard_ban(&nonick_list, mask);
	if (wb != NULL)
	{
		/* also remove the RESV */
		struct ConfItem *aconf = find_nick_resv(mask);
		if (aconf != NULL)
			del_from_resv_hash(mask, aconf);

		del_wildcard_ban(&nonick_list, wb);

		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * NONICK_DEL %s",
			use_id(source_p), mask);

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s removed ACCESS * NONICK for [%s]",
			get_oper_name(source_p), mask);
		sendto_one_notice(source_p, ":Removed NONICK entry [%s]", mask);
		return;
	}

	/* try DENY (kline) */
	if (split_mask(mask, user, sizeof user, host, sizeof host))
	{
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
	}

	/* try GAG */
	{
		char fullmask[USERLEN + HOSTLEN + 2];
		if (strchr(mask, '@'))
		{
			rb_strlcpy(fullmask, mask, sizeof fullmask);
		}
		else
		{
			snprintf(fullmask, sizeof fullmask, "*@%s", mask);
		}

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
	bool show_nochannel = true, show_nonick = true;
	rb_dlink_node *ptr;

	if (level_filter != NULL)
	{
		show_deny = show_gag = show_grant = false;
		show_nochannel = show_nonick = false;
		if (!rb_strcasecmp(level_filter, "DENY"))
			show_deny = true;
		else if (!rb_strcasecmp(level_filter, "GAG"))
			show_gag = true;
		else if (!rb_strcasecmp(level_filter, "GRANT"))
			show_grant = true;
		else if (!rb_strcasecmp(level_filter, "NOCHANNEL"))
			show_nochannel = true;
		else if (!rb_strcasecmp(level_filter, "NONICK"))
			show_nonick = true;
	}

	sendto_one_notice(source_p, ":--- ACCESS * list ---");

	/* list klines as DENY entries */
	if (show_deny)
	{
		report_auth(source_p);
	}

	/* list NOCHANNEL entries */
	if (show_nochannel)
	{
		RB_DLINK_FOREACH(ptr, nochannel_list.head)
		{
			struct wildcard_ban *wb = ptr->data;
			sendto_one_notice(source_p, ":NOCHANNEL %s [%s] (set by %s)",
				wb->pattern, wb->reason, wb->setter);
		}
	}

	/* list NONICK entries */
	if (show_nonick)
	{
		RB_DLINK_FOREACH(ptr, nonick_list.head)
		{
			struct wildcard_ban *wb = ptr->data;
			sendto_one_notice(source_p, ":NONICK %s [%s] (set by %s)",
				wb->pattern, wb->reason, wb->setter);
		}
	}

	sendto_one_notice(source_p, ":--- End of ACCESS * list ---");
}

/*
 * ACCESS * CLEAR [level]
 */
static void
handle_clear(struct Client *source_p, const char *level)
{
	if (level != NULL && !rb_strcasecmp(level, "GAG"))
	{
		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * GAG_CLEAR",
			use_id(source_p));

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

	if (level != NULL && !rb_strcasecmp(level, "NOCHANNEL"))
	{
		clear_wildcard_list(&nochannel_list);

		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * NOCHAN_CLR",
			use_id(source_p));

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s cleared all ACCESS * NOCHANNEL entries",
			get_oper_name(source_p));
		sendto_one_notice(source_p, ":All NOCHANNEL entries cleared");
		return;
	}

	if (level != NULL && !rb_strcasecmp(level, "NONICK"))
	{
		/* remove RESVs too */
		rb_dlink_node *ptr2;
		RB_DLINK_FOREACH(ptr2, nonick_list.head)
		{
			struct wildcard_ban *wb = ptr2->data;
			struct ConfItem *aconf = find_nick_resv(wb->pattern);
			if (aconf != NULL)
				del_from_resv_hash(wb->pattern, aconf);
		}
		clear_wildcard_list(&nonick_list);

		sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
			":%s ENCAP * NONICK_CLR",
			use_id(source_p));

		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"%s cleared all ACCESS * NONICK entries",
			get_oper_name(source_p));
		sendto_one_notice(source_p, ":All NONICK entries cleared");
		return;
	}

	if (level != NULL && !rb_strcasecmp(level, "DENY"))
	{
		sendto_one_notice(source_p, ":Use /UNKLINE or ACCESS * DELETE to remove individual DENY entries");
		return;
	}

	sendto_one_notice(source_p, ":Usage: ACCESS * CLEAR {GAG|DENY|NOCHANNEL|NONICK}");
}

/*
 * dispatch_access_server - core of ACCESS * / SACCESS dispatch.
 * Called by the msgtab handler and by the access_server hook (for ACCESS *).
 * Requires source_p to already be verified as oper.
 * parv[1] is the action (LIST/ADD/DELETE/CLEAR), arg_base is index of
 * first argument after the action.
 */
static void
dispatch_access_server(struct Client *source_p, int parc, const char *parv[],
	const char *action, int arg_base)
{
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
		else if (!rb_strcasecmp(level, "NOCHANNEL"))
			handle_add_nochannel(source_p, mask, parc, parv, arg_base + 2);
		else if (!rb_strcasecmp(level, "NONICK"))
			handle_add_nonick(source_p, mask, parc, parv, arg_base + 2);
		else
			sendto_one_notice(source_p, ":Unknown level '%s'. Use DENY, GAG, GRANT, NOCHANNEL, or NONICK.", level);
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

/*
 * SACCESS command handler.  Also handles SACCESS * <action> form for
 * symmetry with the spec's ACCESS * syntax.
 */
static void
m_access_server(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	const char *action;
	int arg_base;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	if (!strcmp(parv[1], "*"))
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
		action = parv[1];
		arg_base = 2;
	}

	dispatch_access_server(source_p, parc, parv, action, arg_base);
}

/*
 * Hook handler: fires when m_ircx_access.c sees ACCESS * from a client.
 * Delegates to the same dispatch logic as SACCESS.
 */
static void
h_access_server_cmd(void *vdata)
{
	hook_data *data = vdata;
	struct Client *source_p = data->client;
	const char **parv = data->arg1;
	int parc = (int)(intptr_t)data->arg2;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	/* parv[1] is "*"; action starts at parv[2] */
	if (parc < 3)
	{
		handle_list(source_p, NULL);
		return;
	}

	dispatch_access_server(source_p, parc, parv, parv[2], 3);
}

/*
 * ENCAP handlers for NOCHANNEL/NONICK propagation.
 *
 * :source ENCAP * NOCHAN_ADD <pattern> <setter> :<reason>
 * :source ENCAP * NOCHAN_DEL <pattern>
 * :source ENCAP * NOCHAN_CLR
 * :source ENCAP * NONICK_ADD <pattern> <setter> :<reason>
 * :source ENCAP * NONICK_DEL <pattern>
 * :source ENCAP * NONICK_CLR
 */
static void
me_nochan_add(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	const char *pattern = parv[1];
	const char *setter = parv[2];
	const char *reason = (parc > 3 && !EmptyString(parv[3])) ? parv[3] : "Server policy";

	if (find_wildcard_ban(&nochannel_list, pattern) != NULL)
		return;

	add_wildcard_ban(&nochannel_list, pattern, reason, setter);
}

static void
me_nochan_del(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	struct wildcard_ban *wb = find_wildcard_ban(&nochannel_list, parv[1]);
	if (wb != NULL)
		del_wildcard_ban(&nochannel_list, wb);
}

static void
me_nochan_clr(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	clear_wildcard_list(&nochannel_list);
}

static void
me_nonick_add(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	const char *pattern = parv[1];
	const char *setter = parv[2];
	const char *reason = (parc > 3 && !EmptyString(parv[3])) ? parv[3] : "Server policy";

	if (find_wildcard_ban(&nonick_list, pattern) != NULL)
		return;

	add_wildcard_ban(&nonick_list, pattern, reason, setter);

	/* add local RESV if none exists */
	if (find_nick_resv(pattern) == NULL)
	{
		struct ConfItem *aconf = make_conf();
		aconf->status = CONF_RESV_NICK;
		aconf->host = rb_strdup(pattern);
		aconf->passwd = rb_strdup(reason);
		aconf->info.oper = operhash_add(setter);
		add_to_resv_hash(aconf->host, aconf);
	}
}

static void
me_nonick_del(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	struct wildcard_ban *wb = find_wildcard_ban(&nonick_list, parv[1]);
	if (wb != NULL)
	{
		struct ConfItem *aconf = find_nick_resv(parv[1]);
		if (aconf != NULL)
			del_from_resv_hash(parv[1], aconf);

		del_wildcard_ban(&nonick_list, wb);
	}
}

static void
me_nonick_clr(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, nonick_list.head)
	{
		struct wildcard_ban *wb = ptr->data;
		struct ConfItem *aconf = find_nick_resv(wb->pattern);
		if (aconf != NULL)
			del_from_resv_hash(wb->pattern, aconf);
	}
	clear_wildcard_list(&nonick_list);
}

/*
 * Burst sync: send all NOCHANNEL/NONICK entries to a newly linked server.
 */
static void
h_access_burst_finished(void *vdata)
{
	hook_data_client *hclientinfo = vdata;
	struct Client *server_p = hclientinfo->client;
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, nochannel_list.head)
	{
		struct wildcard_ban *wb = ptr->data;
		sendto_one(server_p, ":%s ENCAP %s NOCHAN_ADD %s %s :%s",
			use_id(&me), server_p->name,
			wb->pattern, wb->setter, wb->reason);
	}

	RB_DLINK_FOREACH(ptr, nonick_list.head)
	{
		struct wildcard_ban *wb = ptr->data;
		sendto_one(server_p, ":%s ENCAP %s NONICK_ADD %s %s :%s",
			use_id(&me), server_p->name,
			wb->pattern, wb->setter, wb->reason);
	}
}

static void
ircx_access_server_deinit(void)
{
	/* remove RESVs created by NONICK entries before clearing */
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, nonick_list.head)
	{
		struct wildcard_ban *wb = ptr->data;
		struct ConfItem *aconf = find_nick_resv(wb->pattern);
		if (aconf != NULL)
			del_from_resv_hash(wb->pattern, aconf);
	}

	clear_wildcard_list(&nochannel_list);
	clear_wildcard_list(&nonick_list);
}

DECLARE_MODULE_AV2(ircx_access_server, NULL, ircx_access_server_deinit,
	ircx_access_server_clist, NULL, ircx_access_server_hfnlist,
	NULL, NULL, ircx_access_server_desc);
