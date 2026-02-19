/*
 * modules/m_ircx_access.c
 * Copyright (c) 2020 Ariadne Conill <ariadne@dereferenced.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "stdinc.h"
#include "capability.h"
#include "channel.h"
#include "client.h"
#include "hook.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "monitor.h"
#include "numeric.h"
#include "s_assert.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "supported.h"
#include "hash.h"
#include "match.h"
#include "channel_access.h"

static const char ircx_access_desc[] = "Provides IRCX ACCESS command";

static int ircx_access_init(void);
static void ircx_access_deinit(void);

static void m_access(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message access_msgtab = {
	"ACCESS", 0, 0, 0, 0,
	{mg_unreg, {m_access, 2}, {m_access, 2}, mg_ignore, mg_ignore, {m_access, 2}}
};

/* :server TACCESS #channel channelTS entryTS mask level */
static void ms_taccess(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message taccess_msgtab = {
	"TACCESS", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, {ms_taccess, 4}, mg_ignore, mg_ignore}
};

/* :server BTACCESS #channel channelTS :entryTS mask level entryTS mask level ... */
static void ms_btaccess(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message btaccess_msgtab = {
	"BTACCESS", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, {ms_btaccess, 4}, mg_ignore, mg_ignore}
};

mapi_clist_av1 ircx_access_clist[] = { &access_msgtab, &taccess_msgtab, &btaccess_msgtab, NULL };

static void h_access_can_join(void *);
static void h_access_channel_join(void *);
static void h_access_burst_channel(void *);
static void h_access_channel_lowerts(void *);

mapi_hfn_list_av1 ircx_access_hfnlist[] = {
	{ "can_join", (hookfn) h_access_can_join, HOOK_HIGHEST },
	{ "channel_join", (hookfn) h_access_channel_join },
	{ "burst_channel", (hookfn) h_access_burst_channel },
	{ "channel_lowerts", (hookfn) h_access_channel_lowerts },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(ircx_access, ircx_access_init, ircx_access_deinit, ircx_access_clist, NULL, ircx_access_hfnlist, NULL, NULL, ircx_access_desc);

static int
ircx_access_init(void)
{
	add_isupport("MAXACCESS", isupport_intptr, &ConfigChannel.max_bans);
	return 0;
}

static void
ircx_access_deinit(void)
{
	delete_isupport("MAXACCESS");
}

struct AccessLevel {
	const char *level;
	const char mode_char;
	unsigned int flag;
};

/* sentinel flags for entries stored in mode lists, not access_list */
#define ACCESS_DENY_FLAG  0x80000000	/* stored in banlist (+b) */
#define ACCESS_GRANT_FLAG 0x40000000	/* stored in invexlist (+I) */

/* keep this in alphabetical order for bsearch(3)! */
static const struct AccessLevel alevel[] = {
	{"ADMIN", 'q', CHFL_ADMIN},
	{"DENY", 0, ACCESS_DENY_FLAG},
	{"GRANT", 0, ACCESS_GRANT_FLAG},
	{"HOST", 'o', CHFL_CHANOP},
	{"OP", 'o', CHFL_CHANOP},
	{"OWNER", 'q', CHFL_ADMIN},
	{"VOICE", 'v', CHFL_VOICE}
};

static const char *
ae_level_name(unsigned int level)
{
	size_t i;

	if (level == ACCESS_DENY_FLAG)
		return "DENY";

	if (level == ACCESS_GRANT_FLAG)
		return "GRANT";

	/*
	 * We iterate backwards so that OWNER is preferred over ADMIN for
	 * access level name.  This is so we can remove ADMIN later.
	 *     -- Ariadne
	 */
	for (i = ARRAY_SIZE(alevel) - 1; i > 0; i--)
	{
		if ((alevel[i].flag & level) == level)
			return alevel[i].level;
	}

	return "???";
}

static const char
ae_level_char(unsigned int level)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(alevel); i++)
	{
		if ((alevel[i].flag & level) == level)
			return alevel[i].mode_char;
	}

	return 0;
}

static int
ae_pair_cmp(const void *key, const void *ptr)
{
	const struct AccessLevel *alev = ptr;
	return rb_strcasecmp(key, alev->level);
}

static unsigned int
ae_level_from_name(const char *level_name)
{
	if (level_name == NULL)
		return 0;

	const struct AccessLevel *alev = bsearch(level_name, alevel,
		ARRAY_SIZE(alevel), sizeof(alevel[0]), ae_pair_cmp);

	if (alev == NULL)
		return 0;

	return alev->flag;
}

/*
 * ACCESS command.
 *
 * parv[0] = source
 * parv[1] = object name
 * parv[2] = ADD|CLEAR|DEL[ETE]|LIST|SYNC (default LIST)
 * parv[3] = level (ADMIN|OP|VOICE) (optional for CLEAR and LIST)
 * parv[4] = mask (not used for CLEAR and LIST)
 *
 * No permissions check for remotes, op needed to write to op/voice ACL,
 * admin needed to write to admin ACL.  Op needed to read ACL.  Clearing
 * the ACL requires admin.
 */
static bool
can_read_from_access_list(struct Channel *chptr, struct Client *source_p, unsigned int level)
{
	if (!MyClient(source_p))
		return true;

	const struct membership *msptr = find_channel_membership(chptr, source_p);
	return is_admin(msptr) || is_chanop(msptr);
}

static bool
can_write_to_access_list(struct Channel *chptr, struct Client *source_p, unsigned int level)
{
	if (!MyClient(source_p))
		return true;

	const struct membership *msptr = find_channel_membership(chptr, source_p);
	if (level == CHFL_ADMIN)
		return is_admin(msptr);

	return is_admin(msptr) || is_chanop(msptr);
}

/*
 * since the channel access core uses upserts to update the channel access lists,
 * it is important to enforce write access to any previous ACL entry before doing
 * the upsert.  otherwise, a channel could be taken over. -- Ariadne
 */
static bool
can_upsert_on_access_list(struct Channel *chptr, struct Client *source_p, const char *mask, unsigned int newflags)
{
	/* first, we make sure we can read the ACL at all, to prevent bruteforcing */
	if (!can_read_from_access_list(chptr, source_p, CHFL_CHANOP))
		return false;

	struct AccessEntry *ae = channel_access_find(chptr, mask);
	if (ae == NULL)
		return can_write_to_access_list(chptr, source_p, newflags);

	/* now that we have an entry, try to enforce write access */
	if (!can_write_to_access_list(chptr, source_p, ae->flags))
		return false;

	return can_write_to_access_list(chptr, source_p, newflags);
}

static void
handle_access_list(struct Channel *chptr, struct Client *source_p, const char *level)
{
	unsigned int level_match = ae_level_from_name(level);
	const rb_dlink_node *iter;

	/*
	 * If the level argument is not a known level name, treat it
	 * as a wildcard mask filter for the LIST output.
	 */
	const char *mask_filter = NULL;
	if (level != NULL && level_match == 0)
		mask_filter = level;

	if (!can_read_from_access_list(chptr, source_p, level_match))
	{
		sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
			me.name, source_p->name, chptr->chname);
		return;
	}

	sendto_one_numeric(source_p, RPL_ACCESSSTART, form_str(RPL_ACCESSSTART), chptr->chname);

	/* show access_list entries (membership levels: OWNER/HOST/OP/VOICE) */
	if (level_match != ACCESS_DENY_FLAG && level_match != ACCESS_GRANT_FLAG)
	{
		RB_DLINK_FOREACH(iter, chptr->access_list.head)
		{
			const struct AccessEntry *ae = iter->data;

			if (level_match && (ae->flags & level_match) != level_match)
				continue;

			/* apply wildcard mask filter if given */
			if (mask_filter && !match(mask_filter, ae->mask))
				continue;

			sendto_one_numeric(source_p, RPL_ACCESSENTRY, form_str(RPL_ACCESSENTRY),
				chptr->chname, ae_level_name(ae->flags), ae->mask, (long) 0, ae->who, "");
		}
	}

	/* show ban list entries as DENY level */
	if (!level_match || level_match == ACCESS_DENY_FLAG)
	{
		RB_DLINK_FOREACH(iter, chptr->banlist.head)
		{
			const struct Ban *ban = iter->data;

			if (mask_filter && !match(mask_filter, ban->banstr))
				continue;

			sendto_one_numeric(source_p, RPL_ACCESSENTRY, form_str(RPL_ACCESSENTRY),
				chptr->chname, "DENY", ban->banstr, (long) ban->when, ban->who, "");
		}
	}

	/* show invite exception list entries as GRANT level */
	if (!level_match || level_match == ACCESS_GRANT_FLAG)
	{
		RB_DLINK_FOREACH(iter, chptr->invexlist.head)
		{
			const struct Ban *ban = iter->data;

			if (mask_filter && !match(mask_filter, ban->banstr))
				continue;

			sendto_one_numeric(source_p, RPL_ACCESSENTRY, form_str(RPL_ACCESSENTRY),
				chptr->chname, "GRANT", ban->banstr, (long) ban->when, ban->who, "");
		}
	}

	sendto_one_numeric(source_p, RPL_ACCESSEND, form_str(RPL_ACCESSEND), chptr->chname);
}

static void
handle_access_clear(struct Channel *chptr, struct Client *source_p, const char *level)
{
	unsigned int level_match = ae_level_from_name(level);

	if (!can_write_to_access_list(chptr, source_p, CHFL_ADMIN))
	{
		sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
			me.name, source_p->name, chptr->chname);
		return;
	}

	rb_dlink_node *iter, *next;

	/* clear access_list entries (membership levels) */
	if (level_match != ACCESS_DENY_FLAG && level_match != ACCESS_GRANT_FLAG)
	{
		RB_DLINK_FOREACH_SAFE(iter, next, chptr->access_list.head)
		{
			struct AccessEntry *ae = iter->data;

			if (level_match && (ae->flags & level_match) != level_match)
				continue;

			sendto_server(source_p, chptr, CAP_TS6, NOCAPS,
				":%s TACCESS %s %ld %ld %s :",
				use_id(&me), chptr->chname, (long)chptr->channelts, (long)ae->when,
				ae->mask);

			channel_access_delete(chptr, ae->mask);
		}
	}

	/* clear ban list entries (DENY level) via mode infrastructure */
	if (!level_match || level_match == ACCESS_DENY_FLAG)
	{
		RB_DLINK_FOREACH_SAFE(iter, next, chptr->banlist.head)
		{
			struct Ban *ban = iter->data;
			char mask_copy[BANLEN + 1];

			rb_strlcpy(mask_copy, ban->banstr, sizeof(mask_copy));

			const char *para[] = {"-b", mask_copy};
			set_channel_mode(source_p, &me, chptr, NULL, 2, para);
		}
	}

	/* clear invite exception list entries (GRANT level) via mode infrastructure */
	if (!level_match || level_match == ACCESS_GRANT_FLAG)
	{
		RB_DLINK_FOREACH_SAFE(iter, next, chptr->invexlist.head)
		{
			struct Ban *ban = iter->data;
			char mask_copy[BANLEN + 1];

			rb_strlcpy(mask_copy, ban->banstr, sizeof(mask_copy));

			const char *para[] = {"-I", mask_copy};
			set_channel_mode(source_p, &me, chptr, NULL, 2, para);
		}
	}
}

/*
 * for deletion, we don't really care about the level, since we already know it.
 * we do, however, enforce write ACL based on the ACL level before doing the actual
 * delete.  -- Ariadne
 */
static void
handle_access_delete(struct Channel *chptr, struct Client *source_p, const char *mask)
{
	if (mask == NULL)
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			   me.name,
			   EmptyString(source_p->name) ? "*" : source_p->name,
			   "ACCESS DELETE");
		return;
	}

	/* first, we make sure we can read the ACL at all, to prevent bruteforcing */
	if (!can_read_from_access_list(chptr, source_p, CHFL_CHANOP))
	{
		sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
			me.name, source_p->name, chptr->chname);
		return;
	}

	struct AccessEntry *ae = channel_access_find(chptr, mask);
	if (ae == NULL)
	{
		/*
		 * Not found in access_list -- check the mode lists, since
		 * DENY entries are stored as bans (+b) and GRANT entries
		 * are stored as invite exceptions (+I).
		 */
		rb_dlink_list *lists[] = { &chptr->banlist, &chptr->invexlist };
		const char *level_names[] = { "DENY", "GRANT" };
		const char *modestrs[] = { "-b", "-I" };
		rb_dlink_node *ptr;

		for (size_t i = 0; i < ARRAY_SIZE(lists); i++)
		{
			RB_DLINK_FOREACH(ptr, lists[i]->head)
			{
				struct Ban *b = ptr->data;

				if (irccmp(b->banstr, mask))
					continue;

				if (!can_write_to_access_list(chptr, source_p, CHFL_CHANOP))
				{
					sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
						me.name, source_p->name, chptr->chname);
					return;
				}

				if (MyClient(source_p))
				{
					sendto_one_numeric(source_p, RPL_ACCESSDELETE, form_str(RPL_ACCESSDELETE),
						chptr->chname, level_names[i], mask,
						(long) 0, source_p->name, "");
				}

				const char *para[] = {modestrs[i], mask};
				set_channel_mode(source_p, &me, chptr, NULL, 2, para);
				return;
			}
		}

		sendto_one_numeric(source_p, ERR_ACCESS_MISSING, form_str(ERR_ACCESS_MISSING),
			chptr->chname, mask);
		return;
	}

	/* now that we have an entry, try to enforce write access */
	if (!can_write_to_access_list(chptr, source_p, ae->flags))
	{
		sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
			me.name, source_p->name, chptr->chname);
		return;
	}

	if (MyClient(source_p))
	{
		sendto_one_numeric(source_p, RPL_ACCESSDELETE, form_str(RPL_ACCESSDELETE),
			chptr->chname, ae_level_name(ae->flags), ae->mask,
			(long) 0, ae->who, "");
	}

	/* propagate deletion to servers via TACCESS with empty level */
	sendto_server(source_p, chptr, CAP_TS6, NOCAPS,
		":%s TACCESS %s %ld %ld %s :",
		use_id(&me), chptr->chname, (long)chptr->channelts, (long)ae->when,
		ae->mask);

	channel_access_delete(chptr, ae->mask);
}

static void
handle_access_upsert(struct Channel *chptr, struct Client *source_p, const char *level, const char *mask)
{
	unsigned int newflags = ae_level_from_name(level);

	if (level == NULL || mask == NULL)
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			   me.name,
			   EmptyString(source_p->name) ? "*" : source_p->name,
			   "ACCESS ADD");
		return;
	}

	if (newflags == 0)
	{
		sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
			   me.name,
			   EmptyString(source_p->name) ? "*" : source_p->name,
			   "ACCESS ADD");
		return;
	}

	/* validate mask format: must contain at least one non-whitespace char,
	 * and must not be excessively long */
	if (EmptyString(mask) || strlen(mask) > BANLEN)
	{
		sendto_one_numeric(source_p, ERR_INVALIDBAN, form_str(ERR_INVALIDBAN),
			chptr->chname, 'b', mask ? mask : "*");
		return;
	}

	if (!can_upsert_on_access_list(chptr, source_p, mask, newflags))
	{
		sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
			me.name, source_p->name, chptr->chname);
		return;
	}

	/*
	 * DENY and GRANT entries are stored in channel mode lists, not in
	 * the access_list.  Route through set_channel_mode so the change
	 * is properly propagated via TMODE to all servers.
	 *
	 *   DENY  -> banlist (+b)
	 *   GRANT -> invexlist (+I)
	 */
	if (newflags == ACCESS_DENY_FLAG || newflags == ACCESS_GRANT_FLAG)
	{
		const char *modestr = (newflags == ACCESS_DENY_FLAG) ? "+b" : "+I";
		const char *level_name = (newflags == ACCESS_DENY_FLAG) ? "DENY" : "GRANT";

		const char *para[] = {modestr, mask};
		set_channel_mode(source_p, &me, chptr, NULL, 2, para);

		if (MyClient(source_p))
		{
			sendto_one_numeric(source_p, RPL_ACCESSADD, form_str(RPL_ACCESSADD),
				chptr->chname, level_name, mask,
				(long) 0, source_p->name, "");
		}

		return;
	}

	/* only enforce ACL limit on non-upsert condition */
	if (rb_dlink_list_length(&chptr->access_list) + 1 > ConfigChannel.max_bans &&
	    channel_access_find(chptr, mask) == NULL)
	{
		sendto_one_numeric(source_p, ERR_ACCESS_TOOMANY, form_str(ERR_ACCESS_TOOMANY),
			chptr->chname);
		return;
	}

	struct AccessEntry *ae = channel_access_upsert(chptr, source_p, mask, newflags);

	if (MyClient(source_p))
	{
		sendto_one_numeric(source_p, RPL_ACCESSADD, form_str(RPL_ACCESSADD),
			chptr->chname, ae_level_name(ae->flags), ae->mask,
			(long) 0, ae->who, "");
	}

	sendto_server(source_p, chptr, CAP_TS6, NOCAPS,
		":%s TACCESS %s %ld %ld %s %s",
		use_id(&me), chptr->chname, (long)chptr->channelts, (long)ae->when,
		ae->mask, ae_level_name(ae->flags));
}

/*
 * can_join hook: ACCESS hierarchy overrides join restrictions.
 *
 * Per IRCX spec, users with sufficient ACCESS levels can override
 * channel join restrictions in a hierarchical manner:
 *
 *   OWNER/ADMIN (CHFL_ADMIN) - overrides: +b, +k, +i, +l, +j, +r
 *   HOST/OP (CHFL_CHANOP)    - overrides: +b, +k, +i, +l, +j
 *   VOICE (CHFL_VOICE)       - overrides: +b
 *   GRANT (invex)            - already handled by core via +I
 *   DENY (ban)               - already handled by core via +b
 *
 * This hook runs at HOOK_HIGHEST priority so it executes after the
 * core can_join checks have set the error, allowing us to clear it
 * if the user has sufficient access.
 */
static void
h_access_can_join(void *vdata)
{
	hook_data_channel *data = vdata;
	struct Client *source_p = data->client;
	struct Channel *chptr = data->chptr;

	/* only override if there IS an error to override */
	if (data->approved == 0)
		return;

	/* find the user's best ACCESS entry for this channel */
	struct AccessEntry *ae = channel_access_best_match(chptr, source_p);
	if (ae == NULL)
		return;

	/*
	 * Hierarchical override based on access level:
	 *
	 * CHFL_ADMIN (OWNER) >= 4: overrides everything
	 * CHFL_CHANOP (HOST) >= 2: overrides +b, +k, +i, +l, +j
	 * CHFL_VOICE         >= 1: overrides +b only
	 */
	unsigned int level = ae->flags;

	switch (data->approved)
	{
	case ERR_BANNEDFROMCHAN:
		/* VOICE+ can override bans */
		if (level >= CHFL_VOICE)
			data->approved = 0;
		break;

	case ERR_BADCHANNELKEY:
		/* HOST/OP+ can override +k */
		if (level >= CHFL_CHANOP)
			data->approved = 0;
		break;

	case ERR_INVITEONLYCHAN:
		/* HOST/OP+ can override +i */
		if (level >= CHFL_CHANOP)
			data->approved = 0;
		break;

	case ERR_CHANNELISFULL:
		/* HOST/OP+ can override +l */
		if (level >= CHFL_CHANOP)
			data->approved = 0;
		break;

	case ERR_THROTTLE:
		/* HOST/OP+ can override +j throttle */
		if (level >= CHFL_CHANOP)
			data->approved = 0;
		break;

	case ERR_NEEDREGGEDNICK:
		/* OWNER/ADMIN can override +r */
		if (level >= CHFL_ADMIN)
			data->approved = 0;
		break;

	default:
		break;
	}
}

static void
apply_access_entries(struct Channel *chptr, struct Client *client_p)
{
	/* use best_match to get the highest-privilege matching entry */
	struct AccessEntry *ae = channel_access_best_match(chptr, client_p);
	if (ae == NULL)
		return;

	char mode_char = ae_level_char(ae->flags);
	if (!mode_char)
		return;

	char modestr[] = {'+', mode_char, '\0'};
	const char *para[] = {modestr, client_p->name};
	set_channel_mode(client_p, &me, chptr, NULL, 2, para);
}

static void
handle_access_sync(struct Channel *chptr, struct Client *source_p)
{
	const struct membership *source_msptr = find_channel_membership(chptr, source_p);
	const rb_dlink_node *iter;

	if (source_msptr == NULL || !is_admin(source_msptr))
	{
		sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
			me.name, source_p->name, chptr->chname);
		return;
	}

	RB_DLINK_FOREACH(iter, chptr->members.head)
	{
		const struct membership *msptr = iter->data;

		apply_access_entries(chptr, msptr->client_p);
	}

	sendto_server(source_p, chptr, CAP_TS6, NOCAPS,
		":%s ACCESS %s SYNC",
		use_id(source_p), chptr->chname);
}

static void
m_access(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr = find_channel(parv[1]);
	if (chptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL, form_str(ERR_NOSUCHCHANNEL), parv[1]);
		return;
	}

	if (parv[2] == NULL || !rb_strcasecmp(parv[2], "LIST"))
		handle_access_list(chptr, source_p, parv[3]);
	else if (!rb_strcasecmp(parv[2], "ADD"))
		handle_access_upsert(chptr, source_p, parv[3], parv[4]);
	else if (!rb_strcasecmp(parv[2], "DEL") || !rb_strcasecmp(parv[2], "DELETE"))
	{
		/* Accept both: ACCESS #chan DELETE mask
		 *         and: ACCESS #chan DELETE level mask
		 * If parv[4] exists, use it (level was given). Otherwise use parv[3]. */
		const char *mask = (parc > 4 && parv[4] != NULL) ? parv[4] : parv[3];
		handle_access_delete(chptr, source_p, mask);
	}
	else if (!rb_strcasecmp(parv[2], "CLEAR"))
		handle_access_clear(chptr, source_p, parv[3]);
	else if (!rb_strcasecmp(parv[2], "SYNC"))
		handle_access_sync(chptr, source_p);
}

/*
 * TACCESS command (bursting).
 *
 * parv[0] = source
 * parv[1] = channel name
 * parv[2] = channel ts
 * parv[3] = entry ts
 * parv[4] = mask
 * parv[5] = level
 */
static void
ms_taccess(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr = find_channel(parv[1]);
	if (chptr == NULL)
		return;

	time_t creation_ts = atol(parv[2]);
	time_t entry_ts = atol(parv[3]);

	if (creation_ts > chptr->channelts)
		return;

	/* deletion: level missing or empty */
	if (parc < 6 || !*parv[5])
	{
		channel_access_delete(chptr, parv[4]);

		sendto_server(source_p, chptr, CAP_TS6, NOCAPS,
			":%s TACCESS %s %ld %ld %s :",
			use_id(&me), chptr->chname, creation_ts, entry_ts, parv[4]);
		return;
	}

	unsigned int flags = ae_level_from_name(parv[5]);
	if (flags == 0)
		return;

	/* DENY and GRANT entries are propagated via TMODE, not TACCESS */
	if (flags == ACCESS_DENY_FLAG || flags == ACCESS_GRANT_FLAG)
		return;

	struct AccessEntry *ae = channel_access_upsert(chptr, source_p, parv[4], flags);
	ae->when = entry_ts;

	sendto_server(source_p, chptr, CAP_TS6, NOCAPS,
		":%s TACCESS %s %ld %ld %s %s",
		use_id(&me), chptr->chname, creation_ts, entry_ts,
		ae->mask, ae_level_name(ae->flags));
}

/*
 * BTACCESS - Batched TACCESS for optimized burst.
 *
 * parv[1] = channel name
 * parv[2] = channel TS
 * parv[3] = space-separated triplets: "entryTS mask level entryTS mask level ..."
 */
static void
ms_btaccess(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr = find_channel(parv[1]);
	if (chptr == NULL)
		return;

	time_t creation_ts = atol(parv[2]);
	if (creation_ts > chptr->channelts)
		return;

	char *entries = LOCAL_COPY(parv[3]);
	char *p = entries;
	char *tok;

	while ((tok = strtok_r(p, " ", &p)) != NULL)
	{
		time_t entry_ts = atol(tok);

		char *mask = strtok_r(NULL, " ", &p);
		if (mask == NULL)
			break;

		char *level_name = strtok_r(NULL, " ", &p);
		if (level_name == NULL)
			break;

		unsigned int flags = ae_level_from_name(level_name);
		if (flags == 0)
			continue;

		if (flags == ACCESS_DENY_FLAG || flags == ACCESS_GRANT_FLAG)
			continue;

		struct AccessEntry *ae = channel_access_upsert(chptr, source_p, mask, flags);
		ae->when = entry_ts;

		/* re-propagate as individual TACCESS to non-BPROP servers */
		sendto_server(source_p, chptr, CAP_TS6, CAP_BPROP,
			":%s TACCESS %s %ld %ld %s %s",
			use_id(&me), chptr->chname, creation_ts, entry_ts,
			ae->mask, ae_level_name(ae->flags));
	}

	/* re-propagate in batched form to BPROP-capable servers */
	sendto_server(source_p, chptr, CAP_TS6 | CAP_BPROP, NOCAPS,
		":%s BTACCESS %s %s :%s",
		use_id(&me), parv[1], parv[2], parv[3]);
}

/* channel join hook */
static void
h_access_channel_join(void *vdata)
{
	hook_data_channel_activity *data = vdata;
	struct Channel *chptr = data->chptr;
	struct Client *client_p = data->client;

	apply_access_entries(chptr, client_p);
}

/*
 * Batched TACCESS burst.
 *
 * When the remote server supports CAP_BPROP, access entries are batched
 * into fewer messages using the BTACCESS command.  Entries are packed as
 * space-separated triplets (entryTS mask level) in the trailing parameter:
 *
 *   :<server> BTACCESS <channel> <channelTS> :<ts1> <mask1> <level1> <ts2> ...
 *
 * Fallback: one TACCESS per entry for servers without CAP_BPROP.
 */
static void
h_access_burst_channel(void *vdata)
{
	hook_data_channel *hchaninfo = vdata;
	struct Channel *chptr = hchaninfo->chptr;
	struct Client *client_p = hchaninfo->client;
	rb_dlink_node *it;

	if (rb_dlink_list_length(&chptr->access_list) == 0)
		return;

	if (IsCapable(client_p, CAP_BPROP))
	{
		static char buf[BUFSIZE];
		char *t;
		int mlen, cur_len;

		cur_len = mlen = snprintf(buf, sizeof buf, ":%s BTACCESS %s %ld :",
			me.id, chptr->chname, (long)chptr->channelts);
		t = buf + mlen;

		RB_DLINK_FOREACH(it, chptr->access_list.head)
		{
			struct AccessEntry *ae = it->data;
			const char *level_name = ae_level_name(ae->flags);
			char entry[BUFSIZE];
			int elen;

			elen = snprintf(entry, sizeof entry, "%ld %s %s",
				(long)ae->when, ae->mask, level_name);

			/* +1 for space separator */
			int need = elen + (cur_len > mlen ? 1 : 0);

			if (cur_len + need > BUFSIZE - 3)
			{
				if (cur_len > mlen)
				{
					sendto_one(client_p, "%s", buf);
					cur_len = mlen;
					t = buf + mlen;
				}

				if (mlen + elen > BUFSIZE - 3)
				{
					sendto_one(client_p, ":%s TACCESS %s %ld %ld %s %s",
						use_id(&me), chptr->chname,
						(long)chptr->channelts, (long)ae->when,
						ae->mask, level_name);
					continue;
				}
			}

			if (cur_len > mlen)
			{
				*t++ = ' ';
				cur_len++;
			}

			memcpy(t, entry, elen);
			t += elen;
			cur_len += elen;
			*t = '\0';
		}

		if (cur_len > mlen)
			sendto_one(client_p, "%s", buf);
	}
	else
	{
		RB_DLINK_FOREACH(it, chptr->access_list.head)
		{
			struct AccessEntry *ae = it->data;

			sendto_one(client_p, ":%s TACCESS %s %ld %ld %s %s",
				use_id(&me), chptr->chname, (long)chptr->channelts, ae->when,
				ae->mask, ae_level_name(ae->flags));
		}
	}
}

static void
h_access_channel_lowerts(void *vdata)
{
	hook_data_channel *hchaninfo = vdata;
	struct Channel *chptr = hchaninfo->chptr;

	channel_access_clear(chptr);
}
