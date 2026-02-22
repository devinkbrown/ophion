/*
 * modules/m_chanset.c — CHANSET command (ChanServ settings)
 *
 * CHANSET <#channel> <option> [value]
 *
 * Allows founders and users with CA_SET access to configure channel
 * registration settings, mode locks, topics, URLs, descriptions,
 * successors, and the unified ACCESS list.
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
#include "s_serv.h"

static const char chanset_desc[] =
	"Provides CHANSET command for managing channel registration settings";

static void m_chanset(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message chanset_msgtab = {
	"CHANSET", 0, 0, 0, 0,
	{mg_unreg, {m_chanset, 3}, mg_ignore, mg_ignore, mg_ignore, {m_chanset, 3}}
};

mapi_clist_av1 chanset_clist[] = {
	&chanset_msgtab, NULL
};

DECLARE_MODULE_AV2(chanset, NULL, NULL, chanset_clist, NULL, NULL, NULL, NULL, chanset_desc);

/* -------------------------------------------------------------------------
 * Helper: look up access level for source on a registered channel.
 * Returns the CA_* bitmask for the account, or 0 if none.
 * CA_FOUNDER is added if the account is the primary founder field.
 * ------------------------------------------------------------------------- */
static uint32_t
chanreg_access_for(struct svc_chanreg *reg, const char *account)
{
	rb_dlink_node *ptr;
	struct svc_chanaccess *ca;

	if (irccmp(reg->founder, account) == 0)
		return CA_FOUNDER | CA_SOP | CA_OP | CA_VOICE;

	RB_DLINK_FOREACH(ptr, reg->access.head)
	{
		ca = ptr->data;
		if (irccmp(ca->entity, account) == 0)
			return ca->flags;
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * Helper: parse on|off value to boolean.
 * Returns 1 on "on", 0 on "off", -1 on error.
 * ------------------------------------------------------------------------- */
static int
parse_onoff(const char *val)
{
	if (val == NULL)
		return -1;
	if (irccmp(val, "on") == 0 || irccmp(val, "1") == 0 || irccmp(val, "yes") == 0)
		return 1;
	if (irccmp(val, "off") == 0 || irccmp(val, "0") == 0 || irccmp(val, "no") == 0)
		return 0;
	return -1;
}

/* -------------------------------------------------------------------------
 * Helper: parse an IRC mode string (+nt-sk key etc.) into mlock bitmasks.
 * Supports single-letter modes only; parameters after modes are consumed
 * positionally.  Handles +l limit, +k key.
 *
 * The mode string is expected to be the full remainder of the parv starting
 * at modestr_idx.  parc/parv are the command's originals.
 * ------------------------------------------------------------------------- */
static void
parse_modelock(struct svc_chanreg *reg, const char *modestr)
{
	const char *p;
	int dir = MODE_ADD;
	uint32_t on = 0, off = 0;
	int limit = reg->mlock_limit;
	char key[KEYLEN + 1];

	rb_strlcpy(key, reg->mlock_key, sizeof(key));

	for (p = modestr; *p != '\0'; p++)
	{
		switch (*p)
		{
		case '+':
			dir = MODE_ADD;
			break;
		case '-':
			dir = MODE_DEL;
			break;
		case 'p':
			if (dir == MODE_ADD) { on |= MODE_PRIVATE;    off &= ~MODE_PRIVATE; }
			else                 { off |= MODE_PRIVATE;   on  &= ~MODE_PRIVATE; }
			break;
		case 's':
			if (dir == MODE_ADD) { on |= MODE_SECRET;     off &= ~MODE_SECRET; }
			else                 { off |= MODE_SECRET;    on  &= ~MODE_SECRET; }
			break;
		case 'm':
			if (dir == MODE_ADD) { on |= MODE_MODERATED;  off &= ~MODE_MODERATED; }
			else                 { off |= MODE_MODERATED; on  &= ~MODE_MODERATED; }
			break;
		case 't':
			if (dir == MODE_ADD) { on |= MODE_TOPICLIMIT;  off &= ~MODE_TOPICLIMIT; }
			else                 { off |= MODE_TOPICLIMIT; on  &= ~MODE_TOPICLIMIT; }
			break;
		case 'i':
			if (dir == MODE_ADD) { on |= MODE_INVITEONLY;  off &= ~MODE_INVITEONLY; }
			else                 { off |= MODE_INVITEONLY; on  &= ~MODE_INVITEONLY; }
			break;
		case 'n':
			if (dir == MODE_ADD) { on |= MODE_NOPRIVMSGS;  off &= ~MODE_NOPRIVMSGS; }
			else                 { off |= MODE_NOPRIVMSGS; on  &= ~MODE_NOPRIVMSGS; }
			break;
		case 'l':
			if (dir == MODE_ADD)
			{
				/* limit value must be embedded after space or end */
				/* caller should have tokenised it; skip for now */
				limit = 0; /* cleared; caller sets from next token */
			}
			else
			{
				limit = 0;
			}
			break;
		case 'k':
			if (dir == MODE_ADD)
			{
				/* key set by caller from next token */
			}
			else
			{
				key[0] = '\0';
			}
			break;
		default:
			break;
		}
	}

	reg->mlock_on  = on;
	reg->mlock_off = off;
	reg->mlock_limit = limit;
	rb_strlcpy(reg->mlock_key, key, sizeof(reg->mlock_key));
}

/* -------------------------------------------------------------------------
 * Helper: convert a flags_string such as "founder","sop","aop","hop","vop",
 * "akick", or a raw decimal number to a CA_* bitmask.
 * Returns 0 on unrecognised string.
 * ------------------------------------------------------------------------- */
static uint32_t
parse_access_flags(const char *str)
{
	if (str == NULL)
		return 0;
	if (irccmp(str, "founder") == 0)
		return CA_FOUNDER;
	if (irccmp(str, "sop") == 0)
		return CA_SOP;
	if (irccmp(str, "aop") == 0)
		return CA_AOP;
	if (irccmp(str, "hop") == 0)
		return CA_HOP;
	if (irccmp(str, "vop") == 0)
		return CA_VOP;
	if (irccmp(str, "akick") == 0)
		return CA_AKICK;
	/* raw decimal */
	return (uint32_t) atol(str);
}

/* -------------------------------------------------------------------------
 * ACCESS LIST sub-handler
 * ------------------------------------------------------------------------- */
static void
chanset_access_list(struct Client *source_p, struct svc_chanreg *reg)
{
	rb_dlink_node *ptr;
	struct svc_chanaccess *ca;
	int n = 0;

	svc_notice(source_p, "ChanServ", "Access list for \2%s\2:", reg->channel);

	RB_DLINK_FOREACH(ptr, reg->access.head)
	{
		ca = ptr->data;
		svc_notice(source_p, "ChanServ",
			"  %-32s 0x%08x  set by %s",
			ca->entity, ca->flags, ca->setter);
		n++;
	}

	if (n == 0)
		svc_notice(source_p, "ChanServ", "  (no entries)");

	svc_notice(source_p, "ChanServ", "End of access list.");
}

/* -------------------------------------------------------------------------
 * ACCESS ADD sub-handler
 * ------------------------------------------------------------------------- */
static void
chanset_access_add(struct Client *source_p, struct svc_chanreg *reg,
	const char *entity, const char *flags_str)
{
	struct svc_chanaccess *ca;
	rb_dlink_node *ptr;
	uint32_t flags;

	flags = parse_access_flags(flags_str);
	if (flags == 0)
	{
		svc_notice(source_p, "ChanServ",
			"Unknown access level '%s'.  Use: founder sop aop hop vop akick or a raw number.",
			flags_str);
		return;
	}

	/* Update existing entry if present */
	RB_DLINK_FOREACH(ptr, reg->access.head)
	{
		ca = ptr->data;
		if (irccmp(ca->entity, entity) == 0)
		{
			ca->flags = flags;
			rb_strlcpy(ca->setter, source_p->user->suser, sizeof(ca->setter));
			ca->set_ts = rb_current_time();
			svc_db_chanaccess_add(reg->channel, ca);
			/* Targeted access-entry sync — no need to burst full chanreg */
			svc_sync_chanaccess_set(reg, ca);
			svc_notice(source_p, "ChanServ",
				"Updated access for \2%s\2 on %s to 0x%08x.",
				entity, reg->channel, flags);
			return;
		}
	}

	/* New entry */
	ca = rb_malloc(sizeof(*ca));
	rb_strlcpy(ca->entity, entity, sizeof(ca->entity));
	ca->flags  = flags;
	rb_strlcpy(ca->setter, source_p->user->suser, sizeof(ca->setter));
	ca->set_ts = rb_current_time();

	rb_dlinkAddTail(ca, &ca->node, &reg->access);

	svc_db_chanaccess_add(reg->channel, ca);
	/* Targeted access-entry sync */
	svc_sync_chanaccess_set(reg, ca);

	svc_notice(source_p, "ChanServ",
		"Added \2%s\2 to access list of %s with flags 0x%08x.",
		entity, reg->channel, flags);
}

/* -------------------------------------------------------------------------
 * ACCESS DEL sub-handler
 * ------------------------------------------------------------------------- */
static void
chanset_access_del(struct Client *source_p, struct svc_chanreg *reg,
	const char *entity)
{
	struct svc_chanaccess *ca;
	rb_dlink_node *ptr, *next_ptr;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, reg->access.head)
	{
		ca = ptr->data;
		if (irccmp(ca->entity, entity) == 0)
		{
			rb_dlinkDelete(ptr, &reg->access);
			svc_db_chanaccess_delete(reg->channel, entity);
			/* Targeted access-entry sync — no need to burst full chanreg */
			svc_sync_chanaccess_del(reg->channel, entity);
			rb_free(ca);
			svc_notice(source_p, "ChanServ",
				"Removed \2%s\2 from access list of %s.",
				entity, reg->channel);
			return;
		}
	}

	svc_notice(source_p, "ChanServ",
		"\2%s\2 was not found on the access list for %s.", entity, reg->channel);
}

/* -------------------------------------------------------------------------
 * Main CHANSET handler
 * ------------------------------------------------------------------------- */
static void
m_chanset(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *chname, *option, *value;
	struct svc_chanreg *reg;
	struct Channel *chptr;
	uint32_t access_flags;
	int onoff;

	if (!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "CHANSET");
		return;
	}

	if (EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "ChanServ",
			"You must be identified to an account to use CHANSET.");
		return;
	}

	chname = parv[1];
	option = parv[2];
	value  = (parc > 3) ? parv[3] : NULL;

	if (!IsChannelName(chname))
	{
		svc_notice(source_p, "ChanServ", "%s is not a valid channel name.", chname);
		return;
	}

	reg = svc_chanreg_find(chname);
	if (reg == NULL)
	{
		svc_notice(source_p, "ChanServ", "Channel %s is not registered.", chname);
		return;
	}

	access_flags = chanreg_access_for(reg, source_p->user->suser);

	/* ACCESS subcommand has its own permission check */
	if (irccmp(option, "ACCESS") == 0)
	{
		/* Must have at least CA_SET or be oper */
		if (!(access_flags & (CA_SET | CA_FOUNDER)) && !IsOper(source_p))
		{
			svc_notice(source_p, "ChanServ",
				"You do not have sufficient access on %s.", chname);
			return;
		}

		const char *subcmd = value;            /* parv[3] */
		const char *entity = (parc > 4) ? parv[4] : NULL;
		const char *flags_str = (parc > 5) ? parv[5] : NULL;

		if (subcmd == NULL || irccmp(subcmd, "LIST") == 0)
		{
			chanset_access_list(source_p, reg);
			return;
		}

		if (irccmp(subcmd, "ADD") == 0)
		{
			if (entity == NULL || flags_str == NULL)
			{
				svc_notice(source_p, "ChanServ",
					"Usage: CHANSET %s ACCESS ADD <entity> <flags>", chname);
				return;
			}
			/* Only founders / opers can add CA_FOUNDER */
			if (!(access_flags & CA_FOUNDER) && !IsOperAdmin(source_p))
			{
				if (parse_access_flags(flags_str) & CA_FOUNDER)
				{
					svc_notice(source_p, "ChanServ",
						"Only the founder can grant founder access.");
					return;
				}
			}
			chanset_access_add(source_p, reg, entity, flags_str);
			return;
		}

		if (irccmp(subcmd, "DEL") == 0)
		{
			if (entity == NULL)
			{
				svc_notice(source_p, "ChanServ",
					"Usage: CHANSET %s ACCESS DEL <entity>", chname);
				return;
			}
			chanset_access_del(source_p, reg, entity);
			return;
		}

		svc_notice(source_p, "ChanServ",
			"Unknown ACCESS subcommand: %s.  Use LIST, ADD, or DEL.", subcmd);
		return;
	}

	/* All other options require CA_SET or CA_FOUNDER */
	if (!(access_flags & (CA_SET | CA_FOUNDER)) && !IsOper(source_p))
	{
		svc_notice(source_p, "ChanServ",
			"You do not have sufficient access on %s.", chname);
		return;
	}

	/* ---- Boolean flag options ---- */

#define CHANSET_BOOL_FLAG(optname, flag) \
	if (irccmp(option, (optname)) == 0) \
	{ \
		onoff = parse_onoff(value); \
		if (onoff < 0) \
		{ \
			svc_notice(source_p, "ChanServ", \
				"Usage: CHANSET %s %s on|off", chname, (optname)); \
			return; \
		} \
		if (onoff) reg->flags |= (flag); \
		else        reg->flags &= ~(flag); \
		svc_db_chanreg_save(reg); \
		svc_sync_chanreg(reg); \
		svc_notice(source_p, "ChanServ", \
			"%s for %s is now \2%s\2.", (optname), chname, onoff ? "ON" : "OFF"); \
		return; \
	}

	/*
	 * TOPICLOCK — when ON, also locks +t in the modelock so that only
	 * chanops (which ChanServ grants to CA_OP+ users automatically) can
	 * change the topic.  When OFF, +t is removed from the modelock unless
	 * the operator explicitly set it via MODELOCK.
	 */
	if(irccmp(option, "TOPICLOCK") == 0)
	{
		onoff = parse_onoff(value);
		if(onoff < 0)
		{
			svc_notice(source_p, "ChanServ",
				"Usage: CHANSET %s TOPICLOCK on|off", chname);
			return;
		}
		if(onoff)
		{
			reg->flags |= CHANREG_TOPICLOCK;
			reg->mlock_on  |=  MODE_TOPICLIMIT;
			reg->mlock_off &= ~MODE_TOPICLIMIT;
		}
		else
		{
			reg->flags &= ~CHANREG_TOPICLOCK;
			reg->mlock_on &= ~MODE_TOPICLIMIT;
			/* Don't force-remove +t; let the channel keep it if ops want it */
		}
		svc_db_chanreg_save(reg);
		svc_sync_chanreg(reg);
		/* Immediately enforce the mlock change on the live channel */
		{
			struct Channel *chptr = find_channel(chname);
			if(chptr != NULL)
				svc_modelock_enforce(chptr, reg);
		}
		svc_notice(source_p, "ChanServ",
			"TOPICLOCK for %s is now \2%s\2.%s", chname,
			onoff ? "ON" : "OFF",
			onoff ? "  Channel mode +t has been locked." : "");
		return;
	}
	CHANSET_BOOL_FLAG("KEEPTOPIC",  CHANREG_KEEPTOPIC)
	CHANSET_BOOL_FLAG("SECURE",     CHANREG_SECURE)
	CHANSET_BOOL_FLAG("GUARD",      CHANREG_GUARD)
	CHANSET_BOOL_FLAG("RESTRICTED", CHANREG_RESTRICTED)
	CHANSET_BOOL_FLAG("PRIVATE",    CHANREG_PRIVATE)
	CHANSET_BOOL_FLAG("VERBOSE",    CHANREG_VERBOSE)
	CHANSET_BOOL_FLAG("FANTASY",    CHANREG_FANTASY)
	CHANSET_BOOL_FLAG("PROPLOCK",   CHANREG_PROP_LOCKED)

#undef CHANSET_BOOL_FLAG

	/* ---- MODELOCK ---- */
	if (irccmp(option, "MODELOCK") == 0)
	{
		if (value == NULL)
		{
			/* Clear modelock */
			reg->mlock_on    = 0;
			reg->mlock_off   = 0;
			reg->mlock_limit = 0;
			reg->mlock_key[0] = '\0';
			svc_db_chanreg_save(reg);
			svc_sync_chanreg(reg);
			svc_notice(source_p, "ChanServ",
				"Mode lock for %s has been cleared.", chname);
			return;
		}

		/* Reset first */
		reg->mlock_on    = 0;
		reg->mlock_off   = 0;
		reg->mlock_limit = 0;
		reg->mlock_key[0] = '\0';

		parse_modelock(reg, value);

		/* Check if a limit parameter follows in parv[4] */
		if (parc > 4 && parv[4] != NULL)
		{
			const char *p = value;
			int expect_limit = 0, dir = MODE_ADD;
			for (; *p; p++)
			{
				if (*p == '+') { dir = MODE_ADD; continue; }
				if (*p == '-') { dir = MODE_DEL; continue; }
				if (*p == 'l' && dir == MODE_ADD) { expect_limit = 1; break; }
			}
			if (expect_limit)
			{
				reg->mlock_limit = atoi(parv[4]);
				/* key would be parv[5] */
				if (parc > 5 && parv[5] != NULL)
				{
					const char *mp = value;
					int ddir = MODE_ADD;
					for (; *mp; mp++)
					{
						if (*mp == '+') { ddir = MODE_ADD; continue; }
						if (*mp == '-') { ddir = MODE_DEL; continue; }
						if (*mp == 'k' && ddir == MODE_ADD)
						{
							rb_strlcpy(reg->mlock_key, parv[5], sizeof(reg->mlock_key));
							break;
						}
					}
				}
			}
			else
			{
				/* Perhaps only a key follows */
				const char *mp = value;
				int ddir = MODE_ADD;
				for (; *mp; mp++)
				{
					if (*mp == '+') { ddir = MODE_ADD; continue; }
					if (*mp == '-') { ddir = MODE_DEL; continue; }
					if (*mp == 'k' && ddir == MODE_ADD)
					{
						rb_strlcpy(reg->mlock_key, parv[4], sizeof(reg->mlock_key));
						break;
					}
				}
			}
		}

		svc_db_chanreg_save(reg);
		svc_sync_chanreg(reg);

		svc_notice(source_p, "ChanServ",
			"Mode lock for %s set to \2%s\2.", chname, value);

		/* Apply to the live channel if it exists */
		chptr = find_channel(reg->channel);
		if (chptr != NULL)
			svc_modelock_enforce(chptr, reg);

		return;
	}

	/* ---- TOPIC ---- */
	if (irccmp(option, "TOPIC") == 0)
	{
		if (value == NULL)
		{
			svc_notice(source_p, "ChanServ",
				"Usage: CHANSET %s TOPIC <text>", chname);
			return;
		}

		rb_strlcpy(reg->topic, value, sizeof(reg->topic));
		rb_strlcpy(reg->topic_setter, source_p->user->suser, sizeof(reg->topic_setter));
		reg->topic_ts = rb_current_time();

		/* Apply to live channel */
		chptr = find_channel(reg->channel);
		if (chptr != NULL)
		{
			char topic_info[NICKLEN + USERLEN + HOSTLEN + 3];
			snprintf(topic_info, sizeof(topic_info), "%s!%s@%s",
				source_p->name, source_p->username, source_p->host);
			set_channel_topic(chptr, value, topic_info, reg->topic_ts);
			sendto_server(NULL, chptr, CAP_TS6, NOCAPS,
				":%s TOPIC %s :%s",
				use_id(source_p), chptr->chname, value);
			sendto_channel_local(NULL, ALL_MEMBERS, chptr,
				":%s!%s@%s TOPIC %s :%s",
				source_p->name, source_p->username, source_p->host,
				chptr->chname, value);
		}

		svc_db_chanreg_save(reg);
		svc_sync_chanreg(reg);

		svc_notice(source_p, "ChanServ",
			"Topic for %s set to: %s", chname, value);
		return;
	}

	/* ---- URL ---- */
	if (irccmp(option, "URL") == 0)
	{
		if (value == NULL)
			value = "";

		rb_strlcpy(reg->url, value, sizeof(reg->url));
		svc_db_chanreg_save(reg);
		svc_sync_chanreg(reg);
		svc_notice(source_p, "ChanServ",
			"URL for %s set to: %s", chname, *value ? value : "(cleared)");
		return;
	}

	/* ---- DESC ---- */
	if (irccmp(option, "DESC") == 0)
	{
		if (value == NULL)
			value = "";

		rb_strlcpy(reg->description, value, sizeof(reg->description));
		svc_db_chanreg_save(reg);
		svc_sync_chanreg(reg);
		svc_notice(source_p, "ChanServ",
			"Description for %s set to: %s", chname, *value ? value : "(cleared)");
		return;
	}

	/* ---- SUCCESSOR ---- */
	if (irccmp(option, "SUCCESSOR") == 0)
	{
		if (value == NULL || strcmp(value, "-") == 0)
		{
			reg->successor[0] = '\0';
			svc_db_chanreg_save(reg);
			svc_sync_chanreg(reg);
			svc_notice(source_p, "ChanServ",
				"Successor for %s has been cleared.", chname);
			return;
		}

		/* Verify the account exists */
		if (svc_account_find(value) == NULL)
		{
			svc_notice(source_p, "ChanServ",
				"Account \2%s\2 does not exist.", value);
			return;
		}

		rb_strlcpy(reg->successor, value, sizeof(reg->successor));
		svc_db_chanreg_save(reg);
		svc_sync_chanreg(reg);
		svc_notice(source_p, "ChanServ",
			"Successor for %s set to \2%s\2.", chname, value);
		return;
	}

	svc_notice(source_p, "ChanServ",
		"Unknown CHANSET option: \2%s\2.  Options: TOPICLOCK KEEPTOPIC SECURE GUARD "
		"RESTRICTED PRIVATE VERBOSE FANTASY PROPLOCK MODELOCK TOPIC URL DESC SUCCESSOR ACCESS",
		option);
}
