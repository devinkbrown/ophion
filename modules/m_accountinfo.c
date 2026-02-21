/*
 * modules/m_accountinfo.c — Services INFO command
 *
 * Display information about a nick account or a registered channel.
 *
 * Syntax:
 *   INFO              — show info about the caller's own account
 *   INFO <account>    — show info about a named account
 *   INFO #channel     — show info about a registered channel
 *
 * Account output (as server NOTICEs):
 *   Account:       <name>
 *   Registered:    <date>
 *   Last seen:     <date> (as <nick> from <host>)   [hidden if ACCT_PRIVATE and not oper/self]
 *   Email:         <email>                          [hidden if ACCT_HIDEMAIL and not oper/self]
 *   Flags:         <active flags>
 *   Linked oper:   <block>                          [only to oper or account owner]
 *   Grouped nicks: <nick1>, <nick2>, ...
 *   Certificates: <count>
 *
 * Channel output:
 *   Channel:        <name>
 *   Founder:        <account>
 *   Registered:     <date>
 *   Topic:          <topic>   [if CHANREG_KEEPTOPIC and topic set]
 *   URL:            <url>     [if set]
 *   Flags:          <active flags>
 *   Access entries: <count>
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

static const char accountinfo_desc[] =
	"Services INFO command — display account and channel registration information";

static void m_info(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message info_msgtab = {
	"INFO", 0, 0, 0, 0,
	{mg_unreg, {m_info, 1}, mg_ignore, mg_ignore, mg_ignore, {m_info, 1}}
};

mapi_clist_av1 accountinfo_clist[] = { &info_msgtab, NULL };

DECLARE_MODULE_AV2(m_accountinfo, NULL, NULL, accountinfo_clist, NULL, NULL, NULL, NULL, accountinfo_desc);

/* ---- helpers ------------------------------------------------------------ */

/*
 * format_time — render a Unix timestamp as a human-readable UTC string.
 * Falls back to "never" for zero timestamps.
 */
static const char *
format_time(time_t ts)
{
	static char buf[64];

	if(ts == 0)
		return "never";

	struct tm *tm_p = gmtime(&ts);
	if(tm_p == NULL)
		return "unknown";

	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", tm_p);
	return buf;
}

/*
 * build_flag_string_account — build a comma-separated list of active
 * ACCT_* flag names for an account.
 * Returns a pointer to a static buffer.
 */
static const char *
build_flag_string_account(uint32_t flags)
{
	static char buf[512];
	buf[0] = '\0';

	static const struct { uint32_t flag; const char *name; } ftab[] = {
		{ ACCT_SUSPENDED,   "SUSPENDED"   },
		{ ACCT_HOLD,        "HOLD"        },
		{ ACCT_NEVEREXPIRE, "NEVEREXPIRE" },
		{ ACCT_HIDEMAIL,    "HIDEMAIL"    },
		{ ACCT_NOMEMO,      "NOMEMO"      },
		{ ACCT_MEMONOTIFY,  "MEMONOTIFY"  },
		{ ACCT_PROTECT,     "PROTECT"     },
		{ ACCT_SECURE,      "SECURE"      },
		{ ACCT_PRIVATE,     "PRIVATE"     },
		{ ACCT_NOOP,        "NOOP"        },
		{ ACCT_SASLONLY,    "SASLONLY"    },
		{ ACCT_OPERATOR,    "OPERATOR"    },
		{ ACCT_NOEXPIRE,    "NOEXPIRE"    },
		{ ACCT_ENFORCE,     "ENFORCE"     },
		{ 0, NULL }
	};

	for(int i = 0; ftab[i].name != NULL; i++)
	{
		if(!(flags & ftab[i].flag))
			continue;

		if(buf[0] != '\0')
			rb_strlcat(buf, ", ", sizeof(buf));

		rb_strlcat(buf, ftab[i].name, sizeof(buf));
	}

	return buf[0] ? buf : "(none)";
}

/*
 * build_flag_string_chan — build a comma-separated list of active
 * CHANREG_* flag names for a channel registration.
 */
static const char *
build_flag_string_chan(uint32_t flags)
{
	static char buf[512];
	buf[0] = '\0';

	static const struct { uint32_t flag; const char *name; } ftab[] = {
		{ CHANREG_SUSPENDED,  "SUSPENDED"  },
		{ CHANREG_SECURE,     "SECURE"     },
		{ CHANREG_PRIVATE,    "PRIVATE"    },
		{ CHANREG_TOPICLOCK,  "TOPICLOCK"  },
		{ CHANREG_KEEPTOPIC,  "KEEPTOPIC"  },
		{ CHANREG_VERBOSE,    "VERBOSE"    },
		{ CHANREG_RESTRICTED, "RESTRICTED" },
		{ CHANREG_NOEXPIRE,   "NOEXPIRE"   },
		{ CHANREG_GUARD,      "GUARD"      },
		{ CHANREG_FANTASY,    "FANTASY"    },
		{ 0, NULL }
	};

	for(int i = 0; ftab[i].name != NULL; i++)
	{
		if(!(flags & ftab[i].flag))
			continue;

		if(buf[0] != '\0')
			rb_strlcat(buf, ", ", sizeof(buf));

		rb_strlcat(buf, ftab[i].name, sizeof(buf));
	}

	return buf[0] ? buf : "(none)";
}

/* ---- account INFO display ----------------------------------------------- */

static void
show_account_info(struct Client *source_p, struct svc_account *acct)
{
	bool is_oper = IsOper(source_p);
	bool is_self = (IsPerson(source_p) &&
			!EmptyString(source_p->user->suser) &&
			irccmp(source_p->user->suser, acct->name) == 0);

	svc_notice(source_p, "Services",
		"Information for account \2%s\2:", acct->name);

	svc_notice(source_p, "Services",
		"  %-16s %s", "Registered:", format_time(acct->registered_ts));

	/* Last seen — hidden for PRIVATE accounts unless oper or self. */
	if(is_oper || is_self || !(acct->flags & ACCT_PRIVATE))
	{
		if(acct->last_seen_ts == 0)
		{
			svc_notice(source_p, "Services",
				"  %-16s never", "Last seen:");
		}
		else
		{
			svc_notice(source_p, "Services",
				"  %-16s %s (as %s from %s)",
				"Last seen:",
				format_time(acct->last_seen_ts),
				acct->last_seen_nick[0] ? acct->last_seen_nick : "unknown",
				acct->last_seen_host[0] ? acct->last_seen_host : "unknown");
		}
	}

	/* Email — hidden for HIDEMAIL unless oper or self. */
	if(is_oper || is_self || !(acct->flags & ACCT_HIDEMAIL))
	{
		svc_notice(source_p, "Services",
			"  %-16s %s",
			"Email:",
			acct->email[0] ? acct->email : "(not set)");
	}

	/* Active flags. */
	svc_notice(source_p, "Services",
		"  %-16s %s", "Flags:", build_flag_string_account(acct->flags));

	/* Linked oper block — only to oper or account owner. */
	if(is_oper || is_self)
	{
		if(acct->oper_block[0])
			svc_notice(source_p, "Services",
				"  %-16s %s", "Linked oper:", acct->oper_block);
	}

	/* Grouped nicks. */
	if(rb_dlink_list_length(&acct->nicks) > 0)
	{
		char nick_buf[BUFSIZE];
		nick_buf[0] = '\0';

		rb_dlink_node *ptr;
		RB_DLINK_FOREACH(ptr, acct->nicks.head)
		{
			struct svc_nick *sn = ptr->data;
			if(nick_buf[0] != '\0')
				rb_strlcat(nick_buf, ", ", sizeof(nick_buf));
			rb_strlcat(nick_buf, sn->nick, sizeof(nick_buf));
		}

		svc_notice(source_p, "Services",
			"  %-16s %s", "Grouped nicks:", nick_buf);
	}
	else
	{
		svc_notice(source_p, "Services",
			"  %-16s (none)", "Grouped nicks:");
	}

	/* Certificate count. */
	svc_notice(source_p, "Services",
		"  %-16s %zu",
		"Certificates:",
		rb_dlink_list_length(&acct->certfps));

	svc_notice(source_p, "Services",
		"End of INFO for \2%s\2.", acct->name);
}

/* ---- channel INFO display ----------------------------------------------- */

static void
show_channel_info(struct Client *source_p, struct svc_chanreg *reg)
{
	svc_notice(source_p, "Services",
		"Information for channel \2%s\2:", reg->channel);

	svc_notice(source_p, "Services",
		"  %-16s %s", "Founder:", reg->founder);

	svc_notice(source_p, "Services",
		"  %-16s %s", "Registered:", format_time(reg->registered_ts));

	/* Topic — only if KEEPTOPIC is set and topic is non-empty. */
	if((reg->flags & CHANREG_KEEPTOPIC) && reg->topic[0])
		svc_notice(source_p, "Services",
			"  %-16s %s", "Topic:", reg->topic);

	/* URL — only if set. */
	if(reg->url[0])
		svc_notice(source_p, "Services",
			"  %-16s %s", "URL:", reg->url);

	/* Active flags. */
	svc_notice(source_p, "Services",
		"  %-16s %s", "Flags:", build_flag_string_chan(reg->flags));

	/* Access entry count. */
	svc_notice(source_p, "Services",
		"  %-16s %zu",
		"Access entries:",
		rb_dlink_list_length(&reg->access));

	svc_notice(source_p, "Services",
		"End of INFO for \2%s\2.", reg->channel);
}

/* ---- command handler ---------------------------------------------------- */

/*
 * m_info — INFO [<account>|#channel]
 *
 * parv[1] = optional account name or #channel (absent = caller's account)
 */
static void
m_info(struct MsgBuf *msgbuf_p, struct Client *client_p,
       struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "INFO");
		return;
	}

	if(!IsPerson(source_p))
		return;

	const char *target = (parc >= 2 && !EmptyString(parv[1])) ? parv[1] : NULL;

	/* ---- Channel INFO ---- */
	if(target != NULL && IsChanPrefix(target[0]))
	{
		struct svc_chanreg *reg = svc_chanreg_find(target);
		if(reg == NULL)
		{
			svc_notice(source_p, "Services",
				"Channel \2%s\2 is not registered.", target);
			return;
		}

		show_channel_info(source_p, reg);
		return;
	}

	/* ---- Account INFO ---- */

	/* Determine which account to look up. */
	const char *acct_name;

	if(target != NULL)
	{
		acct_name = target;
	}
	else
	{
		/* No argument: show the caller's own account. */
		if(EmptyString(source_p->user->suser))
		{
			svc_notice(source_p, "Services",
				"You are not identified to any account. "
				"Use: INFO <account>");
			return;
		}
		acct_name = source_p->user->suser;
	}

	/* Try looking up by account name first, then by nick. */
	struct svc_account *acct = svc_account_find(acct_name);
	if(acct == NULL)
		acct = svc_account_find_nick(acct_name);

	if(acct == NULL)
	{
		svc_notice(source_p, "Services",
			"Account \2%s\2 is not registered.", acct_name);
		return;
	}

	/* PRIVATE accounts are hidden from non-opers who aren't the owner. */
	if((acct->flags & ACCT_PRIVATE) && !IsOper(source_p))
	{
		bool is_self = (!EmptyString(source_p->user->suser) &&
				irccmp(source_p->user->suser, acct->name) == 0);

		if(!is_self)
		{
			svc_notice(source_p, "Services",
				"Account \2%s\2 is not registered.", acct_name);
			return;
		}
	}

	show_account_info(source_p, acct);
}
