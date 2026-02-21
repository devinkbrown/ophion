/*
 * modules/m_ircx_event.c
 *
 * IRCX EVENT system per draft-pfenning-irc-extensions-04.
 *
 * EVENT ADD <event> [<mask>]  - subscribe to an event type
 * EVENT DELETE <event> [<mask>] - unsubscribe from an event type
 * EVENT LIST [<event>]        - list current event subscriptions
 *
 * Event types:
 *   CHANNEL  - channel create, destroy, topic, mode, property changes
 *   MEMBER   - join, part, kick, membership mode changes
 *   USER     - nick change, mode change, quit, kill, kline
 *   SERVER   - server connect/disconnect
 *   OPERSPY  - oper command usage (admin, info, links, motd, stats, trace,
 *              whois-on-oper, and operspy commands)
 *
 * Only IRC operators may subscribe to events.  The subscription mask is
 * matched against a per-event subject (nick!user@host, channel name, or
 * server name) using glob patterns.
 *
 * This replaces legacy oper monitoring tools: sno_channelcreate,
 * sno_farconnect, sno_globalkline, sno_globalnickchange, sno_globaloper,
 * sno_whois, spy_admin_notice, spy_info_notice, spy_links_notice,
 * spy_motd_notice, spy_stats_notice, spy_stats_p_notice, spy_trace_notice.
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
#include "s_conf.h"
#include "s_newconf.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"

static const char ircx_event_desc[] = "Provides IRCX EVENT command for oper event monitoring";

/* event type bits */
#define EVENT_CHANNEL	0x01
#define EVENT_MEMBER	0x02
#define EVENT_USER	0x04
#define EVENT_SERVER	0x08
#define EVENT_OPERSPY	0x10
#define EVENT_ALL	(EVENT_CHANNEL | EVENT_MEMBER | EVENT_USER | EVENT_SERVER | EVENT_OPERSPY)

struct event_type_name {
	const char *name;
	unsigned int flag;
};

static const struct event_type_name event_types[] = {
	{ "CHANNEL", EVENT_CHANNEL },
	{ "MEMBER",  EVENT_MEMBER },
	{ "OPERSPY", EVENT_OPERSPY },
	{ "USER",    EVENT_USER },
	{ "SERVER",  EVENT_SERVER },
	{ NULL, 0 }
};

static unsigned int
event_flag_from_name(const char *name)
{
	for (int i = 0; event_types[i].name != NULL; i++)
	{
		if (!rb_strcasecmp(name, event_types[i].name))
			return event_types[i].flag;
	}
	return 0;
}

static const char *
event_name_from_flag(unsigned int flag)
{
	for (int i = 0; event_types[i].name != NULL; i++)
	{
		if (event_types[i].flag == flag)
			return event_types[i].name;
	}
	return "UNKNOWN";
}

/*
 * Per-client event subscription tracking.
 * The mask is matched against the event subject (nick!user@host, channel
 * name, or server name) using glob patterns.
 */
struct event_sub {
	rb_dlink_node node;
	struct Client *client;
	unsigned int events;		/* bitmask of EVENT_* */
	char mask[256];			/* subject glob, default * */
};

static rb_dlink_list event_subscribers = { NULL, NULL, 0 };

static struct event_sub *
find_event_sub(struct Client *client_p)
{
	rb_dlink_node *iter;
	RB_DLINK_FOREACH(iter, event_subscribers.head)
	{
		struct event_sub *sub = iter->data;
		if (sub->client == client_p)
			return sub;
	}
	return NULL;
}

static struct event_sub *
get_or_create_event_sub(struct Client *client_p)
{
	struct event_sub *sub = find_event_sub(client_p);
	if (sub != NULL)
		return sub;

	sub = rb_malloc(sizeof(*sub));
	sub->client = client_p;
	sub->events = 0;
	rb_strlcpy(sub->mask, "*", sizeof(sub->mask));
	rb_dlinkAdd(sub, &sub->node, &event_subscribers);
	return sub;
}

static void
remove_event_sub(struct Client *client_p)
{
	struct event_sub *sub = find_event_sub(client_p);
	if (sub == NULL)
		return;

	rb_dlinkDelete(&sub->node, &event_subscribers);
	rb_free(sub);
}

/*
 * Dispatch an event notification to all subscribers of the given event type.
 * The subject is matched against each subscriber's mask with match().
 */
static void
dispatch_event_subj(unsigned int event_flag, const char *subject,
                    const char *fmt, ...)
{
	rb_dlink_node *iter;
	char buf[BUFSIZE];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	RB_DLINK_FOREACH(iter, event_subscribers.head)
	{
		struct event_sub *sub = iter->data;

		if (!(sub->events & event_flag))
			continue;

		if (!match(sub->mask, subject))
			continue;

		sendto_one_notice(sub->client, ":*** EVENT %s %s",
			event_name_from_flag(event_flag), buf);
	}
}

/*
 * DISPATCH_USER - build a nick!user@host subject and dispatch.
 * Used for USER and OPERSPY events where the subject is a user.
 */
#define DISPATCH_USER(flag_, client_, fmt_, ...) \
	do { \
		char _subj[NICKLEN + 1 + USERLEN + 1 + HOSTLEN + 1]; \
		snprintf(_subj, sizeof(_subj), "%s!%s@%s", \
			(client_)->name, (client_)->username, (client_)->host); \
		dispatch_event_subj((flag_), _subj, (fmt_), ## __VA_ARGS__); \
	} while (0)

/*
 * format_umodes - convert a umode bitmask to a mode string like "+iow"
 */
static const char *
format_umodes(unsigned int umodes)
{
	static char buf[64];
	char *p = buf;
	int i;

	*p++ = '+';
	for (i = 0; i < 256; i++)
	{
		if (user_modes[i] && (umodes & user_modes[i]))
			*p++ = (char)i;
	}
	*p = '\0';
	return buf;
}

/* --- Hook handlers --- */

/* MEMBER event: channel join */
static void
h_event_channel_join(void *vdata)
{
	hook_data_channel_activity *data = vdata;
	struct Channel *chptr = data->chptr;
	struct Client *client_p = data->client;

	dispatch_event_subj(EVENT_MEMBER, chptr->chname,
		"JOIN %s %s!%s@%s",
		chptr->chname, client_p->name,
		client_p->username, client_p->host);
}

/* MEMBER event: channel part */
static void
h_event_channel_part(void *vdata)
{
	hook_data_channel_activity *data = vdata;
	struct Channel *chptr = data->chptr;
	struct Client *client_p = data->client;

	dispatch_event_subj(EVENT_MEMBER, chptr->chname,
		"PART %s %s!%s@%s",
		chptr->chname, client_p->name,
		client_p->username, client_p->host);
}

/* CHANNEL event: channel creation (first member joined as chanop) */
static void
h_event_channel_create(void *vdata)
{
	hook_data_channel_activity *data = vdata;
	struct Channel *chptr = data->chptr;
	struct Client *client_p = data->client;

	if (rb_dlink_list_length(&chptr->members) == 1 &&
	    is_chanop(find_channel_membership(chptr, client_p)))
	{
		dispatch_event_subj(EVENT_CHANNEL, chptr->chname,
			"CREATE %s by %s!%s@%s",
			chptr->chname, client_p->name,
			client_p->username, client_p->host);
	}
}

/* CHANNEL event: channel burst during netjoin */
static void
h_event_burst_channel(void *vdata)
{
	hook_data_channel *data = vdata;
	struct Channel *chptr = data->chptr;

	dispatch_event_subj(EVENT_CHANNEL, chptr->chname,
		"BURST %s %lu",
		chptr->chname, (unsigned long)chptr->channelts);
}

/* USER event: local user connect */
static void
h_event_new_local_user(void *vdata)
{
	struct Client *source_p = vdata;

	DISPATCH_USER(EVENT_USER, source_p,
		"CONNECT %s!%s@%s [%s]",
		source_p->name, source_p->username,
		source_p->host, source_p->sockhost);
}

/*
 * USER event: remote user connect.
 * Mirrors sno_farconnect: only fires after the introducing server has sent
 * EOB, to avoid flooding during netjoins.
 */
static void
h_event_new_remote_user(void *vdata)
{
	struct Client *source_p = vdata;

	if (!HasSentEob(source_p->servptr))
		return;

	DISPATCH_USER(EVENT_USER, source_p,
		"CONNECT %s!%s@%s [%s] (remote via %s)",
		source_p->name, source_p->username,
		source_p->host, source_p->sockhost,
		source_p->servptr ? source_p->servptr->name : "?");
}

/*
 * USER event: client exit.
 * Detects kline/xline reasons (from sno_globalkline) and emits a separate
 * KLINE notice before the standard QUIT.  Remote exits are filtered by EOB
 * (from sno_farconnect) to suppress netjoin/netsplit noise.
 */
static void
h_event_client_exit(void *vdata)
{
	hook_data_client_exit *data = vdata;
	struct Client *target = data->target;
	const char *comment = data->comment ? data->comment : "";

	if (!IsPerson(target))
		return;

	/* suppress remote exits during netjoins/netsplits */
	if (!MyConnect(target) && !HasSentEob(target->servptr))
		return;

	/* kline/xline detection */
	if (!strcmp(comment, "Bad user info"))
	{
		DISPATCH_USER(EVENT_USER, target,
			"KLINE %s!%s@%s :XLINE (%s)",
			target->name, target->username, target->host,
			target->servptr ? target->servptr->name : me.name);
	}
	else if ((ConfigFileEntry.kline_reason != NULL &&
	          !strcmp(comment, ConfigFileEntry.kline_reason)) ||
	         !strncmp(comment, "Temporary K-line ", 17) ||
	         !strncmp(comment, "Temporary D-line ", 17))
	{
		DISPATCH_USER(EVENT_USER, target,
			"KLINE %s!%s@%s :K/DLINE (%s)",
			target->name, target->username, target->host,
			target->servptr ? target->servptr->name : me.name);
	}

	DISPATCH_USER(EVENT_USER, target,
		"QUIT %s!%s@%s :%s",
		target->name, target->username, target->host,
		comment);
}

/*
 * USER event: umode change (excluding oper-up, which goes to h_event_oper).
 */
static void
h_event_umode_changed(void *vdata)
{
	hook_data_umode_changed *data = vdata;
	struct Client *source_p = data->client;

	/* oper-up is handled separately by h_event_oper */
	if (!(data->oldumodes & UMODE_OPER) && IsOper(source_p))
		return;

	{
		const char *newmodes = format_umodes(source_p->umodes);
		char oldstr[64];
		rb_strlcpy(oldstr, format_umodes(data->oldumodes), sizeof(oldstr));
		DISPATCH_USER(EVENT_USER, source_p,
			"MODE %s %s (was %s)",
			source_p->name, newmodes, oldstr);
	}
}

/*
 * USER event: oper-up (local or remote).
 * Mirrors sno_globaloper: remote oper-ups are suppressed until EOB.
 * Both hooks registered for umode_changed run back-to-back.
 */
static void
h_event_oper(void *vdata)
{
	hook_data_umode_changed *data = vdata;
	struct Client *source_p = data->client;

	if (!(data->oldumodes & UMODE_OPER) && IsOper(source_p))
	{
		if (!MyConnect(source_p) && !HasSentEob(source_p->servptr))
			return;

		DISPATCH_USER(EVENT_USER, source_p,
			"OPER %s!%s@%s (%s)",
			source_p->name, source_p->username, source_p->host,
			source_p->servptr ? source_p->servptr->name : me.name);
	}
}

/* SERVER event: server introduced */
static void
h_event_server_introduced(void *vdata)
{
	struct Client *source_p = vdata;

	dispatch_event_subj(EVENT_SERVER, source_p->name,
		"INTRODUCED %s :%s",
		source_p->name, source_p->info);
}

/* SERVER event: server end-of-burst */
static void
h_event_server_eob(void *vdata)
{
	struct Client *source_p = vdata;

	dispatch_event_subj(EVENT_SERVER, source_p->name,
		"EOB %s",
		source_p->name);
}

/* USER event: local nick change */
static void
h_event_nick_change(void *vdata)
{
	hook_data *data = vdata;
	struct Client *source_p = data->client;
	const char *oldnick = data->arg1;
	const char *newnick = data->arg2;

	DISPATCH_USER(EVENT_USER, source_p,
		"NICK %s -> %s [%s@%s]",
		oldnick, newnick, source_p->username, source_p->host);
}

/* USER event: remote nick change (from sno_globalnickchange) */
static void
h_event_remote_nick_change(void *vdata)
{
	hook_data *data = vdata;
	struct Client *source_p = data->client;
	const char *oldnick = data->arg1;
	const char *newnick = data->arg2;

	DISPATCH_USER(EVENT_USER, source_p,
		"NICK %s -> %s [%s@%s] (remote via %s)",
		oldnick, newnick, source_p->username, source_p->host,
		source_p->servptr ? source_p->servptr->name : "?");
}

/*
 * MEMBER event: kick.
 * Registered at HOOK_LOWEST so we only fire after kick is confirmed approved.
 * Uses hook_data_channel_approval to access the kicked target (data->target).
 */
static void
h_event_channel_kick(void *vdata)
{
	hook_data_channel_approval *data = vdata;
	struct Channel *chptr = data->chptr;
	struct Client *source_p = data->client;
	struct Client *target_p = data->target;

	if (!data->approved)
		return;

	dispatch_event_subj(EVENT_MEMBER, chptr->chname,
		"KICK %s %s!%s@%s by %s!%s@%s",
		chptr->chname,
		target_p->name, target_p->username, target_p->host,
		source_p->name, source_p->username, source_p->host);
}

/* OPERSPY event: dispatched from report_operspy() via the operspy hook */
static void
h_event_operspy(void *vdata)
{
	hook_cdata *data = vdata;
	struct Client *source_p = data->client;
	const char *token = data->arg1;
	const char *arg = data->arg2;

	DISPATCH_USER(EVENT_OPERSPY, source_p,
		"OPERSPY %s!%s@%s %s %s",
		source_p->name, source_p->username, source_p->host,
		token ? token : "",
		arg ? arg : "");
}

/*
 * OPERSPY event: non-oper performing WHOIS on an oper (from sno_whois).
 * Unlike sno_whois which notified the target oper, this dispatches to all
 * OPERSPY subscribers.
 */
static void
h_event_whois(void *vdata)
{
	hook_data_client *data = vdata;
	struct Client *source_p = data->client;
	struct Client *target_p = data->target;

	/* only fire when a non-oper WHOISes an oper */
	if (IsOperGeneral(source_p))
		return;
	if (!IsOperGeneral(target_p))
		return;

	DISPATCH_USER(EVENT_OPERSPY, source_p,
		"WHOIS %s!%s@%s on %s!%s@%s",
		source_p->name, source_p->username, source_p->host,
		target_p->name, target_p->username, target_p->host);
}

/* cleanup: remove subscription when subscriber disconnects */
static void
h_event_cleanup(void *vdata)
{
	hook_data_client_exit *data = vdata;
	remove_event_sub(data->target);
}

/*
 * Spy command handlers — merged from spy_* extension modules.
 * Fire on doing_admin, doing_info, doing_links, doing_motd, doing_stats_p
 * when any user invokes those commands.  All receive hook_data * with
 * client being the requesting user.
 */
#define MAKE_SPY_HANDLER(funcname_, label_) \
static void \
funcname_(void *vdata) \
{ \
	hook_data *data = vdata; \
	struct Client *source_p = data->client; \
	DISPATCH_USER(EVENT_OPERSPY, source_p, \
		label_ " %s!%s@%s [%s]", \
		source_p->name, source_p->username, source_p->host, \
		source_p->servptr->name); \
}

MAKE_SPY_HANDLER(h_event_spy_admin,   "ADMIN")
MAKE_SPY_HANDLER(h_event_spy_info,    "INFO")
MAKE_SPY_HANDLER(h_event_spy_links,   "LINKS")
MAKE_SPY_HANDLER(h_event_spy_motd,    "MOTD")
MAKE_SPY_HANDLER(h_event_spy_stats_p, "STATS_P")

/*
 * doing_stats receives hook_data_int:
 *   arg2 = statchar (cast to char)
 *   arg1 = target name (for L/l stats)
 */
static void
h_event_spy_stats(void *vdata)
{
	hook_data_int *data = vdata;
	struct Client *source_p = data->client;
	char statchar = (char)data->arg2;
	const char *name = data->arg1;

	if ((statchar == 'L' || statchar == 'l') && !EmptyString(name))
	{
		DISPATCH_USER(EVENT_OPERSPY, source_p,
			"STATS %c %s!%s@%s [%s] on %s",
			statchar,
			source_p->name, source_p->username, source_p->host,
			source_p->servptr->name, name);
	}
	else
	{
		DISPATCH_USER(EVENT_OPERSPY, source_p,
			"STATS %c %s!%s@%s [%s]",
			statchar,
			source_p->name, source_p->username, source_p->host,
			source_p->servptr->name);
	}
}

/*
 * doing_trace receives hook_data_client * with an optional target client.
 */
static void
h_event_spy_trace(void *vdata)
{
	hook_data_client *data = vdata;
	struct Client *source_p = data->client;

	if (data->target)
	{
		DISPATCH_USER(EVENT_OPERSPY, source_p,
			"TRACE %s!%s@%s [%s] on %s",
			source_p->name, source_p->username, source_p->host,
			source_p->servptr->name,
			data->target->name);
	}
	else
	{
		DISPATCH_USER(EVENT_OPERSPY, source_p,
			"TRACE %s!%s@%s [%s]",
			source_p->name, source_p->username, source_p->host,
			source_p->servptr->name);
	}
}

mapi_hfn_list_av1 ircx_event_hfnlist[] = {
	{ "channel_join",       (hookfn) h_event_channel_join },
	{ "channel_part",       (hookfn) h_event_channel_part },
	{ "channel_join",       (hookfn) h_event_channel_create },
	{ "burst_channel",      (hookfn) h_event_burst_channel },
	{ "new_local_user",     (hookfn) h_event_new_local_user },
	{ "new_remote_user",    (hookfn) h_event_new_remote_user },
	{ "client_exit",        (hookfn) h_event_client_exit },
	{ "after_client_exit",  (hookfn) h_event_cleanup },
	{ "umode_changed",      (hookfn) h_event_umode_changed },
	{ "umode_changed",      (hookfn) h_event_oper },
	{ "nick_change",        (hookfn) h_event_nick_change },
	{ "remote_nick_change", (hookfn) h_event_remote_nick_change },
	{ "can_kick",           (hookfn) h_event_channel_kick, HOOK_LOWEST },
	{ "server_introduced",  (hookfn) h_event_server_introduced },
	{ "server_eob",         (hookfn) h_event_server_eob },
	{ "operspy",            (hookfn) h_event_operspy },
	{ "doing_whois",        (hookfn) h_event_whois },
	{ "doing_whois_global", (hookfn) h_event_whois },
	{ "doing_admin",        (hookfn) h_event_spy_admin },
	{ "doing_info",         (hookfn) h_event_spy_info },
	{ "doing_links",        (hookfn) h_event_spy_links },
	{ "doing_motd",         (hookfn) h_event_spy_motd },
	{ "doing_stats",        (hookfn) h_event_spy_stats },
	{ "doing_stats_p",      (hookfn) h_event_spy_stats_p },
	{ "doing_trace",        (hookfn) h_event_spy_trace },
	{ NULL, NULL }
};

/* --- EVENT command handler --- */

static void
m_event(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		return;
	}

	if (parc < 2 || !rb_strcasecmp(parv[1], "LIST"))
	{
		/* EVENT LIST [<event>] */
		struct event_sub *sub = find_event_sub(source_p);

		if (parc >= 3)
		{
			unsigned int flag = event_flag_from_name(parv[2]);
			if (flag == 0)
			{
				sendto_one_numeric(source_p, ERR_NOSUCHEVENT,
					form_str(ERR_NOSUCHEVENT), parv[2]);
				return;
			}
			if (sub && (sub->events & flag))
			{
				sendto_one_numeric(source_p, RPL_EVENTLIST,
					form_str(RPL_EVENTLIST),
					event_name_from_flag(flag), sub->mask);
			}
		}
		else if (sub)
		{
			for (int i = 0; event_types[i].name != NULL; i++)
			{
				if (sub->events & event_types[i].flag)
				{
					sendto_one_numeric(source_p, RPL_EVENTLIST,
						form_str(RPL_EVENTLIST),
						event_types[i].name, sub->mask);
				}
			}
		}

		sendto_one_numeric(source_p, RPL_EVENTEND,
			form_str(RPL_EVENTEND));
		return;
	}

	if (!rb_strcasecmp(parv[1], "ADD"))
	{
		if (parc < 3)
		{
			sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
				me.name, source_p->name, "EVENT ADD");
			return;
		}

		unsigned int flag = event_flag_from_name(parv[2]);
		if (flag == 0)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHEVENT,
				form_str(ERR_NOSUCHEVENT), parv[2]);
			return;
		}

		/* OPERSPY events require the oper:spy privilege */
		if ((flag & EVENT_OPERSPY) && !HasPrivilege(source_p, "oper:spy"))
		{
			sendto_one_numeric(source_p, ERR_NOPRIVS,
				form_str(ERR_NOPRIVS), "oper:spy");
			return;
		}

		struct event_sub *sub = get_or_create_event_sub(source_p);

		if (sub->events & flag)
		{
			sendto_one_numeric(source_p, ERR_EVENTDUP,
				form_str(ERR_EVENTDUP), parv[2]);
			return;
		}

		sub->events |= flag;

		if (parc >= 4 && !EmptyString(parv[3]))
			rb_strlcpy(sub->mask, parv[3], sizeof(sub->mask));

		sendto_one_numeric(source_p, RPL_EVENTADD,
			form_str(RPL_EVENTADD), parv[2], sub->mask);
		return;
	}

	if (!rb_strcasecmp(parv[1], "DELETE"))
	{
		if (parc < 3)
		{
			sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
				me.name, source_p->name, "EVENT DELETE");
			return;
		}

		unsigned int flag = event_flag_from_name(parv[2]);
		if (flag == 0)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHEVENT,
				form_str(ERR_NOSUCHEVENT), parv[2]);
			return;
		}

		struct event_sub *sub = find_event_sub(source_p);
		if (sub == NULL || !(sub->events & flag))
		{
			sendto_one_numeric(source_p, ERR_EVENTMIS,
				form_str(ERR_EVENTMIS), parv[2]);
			return;
		}

		sub->events &= ~flag;

		/* if no more subscriptions, clean up */
		if (sub->events == 0)
			remove_event_sub(source_p);

		sendto_one_notice(source_p, ":Event %s removed", parv[2]);
		return;
	}

	sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
		me.name, source_p->name, "EVENT");
}

struct Message event_msgtab = {
	"EVENT", 0, 0, 0, 0,
	{mg_unreg, {m_event, 0}, mg_ignore, mg_ignore, mg_ignore, {m_event, 0}}
};

mapi_clist_av1 ircx_event_clist[] = { &event_msgtab, NULL };

static int
ircx_event_init(void)
{
	return 0;
}

static void
ircx_event_deinit(void)
{
	rb_dlink_node *n, *tn;
	RB_DLINK_FOREACH_SAFE(n, tn, event_subscribers.head)
	{
		struct event_sub *sub = n->data;
		rb_dlinkDelete(n, &event_subscribers);
		rb_free(sub);
	}
}

DECLARE_MODULE_AV2(ircx_event, ircx_event_init, ircx_event_deinit,
	ircx_event_clist, NULL, ircx_event_hfnlist, NULL, NULL, ircx_event_desc);
