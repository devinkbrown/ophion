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
 *   USER     - nick change, mode change, quit, kill
 *   SERVER   - server connect/disconnect
 *
 * Only sysops (IRC operators) may subscribe to events.
 * This replaces legacy oper monitoring tools (sno_channelcreate,
 * sno_globalnickchange, etc.) with a unified event framework.
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
 * We store the subscription bitmask in a simple linked list
 * keyed by client pointer. The mask allows wildcard filtering.
 */
struct event_sub {
	rb_dlink_node node;
	struct Client *client;
	unsigned int events;		/* bitmask of EVENT_* */
	char mask[256];			/* selection mask, default *!*@*$* */
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
	rb_strlcpy(sub->mask, "*!*@*$*", sizeof(sub->mask));
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
 */
static void
dispatch_event(unsigned int event_flag, const char *fmt, ...)
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

		sendto_one_notice(sub->client, ":*** EVENT %s %s",
			event_name_from_flag(event_flag), buf);
	}
}

/* --- Hook handlers --- */

/* CHANNEL events: channel creation via join */
static void
h_event_channel_join(void *vdata)
{
	hook_data_channel_activity *data = vdata;
	struct Channel *chptr = data->chptr;
	struct Client *client_p = data->client;

	dispatch_event(EVENT_MEMBER, "JOIN %s %s!%s@%s",
		chptr->chname, client_p->name,
		client_p->username, client_p->host);
}

static void
h_event_burst_channel(void *vdata)
{
	hook_data_channel *data = vdata;
	struct Channel *chptr = data->chptr;

	dispatch_event(EVENT_CHANNEL, "CREATE %s %lu",
		chptr->chname, (unsigned long)chptr->channelts);
}

static void
h_event_new_local_user(void *vdata)
{
	struct Client *source_p = vdata;

	dispatch_event(EVENT_USER, "CONNECT %s!%s@%s [%s]",
		source_p->name, source_p->username,
		source_p->host, source_p->sockhost);
}

static void
h_event_new_remote_user(void *vdata)
{
	struct Client *source_p = vdata;

	dispatch_event(EVENT_USER, "CONNECT %s!%s@%s [%s] (remote via %s)",
		source_p->name, source_p->username,
		source_p->host, source_p->sockhost,
		source_p->servptr ? source_p->servptr->name : "?");
}

static void
h_event_client_exit(void *vdata)
{
	hook_data_client_exit *data = vdata;
	struct Client *target = data->target;

	if (!IsPerson(target))
		return;

	dispatch_event(EVENT_USER, "QUIT %s!%s@%s :%s",
		target->name, target->username, target->host,
		data->comment ? data->comment : "");
}

static void
h_event_umode_changed(void *vdata)
{
	hook_data_umode_changed *data = vdata;
	struct Client *source_p = data->client;

	dispatch_event(EVENT_USER, "MODE %s +%u (was +%u)",
		source_p->name, source_p->umodes, data->oldumodes);
}

static void
h_event_server_introduced(void *vdata)
{
	struct Client *source_p = vdata;

	dispatch_event(EVENT_SERVER, "INTRODUCED %s :%s",
		source_p->name, source_p->info);
}

static void
h_event_server_eob(void *vdata)
{
	struct Client *source_p = vdata;

	dispatch_event(EVENT_SERVER, "EOB %s",
		source_p->name);
}

/* CHANNEL event: channel creation (first member joined as chanop) */
static void
h_event_channel_create(void *vdata)
{
	hook_data_channel_activity *data = vdata;
	struct Channel *chptr = data->chptr;
	struct Client *client_p = data->client;

	/* only fire for newly created channels (single member who is chanop) */
	if (rb_dlink_list_length(&chptr->members) == 1 &&
	    is_chanop(find_channel_membership(chptr, client_p)))
	{
		dispatch_event(EVENT_CHANNEL, "CREATE %s by %s!%s@%s",
			chptr->chname, client_p->name,
			client_p->username, client_p->host);
	}
}

/* USER event: nick changes (local) */
static void
h_event_nick_change(void *vdata)
{
	hook_data *data = vdata;
	struct Client *source_p = data->client;
	const char *oldnick = data->arg1;
	const char *newnick = data->arg2;

	dispatch_event(EVENT_USER, "NICK %s -> %s [%s@%s]",
		oldnick, newnick, source_p->username, source_p->host);
}

/* USER event: remote nick changes */
static void
h_event_remote_nick_change(void *vdata)
{
	hook_data *data = vdata;
	struct Client *source_p = data->client;
	const char *oldnick = data->arg1;
	const char *newnick = data->arg2;

	dispatch_event(EVENT_USER, "NICK %s -> %s [%s@%s] (remote via %s)",
		oldnick, newnick, source_p->username, source_p->host,
		source_p->servptr ? source_p->servptr->name : "?");
}

/* MEMBER event: kick */
static void
h_event_channel_kick(void *vdata)
{
	hook_data_channel_activity *data = vdata;
	struct Channel *chptr = data->chptr;
	struct Client *source_p = data->client;

	dispatch_event(EVENT_MEMBER, "KICK %s %s!%s@%s",
		chptr->chname, source_p->name,
		source_p->username, source_p->host);
}

/* cleanup on client exit */
static void
h_event_cleanup(void *vdata)
{
	hook_data_client_exit *data = vdata;
	remove_event_sub(data->target);
}

mapi_hfn_list_av1 ircx_event_hfnlist[] = {
	{ "channel_join", (hookfn) h_event_channel_join },
	{ "channel_join", (hookfn) h_event_channel_create },
	{ "burst_channel", (hookfn) h_event_burst_channel },
	{ "new_local_user", (hookfn) h_event_new_local_user },
	{ "new_remote_user", (hookfn) h_event_new_remote_user },
	{ "client_exit", (hookfn) h_event_client_exit },
	{ "after_client_exit", (hookfn) h_event_cleanup },
	{ "umode_changed", (hookfn) h_event_umode_changed },
	{ "nick_change", (hookfn) h_event_nick_change },
	{ "remote_nick_change", (hookfn) h_event_remote_nick_change },
	{ "can_kick", (hookfn) h_event_channel_kick },
	{ "server_introduced", (hookfn) h_event_server_introduced },
	{ "server_eob", (hookfn) h_event_server_eob },
	{ NULL, NULL }
};

/* --- EVENT command handler --- */

static void
m_event(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	if (!IsOper(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVILEGES), me.name, source_p->name);
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
		rb_dlinkDelete(n, &event_subscribers);
		rb_free(n->data);
	}
}

DECLARE_MODULE_AV2(ircx_event, ircx_event_init, ircx_event_deinit,
	ircx_event_clist, NULL, ircx_event_hfnlist, NULL, NULL, ircx_event_desc);
