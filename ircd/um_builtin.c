/*
 * ircd/um_builtin.c - built-in user mode handlers
 *
 * Provides user modes +g/+B (callerid), +R (registered-only messages),
 * and +C (no CTCP) as core functionality registered at startup via
 * um_builtin_init().  Previously these were loadable modules.
 */

#include "stdinc.h"
#include "client.h"
#include "hook.h"
#include "ircd.h"
#include "logger.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_user.h"
#include "send.h"
#include "supported.h"
#include "inline/stringops.h"

/* --------------------------------------------------------------------------
 * +g / +B  callerid: restrict messages to users in an allow-list
 * -------------------------------------------------------------------------- */

#define IsSetStrictCallerID(c)  ((c)->umodes & user_modes['g'])
#define IsSetRelaxedCallerID(c) ((c)->umodes & user_modes['B'])
#define IsSetAnyCallerID(c)     (IsSetStrictCallerID(c) || IsSetRelaxedCallerID(c))

static bool
callerid_has_common_channel(struct Client *source_p, struct Client *target_p)
{
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, source_p->user->channel.head)
	{
		struct membership *msptr = ptr->data;
		if (IsMember(target_p, msptr->chptr))
			return true;
	}
	return false;
}

static bool
callerid_allow_message(struct Client *source_p, struct Client *target_p)
{
	if (!MyClient(target_p))
		return true;
	if (!IsSetAnyCallerID(target_p))
		return true;
	if (IsSetRelaxedCallerID(target_p) &&
	    callerid_has_common_channel(source_p, target_p) &&
	    !IsSetStrictCallerID(target_p))
		return true;
	if (IsServer(source_p))
		return true;
	if (IsOperGeneral(source_p))
		return true;
	if (accept_message(source_p, target_p))
		return true;
	return false;
}

static void
callerid_send_notice(enum message_type msgtype,
                     struct Client *source_p, struct Client *target_p)
{
	if (!MyClient(target_p) || msgtype == MESSAGE_TYPE_NOTICE)
		return;

	sendto_one_numeric(source_p, ERR_TARGUMODEG, form_str(ERR_TARGUMODEG),
	                   target_p->name,
	                   IsSetStrictCallerID(target_p) ? "+g" : "+B");

	if ((target_p->localClient->last_caller_id_time +
	     ConfigFileEntry.caller_id_wait) < rb_current_time())
	{
		sendto_one_numeric(source_p, RPL_TARGNOTIFY,
		                   form_str(RPL_TARGNOTIFY), target_p->name);
		sendto_one(target_p, form_str(RPL_UMODEGMSG),
		           me.name, target_p->name, source_p->name,
		           source_p->username, source_p->host,
		           IsSetStrictCallerID(target_p) ? "+g" : "+B");
		target_p->localClient->last_caller_id_time = rb_current_time();
	}
}

static bool
callerid_add_accept(enum message_type msgtype,
                    struct Client *source_p, struct Client *target_p)
{
	if (!MyClient(source_p))
		return true;

	if (msgtype != MESSAGE_TYPE_NOTICE &&
	    IsSetAnyCallerID(source_p) &&
	    !accept_message(target_p, source_p) &&
	    !IsOperGeneral(target_p))
	{
		if (rb_dlink_list_length(&source_p->localClient->allow_list) <
		    (unsigned long)ConfigFileEntry.max_accept)
		{
			rb_dlinkAddAlloc(target_p, &source_p->localClient->allow_list);
			rb_dlinkAddAlloc(source_p, &target_p->on_allow_list);
		}
		else
		{
			sendto_one_numeric(source_p, ERR_OWNMODE,
			                   form_str(ERR_OWNMODE), target_p->name,
			                   IsSetStrictCallerID(target_p) ? "+g" : "+B");
			return false;
		}
	}
	return true;
}

static void
h_callerid_invite(void *vdata)
{
	hook_data_channel_approval *data = vdata;
	static char errorbuf[BUFSIZE];

	if (data->approved)
		return;
	if (!callerid_add_accept(MESSAGE_TYPE_PRIVMSG, data->client, data->target))
	{
		data->approved = ERR_TARGUMODEG;
		return;
	}
	if (callerid_allow_message(data->client, data->target))
		return;

	snprintf(errorbuf, sizeof errorbuf, form_str(ERR_TARGUMODEG),
	         data->target->name,
	         IsSetStrictCallerID(data->target) ? "+g" : "+B");
	data->approved = ERR_TARGUMODEG;
	data->error = errorbuf;
}

static void
h_callerid_privmsg_user(void *vdata)
{
	hook_data_privmsg_user *data = vdata;

	if (data->approved)
		return;
	if (!callerid_add_accept(data->msgtype, data->source_p, data->target_p))
	{
		data->approved = ERR_TARGUMODEG;
		return;
	}
	if (callerid_allow_message(data->source_p, data->target_p))
		return;

	callerid_send_notice(data->msgtype, data->source_p, data->target_p);
	data->approved = ERR_TARGUMODEG;
}

/* --------------------------------------------------------------------------
 * +R  registered-only messages: block privmsgs from unregistered users
 * -------------------------------------------------------------------------- */

static bool
regonlymsg_allow_message(struct Client *source_p, struct Client *target_p)
{
	if (!MyClient(target_p))
		return true;
	if (!user_modes['R'] || !(target_p->umodes & user_modes['R']))
		return true;
	if (IsServer(source_p))
		return true;
	if (IsOper(source_p))
		return true;
	if (accept_message(source_p, target_p))
		return true;
	if (source_p->user->suser[0])
		return true;
	return false;
}

static void
h_regonlymsg_invite(void *vdata)
{
	hook_data_channel_approval *data = vdata;
	static char errorbuf[BUFSIZE];

	if (data->approved)
		return;
	if (regonlymsg_allow_message(data->client, data->target))
		return;

	snprintf(errorbuf, sizeof errorbuf, form_str(ERR_NONONREG),
	         data->target->name);
	data->approved = ERR_NONONREG;
	data->error = errorbuf;
}

static void
h_regonlymsg_privmsg_user(void *vdata)
{
	hook_data_privmsg_user *data = vdata;

	if (data->approved)
		return;
	if (regonlymsg_allow_message(data->source_p, data->target_p))
		return;
	if (data->msgtype == MESSAGE_TYPE_NOTICE)
		return;

	sendto_one_numeric(data->source_p, ERR_NONONREG,
	                   form_str(ERR_NONONREG), data->target_p->name);
	data->approved = ERR_NONONREG;
}

/* --------------------------------------------------------------------------
 * +C  user no-CTCP: block CTCP requests to the user (except ACTION)
 * -------------------------------------------------------------------------- */

static void
h_umode_noctcp_privmsg_user(void *vdata)
{
	hook_data_privmsg_user *data = vdata;

	if (!MyClient(data->target_p))
		return;
	if (data->approved || data->msgtype == MESSAGE_TYPE_NOTICE)
		return;

	if (user_modes['C'] &&
	    (data->target_p->umodes & user_modes['C']) &&
	    *data->text == '\001' &&
	    rb_strncasecmp(data->text + 1, "ACTION", 6))
	{
		sendto_one_numeric(data->source_p, ERR_CANNOTSENDTOUSER,
		                   form_str(ERR_CANNOTSENDTOUSER),
		                   data->target_p->name, "+C set");
		data->approved = ERR_CANNOTSENDTOUSER;
	}
}

/* --------------------------------------------------------------------------
 * um_builtin_init - register all built-in user mode handlers.
 * Must be called after chmode_init() / extban_init().
 * -------------------------------------------------------------------------- */
void
um_builtin_init(void)
{
	/* +g strict callerid, +B relaxed callerid */
	user_modes['g'] = find_umode_slot();
	user_modes['B'] = find_umode_slot();
	if (!user_modes['g'] || !user_modes['B'])
		ierror("um_builtin_init: failed to allocate umode slot for +g/+B");
	else
	{
		add_isupport("CALLERID", isupport_umode, "g");
		add_hook("invite",       h_callerid_invite);
		add_hook("privmsg_user", h_callerid_privmsg_user);
	}

	/* +R registered-only messages */
	user_modes['R'] = find_umode_slot();
	if (!user_modes['R'])
		ierror("um_builtin_init: failed to allocate umode slot for +R");
	else
	{
		add_hook("invite",       h_regonlymsg_invite);
		add_hook("privmsg_user", h_regonlymsg_privmsg_user);
	}

	/* +C user no-CTCP */
	user_modes['C'] = find_umode_slot();
	if (!user_modes['C'])
		ierror("um_builtin_init: failed to allocate umode slot for +C");
	else
		add_hook("privmsg_user", h_umode_noctcp_privmsg_user);

	construct_umodebuf();
}
