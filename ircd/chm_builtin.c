/*
 * ircd/chm_builtin.c - built-in channel mode handlers
 *
 * Provides channel modes +c (no colour), +C (no CTCP), +O (oper-only),
 * and +S (SSL-only) as core functionality registered at startup via
 * chm_builtin_init().  Previously these were loadable modules.
 */

#include "stdinc.h"
#include "channel.h"
#include "chmode.h"
#include "client.h"
#include "hook.h"
#include "ircd.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_user.h"
#include "send.h"
#include "inline/stringops.h"

static unsigned int mode_nocolour;
static unsigned int mode_noctcp;
static unsigned int mode_operonly;
static unsigned int mode_sslonly;

/* +c -- strip colour/formatting codes from channel messages */
static char colour_strip_buf[BUFSIZE];

static void
h_chm_nocolour(void *vdata)
{
	hook_data_privmsg_channel *data = vdata;

	if (!ConfigFeatures.channel_nocolour)
		return;
	if (data->approved)
		return;

	if (data->chptr->mode.mode & mode_nocolour)
	{
		rb_strlcpy(colour_strip_buf, data->text, sizeof colour_strip_buf);
		strip_colour(colour_strip_buf);
		data->text = colour_strip_buf;
	}
}

/* +C -- block CTCP messages to a channel (except ACTION) */
static void
h_chm_noctcp(void *vdata)
{
	hook_data_privmsg_channel *data = vdata;

	if (!ConfigFeatures.channel_noctcp)
		return;
	if (data->approved || data->msgtype == MESSAGE_TYPE_NOTICE)
		return;

	if (*data->text == '\001' &&
	    rb_strncasecmp(data->text + 1, "ACTION ", 7) &&
	    data->chptr->mode.mode & mode_noctcp)
	{
		sendto_one_numeric(data->source_p, ERR_CANNOTSENDTOCHAN,
		                   form_str(ERR_CANNOTSENDTOCHAN), data->chptr->chname);
		data->approved = ERR_CANNOTSENDTOCHAN;
		return;
	}

	if (rb_dlink_list_length(&data->chptr->locmembers) >
	    (unsigned)(GlobalSetOptions.floodcount / 2))
		data->source_p->large_ctcp_sent = rb_current_time();
}

/* +O -- oper-only channel: only IRC operators may join */
static void
h_chm_operonly(void *vdata)
{
	hook_data_channel *data = vdata;
	struct Client *source_p = data->client;
	struct Channel *chptr = data->chptr;

	if (!ConfigFeatures.channel_operonly)
		return;
	if (data->approved)
		return;

	if ((chptr->mode.mode & mode_operonly) && !IsOper(source_p))
	{
		sendto_one_numeric(source_p, 520,
		                   "%s :Cannot join channel (+O) - you are not an IRC operator",
		                   chptr->chname);
		data->approved = ERR_CUSTOM;
	}
}

/* +S -- SSL-only channel: only SSL/TLS-connected users may join */
static void
h_chm_sslonly(void *vdata)
{
	hook_data_channel *data = vdata;
	struct Client *source_p = data->client;
	struct Channel *chptr = data->chptr;

	if (!ConfigFeatures.channel_sslonly)
		return;
	if (data->approved)
		return;

	if ((chptr->mode.mode & mode_sslonly) && !IsSSLClient(source_p))
	{
		sendto_one_numeric(source_p, 480,
		                   "%s :Cannot join channel (+S) - SSL/TLS required",
		                   chptr->chname);
		data->approved = ERR_CUSTOM;
	}
}

/*
 * chm_builtin_init - register all built-in channel mode handlers.
 * Must be called after chmode_init().
 */
void
chm_builtin_init(void)
{
	mode_nocolour = cflag_add('c', chm_simple);
	mode_noctcp   = cflag_add('C', chm_simple);
	mode_operonly = cflag_add('O', chm_staff);
	mode_sslonly  = cflag_add('S', chm_simple);

	add_hook("privmsg_channel", h_chm_nocolour);
	add_hook("privmsg_channel", h_chm_noctcp);
	add_hook("can_join",        h_chm_operonly);
	add_hook("can_join",        h_chm_sslonly);
}
