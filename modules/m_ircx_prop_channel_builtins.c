/*
 * modules/m_ircx_prop_channel_builtins.c
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
#include "client.h"
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
#include "propertyset.h"

static const char ircx_prop_channel_builtins_desc[] =
	"Provides IRCX built-in channel properties (OID, NAME, CREATION, TOPIC, MEMBERKEY, LANGUAGE, SUBJECT)";

static void h_prop_list_append(void *);
static void h_prop_chan_write(void *);
static void h_prop_show(void *);
static void h_prop_change(void *);

mapi_hfn_list_av1 ircx_prop_channel_builtins_hfnlist[] = {
	{ "prop_list_append", (hookfn) h_prop_list_append },
	{ "prop_chan_write", (hookfn) h_prop_chan_write },
	{ "prop_show", (hookfn) h_prop_show },
	{ "prop_change", (hookfn) h_prop_change },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(ircx_prop_channel_builtins, NULL, NULL, NULL, NULL,
	ircx_prop_channel_builtins_hfnlist, NULL, NULL, ircx_prop_channel_builtins_desc);

static inline bool
key_matches(const char *keys, const char *name)
{
	return keys == NULL || match(keys, name);
}

/*
 * Emit computed/virtual channel properties during PROP listing.
 *
 * Per the IRCX draft spec (draft-pfenning-irc-extensions-04), channels
 * expose these built-in properties:
 *
 *   OID       - channel unique object identifier (read-only)
 *   NAME      - channel name (read-only)
 *   CREATION  - channel creation timestamp (read-only)
 *   TOPIC     - channel topic (read/write, linked to channel topic)
 *   LANGUAGE  - channel language code (read/write, stored in prop_list)
 *   SUBJECT   - channel subject (read/write, stored in prop_list)
 *   MEMBERKEY - channel join key (write-only, linked to +k mode)
 *
 * The first three are computed from channel state and never stored in
 * prop_list.  TOPIC is read from channel state but writes go through
 * the prop system.  MEMBERKEY is write-only (never shown in listings).
 * LANGUAGE and SUBJECT are ordinary stored properties but mentioned in
 * the spec.
 */
static void
h_prop_list_append(void *vdata)
{
	hook_data_prop_list *data = vdata;
	char buf[64];

	if (!IsChanPrefix(*data->target))
		return;

	struct Channel *chptr = (struct Channel *)data->target_ptr;
	if (chptr == NULL)
		return;

	/* OID: use channel name as unique identifier */
	if (key_matches(data->keys, "OID"))
	{
		sendto_one_numeric(data->client, RPL_PROPLIST, form_str(RPL_PROPLIST),
			data->target, "OID", chptr->chname);
	}

	/* NAME: channel display name */
	if (key_matches(data->keys, "NAME"))
	{
		sendto_one_numeric(data->client, RPL_PROPLIST, form_str(RPL_PROPLIST),
			data->target, "NAME", chptr->chname);
	}

	/* CREATION: channel creation timestamp */
	if (key_matches(data->keys, "CREATION"))
	{
		snprintf(buf, sizeof buf, "%ld", (long)chptr->channelts);
		sendto_one_numeric(data->client, RPL_PROPLIST, form_str(RPL_PROPLIST),
			data->target, "CREATION", buf);
	}

	/* TOPIC: from channel state */
	if (key_matches(data->keys, "TOPIC"))
	{
		const char *topic = chptr->topic ? chptr->topic : "";
		sendto_one_numeric(data->client, RPL_PROPLIST, form_str(RPL_PROPLIST),
			data->target, "TOPIC", topic);
	}
}

/*
 * Enforce write permissions on built-in channel properties.
 *
 * Read-only properties (OID, NAME, CREATION) are never writable.
 * TOPIC requires chanop.
 * MEMBERKEY requires chanop.
 */
static void
h_prop_chan_write(void *vdata)
{
	hook_data_prop_activity *data = vdata;

	if (!IsChanPrefix(*data->target))
		return;

	/* read-only properties: deny all writes */
	if (!rb_strcasecmp(data->key, "OID") ||
	    !rb_strcasecmp(data->key, "NAME") ||
	    !rb_strcasecmp(data->key, "CREATION"))
	{
		data->approved = 0;
		return;
	}

	/* TOPIC: requires chanop to write */
	if (!rb_strcasecmp(data->key, "TOPIC"))
	{
		data->approved = data->alevel >= CHFL_CHANOP;
		return;
	}

	/* MEMBERKEY: requires chanop to write */
	if (!rb_strcasecmp(data->key, "MEMBERKEY"))
	{
		data->approved = data->alevel >= CHFL_CHANOP;
		return;
	}
}

/*
 * Filter visibility of properties during listing.
 *
 * MEMBERKEY is write-only per IRCX spec, so hide it from listings.
 */
static void
h_prop_show(void *vdata)
{
	hook_data_prop_activity *data = vdata;

	if (!IsChanPrefix(*data->target))
		return;

	if (!rb_strcasecmp(data->key, "MEMBERKEY"))
		data->approved = 0;
}

/*
 * Intercept property changes and apply side effects to channel state.
 *
 * TOPIC: update the channel's actual topic.
 * MEMBERKEY: set the channel key mode (+k/-k).
 */
static void
h_prop_change(void *vdata)
{
	hook_data_prop_activity *data = vdata;
	char prefix[BUFSIZE];

	if (!IsChanPrefix(*data->target))
		return;

	struct Channel *chptr = (struct Channel *)data->target_ptr;
	if (chptr == NULL)
		return;

	if (IsPerson(data->client))
		snprintf(prefix, sizeof prefix, "%s!%s@%s",
			data->client->name, data->client->username, data->client->host);
	else
		rb_strlcpy(prefix, data->client->name, sizeof prefix);

	/* TOPIC property -> channel topic */
	if (!rb_strcasecmp(data->key, "TOPIC"))
	{
		const char *topic_val = data->value ? data->value : "";
		set_channel_topic(chptr, topic_val, prefix, rb_current_time());
		return;
	}

	/* MEMBERKEY property -> +k/-k mode */
	if (!rb_strcasecmp(data->key, "MEMBERKEY"))
	{
		if (data->value && *data->value)
		{
			const char *para[] = {"+k", data->value};
			set_channel_mode((struct Client *)data->client, &me, chptr, NULL, 2, para);
		}
		else
		{
			const char *para[] = {"-k", "*"};
			set_channel_mode((struct Client *)data->client, &me, chptr, NULL, 2, para);
		}

		/* remove from prop_list since this is stored as a mode */
		propertyset_delete((rb_dlink_list *)data->prop_list, "MEMBERKEY");
		return;
	}
}
