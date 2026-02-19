/*
 * modules/m_ircx_prop_user_profile.c
 * Copyright (c) 2024 ophion contributors
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

/*
 * IRCX user profile properties
 *
 * This module allows users to set personal profile properties on
 * themselves via the PROP command.  The following profile properties
 * are supported:
 *
 *   URL       - User's website URL
 *   GENDER    - User's gender identity
 *   PICTURE   - URL to a user avatar/picture
 *   LOCATION  - User's geographic location
 *   BIO       - Short biography/description
 *   REALNAME  - Alternative display name
 *   EMAIL     - Contact email address
 *
 * All profile properties are optional and user-writable only for the
 * owning user (you can only set your own profile).  Opers can view
 * any user's properties but cannot write them.
 *
 * Properties are propagated to other servers via TPROP/BTPROP and
 * are visible to any user via PROP <nick>.
 *
 * Size limits: each profile property value is limited to 200 chars.
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
#include "propertyset.h"

static const char ircx_prop_user_profile_desc[] =
	"Provides IRCX user profile properties (URL, GENDER, PICTURE, LOCATION, BIO, etc)";

#define MAX_PROFILE_VALUE_LEN 200

static const char *allowed_profile_keys[] = {
	"URL",
	"GENDER",
	"PICTURE",
	"LOCATION",
	"BIO",
	"REALNAME",
	"EMAIL",
	NULL
};

static bool
is_profile_key(const char *key)
{
	for (const char **k = allowed_profile_keys; *k != NULL; k++)
	{
		if (!rb_strcasecmp(key, *k))
			return true;
	}
	return false;
}

/*
 * Hook into prop_user_write: allow writes only for known profile keys
 * and enforce the value length limit.
 */
static void
h_prop_user_write(void *vdata)
{
	hook_data_prop_activity *data = vdata;

	/* only handle user targets (not channels or accounts) */
	if (IsChanPrefix(*data->target))
		return;

	if (!is_profile_key(data->key))
	{
		/* unknown profile key -- deny write */
		data->approved = 0;
		return;
	}

	/* enforce value length limit */
	if (data->value != NULL && strlen(data->value) > MAX_PROFILE_VALUE_LEN)
	{
		data->approved = 0;
		return;
	}

	/* allow the write */
	data->approved = 1;
}

/*
 * Hook into prop_list_append: emit computed NICK property for users.
 */
static void
h_prop_list_append(void *vdata)
{
	hook_data_prop_list *data = vdata;

	/* only for user targets */
	if (IsChanPrefix(*data->target))
		return;

	struct Client *target_p = find_client(data->target);
	if (target_p == NULL || target_p->user == NULL)
		return;

	/* emit NICK as a virtual read-only property */
	if (data->keys == NULL || rb_strcasestr(data->keys, "NICK") != NULL)
	{
		sendto_one_numeric(data->client, RPL_PROPLIST, form_str(RPL_PROPLIST),
			data->target, "NICK", target_p->name);
	}
}

mapi_hfn_list_av1 ircx_prop_user_profile_hfnlist[] = {
	{ "prop_user_write", (hookfn) h_prop_user_write },
	{ "prop_list_append", (hookfn) h_prop_list_append },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(ircx_prop_user_profile, NULL, NULL, NULL, NULL,
	ircx_prop_user_profile_hfnlist, NULL, NULL, ircx_prop_user_profile_desc);
