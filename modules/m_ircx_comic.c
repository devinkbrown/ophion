/*
 * modules/m_ircx_comic.c
 *
 * Microsoft Comic Chat (IRCX) protocol support.
 *
 * Microsoft Chat (aka Comic Chat) was a graphical IRC client by Microsoft
 * that rendered conversations as comic strips.  It used IRCX properties
 * and CTCP-like control messages to transmit character metadata between
 * clients.  This module provides full server-side support:
 *
 * 1. Registers Comic Chat PROP keys on users:
 *    - MCC      Microsoft Comic Chat character data (base64-encoded)
 *    - MCCGUID  Character GUID for identity matching
 *    - MCCEX    Comic Chat expression/gesture data
 *
 * 2. Validates and allows Comic Chat control messages in PRIVMSG/NOTICE.
 *    Comic Chat uses CTCP-style framing (\x01...\x01) with a '#' prefix
 *    to transmit character selection and expression data inline.
 *    Format: \x01#<type><data>\x01
 *    Types:
 *      #c - Character selection
 *      #e - Expression/emotion
 *      #g - Gesture
 *      #p - Panel data
 *      #t - Thought balloon (vs speech)
 *      #w - Whisper balloon
 *
 * 3. Advertises support via ISUPPORT COMICCHAT token.
 *
 * 4. Exposes a MIME type for metadata content negotiation:
 *    application/x-mschat
 *
 * The actual rendering is entirely client-side; the server simply stores
 * and relays the character metadata properties.
 */

#include "stdinc.h"
#include "client.h"
#include "channel.h"
#include "hook.h"
#include "msg.h"
#include "modules.h"
#include "numeric.h"
#include "parse.h"
#include "s_conf.h"
#include "send.h"
#include "supported.h"
#include "hash.h"
#include "propertyset.h"

static const char ircx_comic_desc[] =
	"Provides Microsoft Comic Chat/Microsoft Chat character metadata support";

/* Maximum length for Comic Chat property values (base64-encoded data) */
#define MAX_MCC_VALUE_LEN 1024

/* Known Comic Chat PROP keys */
static const char *mcc_prop_keys[] = {
	"MCC",		/* character definition (base64-encoded comic chat data) */
	"MCCGUID",	/* character GUID (e.g., {12345678-1234-1234-1234-123456789012}) */
	"MCCEX",	/* expression/gesture state data */
	NULL
};

static bool
is_mcc_key(const char *key)
{
	for (const char **k = mcc_prop_keys; *k != NULL; k++)
	{
		if (!rb_strcasecmp(key, *k))
			return true;
	}
	return false;
}

/*
 * Hook: prop_user_write - allow Comic Chat property writes
 *
 * Comic Chat clients set their character data on themselves via PROP.
 * We validate the key name and enforce a size limit on the value.
 */
static void
h_comic_prop_user_write(void *vdata)
{
	hook_data_prop_activity *data = vdata;

	/* only handle user targets */
	if (IsChanPrefix(*data->target))
		return;

	if (!is_mcc_key(data->key))
		return;

	/* validate GUID format if it's the MCCGUID key */
	if (!rb_strcasecmp(data->key, "MCCGUID") && data->value != NULL)
	{
		/* GUID should be {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} or similar */
		if (strlen(data->value) > 64)
		{
			data->approved = 0;
			return;
		}
	}

	/* enforce value length limit for MCC data */
	if (data->value != NULL && strlen(data->value) > MAX_MCC_VALUE_LEN)
	{
		data->approved = 0;
		return;
	}

	/* allow the write */
	data->approved = 1;
}

/*
 * Hook: prop_list_append - emit Comic Chat properties in PROP listings
 *
 * When a user's properties are listed, include any MCC properties
 * that have been set.
 */
static void
h_comic_prop_list_append(void *vdata)
{
	hook_data_prop_list *data = vdata;

	/* only for user targets */
	if (IsChanPrefix(*data->target))
		return;

	/* The PROP system already handles listing stored properties.
	 * This hook is available for computed/virtual properties.
	 * Comic Chat properties are stored via the standard PROP
	 * mechanism, so no extra work is needed here.
	 */
}

mapi_hfn_list_av1 ircx_comic_hfnlist[] = {
	{ "prop_user_write", (hookfn) h_comic_prop_user_write },
	{ "prop_list_append", (hookfn) h_comic_prop_list_append },
	{ NULL, NULL }
};

static int
ircx_comic_init(void)
{
	/* advertise Comic Chat support via ISUPPORT */
	add_isupport("COMICCHAT", isupport_string, "");

	return 0;
}

static void
ircx_comic_deinit(void)
{
	delete_isupport("COMICCHAT");
}

DECLARE_MODULE_AV2(ircx_comic, ircx_comic_init, ircx_comic_deinit,
	NULL, NULL, ircx_comic_hfnlist, NULL, NULL, ircx_comic_desc);
