/*
 * modules/m_ircx_oper_autoowner.c
 *
 * IRCX oper auto-owner on channel join.
 *
 * When an IRC operator with the "oper:autoowner" privilege joins a
 * channel, they are automatically granted channel owner (+q) status.
 * This implements the IRCX concept that system administrators have
 * implicit authority over all channels.
 *
 * The privilege is controlled via privset{} configuration blocks,
 * allowing network administrators to choose which operator classes
 * receive automatic owner status.
 *
 * Example configuration:
 *   privset "admin" {
 *       privs = oper:admin, oper:autoowner;
 *   };
 */

#include "stdinc.h"
#include "channel.h"
#include "client.h"
#include "hook.h"
#include "modules.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_serv.h"
#include "send.h"

static const char ircx_oper_autoowner_desc[] =
	"Grants channel owner (+q) to opers with oper:autoowner privilege on join";

/*
 * Hook: channel_join - auto-owner opers on join
 *
 * When an oper with the "oper:autoowner" privilege joins any channel,
 * they are automatically granted +q (admin/owner) status.
 *
 * This only applies to local clients (remote opers will have their
 * status propagated normally).
 */
static void
h_oper_autoowner_join(void *vdata)
{
	hook_data_channel_activity *data = vdata;
	struct Channel *chptr = data->chptr;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	if (!IsOper(source_p))
		return;

	if (!HasPrivilege(source_p, "oper:autoowner"))
		return;

	struct membership *msptr = find_channel_membership(chptr, source_p);
	if (msptr == NULL)
		return;

	/* already owner/admin? skip */
	if (is_admin(msptr))
		return;

	/* grant +q (admin/owner) status */
	msptr->flags |= CHFL_ADMIN;

	sendto_channel_local(source_p, ALL_MEMBERS, chptr,
		":%s MODE %s +q %s",
		me.name, chptr->chname, source_p->name);
	sendto_server(NULL, chptr, CAP_TS6, NOCAPS,
		":%s TMODE %ld %s +q %s",
		me.id, (long)chptr->channelts,
		chptr->chname, use_id(source_p));
}

mapi_hfn_list_av1 ircx_oper_autoowner_hfnlist[] = {
	{ "channel_join", (hookfn) h_oper_autoowner_join },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(ircx_oper_autoowner, NULL, NULL,
	NULL, NULL, ircx_oper_autoowner_hfnlist, NULL, NULL, ircx_oper_autoowner_desc);
