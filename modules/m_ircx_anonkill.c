/*
 * modules/m_ircx_anonkill.c
 *
 * Anonymous kill module. Provides user mode +K which causes KILL
 * messages to show "SYSTEM" instead of the operator's name, similar
 * to Microsoft Exchange Chat / IRCX behavior.
 *
 * Only operators with the "oper:anonkill" privilege may set +K.
 * When +K is active, kill quit messages show:
 *   "Killed (SYSTEM (reason))" instead of "Killed (opernick (reason))"
 *
 * Configuration:
 *   privset "admin" {
 *       privs = oper:admin, oper:anonkill;
 *   };
 *
 * The oper can toggle anonymous kills on/off with:
 *   /MODE yournick +K   (enable anonymous kills)
 *   /MODE yournick -K   (disable, show real name)
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_user.h"
#include "numeric.h"

static const char ircx_anonkill_desc[] =
	"Provides user mode +K for anonymous (SYSTEM) kills";

static void check_umode_change(void *data);

mapi_hfn_list_av1 ircx_anonkill_hfnlist[] = {
	{ "umode_changed", (hookfn) check_umode_change },
	{ NULL, NULL }
};

static int
_modinit(void)
{
	user_modes['K'] = find_umode_slot();
	construct_umodebuf();
	return 0;
}

static void
_moddeinit(void)
{
	user_modes['K'] = 0;
	construct_umodebuf();
}

DECLARE_MODULE_AV2(ircx_anonkill, _modinit, _moddeinit,
	NULL, NULL, ircx_anonkill_hfnlist, NULL, NULL, ircx_anonkill_desc);

/*
 * Only allow opers with oper:anonkill to set +K.
 * Automatically remove +K if the user is not an oper.
 */
static void
check_umode_change(void *vdata)
{
	hook_data_umode_changed *data = vdata;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	/* didn't change +K, nothing to do */
	if (!((data->oldumodes ^ source_p->umodes) & user_modes['K']))
		return;

	if (source_p->umodes & user_modes['K'])
	{
		/* trying to set +K -- must be oper with anonkill priv */
		if (!IsOper(source_p) || !HasPrivilege(source_p, "oper:anonkill"))
		{
			source_p->umodes &= ~user_modes['K'];
			sendto_one_notice(source_p,
				":You need the oper:anonkill privilege to use +K");
			return;
		}

		sendto_one_notice(source_p,
			":Anonymous kill mode enabled - kills will show as SYSTEM");
	}
}
