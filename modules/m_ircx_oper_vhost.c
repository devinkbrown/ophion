/*
 * modules/m_ircx_oper_vhost.c
 *
 * Oper virtual host and hidden oper status module.
 *
 * When an operator successfully /OPERs up, this module:
 *   1. Changes their visible hostname to the vhost configured in their
 *      operator{} block (if set), making them appear as a normal user.
 *   2. Works with the existing oper:hidden privilege to fully conceal
 *      oper status from WHOIS for non-opers.
 *
 * Before /OPER, the user appears with their cloaked address.
 * After /OPER, their host changes to the configured vhost.
 * Only opers/admins can see through the disguise via WHOIS.
 *
 * Configuration:
 *   operator "admin" {
 *       ...
 *       vhost = "staff.example.net";
 *       privset = "admin";
 *   };
 *
 *   privset "admin" {
 *       privs = oper:admin, oper:hidden;
 *   };
 */

#include "stdinc.h"
#include "client.h"
#include "hook.h"
#include "ircd.h"
#include "modules.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"

static const char ircx_oper_vhost_desc[] =
	"Applies configured vhost on oper-up and hides oper status";

static void h_oper_vhost_umode_changed(void *);

mapi_hfn_list_av1 ircx_oper_vhost_hfnlist[] = {
	{ "umode_changed", (hookfn) h_oper_vhost_umode_changed },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(ircx_oper_vhost, NULL, NULL,
	NULL, NULL, ircx_oper_vhost_hfnlist, NULL, NULL, ircx_oper_vhost_desc);

/*
 * Detect when a user opers up (UMODE_OPER was just set) and apply
 * their configured vhost if one exists.
 */
static void
h_oper_vhost_umode_changed(void *vdata)
{
	hook_data_umode_changed *data = vdata;
	struct Client *source_p = data->client;

	/* only trigger when OPER was just set (not already opered) */
	if (!(source_p->umodes & UMODE_OPER) || (data->oldumodes & UMODE_OPER))
		return;

	if (!MyClient(source_p))
		return;

	if (EmptyString(source_p->user->opername))
		return;

	/* find the matching oper_conf to get the vhost */
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, oper_conf_list.head)
	{
		struct oper_conf *oper_p = ptr->data;

		if (irccmp(oper_p->name, source_p->user->opername))
			continue;

		if (EmptyString(oper_p->vhost))
			break;

		/* save the original host before cloaking */
		/* orighost is already preserved by the client struct */

		/* propagate the host change to the network */
		sendto_server(NULL, NULL,
			CAP_EUID | CAP_TS6, NOCAPS, ":%s CHGHOST %s :%s",
			use_id(&me), use_id(source_p), oper_p->vhost);
		sendto_server(NULL, NULL,
			CAP_TS6, CAP_EUID, ":%s ENCAP * CHGHOST %s :%s",
			use_id(&me), use_id(source_p), oper_p->vhost);

		change_nick_user_host(source_p, source_p->name,
			source_p->username, oper_p->vhost, 0,
			"Changing host");

		SetDynSpoof(source_p);

		sendto_one_numeric(source_p, RPL_HOSTHIDDEN,
			"%s :is now your oper host",
			oper_p->vhost);

		break;
	}
}
