/*
 * +W snomask: Notifies IRC operators and server admins when a non-oper
 * performs a WHOIS on them.  Only fires when the requesting user is not
 * an IRC operator, so routine oper-to-oper WHOIS queries are silent.
 *
 * Derived from spy_whois_notice.c.
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_newconf.h"

static const char sno_desc[] =
	"Adds server notice mask +W: notifies operators when a non-operator "
	"performs a WHOIS on them";

void show_whois(hook_data_client *);

mapi_hfn_list_av1 whois_hfnlist[] = {
	{"doing_whois",        (hookfn) show_whois},
	{"doing_whois_global", (hookfn) show_whois},
	{NULL, NULL}
};

static int
init(void)
{
	snomask_modes['W'] = find_snomask_slot();
	return 0;
}

static void
fini(void)
{
	snomask_modes['W'] = 0;
}

DECLARE_MODULE_AV2(sno_whois, init, fini, NULL, NULL, whois_hfnlist, NULL, NULL, sno_desc);

void
show_whois(hook_data_client *data)
{
	struct Client *source_p = data->client;
	struct Client *target_p = data->target;

	/* target must be a local oper or admin with +W set */
	if (!MyClient(target_p))
		return;
	if (!IsOperGeneral(target_p))
		return;
	if (!(target_p->snomask & snomask_modes['W']))
		return;

	/* don't notify for self-whois or oper-to-oper whois */
	if (source_p == target_p)
		return;
	if (IsOperGeneral(source_p))
		return;

	sendto_one_notice(target_p,
		":*** Notice -- %s (%s@%s) [%s] is performing a WHOIS on you",
		source_p->name,
		source_p->username, source_p->host,
		source_p->servptr->name);
}
