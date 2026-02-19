/*
 * modules/m_ircx_identify.c
 *
 * IRCX IDENTIFY command for channel key-based access.
 *
 * IDENTIFY #channel <key>
 *
 * Checks the provided key against channel properties:
 *   OWNERKEY/ADMINKEY  -> grants +q (channel owner)
 *   HOSTKEY/OPKEY      -> grants +o (channel operator)
 *   MEMBERKEY (+k key) -> grants +v (voice)
 *
 * The user must be a member of the channel. This allows users to
 * authenticate to a channel after joining, rather than only at join time.
 */

#include "stdinc.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "msg.h"
#include "modules.h"
#include "numeric.h"
#include "parse.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "propertyset.h"

static const char ircx_identify_desc[] =
	"Provides IDENTIFY command for channel key-based access elevation";

static void m_identify(struct MsgBuf *, struct Client *, struct Client *,
	int, const char **);

struct Message identify_msgtab = {
	"IDENTIFY", 0, 0, 0, 0,
	{mg_unreg, {m_identify, 3}, mg_ignore, mg_ignore, mg_ignore, {m_identify, 3}}
};

mapi_clist_av1 ircx_identify_clist[] = { &identify_msgtab, NULL };

DECLARE_MODULE_AV2(ircx_identify, NULL, NULL,
	ircx_identify_clist, NULL, NULL, NULL, NULL, ircx_identify_desc);

/*
 * m_identify - IDENTIFY #channel <key>
 *
 * parv[1] = channel name
 * parv[2] = key
 */
static void
m_identify(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr;
	struct membership *msptr;
	const char *key;
	struct Property *prop;

	if (!IsChanPrefix(parv[1][0]))
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
			form_str(ERR_NOSUCHCHANNEL), parv[1]);
		return;
	}

	chptr = find_channel(parv[1]);
	if (chptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
			form_str(ERR_NOSUCHCHANNEL), parv[1]);
		return;
	}

	msptr = find_channel_membership(chptr, source_p);
	if (msptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOTONCHANNEL,
			form_str(ERR_NOTONCHANNEL), chptr->chname);
		return;
	}

	key = parv[2];

	/* Check OWNERKEY/ADMINKEY -> +q */
	prop = propertyset_find(&chptr->prop_list, "OWNERKEY");
	if (prop == NULL)
		prop = propertyset_find(&chptr->prop_list, "ADMINKEY");

	if (prop != NULL && !strcmp(prop->value, key))
	{
		if (is_admin(msptr))
		{
			sendto_one_notice(source_p,
				":You are already a channel owner on %s",
				chptr->chname);
			return;
		}

		const char *para[] = {"+q", source_p->name};
		set_channel_mode(source_p, &me, chptr, NULL, 2, para);

		sendto_one_notice(source_p,
			":IDENTIFY successful - owner access granted on %s",
			chptr->chname);
		return;
	}

	/* Check HOSTKEY/OPKEY -> +o */
	prop = propertyset_find(&chptr->prop_list, "HOSTKEY");
	if (prop == NULL)
		prop = propertyset_find(&chptr->prop_list, "OPKEY");

	if (prop != NULL && !strcmp(prop->value, key))
	{
		if (is_chanop(msptr))
		{
			sendto_one_notice(source_p,
				":You are already a channel operator on %s",
				chptr->chname);
			return;
		}

		const char *para[] = {"+o", source_p->name};
		set_channel_mode(source_p, &me, chptr, NULL, 2, para);

		sendto_one_notice(source_p,
			":IDENTIFY successful - operator access granted on %s",
			chptr->chname);
		return;
	}

	/* Check MEMBERKEY / +k channel key -> +v */
	if (*chptr->mode.key && !strcmp(chptr->mode.key, key))
	{
		if (is_voiced(msptr))
		{
			sendto_one_notice(source_p,
				":You are already voiced on %s",
				chptr->chname);
			return;
		}

		const char *para[] = {"+v", source_p->name};
		set_channel_mode(source_p, &me, chptr, NULL, 2, para);

		sendto_one_notice(source_p,
			":IDENTIFY successful - voice access granted on %s",
			chptr->chname);
		return;
	}

	/* No match */
	sendto_one_notice(source_p,
		":IDENTIFY failed - incorrect key for %s",
		chptr->chname);
}
