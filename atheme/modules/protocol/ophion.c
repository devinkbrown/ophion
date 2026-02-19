/*
 * SPDX-License-Identifier: ISC
 *
 * ophion.c — Atheme protocol module for Ophion IRCd
 *
 * Ophion is a charybdis-derived IRCd with an integrated Discord gateway
 * bridge.  It is fully TS6-compatible and uses the same channel/user modes
 * as charybdis, so this module is a thin wrapper that:
 *
 *   1. Loads "protocol/charybdis" as a dependency (which in turn loads
 *      "protocol/ts6-generic"), inheriting all TS6 logic, mode lists,
 *      ban matching, and SASL handling.
 *
 *   2. Overrides the `ircd` identification struct so that Atheme reports
 *      the server type as "Ophion" rather than "Charybdis".
 *
 * Discord phantom clients
 * -----------------------
 * The Discord bridge introduces "phantom" IRC clients that represent Discord
 * users.  These are introduced to the network with umode +S (service flag),
 * and their hostname is always "discord.invalid".  Atheme already handles
 * +S clients correctly — NickServ will not attempt to enforce nicknames on
 * them, and no SASL prompts will be sent.  No extra code is needed here.
 *
 * Build instructions
 * ------------------
 * Place this file in atheme/modules/protocol/ inside your Atheme source tree,
 * then rebuild Atheme:
 *
 *   cp ophion.c /path/to/atheme/modules/protocol/
 *   cd /path/to/atheme && make
 *
 * Then load "protocol/ophion" instead of "protocol/charybdis" in atheme.conf.
 */

#include <atheme.h>
#include <atheme/protocol/charybdis.h>

/* Override only the identification name; everything else is charybdis. */
static struct ircd Ophion = {
	.ircdname        = "Ophion",
	.tldprefix       = "$$",
	.uses_uid        = true,
	.uses_rcommand   = false,
	.uses_owner      = false,
	.uses_protect    = false,
	.uses_halfops    = false,
	.uses_p10        = false,
	.uses_vhost      = false,
	.oper_only_modes = CMODE_EXLIMIT | CMODE_PERM | CMODE_IMMUNE,
	.owner_mode      = 0,
	.protect_mode    = 0,
	.halfops_mode    = 0,
	.owner_mchar     = "+",
	.protect_mchar   = "+",
	.halfops_mchar   = "+",
	.type            = PROTOCOL_CHARYBDIS,   /* TS6 / charybdis family */
	.perm_mode       = CMODE_PERM,
	.oimmune_mode    = CMODE_IMMUNE,
	.ban_like_modes  = "beIq",
	.except_mchar    = 'e',
	.invex_mchar     = 'I',
	.flags           = IRCD_CIDR_BANS | IRCD_HOLDNICK,
};

static void
mod_init(struct module *const restrict m)
{
	/*
	 * Pull in the full charybdis implementation — mode lists, ban
	 * matching, SASL, ENCAP IDENTIFIED, etc.
	 */
	MODULE_TRY_REQUEST_DEPENDENCY(m, "protocol/charybdis")

	/* Replace the charybdis identification struct with our own. */
	ircd = &Ophion;
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
}

SIMPLE_DECLARE_MODULE_V1("protocol/ophion", MODULE_UNLOAD_CAPABILITY_NEVER)
