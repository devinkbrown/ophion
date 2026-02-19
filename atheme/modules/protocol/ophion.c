/*
 * SPDX-License-Identifier: ISC
 *
 * ophion.c — Atheme protocol module for Ophion IRCd
 *
 * Ophion is a charybdis-derived IRCd with an integrated Discord gateway
 * bridge.  It is fully TS6-compatible and uses the same channel/user modes
 * as charybdis, so this module:
 *
 *   1. Loads "protocol/charybdis" as a dependency (which in turn loads
 *      "protocol/ts6-generic"), inheriting all TS6 logic, mode lists,
 *      ban matching, and SASL handling.
 *
 *   2. Overrides the `ircd` identification struct so that Atheme reports
 *      the server type as "Ophion" rather than "Charybdis".
 *
 *   3. Adds a user_add hook that fires when a Discord phantom first
 *      appears on the network.  If the user is already identified (their
 *      account name was embedded in the UID burst), nothing is done —
 *      ChanServ will grant them +o/+v automatically on channel join.
 *      If the user is not identified, and NickServ is loaded, they receive
 *      a notice explaining how to run !identify from Discord.
 *
 * Discord phantom clients
 * -----------------------
 * Phantom clients (representing Discord users) have:
 *   host       = "discord.invalid"
 *   umode      = +S (service flag)
 *   suser/acct = NickServ account name (if previously identified), else ""
 *
 * Because phantoms carry +S, Atheme will NOT:
 *   - Send NickServ nick-enforcement or SASL prompts to them.
 *   - Include them in MemoServ "new memo" notifications.
 *
 * Because phantoms MAY carry a pre-set account name in the UID burst
 * (set by Ophion when it knows the discord_uid → NickServ mapping from
 * its discord_accounts.db file), ChanServ WILL:
 *   - Recognise them as identified on join.
 *   - Apply AUTOOP / AUTOVOICE / AUTOHALFOP flags from the access list.
 *   - Enforce AKICK entries against them.
 *   - Respect the RESTRICTED channel flag (kick if not on the access list).
 *
 * Identifying from Discord
 * ------------------------
 * Discord users send "!identify [account] password" in any bridged channel.
 * Ophion's discordd detects the "!identify" prefix, suppresses it from
 * appearing as a PRIVMSG on IRC, and relays it to discordproc via the "I"
 * wire-protocol message.  discordproc then sends PRIVMSG NickServ IDENTIFY
 * from the phantom's UID.  On success, NickServ sends SU <uid> <account>,
 * which Ophion records in discord_accounts.db and uses to pre-identify
 * future sessions for that Discord user.
 *
 * Services are optional
 * ---------------------
 * If no Atheme instance is connected, phantom clients still function as
 * normal IRC users — they just won't receive channel access modes
 * automatically.  All the code in this module is guarded against
 * nicksvs.me / chansvs.me being NULL.
 *
 * Build instructions
 * ------------------
 * Place this file in atheme/modules/protocol/ inside your Atheme source tree,
 * then rebuild Atheme:
 *
 *   cp ophion.c /path/to/atheme/modules/protocol/
 *   cd /path/to/atheme && make
 *
 * Then in atheme.conf load "protocol/ophion" instead of "protocol/charybdis".
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

/*
 * is_discord_phantom - returns true if the user was introduced by the
 * Ophion Discord bridge (host == "discord.invalid").
 */
static inline bool
is_discord_phantom(const struct user *u)
{
	return u != NULL && strcmp(u->host, "discord.invalid") == 0;
}

/*
 * ophion_user_add - fired when any user appears on the network.
 *
 * For Discord phantoms that are not yet identified to services, send a
 * brief NickServ notice explaining how to link their account.  This gives
 * them a prompt to run "!identify" from Discord.
 *
 * If services are not loaded (nicksvs.me == NULL), this is a no-op so
 * that Ophion works correctly in a services-free configuration.
 */
static void
ophion_user_add(hook_user_nick_t *data)
{
	struct user *u = data->u;

	if (!is_discord_phantom(u))
		return;

	/* Already identified — ChanServ will auto-op them on channel join. */
	if (u->myuser != NULL)
		return;

	/*
	 * Services are optional.  If NickServ isn't loaded, nothing to do.
	 * Phantoms without a services account still work; they just won't
	 * receive automatic channel modes.
	 */
	if (nicksvs.me == NULL)
		return;

	notice(nicksvs.nick, u->nick,
	       "You are connected via the Discord bridge. "
	       "To receive your IRC channel access (op/voice), link your "
	       "NickServ account by typing in any bridged Discord channel: "
	       "\x02!identify password\x02  "
	       "or  \x02!identify accountname password\x02");
}

/*
 * ophion_user_identify - fired when a user successfully identifies to
 * services (via NickServ IDENTIFY, SASL, or CertFP).
 *
 * For Discord phantoms this is largely handled by ChanServ automatically;
 * we log a note for debugging purposes.
 */
static void
ophion_user_identify(struct user *u)
{
	if (!is_discord_phantom(u))
		return;

	slog(LG_DEBUG,
	     "ophion: Discord phantom %s identified as %s",
	     u->nick,
	     u->myuser ? entity(u->myuser)->name : "(unknown)");

	/*
	 * ChanServ will now apply AUTOOP/AUTOVOICE for all channels this
	 * phantom is in.  No action required here; the channel_join hook
	 * in chanserv/main handles the mode grant.
	 */
}

static void
mod_init(struct module *const restrict m)
{
	/*
	 * Pull in the full charybdis implementation — mode lists, ban
	 * matching, SASL, ENCAP IDENTIFIED, channel mode validation, etc.
	 */
	MODULE_TRY_REQUEST_DEPENDENCY(m, "protocol/charybdis")

	/* Replace the charybdis identification struct with Ophion's. */
	ircd = &Ophion;

	/* Register Discord-bridge-aware hooks. */
	hook_add_user_add(ophion_user_add);
	hook_add_user_identify(ophion_user_identify);
}

static void
mod_deinit(const enum module_unload_intent ATHEME_VATTR_UNUSED intent)
{
	hook_del_user_add(ophion_user_add);
	hook_del_user_identify(ophion_user_identify);
}

SIMPLE_DECLARE_MODULE_V1("protocol/ophion", MODULE_UNLOAD_CAPABILITY_NEVER)
