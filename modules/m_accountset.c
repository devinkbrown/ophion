/*
 * modules/m_accountset.c — Account settings commands
 *
 * SETPASS: Change the account password.
 *   Syntax: SETPASS <old_password> <new_password>
 *
 * SETEMAIL: Change the account email address.
 *   Syntax: SETEMAIL <email>
 *
 * SET: Toggle boolean account flags.
 *   Syntax: SET <option> <on|off>
 *
 *   Options:
 *     HIDE EMAIL   — ACCT_HIDEMAIL  — hide email from INFO output
 *     PROTECT      — ACCT_PROTECT   — ghost/kill on nick collision
 *     SECURE       — ACCT_SECURE    — require access-list match to IDENTIFY
 *     PRIVATE      — ACCT_PRIVATE   — hide from LIST/searches
 *     MEMONOTIFY   — ACCT_MEMONOTIFY — notify on new memo
 *     NOMEMO       — ACCT_NOMEMO    — reject incoming memos
 *     NOOP         — ACCT_NOOP      — never auto-op on channel join
 *     ENFORCE      — ACCT_ENFORCE   — kill nick after enforce_delay if unid
 *     SASLONLY     — ACCT_SASLONLY  — IDENTIFY rejected; SASL PLAIN only
 *
 * Copyright (c) 2026 Ophion development team. GPL v2.
 */

#include "stdinc.h"
#include "client.h"
#include "hash.h"
#include "modules.h"
#include "msg.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "services.h"
#include "services_db.h"
#include "services_sync.h"

static const char accountset_desc[] =
	"Services SETPASS, SETEMAIL, SET commands — manage account settings and flags";

static void m_setpass(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void m_setemail(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void m_set(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message setpass_msgtab = {
	"SETPASS", 0, 0, 0, 0,
	{mg_unreg, {m_setpass, 3}, mg_ignore, mg_ignore, mg_ignore, {m_setpass, 3}}
};

struct Message setemail_msgtab = {
	"SETEMAIL", 0, 0, 0, 0,
	{mg_unreg, {m_setemail, 2}, mg_ignore, mg_ignore, mg_ignore, {m_setemail, 2}}
};

struct Message set_msgtab = {
	"SET", 0, 0, 0, 0,
	{mg_unreg, {m_set, 3}, mg_ignore, mg_ignore, mg_ignore, {m_set, 3}}
};

mapi_clist_av1 accountset_clist[] = {
	&setpass_msgtab, &setemail_msgtab, &set_msgtab, NULL
};

DECLARE_MODULE_AV2(m_accountset, NULL, NULL, accountset_clist, NULL, NULL, NULL, NULL, accountset_desc);

/* ---- salt/hash helpers (shared with m_register) ------------------------- */

static const char salt_chars[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void
build_sha512_salt(char *out, size_t outlen)
{
	if(outlen < 21)
		return;

	out[0] = '$';
	out[1] = '6';
	out[2] = '$';

	for(int i = 0; i < 16; i++)
		out[3 + i] = salt_chars[rb_random_uint32() % 64];

	out[19] = '$';
	out[20] = '\0';
}

/* ---- SETPASS handler ---------------------------------------------------- */

/*
 * m_setpass — SETPASS <old_password> <new_password>
 */
static void
m_setpass(struct MsgBuf *msgbuf_p, struct Client *client_p,
	  struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "SETPASS");
		return;
	}

	if(!IsPerson(source_p))
		return;

	if(EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "Services",
			"You must be identified to use SETPASS.");
		return;
	}

	const char *old_pass = parv[1];
	const char *new_pass = parv[2];

	if(strlen(new_pass) < 5)
	{
		svc_notice(source_p, "Services",
			"New password must be at least 5 characters long.");
		return;
	}

	/* Verify the old password. */
	struct svc_account *acct   = NULL;
	struct oper_conf   *oper_p = NULL;

	if(!svc_authenticate_password(source_p->user->suser, old_pass,
				      &acct, &oper_p) || acct == NULL)
	{
		svc_notice(source_p, "Services",
			"Old password is incorrect.");
		return;
	}

	/* Hash the new password. */
	char salt[21];
	build_sha512_salt(salt, sizeof(salt));

	const char *hash = rb_crypt(new_pass, salt);
	if(hash == NULL)
	{
		svc_notice(source_p, "Services",
			"Internal error: password hashing failed.");
		return;
	}

	rb_strlcpy(acct->passhash, hash, sizeof(acct->passhash));

	if(!svc_db_account_save(acct))
	{
		svc_notice(source_p, "Services",
			"Internal error: could not save account.");
		return;
	}

	svc_sync_account_pwd(acct);

	svc_notice(source_p, "Services",
		"Your password has been changed.");
}

/* ---- SETEMAIL handler --------------------------------------------------- */

/*
 * m_setemail — SETEMAIL <email>
 */
static void
m_setemail(struct MsgBuf *msgbuf_p, struct Client *client_p,
	   struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "SETEMAIL");
		return;
	}

	if(!IsPerson(source_p))
		return;

	if(EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "Services",
			"You must be identified to use SETEMAIL.");
		return;
	}

	const char *email = parv[1];

	if(strchr(email, '@') == NULL)
	{
		svc_notice(source_p, "Services",
			"Invalid email address (must contain '@').");
		return;
	}

	struct svc_account *acct = svc_account_find(source_p->user->suser);
	if(acct == NULL)
	{
		svc_notice(source_p, "Services",
			"Internal error: could not find your account record.");
		return;
	}

	rb_strlcpy(acct->email, email, sizeof(acct->email));

	if(!svc_db_account_save(acct))
	{
		svc_notice(source_p, "Services",
			"Internal error: could not save account.");
		return;
	}

	svc_sync_account_reg(acct);

	svc_notice(source_p, "Services",
		"Your email address has been updated to \2%s\2.", email);
}

/* ---- SET handler -------------------------------------------------------- */

/*
 * Flag descriptor table for the SET command.
 */
struct set_flag_entry {
	const char *name;
	uint32_t    flag;
};

static const struct set_flag_entry set_flags[] = {
	{ "HIDE EMAIL",  ACCT_HIDEMAIL   },
	{ "PROTECT",     ACCT_PROTECT    },
	{ "SECURE",      ACCT_SECURE     },
	{ "PRIVATE",     ACCT_PRIVATE    },
	{ "MEMONOTIFY",  ACCT_MEMONOTIFY },
	{ "NOMEMO",      ACCT_NOMEMO     },
	{ "NOOP",        ACCT_NOOP       },
	{ "ENFORCE",     ACCT_ENFORCE    },
	{ "SASLONLY",    ACCT_SASLONLY   },
	{ NULL, 0 }
};

/*
 * m_set — SET <option> <on|off>
 *
 * parv[1] = option name
 * parv[2] = "on" or "off"
 *
 * Special case: SET HIDE EMAIL uses two words for the option.
 * We detect this by checking if parv[1] == "HIDE" and parv[2] == "EMAIL",
 * then require parv[3] for the on/off value.
 */
static void
m_set(struct MsgBuf *msgbuf_p, struct Client *client_p,
      struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "SET");
		return;
	}

	if(!IsPerson(source_p))
		return;

	if(EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "Services",
			"You must be identified to use SET.");
		return;
	}

	/* Determine the option name and on/off value.
	 * Handle "SET HIDE EMAIL on|off" (three-word command). */
	char option[64];
	const char *value_str;

	if(rb_strcasecmp(parv[1], "HIDE") == 0 &&
	   parc >= 4 &&
	   rb_strcasecmp(parv[2], "EMAIL") == 0)
	{
		rb_strlcpy(option, "HIDE EMAIL", sizeof(option));
		value_str = parv[3];
	}
	else
	{
		rb_strlcpy(option, parv[1], sizeof(option));
		value_str = parv[2];
	}

	/* Parse on/off. */
	bool enable;
	if(rb_strcasecmp(value_str, "on") == 0 ||
	   rb_strcasecmp(value_str, "1") == 0 ||
	   rb_strcasecmp(value_str, "yes") == 0)
	{
		enable = true;
	}
	else if(rb_strcasecmp(value_str, "off") == 0 ||
		rb_strcasecmp(value_str, "0") == 0 ||
		rb_strcasecmp(value_str, "no") == 0)
	{
		enable = false;
	}
	else
	{
		svc_notice(source_p, "Services",
			"Invalid value '%s'. Use ON or OFF.", value_str);
		return;
	}

	/* Look up the flag. */
	uint32_t flag = 0;
	for(int i = 0; set_flags[i].name != NULL; i++)
	{
		if(rb_strcasecmp(option, set_flags[i].name) == 0)
		{
			flag = set_flags[i].flag;
			break;
		}
	}

	if(flag == 0)
	{
		svc_notice(source_p, "Services",
			"Unknown option \2%s\2. Valid options: "
			"HIDE EMAIL, PROTECT, SECURE, PRIVATE, "
			"MEMONOTIFY, NOMEMO, NOOP, ENFORCE, SASLONLY.",
			option);
		return;
	}

	struct svc_account *acct = svc_account_find(source_p->user->suser);
	if(acct == NULL)
	{
		svc_notice(source_p, "Services",
			"Internal error: could not find your account record.");
		return;
	}

	/* Apply the flag change. */
	if(enable)
		acct->flags |= flag;
	else
		acct->flags &= ~flag;

	if(!svc_db_account_save(acct))
	{
		svc_notice(source_p, "Services",
			"Internal error: could not save account settings.");
		return;
	}

	svc_sync_account_reg(acct);

	svc_notice(source_p, "Services",
		"Option \2%s\2 has been set to \2%s\2.",
		option, enable ? "ON" : "OFF");
}
