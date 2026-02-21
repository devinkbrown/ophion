/*
 * modules/m_register.c — Services REGISTER command
 *
 * Register the current nick as a new account.
 *
 * Syntax: REGISTER <email> <password>
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

static const char register_desc[] =
	"Services REGISTER command — registers the current nick as a new account";

static void m_register(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message register_msgtab = {
	"REGISTER", 0, 0, 0, 0,
	{mg_unreg, {m_register, 3}, mg_ignore, mg_ignore, mg_ignore, {m_register, 3}}
};

mapi_clist_av1 register_clist[] = { &register_msgtab, NULL };

DECLARE_MODULE_AV2(m_register, NULL, NULL, register_clist, NULL, NULL, NULL, NULL, register_desc);

/* ---- salt/hash helpers -------------------------------------------------- */

/* rb_random_uint32 is not exported from libircd; use rb_get_random instead */
extern int rb_get_random(void *buf, size_t len);
static uint32_t rand_u32(void) { uint32_t v; rb_get_random(&v, sizeof(v)); return v; }

static const char salt_chars[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/*
 * build_sha512_salt — fill `out` with "$6$<16 random chars>$\0".
 * `out` must be at least 21 bytes.
 */
static void
build_sha512_salt(char *out, size_t outlen)
{
	/* We need at least "$6$" (3) + 16 chars + "$" + NUL = 21 bytes. */
	if(outlen < 21)
		return;

	out[0] = '$';
	out[1] = '6';
	out[2] = '$';

	for(int i = 0; i < 16; i++)
		out[3 + i] = salt_chars[rand_u32() % 64];

	out[19] = '$';
	out[20] = '\0';
}

/* ---- command handler ---------------------------------------------------- */

/*
 * m_register — REGISTER <email> <password>
 *
 * parv[1] = email
 * parv[2] = password
 */
static void
m_register(struct MsgBuf *msgbuf_p, struct Client *client_p,
	   struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	/* Services must be enabled. */
	if(!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "REGISTER");
		return;
	}

	/* Registrations may be administratively closed. */
	if(!services.registration_open)
	{
		svc_notice(source_p, "Services",
			"Registration is currently closed.");
		return;
	}

	/* Must be a fully-registered user. */
	if(!IsPerson(source_p))
	{
		svc_notice(source_p, "Services",
			"You must complete connection registration before using REGISTER.");
		return;
	}

	/* Must not already be identified. */
	if(!EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "Services",
			"You are already identified as \2%s\2.", source_p->user->suser);
		return;
	}

	const char *email    = parv[1];
	const char *password = parv[2];

	/* Validate email — must contain '@'. */
	if(strchr(email, '@') == NULL)
	{
		svc_notice(source_p, "Services",
			"Invalid email address (must contain '@').");
		return;
	}

	/* Password must be at least 5 characters. */
	if(strlen(password) < 5)
	{
		svc_notice(source_p, "Services",
			"Password must be at least 5 characters long.");
		return;
	}

	const char *nick = source_p->name;

	/* Nick must not already be a registered account. */
	if(svc_account_find(nick) != NULL || svc_account_find_nick(nick) != NULL)
	{
		svc_notice(source_p, "Services",
			"The nick \2%s\2 is already registered.", nick);
		return;
	}

	/* Hash the password using SHA-512 crypt. */
	char salt[21];
	build_sha512_salt(salt, sizeof(salt));

	const char *hash = rb_crypt(password, salt);
	if(hash == NULL)
	{
		svc_notice(source_p, "Services",
			"Internal error: password hashing failed. Please try again later.");
		return;
	}

	/* Create the account record. */
	struct svc_account *acct = svc_account_create(nick, hash, email);
	if(acct == NULL)
	{
		svc_notice(source_p, "Services",
			"Internal error: account creation failed. Please try again later.");
		return;
	}

	/* Add the nick to the account's nick group (primary nick == account name). */
	svc_db_nick_add(nick, nick);

	/* Mark the client as identified. */
	rb_strlcpy(source_p->user->suser, acct->name,
		   sizeof(source_p->user->suser));

	/* Propagate account to other servers. */
	svc_sync_account_reg(acct);

	/* Also inform other servers that this client is now logged in. */
	sendto_server(NULL, NULL, CAP_ENCAP, NOCAPS,
		":%s ENCAP * LOGIN %s",
		use_id(source_p), source_p->user->suser);

	/* RPL_LOGGEDIN (900): notify the client it is now logged in. */
	sendto_one(source_p, form_str(RPL_LOGGEDIN),
		me.name, source_p->name,
		source_p->name, source_p->username, source_p->host,
		acct->name, acct->name);

	svc_notice(source_p, "Services",
		"Your nick \2%s\2 has been registered. "
		"You are now identified.", nick);
}
