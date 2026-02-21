/*
 * modules/m_sendpass.c — SENDPASS command (token-based password reset)
 *
 * Request a token:
 *   SENDPASS <account>
 *   Generates a short-lived (15 min) reset token.  If the account has a
 *   registered email and sendmail(8) is available on the server, the token
 *   is delivered by email.  IRC operators are always notified via server
 *   notice so they can relay the token manually if email delivery fails.
 *
 * Apply a token:
 *   SENDPASS <account> <token> <new-password>
 *   Validates the token and resets the account password.
 *
 * Security notes:
 *   - The token store is purely in-memory; tokens do not survive a restart.
 *   - Only one pending token exists per account at a time.
 *   - The response to a request always looks the same whether or not the
 *     account exists, preventing account enumeration.
 *   - Opers are notified of every request (token included) so the network
 *     can function without email infrastructure.
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
#include "snomask.h"
#include "logger.h"
#include "services.h"
#include "services_db.h"
#include "services_sync.h"

/* rb_random_uint32 is not exported from librb; use rb_get_random instead */
extern int rb_get_random(void *buf, size_t len);
static uint32_t rand_u32(void) { uint32_t v; rb_get_random(&v, sizeof(v)); return v; }

static const char sendpass_desc[] =
	"Services SENDPASS command — token-based account password reset";

static void m_sendpass(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void moddeinit(void);

struct Message sendpass_msgtab = {
	"SENDPASS", 0, 0, 0, 0,
	{mg_unreg, {m_sendpass, 2}, mg_ignore, mg_ignore, mg_ignore, {m_sendpass, 2}}
};

mapi_clist_av1 sendpass_clist[] = { &sendpass_msgtab, NULL };

DECLARE_MODULE_AV2(m_sendpass, NULL, moddeinit, sendpass_clist, NULL, NULL, NULL, NULL, sendpass_desc);

/* =========================================================================
 * Token store
 * ========================================================================= */

#define TOKEN_EXPIRE_SECS  900   /* 15 minutes */
#define TOKEN_HEX_LEN      16   /* 16 hex chars → 64 bits of entropy */

struct sendpass_token {
	char account[NICKLEN + 1];
	char token[TOKEN_HEX_LEN + 1];
	time_t expires;
	rb_dlink_node node;
};

static rb_dlink_list token_list = { NULL, NULL, 0 };

static void
token_purge_expired(void)
{
	rb_dlink_node *ptr, *next;
	time_t now = rb_current_time();
	RB_DLINK_FOREACH_SAFE(ptr, next, token_list.head)
	{
		struct sendpass_token *t = ptr->data;
		if (t->expires <= now)
		{
			rb_dlinkDelete(ptr, &token_list);
			rb_free(t);
		}
	}
}

static struct sendpass_token *
token_find(const char *account)
{
	rb_dlink_node *ptr;
	time_t now = rb_current_time();
	RB_DLINK_FOREACH(ptr, token_list.head)
	{
		struct sendpass_token *t = ptr->data;
		if (irccmp(t->account, account) == 0 && t->expires > now)
			return t;
	}
	return NULL;
}

static void
token_remove(const char *account)
{
	rb_dlink_node *ptr, *next;
	RB_DLINK_FOREACH_SAFE(ptr, next, token_list.head)
	{
		struct sendpass_token *t = ptr->data;
		if (irccmp(t->account, account) == 0)
		{
			rb_dlinkDelete(ptr, &token_list);
			rb_free(t);
			return;
		}
	}
}

static struct sendpass_token *
token_create(const char *account)
{
	static const char hex[] = "0123456789abcdef";
	struct sendpass_token *t;

	token_remove(account);

	t = rb_malloc(sizeof(*t));
	rb_strlcpy(t->account, account, sizeof(t->account));
	for (int i = 0; i < TOKEN_HEX_LEN; i++)
		t->token[i] = hex[rand_u32() % 16];
	t->token[TOKEN_HEX_LEN] = '\0';
	t->expires = rb_current_time() + TOKEN_EXPIRE_SECS;
	rb_dlinkAdd(t, &t->node, &token_list);
	return t;
}

/* =========================================================================
 * Email delivery (best-effort via sendmail)
 * ========================================================================= */

static void
try_send_email(const char *to, const char *account, const char *token)
{
	if (EmptyString(to))
		return;

	FILE *fp = popen("/usr/sbin/sendmail -t", "w");
	if (fp == NULL)
		fp = popen("/usr/lib/sendmail -t", "w");
	if (fp == NULL)
		return;

	fprintf(fp, "To: %s\r\n", to);
	fprintf(fp, "From: services@%s\r\n", me.name);
	fprintf(fp, "Subject: Password reset for IRC account %s\r\n", account);
	fprintf(fp, "X-Mailer: Ophion IRC Services\r\n");
	fprintf(fp, "\r\n");
	fprintf(fp, "A password reset was requested for the IRC account: %s\r\n\r\n",
		account);
	fprintf(fp, "Your one-time reset token is:\r\n\r\n");
	fprintf(fp, "    %s\r\n\r\n", token);
	fprintf(fp, "To set a new password, connect to the IRC network and type:\r\n\r\n");
	fprintf(fp, "    /SENDPASS %s %s <your-new-password>\r\n\r\n", account, token);
	fprintf(fp, "This token expires in %d minutes.\r\n\r\n",
		TOKEN_EXPIRE_SECS / 60);
	fprintf(fp, "If you did not request this reset, ignore this message.\r\n");
	pclose(fp);
}

/* =========================================================================
 * Password hash helpers (same as m_accountset / m_register)
 * ========================================================================= */

static const char salt_chars[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void
build_sha512_salt(char *out, size_t outlen)
{
	if (outlen < 21)
		return;
	out[0] = '$'; out[1] = '6'; out[2] = '$';
	for (int i = 0; i < 16; i++)
		out[3 + i] = salt_chars[rand_u32() % 64];
	out[19] = '$'; out[20] = '\0';
}

/* =========================================================================
 * Module cleanup
 * ========================================================================= */

static void
moddeinit(void)
{
	rb_dlink_node *ptr, *next;
	RB_DLINK_FOREACH_SAFE(ptr, next, token_list.head)
	{
		struct sendpass_token *t = ptr->data;
		rb_dlinkDelete(ptr, &token_list);
		rb_free(t);
	}
}

/* =========================================================================
 * Command handler
 * ========================================================================= */

/*
 * m_sendpass — SENDPASS <account> [<token> <new-password>]
 *
 * parv[1] = account name
 * parv[2] = token        (apply form only)
 * parv[3] = new password (apply form only)
 */
static void
m_sendpass(struct MsgBuf *msgbuf_p, struct Client *client_p,
	   struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if (!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "SENDPASS");
		return;
	}

	if (!IsPerson(source_p))
		return;

	token_purge_expired();

	const char *account_name = parv[1];

	/* ---- Apply token: SENDPASS <account> <token> <newpassword> ---- */
	if (parc >= 4)
	{
		const char *given_token = parv[2];
		const char *new_pass    = parv[3];

		struct sendpass_token *t = token_find(account_name);

		if (t == NULL || rb_strcasecmp(t->token, given_token) != 0)
		{
			svc_notice(source_p, "Services",
				"Invalid or expired reset token. "
				"Use SENDPASS <account> to request a new one.");
			return;
		}

		if (strlen(new_pass) < 5)
		{
			svc_notice(source_p, "Services",
				"New password must be at least 5 characters.");
			return;
		}

		struct svc_account *acct = svc_account_find(account_name);
		if (acct == NULL)
		{
			/* Token was valid but account is gone — clean up. */
			token_remove(account_name);
			svc_notice(source_p, "Services",
				"Account \2%s\2 no longer exists.", account_name);
			return;
		}

		char salt[21];
		build_sha512_salt(salt, sizeof(salt));
		const char *hash = rb_crypt(new_pass, salt);
		if (hash == NULL)
		{
			svc_notice(source_p, "Services",
				"Internal error: password hashing failed.");
			return;
		}

		rb_strlcpy(acct->passhash, hash, sizeof(acct->passhash));
		svc_db_account_save(acct);
		svc_sync_account_pwd(acct);
		token_remove(account_name);

		ilog(L_MAIN, "SENDPASS: password reset for account %s by %s!%s@%s",
			acct->name,
			source_p->name, source_p->username, source_p->host);

		sendto_realops_snomask(SNO_GENERAL, L_ALL,
			"SENDPASS: password for account \2%s\2 was reset by %s!%s@%s",
			acct->name,
			source_p->name, source_p->username, source_p->host);

		svc_notice(source_p, "Services",
			"Password for account \2%s\2 has been reset. "
			"You may now IDENTIFY with your new password.",
			account_name);
		return;
	}

	/* ---- Request token: SENDPASS <account> ---- */
	struct svc_account *acct = svc_account_find(account_name);

	if (acct != NULL)
	{
		struct sendpass_token *t = token_create(acct->name);

		/* Attempt email delivery */
		if (!EmptyString(acct->email))
			try_send_email(acct->email, acct->name, t->token);

		/* Notify opers regardless, so they can relay the token
		 * manually if email infrastructure is unavailable. */
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
			"SENDPASS: reset token for account \2%s\2 requested by "
			"%s!%s@%s — token: %s (valid %d min)",
			acct->name,
			source_p->name, source_p->username, source_p->host,
			t->token, TOKEN_EXPIRE_SECS / 60);

		ilog(L_MAIN,
			"SENDPASS: token %s issued for account %s (requested by %s!%s@%s)",
			t->token, acct->name,
			source_p->name, source_p->username, source_p->host);
	}

	/* Always show the same message to prevent account enumeration. */
	svc_notice(source_p, "Services",
		"If account \2%s\2 exists and has a registered email, "
		"a reset token has been sent. "
		"The token expires in %d minutes. "
		"If you do not receive an email, contact a network operator.",
		account_name, TOKEN_EXPIRE_SECS / 60);
}
