/*
 * modules/sasl_account.c — Account-aware SASL PLAIN and EXTERNAL mechanisms
 *
 * Replaces (at higher priority) the oper-only sasl_plain.c and
 * sasl_external.c mechanisms when Ophion services are enabled.  The
 * unified authentication sequence is:
 *
 * PLAIN:
 *   1. Parse the [authzid NUL] authcid NUL password wire payload.
 *   2. Try svc_authenticate_password(authcid, password) against the
 *      services account database.
 *   3. On account match: set sess->authzid to the account name; if the
 *      account has a linked oper block, stash it in pending_oper.
 *   4. If no account found: fall back to oper_find_by_name(authcid) +
 *      oper_check_password() (identical to sasl_plain.c behaviour).
 *   5. Return SUCCESS or FAILURE.
 *
 * EXTERNAL:
 *   1. Obtain client TLS certificate fingerprint.
 *   2. Try svc_authenticate_certfp(certfp, authzid) against the services DB.
 *   3. On account match: set sess->authzid; optionally stash pending_oper.
 *   4. If no account found: fall back to oper_find_certfp_only / match
 *      (identical to sasl_external.c behaviour).
 *   5. Return SUCCESS or FAILURE.
 *
 * Priority / co-existence with existing modules
 * ---------------------------------------------
 * Both this module and sasl_plain.c/sasl_external.c hook "sasl_start".
 * The SASL core calls hooks in order; the first hook to set hdata->mech
 * wins.  This module registers its hooks with HOOK_HIGH so it runs before
 * the oper-only HOOK_NORMAL modules.  When services are disabled, this
 * module sets nothing and the oper-only modules take over as normal.
 *
 * If services ARE enabled this module always handles PLAIN and EXTERNAL,
 * providing account auth with oper fallback in a single step.
 *
 * Wire formats
 * ------------
 *   PLAIN:    [authzid NUL] authcid NUL password   (same as RFC 4616)
 *   EXTERNAL: authzid (may be empty / "=")
 *
 * Copyright (c) 2026 Ophion development team.  GPL v2.
 */

#include "stdinc.h"
#include "client.h"
#include "sasl.h"
#include "hook.h"
#include "modules.h"
#include "auth_oper.h"
#include "s_newconf.h"
#include "services.h"

static const char sasl_account_desc[] =
	"Account-aware SASL PLAIN/EXTERNAL — authenticates services accounts "
	"and oper blocks in a single unified step";

/* =========================================================================
 * PLAIN mechanism
 * ========================================================================= */

static enum sasl_mechanism_result
sasl_acct_plain_start(struct sasl_session *sess,
                      struct sasl_output_buf *outbuf)
{
	/* PLAIN needs no server challenge */
	outbuf->buf = NULL;
	outbuf->len = 0;
	return SASL_MRESULT_CONTINUE;
}

static enum sasl_mechanism_result
sasl_acct_plain_step(struct sasl_session *sess,
                     const struct sasl_input_buf *inbuf,
                     struct sasl_output_buf *outbuf)
{
	outbuf->buf = NULL;
	outbuf->len = 0;

	if(inbuf->buf == NULL || inbuf->len == 0)
		return SASL_MRESULT_FAILURE;

	/*
	 * PLAIN wire format: [authzid NUL] authcid NUL password
	 * The password is NOT NUL-terminated; it runs to end of buffer.
	 */
	const uint8_t *buf = (const uint8_t *)inbuf->buf;
	size_t rem = inbuf->len;

	/* First NUL: end of optional authzid */
	const uint8_t *nul = memchr(buf, '\0', rem);
	if(nul == NULL)
		return SASL_MRESULT_FAILURE;

	size_t authzid_len = (size_t)(nul - buf);
	char authzid[NICKLEN + 1] = { 0 };
	if(authzid_len > NICKLEN)
		return SASL_MRESULT_FAILURE;
	if(authzid_len)
		memcpy(authzid, buf, authzid_len);

	buf += authzid_len + 1;
	rem -= authzid_len + 1;

	/* Second NUL: end of authcid */
	nul = memchr(buf, '\0', rem);
	if(nul == NULL)
		return SASL_MRESULT_FAILURE;

	size_t authcid_len = (size_t)(nul - buf);
	char authcid[NICKLEN + 1] = { 0 };
	if(authcid_len == 0 || authcid_len > NICKLEN)
		return SASL_MRESULT_FAILURE;
	memcpy(authcid, buf, authcid_len);

	buf += authcid_len + 1;
	rem -= authcid_len + 1;

	/* Remainder is the password */
	if(rem == 0 || rem >= BUFSIZE)
		return SASL_MRESULT_FAILURE;
	char passwd[BUFSIZE] = { 0 };
	memcpy(passwd, buf, rem);

	/* authzid, if provided, must equal authcid */
	if(*authzid && irccmp(authzid, authcid) != 0)
		return SASL_MRESULT_FAILURE;

	/* ---------------------------------------------------------------
	 * Path 1: try services account database
	 * --------------------------------------------------------------- */
	if(services.enabled) {
		struct svc_account *acct  = NULL;
		struct oper_conf   *oper_p = NULL;

		if(svc_authenticate_password(authcid, passwd, &acct, &oper_p)) {
			rb_strlcpy(sess->authzid, acct->name,
			           sizeof(sess->authzid));

			if(oper_p != NULL)
				sess->client->localClient->pending_oper = oper_p;

			return SASL_MRESULT_SUCCESS;
		}
	}

	/* ---------------------------------------------------------------
	 * Path 2: fall back to oper block (mirrors sasl_plain.c)
	 * --------------------------------------------------------------- */
	struct oper_conf *oper_p = oper_find_by_name(authcid);
	if(oper_p == NULL) {
		oper_log_failure(sess->client, authcid,
		                 "no account or oper block", "SASL PLAIN");
		return SASL_MRESULT_FAILURE;
	}

	if(!oper_check_password(passwd, oper_p)) {
		oper_log_failure(sess->client, authcid,
		                 "password mismatch", "SASL PLAIN");
		return SASL_MRESULT_FAILURE;
	}

	if(oper_p->certfp != NULL && !oper_check_certfp(sess->client, oper_p)) {
		oper_log_failure(sess->client, authcid,
		                 "certfp mismatch", "SASL PLAIN");
		return SASL_MRESULT_FAILURE;
	}

	rb_strlcpy(sess->authzid, authcid, sizeof(sess->authzid));
	sess->client->localClient->pending_oper = oper_p;

	return SASL_MRESULT_SUCCESS;
}

static struct sasl_mechanism sasl_acct_plain_mech = {
	.name           = "PLAIN",
	.start_fn       = sasl_acct_plain_start,
	.step_fn        = sasl_acct_plain_step,
	.finish_fn      = NULL,
	.password_based = true,
};

/* =========================================================================
 * EXTERNAL mechanism
 * ========================================================================= */

static enum sasl_mechanism_result
sasl_acct_external_start(struct sasl_session *sess,
                         struct sasl_output_buf *outbuf)
{
	outbuf->buf = NULL;
	outbuf->len = 0;

	/* Fail immediately if the client has no TLS certificate — there is no
	 * point in sending AUTHENTICATE + and waiting for a payload that cannot
	 * possibly authenticate without a cert fingerprint. */
	if(sess->client->certfp == NULL)
	{
		oper_log_failure(sess->client, "*", "no client certificate", "SASL EXTERNAL");
		return SASL_MRESULT_FAILURE;
	}

	return SASL_MRESULT_CONTINUE;
}

static enum sasl_mechanism_result
sasl_acct_external_step(struct sasl_session *sess,
                        const struct sasl_input_buf *inbuf,
                        struct sasl_output_buf *outbuf)
{
	outbuf->buf = NULL;
	outbuf->len = 0;

	if(sess->client->certfp == NULL) {
		oper_log_failure(sess->client, "*",
		                 "no client certificate", "SASL EXTERNAL");
		return SASL_MRESULT_FAILURE;
	}

	/*
	 * The EXTERNAL payload is the authzid: either an account name, an oper
	 * block name, or empty (auto-discovery).  An empty payload or "=" means
	 * the server should look up the certificate automatically.
	 */
	char authzid[NICKLEN + 1] = { 0 };

	if(inbuf->buf != NULL && inbuf->len > 0) {
		if(inbuf->len > NICKLEN)
			return SASL_MRESULT_FAILURE;
		memcpy(authzid, inbuf->buf, inbuf->len);
		if(memchr(authzid, '\0', inbuf->len) != NULL)
			return SASL_MRESULT_FAILURE;
	}

	const char *certfp = sess->client->certfp;

	/* ---------------------------------------------------------------
	 * Path 1: try services account database (certfp lookup)
	 * --------------------------------------------------------------- */
	if(services.enabled) {
		struct svc_account *acct   = NULL;
		struct oper_conf   *oper_p = NULL;

		/*
		 * svc_authenticate_certfp: pass authzid as account_hint
		 * (may be empty for auto-discovery).  On success, *acct and
		 * *oper_p may both be set (account with linked oper block).
		 */
		if(svc_authenticate_certfp(certfp, authzid, &acct, &oper_p)) {
			if(acct != NULL) {
				rb_strlcpy(sess->authzid, acct->name,
				           sizeof(sess->authzid));
			} else if(oper_p != NULL) {
				rb_strlcpy(sess->authzid, oper_p->name,
				           sizeof(sess->authzid));
			}

			if(oper_p != NULL)
				sess->client->localClient->pending_oper = oper_p;

			return SASL_MRESULT_SUCCESS;
		}
	}

	/* ---------------------------------------------------------------
	 * Path 2: fall back to certfp_only oper blocks (mirrors sasl_external.c)
	 * --------------------------------------------------------------- */
	struct oper_conf *oper_p;

	if(*authzid) {
		oper_p = oper_find_certfp_only(authzid);
		if(oper_p == NULL) {
			oper_log_failure(sess->client, authzid,
			                 "no certfp_only oper block",
			                 "SASL EXTERNAL");
			return SASL_MRESULT_FAILURE;
		}
		if(!oper_check_certfp(sess->client, oper_p)) {
			oper_log_failure(sess->client, authzid,
			                 "certfp mismatch", "SASL EXTERNAL");
			return SASL_MRESULT_FAILURE;
		}
	} else {
		oper_p = oper_find_certfp_match(sess->client);
		if(oper_p == NULL) {
			oper_log_failure(sess->client, "*",
			                 "no certfp_only block matches certificate",
			                 "SASL EXTERNAL");
			return SASL_MRESULT_FAILURE;
		}
	}

	rb_strlcpy(sess->authzid, oper_p->name, sizeof(sess->authzid));
	sess->client->localClient->pending_oper = oper_p;

	return SASL_MRESULT_SUCCESS;
}

static struct sasl_mechanism sasl_acct_external_mech = {
	.name           = "EXTERNAL",
	.start_fn       = sasl_acct_external_start,
	.step_fn        = sasl_acct_external_step,
	.finish_fn      = NULL,
	.password_based = false,
};

/* =========================================================================
 * Hook: intercept mechanism selection
 *
 * Registered at HOOK_HIGH so we run before sasl_plain.c / sasl_external.c
 * (which use the default HOOK_NORMAL priority).  If hdata->mech is already
 * set by a higher-priority hook we do not override it.
 * ========================================================================= */

static void
h_sasl_account_start(void *vdata)
{
	struct sasl_hook_data *hdata = vdata;

	/* Do not override a mechanism that was already selected */
	if(hdata->mech != NULL)
		return;

	/*
	 * When services are disabled, this module still intercepts the hook
	 * but presents mechanisms that transparently fall back to oper-only
	 * auth — so behaviour is identical to the oper-only modules.
	 * There is no need to skip registration when services are disabled.
	 */

	if(irccmp(hdata->name, "PLAIN") == 0) {
		hdata->mech = &sasl_acct_plain_mech;
		return;
	}

	if(irccmp(hdata->name, "EXTERNAL") == 0) {
		hdata->mech = &sasl_acct_external_mech;
		return;
	}
}

/* =========================================================================
 * Module wiring
 * ========================================================================= */

mapi_hfn_list_av1 sasl_account_hfnlist[] = {
	{ "sasl_start", h_sasl_account_start, HOOK_HIGH },
	{ NULL, NULL, 0 }
};

DECLARE_MODULE_AV2(sasl_account, NULL, NULL, NULL, NULL,
                   sasl_account_hfnlist, NULL, NULL, sasl_account_desc);
