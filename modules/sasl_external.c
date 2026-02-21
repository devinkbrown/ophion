/*
 * modules/sasl_external.c -- SASL EXTERNAL mechanism for oper pre-authentication
 *
 * Allows a client to authenticate as an IRC operator during connection
 * registration using SASL EXTERNAL (TLS certificate fingerprint), before
 * sending the OPER command.  On success the client's pending_oper pointer is
 * set; register_local_user() calls oper_up() automatically once registration
 * completes.
 *
 * Only oper blocks that have certfp_only = yes; are eligible — those blocks
 * do not require a password and authenticate solely by certificate fingerprint.
 *
 * Protocol exchange
 * -----------------
 *   Client: AUTHENTICATE EXTERNAL
 *   Server: AUTHENTICATE +               (no server challenge for EXTERNAL)
 *   Client: AUTHENTICATE <base64(authzid)>   or   AUTHENTICATE =
 *   Server: 900 (RPL_LOGGEDIN) + 903 (RPL_SASLSUCCESS)  on success
 *           908 (ERR_SASLFAIL)                           on failure
 *
 * authzid semantics
 * -----------------
 *   Non-empty: the client names a specific certfp_only oper block.  The server
 *              checks that block's fingerprint against the client's cert.
 *   Empty / "=": the server tries every certfp_only block and grants the first
 *              one whose fingerprint matches the client's certificate.
 *
 * Example (netcat / ircd):
 *   CAP REQ :sasl
 *   NICK alice
 *   USER alice 0 * :Alice
 *   AUTHENTICATE EXTERNAL
 *   AUTHENTICATE =
 *   --- oper_up() fires automatically after 001 Welcome ---
 */

#include "stdinc.h"
#include "client.h"
#include "sasl.h"
#include "hook.h"
#include "modules.h"
#include "auth_oper.h"
#include "numeric.h"
#include "s_newconf.h"

static const char sasl_external_desc[] =
	"SASL EXTERNAL mechanism — authenticates a certfp_only oper block during registration";

/* ---- mechanism callbacks ----------------------------------------------- */

static enum sasl_mechanism_result
sasl_external_start(struct sasl_session *sess, struct sasl_output_buf *outbuf)
{
	/* EXTERNAL needs no server challenge; tell the core to send AUTHENTICATE + */
	outbuf->buf = NULL;
	outbuf->len = 0;
	return SASL_MRESULT_CONTINUE;
}

static enum sasl_mechanism_result
sasl_external_step(struct sasl_session *sess,
		   const struct sasl_input_buf *inbuf,
		   struct sasl_output_buf *outbuf)
{
	outbuf->buf = NULL;
	outbuf->len = 0;

	/* Client must have a TLS certificate for EXTERNAL to make sense. */
	if(sess->client->certfp == NULL)
		return SASL_MRESULT_FAILURE;

	/*
	 * The EXTERNAL payload is the authzid: the name of the certfp_only oper
	 * block the client wants to become.  An empty payload (or the single
	 * byte '=') means "pick the first matching block automatically".
	 *
	 * inbuf->buf may be NULL when the client sent "AUTHENTICATE =" which the
	 * core decodes to an empty/zero-length buffer.
	 */
	char authzid[NICKLEN + 1] = { 0 };

	if(inbuf->buf != NULL && inbuf->len > 0)
	{
		if(inbuf->len > NICKLEN)
			return SASL_MRESULT_FAILURE;
		memcpy(authzid, inbuf->buf, inbuf->len);
		/* authzid must not contain embedded NUL bytes */
		if(memchr(authzid, '\0', inbuf->len) != NULL)
			return SASL_MRESULT_FAILURE;
	}

	struct oper_conf *oper_p;

	if(*authzid)
	{
		/*
		 * Client specified a block name — look it up and verify the cert.
		 * oper_find_certfp_only() only returns blocks with OPER_CERTFP_ONLY set.
		 */
		oper_p = oper_find_certfp_only(authzid);
		if(oper_p == NULL)
			return SASL_MRESULT_FAILURE;

		if(!oper_check_certfp(sess->client, oper_p))
			return SASL_MRESULT_FAILURE;
	}
	else
	{
		/*
		 * No authzid supplied — scan every certfp_only block and pick the
		 * first one whose fingerprint matches the client's certificate.
		 */
		rb_dlink_node *ptr;
		oper_p = NULL;

		RB_DLINK_FOREACH(ptr, oper_conf_list.head)
		{
			struct oper_conf *candidate = ptr->data;
			if(!IsOperConfCertFPOnly(candidate))
				continue;
			if(oper_check_certfp(sess->client, candidate))
			{
				oper_p = candidate;
				break;
			}
		}

		if(oper_p == NULL)
			return SASL_MRESULT_FAILURE;
	}

	/* success: record authzid and stash the oper block for post-registration */
	rb_strlcpy(sess->authzid, oper_p->name, sizeof(sess->authzid));
	sess->client->localClient->pending_oper = oper_p;

	return SASL_MRESULT_SUCCESS;
}

/* ---- mechanism descriptor ---------------------------------------------- */

static struct sasl_mechanism sasl_external_mech = {
	.name           = "EXTERNAL",
	.start_fn       = sasl_external_start,
	.step_fn        = sasl_external_step,
	.finish_fn      = NULL,
	.password_based = false,
};

/* ---- hook: announce ourselves to the SASL core on mechanism lookup ------ */

static void
h_sasl_external_start(void *vdata)
{
	struct sasl_hook_data *hdata = vdata;

	if(irccmp(hdata->name, sasl_external_mech.name) != 0)
		return;

	hdata->mech = &sasl_external_mech;
}

/* ---- module wiring ------------------------------------------------------- */

mapi_hfn_list_av1 sasl_external_hfnlist[] = {
	{ "sasl_start", h_sasl_external_start },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(sasl_external, NULL, NULL, NULL, NULL,
		sasl_external_hfnlist, NULL, NULL, sasl_external_desc);
