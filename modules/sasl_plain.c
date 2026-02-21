/*
 * modules/sasl_plain.c -- SASL PLAIN mechanism for oper pre-authentication
 *
 * Allows a client to authenticate as an IRC operator during connection
 * registration using SASL PLAIN, before sending the OPER command.  On
 * success the client's pending_oper pointer is set; register_local_user()
 * calls oper_up() automatically once registration completes.
 *
 * Protocol exchange
 * -----------------
 *   Client: AUTHENTICATE PLAIN
 *   Server: AUTHENTICATE +               (no server challenge for PLAIN)
 *   Client: AUTHENTICATE <base64([authzid \0] authcid \0 password)>
 *   Server: 900 (RPL_LOGGEDIN) + 903 (RPL_SASLSUCCESS)  on success
 *           908 (ERR_SASLFAIL)                           on failure
 *
 * Field mapping
 * -------------
 *   authcid   — the oper block name (authentication identity)
 *   authzid   — optional; if non-empty must equal authcid (authorization id)
 *   password  — the oper block password (plaintext or pre-hashed by client)
 *
 * Example (netcat / ircd):
 *   CAP REQ :sasl
 *   NICK alice
 *   USER alice 0 * :Alice
 *   AUTHENTICATE PLAIN
 *   AUTHENTICATE <base64(\0godoper\0s3cret)>
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

static const char sasl_plain_desc[] =
	"SASL PLAIN mechanism — authenticates an oper block during registration";

/* ---- mechanism callbacks ----------------------------------------------- */

static enum sasl_mechanism_result
sasl_plain_start(struct sasl_session *sess, struct sasl_output_buf *outbuf)
{
	/* PLAIN needs no server challenge; tell the core to send AUTHENTICATE + */
	outbuf->buf = NULL;
	outbuf->len = 0;
	return SASL_MRESULT_CONTINUE;
}

static enum sasl_mechanism_result
sasl_plain_step(struct sasl_session *sess,
		const struct sasl_input_buf *inbuf,
		struct sasl_output_buf *outbuf)
{
	outbuf->buf = NULL;
	outbuf->len = 0;

	if(inbuf->buf == NULL || inbuf->len == 0)
		return SASL_MRESULT_FAILURE;

	/* PLAIN wire format:  [authzid NUL] authcid NUL passwd
	 * All three fields are packed in a single binary blob; the password
	 * is NOT null-terminated — it runs to the end of the buffer.
	 */
	const uint8_t *buf = (const uint8_t *)inbuf->buf;
	size_t rem = inbuf->len;

	/* locate first NUL → end of authzid (may be zero-length) */
	const uint8_t *nul = memchr(buf, '\0', rem);
	if(nul == NULL)
		return SASL_MRESULT_FAILURE;

	size_t authzid_len = (size_t)(nul - buf);
	char authzid[NICKLEN + 1] = { 0 };
	if(authzid_len > NICKLEN)
		return SASL_MRESULT_FAILURE;
	if(authzid_len)
		memcpy(authzid, buf, authzid_len);

	buf = nul + 1;
	rem -= authzid_len + 1;

	/* locate second NUL → end of authcid */
	nul = memchr(buf, '\0', rem);
	if(nul == NULL)
		return SASL_MRESULT_FAILURE;

	size_t authcid_len = (size_t)(nul - buf);
	char authcid[NICKLEN + 1] = { 0 };
	if(authcid_len == 0 || authcid_len > NICKLEN)
		return SASL_MRESULT_FAILURE;
	memcpy(authcid, buf, authcid_len);

	buf = nul + 1;
	rem -= authcid_len + 1;

	/* remainder is the password (not NUL-terminated in the stream) */
	if(rem == 0 || rem >= BUFSIZE)
		return SASL_MRESULT_FAILURE;
	char passwd[BUFSIZE] = { 0 };
	memcpy(passwd, buf, rem);

	/* authzid, if provided, must match authcid (same oper block) */
	if(*authzid && irccmp(authzid, authcid) != 0)
		return SASL_MRESULT_FAILURE;

	/* oper block lookup (by name only; host matching deferred to oper_up) */
	struct oper_conf *oper_p = oper_find_by_name(authcid);
	if(oper_p == NULL)
		return SASL_MRESULT_FAILURE;

	/* password verification */
	if(!oper_check_password(passwd, oper_p))
		return SASL_MRESULT_FAILURE;

	/* if the block also has a certfp requirement, verify it now */
	if(oper_p->certfp != NULL && !oper_check_certfp(sess->client, oper_p))
		return SASL_MRESULT_FAILURE;

	/* success: record authzid and stash the oper block for post-registration */
	rb_strlcpy(sess->authzid, authcid, sizeof(sess->authzid));
	sess->client->localClient->pending_oper = oper_p;

	return SASL_MRESULT_SUCCESS;
}

/* ---- mechanism descriptor ---------------------------------------------- */

static struct sasl_mechanism sasl_plain_mech = {
	.name           = "PLAIN",
	.start_fn       = sasl_plain_start,
	.step_fn        = sasl_plain_step,
	.finish_fn      = NULL,
	.password_based = true,
};

/* ---- hook: announce ourselves to the SASL core on mechanism lookup ------ */

static void
h_sasl_plain_start(void *vdata)
{
	struct sasl_hook_data *hdata = vdata;

	if(irccmp(hdata->name, sasl_plain_mech.name) != 0)
		return;

	hdata->mech = &sasl_plain_mech;
}

/* ---- module wiring ------------------------------------------------------- */

mapi_hfn_list_av1 sasl_plain_hfnlist[] = {
	{ "sasl_start", h_sasl_plain_start },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(sasl_plain, NULL, NULL, NULL, NULL,
		sasl_plain_hfnlist, NULL, NULL, sasl_plain_desc);
