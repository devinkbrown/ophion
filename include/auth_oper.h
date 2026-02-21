/*
 * include/auth_oper.h -- shared oper authentication helpers
 *
 * Centralises the credential-checking logic so that SASL mechanisms
 * (sasl_plain, sasl_external) and the legacy CHALLENGE command can all call
 * the same primitives without duplicating code.
 *
 * How it fits together
 * --------------------
 *
 *  ┌──────────────────┐  ┌───────────────────┐  ┌─────────────────┐
 *  │  sasl_plain.c    │  │  sasl_external.c  │  │  m_challenge.c  │
 *  │  (SASL PLAIN)    │  │  (SASL EXTERNAL)  │  │  (CHALLENGE cmd)│
 *  └────────┬─────────┘  └────────┬──────────┘  └───────┬─────────┘
 *           │                     │                      │
 *           └─────────────────────┼──────────────────────┘
 *                                 │ all call
 *                       ┌─────────▼──────────┐
 *                       │    auth_oper.c     │
 *                       │  oper_check_*()    │
 *                       │  oper_find_*()     │
 *                       │  oper_log_*()      │
 *                       └────────────────────┘
 *
 * SASL path (pre-registration) — primary oper authentication method
 * -----------------------------------------------------------------
 * 1. Client negotiates  CAP REQ :sasl  and sends:
 *      AUTHENTICATE PLAIN  /  AUTHENTICATE EXTERNAL
 *    OR the IRCX equivalent:
 *      AUTH PLAIN I :<base64data>  /  AUTH EXTERNAL I
 * 2. The mechanism verifies credentials via auth_oper helpers.
 * 3. On success the mechanism stores the matched oper_conf pointer in
 *    client_p->localClient->pending_oper.
 * 4. register_local_user() (ircd/s_user.c) detects pending_oper after the
 *    user is fully registered and calls oper_up() automatically.
 *
 * OPER command (deprecated / stubbed)
 * ------------------------------------
 * The OPER command no longer performs authentication.  Its handler sends
 * a notice directing the user to SASL (AUTHENTICATE or AUTH).
 */

#ifndef OPHION_AUTH_OPER_H
#define OPHION_AUTH_OPER_H

#include "stdinc.h"
#include "client.h"
#include "s_newconf.h"

/*
 * oper_check_password
 *
 * Verify a plaintext password against the credential stored in oper_p.
 * Handles both plaintext and crypt(3)-encrypted passwords (OPER_ENCRYPTED).
 * Returns true on success, false on failure.
 */
bool oper_check_password(const char *password, struct oper_conf *oper_p);

/*
 * oper_check_certfp
 *
 * Compare client_p's TLS certificate fingerprint against the fingerprint
 * configured in oper_p->certfp.  The comparison is case-insensitive.
 *
 * Returns true when oper_p->certfp is non-NULL and matches client_p->certfp.
 * Returns false if either fingerprint is NULL or if they differ.
 */
bool oper_check_certfp(struct Client *client_p, struct oper_conf *oper_p);

/*
 * oper_find_by_name
 *
 * Walk oper_conf_list and return the first block whose name matches `name`
 * (case-insensitive).  Returns NULL when no block is found.
 *
 * Used by SASL PLAIN: the caller supplies the authentication identity
 * (oper block name) from the PLAIN payload and then validates credentials
 * with oper_check_password() or oper_check_certfp() separately.
 *
 * Note: unlike find_oper_conf() this function does *not* perform
 * username/host matching, since during SASL the client is not yet fully
 * registered.  Host matching is enforced at oper-up time if desired.
 */
struct oper_conf *oper_find_by_name(const char *name);

/*
 * oper_find_certfp_only
 *
 * Walk oper_conf_list and return the first block that has OPER_CERTFP_ONLY
 * set and whose name matches `name` (case-insensitive).  Returns NULL when
 * no matching block is found.
 *
 * Used by SASL EXTERNAL when the client supplies an explicit authzid (oper
 * block name).  The caller then validates the TLS fingerprint with
 * oper_check_certfp().
 */
struct oper_conf *oper_find_certfp_only(const char *name);

/*
 * oper_find_certfp_match
 *
 * Scan every OPER_CERTFP_ONLY block and return the first one whose
 * configured fingerprint matches client_p's TLS certificate fingerprint.
 * Returns NULL when no block matches or when client_p carries no certificate.
 *
 * Used by SASL EXTERNAL when the client sends an empty authzid — the server
 * auto-discovers which certfp_only block the certificate belongs to.
 */
struct oper_conf *oper_find_certfp_match(struct Client *client_p);

/*
 * oper_log_success
 *
 * Emit a L_OPERED audit log entry for a successful oper-up.
 * `method` identifies the authentication path: "SASL PLAIN", "SASL EXTERNAL",
 * "CHALLENGE", etc.
 *
 * Called by register_local_user() (SASL paths) and the CHALLENGE handler.
 */
void oper_log_success(struct Client *client_p, struct oper_conf *oper_p,
                      const char *method);

/*
 * oper_log_failure
 *
 * Emit a L_FOPER audit log entry for a failed oper authentication attempt
 * and, when failed_oper_notice is enabled, broadcast a SNO_GENERAL notice
 * to IRC operators.
 *
 * `oper_name` is the block name the client tried — pass "*" when unknown.
 * `reason` is a short human-readable string describing why authentication
 * failed (e.g. "password mismatch", "certfp mismatch", "no oper block").
 * `method` is the same short tag as for oper_log_success.
 */
void oper_log_failure(struct Client *client_p, const char *oper_name,
                      const char *reason, const char *method);

#endif /* OPHION_AUTH_OPER_H */
