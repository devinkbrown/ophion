/*
 * include/auth_oper.h -- shared oper authentication helpers
 *
 * Centralises the credential-checking logic so that m_oper, m_challenge,
 * and SASL mechanisms (sasl_plain, sasl_external) can all call the same
 * primitives without duplicating code.
 *
 * How it fits together
 * --------------------
 *
 *  ┌─────────────┐  ┌──────────────────┐  ┌───────────────────┐
 *  │  m_oper.c   │  │  sasl_plain.c    │  │  sasl_external.c  │
 *  │  (OPER cmd) │  │  (SASL PLAIN)    │  │  (SASL EXTERNAL)  │
 *  └──────┬──────┘  └────────┬─────────┘  └────────┬──────────┘
 *         │                  │                      │
 *         └──────────────────┼──────────────────────┘
 *                            │ all call
 *                  ┌─────────▼──────────┐
 *                  │    auth_oper.c     │
 *                  │  oper_check_*()    │
 *                  │  oper_find_*()     │
 *                  └────────────────────┘
 *
 * SASL path (pre-registration)
 * ----------------------------
 * 1. Client sends  AUTHENTICATE PLAIN  or  AUTHENTICATE EXTERNAL.
 * 2. The mechanism verifies credentials via auth_oper helpers.
 * 3. On success the mechanism stores the matched oper_conf pointer in
 *    client_p->localClient->pending_oper.
 * 4. register_local_user() (ircd/s_user.c) detects pending_oper after the
 *    user is fully registered and calls oper_up() automatically.
 *
 * Traditional OPER path (post-registration)
 * ------------------------------------------
 * 1. Client sends  OPER name password.
 * 2. m_oper.c calls find_oper_conf() then oper_check_certfp() /
 *    oper_check_password() directly, then calls oper_up().
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
 * Used by SASL EXTERNAL: the caller supplies the desired oper block name
 * (authzid) and then validates the TLS fingerprint with oper_check_certfp().
 *
 * When `name` is NULL or an empty string every certfp_only block is tried
 * and the first one whose certfp matches the client is returned directly
 * by the SASL EXTERNAL mechanism itself.
 */
struct oper_conf *oper_find_certfp_only(const char *name);

#endif /* OPHION_AUTH_OPER_H */
