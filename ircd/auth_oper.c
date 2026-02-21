/*
 * ircd/auth_oper.c -- shared oper authentication primitives
 *
 * Provides the credential-checking functions declared in include/auth_oper.h.
 * All oper authentication paths (OPER command, CHALLENGE, SASL PLAIN,
 * SASL EXTERNAL) call into this module so that the logic lives in one place.
 */

#include "stdinc.h"
#include "client.h"
#include "match.h"
#include "s_newconf.h"
#include "auth_oper.h"

/*
 * oper_check_password
 *
 * Verify a plaintext password against oper_p->passwd.  When OPER_ENCRYPTED
 * is set the stored value is a crypt(3) hash; we hash the supplied password
 * with the same salt before comparing.
 */
bool
oper_check_password(const char *password, struct oper_conf *oper_p)
{
	const char *encr;

	if(EmptyString(oper_p->passwd))
		return false;

	if(IsOperConfEncrypted(oper_p))
	{
		if(!EmptyString(password))
			encr = rb_crypt(password, oper_p->passwd);
		else
			encr = "";
	}
	else
		encr = password;

	return (encr != NULL && strcmp(encr, oper_p->passwd) == 0);
}

/*
 * oper_check_certfp
 *
 * Return true when oper_p has a configured fingerprint and it matches the
 * fingerprint extracted from client_p's TLS certificate (case-insensitive).
 */
bool
oper_check_certfp(struct Client *client_p, struct oper_conf *oper_p)
{
	if(oper_p->certfp == NULL || client_p->certfp == NULL)
		return false;

	return rb_strcasecmp(oper_p->certfp, client_p->certfp) == 0;
}

/*
 * oper_find_by_name
 *
 * Walk oper_conf_list and return the first block whose name matches `name`.
 * Does not perform username/host matching (host check happens post-
 * registration via find_oper_conf when using the traditional OPER command;
 * SASL paths skip it because the client is not yet fully registered).
 */
struct oper_conf *
oper_find_by_name(const char *name)
{
	struct oper_conf *oper_p;
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, oper_conf_list.head)
	{
		oper_p = ptr->data;
		if(!irccmp(oper_p->name, name))
			return oper_p;
	}

	return NULL;
}

/*
 * oper_find_certfp_only
 *
 * Return the first oper block that has OPER_CERTFP_ONLY set and whose name
 * matches `name`.  Used by SASL EXTERNAL to locate the block before verifying
 * the certificate fingerprint.
 *
 * If name is NULL or empty every certfp_only block is a candidate; the SASL
 * EXTERNAL mechanism iterates them itself via oper_conf_list in that case.
 */
struct oper_conf *
oper_find_certfp_only(const char *name)
{
	struct oper_conf *oper_p;
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, oper_conf_list.head)
	{
		oper_p = ptr->data;
		if(!IsOperConfCertFPOnly(oper_p))
			continue;
		if(EmptyString(name) || !irccmp(oper_p->name, name))
			return oper_p;
	}

	return NULL;
}
