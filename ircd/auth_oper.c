/*
 * ircd/auth_oper.c -- shared oper authentication primitives
 *
 * Provides the credential-checking, block-discovery, and audit-logging
 * functions declared in include/auth_oper.h.  All oper authentication paths
 * (SASL PLAIN, SASL EXTERNAL, CHALLENGE) call into this module so that the
 * logic and log format live in one place.
 */

#include "stdinc.h"
#include "client.h"
#include "match.h"
#include "s_newconf.h"
#include "logger.h"
#include "send.h"
#include "s_conf.h"
#include "snomask.h"
#include "auth_oper.h"

/* ---- credential checks -------------------------------------------------- */

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

/* ---- block discovery ---------------------------------------------------- */

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
 * If name is NULL or empty, returns the first certfp_only block regardless of
 * name; for auto-discovery by certificate use oper_find_certfp_match() instead.
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

/*
 * oper_find_certfp_match
 *
 * Scan every certfp_only block and return the first whose configured
 * fingerprint matches client_p's TLS certificate fingerprint.  Used by
 * SASL EXTERNAL when the client sends an empty authzid.
 */
struct oper_conf *
oper_find_certfp_match(struct Client *client_p)
{
	struct oper_conf *oper_p;
	rb_dlink_node *ptr;

	if(client_p->certfp == NULL)
		return NULL;

	RB_DLINK_FOREACH(ptr, oper_conf_list.head)
	{
		oper_p = ptr->data;
		if(!IsOperConfCertFPOnly(oper_p))
			continue;
		if(oper_check_certfp(client_p, oper_p))
			return oper_p;
	}

	return NULL;
}

/* ---- audit logging ------------------------------------------------------ */

/*
 * oper_log_success
 *
 * Emit an L_OPERED log entry for a successful oper-up.  The log line uses
 * the same format as the traditional OPER / CHALLENGE commands so that all
 * authentication paths produce a uniform audit trail.
 */
void
oper_log_success(struct Client *client_p, struct oper_conf *oper_p,
                 const char *method)
{
	ilog(L_OPERED, "%s %s by %s!%s@%s (%s)",
	     method, oper_p->name,
	     client_p->name, client_p->username,
	     client_p->host, client_p->sockhost);
}

/*
 * oper_log_failure
 *
 * Emit an L_FOPER log entry and, when failed_oper_notice is enabled,
 * broadcast a SNO_GENERAL snomask notice for a failed oper authentication
 * attempt.  `oper_name` is the block name the client tried ("*" if unknown).
 */
void
oper_log_failure(struct Client *client_p, const char *oper_name,
                 const char *reason, const char *method)
{
	const char *nick = EmptyString(client_p->name) ? "*" : client_p->name;
	const char *user = EmptyString(client_p->username) ? "*" : client_p->username;
	const char *name = EmptyString(oper_name) ? "*" : oper_name;

	ilog(L_FOPER, "FAILED %s (%s) by (%s!%s@%s) (%s) -- %s",
	     method, name, nick, user, client_p->host,
	     client_p->sockhost, reason);

	if(ConfigFileEntry.failed_oper_notice)
		sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			"Failed %s attempt - %s for %s by %s (%s@%s)",
			method, reason, name, nick, user, client_p->host);
}
