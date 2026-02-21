/*
 * ircd/services_core.c — Core services infrastructure
 *
 * Initialises the Ophion built-in services layer: creates the in-memory
 * radixtrees, opens the SQLite database, registers S2S sync, and installs
 * the channel JOIN hook that enforces access lists, AKICKs, mode-locks and
 * topic restoration.
 *
 * Also provides:
 *   - SASL authentication helpers (password and certfp)
 *   - Account / channel-registration lookup and allocation helpers
 *   - Hub/leaf state-machine transitions
 *   - svc_notice() reply helper
 *   - svc_memo_deliver_notice()
 *
 * The actual NickServ / ChanServ / MemoServ / HostServ / OperServ command
 * dispatch functions (nickserv_dispatch, chanserv_dispatch, etc.) are defined
 * in their respective source files (ircd/nickserv.c, ircd/chanserv.c, …) and
 * are merely declared extern via include/services.h.
 *
 * Copyright (c) 2026 Ophion development team.  GPL v2.
 */

#include "stdinc.h"
#include "hash.h"
#include "s_conf.h"
#include "ircd.h"
#include "logger.h"
#include "match.h"
#include "client.h"
#include "channel.h"
#include "hook.h"
#include "send.h"
#include "s_newconf.h"
#include "services.h"
#include "services_db.h"
#include "services_sync.h"
#include "auth_oper.h"

/* -------------------------------------------------------------------------
 * Global state
 * ---------------------------------------------------------------------- */

struct services_state services = {
	.enabled            = false,
	.mode               = SVCS_MODE_STANDALONE,
	.is_hub             = false,
	.hub_server         = NULL,
	.split_start        = 0,
	.dirty_count        = 0,
	.db_path            = "/var/lib/ophion/services.db",
	.nick_expire_days   = 30,
	.chan_expire_days   = 60,
	.enforce_delay_secs = 30,
	.maxnicks           = 10,
	.maxmemos           = 20,
	.registration_open  = true,
};

rb_radixtree *svc_account_dict = NULL;  /* name  → struct svc_account *  */
rb_radixtree *svc_nick_dict    = NULL;  /* nick  → struct svc_nick *      */
rb_radixtree *svc_chanreg_dict = NULL;  /* chan  → struct svc_chanreg *   */

/* -------------------------------------------------------------------------
 * Forward declarations of file-private functions
 * ---------------------------------------------------------------------- */

/* can_join fires BEFORE the client is admitted; hook_data_channel */
static void h_services_can_join(hook_data_channel *hdata);
/* channel_join fires AFTER the client is added; hook_data_channel_activity */
static void h_services_post_join(hook_data_channel_activity *hdata);

/* -------------------------------------------------------------------------
 * Lifecycle: init / shutdown / rehash
 * ---------------------------------------------------------------------- */

void
services_init(void)
{
	if(!services.enabled)
		return;

	/*
	 * Create in-memory index trees.  All keys are IRC-casefolded so that
	 * lookups are case-insensitive, matching the COLLATE NOCASE columns in
	 * the database schema.
	 */
	svc_account_dict = rb_radixtree_create("svc_accounts", irccasecanon);
	svc_nick_dict    = rb_radixtree_create("svc_nicks",    irccasecanon);
	svc_chanreg_dict = rb_radixtree_create("svc_chanregs", irccasecanon);

	if(!svc_db_init(services.db_path))
	{
		ilog(L_MAIN, "services: FATAL: could not open database '%s'",
		     services.db_path);
		/* Allow ircd to continue; services commands will fail gracefully */
		return;
	}

	svc_sync_init();

	/*
	 * Install channel hooks:
	 *   can_join    — access control and founder key bypass (pre-join)
	 *   channel_join — auto-mode grants (post-join)
	 */
	add_hook("can_join",     (hookfn)h_services_can_join);
	add_hook("channel_join", (hookfn)h_services_post_join);

	ilog(L_MAIN, "services: initialised (mode: %s, db: %s)",
	     services_mode_name(services.mode), services.db_path);
}

void
services_shutdown(void)
{
	if(!services.enabled)
		return;

	remove_hook("can_join",     (hookfn)h_services_can_join);
	remove_hook("channel_join", (hookfn)h_services_post_join);

	svc_sync_shutdown();
	svc_db_shutdown();

	/* Free all channel registrations */
	if(svc_chanreg_dict != NULL)
	{
		rb_radixtree_iteration_state state;
		struct svc_chanreg *reg;
		RB_RADIXTREE_FOREACH(reg, &state, svc_chanreg_dict)
		{
			rb_radixtree_delete(svc_chanreg_dict, reg->channel);
			svc_chanreg_free(reg);
		}
		/* radixtree is now empty but not destroyed — that's fine on
		 * shutdown; the process is about to exit anyway */
	}

	/* Free all accounts (also cleans up svc_nick_dict entries) */
	if(svc_account_dict != NULL)
	{
		rb_radixtree_iteration_state state;
		struct svc_account *acct;
		RB_RADIXTREE_FOREACH(acct, &state, svc_account_dict)
		{
			/* Remove grouped nicks from nick dict first */
			rb_dlink_node *ptr, *nptr;
			RB_DLINK_FOREACH_SAFE(ptr, nptr, acct->nicks.head)
			{
				struct svc_nick *sn = ptr->data;
				rb_radixtree_delete(svc_nick_dict, sn->nick);
			}
			rb_radixtree_delete(svc_account_dict, acct->name);
			svc_account_free(acct);
		}
	}

	ilog(L_MAIN, "services: shut down");
}

void
services_rehash(void)
{
	if(!services.enabled)
		return;

	/* Close and re-open the database; the in-memory trees stay intact
	 * since only the DB handle changes during a simple rehash. */
	svc_db_shutdown();

	if(!svc_db_init(services.db_path))
		ilog(L_MAIN, "services: rehash: could not reopen database '%s'",
		     services.db_path);
	else
		ilog(L_MAIN, "services: rehash complete");
}

/* -------------------------------------------------------------------------
 * Hub / leaf state machine
 * ---------------------------------------------------------------------- */

void
services_enter_hub_mode(void)
{
	services.mode       = SVCS_MODE_HUB;
	services.is_hub     = true;
	services.hub_server = NULL;
	ilog(L_MAIN, "services: entered HUB mode (authoritative DB)");
}

void
services_enter_connected_mode(struct Client *hub_p)
{
	services.mode       = SVCS_MODE_CONNECTED;
	services.is_hub     = false;
	services.hub_server = hub_p;
	ilog(L_MAIN, "services: entered CONNECTED mode (hub: %s)",
	     hub_p ? hub_p->name : "<unknown>");

	/*
	 * Flush any records dirtied during the split back to the hub now
	 * that we are reconnected.  svc_db_flush_dirty() returns the number
	 * of records written; log it so operators can monitor reconciliation.
	 */
	int flushed = svc_db_flush_dirty();
	if(flushed > 0)
		ilog(L_MAIN,
		     "services: flushed %d dirty record(s) to hub after split",
		     flushed);
}

void
services_enter_split_mode(void)
{
	services.mode        = SVCS_MODE_SPLIT;
	services.split_start = rb_current_time();
	services.hub_server  = NULL;
	ilog(L_MAIN,
	     "services: WARNING: hub link lost — entering SPLIT mode; "
	     "local writes will be marked dirty for later reconciliation");
}

void
services_enter_standalone_mode(void)
{
	services.mode       = SVCS_MODE_STANDALONE;
	services.is_hub     = true;
	services.hub_server = NULL;
	ilog(L_MAIN, "services: entered STANDALONE mode");
}

const char *
services_mode_name(svcs_mode_t m)
{
	switch(m)
	{
	case SVCS_MODE_HUB:        return "HUB";
	case SVCS_MODE_CONNECTED:  return "CONNECTED";
	case SVCS_MODE_SPLIT:      return "SPLIT";
	case SVCS_MODE_STANDALONE: return "STANDALONE";
	default:                   return "UNKNOWN";
	}
}

/* -------------------------------------------------------------------------
 * Account lookup helpers
 * ---------------------------------------------------------------------- */

struct svc_account *
svc_account_find(const char *name)
{
	if(svc_account_dict == NULL || name == NULL)
		return NULL;
	return rb_radixtree_retrieve(svc_account_dict, name);
}

struct svc_account *
svc_account_find_nick(const char *nick)
{
	if(svc_nick_dict == NULL || nick == NULL)
		return NULL;

	struct svc_nick *sn = rb_radixtree_retrieve(svc_nick_dict, nick);
	if(sn == NULL)
		return NULL;

	return rb_radixtree_retrieve(svc_account_dict, sn->account);
}

/*
 * svc_account_find_certfp — linear scan over all accounts looking for a
 * matching certificate fingerprint.  Case-insensitive comparison.
 *
 * This is O(n*m) where n = accounts and m = certfps per account.  Given that
 * the total number of certfps across all accounts is expected to be small
 * (< few thousand), this is acceptable.  A secondary hash could be added if
 * profiling shows it is a bottleneck.
 */

struct certfp_search {
	const char *certfp;
	struct svc_account *result;
};

static int
certfp_search_cb(const char *key, void *data, void *privdata)
{
	(void)key;
	struct svc_account *acct = data;
	struct certfp_search *s  = privdata;

	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, acct->certfps.head)
	{
		struct svc_certfp *scf = ptr->data;
		if(rb_strcasecmp(scf->fingerprint, s->certfp) == 0)
		{
			s->result = acct;
			return 1; /* non-zero stops iteration */
		}
	}
	return 0;
}

struct svc_account *
svc_account_find_certfp(const char *certfp)
{
	if(svc_account_dict == NULL || certfp == NULL)
		return NULL;

	struct certfp_search s = { .certfp = certfp, .result = NULL };
	rb_radixtree_foreach(svc_account_dict, certfp_search_cb, &s);
	return s.result;
}

/*
 * svc_account_create — allocate a new account, insert into the in-memory
 * index, and persist it to the database.  Returns NULL on failure.
 */
struct svc_account *
svc_account_create(const char *name, const char *passhash, const char *email)
{
	if(name == NULL || *name == '\0')
		return NULL;

	/* Refuse to create a duplicate */
	if(svc_account_find(name) != NULL)
		return NULL;

	struct svc_account *acct = rb_malloc(sizeof *acct);
	memset(acct, 0, sizeof *acct);

	rb_strlcpy(acct->name, name, sizeof acct->name);
	if(passhash && *passhash)
		rb_strlcpy(acct->passhash, passhash, sizeof acct->passhash);
	if(email && *email)
		rb_strlcpy(acct->email, email, sizeof acct->email);
	acct->registered_ts = rb_current_time();
	rb_strlcpy(acct->language, "en", sizeof acct->language);
	acct->dirty = false;

	rb_radixtree_add(svc_account_dict, acct->name, acct);

	if(!svc_db_account_save(acct))
	{
		rb_radixtree_delete(svc_account_dict, acct->name);
		rb_free(acct);
		return NULL;
	}

	return acct;
}

/*
 * svc_account_free — free all sub-lists and the account struct itself.
 * Does NOT remove the account from svc_account_dict; callers that want
 * removal should call rb_radixtree_delete() before or after this.
 */
void
svc_account_free(struct svc_account *acct)
{
	if(acct == NULL)
		return;

	rb_dlink_node *ptr, *nptr;

	RB_DLINK_FOREACH_SAFE(ptr, nptr, acct->nicks.head)
	{
		struct svc_nick *sn = ptr->data;
		rb_dlinkDestroy(ptr, &acct->nicks);
		rb_free(sn);
	}

	RB_DLINK_FOREACH_SAFE(ptr, nptr, acct->certfps.head)
	{
		struct svc_certfp *scf = ptr->data;
		rb_dlinkDestroy(ptr, &acct->certfps);
		rb_free(scf);
	}

	RB_DLINK_FOREACH_SAFE(ptr, nptr, acct->access_masks.head)
	{
		struct svc_accessmask *sam = ptr->data;
		rb_dlinkDestroy(ptr, &acct->access_masks);
		rb_free(sam);
	}

	RB_DLINK_FOREACH_SAFE(ptr, nptr, acct->metadata.head)
	{
		struct svc_metadata *sm = ptr->data;
		rb_dlinkDestroy(ptr, &acct->metadata);
		rb_free(sm);
	}

	rb_free(acct);
}

/* -------------------------------------------------------------------------
 * Channel registration lookup helpers
 * ---------------------------------------------------------------------- */

struct svc_chanreg *
svc_chanreg_find(const char *channel)
{
	if(svc_chanreg_dict == NULL || channel == NULL)
		return NULL;
	return rb_radixtree_retrieve(svc_chanreg_dict, channel);
}

struct svc_chanreg *
svc_chanreg_create(const char *channel, const char *founder_name)
{
	if(channel == NULL || *channel == '\0' || founder_name == NULL)
		return NULL;

	if(svc_chanreg_find(channel) != NULL)
		return NULL;

	struct svc_chanreg *reg = rb_malloc(sizeof *reg);
	memset(reg, 0, sizeof *reg);

	rb_strlcpy(reg->channel, channel,      sizeof reg->channel);
	rb_strlcpy(reg->founder, founder_name, sizeof reg->founder);
	reg->registered_ts = rb_current_time();
	reg->dirty         = false;

	rb_radixtree_add(svc_chanreg_dict, reg->channel, reg);

	if(!svc_db_chanreg_save(reg))
	{
		rb_radixtree_delete(svc_chanreg_dict, reg->channel);
		rb_free(reg);
		return NULL;
	}

	return reg;
}

void
svc_chanreg_free(struct svc_chanreg *reg)
{
	if(reg == NULL)
		return;

	rb_dlink_node *ptr, *nptr;
	RB_DLINK_FOREACH_SAFE(ptr, nptr, reg->access.head)
	{
		struct svc_chanaccess *ca = ptr->data;
		rb_dlinkDestroy(ptr, &reg->access);
		rb_free(ca);
	}

	rb_free(reg);
}

/* -------------------------------------------------------------------------
 * SASL / account authentication
 * ---------------------------------------------------------------------- */

/*
 * svc_authenticate_password — verify PLAIN credentials.
 *
 * Returns true when:
 *   - account exists
 *   - account has a non-empty passhash (cert-only accounts are rejected)
 *   - account is not suspended
 *   - crypt(3) comparison of password against passhash succeeds
 *
 * On success populates *out and, if the account links to an oper block,
 * *oper_out.
 */
bool
svc_authenticate_password(const char *account_name, const char *password,
                          struct svc_account **out,
                          struct oper_conf **oper_out)
{
	if(out != NULL)
		*out = NULL;
	if(oper_out != NULL)
		*oper_out = NULL;

	if(account_name == NULL || password == NULL)
		return false;

	struct svc_account *acct = svc_account_find(account_name);
	if(acct == NULL)
		return false;

	/* Cert-only accounts have an empty passhash */
	if(acct->passhash[0] == '\0')
		return false;

	/* Suspended accounts are not allowed to authenticate */
	if(acct->flags & ACCT_SUSPENDED)
		return false;

	/*
	 * Verify using crypt(3).  The stored passhash starts with $6$ for
	 * sha512crypt (or $5$ for sha256crypt, etc.); crypt() auto-detects
	 * the algorithm from the stored hash prefix.
	 *
	 * For ACCT_SASLONLY accounts we still verify the password here; the
	 * SASLONLY flag merely prevents NS IDENTIFY (handled in nickserv.c).
	 */
	const char *computed = rb_crypt(password, acct->passhash);
	if(computed == NULL || strcmp(computed, acct->passhash) != 0)
		return false;

	if(out != NULL)
		*out = acct;

	if(oper_out != NULL && acct->oper_block[0] != '\0')
		*oper_out = oper_find_by_name(acct->oper_block);

	return true;
}

/*
 * svc_authenticate_certfp — verify EXTERNAL (TLS certfp) credentials.
 *
 * If account_hint is non-empty, look up that specific account and check
 * whether certfp appears in its certfp list.  Otherwise perform a
 * network-wide scan via svc_account_find_certfp().
 *
 * Also handles the case where no account matches but the certfp belongs to
 * a certfp-only oper block: in that case *out is left NULL but *oper_out is
 * set, allowing the SASL mechanism to grant oper status without an account.
 */
bool
svc_authenticate_certfp(const char *certfp, const char *account_hint,
                        struct svc_account **out,
                        struct oper_conf **oper_out)
{
	if(out != NULL)
		*out = NULL;
	if(oper_out != NULL)
		*oper_out = NULL;

	if(certfp == NULL)
		return false;

	struct svc_account *acct = NULL;

	if(account_hint != NULL && *account_hint != '\0')
	{
		/* Caller supplied an explicit account name (SASL authzid) */
		acct = svc_account_find(account_hint);
		if(acct == NULL)
		{
			/*
			 * No account matches the hint.  Try oper blocks in case
			 * the authzid is an oper block name, not an account name.
			 */
			goto try_oper;
		}

		/* Verify certfp is listed on this account */
		bool found = false;
		rb_dlink_node *ptr;
		RB_DLINK_FOREACH(ptr, acct->certfps.head)
		{
			struct svc_certfp *scf = ptr->data;
			if(rb_strcasecmp(scf->fingerprint, certfp) == 0)
			{
				found = true;
				break;
			}
		}
		if(!found)
			acct = NULL;
	}
	else
	{
		/* Auto-discover by scanning all accounts */
		acct = svc_account_find_certfp(certfp);
	}

	if(acct != NULL)
	{
		if(acct->flags & ACCT_SUSPENDED)
			return false;

		if(out != NULL)
			*out = acct;

		if(oper_out != NULL && acct->oper_block[0] != '\0')
			*oper_out = oper_find_by_name(acct->oper_block);

		return true;
	}

try_oper:
	/*
	 * No account matched.  Check whether a certfp-only oper block claims
	 * this fingerprint.  We cannot call oper_find_certfp_match() here
	 * because that requires a struct Client* with a certfp field.  Instead
	 * we walk oper_conf_list looking for CERTFP_ONLY blocks whose certfp
	 * matches the supplied fingerprint string.
	 */
	if(oper_out != NULL)
	{
		rb_dlink_node *ptr;
		RB_DLINK_FOREACH(ptr, oper_conf_list.head)
		{
			struct oper_conf *oper_p = ptr->data;
			if(!IsOperConfCertFPOnly(oper_p))
				continue;
			if(oper_p->certfp == NULL)
				continue;
			if(rb_strcasecmp(oper_p->certfp, certfp) == 0)
			{
				*oper_out = oper_p;
				/* *out remains NULL — no account association */
				return true;
			}
		}
	}

	return false;
}

/* -------------------------------------------------------------------------
 * Channel JOIN hook — access enforcement, AKICK, MODELOCK, KEEPTOPIC
 * ---------------------------------------------------------------------- */

/*
 * match_entity — return true if the account's suser or the user@host mask
 * matches the access-list entity string.
 *
 * entity may be:
 *   - an account name (plain alphanumeric string without @)
 *   - a user@host glob mask
 */
static bool
match_entity(struct Client *client_p, const char *entity)
{
	if(entity == NULL || *entity == '\0')
		return false;

	/* If entity contains '@' treat it as a user@host glob */
	if(strchr(entity, '@') != NULL)
	{
		char uhost[USERLEN + HOSTLEN + 2];
		snprintf(uhost, sizeof uhost, "%s@%s",
		         client_p->username, client_p->host);
		return (match(entity, uhost) != 0);
	}

	/* Otherwise it is an account name: compare against suser */
	if(client_p->user == NULL)
		return false;
	return (rb_strcasecmp(entity, client_p->user->suser) == 0);
}

/*
 * h_services_can_join — "can_join" hook (hook_data_channel).
 *
 * Fires BEFORE the join is committed.  Handles:
 *
 *   1. Founder key bypass — when a channel has a +k key that the founder
 *      doesn't know (someone changed it), we still let the identified founder
 *      in.  This prevents founders from being permanently locked out.
 *
 *   2. AKICK enforcement — veto the join for auto-kicked entities.
 *
 * Auto-mode granting (CA_OP → +o etc.) is handled in h_services_post_join
 * because the membership struct doesn't exist yet at can_join time.
 */
static void
h_services_can_join(hook_data_channel *hdata)
{
	if(!services.enabled)
		return;

	if(hdata == NULL || hdata->client == NULL || hdata->chptr == NULL)
		return;

	if(!MyClient(hdata->client))
		return;

	struct Client  *client_p = hdata->client;
	struct Channel *chptr    = hdata->chptr;

	struct svc_chanreg *reg = svc_chanreg_find(chptr->chname);
	if(reg == NULL)
		return;

	/* --- 1. Founder key bypass ----------------------------------------- */
	/*
	 * If the join is being rejected because of a bad/missing channel key,
	 * check whether the client is the registered founder (CA_FOUNDER) or
	 * has CA_STAFF.  If so, admit them regardless of the key.
	 *
	 * This preserves the invariant: the registered owner can never be
	 * permanently locked out of their channel, even if operators change +k.
	 */
	if(hdata->approved == ERR_BADCHANNELKEY && client_p->user != NULL
	   && client_p->user->suser[0] != '\0')
	{
		const char *suser = client_p->user->suser;
		bool bypass = false;

		/* Primary founder field — fastest check */
		if(irccmp(reg->founder, suser) == 0)
			bypass = true;

		/* Access list: CA_FOUNDER or CA_STAFF also get key bypass */
		if(!bypass)
		{
			rb_dlink_node *ptr;
			RB_DLINK_FOREACH(ptr, reg->access.head)
			{
				struct svc_chanaccess *ca = ptr->data;
				if(!(ca->flags & (CA_FOUNDER | CA_STAFF)))
					continue;
				if(irccmp(ca->entity, suser) != 0)
					continue;
				bypass = true;
				break;
			}
		}

		if(bypass)
		{
			hdata->approved = 0;
			svc_notice(client_p, "ChanServ",
			    "Channel key bypassed — you are the "
			    "registered owner/staff of %s.",
			    chptr->chname);
		}
	}

	/* If join is still blocked for any reason, don't apply AKICK */
	if(hdata->approved != 0)
		return;

	/* --- 2. AKICK check ----------------------------------------------- */
	{
		rb_dlink_node *ptr;
		RB_DLINK_FOREACH(ptr, reg->access.head)
		{
			struct svc_chanaccess *ca = ptr->data;
			if(!(ca->flags & CA_AKICK))
				continue;
			if(!match_entity(client_p, ca->entity))
				continue;

			/* Veto the join */
			hdata->approved = ERR_BANNEDFROMCHAN;
			return;
		}
	}

	/*
	 * --- 3. CHANREG_RESTRICTED -------------------------------------------
	 * Only users who are identified to a registered account may join.
	 * Opers with IsOper() are exempt (services staff access).
	 */
	if((reg->flags & CHANREG_RESTRICTED)
	   && !IsOper(client_p)
	   && (client_p->user == NULL || client_p->user->suser[0] == '\0'))
	{
		hdata->approved = ERR_INVITEONLYCHAN;
		svc_notice(client_p, "ChanServ",
		    "%s is restricted to registered users — "
		    "please identify with IDENTIFY first.",
		    chptr->chname);
		return;
	}

	/*
	 * --- 4. CHANREG_SECURE -----------------------------------------------
	 * Only users who appear on the channel's access list may join.
	 * Opers and the registered founder are always admitted.
	 */
	if(reg->flags & CHANREG_SECURE)
	{
		if(IsOper(client_p))
			return; /* oper always gets in */
		if(client_p->user != NULL && client_p->user->suser[0] != '\0'
		   && irccmp(reg->founder, client_p->user->suser) == 0)
			return; /* founder always gets in */

		bool on_list = false;
		if(client_p->user != NULL && client_p->user->suser[0] != '\0')
		{
			rb_dlink_node *ptr;
			RB_DLINK_FOREACH(ptr, reg->access.head)
			{
				struct svc_chanaccess *ca = ptr->data;
				if(ca->flags & CA_AKICK)
					continue;
				if(match_entity(client_p, ca->entity))
				{
					on_list = true;
					break;
				}
			}
		}
		if(!on_list)
		{
			hdata->approved = ERR_INVITEONLYCHAN;
			svc_notice(client_p, "ChanServ",
			    "%s requires a ChanServ access entry to join — "
			    "contact the channel operators.",
			    chptr->chname);
		}
	}
}

/*
 * h_services_post_join — "channel_join" hook (hook_data_channel_activity).
 *
 * Fires AFTER the client has been added to the channel.  Handles:
 *
 *   1. Auto-modes — grant +o / +v / +q based on ChanServ access list.
 *   2. MODELOCK   — enforce any locked channel modes.
 *   3. KEEPTOPIC  — restore the registered topic if the channel had none.
 */
static void
h_services_post_join(hook_data_channel_activity *hdata)
{
	if(!services.enabled)
		return;

	if(hdata == NULL || hdata->client == NULL || hdata->chptr == NULL)
		return;

	if(!MyClient(hdata->client))
		return;

	struct Client  *client_p = hdata->client;
	struct Channel *chptr    = hdata->chptr;

	struct svc_chanreg *reg = svc_chanreg_find(chptr->chname);
	if(reg == NULL)
		return;

	/* --- 1. Auto-modes ------------------------------------------------- */
	{
		unsigned int best_mode = 0;
		uint32_t     best_ca   = 0;
		rb_dlink_node *ptr;

		RB_DLINK_FOREACH(ptr, reg->access.head)
		{
			struct svc_chanaccess *ca = ptr->data;
			if(ca->flags & CA_AKICK)
				continue;
			if(!match_entity(client_p, ca->entity))
				continue;
			if(ca->flags <= best_ca)
				continue;

			best_ca = ca->flags;

			/*
			 * Map CA_* tiers to IRCX membership flags.
			 *
			 * This codebase uses CHFL_ADMIN (mode 'q') for channel
			 * owner and CHFL_CHANOP (mode 'o') for operator.  There
			 * is no +a/+h mode; CA_PROTECT collapses to owner and
			 * CA_HALFOP collapses to op.
			 *
			 * CHFL_ADMIN implies CHFL_CHANOP (chm_admin sets both).
			 */
			if(ca->flags & (CA_FOUNDER | CA_OWNER | CA_PROTECT))
				best_mode = CHFL_ADMIN | CHFL_CHANOP;
			else if(ca->flags & (CA_OP | CA_HALFOP))
				best_mode = CHFL_CHANOP;
			else if(ca->flags & CA_VOICE)
				best_mode = CHFL_VOICE;
		}

		/* Also check the primary founder field */
		if(best_ca == 0
		   && client_p->user != NULL && client_p->user->suser[0] != '\0'
		   && irccmp(reg->founder, client_p->user->suser) == 0)
		{
			best_mode = CHFL_ADMIN | CHFL_CHANOP;
		}

		if(best_mode != 0)
		{
			/* Respect ACCT_NOOP — user opted out of auto-modes */
			bool noop = false;
			if(client_p->user != NULL && client_p->user->suser[0])
			{
				struct svc_account *acct =
				    svc_account_find(client_p->user->suser);
				if(acct != NULL && (acct->flags & ACCT_NOOP))
					noop = true;
			}

			if(!noop)
			{
				struct membership *msptr =
				    find_channel_membership(chptr, client_p);
				if(msptr != NULL)
				{
					msptr->flags |= best_mode;

					/*
					 * Mode letter:
					 *   +q = owner (CHFL_ADMIN, sets both
					 *        CHFL_ADMIN and CHFL_CHANOP)
					 *   +o = chanop
					 *   +v = voice
					 */
					const char *modestr =
					    (best_mode & CHFL_ADMIN)
					    ? "+q" : (best_mode & CHFL_CHANOP)
					    ? "+o" : "+v";
					sendto_channel_local(NULL, ALL_MEMBERS,
					    chptr,
					    ":%s MODE %s %s %s",
					    me.name, chptr->chname,
					    modestr, client_p->name);
					sendto_server(NULL, chptr,
					    CAP_TS6, NOCAPS,
					    ":%s TMODE %ld %s %s %s",
					    me.id,
					    (long)chptr->channelts,
					    chptr->chname,
					    modestr,
					    use_id(client_p));
				}
			}
		}
	}

	/* --- 2. MODELOCK --------------------------------------------------- */
	svc_modelock_enforce(chptr, reg);

	/* --- 3. KEEPTOPIC -------------------------------------------------- */
	svc_topic_restore(chptr, reg);
}

/* -------------------------------------------------------------------------
 * MODELOCK enforcement
 * ---------------------------------------------------------------------- */

/*
 * svc_modelock_enforce — build a corrective MODE string from the chanreg's
 * mlock_on / mlock_off bitmasks and send it as a server MODE if the channel's
 * current modes do not match.
 *
 * Only the simple flags are handled here (+n, +t, +s, +m, +i, +p).
 * +l (limit) and +k (key) are handled separately below.
 */
void
svc_modelock_enforce(struct Channel *chptr, struct svc_chanreg *reg)
{
	if(chptr == NULL || reg == NULL)
		return;
	if(reg->mlock_on == 0 && reg->mlock_off == 0
	   && reg->mlock_limit == 0 && reg->mlock_key[0] == '\0')
		return;

	/* Modes that need to be set (locked-on but currently off) */
	uint32_t need_set = reg->mlock_on & ~chptr->mode.mode;
	/* Modes that need to be unset (locked-off but currently on) */
	uint32_t need_unset = reg->mlock_off & chptr->mode.mode;

	bool fix_limit = (reg->mlock_limit > 0
	                  && chptr->mode.limit != reg->mlock_limit);
	bool fix_key   = (reg->mlock_key[0] != '\0'
	                  && strcmp(chptr->mode.key, reg->mlock_key) != 0);

	if(need_set == 0 && need_unset == 0 && !fix_limit && !fix_key)
		return; /* already compliant */

	char modebuf[MODEBUFLEN];
	char parabuf[MODEBUFLEN];
	int  mi = 0, pi = 0;

	/* Build +<modes> string */
	if(need_set || fix_limit || fix_key)
	{
		modebuf[mi++] = '+';

		/* Iterate common channel mode bits */
		static const struct { uint32_t bit; char letter; } mbits[] = {
			{ MODE_NOPRIVMSGS, 'n' },
			{ MODE_TOPICLIMIT, 't' },
			{ MODE_SECRET,     's' },
			{ MODE_MODERATED,  'm' },
			{ MODE_INVITEONLY, 'i' },
			{ MODE_PRIVATE,    'p' },
			{ MODE_PERMANENT,  'P' },
			{ MODE_OPMODERATE, 'z' },
			{ MODE_FREEINVITE, 'g' },
			{ MODE_FREETARGET, 'F' },
			{ MODE_DISFORWARD, 'Q' },
		};
		for(size_t j = 0; j < ARRAY_SIZE(mbits); j++)
		{
			if(need_set & mbits[j].bit)
				modebuf[mi++] = mbits[j].letter;
		}

		if(fix_limit)
		{
			modebuf[mi++] = 'l';
			pi += snprintf(parabuf + pi, sizeof parabuf - pi,
			               "%d ", reg->mlock_limit);
		}
		if(fix_key)
		{
			modebuf[mi++] = 'k';
			pi += snprintf(parabuf + pi, sizeof parabuf - pi,
			               "%s ", reg->mlock_key);
		}
	}

	/* Build -<modes> string */
	if(need_unset)
	{
		modebuf[mi++] = '-';

		static const struct { uint32_t bit; char letter; } mbits[] = {
			{ MODE_NOPRIVMSGS, 'n' },
			{ MODE_TOPICLIMIT, 't' },
			{ MODE_SECRET,     's' },
			{ MODE_MODERATED,  'm' },
			{ MODE_INVITEONLY, 'i' },
			{ MODE_PRIVATE,    'p' },
			{ MODE_PERMANENT,  'P' },
			{ MODE_OPMODERATE, 'z' },
			{ MODE_FREEINVITE, 'g' },
			{ MODE_FREETARGET, 'F' },
			{ MODE_DISFORWARD, 'Q' },
		};
		for(size_t j = 0; j < ARRAY_SIZE(mbits); j++)
		{
			if(need_unset & mbits[j].bit)
				modebuf[mi++] = mbits[j].letter;
		}
	}

	modebuf[mi] = '\0';
	if(pi > 0 && parabuf[pi - 1] == ' ')
		parabuf[--pi] = '\0';
	else
		parabuf[pi] = '\0';

	if(mi == 0)
		return;

	if(pi > 0)
		sendto_channel_local(NULL, ALL_MEMBERS, chptr,
		                     ":%s MODE %s %s %s",
		                     me.name, chptr->chname, modebuf, parabuf);
	else
		sendto_channel_local(NULL, ALL_MEMBERS, chptr,
		                     ":%s MODE %s %s",
		                     me.name, chptr->chname, modebuf);

	sendto_server(NULL, chptr, 0, 0,
	              ":%s MODE %s %s%s%s",
	              me.id, chptr->chname, modebuf,
	              pi > 0 ? " " : "", pi > 0 ? parabuf : "");

	/* Apply the mode changes to the live channel struct */
	chptr->mode.mode |= reg->mlock_on;
	chptr->mode.mode &= ~reg->mlock_off;
	if(fix_limit)
		chptr->mode.limit = reg->mlock_limit;
	if(fix_key)
		rb_strlcpy(chptr->mode.key, reg->mlock_key,
		           sizeof chptr->mode.key);
}

/* -------------------------------------------------------------------------
 * Topic restoration
 * ---------------------------------------------------------------------- */

void
svc_topic_restore(struct Channel *chptr, struct svc_chanreg *reg)
{
	if(chptr == NULL || reg == NULL)
		return;

	if(!(reg->flags & CHANREG_KEEPTOPIC))
		return;

	if(reg->topic[0] == '\0')
		return;

	/* Only restore when the live channel has no topic */
	if(chptr->topic != NULL && chptr->topic[0] != '\0')
		return;

	/* Set the topic on the live channel struct */
	rb_free(chptr->topic);
	rb_free(chptr->topic_info);
	chptr->topic      = rb_strdup(reg->topic);
	chptr->topic_info = rb_strdup(reg->topic_setter[0] != '\0'
	                              ? reg->topic_setter : me.name);
	chptr->topic_time = reg->topic_ts ? reg->topic_ts : rb_current_time();

	/* Propagate to local members */
	sendto_channel_local(NULL, ALL_MEMBERS, chptr,
	                     ":%s TOPIC %s :%s",
	                     me.name, chptr->chname, chptr->topic);

	/* Propagate to other servers */
	sendto_server(NULL, chptr, 0, 0,
	              ":%s TOPIC %s %s %ld :%s",
	              me.id, chptr->chname,
	              chptr->topic_info,
	              (long)chptr->topic_time,
	              chptr->topic);
}

/* -------------------------------------------------------------------------
 * Oper block integration
 * ---------------------------------------------------------------------- */

struct oper_conf *
svc_account_oper_conf(struct svc_account *acct)
{
	if(acct == NULL || acct->oper_block[0] == '\0')
		return NULL;
	return oper_find_by_name(acct->oper_block);
}

/* -------------------------------------------------------------------------
 * Reply helpers
 * ---------------------------------------------------------------------- */

/*
 * svc_notice — send a server-originated NOTICE to a client formatted as:
 *   :<server> NOTICE <nick> :<service>: <message>
 *
 * The `service` parameter is a short token like "NickServ", "ChanServ", etc.
 */
void
svc_notice(struct Client *target_p, const char *service,
           const char *fmt, ...)
{
	if(target_p == NULL || service == NULL || fmt == NULL)
		return;
	if(!MyClient(target_p))
		return;

	char msg[BUFSIZE];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof msg, fmt, ap);
	va_end(ap);

	sendto_one(target_p, ":%s NOTICE %s :%s: %s",
	           me.name, target_p->name, service, msg);
}

/*
 * svc_memo_deliver_notice — if the account has unread memos, send the user a
 * NOTICE informing them how many are waiting.  Called immediately after a
 * successful SASL identification.
 */
void
svc_memo_deliver_notice(struct Client *client_p, struct svc_account *acct)
{
	if(client_p == NULL || acct == NULL)
		return;

	rb_dlink_list memos;
	memset(&memos, 0, sizeof memos);

	if(!svc_db_memo_load_for(acct->name, &memos))
		return;

	int unread = 0;
	rb_dlink_node *ptr, *nptr;
	RB_DLINK_FOREACH(ptr, memos.head)
	{
		struct svc_memo *m = ptr->data;
		if(!m->read)
			unread++;
	}

	/* Free the temporary list */
	RB_DLINK_FOREACH_SAFE(ptr, nptr, memos.head)
	{
		struct svc_memo *m = ptr->data;
		rb_dlinkDestroy(ptr, &memos);
		rb_free(m);
	}

	if(unread > 0)
		svc_notice(client_p, "MemoServ",
		           "You have %d unread memo%s. "
		           "Use /MS LIST to read them.",
		           unread, unread == 1 ? "" : "s");
}
