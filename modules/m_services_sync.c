/*
 * modules/m_services_sync.c — S2S SVCS* command handlers
 *
 * Registers the twelve server-to-server commands that implement the Ophion
 * services synchronisation protocol.  All commands are silently ignored
 * from non-server sources (mg_ignore); only server-originated messages
 * are processed.
 *
 * Command summary (all fields positional unless noted as trailing with ':'):
 *
 *   SVCSREG  <name> <passhash> <email> <ts> <flags> <oper_block> <vhost> <hmac>
 *   SVCSDROP <name> <hmac>
 *   SVCSPWD  <name> <passhash> <ts> <hmac>
 *   SVCSCERT <name> ADD|DEL <certfp> <ts> <hmac>
 *   SVCSNICK ADD <nick> <account> <ts> <hmac>
 *   SVCSNICK DEL <nick> <hmac>
 *   SVCSID   <uid> <account_name>
 *   SVCSCHAN <channel> <founder> <ts> <flags> <mlock_on> <mlock_off>
 *            <mlock_limit> <mlock_key> <hmac> :<topic>
 *   SVCSCDROP <channel> <hmac>
 *   SVCSACCESS SET <channel> <entity> <flags> <setter> <set_ts> <hmac>
 *   SVCSACCESS DEL <channel> <entity> <hmac>
 *   SVCSOPER <account_name> <oper_block|-> <hmac>
 *   SVCSBURST <count>
 *   SVCSMODE HUB|LEAF|SPLIT
 *
 * Copyright (c) 2026 Ophion development team.  GPL v2.
 */

#include "stdinc.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_serv.h"
#include "hash.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "hook.h"
#include "logger.h"
#include "services.h"
#include "services_sync.h"
#include "services_db.h"

static const char services_sync_desc[] =
	"S2S SVCS* command handlers for services account/channel synchronisation";

static int  modinit(void);
static void moddeinit(void);

/* ---- forward declarations for handler functions ---- */

static void ms_svcsreg   (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_svcsdrop  (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_svcspwd   (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_svcscert  (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_svcsnick  (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_svcsid    (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_svcschan  (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_svcscdrop (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_svcsaccess(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_svcsoper  (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_svcsburst (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void ms_svcsmode  (struct MsgBuf *, struct Client *, struct Client *, int, const char **);

/* ---- Message table entries --------------------------------------------- */
/*
 * Handler layout (indexed by HandlerType):
 *   [UNREGISTERED] [CLIENT] [RCLIENT] [SERVER] [ENCAP] [OPER]
 *
 * All SVCS* commands are server-only; every other source gets mg_ignore.
 */

static struct Message svcsreg_msgtab = {
	"SVCSREG", 0, 0, 0, 0,
	{ mg_ignore, mg_ignore, mg_ignore, {ms_svcsreg, 9}, mg_ignore, mg_ignore }
};
static struct Message svcsdrop_msgtab = {
	"SVCSDROP", 0, 0, 0, 0,
	{ mg_ignore, mg_ignore, mg_ignore, {ms_svcsdrop, 2}, mg_ignore, mg_ignore }
};
static struct Message svcspwd_msgtab = {
	"SVCSPWD", 0, 0, 0, 0,
	{ mg_ignore, mg_ignore, mg_ignore, {ms_svcspwd, 4}, mg_ignore, mg_ignore }
};
static struct Message svcscert_msgtab = {
	"SVCSCERT", 0, 0, 0, 0,
	{ mg_ignore, mg_ignore, mg_ignore, {ms_svcscert, 5}, mg_ignore, mg_ignore }
};
static struct Message svcsnick_msgtab = {
	"SVCSNICK", 0, 0, 0, 0,
	/* ADD needs 5 params (ADD nick account ts hmac); DEL needs 3 (DEL nick hmac) */
	{ mg_ignore, mg_ignore, mg_ignore, {ms_svcsnick, 3}, mg_ignore, mg_ignore }
};
static struct Message svcsid_msgtab = {
	"SVCSID", 0, 0, 0, 0,
	{ mg_ignore, mg_ignore, mg_ignore, {ms_svcsid, 2}, mg_ignore, mg_ignore }
};
static struct Message svcschan_msgtab = {
	"SVCSCHAN", 0, 0, 0, 0,
	/* channel founder ts flags mlock_on mlock_off mlock_limit mlock_key hmac :topic */
	{ mg_ignore, mg_ignore, mg_ignore, {ms_svcschan, 10}, mg_ignore, mg_ignore }
};
static struct Message svcscdrop_msgtab = {
	"SVCSCDROP", 0, 0, 0, 0,
	{ mg_ignore, mg_ignore, mg_ignore, {ms_svcscdrop, 2}, mg_ignore, mg_ignore }
};
static struct Message svcsaccess_msgtab = {
	"SVCSACCESS", 0, 0, 0, 0,
	/* SET channel entity flags setter set_ts hmac = 7 fields + op = min 4 for DEL */
	{ mg_ignore, mg_ignore, mg_ignore, {ms_svcsaccess, 4}, mg_ignore, mg_ignore }
};
static struct Message svcsoper_msgtab = {
	"SVCSOPER", 0, 0, 0, 0,
	{ mg_ignore, mg_ignore, mg_ignore, {ms_svcsoper, 3}, mg_ignore, mg_ignore }
};
static struct Message svcsburst_msgtab = {
	"SVCSBURST", 0, 0, 0, 0,
	{ mg_ignore, mg_ignore, mg_ignore, {ms_svcsburst, 2}, mg_ignore, mg_ignore }
};
static struct Message svcsmode_msgtab = {
	"SVCSMODE", 0, 0, 0, 0,
	{ mg_ignore, mg_ignore, mg_ignore, {ms_svcsmode, 2}, mg_ignore, mg_ignore }
};

mapi_clist_av1 services_sync_clist[] = {
	&svcsreg_msgtab, &svcsdrop_msgtab, &svcspwd_msgtab,
	&svcscert_msgtab, &svcsnick_msgtab, &svcsid_msgtab,
	&svcschan_msgtab, &svcscdrop_msgtab, &svcsaccess_msgtab,
	&svcsoper_msgtab, &svcsburst_msgtab, &svcsmode_msgtab, NULL
};

DECLARE_MODULE_AV2(m_services_sync, modinit, moddeinit,
                   services_sync_clist, NULL, NULL, NULL, NULL,
                   services_sync_desc);

static int
modinit(void)
{
	return 0;
}

static void
moddeinit(void)
{
}

/* =========================================================================
 * Helper: relay a message to all servers except the one it arrived from.
 * ========================================================================= */

#define RELAY_TO_SERVERS(source_p, fmt, ...) \
	sendto_server((source_p), NULL, CAP_TS6, NOCAPS, fmt, ##__VA_ARGS__)

/* =========================================================================
 * ms_svcsreg
 *
 *   parv[1]  account name
 *   parv[2]  passhash
 *   parv[3]  email
 *   parv[4]  registered_ts
 *   parv[5]  flags (decimal)
 *   parv[6]  oper_block (or "-")
 *   parv[7]  vhost (or "-")
 *   parv[8]  hmac
 * ========================================================================= */

static void
ms_svcsreg(struct MsgBuf *msgbuf_p, struct Client *client_p,
           struct Client *source_p, int parc, const char *parv[])
{
	if(!services.enabled)
		return;

	const char *name       = parv[1];
	const char *passhash   = parv[2];
	const char *email      = parv[3];
	time_t      reg_ts     = (time_t)atol(parv[4]);
	uint32_t    flags      = (uint32_t)strtoul(parv[5], NULL, 10);
	const char *oper_block = parv[6];
	const char *vhost      = parv[7];
	const char *hmac_in    = parv[8];

	/* Verify HMAC */
	char payload[BUFSIZE];
	snprintf(payload, sizeof(payload), "%s %s %s %ld %u %s %s",
	         name, passhash, email, (long)reg_ts, flags, oper_block, vhost);

	if(!svc_sync_hmac_verify(me.certfp, source_p->certfp,
	                         payload, strlen(payload), hmac_in))
	{
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
		    "SVCSREG: HMAC mismatch from %s for account %s",
		    source_p->name, name);
		return;
	}

	/* Create or update account */
	struct svc_account *acct = svc_account_find(name);
	if(acct == NULL) {
		acct = svc_account_create(name, passhash, email);
		if(acct == NULL) {
			ilog(L_MAIN, "ms_svcsreg: failed to create account %s", name);
			return;
		}
	} else {
		/* Last-write-wins: only update if incoming is newer or equal */
		if(reg_ts < acct->registered_ts)
			goto relay;
		rb_strlcpy(acct->passhash, passhash, sizeof(acct->passhash));
		rb_strlcpy(acct->email,    email,    sizeof(acct->email));
	}

	acct->registered_ts = reg_ts;
	acct->flags         = flags;

	if(strcmp(oper_block, "-") == 0)
		acct->oper_block[0] = '\0';
	else
		rb_strlcpy(acct->oper_block, oper_block, sizeof(acct->oper_block));

	if(strcmp(vhost, "-") == 0)
		acct->vhost[0] = '\0';
	else
		rb_strlcpy(acct->vhost, vhost, sizeof(acct->vhost));

	svc_db_account_save(acct);

relay:
	RELAY_TO_SERVERS(client_p,
	    ":%s SVCSREG %s %s %s %ld %u %s %s %s",
	    use_id(source_p),
	    name, passhash, email, (long)reg_ts, flags,
	    oper_block, vhost, hmac_in);
}

/* =========================================================================
 * ms_svcsdrop
 *
 *   parv[1]  account name
 *   parv[2]  hmac
 * ========================================================================= */

static void
ms_svcsdrop(struct MsgBuf *msgbuf_p, struct Client *client_p,
            struct Client *source_p, int parc, const char *parv[])
{
	if(!services.enabled)
		return;

	const char *name    = parv[1];
	const char *hmac_in = parv[2];

	if(!svc_sync_hmac_verify(me.certfp, source_p->certfp,
	                         name, strlen(name), hmac_in))
	{
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
		    "SVCSDROP: HMAC mismatch from %s for account %s",
		    source_p->name, name);
		return;
	}

	struct svc_account *acct = svc_account_find(name);
	if(acct != NULL) {
		svc_db_account_delete(name);
		/* svc_db_account_delete frees and removes from dict */
	}

	RELAY_TO_SERVERS(client_p,
	    ":%s SVCSDROP %s %s",
	    use_id(source_p), name, hmac_in);
}

/* =========================================================================
 * ms_svcspwd
 *
 *   parv[1]  account name
 *   parv[2]  new passhash
 *   parv[3]  timestamp
 *   parv[4]  hmac
 * ========================================================================= */

static void
ms_svcspwd(struct MsgBuf *msgbuf_p, struct Client *client_p,
           struct Client *source_p, int parc, const char *parv[])
{
	if(!services.enabled)
		return;

	const char *name     = parv[1];
	const char *passhash = parv[2];
	time_t      ts       = (time_t)atol(parv[3]);
	const char *hmac_in  = parv[4];

	char payload[BUFSIZE];
	snprintf(payload, sizeof(payload), "%s %s %ld", name, passhash, (long)ts);

	if(!svc_sync_hmac_verify(me.certfp, source_p->certfp,
	                         payload, strlen(payload), hmac_in))
	{
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
		    "SVCSPWD: HMAC mismatch from %s for account %s",
		    source_p->name, name);
		return;
	}

	struct svc_account *acct = svc_account_find(name);
	if(acct != NULL) {
		rb_strlcpy(acct->passhash, passhash, sizeof(acct->passhash));
		svc_db_account_save(acct);
	}

	RELAY_TO_SERVERS(client_p,
	    ":%s SVCSPWD %s %s %ld %s",
	    use_id(source_p), name, passhash, (long)ts, hmac_in);
}

/* =========================================================================
 * ms_svcscert
 *
 *   parv[1]  account name
 *   parv[2]  ADD|DEL
 *   parv[3]  certfp
 *   parv[4]  timestamp
 *   parv[5]  hmac
 * ========================================================================= */

static void
ms_svcscert(struct MsgBuf *msgbuf_p, struct Client *client_p,
            struct Client *source_p, int parc, const char *parv[])
{
	if(!services.enabled)
		return;

	const char *name    = parv[1];
	const char *op      = parv[2];
	const char *certfp  = parv[3];
	time_t      ts      = (time_t)atol(parv[4]);
	const char *hmac_in = parv[5];

	char payload[BUFSIZE];
	snprintf(payload, sizeof(payload), "%s %s %s %ld",
	         name, op, certfp, (long)ts);

	if(!svc_sync_hmac_verify(me.certfp, source_p->certfp,
	                         payload, strlen(payload), hmac_in))
	{
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
		    "SVCSCERT: HMAC mismatch from %s for account %s",
		    source_p->name, name);
		return;
	}

	struct svc_account *acct = svc_account_find(name);
	if(acct != NULL) {
		bool adding = (strcasecmp(op, "ADD") == 0);
		if(adding) {
			/* Add to DB and in-memory list if not already present */
			bool found = false;
			rb_dlink_node *ptr;
			RB_DLINK_FOREACH(ptr, acct->certfps.head) {
				struct svc_certfp *cf = ptr->data;
				if(strcasecmp(cf->fingerprint, certfp) == 0) {
					found = true;
					break;
				}
			}
			if(!found) {
				svc_db_certfp_add(name, certfp);
				struct svc_certfp *cf = rb_malloc(sizeof(*cf));
				rb_strlcpy(cf->fingerprint, certfp,
				           sizeof(cf->fingerprint));
				cf->added_ts = ts;
				rb_dlinkAddAlloc(cf, &acct->certfps);
			}
		} else {
			/* Remove from DB and in-memory list */
			svc_db_certfp_delete(name, certfp);
			rb_dlink_node *ptr, *nptr;
			RB_DLINK_FOREACH_SAFE(ptr, nptr, acct->certfps.head) {
				struct svc_certfp *cf = ptr->data;
				if(strcasecmp(cf->fingerprint, certfp) == 0) {
					rb_dlinkDelete(ptr, &acct->certfps);
					rb_free(cf);
					break;
				}
			}
		}
	}

	RELAY_TO_SERVERS(client_p,
	    ":%s SVCSCERT %s %s %s %ld %s",
	    use_id(source_p), name, op, certfp, (long)ts, hmac_in);
}

/* =========================================================================
 * ms_svcsnick
 *
 *   ADD variant:
 *     parv[1]  "ADD"
 *     parv[2]  nick
 *     parv[3]  account name
 *     parv[4]  registered_ts
 *     parv[5]  hmac
 *
 *   DEL variant:
 *     parv[1]  "DEL"
 *     parv[2]  nick
 *     parv[3]  hmac
 * ========================================================================= */

static void
ms_svcsnick(struct MsgBuf *msgbuf_p, struct Client *client_p,
            struct Client *source_p, int parc, const char *parv[])
{
	if(!services.enabled)
		return;

	const char *op = parv[1];

	if(strcasecmp(op, "ADD") == 0) {
		if(parc < 6) return;

		const char *nick    = parv[2];
		const char *account = parv[3];
		time_t      ts      = (time_t)atol(parv[4]);
		const char *hmac_in = parv[5];

		char payload[BUFSIZE];
		snprintf(payload, sizeof(payload), "ADD %s %s %ld",
		         nick, account, (long)ts);

		if(!svc_sync_hmac_verify(me.certfp, source_p->certfp,
		                         payload, strlen(payload), hmac_in))
		{
			sendto_realops_snomask(SNO_GENERAL, L_ALL,
			    "SVCSNICK ADD: HMAC mismatch from %s for nick %s",
			    source_p->name, nick);
			return;
		}

		/* Only add if account exists and nick is not already registered */
		struct svc_account *acct = svc_account_find(account);
		if(acct != NULL && rb_radixtree_retrieve(svc_nick_dict, nick) == NULL) {
			svc_db_nick_add(nick, account);
		}

		RELAY_TO_SERVERS(client_p,
		    ":%s SVCSNICK ADD %s %s %ld %s",
		    use_id(source_p), nick, account, (long)ts, hmac_in);

	} else if(strcasecmp(op, "DEL") == 0) {
		if(parc < 4) return;

		const char *nick    = parv[2];
		const char *hmac_in = parv[3];

		char payload[BUFSIZE];
		snprintf(payload, sizeof(payload), "DEL %s", nick);

		if(!svc_sync_hmac_verify(me.certfp, source_p->certfp,
		                         payload, strlen(payload), hmac_in))
		{
			sendto_realops_snomask(SNO_GENERAL, L_ALL,
			    "SVCSNICK DEL: HMAC mismatch from %s for nick %s",
			    source_p->name, nick);
			return;
		}

		if(rb_radixtree_retrieve(svc_nick_dict, nick) != NULL)
			svc_db_nick_delete(nick);

		RELAY_TO_SERVERS(client_p,
		    ":%s SVCSNICK DEL %s %s",
		    use_id(source_p), nick, hmac_in);
	}
}

/* =========================================================================
 * ms_svcsid
 *
 *   parv[1]  client UID
 *   parv[2]  account name
 *
 * Marks a client as identified to an account.  The account must exist in
 * the local database; if it does not (e.g., burst not yet received) the
 * message is silently dropped rather than creating a phantom identification.
 * ========================================================================= */

static void
ms_svcsid(struct MsgBuf *msgbuf_p, struct Client *client_p,
          struct Client *source_p, int parc, const char *parv[])
{
	const char *uid          = parv[1];
	const char *account_name = parv[2];

	/* Validate the account exists locally before applying */
	if(services.enabled && svc_account_find(account_name) == NULL)
		return;

	struct Client *target_p = find_id(uid);
	if(target_p == NULL || !IsPerson(target_p))
		return;

	rb_strlcpy(target_p->user->suser, account_name,
	           sizeof(target_p->user->suser));

	RELAY_TO_SERVERS(client_p,
	    ":%s SVCSID %s %s",
	    use_id(source_p), uid, account_name);
}

/* =========================================================================
 * ms_svcschan
 *
 *   parv[1]   channel name
 *   parv[2]   founder account
 *   parv[3]   registered_ts
 *   parv[4]   flags
 *   parv[5]   mlock_on
 *   parv[6]   mlock_off
 *   parv[7]   mlock_limit
 *   parv[8]   mlock_key (or "-")
 *   parv[9]   hmac
 *   parv[10]  topic (trailing parameter, may be "-")
 * ========================================================================= */

static void
ms_svcschan(struct MsgBuf *msgbuf_p, struct Client *client_p,
            struct Client *source_p, int parc, const char *parv[])
{
	if(!services.enabled)
		return;

	const char *channel    = parv[1];
	const char *founder    = parv[2];
	time_t      reg_ts     = (time_t)atol(parv[3]);
	uint32_t    flags      = (uint32_t)strtoul(parv[4], NULL, 10);
	uint32_t    mlock_on   = (uint32_t)strtoul(parv[5], NULL, 10);
	uint32_t    mlock_off  = (uint32_t)strtoul(parv[6], NULL, 10);
	int         mlock_lim  = atoi(parv[7]);
	const char *mlock_key  = parv[8];
	const char *hmac_in    = parv[9];
	const char *topic      = (parc > 10) ? parv[10] : "-";

	char payload[BUFSIZE];
	snprintf(payload, sizeof(payload),
	         "%s %s %ld %u %u %u %d %s %s",
	         channel, founder, (long)reg_ts, flags,
	         mlock_on, mlock_off, mlock_lim,
	         mlock_key, topic);

	if(!svc_sync_hmac_verify(me.certfp, source_p->certfp,
	                         payload, strlen(payload), hmac_in))
	{
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
		    "SVCSCHAN: HMAC mismatch from %s for channel %s",
		    source_p->name, channel);
		return;
	}

	struct svc_chanreg *reg = svc_chanreg_find(channel);
	if(reg == NULL) {
		reg = svc_chanreg_create(channel, founder);
		if(reg == NULL) {
			ilog(L_MAIN, "ms_svcschan: failed to create chanreg %s",
			     channel);
			return;
		}
	} else {
		/* Last-write-wins */
		if(reg_ts < reg->registered_ts)
			goto relay_chan;
		rb_strlcpy(reg->founder, founder, sizeof(reg->founder));
	}

	reg->registered_ts = reg_ts;
	reg->flags         = flags;
	reg->mlock_on      = mlock_on;
	reg->mlock_off     = mlock_off;
	reg->mlock_limit   = mlock_lim;

	if(strcmp(mlock_key, "-") == 0)
		reg->mlock_key[0] = '\0';
	else
		rb_strlcpy(reg->mlock_key, mlock_key, sizeof(reg->mlock_key));

	if(strcmp(topic, "-") != 0)
		rb_strlcpy(reg->topic, topic, sizeof(reg->topic));

	svc_db_chanreg_save(reg);

relay_chan:
	RELAY_TO_SERVERS(client_p,
	    ":%s SVCSCHAN %s %s %ld %u %u %u %d %s %s :%s",
	    use_id(source_p),
	    channel, founder, (long)reg_ts, flags,
	    mlock_on, mlock_off, mlock_lim, mlock_key,
	    hmac_in, topic);
}

/* =========================================================================
 * ms_svcscdrop
 *
 *   parv[1]  channel name
 *   parv[2]  hmac
 * ========================================================================= */

static void
ms_svcscdrop(struct MsgBuf *msgbuf_p, struct Client *client_p,
             struct Client *source_p, int parc, const char *parv[])
{
	if(!services.enabled)
		return;

	const char *channel = parv[1];
	const char *hmac_in = parv[2];

	if(!svc_sync_hmac_verify(me.certfp, source_p->certfp,
	                         channel, strlen(channel), hmac_in))
	{
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
		    "SVCSCDROP: HMAC mismatch from %s for channel %s",
		    source_p->name, channel);
		return;
	}

	struct svc_chanreg *reg = svc_chanreg_find(channel);
	if(reg != NULL) {
		svc_db_chanreg_delete(channel);
		svc_chanreg_free(reg);
	}

	RELAY_TO_SERVERS(client_p,
	    ":%s SVCSCDROP %s %s",
	    use_id(source_p), channel, hmac_in);
}

/* =========================================================================
 * ms_svcsaccess
 *
 *   SET variant:
 *     parv[1]  "SET"
 *     parv[2]  channel
 *     parv[3]  entity (account name or user@host)
 *     parv[4]  flags (decimal)
 *     parv[5]  setter (or "-")
 *     parv[6]  set_ts
 *     parv[7]  hmac
 *
 *   DEL variant:
 *     parv[1]  "DEL"
 *     parv[2]  channel
 *     parv[3]  entity
 *     parv[4]  hmac
 * ========================================================================= */

static void
ms_svcsaccess(struct MsgBuf *msgbuf_p, struct Client *client_p,
              struct Client *source_p, int parc, const char *parv[])
{
	if(!services.enabled)
		return;

	const char *op = parv[1];

	if(strcasecmp(op, "SET") == 0) {
		if(parc < 8) return;

		const char *channel = parv[2];
		const char *entity  = parv[3];
		uint32_t    flags   = (uint32_t)strtoul(parv[4], NULL, 10);
		const char *setter  = parv[5];
		time_t      set_ts  = (time_t)atol(parv[6]);
		const char *hmac_in = parv[7];

		char payload[BUFSIZE];
		snprintf(payload, sizeof(payload),
		         "SET %s %s %u %s %ld",
		         channel, entity, flags, setter, (long)set_ts);

		if(!svc_sync_hmac_verify(me.certfp, source_p->certfp,
		                         payload, strlen(payload), hmac_in))
		{
			sendto_realops_snomask(SNO_GENERAL, L_ALL,
			    "SVCSACCESS SET: HMAC mismatch from %s for %s/%s",
			    source_p->name, channel, entity);
			return;
		}

		struct svc_chanreg *reg = svc_chanreg_find(channel);
		if(reg != NULL) {
			/* Find existing entry or create new one */
			struct svc_chanaccess *ca = NULL;
			rb_dlink_node *ptr;
			RB_DLINK_FOREACH(ptr, reg->access.head) {
				struct svc_chanaccess *e = ptr->data;
				if(irccmp(e->entity, entity) == 0) {
					ca = e;
					break;
				}
			}
			if(ca == NULL) {
				ca = rb_malloc(sizeof(*ca));
				memset(ca, 0, sizeof(*ca));
				rb_strlcpy(ca->entity, entity, sizeof(ca->entity));
				rb_dlinkAddAlloc(ca, &reg->access);
			}
			ca->flags  = flags;
			ca->set_ts = set_ts;
			if(strcmp(setter, "-") == 0)
				ca->setter[0] = '\0';
			else
				rb_strlcpy(ca->setter, setter, sizeof(ca->setter));

			svc_db_chanaccess_add(channel, ca);
		}

		RELAY_TO_SERVERS(client_p,
		    ":%s SVCSACCESS SET %s %s %u %s %ld %s",
		    use_id(source_p),
		    channel, entity, flags, setter, (long)set_ts, hmac_in);

	} else if(strcasecmp(op, "DEL") == 0) {
		if(parc < 5) return;

		const char *channel = parv[2];
		const char *entity  = parv[3];
		const char *hmac_in = parv[4];

		char payload[BUFSIZE];
		snprintf(payload, sizeof(payload), "DEL %s %s", channel, entity);

		if(!svc_sync_hmac_verify(me.certfp, source_p->certfp,
		                         payload, strlen(payload), hmac_in))
		{
			sendto_realops_snomask(SNO_GENERAL, L_ALL,
			    "SVCSACCESS DEL: HMAC mismatch from %s for %s/%s",
			    source_p->name, channel, entity);
			return;
		}

		struct svc_chanreg *reg = svc_chanreg_find(channel);
		if(reg != NULL) {
			rb_dlink_node *ptr, *nptr;
			RB_DLINK_FOREACH_SAFE(ptr, nptr, reg->access.head) {
				struct svc_chanaccess *ca = ptr->data;
				if(irccmp(ca->entity, entity) == 0) {
					rb_dlinkDelete(ptr, &reg->access);
					rb_free(ca);
					break;
				}
			}
			svc_db_chanaccess_delete(channel, entity);
		}

		RELAY_TO_SERVERS(client_p,
		    ":%s SVCSACCESS DEL %s %s %s",
		    use_id(source_p), channel, entity, hmac_in);
	}
}

/* =========================================================================
 * ms_svcsoper
 *
 *   parv[1]  account name
 *   parv[2]  oper_block name or "-" to unlink
 *   parv[3]  hmac
 * ========================================================================= */

static void
ms_svcsoper(struct MsgBuf *msgbuf_p, struct Client *client_p,
            struct Client *source_p, int parc, const char *parv[])
{
	if(!services.enabled)
		return;

	const char *name       = parv[1];
	const char *oper_block = parv[2];
	const char *hmac_in    = parv[3];

	char payload[BUFSIZE];
	snprintf(payload, sizeof(payload), "%s %s", name, oper_block);

	if(!svc_sync_hmac_verify(me.certfp, source_p->certfp,
	                         payload, strlen(payload), hmac_in))
	{
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
		    "SVCSOPER: HMAC mismatch from %s for account %s",
		    source_p->name, name);
		return;
	}

	struct svc_account *acct = svc_account_find(name);
	if(acct != NULL) {
		if(strcmp(oper_block, "-") == 0) {
			acct->oper_block[0] = '\0';
			acct->flags &= ~ACCT_OPERATOR;
		} else {
			rb_strlcpy(acct->oper_block, oper_block,
			           sizeof(acct->oper_block));
			acct->flags |= ACCT_OPERATOR;
		}
		svc_db_account_save(acct);
	}

	RELAY_TO_SERVERS(client_p,
	    ":%s SVCSOPER %s %s %s",
	    use_id(source_p), name, oper_block, hmac_in);
}

/* =========================================================================
 * ms_svcsburst
 *
 *   parv[1]  count  (> 0 = burst start with N accounts; 0 = burst end)
 * ========================================================================= */

static void
ms_svcsburst(struct MsgBuf *msgbuf_p, struct Client *client_p,
             struct Client *source_p, int parc, const char *parv[])
{
	if(!services.enabled)
		return;

	int count = atoi(parv[1]);

	if(count > 0) {
		ilog(L_MAIN, "services_sync: burst from %s starting (%d accounts)",
		     source_p->name, count);
	} else {
		ilog(L_MAIN, "services_sync: burst from %s complete",
		     source_p->name);

		/*
		 * Burst end.  Transition to connected mode (sets mode=CONNECTED,
		 * records hub pointer) then send our dirty records back to hub.
		 *
		 * Dirty records were accumulated during the netsplit: every call
		 * to svc_db_account_save/svc_db_chanreg_save in SPLIT mode kept
		 * dirty=true instead of clearing it.
		 */
		if(!services.is_hub && services.mode == SVCS_MODE_SPLIT)
			services_enter_connected_mode(source_p);

		if(!services.is_hub) {
			rb_radixtree_iteration_state iter;
			struct svc_account *acct;
			struct svc_chanreg *reg;

			/* Send dirty accounts to hub */
			RB_RADIXTREE_FOREACH(acct, &iter, svc_account_dict) {
				if(!acct->dirty)
					continue;
				svc_sync_account_reg(acct);
				acct->dirty = false;
				svc_db_account_save(acct);
			}

			/* Send dirty channel regs + their access lists to hub */
			RB_RADIXTREE_FOREACH(reg, &iter, svc_chanreg_dict) {
				if(!reg->dirty)
					continue;
				svc_sync_chanreg(reg);
				/* Also re-sync the full access list */
				rb_dlink_node *ptr;
				RB_DLINK_FOREACH(ptr, reg->access.head) {
					struct svc_chanaccess *ca = ptr->data;
					svc_sync_chanaccess_set(reg, ca);
				}
				reg->dirty = false;
				svc_db_chanreg_save(reg);
			}

			services.dirty_count = 0;
		}
	}

	/* Relay the burst marker to further servers */
	RELAY_TO_SERVERS(client_p,
	    ":%s SVCSBURST %d",
	    use_id(source_p), count);
}

/* =========================================================================
 * ms_svcsmode
 *
 *   parv[1]  HUB | LEAF | SPLIT
 * ========================================================================= */

static void
ms_svcsmode(struct MsgBuf *msgbuf_p, struct Client *client_p,
            struct Client *source_p, int parc, const char *parv[])
{
	if(!services.enabled)
		return;

	const char *mode_str = parv[1];

	if(strcasecmp(mode_str, "HUB") == 0) {
		/*
		 * The server that sent this is the hub.  Adopt source_p as our
		 * hub if we do not already have one.
		 */
		if(!services.is_hub && services.hub_server == NULL)
			services_enter_connected_mode(source_p);
	} else if(strcasecmp(mode_str, "SPLIT") == 0) {
		if(!services.is_hub)
			services_enter_split_mode();
	} else if(strcasecmp(mode_str, "LEAF") == 0) {
		/* Informational; leaves do not need to act on this. */
	}

	/* Relay the mode announcement */
	RELAY_TO_SERVERS(client_p,
	    ":%s SVCSMODE %s",
	    use_id(source_p), mode_str);
}
