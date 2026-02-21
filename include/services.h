/*
 * include/services.h — Ophion built-in account services
 *
 * Implements NickServ, ChanServ, MemoServ, HostServ, and OperServ as
 * direct IRC commands — no pseudo-client bots.  Clients use:
 *
 *   /NS REGISTER <email> <password>
 *   /CS SET #chan MODELOCK +nt
 *   /OS AKILL *@evil.example.com
 *   etc.
 *
 * The services layer integrates with:
 *   - PROP system  (channel settings stored as PROPs; account metadata as PROPs)
 *   - ACCESS system (ChanServ access list unified with IRCX ACCESS)
 *   - SASL system  (accounts are SASL identities, not only oper blocks)
 *   - Oper system  (accounts can link to oper blocks; one auth chain)
 *
 * Hub/leaf topology
 * -----------------
 *   SVCS_MODE_HUB        — authoritative SQLite DB on this server
 *   SVCS_MODE_CONNECTED  — leaf, hub reachable; writes forwarded to hub
 *   SVCS_MODE_SPLIT      — hub unreachable; leaf uses local cache, marks
 *                          dirty records; syncs on hub reconnect
 *   SVCS_MODE_STANDALONE — no hub configured; every server autonomous
 *
 * Inter-server encryption
 * -----------------------
 *   Sync messages carry an HMAC-SHA256 tag keyed by:
 *     K = SHA256(sort(fp_local, fp_remote) || ":ophion-services:")
 *   Provides authentication-in-depth beyond TLS.
 *
 * Copyright (c) 2026 Ophion development team.  GPL v2.
 */

#ifndef OPHION_SERVICES_H
#define OPHION_SERVICES_H

#include "stdinc.h"
#include "ircd_defs.h"
#include "client.h"
#include "rb_lib.h"

/* =========================================================================
 * Services mode
 * ========================================================================= */

typedef enum {
	SVCS_MODE_HUB        = 0,   /* this server is authoritative hub     */
	SVCS_MODE_CONNECTED  = 1,   /* leaf, hub is reachable               */
	SVCS_MODE_SPLIT      = 2,   /* hub unreachable; autonomous fallback  */
	SVCS_MODE_STANDALONE = 3,   /* no hub; every server is its own hub   */
} svcs_mode_t;

/* =========================================================================
 * Account flags (ACCT_*)
 * ========================================================================= */

#define ACCT_SUSPENDED   0x00000001u  /* suspended by services admin          */
#define ACCT_HOLD        0x00000002u  /* nick reserved even after expiry       */
#define ACCT_NEVEREXPIRE 0x00000004u  /* never expires (admin flag)            */
#define ACCT_HIDEMAIL    0x00000008u  /* hide email from INFO output           */
#define ACCT_NOMEMO      0x00000010u  /* reject incoming memos                 */
#define ACCT_MEMONOTIFY  0x00000020u  /* notify on new memo (default: on)      */
#define ACCT_PROTECT     0x00000040u  /* ghost/kill on nick collision           */
#define ACCT_SECURE      0x00000080u  /* require access-list match to IDENTIFY  */
#define ACCT_PRIVATE     0x00000100u  /* hide from LIST/searches               */
#define ACCT_NOOP        0x00000200u  /* never auto-op on channel join          */
#define ACCT_SASLONLY    0x00000400u  /* IDENTIFY rejected; SASL PLAIN only     */
#define ACCT_OPERATOR    0x00000800u  /* has a linked oper block               */
#define ACCT_NOEXPIRE    0x00001000u  /* admin: no expiry even without login    */
#define ACCT_ENFORCE     0x00002000u  /* kill nick after enforce_delay if unid  */

/* =========================================================================
 * Channel registration flags (CHANREG_*)
 * ========================================================================= */

#define CHANREG_SUSPENDED  0x00000001u
#define CHANREG_SECURE     0x00000002u  /* ops only from ChanServ access list    */
#define CHANREG_PRIVATE    0x00000004u  /* hide from LIST/searches              */
#define CHANREG_TOPICLOCK  0x00000008u  /* only ChanServ-listed ops change topic */
#define CHANREG_KEEPTOPIC  0x00000010u  /* restore registered topic on join      */
#define CHANREG_VERBOSE    0x00000020u  /* notify founder of access changes      */
#define CHANREG_RESTRICTED 0x00000040u  /* only access-list users may join       */
#define CHANREG_NOEXPIRE   0x00000080u  /* admin: never expire                   */
#define CHANREG_GUARD      0x00000100u  /* server holds a virtual presence       */
#define CHANREG_FANTASY    0x00000200u  /* enable !op / !voice fantasy commands  */

/* =========================================================================
 * Channel access flags (CA_*) — unified with IRCX ACCESS
 *
 * These flags correspond directly to the IRCX ACCESS levels.  When an
 * account has CA_OP on a channel, the join hook applies +o; this uses the
 * same mechanism as the existing m_ircx_access module (unified, not
 * duplicated).
 * ========================================================================= */

#define CA_VOICE     0x00000001u  /* +v on join                             */
#define CA_HALFOP    0x00000002u  /* +h on join                             */
#define CA_OP        0x00000004u  /* +o on join                             */
#define CA_PROTECT   0x00000008u  /* +a on join                             */
#define CA_OWNER     0x00000010u  /* +q on join                             */
#define CA_SET       0x00000020u  /* change channel settings via CS         */
#define CA_TOPIC     0x00000040u  /* set topic (bypasses TOPICLOCK)         */
#define CA_INVITE    0x00000080u  /* CS INVITE to self/others               */
#define CA_UNBAN     0x00000100u  /* CS UNBAN self                          */
#define CA_AKICK     0x00000200u  /* auto-kicked on join                    */
#define CA_STAFF     0x00000400u  /* services staff flag (oper integration) */
#define CA_FOUNDER   0x80000000u  /* channel founder (full control)         */

/* Shorthand access tiers (mirroring Atheme VOP/HOP/AOP/SOP) */
#define CA_VOP  (CA_VOICE)
#define CA_HOP  (CA_VOICE | CA_HALFOP)
#define CA_AOP  (CA_VOICE | CA_HALFOP | CA_OP | CA_UNBAN | CA_INVITE)
#define CA_SOP  (CA_AOP | CA_PROTECT | CA_SET | CA_TOPIC)

/* =========================================================================
 * Data structures
 * ========================================================================= */

/* A TLS certificate fingerprint attached to an account */
struct svc_certfp {
	char fingerprint[512];    /* e.g. "cert_sha256:deadbeef..."  */
	time_t added_ts;
	rb_dlink_node node;
};

/* A user@host access mask on an account (for SECURE mode) */
struct svc_accessmask {
	char mask[USERLEN + HOSTLEN + 2];
	time_t added_ts;
	rb_dlink_node node;
};

/* A nick grouped to an account */
struct svc_nick {
	char nick[NICKLEN + 1];
	char account[NICKLEN + 1];
	time_t registered_ts;
	rb_dlink_node node;
};

/* Key-value metadata on an account (SET PRIVATE, SET URL, etc.) */
struct svc_metadata {
	char key[64];
	char value[512];
	rb_dlink_node node;
};

/*
 * NickServ account record.
 *
 * passhash: sha512crypt output (starts with $6$).  Empty string means the
 *           account is cert-only; NS IDENTIFY will be rejected.
 * oper_block: name of a matching oper{} block in ircd.conf.  When set and
 *             SASL auth succeeds for this account, oper_up() is also called.
 *             The oper block's certfp list is merged with account certfps
 *             at auth time, giving one unified cert → oper path.
 */
struct svc_account {
	char name[NICKLEN + 1];
	char passhash[512];                 /* sha512crypt or ""             */
	char email[256];
	time_t registered_ts;
	time_t last_seen_ts;
	char last_seen_nick[NICKLEN + 1];
	char last_seen_host[HOSTLEN + 1];
	uint32_t flags;                     /* ACCT_* bitmask                */

	/* Oper integration: when non-empty this account links to an
	 * oper{} block.  SASL PLAIN/EXTERNAL against this account also
	 * calls oper_up() using the referenced block.                       */
	char oper_block[NAMELEN + 1];

	/* HostServ-assigned vhost ("" if none) */
	char vhost[HOSTLEN + 1];

	char language[16];                  /* locale tag for responses      */

	rb_dlink_list nicks;                /* struct svc_nick               */
	rb_dlink_list certfps;              /* struct svc_certfp             */
	rb_dlink_list access_masks;         /* struct svc_accessmask         */
	rb_dlink_list metadata;             /* struct svc_metadata           */

	bool dirty;                         /* modified in SPLIT mode        */
	rb_dlink_node node;
};

/* A channel access entry (one per account/mask per channel) */
struct svc_chanaccess {
	char entity[NICKLEN + 1];           /* account name or user@host     */
	uint32_t flags;                     /* CA_* bitmask                  */
	char setter[NICKLEN + 1];
	time_t set_ts;
	rb_dlink_node node;
};

/*
 * ChanServ channel registration.
 *
 * Settings (url, description, mlock_*) are ALSO stored as PROPs on the
 * live channel object when it exists, keeping them visible through the
 * PROP system without duplication: the chanreg is the authoritative store,
 * PROP is the live view.
 */
struct svc_chanreg {
	char channel[CHANNELLEN + 1];
	char founder[NICKLEN + 1];          /* primary founder account       */
	char successor[NICKLEN + 1];        /* successor account if any      */
	time_t registered_ts;
	char topic[TOPICLEN + 1];           /* registered/saved topic        */
	char topic_setter[NICKLEN + 1];
	time_t topic_ts;
	uint32_t flags;                     /* CHANREG_* bitmask             */
	char url[512];
	char description[512];
	uint32_t mlock_on;                  /* MODE bits to lock on          */
	uint32_t mlock_off;                 /* MODE bits to lock off         */
	int mlock_limit;                    /* +l limit (0 = not locked)     */
	char mlock_key[KEYLEN + 1];         /* +k key ("" = not locked)      */
	rb_dlink_list access;               /* struct svc_chanaccess         */
	bool dirty;
	rb_dlink_node node;
};

/* A MemoServ message */
struct svc_memo {
	int id;
	char to_account[NICKLEN + 1];
	char from_account[NICKLEN + 1];
	time_t sent_ts;
	bool read;
	char text[512];
	rb_dlink_node node;
};

/* A HostServ vhost offer */
struct svc_vhost_offer {
	char vhost[HOSTLEN + 1];
	char offered_by[NICKLEN + 1];
	time_t offered_ts;
	rb_dlink_node node;
};

/* =========================================================================
 * Global services state
 * ========================================================================= */

struct services_state {
	bool enabled;                        /* services {} enabled = yes/no; */

	svcs_mode_t mode;
	bool is_hub;
	struct Client *hub_server;           /* NULL if we ARE hub or split   */
	time_t split_start;
	int dirty_count;

	/* Configuration (from services {} block in ircd.conf) */
	char db_path[PATH_MAX];
	int  nick_expire_days;               /* 0 = never expire              */
	int  chan_expire_days;
	int  enforce_delay_secs;             /* delay before ENFORCE kills     */
	int  maxnicks;                       /* grouped nicks per account      */
	int  maxmemos;
	bool registration_open;
};

extern struct services_state services;

/* In-memory indices */
extern rb_radixtree *svc_account_dict;    /* name  → svc_account *         */
extern rb_radixtree *svc_nick_dict;       /* nick  → svc_nick *            */
extern rb_radixtree *svc_chanreg_dict;    /* chan  → svc_chanreg *         */

/* =========================================================================
 * Core API
 * ========================================================================= */

/* Lifecycle */
void services_init(void);
void services_shutdown(void);
void services_rehash(void);              /* re-read config, keep DB open   */

/* Hub/leaf transitions */
void services_enter_hub_mode(void);
void services_enter_connected_mode(struct Client *hub_p);
void services_enter_split_mode(void);
void services_enter_standalone_mode(void);
const char *services_mode_name(svcs_mode_t m);

/* Account lookup */
struct svc_account *svc_account_find(const char *name);
struct svc_account *svc_account_find_nick(const char *nick);
struct svc_account *svc_account_find_certfp(const char *certfp);
struct svc_account *svc_account_create(const char *name, const char *passhash,
                                       const char *email);
void svc_account_free(struct svc_account *acct);

/* Channel registration lookup */
struct svc_chanreg *svc_chanreg_find(const char *channel);
struct svc_chanreg *svc_chanreg_create(const char *channel,
                                       const char *founder_name);
void svc_chanreg_free(struct svc_chanreg *reg);

/* Memo helpers */
void svc_memo_deliver_notice(struct Client *client_p, struct svc_account *acct);

/*
 * SASL account authentication (called from modules/sasl_account.c).
 *
 * svc_authenticate_password: verify PLAIN credentials; on success *out
 *   points to the account and *oper_out (if non-NULL) to a matching oper
 *   block so the SASL mechanism can set pending_oper.
 *
 * svc_authenticate_certfp: verify EXTERNAL credentials; account_hint is
 *   the authzid (may be empty for auto-discovery).
 */
bool svc_authenticate_password(const char *account_name, const char *password,
                               struct svc_account **out,
                               struct oper_conf **oper_out);
bool svc_authenticate_certfp(const char *certfp, const char *account_hint,
                              struct svc_account **out,
                              struct oper_conf **oper_out);

/* Channel access check — called by JOIN hook (replaces separate CS hook) */
void svc_chanaccess_on_join(struct Client *client_p, struct Channel *chptr);

/* Apply MODELOCK for a channel (called on MODE change and JOIN) */
void svc_modelock_enforce(struct Channel *chptr, struct svc_chanreg *reg);

/* Apply registered topic (called on JOIN when KEEPTOPIC is set) */
void svc_topic_restore(struct Channel *chptr, struct svc_chanreg *reg);

/* Find linked oper block for an account */
struct oper_conf *svc_account_oper_conf(struct svc_account *acct);

/* Reply helpers (send server NOTICE to a client) */
void svc_notice(struct Client *target_p, const char *service,
                const char *fmt, ...) __attribute__((format(printf, 3, 4)));

/* Command dispatch — called by IRC command handlers */
void nickserv_dispatch(struct Client *source_p, int parc, const char *parv[]);
void chanserv_dispatch(struct Client *source_p, int parc, const char *parv[]);
void memoserv_dispatch(struct Client *source_p, int parc, const char *parv[]);
void hostserv_dispatch(struct Client *source_p, int parc, const char *parv[]);
void operserv_dispatch(struct Client *source_p, int parc, const char *parv[]);

#endif /* OPHION_SERVICES_H */
