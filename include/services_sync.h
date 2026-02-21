/*
 * include/services_sync.h — Services S2S synchronisation protocol
 *
 * Commands added to the TS6 server-to-server protocol:
 *
 *   SVCSREG  <name> <passhash> <email> <registered_ts> <flags>
 *            <oper_block|-> <vhost|-> <hmac>
 *     Register or update an account on all servers.  The vhost field was
 *     added so HostServ-assigned vhosts propagate to all leaves without a
 *     separate message.
 *
 *   SVCSDROP <name> <hmac>
 *     Drop an account network-wide.
 *
 *   SVCSPWD  <name> <new_passhash> <ts> <hmac>
 *     Password change propagation.
 *
 *   SVCSCERT <name> ADD|DEL <certfp> <ts> <hmac>
 *     Certificate fingerprint add/remove.
 *
 *   SVCSNICK ADD <nick> <account> <registered_ts> <hmac>
 *   SVCSNICK DEL <nick> <hmac>
 *     Grouped nick add/remove.  Keeps the nick→account index consistent
 *     across leaves without requiring a full account re-burst.
 *
 *   SVCSID   <uid> <account_name>
 *     Notify that a client has identified to an account (like ENCAP LOGIN
 *     but for the services DB layer).  No HMAC needed; already over TLS.
 *     Receiving server validates the account name exists before applying.
 *
 *   SVCSCHAN <channel> <founder> <registered_ts> <flags>
 *            <mlock_on> <mlock_off> <mlock_limit> <mlock_key|->
 *            <hmac> :<topic|->
 *     Channel registration propagation.  mlock fields are now included so
 *     leaves can enforce mode locks without needing the hub.  Topic is the
 *     trailing parameter (after hmac) so spaces are preserved.
 *
 *   SVCSCDROP <channel> <hmac>
 *     Drop channel registration.
 *
 *   SVCSACCESS SET <channel> <entity> <flags> <setter|-> <set_ts> <hmac>
 *   SVCSACCESS DEL <channel> <entity> <hmac>
 *     Channel access list synchronisation.  Each entry syncs independently
 *     so point-in-time access changes propagate without a full chan re-burst.
 *
 *   SVCSOPER <account_name> <oper_block_name|-> <hmac>
 *     Link or unlink an account to an oper block.
 *
 *   SVCSBURST <count>
 *     Sent by hub before and after the full account burst so leaves can
 *     detect burst completion and reconcile dirty records.
 *
 *   SVCSMODE HUB|LEAF|SPLIT
 *     Hub announces its current mode; leaves adjust accordingly.
 *
 * HMAC key derivation
 * -------------------
 *   K   = SHA256( sort(fp_local, fp_remote) || ":ophion-services:" )
 *   tag = HMAC-SHA256( K, payload )
 *
 *   The fingerprints are the TLS cert fingerprints of both endpoints as
 *   configured in connect{} blocks (certfp= or fingerprint=).  If either
 *   endpoint has no TLS cert, the tag is the literal string "none" and the
 *   HMAC check is skipped — the TLS channel itself is the primary guard.
 *
 * Hub/leaf state machine
 * ----------------------
 *   On LINK established:
 *     Hub → leaf: SVCSMODE HUB
 *                 SVCSBURST <account_count>
 *                 SVCSREG × N   (all accounts)
 *                 SVCSCERT × M  (all certfps)
 *                 SVCSNICK × P  (all grouped nicks)
 *                 SVCSCHAN × Q  (all channel registrations, with mlock)
 *                 SVCSACCESS × R (all channel access entries)
 *                 SVCSBURST 0   (burst end)
 *     Leaf stores records, marks clean.
 *
 *   On LINK lost (netsplit):
 *     Leaf transitions to SVCS_MODE_SPLIT.
 *     Local writes are committed to local DB and kept dirty=true.
 *
 *   On LINK re-established (hub reconnects):
 *     Hub sends fresh burst (SVCSBURST N … SVCSBURST 0).
 *     On burst end, leaf sends dirty records back to hub (SVCSREG/SVCSCHAN).
 *     Hub resolves conflicts by last-write-wins (registered_ts).
 *     Leaf clears dirty flags after sending.
 *
 * Copyright (c) 2026 Ophion development team.  GPL v2.
 */

#ifndef OPHION_SERVICES_SYNC_H
#define OPHION_SERVICES_SYNC_H

#include "services.h"
#include "client.h"

/* =========================================================================
 * HMAC helpers
 * ========================================================================= */

/*
 * Compute the HMAC-SHA256 authentication tag for a sync message.
 *
 *   fp_local:    TLS cert fingerprint of THIS server (may be NULL)
 *   fp_remote:   TLS cert fingerprint of the peer   (may be NULL)
 *   payload:     message payload to authenticate
 *   payload_len: length of payload
 *   out_hex:     output buffer for hex-encoded HMAC (at least 65 bytes)
 *   out_len:     size of out_hex
 *
 * If either fingerprint is NULL, the output is the literal string "none".
 */
void svc_sync_hmac(const char *fp_local, const char *fp_remote,
                   const char *payload, size_t payload_len,
                   char *out_hex, size_t out_len);

/*
 * Verify an HMAC tag.  Returns true if the tag matches or if either
 * fingerprint is NULL (permissive mode — still over TLS).
 */
bool svc_sync_hmac_verify(const char *fp_local, const char *fp_remote,
                          const char *payload, size_t payload_len,
                          const char *expected_hex);

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

void svc_sync_init(void);          /* called from services_init()          */
void svc_sync_shutdown(void);

/* Called when a server successfully links */
void svc_sync_server_linked(struct Client *server_p);

/* Called when a server disconnects (netsplit detection) */
void svc_sync_server_lost(struct Client *server_p);

/* =========================================================================
 * Hub → leaf burst
 * ========================================================================= */

/* Send full account+channel+access burst to a newly-linked server */
void svc_sync_burst_to(struct Client *server_p);

/* =========================================================================
 * Propagation — called after local DB writes
 * ========================================================================= */

/* Account operations */
void svc_sync_account_reg(struct svc_account *acct);
void svc_sync_account_drop(const char *name);
void svc_sync_account_pwd(struct svc_account *acct);
void svc_sync_account_certfp(struct svc_account *acct,
                              const char *certfp, bool adding);

/* Grouped nick operations */
void svc_sync_nick_group(const char *nick, const char *account_name,
                         time_t registered_ts);
void svc_sync_nick_ungroup(const char *nick);

/* Oper linkage */
void svc_sync_account_oper(struct svc_account *acct);

/* Client identification (no HMAC needed; transient state) */
void svc_sync_client_id(struct Client *client_p, struct svc_account *acct);

/* Channel registration */
void svc_sync_chanreg(struct svc_chanreg *reg);
void svc_sync_chandrop(const char *channel);

/* Channel access list entries */
void svc_sync_chanaccess_set(struct svc_chanreg *reg,
                             struct svc_chanaccess *ca);
void svc_sync_chanaccess_del(const char *channel, const char *entity);

#endif /* OPHION_SERVICES_SYNC_H */
