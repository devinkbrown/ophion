/*
 * include/services_sync.h — Services S2S synchronisation protocol
 *
 * Commands added to the TS6 server-to-server protocol:
 *
 *   SVCSREG  <name> <passhash> <email> <registered_ts> <flags> <oper_block>
 *            <hmac>
 *     Register or update an account on all servers.
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
 *   SVCSID   <uid> <account_name>
 *     Notify that a client has identified to an account (like ENCAP LOGIN
 *     but for the services DB layer).  No HMAC needed; already over TLS.
 *
 *   SVCSCHAN <channel> <founder> <registered_ts> <flags> <topic> <hmac>
 *     Channel registration propagation.
 *
 *   SVCSCDROP <channel> <hmac>
 *     Drop channel registration.
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
 *   tag = HMAC-SHA256( K, ts || ":" || account_name || ":" || payload )
 *
 *   The fingerprints are the TLS cert fingerprints of both endpoints
 *   as configured in connect{} blocks (certfp or fingerprint=).
 *   If either endpoint has no TLS cert, tag is "none" and the check is
 *   skipped (the TLS channel itself is still the primary protection).
 *
 * Hub/leaf state machine
 * ----------------------
 *   On LINK established:
 *     Hub → leaf: SVCSMODE HUB, then SVCSBURST <n>, then SVCSREG×n,
 *                 then SVCSBURST 0 (end marker).
 *     Leaf stores records, marks clean.
 *
 *   On LINK lost (netsplit):
 *     Leaf transitions to SVCS_MODE_SPLIT.
 *     Local writes are committed to local DB and marked dirty.
 *
 *   On LINK re-established (hub reconnects):
 *     Hub sends fresh burst.
 *     Leaf sends dirty records (SVCSREG for each dirty account).
 *     Hub resolves conflicts by last-write-wins (registered_ts).
 *     Leaf clears dirty flags after hub ACKs.
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

void svc_sync_burst_to(struct Client *server_p);   /* send full account+chan burst */

/* =========================================================================
 * Propagation — called after local DB writes
 * ========================================================================= */

/* Account operations */
void svc_sync_account_reg(struct svc_account *acct);
void svc_sync_account_drop(const char *name);
void svc_sync_account_pwd(struct svc_account *acct);
void svc_sync_account_certfp(struct svc_account *acct,
                              const char *certfp, bool adding);

/* Oper linkage */
void svc_sync_account_oper(struct svc_account *acct);

/* Client identification (no HMAC needed; transient state) */
void svc_sync_client_id(struct Client *client_p, struct svc_account *acct);

/* Channel operations */
void svc_sync_chanreg(struct svc_chanreg *reg);
void svc_sync_chandrop(const char *channel);

/* =========================================================================
 * S2S message handlers — registered by modules/m_services_sync.c
 * ========================================================================= */

void ms_svcsreg  (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
void ms_svcsdrop (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
void ms_svcspwd  (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
void ms_svcscert (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
void ms_svcsid   (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
void ms_svcschan (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
void ms_svcscdrop(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
void ms_svcsoper (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
void ms_svcsburst(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
void ms_svcsmode (struct MsgBuf *, struct Client *, struct Client *, int, const char **);

#endif /* OPHION_SERVICES_SYNC_H */
