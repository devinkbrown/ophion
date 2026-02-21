/*
 * ircd/services_sync.c — Services S2S synchronisation protocol
 *
 * Implements the SVCS* inter-server protocol for replicating account and
 * channel-registration state across a hub/leaf network.  Provides:
 *
 *   - Compact pure-C SHA-256 (RFC 6234 / FIPS 180-4)
 *   - HMAC-SHA256 keyed by a fingerprint-derived key
 *   - Hub-to-leaf burst on server link
 *   - Per-operation propagation helpers called after local DB writes
 *   - Server-link / server-lost hooks that drive mode transitions
 *
 * TLS is provided by wolfSSL (no direct OpenSSL dependency here).
 * The HMAC-SHA256 for S2S message authentication is implemented in pure C
 * so that this file has zero crypto-library dependencies of its own.
 *
 * Copyright (c) 2026 Ophion development team.  GPL v2.
 */

#include "stdinc.h"
#include "client.h"
#include "hook.h"
#include "ircd.h"
#include "send.h"
#include "s_serv.h"
#include "services.h"
#include "services_sync.h"
#include "services_db.h"
#include "logger.h"

/* =========================================================================
 * Pure-C SHA-256 (RFC 6234 / FIPS 180-4)
 * Self-contained; no crypto-library dependency.
 * ========================================================================= */

/* SHA-256 round constants */
static const uint32_t sha256_K[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
	0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
	0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
	0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
	0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
	0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
	0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
	0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
	0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
	0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
	0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
	0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
	0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(e,f,g)    (((e) & (f)) ^ (~(e) & (g)))
#define MAJ(a,b,c)   (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define EP0(a)       (ROTR32(a,2)  ^ ROTR32(a,13) ^ ROTR32(a,22))
#define EP1(e)       (ROTR32(e,6)  ^ ROTR32(e,11) ^ ROTR32(e,25))
#define SIG0(x)      (ROTR32(x,7)  ^ ROTR32(x,18) ^ ((x) >> 3))
#define SIG1(x)      (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x) >> 10))

typedef struct {
	uint8_t  data[64];
	uint32_t state[8];
	uint32_t datalen;
	uint64_t bitlen;
} sha256_ctx;

static void
sha256_transform(sha256_ctx *ctx, const uint8_t *data)
{
	uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
	int i, j;

	for(i = 0, j = 0; i < 16; i++, j += 4)
		m[i] = ((uint32_t)data[j] << 24)
		      | ((uint32_t)data[j+1] << 16)
		      | ((uint32_t)data[j+2] << 8)
		      | ((uint32_t)data[j+3]);
	for(; i < 64; i++)
		m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

	a = ctx->state[0]; b = ctx->state[1];
	c = ctx->state[2]; d = ctx->state[3];
	e = ctx->state[4]; f = ctx->state[5];
	g = ctx->state[6]; h = ctx->state[7];

	for(i = 0; i < 64; i++) {
		t1 = h + EP1(e) + CH(e,f,g) + sha256_K[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	ctx->state[0] += a; ctx->state[1] += b;
	ctx->state[2] += c; ctx->state[3] += d;
	ctx->state[4] += e; ctx->state[5] += f;
	ctx->state[6] += g; ctx->state[7] += h;
}

static void
sha256_init(sha256_ctx *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen  = 0;
	ctx->state[0] = 0x6a09e667u;
	ctx->state[1] = 0xbb67ae85u;
	ctx->state[2] = 0x3c6ef372u;
	ctx->state[3] = 0xa54ff53au;
	ctx->state[4] = 0x510e527fu;
	ctx->state[5] = 0x9b05688cu;
	ctx->state[6] = 0x1f83d9abu;
	ctx->state[7] = 0x5be0cd19u;
}

static void
sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
	size_t i;
	for(i = 0; i < len; i++) {
		ctx->data[ctx->datalen++] = data[i];
		if(ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen  += 512;
			ctx->datalen  = 0;
		}
	}
}

static void
sha256_final(sha256_ctx *ctx, uint8_t hash[32])
{
	uint32_t i = ctx->datalen;

	/* Pad to 55 bytes (< 56) or 119 bytes (>= 56) */
	if(ctx->datalen < 56) {
		ctx->data[i++] = 0x80u;
		while(i < 56)
			ctx->data[i++] = 0x00u;
	} else {
		ctx->data[i++] = 0x80u;
		while(i < 64)
			ctx->data[i++] = 0x00u;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	ctx->bitlen += (uint64_t)ctx->datalen * 8;
	ctx->data[63] = (uint8_t)(ctx->bitlen);
	ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
	ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
	ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
	ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
	ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
	ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
	ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
	sha256_transform(ctx, ctx->data);

	for(i = 0; i < 4; i++) {
		hash[i]      = (ctx->state[0] >> (24 - i*8)) & 0xffu;
		hash[i+4]    = (ctx->state[1] >> (24 - i*8)) & 0xffu;
		hash[i+8]    = (ctx->state[2] >> (24 - i*8)) & 0xffu;
		hash[i+12]   = (ctx->state[3] >> (24 - i*8)) & 0xffu;
		hash[i+16]   = (ctx->state[4] >> (24 - i*8)) & 0xffu;
		hash[i+20]   = (ctx->state[5] >> (24 - i*8)) & 0xffu;
		hash[i+24]   = (ctx->state[6] >> (24 - i*8)) & 0xffu;
		hash[i+28]   = (ctx->state[7] >> (24 - i*8)) & 0xffu;
	}
}

/* Simple HMAC-SHA256 built on the pure-C SHA256 above */
static void
hmac_sha256_raw(const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len,
                uint8_t out[32])
{
	uint8_t k_pad[64];
	uint8_t inner[32];
	sha256_ctx ctx;
	size_t i;

	/* If key > block size, hash it first */
	if(key_len > 64) {
		sha256_init(&ctx);
		sha256_update(&ctx, key, key_len);
		sha256_final(&ctx, k_pad);
		memset(k_pad + 32, 0, 32);
	} else {
		memcpy(k_pad, key, key_len);
		memset(k_pad + key_len, 0, 64 - key_len);
	}

	/* inner = SHA256(k XOR ipad || msg) */
	for(i = 0; i < 64; i++)
		k_pad[i] ^= 0x36u;
	sha256_init(&ctx);
	sha256_update(&ctx, k_pad, 64);
	sha256_update(&ctx, msg, msg_len);
	sha256_final(&ctx, inner);

	/* restore k_pad to original key */
	for(i = 0; i < 64; i++)
		k_pad[i] ^= (0x36u ^ 0x5cu);

	/* outer = SHA256(k XOR opad || inner) */
	sha256_init(&ctx);
	sha256_update(&ctx, k_pad, 64);
	sha256_update(&ctx, inner, 32);
	sha256_final(&ctx, out);
}

/* Thin wrappers to match our internal call convention */
static void
ophion_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
	sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, data, len);
	sha256_final(&ctx, out);
}

static void
ophion_hmac_sha256(const uint8_t *key, size_t key_len,
                   const uint8_t *msg, size_t msg_len,
                   uint8_t out[32])
{
	hmac_sha256_raw(key, key_len, msg, msg_len, out);
}


/* =========================================================================
 * HMAC key derivation
 *
 *   K = SHA256( sort(fp_local, fp_remote) + ":" + other_fp + ":ophion-services:" )
 * ========================================================================= */

static void
derive_sync_key(const char *fp_local, const char *fp_remote, uint8_t key[32])
{
	if(fp_local == NULL || *fp_local == '\0' ||
	   fp_remote == NULL || *fp_remote == '\0')
	{
		memset(key, 0, 32);
		return;
	}

	const char *first, *second;
	if(strcmp(fp_local, fp_remote) <= 0) {
		first  = fp_local;
		second = fp_remote;
	} else {
		first  = fp_remote;
		second = fp_local;
	}

	/* Build: first + ":" + second + ":ophion-services:" */
	char buf[2048];
	snprintf(buf, sizeof(buf), "%s:%s:ophion-services:", first, second);

	ophion_sha256((const uint8_t *)buf, strlen(buf), key);
}

/* =========================================================================
 * Public HMAC helpers
 * ========================================================================= */

void
svc_sync_hmac(const char *fp_local, const char *fp_remote,
              const char *payload, size_t payload_len,
              char *out_hex, size_t out_len)
{
	if(fp_local == NULL || *fp_local == '\0' ||
	   fp_remote == NULL || *fp_remote == '\0')
	{
		rb_strlcpy(out_hex, "none", out_len);
		return;
	}

	uint8_t key[32];
	derive_sync_key(fp_local, fp_remote, key);

	uint8_t tag[32];
	ophion_hmac_sha256(key, 32, (const uint8_t *)payload, payload_len, tag);

	/* Hex-encode tag */
	static const char hex[] = "0123456789abcdef";
	size_t i, out_pos = 0;
	for(i = 0; i < 32 && out_pos + 2 < out_len - 1; i++) {
		out_hex[out_pos++] = hex[(tag[i] >> 4) & 0x0fu];
		out_hex[out_pos++] = hex[tag[i] & 0x0fu];
	}
	out_hex[out_pos] = '\0';
}

bool
svc_sync_hmac_verify(const char *fp_local, const char *fp_remote,
                     const char *payload, size_t payload_len,
                     const char *expected_hex)
{
	/* Permissive: if no fingerprints or expected is "none", allow */
	if(expected_hex == NULL || strcmp(expected_hex, "none") == 0)
		return true;
	if(fp_local == NULL || *fp_local == '\0' ||
	   fp_remote == NULL || *fp_remote == '\0')
		return true;

	char computed[65];
	svc_sync_hmac(fp_local, fp_remote, payload, payload_len,
	              computed, sizeof(computed));

	/* Constant-time comparison */
	size_t len_c = strlen(computed);
	size_t len_e = strlen(expected_hex);
	uint8_t diff = (len_c != len_e) ? 1 : 0;
	size_t i;
	for(i = 0; i < len_c && i < len_e; i++)
		diff |= (uint8_t)computed[i] ^ (uint8_t)expected_hex[i];
	return diff == 0;
}

/* =========================================================================
 * Hook handlers
 * ========================================================================= */

static void
h_sync_server_introduced(hook_data_client *hdata)
{
	if(hdata->target == NULL || !IsServer(hdata->target))
		return;
	svc_sync_server_linked(hdata->target);
}

static void
h_sync_client_exit(hook_data_client_exit *hdata)
{
	struct Client *target = hdata->target;
	if(target == NULL || !IsServer(target))
		return;
	svc_sync_server_lost(target);
}

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

void
svc_sync_init(void)
{
	add_hook("server_introduced", (hookfn)h_sync_server_introduced);
	add_hook("client_exit",       (hookfn)h_sync_client_exit);
}

void
svc_sync_shutdown(void)
{
	remove_hook("server_introduced", (hookfn)h_sync_server_introduced);
	remove_hook("client_exit",       (hookfn)h_sync_client_exit);
}

/* =========================================================================
 * Server link / lost
 * ========================================================================= */

void
svc_sync_server_linked(struct Client *server_p)
{
	if(!services.enabled)
		return;

	if(services.is_hub) {
		svc_sync_burst_to(server_p);
	} else {
		/*
		 * If this incoming server matches the hub name from config,
		 * enter connected mode.  The hub name is stored in
		 * services.hub_server once set; here we check by server name.
		 */
		if(services.hub_server == NULL && server_p != NULL) {
			/* The hub will send SVCSMODE HUB to identify itself;
			 * for now optimistically track the uplink candidate. */
			services_enter_connected_mode(server_p);
		}
	}
}

void
svc_sync_server_lost(struct Client *server_p)
{
	if(!services.enabled)
		return;

	if(server_p == services.hub_server)
		services_enter_split_mode();
}

/* =========================================================================
 * Hub → leaf burst
 * ========================================================================= */

/* =========================================================================
 * Internal helper: build SVCSREG payload string (shared by burst and prop)
 *
 * Format: "name passhash email ts flags oper_block vhost"
 * ========================================================================= */
static void
build_svcsreg_payload(struct svc_account *acct, char *buf, size_t bufsz)
{
	snprintf(buf, bufsz,
	         "%s %s %s %ld %u %s %s",
	         acct->name, acct->passhash, acct->email,
	         (long)acct->registered_ts, acct->flags,
	         *acct->oper_block ? acct->oper_block : "-",
	         *acct->vhost      ? acct->vhost      : "-");
}

/* =========================================================================
 * Internal helper: build SVCSCHAN payload string (shared by burst and prop)
 *
 * Format: "channel founder ts flags mlock_on mlock_off mlock_limit mlock_key topic"
 *
 * Topic is always last; spaces in topic are preserved because the IRC
 * message puts topic as the trailing parameter (after the hmac field so
 * the hmac itself can be a fixed-position token).
 *
 * Message wire format:
 *   SVCSCHAN channel founder ts flags mlock_on mlock_off mlock_limit
 *            mlock_key hmac :topic
 * ========================================================================= */
static void
build_svcschan_payload(struct svc_chanreg *reg, char *buf, size_t bufsz)
{
	snprintf(buf, bufsz,
	         "%s %s %ld %u %u %u %d %s %s",
	         reg->channel, reg->founder,
	         (long)reg->registered_ts, reg->flags,
	         reg->mlock_on, reg->mlock_off, reg->mlock_limit,
	         *reg->mlock_key ? reg->mlock_key : "-",
	         *reg->topic     ? reg->topic     : "-");
}

/* =========================================================================
 * Hub → leaf burst
 *
 * Order:
 *   1. SVCSMODE HUB
 *   2. SVCSBURST <account_count>
 *   3. SVCSREG × N           (all accounts)
 *   4. SVCSCERT ADD × M      (all certfps)
 *   5. SVCSNICK ADD × P      (all grouped nicks)
 *   6. SVCSCHAN × Q          (all channel registrations)
 *   7. SVCSACCESS SET × R    (all channel access entries)
 *   8. SVCSBURST 0           (burst end marker)
 * ========================================================================= */

void
svc_sync_burst_to(struct Client *server_p)
{
	if(!services.enabled || server_p == NULL)
		return;

	rb_radixtree_iteration_state iter;
	struct svc_account *acct;
	struct svc_chanreg *reg;
	int count = 0;

	/* Count accounts for the burst header */
	RB_RADIXTREE_FOREACH(acct, &iter, svc_account_dict)
		count++;

	/* Announce hub mode so the leaf knows who the authoritative server is */
	sendto_one(server_p, ":%s SVCSMODE HUB", me.id);

	/* Burst start marker — count lets the leaf pre-allocate and log */
	sendto_one(server_p, ":%s SVCSBURST %d", me.id, count);

	/* ---- Phase 1: Account records ---------------------------------------- */
	RB_RADIXTREE_FOREACH(acct, &iter, svc_account_dict) {
		char payload[BUFSIZE];
		build_svcsreg_payload(acct, payload, sizeof(payload));

		char hmac[65];
		svc_sync_hmac(me.certfp, server_p->certfp,
		              payload, strlen(payload), hmac, sizeof(hmac));

		sendto_one(server_p,
		           ":%s SVCSREG %s %s %s %ld %u %s %s %s",
		           me.id,
		           acct->name, acct->passhash, acct->email,
		           (long)acct->registered_ts, acct->flags,
		           *acct->oper_block ? acct->oper_block : "-",
		           *acct->vhost      ? acct->vhost      : "-",
		           hmac);
	}

	/* ---- Phase 2: Certificate fingerprints -------------------------------- */
	RB_RADIXTREE_FOREACH(acct, &iter, svc_account_dict) {
		rb_dlink_node *ptr;
		RB_DLINK_FOREACH(ptr, acct->certfps.head) {
			struct svc_certfp *cf = ptr->data;
			char payload[BUFSIZE];
			snprintf(payload, sizeof(payload), "%s ADD %s %ld",
			         acct->name, cf->fingerprint, (long)cf->added_ts);

			char hmac[65];
			svc_sync_hmac(me.certfp, server_p->certfp,
			              payload, strlen(payload), hmac, sizeof(hmac));

			sendto_one(server_p,
			           ":%s SVCSCERT %s ADD %s %ld %s",
			           me.id, acct->name, cf->fingerprint,
			           (long)cf->added_ts, hmac);
		}
	}

	/* ---- Phase 3: Grouped nicks ------------------------------------------ */
	RB_RADIXTREE_FOREACH(acct, &iter, svc_account_dict) {
		rb_dlink_node *ptr;
		RB_DLINK_FOREACH(ptr, acct->nicks.head) {
			struct svc_nick *sn = ptr->data;
			char payload[BUFSIZE];
			snprintf(payload, sizeof(payload), "ADD %s %s %ld",
			         sn->nick, acct->name, (long)sn->registered_ts);

			char hmac[65];
			svc_sync_hmac(me.certfp, server_p->certfp,
			              payload, strlen(payload), hmac, sizeof(hmac));

			sendto_one(server_p,
			           ":%s SVCSNICK ADD %s %s %ld %s",
			           me.id, sn->nick, acct->name,
			           (long)sn->registered_ts, hmac);
		}
	}

	/* ---- Phase 4: Channel registrations ---------------------------------- */
	RB_RADIXTREE_FOREACH(reg, &iter, svc_chanreg_dict) {
		char payload[BUFSIZE];
		build_svcschan_payload(reg, payload, sizeof(payload));

		char hmac[65];
		svc_sync_hmac(me.certfp, server_p->certfp,
		              payload, strlen(payload), hmac, sizeof(hmac));

		sendto_one(server_p,
		           ":%s SVCSCHAN %s %s %ld %u %u %u %d %s %s :%s",
		           me.id,
		           reg->channel, reg->founder,
		           (long)reg->registered_ts, reg->flags,
		           reg->mlock_on, reg->mlock_off, reg->mlock_limit,
		           *reg->mlock_key ? reg->mlock_key : "-",
		           hmac,
		           *reg->topic ? reg->topic : "-");
	}

	/* ---- Phase 5: Channel access entries --------------------------------- */
	RB_RADIXTREE_FOREACH(reg, &iter, svc_chanreg_dict) {
		rb_dlink_node *ptr;
		RB_DLINK_FOREACH(ptr, reg->access.head) {
			struct svc_chanaccess *ca = ptr->data;
			char payload[BUFSIZE];
			snprintf(payload, sizeof(payload),
			         "SET %s %s %u %s %ld",
			         reg->channel, ca->entity, ca->flags,
			         *ca->setter ? ca->setter : "-",
			         (long)ca->set_ts);

			char hmac[65];
			svc_sync_hmac(me.certfp, server_p->certfp,
			              payload, strlen(payload), hmac, sizeof(hmac));

			sendto_one(server_p,
			           ":%s SVCSACCESS SET %s %s %u %s %ld %s",
			           me.id,
			           reg->channel, ca->entity, ca->flags,
			           *ca->setter ? ca->setter : "-",
			           (long)ca->set_ts, hmac);
		}
	}

	/* Burst end marker */
	sendto_one(server_p, ":%s SVCSBURST 0", me.id);
}

/* =========================================================================
 * Propagation helpers
 *
 * Each sends the appropriate S2S message to all servers using
 * sendto_server(NULL, NULL, CAP_TS6, NOCAPS, ...).
 *
 * HMAC uses me.certfp for both endpoints in the broadcast path (all links
 * share a key derived from our own cert).  Per-link HMACs with individual
 * peer certfps would require iterating over server list — left as a future
 * enhancement for very high-security deployments.
 * ========================================================================= */

void
svc_sync_account_reg(struct svc_account *acct)
{
	if(!services.enabled || acct == NULL)
		return;

	char payload[BUFSIZE];
	build_svcsreg_payload(acct, payload, sizeof(payload));

	char hmac[65];
	svc_sync_hmac(me.certfp, me.certfp, payload, strlen(payload),
	              hmac, sizeof(hmac));

	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
	              ":%s SVCSREG %s %s %s %ld %u %s %s %s",
	              me.id,
	              acct->name, acct->passhash, acct->email,
	              (long)acct->registered_ts, acct->flags,
	              *acct->oper_block ? acct->oper_block : "-",
	              *acct->vhost      ? acct->vhost      : "-",
	              hmac);
}

void
svc_sync_account_drop(const char *name)
{
	if(!services.enabled || name == NULL)
		return;

	char hmac[65];
	svc_sync_hmac(me.certfp, me.certfp, name, strlen(name),
	              hmac, sizeof(hmac));

	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
	              ":%s SVCSDROP %s %s",
	              me.id, name, hmac);
}

void
svc_sync_account_pwd(struct svc_account *acct)
{
	if(!services.enabled || acct == NULL)
		return;

	time_t now = rb_current_time();
	char payload[BUFSIZE];
	snprintf(payload, sizeof(payload), "%s %s %ld",
	         acct->name, acct->passhash, (long)now);

	char hmac[65];
	svc_sync_hmac(me.certfp, me.certfp, payload, strlen(payload),
	              hmac, sizeof(hmac));

	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
	              ":%s SVCSPWD %s %s %ld %s",
	              me.id, acct->name, acct->passhash, (long)now, hmac);
}

void
svc_sync_account_certfp(struct svc_account *acct,
                        const char *certfp, bool adding)
{
	if(!services.enabled || acct == NULL || certfp == NULL)
		return;

	time_t now = rb_current_time();
	char payload[BUFSIZE];
	snprintf(payload, sizeof(payload), "%s %s %s %ld",
	         acct->name, adding ? "ADD" : "DEL", certfp, (long)now);

	char hmac[65];
	svc_sync_hmac(me.certfp, me.certfp, payload, strlen(payload),
	              hmac, sizeof(hmac));

	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
	              ":%s SVCSCERT %s %s %s %ld %s",
	              me.id, acct->name,
	              adding ? "ADD" : "DEL", certfp, (long)now, hmac);
}

void
svc_sync_account_oper(struct svc_account *acct)
{
	if(!services.enabled || acct == NULL)
		return;

	const char *ob = *acct->oper_block ? acct->oper_block : "-";
	char payload[BUFSIZE];
	snprintf(payload, sizeof(payload), "%s %s", acct->name, ob);

	char hmac[65];
	svc_sync_hmac(me.certfp, me.certfp, payload, strlen(payload),
	              hmac, sizeof(hmac));

	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
	              ":%s SVCSOPER %s %s %s",
	              me.id, acct->name, ob, hmac);
}

void
svc_sync_client_id(struct Client *client_p, struct svc_account *acct)
{
	if(!services.enabled || client_p == NULL || acct == NULL)
		return;

	/*
	 * SVCSID propagates client→account identification network-wide.
	 * No HMAC: this is transient session state, already protected by TLS,
	 * and the receiving server validates the account name exists.
	 */
	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
	              ":%s SVCSID %s %s",
	              me.id, use_id(client_p), acct->name);
}

void
svc_sync_chanreg(struct svc_chanreg *reg)
{
	if(!services.enabled || reg == NULL)
		return;

	char payload[BUFSIZE];
	build_svcschan_payload(reg, payload, sizeof(payload));

	char hmac[65];
	svc_sync_hmac(me.certfp, me.certfp, payload, strlen(payload),
	              hmac, sizeof(hmac));

	/*
	 * Wire format:
	 *   SVCSCHAN channel founder ts flags mlock_on mlock_off
	 *            mlock_limit mlock_key hmac :topic
	 *
	 * hmac is a fixed-position token; topic is the trailing parameter
	 * (after ':') so it can safely contain spaces.
	 */
	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
	              ":%s SVCSCHAN %s %s %ld %u %u %u %d %s %s :%s",
	              me.id,
	              reg->channel, reg->founder,
	              (long)reg->registered_ts, reg->flags,
	              reg->mlock_on, reg->mlock_off, reg->mlock_limit,
	              *reg->mlock_key ? reg->mlock_key : "-",
	              hmac,
	              *reg->topic ? reg->topic : "-");
}

void
svc_sync_chandrop(const char *channel)
{
	if(!services.enabled || channel == NULL)
		return;

	char hmac[65];
	svc_sync_hmac(me.certfp, me.certfp, channel, strlen(channel),
	              hmac, sizeof(hmac));

	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
	              ":%s SVCSCDROP %s %s",
	              me.id, channel, hmac);
}

void
svc_sync_chanaccess_set(struct svc_chanreg *reg, struct svc_chanaccess *ca)
{
	if(!services.enabled || reg == NULL || ca == NULL)
		return;

	char payload[BUFSIZE];
	snprintf(payload, sizeof(payload),
	         "SET %s %s %u %s %ld",
	         reg->channel, ca->entity, ca->flags,
	         *ca->setter ? ca->setter : "-",
	         (long)ca->set_ts);

	char hmac[65];
	svc_sync_hmac(me.certfp, me.certfp, payload, strlen(payload),
	              hmac, sizeof(hmac));

	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
	              ":%s SVCSACCESS SET %s %s %u %s %ld %s",
	              me.id,
	              reg->channel, ca->entity, ca->flags,
	              *ca->setter ? ca->setter : "-",
	              (long)ca->set_ts, hmac);
}

void
svc_sync_chanaccess_del(const char *channel, const char *entity)
{
	if(!services.enabled || channel == NULL || entity == NULL)
		return;

	char payload[BUFSIZE];
	snprintf(payload, sizeof(payload), "DEL %s %s", channel, entity);

	char hmac[65];
	svc_sync_hmac(me.certfp, me.certfp, payload, strlen(payload),
	              hmac, sizeof(hmac));

	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
	              ":%s SVCSACCESS DEL %s %s %s",
	              me.id, channel, entity, hmac);
}

void
svc_sync_nick_group(const char *nick, const char *account_name, time_t ts)
{
	if(!services.enabled || nick == NULL || account_name == NULL)
		return;

	char payload[BUFSIZE];
	snprintf(payload, sizeof(payload), "ADD %s %s %ld",
	         nick, account_name, (long)ts);

	char hmac[65];
	svc_sync_hmac(me.certfp, me.certfp, payload, strlen(payload),
	              hmac, sizeof(hmac));

	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
	              ":%s SVCSNICK ADD %s %s %ld %s",
	              me.id, nick, account_name, (long)ts, hmac);
}

void
svc_sync_nick_ungroup(const char *nick)
{
	if(!services.enabled || nick == NULL)
		return;

	char payload[BUFSIZE];
	snprintf(payload, sizeof(payload), "DEL %s", nick);

	char hmac[65];
	svc_sync_hmac(me.certfp, me.certfp, payload, strlen(payload),
	              hmac, sizeof(hmac));

	sendto_server(NULL, NULL, CAP_TS6, NOCAPS,
	              ":%s SVCSNICK DEL %s %s",
	              me.id, nick, hmac);
}
