/*
 * extensions/ip_cloaking_unified.c
 * Copyright (c) 2020 Ariadne Conill <ariadne@dereferenced.org>
 * Copyright (c) 2024 ophion contributors
 *
 * Unified IP cloaking module supporting multiple cloaking styles.
 *
 * This module replaces the four separate cloaking modules
 * (ip_cloaking, ip_cloaking_old, ip_cloaking_3.0, ip_cloaking_4.0)
 * with a single configurable module that supports many cloaking styles.
 *
 * Configuration:
 *   general { cloaking_style = "charybdis"; };
 *
 * Available styles:
 *   charybdis   - FNV-based scrambling (default, from ip_cloaking.c)
 *   legacy      - Old custom hash (from ip_cloaking_old.c)
 *   entropy     - Weighted entropy hash (from ip_cloaking_3.0.c)
 *   hex         - Clean hex segment cloaking (a7f3.b2c1.network)
 *   unrealircd  - UnrealIRCd-style (prefix-HASH.suffix)
 *   words       - Word-based cloaking (brave-tiger-42.network)
 *   geo         - Cloud/CDN-style fake geographic cloaking
 *   account     - Uses SASL account name when available
 *   truncated   - Short compact hash (3f7a2b.cloak.network)
 *   stellar     - Constellation-themed (lyra-vega-42.network)
 *   none/off    - Disable cloaking entirely (+x does nothing)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "hash.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"
#include "hostmask.h"

static const char ip_cloaking_desc[] =
	"Unified IP cloaking module with multiple cloaking styles (+x)";

/* --- Cloaking style enumeration --- */
enum cloak_style {
	CLOAK_CHARYBDIS = 0,
	CLOAK_LEGACY,
	CLOAK_ENTROPY,
	CLOAK_HEX,
	CLOAK_UNREALIRCD,
	CLOAK_WORDS,
	CLOAK_GEO,
	CLOAK_ACCOUNT,
	CLOAK_TRUNCATED,
	CLOAK_STELLAR,
	CLOAK_NONE,
};

static enum cloak_style active_style = CLOAK_CHARYBDIS;

/* --- Forward declarations --- */
static void cloak_ip(const char *inbuf, char *outbuf, struct Client *client_p);
static void cloak_host(const char *inbuf, char *outbuf, struct Client *client_p);
static void update_style_from_config(void);

/* --- Module lifecycle --- */

static int
_modinit(void)
{
	user_modes['x'] = find_umode_slot();
	construct_umodebuf();
	update_style_from_config();
	return 0;
}

static void
_moddeinit(void)
{
	user_modes['x'] = 0;
	construct_umodebuf();
}

static void check_umode_change(void *data);
static void check_new_user(void *data);
static void check_rehash(void *data);

mapi_hfn_list_av1 ip_cloaking_hfnlist[] = {
	{ "umode_changed", (hookfn) check_umode_change },
	{ "new_local_user", (hookfn) check_new_user },
	{ "rehash", (hookfn) check_rehash },
	{ NULL, NULL }
};

DECLARE_MODULE_AV2(ip_cloaking_unified, _modinit, _moddeinit, NULL, NULL,
		   ip_cloaking_hfnlist, NULL, NULL, ip_cloaking_desc);

/* --- Config reload handler --- */
static void
update_style_from_config(void)
{
	const char *style = ConfigFileEntry.cloaking_style;

	if (style == NULL || !*style)
	{
		active_style = CLOAK_CHARYBDIS;
		return;
	}

	if (!rb_strcasecmp(style, "charybdis") || !rb_strcasecmp(style, "fnv"))
		active_style = CLOAK_CHARYBDIS;
	else if (!rb_strcasecmp(style, "legacy") || !rb_strcasecmp(style, "old"))
		active_style = CLOAK_LEGACY;
	else if (!rb_strcasecmp(style, "entropy"))
		active_style = CLOAK_ENTROPY;
	else if (!rb_strcasecmp(style, "hex"))
		active_style = CLOAK_HEX;
	else if (!rb_strcasecmp(style, "unrealircd") || !rb_strcasecmp(style, "unreal"))
		active_style = CLOAK_UNREALIRCD;
	else if (!rb_strcasecmp(style, "words"))
		active_style = CLOAK_WORDS;
	else if (!rb_strcasecmp(style, "geo"))
		active_style = CLOAK_GEO;
	else if (!rb_strcasecmp(style, "account"))
		active_style = CLOAK_ACCOUNT;
	else if (!rb_strcasecmp(style, "truncated") || !rb_strcasecmp(style, "short"))
		active_style = CLOAK_TRUNCATED;
	else if (!rb_strcasecmp(style, "stellar") || !rb_strcasecmp(style, "constellation"))
		active_style = CLOAK_STELLAR;
	else if (!rb_strcasecmp(style, "none") || !rb_strcasecmp(style, "off") || !rb_strcasecmp(style, "disabled"))
		active_style = CLOAK_NONE;
	else
		active_style = CLOAK_CHARYBDIS;
}

static void
check_rehash(void *vdata)
{
	update_style_from_config();
}

/* --- Host distribution (common for all styles) --- */
static void
distribute_hostchange(struct Client *client_p, char *newhost)
{
	if (newhost != client_p->orighost)
		sendto_one_numeric(client_p, RPL_HOSTHIDDEN, "%s :is now your hidden host",
				   newhost);
	else
		sendto_one_numeric(client_p, RPL_HOSTHIDDEN, "%s :hostname reset",
				   newhost);

	sendto_server(NULL, NULL,
		      CAP_EUID | CAP_TS6, NOCAPS, ":%s CHGHOST %s :%s",
		      use_id(&me), use_id(client_p), newhost);
	sendto_server(NULL, NULL,
		      CAP_TS6, CAP_EUID, ":%s ENCAP * CHGHOST %s :%s",
		      use_id(&me), use_id(client_p), newhost);

	change_nick_user_host(client_p, client_p->name, client_p->username, newhost, 0, "Changing host");

	if (newhost != client_p->orighost)
		SetDynSpoof(client_p);
	else
		ClearDynSpoof(client_p);
}

/* ============================================================
 * HASHING PRIMITIVES
 * ============================================================ */

/* FNV-1a 32-bit hash */
static uint32_t
fnv1a_hash(const char *str)
{
	uint32_t hash = 0x811c9dc5;
	const unsigned char *p = (const unsigned char *)str;

	while (*p)
	{
		hash ^= *p++;
		hash += (hash << 1) + (hash << 4) + (hash << 7) +
			(hash << 8) + (hash << 24);
	}
	return hash;
}

/* Secondary hash for additional entropy */
static uint32_t
djb2_hash(const char *str)
{
	uint32_t hash = 5381;
	const unsigned char *p = (const unsigned char *)str;

	while (*p)
	{
		hash = ((hash << 5) + hash) ^ *p++;
	}
	return hash;
}

/* Legacy key constant */
#define LEGACY_KEY 0x13748cfa

/* Entropy constants */
#define ENTROPY_NVAL 0x8c3a48ac
#define ENTROPY_INITDATA "98fwqefnoiqefv03f423t34gbv3vb89tg432t3b8"

static unsigned int
get_string_entropy(const char *inbuf)
{
	unsigned int accum = 1;
	while (*inbuf != '\0')
		accum += *inbuf++;
	return accum;
}

static unsigned int
get_string_weighted_entropy(const char *inbuf)
{
	static unsigned int base_entropy = 0;
	unsigned int accum = get_string_entropy(inbuf);

	if (base_entropy == 0)
		base_entropy = get_string_entropy(ENTROPY_INITDATA);

	return (ENTROPY_NVAL * accum) ^ base_entropy;
}

/* ============================================================
 * STYLE: CHARYBDIS (FNV-based, from ip_cloaking.c)
 * ============================================================ */

static void
charybdis_cloak_ip(const char *inbuf, char *outbuf)
{
	char chartable[] = "ghijklmnopqrstuvwxyz";
	char *tptr;
	uint32_t accum = fnv_hash((const unsigned char *)inbuf, 32);
	int sepcount = 0;
	int totalcount = 0;
	int ipv6 = 0;

	rb_strlcpy(outbuf, inbuf, HOSTLEN + 1);

	if (strchr(outbuf, ':'))
	{
		ipv6 = 1;
		for (tptr = outbuf; *tptr != '\0'; tptr++)
			if (*tptr == ':')
				totalcount++;
	}
	else if (!strchr(outbuf, '.'))
		return;

	for (tptr = outbuf; *tptr != '\0'; tptr++)
	{
		if (*tptr == ':' || *tptr == '.')
		{
			sepcount++;
			continue;
		}

		if (ipv6 && sepcount < totalcount / 2)
			continue;

		if (!ipv6 && sepcount < 2)
			continue;

		*tptr = chartable[(*tptr + accum) % 20];
		accum = (accum << 1) | (accum >> 31);
	}
}

static void
charybdis_cloak_host(const char *inbuf, char *outbuf)
{
	char b26_alphabet[] = "abcdefghijklmnopqrstuvwxyz";
	char *tptr;
	uint32_t accum = fnv_hash((const unsigned char *)inbuf, 32);

	rb_strlcpy(outbuf, inbuf, HOSTLEN + 1);

	for (tptr = outbuf; *tptr != '\0'; tptr++)
	{
		if (*tptr == '.')
			break;

		if (isdigit((unsigned char)*tptr) || *tptr == '-')
			continue;

		*tptr = b26_alphabet[(*tptr + accum) % 26];
		accum = (accum << 1) | (accum >> 31);
	}

	for (tptr = outbuf; *tptr != '\0'; tptr++)
	{
		if (isdigit((unsigned char)*tptr))
			*tptr = '0' + (*tptr + accum) % 10;

		accum = (accum << 1) | (accum >> 31);
	}
}

/* ============================================================
 * STYLE: LEGACY (from ip_cloaking_old.c)
 * ============================================================ */

static void
legacy_cloak(const char *inbuf, char *outbuf, int ipmask)
{
	unsigned int cyc;
	unsigned int hosthash = 1, hosthash2 = 1;
	unsigned int maxcycle = strlen(inbuf);
	int len1;
	const char *rest, *next;

	for (cyc = 0; cyc < maxcycle - 2; cyc += 2)
		hosthash *= (unsigned int)inbuf[cyc];

	for (cyc = maxcycle - 1; cyc >= 1; cyc -= 2)
		hosthash2 *= (unsigned int)inbuf[cyc];

	hosthash += (hosthash2 / LEGACY_KEY);
	hosthash2 += (hosthash / LEGACY_KEY);

	if (ipmask == 0)
	{
		snprintf(outbuf, HOSTLEN, "%s-%X%X",
			 ServerInfo.network_name, hosthash2, hosthash);
		len1 = strlen(outbuf);
		rest = strchr(inbuf, '.');
		if (rest == NULL)
			rest = ".";
		while (len1 + (int)strlen(rest) >= HOSTLEN && (next = strchr(rest + 1, '.')) != NULL)
			rest = next;
		rb_strlcat(outbuf, rest, HOSTLEN);
	}
	else
		snprintf(outbuf, HOSTLEN, "%X%X.%s",
			 hosthash2, hosthash, ServerInfo.network_name);
}

/* ============================================================
 * STYLE: ENTROPY (from ip_cloaking_3.0.c)
 * ============================================================ */

static void
entropy_cloak_ip(const char *inbuf, char *outbuf)
{
	char *tptr;
	unsigned int accum = get_string_weighted_entropy(inbuf);
	char buf[HOSTLEN + 1] = {0};
	int ipv6 = 0;

	strncpy(buf, inbuf, HOSTLEN);
	tptr = strrchr(buf, '.');

	if (tptr == NULL)
	{
		tptr = strrchr(buf, ':');
		ipv6 = 1;
	}

	if (tptr == NULL)
	{
		strncpy(outbuf, inbuf, HOSTLEN);
		return;
	}

	*tptr++ = '\0';

	if (ipv6)
		snprintf(outbuf, HOSTLEN, "%.60s:%x", buf, accum);
	else
		snprintf(outbuf, HOSTLEN, "%.60s.%x", buf, accum);
}

static void
entropy_cloak_host(const char *inbuf, char *outbuf)
{
	char b26_alphabet[] = "abcdefghijklmnopqrstuvwxyz";
	char *tptr;
	unsigned int accum = get_string_weighted_entropy(inbuf);

	strncpy(outbuf, inbuf, HOSTLEN);

	for (tptr = outbuf; *tptr != '\0'; tptr++)
	{
		if (*tptr == '.')
			break;

		if (isdigit((unsigned char)*tptr) || *tptr == '-')
			continue;

		*tptr = b26_alphabet[(*tptr * accum) % 26];
	}

	for (tptr = outbuf; *tptr != '\0'; tptr++)
	{
		if (isdigit((unsigned char)*tptr))
			*tptr = 48 + ((*tptr * accum) % 10);
	}
}

/* ============================================================
 * STYLE: HEX - Clean hex segment cloaking
 *
 * Produces: a7f3.b2c1.d4e5.network
 * Three hex segments derived from the hostname hash,
 * plus network suffix.
 * ============================================================ */

static void
hex_cloak(const char *inbuf, char *outbuf, int is_ip)
{
	uint32_t h1 = fnv1a_hash(inbuf);
	uint32_t h2 = djb2_hash(inbuf);
	uint32_t h3 = h1 ^ h2;

	const char *suffix = ServerInfo.network_name;
	if (suffix == NULL || !*suffix)
		suffix = "cloak";

	snprintf(outbuf, HOSTLEN, "%04x.%04x.%04x.%s",
		 (h1 >> 16) & 0xffff, h2 & 0xffff, h3 & 0xffff, suffix);
}

/* ============================================================
 * STYLE: UNREALIRCD - UnrealIRCd-compatible cloaking
 *
 * Produces: prefix-HEXHASH.suffix
 * For hostnames: preserves TLD, hashes the rest
 * For IPs: full replacement with network suffix
 * ============================================================ */

static void
unrealircd_cloak_ip(const char *inbuf, char *outbuf)
{
	uint32_t h = fnv1a_hash(inbuf);
	const char *suffix = ServerInfo.network_name;
	if (suffix == NULL || !*suffix)
		suffix = "network";

	snprintf(outbuf, HOSTLEN, "%08X.IP.%s", h, suffix);
}

static void
unrealircd_cloak_host(const char *inbuf, char *outbuf)
{
	uint32_t h = fnv1a_hash(inbuf);
	const char *suffix = NULL;
	const char *dot;

	/* find the last two domain labels as suffix */
	dot = strrchr(inbuf, '.');
	if (dot != NULL && dot > inbuf)
	{
		const char *prev = dot - 1;
		while (prev > inbuf && *prev != '.')
			prev--;
		if (*prev == '.')
			prev++;
		suffix = prev;
	}

	if (suffix == NULL)
		suffix = inbuf;

	if ((int)strlen(suffix) + 10 >= HOSTLEN)
		suffix = ServerInfo.network_name ? ServerInfo.network_name : "cloak";

	snprintf(outbuf, HOSTLEN, "%08X.%s", h, suffix);
}

/* ============================================================
 * STYLE: WORDS - Word-based pronounceable cloaking
 *
 * Produces: brave-tiger-42.network
 * Maps hash values to adjective-noun pairs with a
 * numeric suffix for uniqueness.
 * ============================================================ */

static const char *word_adjectives[] = {
	"bold",   "calm",   "dark",   "deep",   "fair",
	"fast",   "free",   "gold",   "keen",   "kind",
	"lost",   "mild",   "neat",   "pale",   "pure",
	"rare",   "rich",   "safe",   "slim",   "soft",
	"tall",   "true",   "vast",   "warm",   "wide",
	"wild",   "wise",   "cool",   "glad",   "last",
	"late",   "long",   "live",   "open",   "real",
	"able",   "blue",   "dear",   "easy",   "fine",
	"full",   "good",   "gray",   "hard",   "high",
	"huge",   "just",   "main",   "next",   "nice",
	"pink",   "left",   "same",   "sure",   "thin",
	"tiny",   "used",   "weak",   "zero",   "firm",
	"flat",   "low",    "new",    "old",    "raw",
};

static const char *word_nouns[] = {
	"arch",   "bark",   "bell",   "bird",   "bone",
	"cave",   "clay",   "cliff",  "cloud",  "coral",
	"crane",  "creek",  "crow",   "dawn",   "deer",
	"delta",  "dove",   "dream",  "drift",  "dune",
	"eagle",  "ember",  "fawn",   "fern",   "field",
	"finch",  "flame",  "flint",  "forge",  "frost",
	"gale",   "gate",   "glade",  "grove",  "hawk",
	"heart",  "hill",   "horn",   "isle",   "jade",
	"lake",   "leaf",   "lark",   "ledge",  "light",
	"marsh",  "maple",  "mist",   "moon",   "moth",
	"oak",    "opal",   "peak",   "pine",   "pond",
	"quail",  "rain",   "reef",   "ridge",  "river",
	"rock",   "rose",   "sage",   "sand",   "shade",
	"shell",  "shore",  "silk",   "slate",  "snow",
	"spark",  "star",   "stone",  "storm",  "swift",
	"thorn",  "tide",   "trail",  "tree",   "vale",
	"vine",   "wave",   "wind",   "wolf",   "wood",
};

#define NUM_ADJECTIVES (sizeof(word_adjectives) / sizeof(word_adjectives[0]))
#define NUM_NOUNS (sizeof(word_nouns) / sizeof(word_nouns[0]))

static void
words_cloak(const char *inbuf, char *outbuf, int is_ip)
{
	uint32_t h1 = fnv1a_hash(inbuf);
	uint32_t h2 = djb2_hash(inbuf);

	const char *adj = word_adjectives[h1 % NUM_ADJECTIVES];
	const char *noun = word_nouns[h2 % NUM_NOUNS];
	unsigned int num = (h1 ^ h2) % 100;

	const char *suffix = ServerInfo.network_name;
	if (suffix == NULL || !*suffix)
		suffix = "cloak";

	snprintf(outbuf, HOSTLEN, "%s-%s-%02u.%s", adj, noun, num, suffix);
}

/* ============================================================
 * STYLE: GEO - Cloud/CDN-style fake geographic cloaking
 *
 * Produces: us-east-7a3f.cdn.network
 * Makes the cloaked host look like a CDN or cloud endpoint.
 * ============================================================ */

static const char *geo_regions[] = {
	"us-east",  "us-west",  "us-cent",  "eu-west",
	"eu-east",  "eu-nord",  "ap-east",  "ap-west",
	"ap-sout",  "sa-east",  "me-sout",  "af-west",
	"oc-east",  "na-east",  "na-west",  "ca-east",
};
#define NUM_GEO_REGIONS (sizeof(geo_regions) / sizeof(geo_regions[0]))

static void
geo_cloak(const char *inbuf, char *outbuf, int is_ip)
{
	uint32_t h1 = fnv1a_hash(inbuf);
	uint32_t h2 = djb2_hash(inbuf);

	const char *region = geo_regions[h1 % NUM_GEO_REGIONS];

	const char *suffix = ServerInfo.network_name;
	if (suffix == NULL || !*suffix)
		suffix = "network";

	snprintf(outbuf, HOSTLEN, "%s-%04x.cdn.%s", region, h2 & 0xffff, suffix);
}

/* ============================================================
 * STYLE: ACCOUNT - SASL account-based cloaking
 *
 * Uses the authenticated account name as part of the cloak.
 * Falls back to hex-style if not authenticated.
 *
 * Produces: accountname.users.network  (when logged in)
 *           a7f3.b2c1.d4e5.network     (when not logged in)
 * ============================================================ */

static void
account_cloak(const char *inbuf, char *outbuf, struct Client *client_p)
{
	const char *suffix = ServerInfo.network_name;
	if (suffix == NULL || !*suffix)
		suffix = "network";

	if (client_p != NULL && client_p->user != NULL && *client_p->user->suser)
	{
		char acct_clean[NICKLEN + 1];
		const char *src = client_p->user->suser;
		char *dst = acct_clean;
		int i = 0;

		while (*src && i < NICKLEN)
		{
			char c = tolower((unsigned char)*src);
			if (IsHostChar(c))
				*dst++ = c;
			src++;
			i++;
		}
		*dst = '\0';

		if (*acct_clean)
		{
			snprintf(outbuf, HOSTLEN, "%s.users.%s", acct_clean, suffix);
			return;
		}
	}

	/* fall back to hex cloaking */
	hex_cloak(inbuf, outbuf, 1);
}

/* ============================================================
 * STYLE: TRUNCATED - Short compact hash cloaking
 *
 * Produces: 3f7a2b.cloak.network
 * A single short hex hash for minimal visual footprint.
 * ============================================================ */

static void
truncated_cloak(const char *inbuf, char *outbuf, int is_ip)
{
	uint32_t h = fnv1a_hash(inbuf) ^ djb2_hash(inbuf);

	const char *suffix = ServerInfo.network_name;
	if (suffix == NULL || !*suffix)
		suffix = "network";

	snprintf(outbuf, HOSTLEN, "%06x.cloak.%s", h & 0xffffff, suffix);
}

/* ============================================================
 * STYLE: STELLAR - Constellation-themed cloaking
 *
 * Produces: lyra-vega-42.network
 * Maps hash values to constellation-star pairs with a
 * numeric suffix.
 * ============================================================ */

static const char *stellar_constellations[] = {
	"lyra",   "orion",  "draco",  "cygnus", "aquila",
	"hydra",  "virgo",  "leo",    "cetus",  "lupus",
	"pavo",   "ara",    "vela",   "pyxis",  "crux",
	"corvus", "norma",  "musca",  "canis",  "lepus",
	"columba","pictor", "fornax", "dorado", "phoenix",
	"tucana", "grus",   "indus",  "volans", "mensa",
	"apus",   "scutum",
};

static const char *stellar_stars[] = {
	"vega",   "rigel",  "spica",  "deneb",  "altair",
	"sirius", "polaris","castor", "mira",   "atlas",
	"capella","achernar","procyon","canopus","antares",
	"regulus","bellatrix","mimosa","acrux",  "naos",
	"suhail", "avior",  "menkib", "hadar",  "shaula",
	"sargas", "dschubba","nunki", "kaus",   "alnilam",
	"alnitak","mintaka",
};

#define NUM_CONSTELLATIONS (sizeof(stellar_constellations) / sizeof(stellar_constellations[0]))
#define NUM_STARS (sizeof(stellar_stars) / sizeof(stellar_stars[0]))

static void
stellar_cloak(const char *inbuf, char *outbuf, int is_ip)
{
	uint32_t h1 = fnv1a_hash(inbuf);
	uint32_t h2 = djb2_hash(inbuf);

	const char *constellation = stellar_constellations[h1 % NUM_CONSTELLATIONS];
	const char *star = stellar_stars[h2 % NUM_STARS];
	unsigned int num = (h1 ^ h2) % 100;

	const char *suffix = ServerInfo.network_name;
	if (suffix == NULL || !*suffix)
		suffix = "network";

	snprintf(outbuf, HOSTLEN, "%s-%s-%02u.%s", constellation, star, num, suffix);
}

/* ============================================================
 * STYLE DISPATCHER
 * ============================================================ */

static void
cloak_ip(const char *inbuf, char *outbuf, struct Client *client_p)
{
	switch (active_style)
	{
	case CLOAK_CHARYBDIS:
		charybdis_cloak_ip(inbuf, outbuf);
		break;
	case CLOAK_LEGACY:
		legacy_cloak(inbuf, outbuf, 1);
		break;
	case CLOAK_ENTROPY:
		entropy_cloak_ip(inbuf, outbuf);
		break;
	case CLOAK_HEX:
		hex_cloak(inbuf, outbuf, 1);
		break;
	case CLOAK_UNREALIRCD:
		unrealircd_cloak_ip(inbuf, outbuf);
		break;
	case CLOAK_WORDS:
		words_cloak(inbuf, outbuf, 1);
		break;
	case CLOAK_GEO:
		geo_cloak(inbuf, outbuf, 1);
		break;
	case CLOAK_ACCOUNT:
		account_cloak(inbuf, outbuf, client_p);
		break;
	case CLOAK_TRUNCATED:
		truncated_cloak(inbuf, outbuf, 1);
		break;
	case CLOAK_STELLAR:
		stellar_cloak(inbuf, outbuf, 1);
		break;
	case CLOAK_NONE:
		rb_strlcpy(outbuf, inbuf, HOSTLEN + 1);
		break;
	}
}

static void
cloak_host(const char *inbuf, char *outbuf, struct Client *client_p)
{
	switch (active_style)
	{
	case CLOAK_CHARYBDIS:
		charybdis_cloak_host(inbuf, outbuf);
		break;
	case CLOAK_LEGACY:
		legacy_cloak(inbuf, outbuf, 0);
		break;
	case CLOAK_ENTROPY:
		entropy_cloak_host(inbuf, outbuf);
		break;
	case CLOAK_HEX:
		hex_cloak(inbuf, outbuf, 0);
		break;
	case CLOAK_UNREALIRCD:
		unrealircd_cloak_host(inbuf, outbuf);
		break;
	case CLOAK_WORDS:
		words_cloak(inbuf, outbuf, 0);
		break;
	case CLOAK_GEO:
		geo_cloak(inbuf, outbuf, 0);
		break;
	case CLOAK_ACCOUNT:
		account_cloak(inbuf, outbuf, client_p);
		break;
	case CLOAK_TRUNCATED:
		truncated_cloak(inbuf, outbuf, 0);
		break;
	case CLOAK_STELLAR:
		stellar_cloak(inbuf, outbuf, 0);
		break;
	case CLOAK_NONE:
		rb_strlcpy(outbuf, inbuf, HOSTLEN + 1);
		break;
	}
}

/* ============================================================
 * HOOK HANDLERS
 * ============================================================ */

static void
check_umode_change(void *vdata)
{
	hook_data_umode_changed *data = (hook_data_umode_changed *)vdata;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	if (!((data->oldumodes ^ source_p->umodes) & user_modes['x']))
		return;

	/* cloaking disabled: silently strip +x */
	if (active_style == CLOAK_NONE)
	{
		source_p->umodes &= ~user_modes['x'];
		return;
	}

	if (source_p->umodes & user_modes['x'])
	{
		if (IsIPSpoof(source_p) || source_p->localClient->mangledhost == NULL ||
		    (IsDynSpoof(source_p) && strcmp(source_p->host, source_p->localClient->mangledhost)))
		{
			source_p->umodes &= ~user_modes['x'];
			return;
		}
		if (strcmp(source_p->host, source_p->localClient->mangledhost))
		{
			distribute_hostchange(source_p, source_p->localClient->mangledhost);
		}
		else
			sendto_one_numeric(source_p, RPL_HOSTHIDDEN, "%s :is now your hidden host",
					   source_p->host);
	}
	else if (!(source_p->umodes & user_modes['x']))
	{
		if (source_p->localClient->mangledhost != NULL &&
		    !strcmp(source_p->host, source_p->localClient->mangledhost))
		{
			distribute_hostchange(source_p, source_p->orighost);
		}
	}
}

static void
check_new_user(void *vdata)
{
	struct Client *source_p = (void *)vdata;

	if (IsIPSpoof(source_p))
	{
		source_p->umodes &= ~user_modes['x'];
		return;
	}
	source_p->localClient->mangledhost = rb_malloc(HOSTLEN + 1);
	if (!irccmp(source_p->orighost, source_p->sockhost))
		cloak_ip(source_p->orighost, source_p->localClient->mangledhost, source_p);
	else
		cloak_host(source_p->orighost, source_p->localClient->mangledhost, source_p);
	if (IsDynSpoof(source_p))
		source_p->umodes &= ~user_modes['x'];
	if (source_p->umodes & user_modes['x'])
	{
		rb_strlcpy(source_p->host, source_p->localClient->mangledhost, sizeof(source_p->host));
		if (irccmp(source_p->host, source_p->orighost))
			SetDynSpoof(source_p);
	}
}
