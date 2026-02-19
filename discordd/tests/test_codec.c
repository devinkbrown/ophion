/*
 * discordd/tests/test_codec.c
 *
 * Unit tests for the pure codec functions used by the Discord bridge:
 *   - pct_encode / pct_decode  (percent-encoding for the IPC wire protocol)
 *   - sanitise_nick             (Discord username → valid IRC nick)
 *   - json_str / json_int       (minimal JSON field extractor)
 *   - wire protocol field counts (P / E / Y / D line format)
 *
 * These functions are pulled in by #including discordd.c with DISCORD_NO_MAIN
 * defined so that only the pure-C helpers are compiled (no TLS/socket code
 * reaches the linker because those call-sites remain in functions we never
 * call from this test binary).
 *
 * Build:  cc -DDISCORD_NO_MAIN -o test_codec test_codec.c -lssl -lcrypto
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Minimal stubs required by discordd.c globals that are referenced at
 * compile time but not reachable from the functions under test.
 * ---------------------------------------------------------------------- */

/* Bring in the implementation under test (DISCORD_NO_MAIN passed via -D). */
#include "../discordd.c"

/* -------------------------------------------------------------------------
 * Test framework
 * ---------------------------------------------------------------------- */

static int g_failures = 0;
static int g_checks   = 0;

#define CHECK(cond) \
	do { \
		g_checks++; \
		if(!(cond)) { \
			fprintf(stderr, "FAIL  %s:%d  %s\n", \
				__FILE__, __LINE__, #cond); \
			g_failures++; \
		} \
	} while(0)

#define CHECK_STR(got, expected) \
	do { \
		g_checks++; \
		if(strcmp((got), (expected)) != 0) { \
			fprintf(stderr, "FAIL  %s:%d  got \"%s\", want \"%s\"\n", \
				__FILE__, __LINE__, (got), (expected)); \
			g_failures++; \
		} \
	} while(0)

/* -------------------------------------------------------------------------
 * pct_encode / pct_decode tests
 * ---------------------------------------------------------------------- */

static void
test_pct_roundtrip(void)
{
	char enc[512], dec[512];

	/* Plain ASCII — should pass through unchanged. */
	pct_encode("hello", enc, sizeof(enc));
	CHECK_STR(enc, "hello");

	/* Space must be encoded. */
	pct_encode("hello world", enc, sizeof(enc));
	CHECK_STR(enc, "hello%20world");

	pct_decode(enc);
	CHECK_STR(enc, "hello world");

	/* Percent sign itself must be encoded. */
	pct_encode("100%", enc, sizeof(enc));
	CHECK_STR(enc, "100%25");

	pct_decode(enc);
	CHECK_STR(enc, "100%");

	/* Newline and carriage-return must be encoded. */
	pct_encode("line1\nline2\r\n", enc, sizeof(enc));
	/* Verify no raw newlines remain in encoded output. */
	CHECK(strchr(enc, '\n') == NULL);
	CHECK(strchr(enc, '\r') == NULL);

	pct_decode(enc);
	CHECK_STR(enc, "line1\nline2\r\n");

	/* Empty string. */
	pct_encode("", enc, sizeof(enc));
	CHECK_STR(enc, "");

	/* Decode of plain (no %-sequences) is identity. */
	strlcpy(dec, "no encoding here", sizeof(dec));
	pct_decode(dec);
	CHECK_STR(dec, "no encoding here");

	/* Chained encode of a realistic Discord message. */
	pct_encode("Hello <@123456>! How are you?", enc, sizeof(enc));
	CHECK(strchr(enc, ' ') == NULL);  /* spaces gone */
	pct_decode(enc);
	CHECK_STR(enc, "Hello <@123456>! How are you?");
}

static void
test_pct_partial_sequence(void)
{
	/* A lone '%' at the end should decode to itself (or the trailing chars). */
	char buf[32];
	strlcpy(buf, "test%", sizeof(buf));
	/* pct_decode skips incomplete sequences gracefully — just copies '%'. */
	pct_decode(buf);
	/* Must not crash and must not truncate "test". */
	CHECK(strncmp(buf, "test", 4) == 0);
}

/* -------------------------------------------------------------------------
 * sanitise_nick tests
 * ---------------------------------------------------------------------- */

static void
test_sanitise_nick(void)
{
	char nick[64];

	/* Normal name — should pass through. */
	sanitise_nick("alice", nick, sizeof(nick));
	CHECK_STR(nick, "alice");

	/* Spaces become underscores. */
	sanitise_nick("some user", nick, sizeof(nick));
	CHECK_STR(nick, "some_user");

	/* Leading digit must be prefixed with underscore. */
	sanitise_nick("1stUser", nick, sizeof(nick));
	CHECK(nick[0] == '_');
	CHECK(strstr(nick, "1stUser") || strstr(nick, "stUser"));

	/* Leading dash must be prefixed with underscore. */
	sanitise_nick("-Bot", nick, sizeof(nick));
	CHECK(nick[0] == '_');

	/* IRC-safe special characters should survive. */
	sanitise_nick("user[away]", nick, sizeof(nick));
	CHECK_STR(nick, "user[away]");

	/* Non-IRC characters (e.g. Unicode replaced by nothing). */
	sanitise_nick("caf\xc3\xa9", nick, sizeof(nick));   /* "café" */
	/* At minimum it should not crash and produce a non-empty nick. */
	CHECK(nick[0] != '\0');

	/* All-invalid source → fallback to "Discord_User". */
	sanitise_nick("\xc3\xa9\xc3\xa9", nick, sizeof(nick));  /* purely non-ASCII */
	CHECK_STR(nick, "Discord_User");

	/* Length capped at DISCORD_NICK_LEN (30). */
	sanitise_nick("aabbccddeeffgghhiijjkkllmmnnoo1234", nick, sizeof(nick));
	CHECK(strlen(nick) <= 30);
}

/* -------------------------------------------------------------------------
 * json_str / json_int / json_obj tests
 * ---------------------------------------------------------------------- */

static void
test_json_str(void)
{
	const char *json = "{\"username\":\"alice\",\"id\":\"123456\"}";
	char val[64];

	CHECK(json_str(json, "username", val, sizeof(val)));
	CHECK_STR(val, "alice");

	CHECK(json_str(json, "id", val, sizeof(val)));
	CHECK_STR(val, "123456");

	/* Missing key returns 0 and leaves buf untouched. */
	strlcpy(val, "original", sizeof(val));
	CHECK(!json_str(json, "missing", val, sizeof(val)));
}

static void
test_json_int(void)
{
	const char *json = "{\"heartbeat_interval\":41250}";
	long v = 0;

	CHECK(json_int(json, "heartbeat_interval", &v));
	CHECK(v == 41250);

	CHECK(!json_int(json, "not_there", &v));
}

static void
test_json_obj(void)
{
	const char *json = "{\"author\":{\"username\":\"bob\",\"id\":\"999\"}}";
	const char *obj;
	char val[64];

	obj = json_obj(json, "author");
	CHECK(obj != NULL);

	CHECK(json_str(obj, "username", val, sizeof(val)));
	CHECK_STR(val, "bob");

	CHECK(json_str(obj, "id", val, sizeof(val)));
	CHECK_STR(val, "999");

	/* Missing object returns NULL. */
	CHECK(json_obj(json, "missing") == NULL);
}

/* -------------------------------------------------------------------------
 * Wire protocol format tests
 *
 * Verify that the lines ircd_write() would produce have the expected number
 * of space-delimited fields when parsed by a simple splitter (mimicking
 * rb_string_to_array from librb).
 * ---------------------------------------------------------------------- */

/*
 * A minimal reimplementation of rb_string_to_array so this test is fully
 * self-contained.
 */
static int
split(char *line, char **argv, int max)
{
	int n = 0;
	char *p = line;
	while(*p == ' ') p++;
	while(*p && n < max) {
		if(*p == ':') { argv[n++] = p + 1; break; }
		argv[n++] = p;
		p = strchr(p, ' ');
		if(!p) break;
		*p++ = '\0';
		while(*p == ' ') p++;
	}
	return n;
}

static void
test_wire_protocol_P(void)
{
	/* P <cid> <uid> <nick> <mid> :<enc_text> */
	char line[256];
	char *argv[16];
	int parc;

	strlcpy(line,
		"P 987654321 111222333 alice abc123 :Hello%20world",
		sizeof(line));
	parc = split(line, argv, 16);

	CHECK(parc == 6);
	CHECK_STR(argv[0], "P");
	CHECK_STR(argv[1], "987654321");   /* channel_id */
	CHECK_STR(argv[2], "111222333");   /* user_id */
	CHECK_STR(argv[3], "alice");       /* nick */
	CHECK_STR(argv[4], "abc123");      /* msg_id */
	CHECK_STR(argv[5], "Hello%20world"); /* encoded text (colon stripped) */
}

static void
test_wire_protocol_E(void)
{
	/* E <cid> <mid> <uid> <nick> :<enc_text> */
	char line[256];
	char *argv[16];
	int parc;

	strlcpy(line,
		"E 987654321 abc123 111222333 alice :Edited%20text",
		sizeof(line));
	parc = split(line, argv, 16);

	CHECK(parc == 6);
	CHECK_STR(argv[0], "E");
	CHECK_STR(argv[1], "987654321");  /* channel_id */
	CHECK_STR(argv[2], "abc123");     /* msg_id */
	CHECK_STR(argv[3], "111222333");  /* user_id */
	CHECK_STR(argv[4], "alice");      /* nick */
	CHECK_STR(argv[5], "Edited%20text");
}

static void
test_wire_protocol_Y(void)
{
	/* Y <cid> <uid> <nick> */
	char line[128];
	char *argv[16];
	int parc;

	strlcpy(line, "Y 987654321 111222333 alice", sizeof(line));
	parc = split(line, argv, 16);

	CHECK(parc == 4);
	CHECK_STR(argv[0], "Y");
	CHECK_STR(argv[1], "987654321");
	CHECK_STR(argv[2], "111222333");
	CHECK_STR(argv[3], "alice");
}

static void
test_wire_protocol_D(void)
{
	/* D <cid> <mid> */
	char line[128];
	char *argv[16];
	int parc;

	strlcpy(line, "D 987654321 abc123", sizeof(line));
	parc = split(line, argv, 16);

	CHECK(parc == 3);
	CHECK_STR(argv[0], "D");
	CHECK_STR(argv[1], "987654321");
	CHECK_STR(argv[2], "abc123");
}

static void
test_wire_protocol_G(void)
{
	/* G <guild_name_pct> */
	char line[128];
	char *argv[16];
	int parc;

	strlcpy(line, "G My%20Server", sizeof(line));
	parc = split(line, argv, 16);

	CHECK(parc == 2);
	CHECK_STR(argv[0], "G");
	CHECK_STR(argv[1], "My%20Server");
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

int
main(void)
{
	printf("=== Discord bridge codec tests ===\n");

	test_pct_roundtrip();
	test_pct_partial_sequence();
	test_sanitise_nick();
	test_json_str();
	test_json_int();
	test_json_obj();
	test_wire_protocol_P();
	test_wire_protocol_E();
	test_wire_protocol_Y();
	test_wire_protocol_D();
	test_wire_protocol_G();

	printf("%d check(s) run, %d failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
