/*
 * discordd/discordd.c - Discord gateway bridge daemon
 *
 * Copyright (c) 2024 ophion contributors
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

/*
 * Overview
 * --------
 * discordd is a standalone helper daemon (no librb dependency) that bridges
 * the Ophion IRC daemon with the Discord Gateway WebSocket API.
 *
 * It is spawned by ircd via rb_helper_start().  Communication with ircd uses
 * the two pipe fds passed in the IFD / OFD environment variables as
 * newline-terminated text lines (same convention as authd/ssld).
 *
 * IFD — discordd reads ircd commands from this fd.
 * OFD — discordd writes events/replies to this fd.
 *
 * Gateway URL: wss://gateway.discord.gg/?v=10&encoding=json
 *
 * Gateway opcodes used:
 *    0  Dispatch   recv — events (MESSAGE_CREATE, READY, etc.)
 *    1  Heartbeat  send — keep-alive ping
 *    2  Identify   send — authenticate
 *    6  Resume     send — reconnect with existing session
 *    7  Reconnect  recv — server wants us to reconnect
 *    9  Invalid    recv — session invalid, re-identify
 *   10  Hello      recv — gives heartbeat_interval
 *   11  HB ACK     recv — heartbeat acknowledged
 *
 * Wire protocol (newline-terminated lines):
 *
 *   ircd -> discordd:
 *     C <token> <guild_id>
 *     B <discord_channel_id> <irc_channel>    (channel map entry)
 *     M <channel_id> <nick_pct> :<text_pct>   (send message)
 *     T <channel_id>                           (send typing)
 *
 *   discordd -> ircd:
 *     G <guild_name_pct>
 *     P <channel_id> <user_id> <nick> <msgid> :<text_pct>
 *     Y <channel_id> <user_id> <nick>
 *     D <channel_id> <msgid>
 *     E <channel_id> <msgid> :<text_pct>
 *     W <level> :<message_pct>   (level: D I W C)
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

#define DISCORD_GW_HOST   "gateway.discord.gg"
#define DISCORD_GW_PORT   "443"
#define DISCORD_GW_PATH   "/?v=10&encoding=json"
#define DISCORD_API_HOST  "discord.com"
#define DISCORD_API_PORT  "443"

/* Guild intents: GUILD_MESSAGES | MESSAGE_CONTENT | GUILD_MESSAGE_TYPING */
#define DISCORD_INTENTS   33792

#define RXBUF_SZ   65536
#define LBUF_SZ    65536
#define MAXPARA    12

/* -------------------------------------------------------------------------
 * IPC — pipe fds to/from ircd
 * ---------------------------------------------------------------------- */

static int ircd_rfd = -1;   /* read ircd commands from here (IFD) */
static int ircd_wfd = -1;   /* write events to ircd via here (OFD) */

/* Output line buffer (flushed on each loop iteration) */
static char   ircd_wbuf[LBUF_SZ];
static size_t ircd_wbuf_len = 0;

static void __attribute__((format(printf,1,2)))
ircd_write(const char *fmt, ...)
{
	va_list ap;
	char line[4096];
	size_t len;

	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);

	len = strlen(line);
	if(len + 2 > sizeof(ircd_wbuf) - ircd_wbuf_len)
		return;

	memcpy(ircd_wbuf + ircd_wbuf_len, line, len);
	ircd_wbuf_len += len;
	ircd_wbuf[ircd_wbuf_len++] = '\n';
}

static void
ircd_flush(void)
{
	size_t off = 0;
	ssize_t n;

	while(off < ircd_wbuf_len)
	{
		n = write(ircd_wfd, ircd_wbuf + off, ircd_wbuf_len - off);
		if(n < 0) {
			if(errno == EAGAIN || errno == EWOULDBLOCK) break;
			if(errno == EINTR) continue;
			exit(1);
		}
		off += (size_t)n;
	}
	if(off > 0 && off < ircd_wbuf_len)
		memmove(ircd_wbuf, ircd_wbuf + off, ircd_wbuf_len - off);
	ircd_wbuf_len -= off;
}

/* -------------------------------------------------------------------------
 * Percent-encoding helpers (space/newline/CR/% → %XX)
 * ---------------------------------------------------------------------- */

static void
pct_encode(const char *src, char *dst, size_t dstsz)
{
	size_t i = 0;
	while(*src && i + 4 < dstsz) {
		unsigned char c = (unsigned char)*src;
		if(c == ' ' || c == '\n' || c == '\r' || c == '%') {
			dst[i++] = '%';
			dst[i++] = "0123456789ABCDEF"[c >> 4];
			dst[i++] = "0123456789ABCDEF"[c & 0xF];
		} else
			dst[i++] = c;
		src++;
	}
	dst[i] = '\0';
}

static int hx(char c)
{
	if(c>='0'&&c<='9') return c-'0';
	if(c>='A'&&c<='F') return c-'A'+10;
	if(c>='a'&&c<='f') return c-'a'+10;
	return 0;
}

static void
pct_decode(char *s)
{
	char *r = s, *w = s;
	while(*r) {
		if(*r=='%' && r[1] && r[2]) { *w++ = (char)((hx(r[1])<<4)|hx(r[2])); r+=3; }
		else *w++ = *r++;
	}
	*w = '\0';
}

/* -------------------------------------------------------------------------
 * IRC nick sanitisation
 * ---------------------------------------------------------------------- */

static void
sanitise_nick(const char *src, char *dst, size_t dstsz)
{
	size_t i = 0, max = dstsz - 1;
	if(max > 30) max = 30;
	if(*src == '-' || (*src >= '0' && *src <= '9')) dst[i++] = '_';
	while(*src && i < max) {
		unsigned char c = (unsigned char)*src;
		if(c == ' ') dst[i++] = '_';
		else if((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||
			c=='_'||c=='-'||c=='['||c==']'||c=='\\'||c=='`'||
			c=='^'||c=='{'||c=='|'||c=='}')
			dst[i++] = c;
		src++;
	}
	if(i==0) { strncpy(dst,"Discord_User",dstsz-1); dst[dstsz-1]='\0'; return; }
	dst[i] = '\0';
}

/* -------------------------------------------------------------------------
 * Simple line tokeniser
 * Trailing parameter starts with ':' and may contain spaces.
 * ---------------------------------------------------------------------- */

static int
tokenise(char *line, char **argv, int maxargv)
{
	int argc = 0;
	char *p = line;

	while(*p && argc < maxargv - 1) {
		while(*p == ' ') p++;
		if(!*p) break;
		if(*p == ':') { argv[argc++] = p + 1; break; }
		argv[argc++] = p;
		while(*p && *p != ' ') p++;
		if(*p) *p++ = '\0';
	}
	argv[argc] = NULL;
	return argc;
}

/* -------------------------------------------------------------------------
 * Minimal JSON field extractor
 * ---------------------------------------------------------------------- */

static int
json_str(const char *json, const char *key, char *out, size_t outsz)
{
	char needle[256];
	const char *p;
	size_t i = 0;

	snprintf(needle, sizeof(needle), "\"%s\"", key);
	p = strstr(json, needle);
	if(!p) return 0;
	p += strlen(needle);
	while(*p==' '||*p==':'||*p=='\t') p++;
	if(*p != '"') return 0;
	p++;
	while(*p && *p!='"' && i<outsz-1) {
		if(*p=='\\') { p++; if(!*p) break; }
		out[i++] = *p++;
	}
	out[i] = '\0';
	return 1;
}

static int
json_int(const char *json, const char *key, long *out)
{
	char needle[256];
	const char *p;
	snprintf(needle, sizeof(needle), "\"%s\"", key);
	p = strstr(json, needle);
	if(!p) return 0;
	p += strlen(needle);
	while(*p==' '||*p==':'||*p=='\t') p++;
	if(*p == '"') p++;
	*out = strtol(p, NULL, 10);
	return 1;
}

static const char *
json_obj(const char *json, const char *key)
{
	char needle[256];
	const char *p;
	snprintf(needle, sizeof(needle), "\"%s\"", key);
	p = strstr(json, needle);
	if(!p) return NULL;
	p += strlen(needle);
	while(*p==' '||*p==':'||*p=='\t') p++;
	return (*p=='{') ? p : NULL;
}

/* -------------------------------------------------------------------------
 * Base64 encode via OpenSSL EVP
 * ---------------------------------------------------------------------- */

static int
b64enc(const unsigned char *src, int slen, char *dst, int dsz)
{
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO *mem = BIO_new(BIO_s_mem());
	BUF_MEM *bptr;
	int len;

	b64 = BIO_push(b64, mem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b64, src, slen);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);
	len = (int)bptr->length;
	if(len >= dsz) len = dsz - 1;
	memcpy(dst, bptr->data, len);
	dst[len] = '\0';
	BIO_free_all(b64);
	return len;
}

/* -------------------------------------------------------------------------
 * TLS helpers
 * ---------------------------------------------------------------------- */

static SSL_CTX *
new_ssl_ctx(void)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if(!ctx) return NULL;
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_default_verify_paths(ctx);
	return ctx;
}

static int
tcp_connect(const char *host, const char *port)
{
	struct addrinfo hints, *res, *rp;
	int fd = -1;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if(getaddrinfo(host, port, &hints, &res) != 0) return -1;
	for(rp = res; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(fd==-1) continue;
		if(connect(fd, rp->ai_addr, rp->ai_addrlen)==0) break;
		close(fd); fd = -1;
	}
	freeaddrinfo(res);
	return fd;
}

/* -------------------------------------------------------------------------
 * Gateway state
 * ---------------------------------------------------------------------- */

static char  gw_token[512]   = "";
static char  gw_guild_id[32] = "";

typedef struct { char id[32]; char irc[256]; } ChanMap;
static ChanMap chanmap[256];
static int     chanmap_len = 0;

static int      gw_fd  = -1;
static SSL_CTX *gw_ctx = NULL;
static SSL     *gw_ssl = NULL;

static int    gw_hb_ms   = 0;
static time_t gw_hb_due  = 0;
static int    gw_seq      = -1;
static int    gw_ack_pend = 0;
static int    gw_up       = 0;

static char   gw_sid[128] = "";
static char   gw_rurl[256] = "";
static int    gw_resume   = 0;

static char   gw_rxbuf[RXBUF_SZ];
static size_t gw_rxbuf_len = 0;

/* -------------------------------------------------------------------------
 * WebSocket frame send (masked text frame as required by RFC 6455)
 * ---------------------------------------------------------------------- */

static int
ws_send(const char *data, size_t dlen)
{
	unsigned char frame[RXBUF_SZ + 14];
	unsigned char mask[4];
	size_t hlen = 0, i;

	if(!gw_ssl) return -1;
	if(RAND_bytes(mask, 4) != 1) { mask[0]=0xDE; mask[1]=0xAD; mask[2]=0xBE; mask[3]=0xEF; }

	frame[hlen++] = 0x81; /* FIN + opcode 1 (text) */
	if(dlen <= 125)
		frame[hlen++] = (unsigned char)(0x80 | dlen);
	else if(dlen <= 65535) {
		frame[hlen++] = 0xFE;
		frame[hlen++] = (unsigned char)((dlen>>8)&0xFF);
		frame[hlen++] = (unsigned char)(dlen&0xFF);
	} else {
		frame[hlen++] = 0xFF;
		frame[hlen++] = 0; frame[hlen++] = 0; frame[hlen++] = 0; frame[hlen++] = 0;
		frame[hlen++] = (unsigned char)((dlen>>24)&0xFF);
		frame[hlen++] = (unsigned char)((dlen>>16)&0xFF);
		frame[hlen++] = (unsigned char)((dlen>>8)&0xFF);
		frame[hlen++] = (unsigned char)(dlen&0xFF);
	}
	frame[hlen++] = mask[0]; frame[hlen++] = mask[1];
	frame[hlen++] = mask[2]; frame[hlen++] = mask[3];

	if(hlen + dlen > sizeof(frame)) return -1;
	for(i = 0; i < dlen; i++)
		frame[hlen+i] = ((unsigned char)data[i]) ^ mask[i&3];

	return SSL_write(gw_ssl, frame, (int)(hlen+dlen));
}

/* -------------------------------------------------------------------------
 * Gateway — heartbeat and identify payloads
 * ---------------------------------------------------------------------- */

static void
gw_send_heartbeat(void)
{
	char buf[64];
	if(gw_seq >= 0) snprintf(buf, sizeof(buf), "{\"op\":1,\"d\":%d}", gw_seq);
	else            snprintf(buf, sizeof(buf), "{\"op\":1,\"d\":null}");
	ws_send(buf, strlen(buf));
	gw_ack_pend = 1;
	gw_hb_due   = time(NULL) + (gw_hb_ms > 0 ? gw_hb_ms / 1000 : 45);
}

static void
gw_send_identify(void)
{
	char buf[1024];
	snprintf(buf, sizeof(buf),
		"{\"op\":2,\"d\":{\"token\":\"%s\",\"intents\":%d,"
		"\"properties\":{\"os\":\"linux\",\"browser\":\"ophion\",\"device\":\"ophion\"}}}",
		gw_token, DISCORD_INTENTS);
	ws_send(buf, strlen(buf));
}

static void
gw_send_resume(void)
{
	char buf[512];
	snprintf(buf, sizeof(buf),
		"{\"op\":6,\"d\":{\"token\":\"%s\",\"session_id\":\"%s\",\"seq\":%d}}",
		gw_token, gw_sid, gw_seq);
	ws_send(buf, strlen(buf));
}

/* -------------------------------------------------------------------------
 * Process a complete Discord Gateway JSON dispatch
 * ---------------------------------------------------------------------- */

static void
handle_gw_frame(const char *json)
{
	long op = 0;
	char ev[64] = "";
	const char *d;

	json_int(json, "op", &op);
	json_str(json, "t", ev, sizeof(ev));
	{ long s; if(json_int(json,"s",&s) && s>0) gw_seq = (int)s; }

	d = json_obj(json, "d");
	if(!d) d = "{}";

	switch(op)
	{
	case 10: {
		long ms = 0;
		json_int(d, "heartbeat_interval", &ms);
		gw_hb_ms = (int)ms;
		ircd_write("W I :Discord HELLO, heartbeat interval %ldms", ms);
		gw_send_heartbeat();
		if(gw_resume && gw_sid[0]) gw_send_resume();
		else gw_send_identify();
		break;
	}
	case 11: gw_ack_pend = 0; break;
	case  1: gw_send_heartbeat(); break;
	case  7:
		ircd_write("W I :Discord requested reconnect");
		gw_resume = 1; gw_up = 0;
		break;
	case  9: {
		long ok = 0; json_int(json,"d",&ok);
		if(!ok) { gw_sid[0]='\0'; gw_resume=0; }
		ircd_write("W W :Discord invalid session (resumable=%ld)", ok);
		sleep(5); gw_send_identify();
		break;
	}
	case 0:
		if(strcmp(ev,"READY")==0)
		{
			char gname[256]="unknown", enc[512];
			json_str(d,"session_id", gw_sid, sizeof(gw_sid));
			json_str(d,"resume_gateway_url", gw_rurl, sizeof(gw_rurl));
			gw_resume = 1;
			{ const char *g=strstr(d,"\"guilds\"");
			  if(g){const char *p=strstr(g,"\"properties\"");
			    if(p) json_str(p,"name",gname,sizeof(gname));} }
			pct_encode(gname, enc, sizeof(enc));
			ircd_write("G %s", enc);
		}
		else if(strcmp(ev,"MESSAGE_CREATE")==0)
		{
			char cid[32],mid[32],content[2048],enc[4096];
			char uid[32],uname[256],nick[64],isbot[8]="false";
			const char *author;

			json_str(d,"channel_id",cid,sizeof(cid));
			json_str(d,"id",mid,sizeof(mid));
			json_str(d,"content",content,sizeof(content));

			author = json_obj(d,"author");
			if(!author) break;
			json_str(author,"id",uid,sizeof(uid));
			json_str(author,"global_name",uname,sizeof(uname));
			if(!uname[0]) json_str(author,"username",uname,sizeof(uname));
			json_str(author,"bot",isbot,sizeof(isbot));
			if(strcmp(isbot,"true")==0) break;

			sanitise_nick(uname,nick,sizeof(nick));

			/*
			 * Bot commands start with '!'.  We handle "!identify"
			 * here and suppress it from appearing as a PRIVMSG on
			 * IRC.  Any other '!'-prefixed content is dropped
			 * silently so bots don't spam the IRC channel.
			 *
			 * "!identify [account] password" — relayed as:
			 *   I <cid> <uid> <nick_pct> :<args_pct>
			 * discordproc then forwards PRIVMSG NickServ IDENTIFY.
			 * Services are optional: if NickServ is absent discordproc
			 * simply logs and continues.
			 */
			if(content[0] == '!') {
				if(strncmp(content, "!identify ", 10) == 0) {
					char nenc[256], aenc[512];
					pct_encode(nick, nenc, sizeof(nenc));
					pct_encode(content + 10, aenc, sizeof(aenc));
					ircd_write("I %s %s %s :%s",
						   cid, uid, nenc, aenc);
				}
				/* All other !commands are silently dropped. */
				break;
			}

			pct_encode(content,enc,sizeof(enc));
			ircd_write("P %s %s %s %s :%s", cid, uid, nick, mid, enc);
		}
		else if(strcmp(ev,"MESSAGE_UPDATE")==0)
		{
			char cid[32],mid[32],content[2048],enc[4096];
			char uid[32],uname[256],nick[64];
			const char *author;
			json_str(d,"channel_id",cid,sizeof(cid));
			json_str(d,"id",mid,sizeof(mid));
			if(json_str(d,"content",content,sizeof(content)) && content[0]) {
				uid[0] = '\0'; nick[0] = '\0';
				author = json_obj(d,"author");
				if(author) {
					json_str(author,"id",uid,sizeof(uid));
					uname[0] = '\0';
					json_str(author,"global_name",uname,sizeof(uname));
					if(!uname[0])
						json_str(author,"username",uname,sizeof(uname));
					sanitise_nick(uname, nick, sizeof(nick));
				}
				if(!uid[0]) { snprintf(uid,sizeof(uid),"0"); }
				if(!nick[0]) { snprintf(nick,sizeof(nick),"DiscordUser"); }
				pct_encode(content,enc,sizeof(enc));
				ircd_write("E %s %s %s %s :%s", cid, mid, uid, nick, enc);
			}
		}
		else if(strcmp(ev,"MESSAGE_DELETE")==0)
		{
			char cid[32],mid[32];
			json_str(d,"channel_id",cid,sizeof(cid));
			json_str(d,"id",mid,sizeof(mid));
			ircd_write("D %s %s", cid, mid);
		}
		else if(strcmp(ev,"TYPING_START")==0)
		{
			char cid[32],uid[32],uname[256]="",nick[64];
			json_str(d,"channel_id",cid,sizeof(cid));
			json_str(d,"user_id",uid,sizeof(uid));
			{ const char *m=json_obj(d,"member");
			  if(m){const char *u=json_obj(m,"user");
			    if(u) json_str(u,"username",uname,sizeof(uname));} }
			if(!uname[0]) snprintf(uname,sizeof(uname),"u%s",uid);
			sanitise_nick(uname,nick,sizeof(nick));
			ircd_write("Y %s %s %s", cid, uid, nick);
		}
		break;
	default: break;
	}
}

/* -------------------------------------------------------------------------
 * WebSocket frame reader
 * ---------------------------------------------------------------------- */

static int
ws_read(void)
{
	int n;
	unsigned char *buf = (unsigned char *)gw_rxbuf + gw_rxbuf_len;

	n = SSL_read(gw_ssl, buf, (int)(sizeof(gw_rxbuf) - gw_rxbuf_len - 1));
	if(n <= 0) return -1;
	gw_rxbuf_len += (size_t)n;
	gw_rxbuf[gw_rxbuf_len] = '\0';

	unsigned char *p = (unsigned char *)gw_rxbuf;
	size_t rem = gw_rxbuf_len;

	while(rem >= 2) {
		int fin    = (p[0] & 0x80) != 0;
		int opcode = (p[0] & 0x0F);
		int masked = (p[1] & 0x80) != 0;
		size_t pl  = (p[1] & 0x7F);
		size_t hl  = 2;

		if(pl == 126) {
			if(rem < 4) break;
			pl = ((size_t)p[2]<<8)|p[3]; hl += 2;
		} else if(pl == 127) {
			if(rem < 10) break;
			pl = 0;
			for(int i=2;i<10;i++) pl=(pl<<8)|p[i];
			hl += 8;
		}
		if(masked) hl += 4;
		if(rem < hl + pl) break;

		unsigned char *payload = p + hl;

		if(opcode == 0x8) return -1;
		if(opcode == 0x9) {
			unsigned char pong[2] = {0x8A, 0x00};
			SSL_write(gw_ssl, pong, 2);
		} else if((opcode==0x1||opcode==0x0) && fin) {
			unsigned char sv = payload[pl];
			payload[pl] = '\0';
			handle_gw_frame((char *)payload);
			payload[pl] = sv;
		}

		size_t consumed = hl + pl;
		rem -= consumed; p += consumed;
	}

	if(rem > 0 && p != (unsigned char *)gw_rxbuf)
		memmove(gw_rxbuf, p, rem);
	gw_rxbuf_len = rem;
	return 0;
}

/* -------------------------------------------------------------------------
 * WebSocket HTTP upgrade handshake
 * ---------------------------------------------------------------------- */

static int
ws_handshake(const char *host, const char *path)
{
	unsigned char kb[16];
	char k64[32], req[1024], resp[4096];
	int rlen = 0;

	RAND_bytes(kb, 16);
	b64enc(kb, 16, k64, sizeof(k64));

	snprintf(req, sizeof(req),
		"GET %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Key: %s\r\n"
		"Sec-WebSocket-Version: 13\r\n\r\n",
		path, host, k64);

	if(SSL_write(gw_ssl, req, (int)strlen(req)) <= 0) return -1;

	for(;;) {
		int n = SSL_read(gw_ssl, resp + rlen, sizeof(resp) - rlen - 1);
		if(n <= 0) return -1;
		rlen += n; resp[rlen] = '\0';
		if(strstr(resp, "\r\n\r\n")) break;
		if(rlen >= (int)sizeof(resp) - 1) return -1;
	}

	if(strncmp(resp,"HTTP/1.1 101",12) != 0) {
		char *nl = strchr(resp,'\r'); if(nl) *nl='\0';
		ircd_write("W C :WebSocket upgrade failed: %s", resp);
		return -1;
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * Connect / disconnect from Discord Gateway
 * ---------------------------------------------------------------------- */

static int
gw_connect(void)
{
	const char *host = DISCORD_GW_HOST;

	if(gw_resume && gw_rurl[0]) {
		const char *p = strstr(gw_rurl, "wss://");
		if(p) host = p + 6;
	}

	gw_fd = tcp_connect(host, DISCORD_GW_PORT);
	if(gw_fd == -1) {
		ircd_write("W C :TCP connect to %s failed: %s", host, strerror(errno));
		return -1;
	}

	if(!gw_ctx) gw_ctx = new_ssl_ctx();
	gw_ssl = SSL_new(gw_ctx);
	SSL_set_fd(gw_ssl, gw_fd);
	SSL_set_tlsext_host_name(gw_ssl, host);

	if(SSL_connect(gw_ssl) <= 0) {
		ircd_write("W C :TLS handshake to %s failed", host);
		SSL_free(gw_ssl); gw_ssl = NULL;
		close(gw_fd); gw_fd = -1;
		return -1;
	}

	if(ws_handshake(host, DISCORD_GW_PATH) != 0) {
		SSL_free(gw_ssl); gw_ssl = NULL;
		close(gw_fd); gw_fd = -1;
		return -1;
	}

	gw_rxbuf_len = 0;
	gw_up = 1;
	ircd_write("W I :Connected to Discord Gateway (%s)", host);
	return 0;
}

static void
gw_disconnect(void)
{
	if(gw_ssl) { SSL_shutdown(gw_ssl); SSL_free(gw_ssl); gw_ssl = NULL; }
	if(gw_fd != -1) { close(gw_fd); gw_fd = -1; }
	gw_up = 0;
}

/* -------------------------------------------------------------------------
 * Discord REST — send message / typing
 * ---------------------------------------------------------------------- */

static void
rest_post(const char *channel_id, const char *body, int bodylen)
{
	int fd;
	SSL_CTX *ctx;
	SSL *ssl;
	char req[RXBUF_SZ], resp[256];

	fd = tcp_connect(DISCORD_API_HOST, DISCORD_API_PORT);
	if(fd == -1) { ircd_write("W W :REST connect failed: %s", strerror(errno)); return; }

	ctx = new_ssl_ctx();
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
	SSL_set_tlsext_host_name(ssl, DISCORD_API_HOST);
	if(SSL_connect(ssl) <= 0) {
		ircd_write("W W :REST TLS failed");
		SSL_free(ssl); SSL_CTX_free(ctx); close(fd); return;
	}

	snprintf(req, sizeof(req),
		"POST /api/v10/channels/%s/messages HTTP/1.1\r\n"
		"Host: " DISCORD_API_HOST "\r\n"
		"Authorization: %s\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n\r\n%s",
		channel_id, gw_token, bodylen, body);

	SSL_write(ssl, req, (int)strlen(req));

	{ int n = SSL_read(ssl, resp, sizeof(resp)-1);
	  if(n > 0) { resp[n]='\0';
	    if(strncmp(resp,"HTTP/1.1 2",10)!=0) {
	      char *nl=strchr(resp,'\r'); if(nl)*nl='\0';
	      ircd_write("W W :REST error: %s", resp); } } }

	SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
}

static void
rest_send_message(const char *channel_id, const char *text)
{
	char safe[1800], body[2048];
	size_t j = 0;
	int blen;

	for(size_t i=0; text[i]&&j<sizeof(safe)-2; i++) {
		if(text[i]=='"'||text[i]=='\\') safe[j++]='\\';
		safe[j++] = text[i];
	}
	safe[j] = '\0';
	blen = snprintf(body, sizeof(body), "{\"content\":\"%s\"}", safe);
	rest_post(channel_id, body, blen);
}

static void
rest_send_typing(const char *channel_id)
{
	int fd;
	SSL_CTX *ctx;
	SSL *ssl;
	char req[512];

	fd = tcp_connect(DISCORD_API_HOST, DISCORD_API_PORT);
	if(fd == -1) return;
	ctx = new_ssl_ctx();
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
	SSL_set_tlsext_host_name(ssl, DISCORD_API_HOST);
	if(SSL_connect(ssl) <= 0) { SSL_free(ssl); SSL_CTX_free(ctx); close(fd); return; }

	snprintf(req, sizeof(req),
		"POST /api/v10/channels/%s/typing HTTP/1.1\r\n"
		"Host: " DISCORD_API_HOST "\r\n"
		"Authorization: %s\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n\r\n",
		channel_id, gw_token);

	SSL_write(ssl, req, (int)strlen(req));
	{ char tmp[128]; while(SSL_read(ssl,tmp,sizeof(tmp))>0); }
	SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
}

/* -------------------------------------------------------------------------
 * Handle a command line from ircd
 * ---------------------------------------------------------------------- */

static void
handle_ircd_line(char *line)
{
	char *argv[MAXPARA + 1];
	int argc = tokenise(line, argv, MAXPARA);
	if(argc < 1) return;

	switch(argv[0][0])
	{
	case 'C': /* C <token> <guild_id> */
		if(argc < 3) break;
		strncpy(gw_token,    argv[1], sizeof(gw_token)-1);    gw_token[sizeof(gw_token)-1]='\0';
		strncpy(gw_guild_id, argv[2], sizeof(gw_guild_id)-1); gw_guild_id[sizeof(gw_guild_id)-1]='\0';
		gw_disconnect();
		chanmap_len = 0; gw_resume = 0; gw_sid[0] = '\0';
		gw_connect();
		break;

	case 'B': /* B <discord_channel_id> <irc_channel> */
		if(argc < 3 || chanmap_len >= 256) break;
		strncpy(chanmap[chanmap_len].id,  argv[1], sizeof(chanmap[0].id)-1);
		strncpy(chanmap[chanmap_len].irc, argv[2], sizeof(chanmap[0].irc)-1);
		chanmap_len++;
		break;

	case 'M': { /* M <channel_id> <nick_pct> :<text_pct> */
		char nick[64], text[2048], combined[2200];
		if(argc < 4) break;
		strncpy(nick, argv[2], sizeof(nick)-1); nick[sizeof(nick)-1]='\0';
		strncpy(text, argv[3], sizeof(text)-1); text[sizeof(text)-1]='\0';
		pct_decode(nick); pct_decode(text);
		snprintf(combined, sizeof(combined), "**%s**: %s", nick, text);
		rest_send_message(argv[1], combined);
		break;
	}

	case 'T': /* T <channel_id> */
		if(argc < 2) break;
		rest_send_typing(argv[1]);
		break;

	default: break;
	}
}

/* -------------------------------------------------------------------------
 * Read and dispatch lines from ircd pipe
 * ---------------------------------------------------------------------- */

static char   ircd_rbuf[LBUF_SZ];
static size_t ircd_rbuf_len = 0;

static void
read_ircd(void)
{
	ssize_t n = read(ircd_rfd, ircd_rbuf + ircd_rbuf_len,
			 sizeof(ircd_rbuf) - ircd_rbuf_len - 1);
	if(n <= 0) {
		if(n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
			exit(1);
		return;
	}
	ircd_rbuf_len += (size_t)n;
	ircd_rbuf[ircd_rbuf_len] = '\0';

	char *p, *ls = ircd_rbuf;
	while((p = memchr(ls, '\n', ircd_rbuf_len - (size_t)(ls - ircd_rbuf))) != NULL)
	{
		char *end = p;
		if(end > ls && *(end-1) == '\r') end--;
		*end = '\0';
		handle_ircd_line(ls);
		ls = p + 1;
	}

	size_t rem = ircd_rbuf_len - (size_t)(ls - ircd_rbuf);
	if(rem > 0 && ls != ircd_rbuf) memmove(ircd_rbuf, ls, rem);
	ircd_rbuf_len = rem;
}

/* -------------------------------------------------------------------------
 * Main event loop
 * ---------------------------------------------------------------------- */

static void
run(void)
{
	for(;;)
	{
		fd_set rfds, wfds;
		struct timeval tv;
		int maxfd = ircd_rfd;

		FD_ZERO(&rfds); FD_ZERO(&wfds);
		FD_SET(ircd_rfd, &rfds);

		if(ircd_wbuf_len > 0) {
			FD_SET(ircd_wfd, &wfds);
			if(ircd_wfd > maxfd) maxfd = ircd_wfd;
		}
		if(gw_up && gw_fd >= 0) {
			FD_SET(gw_fd, &rfds);
			if(gw_fd > maxfd) maxfd = gw_fd;
		}

		tv.tv_sec = 1; tv.tv_usec = 0;
		select(maxfd + 1, &rfds, &wfds, NULL, &tv);

		if(ircd_wbuf_len > 0) ircd_flush();

		/* Heartbeat */
		if(gw_up && gw_hb_ms > 0 && time(NULL) >= gw_hb_due) {
			if(gw_ack_pend) {
				ircd_write("W W :Heartbeat ACK timeout, reconnecting");
				gw_disconnect();
				sleep(5);
				gw_connect();
				continue;
			}
			gw_send_heartbeat();
		}

		/* Auto-reconnect */
		if(!gw_up && gw_token[0]) {
			sleep(5);
			gw_connect();
			continue;
		}

		/* Discord reads */
		if(gw_up && gw_fd >= 0 && FD_ISSET(gw_fd, &rfds)) {
			if(ws_read() < 0) {
				ircd_write("W W :Discord read error, reconnecting");
				gw_disconnect();
			}
		}

		/* ircd reads */
		if(FD_ISSET(ircd_rfd, &rfds))
			read_ircd();
	}
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

#ifndef DISCORD_NO_MAIN
int
main(int argc, char *argv[])
{
	const char *ifd_s, *ofd_s, *maxfd_s;
	int maxfd;

	(void)argc; (void)argv;
	sigaction(SIGPIPE, &(struct sigaction){ .sa_handler = SIG_IGN }, NULL);

	ifd_s   = getenv("IFD");
	ofd_s   = getenv("OFD");
	maxfd_s = getenv("MAXFD");

	if(!ifd_s || !ofd_s) {
		fprintf(stderr, "discordd: not meant to be run directly\n");
		return 1;
	}

	/* IFD = fd the child reads commands from (parent writes here)
	 * OFD = fd the child writes replies to  (parent reads from here) */
	ircd_rfd = atoi(ifd_s);
	ircd_wfd = atoi(ofd_s);
	maxfd    = maxfd_s ? atoi(maxfd_s) : 256;

	/* Close everything except our two pipe fds */
	for(int i = 0; i < maxfd; i++)
		if(i != ircd_rfd && i != ircd_wfd)
			close(i);

	/* Redirect stdin/stdout/stderr to /dev/null */
	{
		int dn = open("/dev/null", O_RDWR);
		if(dn >= 0) {
			if(ircd_rfd != 0 && ircd_wfd != 0) dup2(dn, 0);
			if(ircd_rfd != 1 && ircd_wfd != 1) dup2(dn, 1);
			if(ircd_rfd != 2 && ircd_wfd != 2) dup2(dn, 2);
			if(dn > 2) close(dn);
		}
	}

	fcntl(ircd_rfd, F_SETFL, fcntl(ircd_rfd, F_GETFL)|O_NONBLOCK);
	fcntl(ircd_wfd, F_SETFL, fcntl(ircd_wfd, F_GETFL)|O_NONBLOCK);

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	ircd_write("W I :discordd started, awaiting configuration");
	ircd_flush();

	run();
	return 0;
}
#endif /* DISCORD_NO_MAIN */
