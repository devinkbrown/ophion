/*
 * ircd-ratbox: A slightly useful ircd.
 * packet.c: Packet I/O and per-client flood control.
 *
 * Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 * Copyright (C) 1996-2002 Hybrid Development Team
 * Copyright (C) 2002-2005 ircd-ratbox development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "stdinc.h"
#include "s_conf.h"
#include "s_serv.h"
#include "client.h"
#include "ircd.h"
#include "parse.h"
#include "packet.h"
#include "match.h"
#include "hook.h"
#include "send.h"
#include "s_assert.h"
#include "s_newconf.h"

/* Single shared read buffer — we are single-threaded. */
static char readBuf[READBUF_SIZE];

static void client_dopacket(struct Client *client_p, char *buffer, size_t length);

/* ---------- flood-control helpers --------------------------------------- */

/*
 * Return the token bucket burst limit for a fully-registered client.
 * Opers are given 4× the normal allowance when no_oper_flood is set.
 */
static inline int
client_burst_limit(struct Client *client_p)
{
	int limit = IsFloodDone(client_p)
		? ConfigFileEntry.client_flood_burst_max
		: ConfigFileEntry.client_flood_burst_rate;

	limit *= ConfigFileEntry.client_flood_message_time;

	if(IsOperGeneral(client_p) && ConfigFileEntry.no_oper_flood)
		limit *= 4;

	return limit;
}

/*
 * Cost in tokens for each message from a registered client.
 */
static inline int
client_msg_cost(void)
{
	return ConfigFileEntry.client_flood_message_time;
}

/*
 * Clamp sent_parsed into [0, ceiling].  Called after a flood_recalc tick
 * or after completing a parse loop, so that a config reload that lowers
 * limits takes effect immediately rather than waiting for the counter to
 * drain naturally.
 */
static inline void
clamp_sent_parsed(struct Client *client_p, int ceiling)
{
	if(client_p->localClient->sent_parsed < 0)
		client_p->localClient->sent_parsed = 0;
	if(client_p->localClient->sent_parsed > ceiling)
		client_p->localClient->sent_parsed = ceiling;
}

/* ---------- per-client message processing ------------------------------- */

/*
 * parse_client_queued - drain and parse buffered lines for one client.
 *
 * Three distinct paths based on client state:
 *
 *   Unknown  — pre-registration; hard cap at client_flood_burst_max lines,
 *              reset to 0 if the client completes registration mid-loop.
 *
 *   Server / flood-exempt — no limit; drain the whole receive queue.
 *
 *   Registered client — token-bucket: each message costs one
 *              client_flood_message_time token; opers get 4× the bucket.
 *              Also honours post_registration_delay.
 */
static void
parse_client_queued(struct Client *client_p)
{
	int dolen;

	if(IsAnyDead(client_p))
		return;

	/* --- pre-registration --- */
	if(IsUnknown(client_p))
	{
		int limit = ConfigFileEntry.client_flood_burst_max;

		while(client_p->localClient->sent_parsed < limit)
		{
			dolen = rb_linebuf_get(&client_p->localClient->buf_recvq,
					       readBuf, READBUF_SIZE,
					       LINEBUF_COMPLETE, LINEBUF_PARSED);
			if(dolen <= 0 || IsAnyDead(client_p))
				break;

			client_dopacket(client_p, readBuf, dolen);
			client_p->localClient->sent_parsed++;

			if(IsAnyDead(client_p))
				return;

			/* Client just completed registration.  Reset the counter
			 * and fall through to the registered-client path below so
			 * the token-bucket clamp runs in this same call (matching
			 * the original fall-through behaviour and ensuring
			 * sent_parsed is primed correctly for the next read). */
			if(!IsUnknown(client_p))
			{
				client_p->localClient->sent_parsed = 0;
				break;
			}
		}

		/* Still pre-registered: clamp and exit. */
		if(IsUnknown(client_p))
		{
			clamp_sent_parsed(client_p, limit);
			return;
		}
		/* Otherwise fall through to the registered-client path. */
	}

	/* --- servers and flood-exempt clients: unlimited --- */
	if(IsAnyServer(client_p) || IsExemptFlood(client_p))
	{
		while(!IsAnyDead(client_p))
		{
			dolen = rb_linebuf_get(&client_p->localClient->buf_recvq,
					       readBuf, READBUF_SIZE,
					       LINEBUF_COMPLETE, LINEBUF_PARSED);
			if(dolen <= 0)
				break;

			client_dopacket(client_p, readBuf, dolen);
		}
		return;
	}

	/* --- registered clients: token-bucket flood control --- */
	{
		int limit = client_burst_limit(client_p);
		int cost  = client_msg_cost();

		/* Honour the post-registration grace window. */
		if(rb_current_time() >= client_p->localClient->firsttime +
		                        ConfigFileEntry.post_registration_delay)
		{
			while(client_p->localClient->sent_parsed < limit)
			{
				dolen = rb_linebuf_get(&client_p->localClient->buf_recvq,
						       readBuf, READBUF_SIZE,
						       LINEBUF_COMPLETE, LINEBUF_PARSED);
				if(!dolen)
					break;

				client_dopacket(client_p, readBuf, dolen);
				if(IsAnyDead(client_p))
					return;

				client_p->localClient->sent_parsed += cost;
			}
		}

		/* Keep the counter in [0, limit + cost - 1] so that a config
		 * reload that lowers the limit takes effect promptly. */
		clamp_sent_parsed(client_p, limit + cost - 1);
	}
}

/* ---------- public interface -------------------------------------------- */

/*
 * flood_endgrace - mark end of a client's grace period.
 */
void
flood_endgrace(struct Client *client_p)
{
	SetFloodDone(client_p);

	/* sent_parsed might be above client_flood_burst_rate but under
	 * client_flood_burst_max; reset so the new limit applies cleanly. */
	client_p->localClient->sent_parsed = 0;
}

/*
 * flood_recalc - called every second via rb_event.
 *
 * Decrements each client's flood token counter by one tick, then attempts
 * to parse any queued lines that are now affordable.
 */
void
flood_recalc(void *unused)
{
	rb_dlink_node *ptr, *next;
	struct Client *client_p;

	RB_DLINK_FOREACH_SAFE(ptr, next, lclient_list.head)
	{
		client_p = ptr->data;

		if(rb_unlikely(IsMe(client_p)) || rb_unlikely(client_p->localClient == NULL))
			continue;

		if(IsFloodDone(client_p))
			client_p->localClient->sent_parsed -= ConfigFileEntry.client_flood_message_num;
		else
			client_p->localClient->sent_parsed = 0;

		if(client_p->localClient->sent_parsed < 0)
			client_p->localClient->sent_parsed = 0;

		parse_client_queued(client_p);

		if(rb_unlikely(IsAnyDead(client_p)))
			continue;
	}

	RB_DLINK_FOREACH_SAFE(ptr, next, unknown_list.head)
	{
		client_p = ptr->data;

		if(client_p->localClient == NULL)
			continue;

		if(--client_p->localClient->sent_parsed < 0)
			client_p->localClient->sent_parsed = 0;

		parse_client_queued(client_p);
	}
}

/*
 * read_packet - fd read callback; read raw bytes from the socket and queue
 *              them for parsing.
 *
 * We loop until the read returns a short result (nothing more pending) or
 * the client's receive queue overflows its flood limit, or an error occurs.
 */
void
read_packet(rb_fde_t *F, void *data)
{
	struct Client *client_p = data;
	int length;

	while(1)
	{
		if(IsAnyDead(client_p))
			return;

		length = rb_read(client_p->localClient->F, readBuf, READBUF_SIZE);

		if(length < 0)
		{
			if(rb_ignore_errno(errno))
				rb_setselect(client_p->localClient->F,
					     RB_SELECT_READ, read_packet, client_p);
			else
				error_exit_client(client_p, length);
			return;
		}

		if(length == 0)
		{
			error_exit_client(client_p, length);
			return;
		}

		/* Update the last-seen timestamp and clear the ping-sent flag.
		 * Cache the clock value so we only read it once per iteration. */
		time_t now = rb_current_time();
		if(client_p->localClient->lasttime < now)
			client_p->localClient->lasttime = now;
		client_p->flags &= ~FLAGS_PINGSENT;

		/* Binary mode for clients still in handshake/unknown state:
		 * don't treat NUL as a line terminator. */
		int binary = (IsHandshake(client_p) || IsUnknown(client_p)) ? 1 : 0;

		rb_linebuf_parse(&client_p->localClient->buf_recvq,
				 readBuf, length, binary);

		if(IsAnyDead(client_p))
			return;

		parse_client_queued(client_p);

		if(IsAnyDead(client_p))
			return;

		/* Flood check: drop clients whose receive queue is too deep. */
		if(!IsAnyServer(client_p) &&
		   rb_linebuf_alloclen(&client_p->localClient->buf_recvq) >
		   ConfigFileEntry.client_flood_max_lines)
		{
			if(!(ConfigFileEntry.no_oper_flood && IsOperGeneral(client_p)))
			{
				exit_client(client_p, client_p, client_p, "Excess Flood");
				return;
			}
		}

		/* Short read — kernel has no more data waiting.
		 * Re-arm the read event and return.  SCTP delivers framed
		 * packets, so a full-sized read there does not imply more data. */
		if(length < READBUF_SIZE &&
		   !(rb_get_type(client_p->localClient->F) & RB_FD_SCTP))
		{
			rb_setselect(client_p->localClient->F,
				     RB_SELECT_READ, read_packet, client_p);
			return;
		}
	}
}

/* ---------- internal ---------------------------------------------------- */

/*
 * client_dopacket - update receive statistics and dispatch one IRC line
 *                   to the parser.
 *
 * Byte counters are kept as (receiveK, receiveB) pairs: receiveB accumulates
 * raw bytes; every time it exceeds 1023 the kilobyte counter is incremented
 * and the remainder kept.
 */
static void
client_dopacket(struct Client *client_p, char *buffer, size_t length)
{
	s_assert(client_p != NULL);
	s_assert(buffer != NULL);

	if(client_p == NULL || buffer == NULL || IsAnyDead(client_p))
		return;

	/* Per-client and global message count. */
	++me.localClient->receiveM;
	++client_p->localClient->receiveM;

	/* Per-client byte accounting. */
	client_p->localClient->receiveB += length;
	if(client_p->localClient->receiveB > 1023)
	{
		client_p->localClient->receiveK +=
			(client_p->localClient->receiveB >> 10);
		client_p->localClient->receiveB &= 0x03ff;
	}

	/* Global byte accounting. */
	me.localClient->receiveB += length;
	if(me.localClient->receiveB > 1023)
	{
		me.localClient->receiveK += (me.localClient->receiveB >> 10);
		me.localClient->receiveB &= 0x03ff;
	}

	parse(client_p, buffer, buffer + length);
}
