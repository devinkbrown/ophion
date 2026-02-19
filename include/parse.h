/*
 *  ircd-ratbox: A slightly useful ircd.
 *  parse.h: A header for the message parser.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2004 ircd-ratbox development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 */

#ifndef INCLUDED_parse_h_h
#define INCLUDED_parse_h_h

#include "rb_dictionary.h"

struct Message;
struct Client;
struct MsgBuf;

extern void parse(struct Client *, char *, char *);
extern void handle_encap(struct MsgBuf *, struct Client *, struct Client *,
		         const char *, int, const char *parv[]);
extern void clear_hash_parse(void);
extern void mod_add_cmd(struct Message *msg);
extern void mod_del_cmd(struct Message *msg);
extern char *reconstruct_parv(int parc, const char *parv[]);

extern rb_dictionary *alias_dict;
extern rb_dictionary *cmd_dict;

/* IRCv3 message-tags: pointer to the current incoming client MsgBuf.
 * Set in parse() before command dispatch; cleared after.
 * Used by cap_message_tags to forward client-only tags. */
extern const struct MsgBuf *g_client_msgbuf;

/*
 * Client-initiated batch handler callback.
 *
 * Called from parse() before normal command dispatch when a local
 * client's message either:
 *   - has a @batch= message tag, or
 *   - is a BATCH command
 *
 * Returns 1 if the message was consumed (skip normal dispatch),
 * 0 to let normal dispatch proceed.
 */
typedef int (*client_batch_handler_fn)(struct MsgBuf *msgbuf_p,
	struct Client *client_p, struct Client *from);
extern client_batch_handler_fn client_batch_handler;

#endif /* INCLUDED_parse_h_h */
