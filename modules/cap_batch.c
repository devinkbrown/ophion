/*
 * modules/cap_batch.c
 * IRCv3 batch capability
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
 * The batch capability (https://ircv3.net/specs/extensions/batch) allows
 * the server to group multiple related messages together.  Clients that
 * advertise the capability understand BATCH start/end markers and can
 * process the enclosed messages as a logical unit.
 *
 * Server-side helpers for starting and ending a batch are provided as
 * inline functions in cap_batch.h.  This module registers the client
 * capability; other modules use the helpers to emit batched output.
 *
 * Client-sent BATCH commands are silently ignored; clients are not
 * permitted to initiate batches toward the server in this implementation.
 */

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_serv.h"
#include "numeric.h"
#include "msg.h"
#include "parse.h"

static const char cap_batch_desc[] =
	"Provides the batch client capability";

static void m_batch(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message batch_msgtab = {
	"BATCH", 0, 0, 0, 0,
	{mg_unreg, {m_batch, 0}, mg_ignore, mg_ignore, mg_ignore, {m_batch, 0}}
};

mapi_clist_av1 cap_batch_clist[] = { &batch_msgtab, NULL };

DECLARE_MODULE_AV2(cap_batch, NULL, NULL, cap_batch_clist, NULL, NULL, NULL, NULL, cap_batch_desc);

/*
 * m_batch
 *
 * Clients are not permitted to send BATCH to the server in this
 * implementation.  Silently discard any such message.
 */
static void
m_batch(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;
	(void)source_p;
	(void)parc;
	(void)parv;
	/* no-op: clients cannot initiate batches */
}
