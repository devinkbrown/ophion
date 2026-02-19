/*
 * modules/m_ircx_listx.c
 * Copyright (c) 2020 Ariadne Conill <ariadne@dereferenced.org>
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
 * IRCX LISTX command
 *
 * LISTX [filter]
 *
 * Extended channel listing with property data.
 * Filters: <N (member count less than N), >N (member count greater than N)
 *
 * Replies:
 *   811 - RPL_LISTXSTART
 *   812 - RPL_LISTXENTRY  channel modes membercount creationts :topic
 *   816 - RPL_LISTXTRUNC  (if output is truncated)
 *   817 - RPL_LISTXEND
 */

#include "stdinc.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "s_newconf.h"
#include "inline/stringops.h"
#include "rb_radixtree.h"

static const char ircx_listx_desc[] = "Provides IRCX LISTX command for extended channel listing";

static void m_listx(struct MsgBuf *msgbuf_p, struct Client *client_p,
		    struct Client *source_p, int parc, const char *parv[]);

struct Message listx_msgtab = {
	"LISTX", 0, 0, 0, 0,
	{mg_unreg, {m_listx, 0}, mg_ignore, mg_ignore, mg_ignore, {m_listx, 0}}
};

mapi_clist_av1 ircx_listx_clist[] = { &listx_msgtab, NULL };

DECLARE_MODULE_AV2(ircx_listx, NULL, NULL, ircx_listx_clist, NULL, NULL, NULL, NULL, ircx_listx_desc);

static void
m_listx(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr;
	rb_dlink_node *ptr;
	int users_min = 0;
	int users_max = INT_MAX;
	int count = 0;
	int max_entries = 500;	/* prevent flooding */

	/* parse filters */
	if (parc > 1 && !EmptyString(parv[1]))
	{
		char *args = LOCAL_COPY(parv[1]);
		char *p = NULL;
		char *tok;

		for (tok = rb_strtok_r(args, ",", &p); tok; tok = rb_strtok_r(NULL, ",", &p))
		{
			if (*tok == '<' && IsDigit(*(tok + 1)))
			{
				users_max = atoi(tok + 1);
				if (users_max > 0)
					users_max--;
			}
			else if (*tok == '>' && IsDigit(*(tok + 1)))
			{
				users_min = atoi(tok + 1) + 1;
			}
		}
	}

	sendto_one(source_p, form_str(RPL_LISTXSTART), me.name, source_p->name);

	RB_DLINK_FOREACH(ptr, global_channel_list.head)
	{
		char topic[TOPICLEN + 1];
		int visible;

		chptr = ptr->data;

		visible = !SecretChannel(chptr) || IsMember(source_p, chptr);
		if (!visible)
			continue;

		if ((int)rb_dlink_list_length(&chptr->members) < users_min ||
		    (int)rb_dlink_list_length(&chptr->members) > users_max)
			continue;

		if (chptr->topic != NULL)
			rb_strlcpy(topic, chptr->topic, sizeof topic);
		else
			topic[0] = '\0';
		strip_colour(topic);

		sendto_one(source_p, form_str(RPL_LISTXENTRY),
			   me.name, source_p->name,
			   chptr->chname,
			   channel_modes(chptr, source_p),
			   (unsigned long)rb_dlink_list_length(&chptr->members),
			   (unsigned long)chptr->channelts,
			   topic);

		if (++count >= max_entries)
		{
			sendto_one(source_p, form_str(RPL_LISTXTRUNC),
				   me.name, source_p->name);
			break;
		}
	}

	sendto_one(source_p, form_str(RPL_LISTXEND), me.name, source_p->name);
}
