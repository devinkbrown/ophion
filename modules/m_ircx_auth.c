/*
 * modules/m_ircx_auth.c
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
 * IRCX AUTH command
 *
 * AUTH <mechanism> <sequence> [:<data>]
 *
 * Provides IRCX-style authentication that drives the underlying SASL
 * mechanism infrastructure.
 *
 * <sequence> values:
 *   I  - Initial auth request (includes payload)
 *   S  - Subsequent auth step (continuation)
 *   *  - Abort current auth
 */

#include "stdinc.h"
#include "client.h"
#include "sasl.h"
#include "hash.h"
#include "send.h"
#include "msg.h"
#include "modules.h"
#include "numeric.h"
#include "s_serv.h"
#include "s_conf.h"
#include "hook.h"

static const char ircx_auth_desc[] =
	"Provides IRCX AUTH command mapped to SASL authentication";

static void m_auth(struct MsgBuf *msgbuf_p, struct Client *client_p,
		   struct Client *source_p, int parc, const char *parv[]);

struct Message auth_msgtab = {
	"AUTH", 0, 0, 0, 0,
	{{m_auth, 3}, {m_auth, 3}, mg_ignore, mg_ignore, mg_ignore, {m_auth, 3}}
};

mapi_clist_av1 ircx_auth_clist[] = { &auth_msgtab, NULL };

DECLARE_MODULE_AV2(ircx_auth, NULL, NULL, ircx_auth_clist, NULL, NULL, NULL, NULL, ircx_auth_desc);

static void
end_auth_session(struct Client *client_p)
{
	if (!MyClient(client_p))
		return;

	if (client_p->localClient->sess != NULL)
	{
		if (client_p->localClient->sess->mech != NULL &&
		    client_p->localClient->sess->mech->finish_fn != NULL)
			client_p->localClient->sess->mech->finish_fn(client_p->localClient->sess);

		rb_free(client_p->localClient->sess);
		client_p->localClient->sess = NULL;
	}
}

static void
login_auth_session(struct Client *client_p)
{
	if (!MyClient(client_p))
		return;

	struct User *user_p = client_p->user;
	if (!IsPerson(client_p) && IsUnknown(client_p))
		user_p = make_user(client_p);

	struct sasl_session *sess = client_p->localClient->sess;
	if (sess != NULL && *sess->authzid)
		rb_strlcpy(user_p->suser, sess->authzid, sizeof user_p->suser);

	end_auth_session(client_p);
}

static void
m_auth(struct MsgBuf *msgbuf_p, struct Client *client_p,
       struct Client *source_p, int parc, const char *parv[])
{
	const char *mechanism = parv[1];
	const char *sequence = parv[2];
	const char *data = (parc > 3) ? parv[3] : NULL;
	const char *nick = EmptyString(source_p->name) ? "*" : source_p->name;

	/* AUTH * - abort */
	if (!strcmp(mechanism, "*"))
	{
		end_auth_session(source_p);
		sendto_one(source_p, form_str(ERR_SASLABORTED), me.name, nick);
		return;
	}

	/* Sequence must be I (initial) or S (step) */
	if (irccmp(sequence, "I") != 0 && irccmp(sequence, "S") != 0)
	{
		sendto_one(source_p, form_str(ERR_SASLFAIL), me.name, nick);
		return;
	}

	/* Initial request */
	if (irccmp(sequence, "I") == 0)
	{
		/* abort any existing session */
		end_auth_session(source_p);

		/* ask for the mechanism via sasl_start hook */
		struct sasl_hook_data hdata = {
			.client = source_p,
			.name = mechanism,
		};

		call_hook(register_hook("sasl_start"), &hdata);

		if (hdata.mech == NULL)
		{
			sendto_one(source_p, form_str(ERR_SASLFAIL), me.name, nick);
			return;
		}

		source_p->localClient->sess = rb_malloc(sizeof(struct sasl_session));
		memset(source_p->localClient->sess, 0, sizeof(struct sasl_session));
		source_p->localClient->sess->mech = hdata.mech;
		source_p->localClient->sess->client = source_p;

		/* run the start function */
		struct sasl_output_buf outbuf = { 0 };
		enum sasl_mechanism_result ret;

		ret = source_p->localClient->sess->mech->start_fn(source_p->localClient->sess, &outbuf);

		rb_free(outbuf.buf);

		if (ret == SASL_MRESULT_ERROR || ret == SASL_MRESULT_FAILURE)
		{
			end_auth_session(source_p);
			sendto_one(source_p, form_str(ERR_SASLFAIL), me.name, nick);
			return;
		}

		/* if we have data, feed it to step_fn right away */
		if (data != NULL && *data != '\0')
		{
			int declen;
			unsigned char *decbuf = rb_base64_decode(
				(const unsigned char *)data, strlen(data), &declen);

			const struct sasl_input_buf inbuf = {
				.buf = decbuf,
				.len = declen,
			};

			struct sasl_output_buf outbuf2 = { 0 };
			ret = source_p->localClient->sess->mech->step_fn(
				source_p->localClient->sess, &inbuf, &outbuf2);

			rb_free(decbuf);
			rb_free(outbuf2.buf);

			switch (ret)
			{
			case SASL_MRESULT_SUCCESS:
				login_auth_session(source_p);

				if (*source_p->user->suser)
					sendto_one(source_p, form_str(RPL_LOGGEDIN),
						   me.name, nick,
						   nick,
						   EmptyString(source_p->username) ? "*" : source_p->username,
						   EmptyString(source_p->host) ? "*" : source_p->host,
						   source_p->user->suser, source_p->user->suser);

				sendto_one(source_p, form_str(RPL_SASLSUCCESS), me.name, nick);
				return;

			case SASL_MRESULT_CONTINUE:
				source_p->localClient->sess->continuing = true;
				/* need more data, client sends AUTH <mech> S :<data> */
				return;

			default:
				end_auth_session(source_p);
				sendto_one(source_p, form_str(ERR_SASLFAIL), me.name, nick);
				return;
			}
		}

		/* no data provided with initial, mark continuing */
		source_p->localClient->sess->continuing = true;
		return;
	}

	/* Subsequent step (S) */
	if (source_p->localClient->sess == NULL ||
	    source_p->localClient->sess->mech == NULL)
	{
		sendto_one(source_p, form_str(ERR_SASLFAIL), me.name, nick);
		return;
	}

	if (data == NULL || *data == '\0')
	{
		end_auth_session(source_p);
		sendto_one(source_p, form_str(ERR_SASLFAIL), me.name, nick);
		return;
	}

	int declen;
	unsigned char *decbuf = rb_base64_decode(
		(const unsigned char *)data, strlen(data), &declen);

	const struct sasl_input_buf inbuf = {
		.buf = decbuf,
		.len = declen,
	};

	struct sasl_output_buf outbuf = { 0 };
	enum sasl_mechanism_result ret;

	ret = source_p->localClient->sess->mech->step_fn(
		source_p->localClient->sess, &inbuf, &outbuf);

	rb_free(decbuf);
	rb_free(outbuf.buf);

	switch (ret)
	{
	case SASL_MRESULT_SUCCESS:
		login_auth_session(source_p);

		if (*source_p->user->suser)
			sendto_one(source_p, form_str(RPL_LOGGEDIN),
				   me.name, nick,
				   nick,
				   EmptyString(source_p->username) ? "*" : source_p->username,
				   EmptyString(source_p->host) ? "*" : source_p->host,
				   source_p->user->suser, source_p->user->suser);

		sendto_one(source_p, form_str(RPL_SASLSUCCESS), me.name, nick);
		return;

	case SASL_MRESULT_CONTINUE:
		/* more data needed */
		return;

	default:
		end_auth_session(source_p);
		sendto_one(source_p, form_str(ERR_SASLFAIL), me.name, nick);
		return;
	}
}
