/*
 *  ircd-ratbox: A slightly useful ircd.
 *  s_serv.c: Server related functions.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
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

#include "stdinc.h"

#ifdef HAVE_LIBCRYPTO
#include <openssl/rsa.h>
#endif

#include "s_serv.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "match.h"
#include "ircd.h"
#include "ircd_defs.h"
#include "numeric.h"
#include "packet.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "logger.h"
#include "s_stats.h"
#include "s_user.h"
#include "scache.h"
#include "send.h"
#include "client.h"
#include "channel.h"		/* chcap_usage_counts stuff... */
#include "hook.h"
#include "msg.h"
#include "reject.h"
#include "sslproc.h"
#include "capability.h"
#include "s_assert.h"

int MaxConnectionCount = 1;
int MaxClientCount = 1;
int refresh_user_links = 0;

static char buf[BUFSIZE];

/*
 * list of recognized server capabilities.  "TS" is not on the list
 * because all servers that we talk to already do TS, and the kludged
 * extra argument to "PASS" takes care of checking that.  -orabidoo
 */
struct CapabilityIndex *serv_capindex = NULL;
struct CapabilityIndex *cli_capindex = NULL;

unsigned int CAP_CAP;
unsigned int CAP_QS;
unsigned int CAP_EX;
unsigned int CAP_CHW;
unsigned int CAP_IE;
unsigned int CAP_KLN;
unsigned int CAP_KNOCK;
unsigned int CAP_TB;
unsigned int CAP_UNKLN;
unsigned int CAP_CLUSTER;
unsigned int CAP_ENCAP;
unsigned int CAP_TS6;
unsigned int CAP_SERVICE;
unsigned int CAP_RSFNC;
unsigned int CAP_SAVE;
unsigned int CAP_EUID;
unsigned int CAP_EOPMOD;
unsigned int CAP_BAN;
unsigned int CAP_MLOCK;
unsigned int CAP_BPROP;
unsigned int CAP_AUTOSID;

unsigned int CLICAP_MULTI_PREFIX;
unsigned int CLICAP_ACCOUNT_NOTIFY;
unsigned int CLICAP_EXTENDED_JOIN;
unsigned int CLICAP_AWAY_NOTIFY;
unsigned int CLICAP_USERHOST_IN_NAMES;
unsigned int CLICAP_CAP_NOTIFY;
unsigned int CLICAP_CHGHOST;
unsigned int CLICAP_ECHO_MESSAGE;
unsigned int CLICAP_INVITE_NOTIFY;
unsigned int CLICAP_MESSAGE_TAGS;
unsigned int CLICAP_BATCH;
unsigned int CLICAP_SETNAME;
unsigned int CLICAP_LABELED_RESPONSE;
unsigned int CLICAP_STANDARD_REPLIES;

/*
 * initialize our builtin capability table. --nenolod
 */
void
init_builtin_capabs(void)
{
	serv_capindex = capability_index_create("server capabilities");

	/* These two are not set via CAPAB/GCAP keywords. */
	CAP_CAP = capability_put_anonymous(serv_capindex);
	CAP_TS6 = capability_put_anonymous(serv_capindex);

	CAP_QS = capability_put(serv_capindex, "QS", NULL);
	CAP_EX = capability_put(serv_capindex, "EX", NULL);
	CAP_CHW = capability_put(serv_capindex, "CHW", NULL);
	CAP_IE = capability_put(serv_capindex, "IE", NULL);
	CAP_KLN = capability_put(serv_capindex, "KLN", NULL);
	CAP_KNOCK = capability_put(serv_capindex, "KNOCK", NULL);
	CAP_TB = capability_put(serv_capindex, "TB", NULL);
	CAP_UNKLN = capability_put(serv_capindex, "UNKLN", NULL);
	CAP_CLUSTER = capability_put(serv_capindex, "CLUSTER", NULL);
	CAP_ENCAP = capability_put(serv_capindex, "ENCAP", NULL);
	CAP_SERVICE = capability_put(serv_capindex, "SERVICES", NULL);
	CAP_RSFNC = capability_put(serv_capindex, "RSFNC", NULL);
	CAP_SAVE = capability_put(serv_capindex, "SAVE", NULL);
	CAP_EUID = capability_put(serv_capindex, "EUID", NULL);
	CAP_EOPMOD = capability_put(serv_capindex, "EOPMOD", NULL);
	CAP_BAN = capability_put(serv_capindex, "BAN", NULL);
	CAP_MLOCK = capability_put(serv_capindex, "MLOCK", NULL);
	CAP_BPROP = capability_put(serv_capindex, "BPROP", NULL);
	CAP_AUTOSID = capability_put(serv_capindex, "AUTOSID", NULL);

	capability_require(serv_capindex, "QS");
	capability_require(serv_capindex, "EX");
	capability_require(serv_capindex, "IE");
	capability_require(serv_capindex, "ENCAP");

	cli_capindex = capability_index_create("client capabilities");

	CLICAP_MULTI_PREFIX = capability_put(cli_capindex, "multi-prefix", NULL);
	CLICAP_ACCOUNT_NOTIFY = capability_put(cli_capindex, "account-notify", NULL);
	CLICAP_EXTENDED_JOIN = capability_put(cli_capindex, "extended-join", NULL);
	CLICAP_AWAY_NOTIFY = capability_put(cli_capindex, "away-notify", NULL);
	CLICAP_USERHOST_IN_NAMES = capability_put(cli_capindex, "userhost-in-names", NULL);
	CLICAP_CAP_NOTIFY = capability_put(cli_capindex, "cap-notify", NULL);
	CLICAP_CHGHOST = capability_put(cli_capindex, "chghost", NULL);
	CLICAP_ECHO_MESSAGE = capability_put(cli_capindex, "echo-message", NULL);
	CLICAP_INVITE_NOTIFY = capability_put(cli_capindex, "invite-notify", NULL);
	CLICAP_MESSAGE_TAGS = capability_put(cli_capindex, "message-tags", NULL);
	CLICAP_BATCH = capability_put(cli_capindex, "batch", NULL);
	CLICAP_SETNAME = capability_put(cli_capindex, "setname", NULL);
	CLICAP_LABELED_RESPONSE = capability_put(cli_capindex, "labeled-response", NULL);
	CLICAP_STANDARD_REPLIES = capability_put(cli_capindex, "standard-replies", NULL);

	/* draft/typing: purely advisory; +draft/typing client-only tags are
	 * already relayed by cap_message_tags via TAGMSG. */
	capability_put(cli_capindex, "draft/typing", NULL);
}

static CNCB serv_connect_callback;
static CNCB serv_connect_ssl_callback;
static SSL_OPEN_CB serv_connect_ssl_open_callback;

/*
 * hunt_server - Do the basic thing in delivering the message (command)
 *      across the relays to the specific server (server) for
 *      actions.
 *
 *      Note:   The command is a format string and *MUST* be
 *              of prefixed style (e.g. ":%s COMMAND %s ...").
 *              Command can have only max 8 parameters.
 *
 *      server  parv[server] is the parameter identifying the
 *              target server.
 *
 *      *WARNING*
 *              parv[server] is replaced with the pointer to the
 *              real servername from the matched client (I'm lazy
 *              now --msa).
 *
 *      returns: (see #defines)
 */
int
hunt_server(struct Client *client_p, struct Client *source_p,
	    const char *command, int server, int parc, const char *parv[])
{
	struct Client *target_p;
	rb_dlink_node *ptr;
	const char *saved;
	char *target_name;
	bool wilds;

	/* Assume it's me if no server parameter given. */
	if(parc <= server || EmptyString(parv[server]) ||
	   match(parv[server], me.name) || strcmp(parv[server], me.id) == 0)
		return HUNTED_ISME;

	target_name = LOCAL_COPY(parv[server]);

	/* Hash lookup first; wild-card fallback only if needed. */
	target_p = MyClient(source_p) ? find_named_client(target_name)
	                               : find_client(target_name);

	if(target_p != NULL &&
	   target_p->from == source_p->from && !MyConnect(target_p))
		target_p = NULL;

	collapse(target_name);
	wilds = strchr(target_name, '?') != NULL || strchr(target_name, '*') != NULL;

	if(target_p == NULL && wilds)
	{
		RB_DLINK_FOREACH(ptr, global_serv_list.head)
		{
			if(match(target_name, ((struct Client *)(ptr->data))->name))
			{
				target_p = ptr->data;
				break;
			}
		}
	}

	if(target_p != NULL && !IsRegistered(target_p))
		target_p = NULL;

	if(target_p != NULL)
	{
		if(IsMe(target_p) || MyClient(target_p))
			return HUNTED_ISME;

		saved = parv[server];
		parv[server] = get_id(target_p, target_p);
		sendto_one(target_p, command, get_id(source_p, target_p),
			   parv[1], parv[2], parv[3], parv[4],
			   parv[5], parv[6], parv[7], parv[8]);
		parv[server] = saved;
		return HUNTED_PASS;
	}

	if(MyClient(source_p) || !IsDigit(parv[server][0]))
		sendto_one_numeric(source_p, ERR_NOSUCHSERVER,
				   form_str(ERR_NOSUCHSERVER), parv[server]);
	return HUNTED_NOSUCH;
}

/*
 * try_connections - scan through configuration and try new connections.
 * Called periodically by the event loop; connects at most one server per call.
 */
void
try_connections(void *unused)
{
	struct server_conf *server_p = NULL;
	struct server_conf *tmp_p;
	rb_dlink_node *ptr;
	bool connecting = false;

	if(GlobalSetOptions.autoconn == 0)
		return;

	RB_DLINK_FOREACH(ptr, server_conf_list.head)
	{
		tmp_p = ptr->data;

		if(ServerConfIllegal(tmp_p) || !ServerConfAutoconn(tmp_p))
			continue;

		/* Don't attempt SSL links when SSL isn't available. */
		if(ServerConfSSL(tmp_p) && (!ircd_ssl_ok || !get_ssld_count()))
			continue;

		/* Skip entries still cooling down from a previous attempt. */
		if(tmp_p->hold > rb_current_time())
			continue;

		tmp_p->hold = rb_current_time() + get_con_freq(tmp_p->class);

		/* Connect only if the server isn't already linked and the
		 * class has room.  Pick the first eligible candidate. */
		if(!connecting &&
		   find_server(NULL, tmp_p->name) == NULL &&
		   CurrUsers(tmp_p->class) < MaxUsers(tmp_p->class))
		{
			server_p = tmp_p;
			connecting = true;
		}
	}

	if(!connecting)
		return;

	/* Rotate the chosen entry to the tail so the next scan tries a
	 * different server if multiple are eligible. */
	rb_dlinkDelete(&server_p->node, &server_conf_list);
	rb_dlinkAddTail(server_p, &server_p->node, &server_conf_list);

	/* Log before connecting; the callback may log an error immediately. */
	sendto_realops_snomask(SNO_GENERAL, L_ALL,
			"Connection to %s activated", server_p->name);

	serv_connect(server_p, 0);
}

int
check_server(const char *name, struct Client *client_p)
{
	struct server_conf *server_p = NULL;
	struct server_conf *tmp_p;
	rb_dlink_node *ptr;
	int error = -1;
	const char *encr;
	bool name_matched = false;
	bool host_matched = false;
	bool certfp_failed = false;

	s_assert(client_p != NULL);

	if(client_p->localClient->passwd == NULL)
		return -2;

	if(strlen(name) > HOSTLEN)
		return -4;

	RB_DLINK_FOREACH(ptr, server_conf_list.head)
	{
		struct rb_sockaddr_storage client_addr;

		tmp_p = ptr->data;

		if(ServerConfIllegal(tmp_p))
			continue;

		if(!match(tmp_p->name, name))
			continue;

		name_matched = true;

		if(rb_inet_pton_sock(client_p->sockhost, &client_addr) <= 0)
			SET_SS_FAMILY(&client_addr, AF_UNSPEC);

		if((tmp_p->connect_host && match(tmp_p->connect_host, client_p->host))
			|| (GET_SS_FAMILY(&client_addr) == GET_SS_FAMILY(&tmp_p->connect4)
				&& comp_with_mask_sock((struct sockaddr *)&client_addr,
					(struct sockaddr *)&tmp_p->connect4, 32))
			|| (GET_SS_FAMILY(&client_addr) == GET_SS_FAMILY(&tmp_p->connect6)
				&& comp_with_mask_sock((struct sockaddr *)&client_addr,
					(struct sockaddr *)&tmp_p->connect6, 128))
			)
		{
			host_matched = true;

			if(tmp_p->passwd)
			{
				if(ServerConfEncrypted(tmp_p))
				{
					encr = rb_crypt(client_p->localClient->passwd,
									tmp_p->passwd);
					if(encr != NULL && !strcmp(tmp_p->passwd, encr))
					{
						server_p = tmp_p;
						break;
					}
					else
						continue;
				}
				else if(strcmp(tmp_p->passwd, client_p->localClient->passwd))
					continue;
			}

			if(tmp_p->certfp)
			{
				if(!client_p->certfp || rb_strcasecmp(tmp_p->certfp, client_p->certfp) != 0) {
					certfp_failed = true;
					continue;
				}
			}

			server_p = tmp_p;
			break;
		}
	}

	if(server_p == NULL)
	{
		/* return the most specific error */
		if(certfp_failed)
			error = -6;
		else if(host_matched)
			error = -2;
		else if(name_matched)
			error = -3;

		return error;
	}

	if(ServerConfSSL(server_p) && client_p->localClient->ssl_ctl == NULL)
		return -5;

	/* Outgoing connections already attached to the correct class bypass
	 * the class limit check; all other cases must have room. */
	if(CurrUsers(server_p->class) >= MaxUsers(server_p->class))
	{
		struct server_conf *att = client_p->localClient->att_sconf;
		if(att == NULL || att->class != server_p->class)
			return -7;
	}
	attach_server_conf(client_p, server_p);

	/* clear TB if they support but we dont want it */
	if(!ServerConfTb(server_p))
		ClearCap(client_p, CAP_TB);

	return 0;
}

/*
 * send_capabilities
 *
 * inputs	- Client pointer to send to
 *		- int flag of capabilities that this server has
 * output	- NONE
 * side effects	- send the CAPAB line to a server  -orabidoo
 */
void
send_capabilities(struct Client *client_p, unsigned int cap_can_send)
{
	sendto_one(client_p, "CAPAB :%s", capability_index_list(serv_capindex, cap_can_send));
}

static void
burst_ban(struct Client *client_p)
{
	struct ConfItem *aconf;
	const char *type, *oper;
	/* +5 for !,@,{,} and null */
	char operbuf[NICKLEN + USERLEN + HOSTLEN + HOSTLEN + 5];
	char *p;
	size_t melen;
	rb_dictionary_iter state;

	melen = strlen(me.name);
	RB_DICTIONARY_FOREACH(aconf, &state, prop_bans_dict)
	{
		/* Skip expired stuff. */
		if(aconf->lifetime < rb_current_time())
			continue;
		switch(aconf->status & ~CONF_ILLEGAL)
		{
			case CONF_KILL: type = "K"; break;
			case CONF_DLINE: type = "D"; break;
			case CONF_XLINE: type = "X"; break;
			case CONF_RESV_NICK: type = "R"; break;
			case CONF_RESV_CHANNEL: type = "R"; break;
			default:
				continue;
		}
		oper = aconf->info.oper;
		if(aconf->flags & CONF_FLAGS_MYOPER)
		{
			/* Our operator{} names may not be meaningful
			 * to other servers, so rewrite to our server
			 * name.
			 */
			rb_strlcpy(operbuf, aconf->info.oper, sizeof operbuf);
			p = strrchr(operbuf, '{');
			if (p != NULL &&
					operbuf + sizeof operbuf - p > (ptrdiff_t)(melen + 2))
			{
				memcpy(p + 1, me.name, melen);
				p[melen + 1] = '}';
				p[melen + 2] = '\0';
				oper = operbuf;
			}
		}
		sendto_one(client_p, ":%s BAN %s %s %s %lu %d %d %s :%s%s%s",
				me.id,
				type,
				aconf->user ? aconf->user : "*", aconf->host,
				(unsigned long)aconf->created,
				(int)(aconf->hold - aconf->created),
				(int)(aconf->lifetime - aconf->created),
				oper,
				aconf->passwd,
				aconf->spasswd ? "|" : "",
				aconf->spasswd ? aconf->spasswd : "");
	}
}

/* burst_modes_TS6()
 *
 * input	- client to burst to, channel name, list to burst, mode flag
 * output	-
 * side effects - client is sent a list of +b, +e, or +I modes
 */
static void
burst_modes_TS6(struct Client *client_p, struct Channel *chptr,
		rb_dlink_list *list, char flag)
{
	rb_dlink_node *ptr;
	struct Ban *banptr;
	char *t;
	int tlen;
	int mlen;
	int cur_len;

	cur_len = mlen = snprintf(buf, sizeof(buf), ":%s BMASK %ld %s %c :",
				    me.id, (long) chptr->channelts, chptr->chname, flag);
	t = buf + mlen;

	RB_DLINK_FOREACH(ptr, list->head)
	{
		banptr = ptr->data;

		tlen = strlen(banptr->banstr) + (banptr->forward ? strlen(banptr->forward) + 1 : 0) + 1;

		/* uh oh */
		if(cur_len + tlen > BUFSIZE - 3)
		{
			/* the one we're trying to send doesnt fit at all! */
			if(cur_len == mlen)
			{
				s_assert(0);
				continue;
			}

			/* chop off trailing space and send.. */
			*(t-1) = '\0';
			sendto_one(client_p, "%s", buf);
			cur_len = mlen;
			t = buf + mlen;
		}

		if (banptr->forward)
			snprintf(t, buf + BUFSIZE - t, "%s$%s ", banptr->banstr, banptr->forward);
		else
			snprintf(t, buf + BUFSIZE - t, "%s ", banptr->banstr);
		t += tlen;
		cur_len += tlen;
	}

	/* cant ever exit the loop above without having modified buf,
	 * chop off trailing space and send.
	 */
	*(t-1) = '\0';
	sendto_one(client_p, "%s", buf);
}

/* burst_users_TS6 - send all user introductions to a newly linked server. */
static void
burst_users_TS6(struct Client *client_p, hook_data_client *hinfo)
{
	char ubuf[BUFSIZE];
	struct Client *target_p;
	rb_dlink_node *ptr;
	bool euid = IsCapable(client_p, CAP_EUID);

	RB_DLINK_FOREACH(ptr, global_client_list.head)
	{
		target_p = ptr->data;

		if(!IsPerson(target_p))
			continue;

		if(MyClient(target_p->from) &&
		   target_p->localClient->att_sconf != NULL &&
		   ServerConfNoExport(target_p->localClient->att_sconf))
			continue;

		send_umode(NULL, target_p, 0, ubuf);
		if(!*ubuf)
		{
			ubuf[0] = '+';
			ubuf[1] = '\0';
		}

		if(euid)
			sendto_one(client_p,
				   ":%s EUID %s %d %ld %s %s %s %s %s %s %s :%s",
				   target_p->servptr->id, target_p->name,
				   target_p->hopcount + 1, (long)target_p->tsinfo,
				   ubuf, target_p->username, target_p->host,
				   IsIPSpoof(target_p) ? "0" : target_p->sockhost,
				   target_p->id,
				   IsDynSpoof(target_p) ? target_p->orighost : "*",
				   EmptyString(target_p->user->suser) ? "*"
				                                      : target_p->user->suser,
				   target_p->info);
		else
			sendto_one(client_p,
				   ":%s UID %s %d %ld %s %s %s %s %s :%s",
				   target_p->servptr->id, target_p->name,
				   target_p->hopcount + 1, (long)target_p->tsinfo,
				   ubuf, target_p->username, target_p->host,
				   IsIPSpoof(target_p) ? "0" : target_p->sockhost,
				   target_p->id, target_p->info);

		if(!EmptyString(target_p->certfp))
			sendto_one(client_p, ":%s ENCAP * CERTFP :%s",
				   use_id(target_p), target_p->certfp);

		if(!euid)
		{
			if(IsDynSpoof(target_p))
				sendto_one(client_p, ":%s ENCAP * REALHOST %s",
					   use_id(target_p), target_p->orighost);
			if(!EmptyString(target_p->user->suser))
				sendto_one(client_p, ":%s ENCAP * LOGIN %s",
					   use_id(target_p), target_p->user->suser);
		}

		if(ConfigFileEntry.burst_away && !EmptyString(target_p->user->away))
			sendto_one(client_p, ":%s AWAY :%s",
				   use_id(target_p), target_p->user->away);

		if(IsOper(target_p) && target_p->user &&
		   target_p->user->opername && target_p->user->privset)
			sendto_one(client_p, ":%s OPER %s %s",
				   use_id(target_p),
				   target_p->user->opername,
				   target_p->user->privset->name);

		hinfo->target = target_p;
		call_hook(h_burst_client, hinfo);
	}
}

/* burst_channels_TS6 - send all channel state to a newly linked server. */
static void
burst_channels_TS6(struct Client *client_p, hook_data_channel *hinfo)
{
	struct Channel *chptr;
	struct membership *msptr;
	rb_dlink_node *ptr;
	rb_dlink_node *uptr;
	char *t;
	int tlen, mlen, cur_len;

	RB_DLINK_FOREACH(ptr, global_channel_list.head)
	{
		chptr = ptr->data;

		if(*chptr->chname != '#')
			continue;

		cur_len = mlen = snprintf(buf, sizeof(buf),
				":%s SJOIN %ld %s %s :", me.id,
				(long)chptr->channelts, chptr->chname,
				channel_modes(chptr, client_p));
		t = buf + mlen;

		RB_DLINK_FOREACH(uptr, chptr->members.head)
		{
			msptr = uptr->data;

			tlen = strlen(use_id(msptr->client_p)) + 1;
			if(is_admin(msptr))  tlen++;
			if(is_chanop(msptr)) tlen++;
			if(is_voiced(msptr)) tlen++;

			if(cur_len + tlen >= BUFSIZE - 3)
			{
				*(t - 1) = '\0';
				sendto_one(client_p, "%s", buf);
				cur_len = mlen;
				t = buf + mlen;
			}

			snprintf(t, buf + BUFSIZE - t, "%s%s ",
				 find_channel_status(msptr, 1),
				 use_id(msptr->client_p));
			cur_len += tlen;
			t += tlen;
		}

		if(rb_dlink_list_length(&chptr->members) > 0)
			*(t - 1) = '\0'; /* trim trailing space */
		sendto_one(client_p, "%s", buf);

		if(rb_dlink_list_length(&chptr->banlist) > 0)
			burst_modes_TS6(client_p, chptr, &chptr->banlist, 'b');

		if(IsCapable(client_p, CAP_EX) &&
		   rb_dlink_list_length(&chptr->exceptlist) > 0)
			burst_modes_TS6(client_p, chptr, &chptr->exceptlist, 'e');

		if(IsCapable(client_p, CAP_IE) &&
		   rb_dlink_list_length(&chptr->invexlist) > 0)
			burst_modes_TS6(client_p, chptr, &chptr->invexlist, 'I');

		if(IsCapable(client_p, CAP_TB) && chptr->topic != NULL)
			sendto_one(client_p, ":%s TB %s %ld %s%s:%s",
				   me.id, chptr->chname, (long)chptr->topic_time,
				   ConfigChannel.burst_topicwho ? chptr->topic_info : "",
				   ConfigChannel.burst_topicwho ? " " : "",
				   chptr->topic);

		if(IsCapable(client_p, CAP_MLOCK))
			sendto_one(client_p, ":%s MLOCK %ld %s :%s",
				   me.id, (long)chptr->channelts, chptr->chname,
				   EmptyString(chptr->mode_lock) ? "" : chptr->mode_lock);

		hinfo->chptr = chptr;
		call_hook(h_burst_channel, hinfo);
	}
}

/*
 * burst_TS6 - send the full network state (users then channels) to a newly
 * linked server.
 */
static void
burst_TS6(struct Client *client_p)
{
	hook_data_client hclientinfo;
	hook_data_channel hchaninfo;

	hclientinfo.client = hchaninfo.client = client_p;

	burst_users_TS6(client_p, &hclientinfo);
	burst_channels_TS6(client_p, &hchaninfo);

	hclientinfo.target = NULL;
	call_hook(h_burst_finished, &hclientinfo);
}

/*
 * show_capabilities - show current server capabilities
 *
 * inputs       - pointer to an struct Client
 * output       - pointer to static string
 * side effects - build up string representing capabilities of server listed
 */
const char *
show_capabilities(struct Client *target_p)
{
	static char msgbuf[BUFSIZE];

	*msgbuf = '\0';

	if(has_id(target_p))
		rb_strlcpy(msgbuf, " TS6", sizeof(msgbuf));

	if(IsSSL(target_p))
		rb_strlcat(msgbuf, " SSL", sizeof(msgbuf));

	if(!IsServer(target_p) || !target_p->serv->caps)	/* short circuit if no caps */
		return msgbuf + 1;

	rb_strlcat(msgbuf, " ", sizeof(msgbuf));
	rb_strlcat(msgbuf, capability_index_list(serv_capindex, target_p->serv->caps), sizeof(msgbuf));

	return msgbuf + 1;
}

/*
 * server_estab - complete the establishment of a server link.
 *
 * Finalises capability negotiation, registers the server in all relevant
 * data structures, broadcasts the new link to the rest of the network, and
 * triggers the full TS6 burst.
 */
int
server_estab(struct Client *client_p)
{
	struct Client *target_p;
	struct server_conf *server_p;
	hook_data_client hdata;
	rb_dlink_node *ptr;
	char note[HOSTLEN + 15];

	s_assert(client_p != NULL);

	if((server_p = client_p->localClient->att_sconf) == NULL)
	{
		sendto_realops_snomask(SNO_GENERAL,
				is_remote_connect(client_p) ? L_NETWIDE : L_ALL,
				"Warning: Lost connect{} block for server %s!",
				client_p->name);
		return exit_client(client_p, client_p, client_p,
				   "Lost connect{} block!");
	}

	/* Clear the password from memory now that auth is complete. */
	if(client_p->localClient->passwd != NULL)
	{
		memset(client_p->localClient->passwd, 0,
		       strlen(client_p->localClient->passwd));
		rb_free(client_p->localClient->passwd);
		client_p->localClient->passwd = NULL;
	}

	/* Servers always have ident. */
	SetGotId(client_p);

	if(IsUnknown(client_p))
	{
		/* the server may be linking based on certificate fingerprint now. --nenolod */
		sendto_one(client_p, "PASS %s TS %d :%s",
			   EmptyString(server_p->spasswd) ? "*" : server_p->spasswd, TS_CURRENT, me.id);

		/* pass info to new server */
		send_capabilities(client_p, default_server_capabs | CAP_MASK
				  | (ServerConfTb(server_p) ? CAP_TB : 0));

		sendto_one(client_p, "SERVER %s 1 :%s%s",
			   me.name,
			   ConfigServerHide.hidden ? "(H) " : "",
			   (me.info[0]) ? (me.info) : "IRCers United");
	}

	if(!rb_set_buffers(client_p->localClient->F, READBUF_SIZE))
		ilog_error("rb_set_buffers failed for server");

	client_p->servptr = &me;

	if(IsAnyDead(client_p))
		return CLIENT_EXITED;

	sendto_one(client_p, "SVINFO %d %d 0 :%ld", TS_CURRENT, TS_MIN, (long int)rb_current_time());

	rb_dlinkAdd(client_p, &client_p->lnode, &me.serv->servers);
	rb_dlinkMoveNode(&client_p->localClient->tnode, &unknown_list, &serv_list);
	rb_dlinkAddTailAlloc(client_p, &global_serv_list);

	if(has_id(client_p))
		add_to_id_hash(client_p->id, client_p);

	add_to_client_hash(client_p->name, client_p);
	/* doesnt duplicate client_p->serv if allocated this struct already */
	make_server(client_p);
	SetServer(client_p);

	client_p->serv->caps = client_p->localClient->caps;

	if(client_p->localClient->fullcaps)
	{
		client_p->serv->fullcaps = rb_strdup(client_p->localClient->fullcaps);
		rb_free(client_p->localClient->fullcaps);
		client_p->localClient->fullcaps = NULL;
	}

	client_p->serv->nameinfo = scache_connect(client_p->name, client_p->info, IsHidden(client_p));
	client_p->localClient->firsttime = rb_current_time();
	/* fixing eob timings.. -gnp */

	if((rb_dlink_list_length(&lclient_list) + rb_dlink_list_length(&serv_list)) >
	   (unsigned long)MaxConnectionCount)
		MaxConnectionCount = rb_dlink_list_length(&lclient_list) +
					rb_dlink_list_length(&serv_list);

	/* Show the real host/IP to admins */
	sendto_realops_snomask(SNO_GENERAL, L_ALL,
			"Link with %s established: (%s) link",
			client_p->name,
			show_capabilities(client_p));

	ilog(L_SERVER, "Link with %s established: (%s) link",
	     log_client_name(client_p, SHOW_IP), show_capabilities(client_p));

	hdata.client = &me;
	hdata.target = client_p;
	call_hook(h_server_introduced, &hdata);

	snprintf(note, sizeof(note), "Server: %s", client_p->name);
	rb_note(client_p->localClient->F, note);

	/* Notify all existing servers about the new link. */
	RB_DLINK_FOREACH(ptr, serv_list.head)
	{
		target_p = ptr->data;

		if(target_p == client_p)
			continue;

		if(target_p->localClient->att_sconf != NULL && ServerConfNoExport(target_p->localClient->att_sconf))
			continue;

		if(has_id(target_p) && has_id(client_p))
		{
			sendto_one(target_p, ":%s SID %s 2 %s :%s%s",
				   me.id, client_p->name, client_p->id,
				   IsHidden(client_p) ? "(H) " : "", client_p->info);

			if(!EmptyString(client_p->serv->fullcaps))
				sendto_one(target_p, ":%s ENCAP * GCAP :%s",
					client_p->id, client_p->serv->fullcaps);
		}
		else
		{
			sendto_one(target_p, ":%s SERVER %s 2 :%s%s",
				   me.name, client_p->name,
				   IsHidden(client_p) ? "(H) " : "", client_p->info);

			if(!EmptyString(client_p->serv->fullcaps))
				sendto_one(target_p, ":%s ENCAP * GCAP :%s",
					client_p->name, client_p->serv->fullcaps);
		}
	}

	/* Propagate topology: send the new server the rest of the network. */
	RB_DLINK_FOREACH(ptr, global_serv_list.head)
	{
		target_p = ptr->data;

		/* target_p->from == target_p for target_p == client_p */
		if(IsMe(target_p) || target_p->from == client_p)
			continue;

		/* don't distribute downstream leaves of servers that are no-export */
		if(MyClient(target_p->from) && target_p->from->localClient->att_sconf != NULL && ServerConfNoExport(target_p->from->localClient->att_sconf))
			continue;

		/* presumption, if target has an id, so does its uplink */
		if(has_id(client_p) && has_id(target_p))
			sendto_one(client_p, ":%s SID %s %d %s :%s%s",
				   target_p->servptr->id, target_p->name,
				   target_p->hopcount + 1, target_p->id,
				   IsHidden(target_p) ? "(H) " : "", target_p->info);
		else
			sendto_one(client_p, ":%s SERVER %s %d :%s%s",
				   target_p->servptr->name,
				   target_p->name, target_p->hopcount + 1,
				   IsHidden(target_p) ? "(H) " : "", target_p->info);

		if(!EmptyString(target_p->serv->fullcaps))
			sendto_one(client_p, ":%s ENCAP * GCAP :%s",
					get_id(target_p, client_p),
					target_p->serv->fullcaps);
	}

	if(IsCapable(client_p, CAP_BAN))
		burst_ban(client_p);

	burst_TS6(client_p);

	/* Always send a PING after connect burst is done */
	sendto_one(client_p, "PING :%s", get_id(&me, client_p));

	free_pre_client(client_p);

	send_pop_queue(client_p);

	return 0;
}

/*
 * serv_setup_addresses - populate sa_connect/sa_bind arrays from server_conf.
 *
 * When both IPv4 and IPv6 addresses are available and aftype is unspecified,
 * the order is randomised so that successive auto-connect attempts alternate
 * address families.  Returns true if at least one address was resolved.
 */
static bool
serv_setup_addresses(const struct server_conf *server_p,
		     struct sockaddr_storage sa_connect[2],
		     struct sockaddr_storage sa_bind[2])
{
	bool have4 = GET_SS_FAMILY(&server_p->connect4) == AF_INET;
	bool have6 = GET_SS_FAMILY(&server_p->connect6) == AF_INET6;

	for(int i = 0; i < 2; i++)
	{
		SET_SS_FAMILY(&sa_connect[i], AF_UNSPEC);
		SET_SS_FAMILY(&sa_bind[i], AF_UNSPEC);
	}

	if(server_p->aftype == AF_UNSPEC && have4 && have6)
	{
		/* Randomly prefer IPv4 or IPv6 for load-balancing. */
		if(rand() % 2 == 0)
		{
			sa_connect[0] = server_p->connect4; sa_bind[0] = server_p->bind4;
			sa_connect[1] = server_p->connect6; sa_bind[1] = server_p->bind6;
		}
		else
		{
			sa_connect[0] = server_p->connect6; sa_bind[0] = server_p->bind6;
			sa_connect[1] = server_p->connect4; sa_bind[1] = server_p->bind4;
		}
	}
	else if(server_p->aftype == AF_INET || have4)
	{
		sa_connect[0] = server_p->connect4;
		sa_bind[0]    = server_p->bind4;
	}
	else if(server_p->aftype == AF_INET6 || have6)
	{
		sa_connect[0] = server_p->connect6;
		sa_bind[0]    = server_p->bind6;
	}

	return GET_SS_FAMILY(&sa_connect[0]) != AF_UNSPEC;
}

/*
 * serv_connect - initiate an outgoing server connection.
 *
 * Returns 1 if the connection attempt was started, 0 on failure.
 * Completion (success or error) is handled by serv_connect_callback().
 */
int
serv_connect(struct server_conf *server_p, struct Client *by)
{
	struct Client *client_p;
	struct sockaddr_storage sa_connect[2];
	struct sockaddr_storage sa_bind[2];
	char note[HOSTLEN + 10];
	rb_fde_t *F;

	s_assert(server_p != NULL);

	if(!serv_setup_addresses(server_p, sa_connect, sa_bind))
	{
		ilog_error("unspecified socket address family");
		return 0;
	}

	/* Log the target address(es). */
#ifdef HAVE_LIBSCTP
	if(ServerConfSCTP(server_p) && GET_SS_FAMILY(&sa_connect[1]) != AF_UNSPEC)
	{
		char buf2[HOSTLEN + 1];
		buf[0] = buf2[0] = '\0';
		rb_inet_ntop_sock((struct sockaddr *)&sa_connect[0], buf, sizeof(buf));
		rb_inet_ntop_sock((struct sockaddr *)&sa_connect[1], buf2, sizeof(buf2));
		ilog(L_SERVER, "Connect to *[%s] @%s&%s", server_p->name, buf, buf2);
	}
	else
#endif
	{
		buf[0] = '\0';
		rb_inet_ntop_sock((struct sockaddr *)&sa_connect[0], buf, sizeof(buf));
		ilog(L_SERVER, "Connect to *[%s] @%s", server_p->name, buf);
	}

	/* Reject if already connected. */
	if((client_p = find_server(NULL, server_p->name)) != NULL)
	{
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
				"Server %s already present from %s",
				server_p->name, client_p->name);
		if(by != NULL && IsPerson(by) && !MyClient(by))
			sendto_one_notice(by, ":Server %s already present from %s",
					  server_p->name, client_p->name);
		return 0;
	}

	/* Reject if the class is full. */
	if(CurrUsers(server_p->class) >= MaxUsers(server_p->class))
	{
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
				"No more connections allowed in class \"%s\" for server %s",
				server_p->class->class_name, server_p->name);
		if(by != NULL && IsPerson(by) && !MyClient(by))
			sendto_one_notice(by,
				":No more connections allowed in class \"%s\" for server %s",
				server_p->class->class_name, server_p->name);
		return 0;
	}

	/* Open the socket. */
#ifdef HAVE_LIBSCTP
	if(ServerConfSCTP(server_p))
		F = rb_socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP, NULL);
	else
#endif
		F = rb_socket(GET_SS_FAMILY(&sa_connect[0]), SOCK_STREAM, IPPROTO_TCP, NULL);

	if(F == NULL)
	{
		ilog_error("opening a stream socket");
		return 0;
	}

	snprintf(note, sizeof(note), "Server: %s", server_p->name);
	rb_note(F, note);

	/* Build the outgoing client. */
	client_p = make_client(NULL);
	rb_strlcpy(client_p->name, server_p->name, sizeof(client_p->name));
	rb_strlcpy(client_p->host,
		   server_p->connect_host ? server_p->connect_host : buf,
		   sizeof(client_p->host));
	rb_strlcpy(client_p->sockhost, buf, sizeof(client_p->sockhost));
	client_p->localClient->F = F;

	SET_SS_PORT(&sa_connect[0], htons(server_p->port));
	SET_SS_PORT(&sa_connect[1], htons(server_p->port));

	if(!rb_set_buffers(client_p->localClient->F, READBUF_SIZE))
		ilog_error("setting the buffer size for a server connection");

	/* Attach config before the callback fires to prevent null-deref. */
	attach_server_conf(client_p, server_p);

	make_server(client_p);
	rb_strlcpy(client_p->serv->by,
		   (by != NULL && IsClient(by)) ? by->name : "AutoConn.",
		   sizeof(client_p->serv->by));

	SetConnecting(client_p);
	rb_dlinkAddTail(client_p, &client_p->node, &global_client_list);

	/* Fill in any missing bind addresses from global server info. */
	for(int i = 0; i < 2; i++)
	{
		if(GET_SS_FAMILY(&sa_bind[i]) == AF_UNSPEC)
		{
			if(GET_SS_FAMILY(&sa_connect[i]) == GET_SS_FAMILY(&ServerInfo.bind4))
				sa_bind[i] = ServerInfo.bind4;
			else if(GET_SS_FAMILY(&sa_connect[i]) == GET_SS_FAMILY(&ServerInfo.bind6))
				sa_bind[i] = ServerInfo.bind6;
		}
	}

#ifdef HAVE_LIBSCTP
	if(ServerConfSCTP(server_p))
	{
		rb_connect_sctp(client_p->localClient->F,
			sa_connect, ARRAY_SIZE(sa_connect),
			sa_bind, ARRAY_SIZE(sa_bind),
			ServerConfSSL(server_p) ? serv_connect_ssl_callback
			                        : serv_connect_callback,
			client_p, ConfigFileEntry.connect_timeout);
	}
	else
#endif
	{
		rb_connect_tcp(client_p->localClient->F,
			(struct sockaddr *)&sa_connect[0],
			GET_SS_FAMILY(&sa_bind[0]) == AF_UNSPEC
				? NULL : (struct sockaddr *)&sa_bind[0],
			ServerConfSSL(server_p) ? serv_connect_ssl_callback
			                        : serv_connect_callback,
			client_p, ConfigFileEntry.connect_timeout);
	}
	return 1;
}

static void
serv_connect_ssl_callback(rb_fde_t *F, int status, void *data)
{
	struct Client *client_p = data;
	rb_fde_t *xF[2];

	rb_connect_sockaddr(F, (struct sockaddr *)&client_p->localClient->ip,
			    sizeof(client_p->localClient->ip));

	if(status != RB_OK)
	{
		serv_connect_callback(F, status, data);
		return;
	}

	if(rb_socketpair(AF_UNIX, SOCK_STREAM, 0, &xF[0], &xF[1],
			 "Outgoing ssld connection") == -1)
	{
		ilog_error("rb_socketpair failed for server");
		serv_connect_callback(F, RB_ERROR, data);
		return;
	}

	client_p->localClient->F = xF[0];
	client_p->localClient->ssl_callback = serv_connect_ssl_open_callback;
	client_p->localClient->ssl_ctl = start_ssld_connect(F, xF[1],
							     connid_get(client_p));
	if(client_p->localClient->ssl_ctl == NULL)
	{
		serv_connect_callback(client_p->localClient->F, RB_ERROR, data);
		return;
	}
	SetSSL(client_p);
}

static int
serv_connect_ssl_open_callback(struct Client *client_p, int status)
{
	serv_connect_callback(client_p->localClient->F, status, client_p);
	return 1; /* suppress default exit_client handler on error */
}

/*
 * serv_connect_callback - complete an outgoing server connection.
 *
 * Called once the TCP (or SCTP/SSL) handshake finishes.  On failure,
 * notifies ops and tears down the client.  On success, sends PASS/CAPAB/SERVER
 * and begins reading from the new link.
 */
static void
serv_connect_callback(rb_fde_t *F, int status, void *data)
{
	struct Client *client_p = data;
	struct server_conf *server_p;
	int snomask_scope;

	s_assert(client_p != NULL);
	s_assert(client_p->localClient->F == F);

	/* Race: the server linked via another path while we were connecting. */
	if(find_server(NULL, client_p->name) != NULL)
	{
		exit_client(client_p, client_p, &me, "Server Exists");
		return;
	}

	/* Record the peer address for non-SSL connections (SSL callback does it). */
	if(client_p->localClient->ssl_ctl == NULL)
		rb_connect_sockaddr(F, (struct sockaddr *)&client_p->localClient->ip,
				    sizeof(client_p->localClient->ip));

	snomask_scope = is_remote_connect(client_p) ? L_NETWIDE : L_ALL;

	if(status != RB_OK)
	{
		if(status == RB_ERR_TIMEOUT || status == RB_ERROR_SSL)
		{
			/* No errno for timeout/SSL errors. */
			sendto_realops_snomask(SNO_GENERAL, snomask_scope,
					"Error connecting to %s[%s]: %s",
					client_p->name, client_p->sockhost,
					rb_errstr(status));
			ilog(L_SERVER, "Error connecting to %s[%s]: %s",
				client_p->name, client_p->sockhost,
				rb_errstr(status));
		}
		else
		{
			const char *errstr = strerror(rb_get_sockerr(F));
			sendto_realops_snomask(SNO_GENERAL, snomask_scope,
					"Error connecting to %s[%s]: %s (%s)",
					client_p->name, client_p->sockhost,
					rb_errstr(status), errstr);
			ilog(L_SERVER, "Error connecting to %s[%s]: %s (%s)",
				client_p->name, client_p->sockhost,
				rb_errstr(status), errstr);
		}

		exit_client(client_p, client_p, &me, rb_errstr(status));
		return;
	}

	if((server_p = client_p->localClient->att_sconf) == NULL)
	{
		sendto_realops_snomask(SNO_GENERAL, snomask_scope,
				"Lost connect{} block for %s", client_p->name);
		exit_client(client_p, client_p, &me, "Lost connect{} block");
		return;
	}

	if(server_p->certfp != NULL &&
	   (client_p->certfp == NULL ||
	    rb_strcasecmp(server_p->certfp, client_p->certfp) != 0))
	{
		sendto_realops_snomask(SNO_GENERAL, snomask_scope,
			"Connection to %s has invalid certificate fingerprint %s",
			client_p->name, client_p->certfp);
		ilog(L_SERVER,
			"Access denied, invalid certificate fingerprint %s from %s",
			client_p->certfp, log_client_name(client_p, SHOW_IP));
		exit_client(client_p, client_p, &me, "Invalid fingerprint.");
		return;
	}

	SetHandshake(client_p);

	sendto_one(client_p, "PASS %s TS %d :%s",
		   EmptyString(server_p->spasswd) ? "*" : server_p->spasswd,
		   TS_CURRENT, me.id);

	send_capabilities(client_p, default_server_capabs | CAP_MASK
			  | (ServerConfTb(server_p) ? CAP_TB : 0));

	sendto_one(client_p, "SERVER %s 1 :%s%s",
		   me.name, ConfigServerHide.hidden ? "(H) " : "", me.info);

	if(IsAnyDead(client_p))
	{
		sendto_realops_snomask(SNO_GENERAL, snomask_scope,
				"%s went dead during handshake", client_p->name);
		exit_client(client_p, client_p, &me, "Went dead during handshake");
		return;
	}

	/* Don't move to serv_list yet — burst hasn't been sent. */
	read_packet(F, client_p);
}
