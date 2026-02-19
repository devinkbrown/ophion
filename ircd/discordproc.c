/*
 * ircd/discordproc.c - Discord bridge helper process management
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
 * discordproc manages the discordd helper process and bridges messages
 * between the Discord Gateway and Ophion's internal channel/user machinery.
 *
 * Each Discord user that speaks in a bridged channel is represented in IRC
 * as a "phantom" local client (nick!discord@discord.invalid).  Phantom
 * clients are created on first message and removed when the module is
 * unloaded or when explicitly cleaned up.
 *
 * Message routing:
 *   Discord -> IRC:  discordd sends a 'P' line; we find or create the
 *                    phantom client, then PRIVMSG the mapped IRC channel.
 *   IRC -> Discord:  h_privmsg_channel hook fires; if the target channel
 *                    is bridged and the sender is not a phantom, we forward
 *                    the text to discordd with an 'M' command.
 */

#include "stdinc.h"
#include "rb_lib.h"
#include "client.h"
#include "channel.h"
#include "hash.h"
#include "hook.h"
#include "ircd.h"
#include "ircd_defs.h"
#include "logger.h"
#include "modules.h"
#include "newconf.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"
#include "discordproc.h"

/* -------------------------------------------------------------------------
 * Module-level state
 * ---------------------------------------------------------------------- */

struct DiscordConfig discord_config;
rb_helper *discord_helper = NULL;

/* nick -> struct Client* for every active phantom. */
static rb_dictionary *phantom_by_nick = NULL;

/* discord_user_id -> struct Client* for every active phantom. */
static rb_dictionary *phantom_by_uid = NULL;

/* discord_channel_id -> irc_channel_name  (char* -> char*) */
static rb_dictionary *discord_to_irc = NULL;

/* irc_channel_name -> discord_channel_id (char* -> char*) */
static rb_dictionary *irc_to_discord = NULL;

static char *discordd_path = NULL;

/* -------------------------------------------------------------------------
 * Forward declarations
 * ---------------------------------------------------------------------- */

static int  start_discordd(void);
static void parse_discordd_reply(rb_helper *helper);
static void restart_discordd_cb(rb_helper *helper);
static void discord_configure(void);
static struct Client *discord_find_or_create_phantom(const char *nick,
						     const char *user_id);
static void discord_phantom_join_channel(struct Client *phantom,
					 const char *chname);
static void discord_exit_all_phantoms(void);
static void hook_discord_privmsg(void *vdata);

/* -------------------------------------------------------------------------
 * Percent-encoding helpers
 * ---------------------------------------------------------------------- */

/*
 * pct_encode - percent-encode a string for safe transport in our line
 * protocol.  Only spaces, newlines, carriage returns, and '%' itself are
 * encoded; everything else is left as-is.
 */
static void
pct_encode(const char *src, char *dst, size_t dstsz)
{
	size_t i = 0;

	while(*src && i + 4 < dstsz)
	{
		unsigned char c = (unsigned char)*src;
		if(c == ' ' || c == '\n' || c == '\r' || c == '%')
		{
			dst[i++] = '%';
			dst[i++] = "0123456789ABCDEF"[c >> 4];
			dst[i++] = "0123456789ABCDEF"[c & 0xF];
		}
		else
		{
			dst[i++] = c;
		}
		src++;
	}
	dst[i] = '\0';
}

static int
hex_val(char c)
{
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	return 0;
}

/*
 * pct_decode - decode a percent-encoded string in place.
 */
static void
pct_decode(char *s)
{
	char *r = s, *w = s;

	while(*r)
	{
		if(*r == '%' && r[1] && r[2])
		{
			*w++ = (char)((hex_val(r[1]) << 4) | hex_val(r[2]));
			r += 3;
		}
		else
		{
			*w++ = *r++;
		}
	}
	*w = '\0';
}

/* -------------------------------------------------------------------------
 * Nick sanitisation
 * ---------------------------------------------------------------------- */

/*
 * discord_sanitise_nick - turn a Discord username into a valid IRC nick.
 * Spaces become underscores; non-ASCII and characters not valid in IRC
 * nicks are stripped.  The result is at most DISCORD_NICK_LEN chars.
 */
static void
discord_sanitise_nick(const char *src, char *dst, size_t dstsz)
{
	size_t i = 0;
	size_t max = dstsz - 1;
	if(max > DISCORD_NICK_LEN)
		max = DISCORD_NICK_LEN;

	/* A nick must not start with a digit or '-'. */
	if(*src == '-' || (*src >= '0' && *src <= '9'))
		dst[i++] = '_';

	while(*src && i < max)
	{
		unsigned char c = (unsigned char)*src;
		if(c == ' ')
			dst[i++] = '_';
		else if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' ||
			c == '[' || c == ']' || c == '\\' || c == '`' ||
			c == '^' || c == '{' || c == '|' || c == '}')
			dst[i++] = c;
		/* else skip */
		src++;
	}

	if(i == 0)
	{
		rb_strlcpy(dst, "Discord_User", dstsz);
		return;
	}
	dst[i] = '\0';
}

/* -------------------------------------------------------------------------
 * Channel map helpers
 * ---------------------------------------------------------------------- */

static void
build_channel_maps(void)
{
	rb_dlink_node *ptr;
	struct DiscordChannelMap *map;

	/* Tear down old maps */
	if(discord_to_irc)
		rb_dictionary_destroy(discord_to_irc, NULL, NULL);
	if(irc_to_discord)
		rb_dictionary_destroy(irc_to_discord, NULL, NULL);

	discord_to_irc = rb_dictionary_create("discord->irc channel map",
					      rb_strcasecmp);
	irc_to_discord = rb_dictionary_create("irc->discord channel map",
					      rb_strcasecmp);

	RB_DLINK_FOREACH(ptr, discord_config.channel_maps.head)
	{
		map = ptr->data;
		rb_dictionary_add(discord_to_irc,
				  map->discord_channel_id,
				  map->irc_channel);
		rb_dictionary_add(irc_to_discord,
				  map->irc_channel,
				  map->discord_channel_id);
	}
}

/* -------------------------------------------------------------------------
 * Helper process management
 * ---------------------------------------------------------------------- */

static int
start_discordd(void)
{
	char fullpath[PATH_MAX + 1];
#ifdef _WIN32
	const char *suffix = ".exe";
#else
	const char *suffix = "";
#endif

	if(discordd_path == NULL)
	{
		snprintf(fullpath, sizeof(fullpath), "%s%cdiscordd%s",
			 ircd_paths[IRCD_PATH_LIBEXEC],
			 RB_PATH_SEPARATOR, suffix);

		if(access(fullpath, X_OK) == -1)
		{
			snprintf(fullpath, sizeof(fullpath),
				 "%s%cbin%cdiscordd%s",
				 ConfigFileEntry.dpath,
				 RB_PATH_SEPARATOR,
				 RB_PATH_SEPARATOR, suffix);

			if(access(fullpath, X_OK) == -1)
			{
				ierror("Unable to find discordd in %s or %s/bin",
				       ircd_paths[IRCD_PATH_LIBEXEC],
				       ConfigFileEntry.dpath);
				sendto_realops_snomask(SNO_GENERAL, L_ALL,
					"Unable to find discordd in %s or %s/bin",
					ircd_paths[IRCD_PATH_LIBEXEC],
					ConfigFileEntry.dpath);
				return 1;
			}
		}
		discordd_path = rb_strdup(fullpath);
	}

	discord_helper = rb_helper_start("discordd", discordd_path,
					 parse_discordd_reply,
					 restart_discordd_cb);
	if(discord_helper == NULL)
	{
		ierror("Unable to start discordd helper: %s", strerror(errno));
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
			"Unable to start discordd helper: %s", strerror(errno));
		return 1;
	}

	ilog(L_MAIN, "discordd helper started");
	sendto_realops_snomask(SNO_GENERAL, L_ALL, "discordd helper started");
	rb_helper_run(discord_helper);

	/* Send initial configuration to the daemon. */
	discord_configure();
	return 0;
}

static void
restart_discordd_cb(rb_helper *helper)
{
	(void)helper;
	discord_exit_all_phantoms();
	discord_helper = NULL;
	ilog(L_MAIN, "discordd helper died; restarting");
	sendto_realops_snomask(SNO_GENERAL, L_ALL,
			       "discordd helper died; restarting");
	start_discordd();
}

/*
 * discord_configure - send token + guild_id to discordd after (re)start
 * or rehash.
 */
static void
discord_configure(void)
{
	rb_dlink_node *ptr;
	struct DiscordChannelMap *map;

	if(discord_helper == NULL || !discord_config.enabled)
		return;

	if(EmptyString(discord_config.token) ||
	   EmptyString(discord_config.guild_id))
		return;

	rb_helper_write(discord_helper, "C %s %s",
			discord_config.token,
			discord_config.guild_id);

	/* Send all channel mappings. */
	RB_DLINK_FOREACH(ptr, discord_config.channel_maps.head)
	{
		map = ptr->data;
		rb_helper_write(discord_helper, "B %s %s",
				map->discord_channel_id,
				map->irc_channel);
	}
}

/* -------------------------------------------------------------------------
 * Phantom client management
 * ---------------------------------------------------------------------- */

/*
 * discord_find_or_create_phantom - look up (or create) a phantom IRC client
 * for the given Discord user.
 */
static struct Client *
discord_find_or_create_phantom(const char *nick, const char *user_id)
{
	struct Client *client_p;
	struct User *user;
	char safe_nick[NICKLEN + 1];
	char uid_buf[DISCORD_SNOWFLAKE_LEN + 1];
	int suffix = 0;

	/* Have we seen this Discord user before? */
	client_p = rb_dictionary_retrieve(phantom_by_uid, user_id);
	if(client_p != NULL)
		return client_p;

	/* Sanitise nick and ensure uniqueness. */
	discord_sanitise_nick(nick, safe_nick, sizeof(safe_nick));

	/* If the nick is already taken, append a numeric suffix. */
	while(find_client(safe_nick) != NULL)
	{
		if(suffix > 999)
		{
			ilog(L_MAIN, "discord: could not find unique nick for %s", nick);
			return NULL;
		}
		discord_sanitise_nick(nick, safe_nick, sizeof(safe_nick) - 4);
		snprintf(safe_nick + strlen(safe_nick),
			 sizeof(safe_nick) - strlen(safe_nick),
			 "_%d", ++suffix);
	}

	rb_strlcpy(uid_buf, user_id, sizeof(uid_buf));

	/* Allocate the client. */
	client_p = make_client(NULL);

	rb_strlcpy(client_p->name, safe_nick, sizeof(client_p->name));
	rb_strlcpy(client_p->username, "discord", USERLEN + 1);
	rb_strlcpy(client_p->host, "discord.invalid", HOSTLEN + 1);
	rb_strlcpy(client_p->orighost, "discord.invalid", HOSTLEN + 1);
	rb_strlcpy(client_p->sockhost, "discord.invalid", HOSTIPLEN + 1);
	rb_strlcpy(client_p->info, "Discord User", REALLEN + 1);

	client_p->tsinfo = rb_current_time();
	client_p->hopcount = 0;

	user = make_user(client_p);
	(void)user;

	/* Assign a server-unique UID. */
	rb_strlcpy(client_p->id, generate_uid(), sizeof(client_p->id));
	add_to_id_hash(client_p->id, client_p);
	add_to_client_hash(safe_nick, client_p);
	add_to_hostname_hash("discord.invalid", client_p);

	/* Promote from unknown_list to lclient_list and mark as Client. */
	rb_dlinkMoveNode(&client_p->localClient->tnode,
			 &unknown_list, &lclient_list);
	SetClient(client_p);

	/* Attach to this server. */
	client_p->servptr = &me;
	rb_dlinkAdd(client_p, &client_p->lnode, &me.serv->users);

	if(++Count.total > Count.max_tot)
		Count.max_tot = Count.total;
	Count.totalrestartcount++;

	/* Mark as a service so most spam/flood guards ignore it. */
	client_p->flags |= FLAGS_SERVICE;

	/* Announce to the network. */
	introduce_client(&me, client_p, client_p->user, safe_nick, 1);

	/* Register in our own dictionaries. */
	rb_dictionary_add(phantom_by_nick, safe_nick, client_p);
	rb_dictionary_add(phantom_by_uid, uid_buf, client_p);

	ilog(L_MAIN, "discord: introduced phantom %s (uid %s)",
	     safe_nick, user_id);
	return client_p;
}

/*
 * discord_phantom_join_channel - join a phantom client to an IRC channel
 * if not already a member.
 */
static void
discord_phantom_join_channel(struct Client *phantom, const char *chname)
{
	struct Channel *chptr;
	bool isnew;

	if(find_channel_membership(find_channel(chname), phantom) != NULL)
		return; /* already joined */

	chptr = get_or_create_channel(phantom, chname, &isnew);
	if(chptr == NULL)
		return;

	add_user_to_channel(chptr, phantom, 0);
	send_channel_join(chptr, phantom);

	sendto_server(phantom, chptr, CAP_TS6, NOCAPS,
		      ":%s JOIN %ld %s +",
		      phantom->id, (long)chptr->channelts, chptr->chname);
}

/*
 * discord_exit_all_phantoms - QUIT all phantom clients (called on shutdown
 * or module unload).
 */
static void
discord_exit_all_phantoms(void)
{
	rb_dictionary_iter iter;
	struct Client *client_p;

	if(phantom_by_uid == NULL)
		return;

	RB_DICTIONARY_FOREACH(client_p, &iter, phantom_by_uid)
	{
		exit_client(client_p, client_p, &me, "Discord bridge shutdown");
	}

	rb_dictionary_destroy(phantom_by_uid, NULL, NULL);
	rb_dictionary_destroy(phantom_by_nick, NULL, NULL);
	phantom_by_uid = rb_dictionary_create("discord uid->client",
					      rb_strcasecmp);
	phantom_by_nick = rb_dictionary_create("discord nick->client",
					       rb_strcasecmp);
}

/* -------------------------------------------------------------------------
 * Parsing replies from discordd
 * ---------------------------------------------------------------------- */

static void
parse_discordd_reply(rb_helper *helper)
{
	char buf[READBUF_SIZE];
	int len;

	while((len = rb_helper_read(helper, buf, sizeof(buf))) > 0)
	{
		char *argv[MAXPARA + 1];
		int parc;

		buf[len] = '\0';
		parc = rb_string_to_array(buf, argv, MAXPARA);
		if(parc < 1 || argv[0] == NULL || argv[0][0] == '\0')
			continue;

		switch(argv[0][0])
		{
		/*
		 * G <guild_name_pct>
		 * Gateway READY — Discord connection established.
		 */
		case 'G':
			if(parc < 2) break;
			pct_decode(argv[1]);
			ilog(L_MAIN, "discord: gateway ready (guild: %s)",
			     argv[1]);
			sendto_realops_snomask(SNO_GENERAL, L_ALL,
				"Discord bridge: connected to guild \"%s\"",
				argv[1]);
			break;

		/*
		 * P <channel_id> <user_id> <nick> <msgid> :<text_pct>
		 * Discord message received.
		 */
		case 'P':
		{
			struct Client *phantom;
			const char *channel_id, *user_id, *nick, *text;
			const char *irc_channel;

			if(parc < 6) break;
			channel_id = argv[1];
			user_id    = argv[2];
			nick       = argv[3];
			/* argv[4] is the Discord msgid — reserved for future use */
			text       = argv[5];

			irc_channel = rb_dictionary_retrieve(discord_to_irc,
							     channel_id);
			if(irc_channel == NULL)
				break; /* not a bridged channel */

			phantom = discord_find_or_create_phantom(nick, user_id);
			if(phantom == NULL)
				break;

			discord_phantom_join_channel(phantom, irc_channel);

			/* Deliver the message. */
			{
				char decoded[BUFSIZE];
				struct Channel *chptr;

				rb_strlcpy(decoded, text, sizeof(decoded));
				pct_decode(decoded);

				chptr = find_channel(irc_channel);
				if(chptr == NULL)
					break;

				sendto_channel_local(NULL, ALL_MEMBERS, chptr,
					":%s!%s@%s PRIVMSG %s :%s",
					phantom->name,
					phantom->username,
					phantom->host,
					chptr->chname,
					decoded);

				sendto_server(phantom, chptr, CAP_TS6, NOCAPS,
					":%s PRIVMSG %s :%s",
					phantom->id, chptr->chname, decoded);
			}
			break;
		}

		/*
		 * Y <channel_id> <user_id> <nick>
		 * Discord user started typing.
		 */
		case 'Y':
		{
			/* Nothing to do at the IRC level for now — we could
			 * forward a draft/typing TAGMSG here in the future. */
			break;
		}

		/*
		 * D <channel_id> <msgid>
		 * Discord message deleted.
		 */
		case 'D':
			/* No standard IRC mechanism for message deletion;
			 * could emit a NOTICE in the future. */
			break;

		/*
		 * E <channel_id> <msgid> :<new_text_pct>
		 * Discord message edited.
		 */
		case 'E':
		{
			/* Could emit a NOTICE "* nick edited: …" in the future. */
			break;
		}

		/*
		 * W <level> :<message_pct>
		 * Warning/log message from discordd.
		 */
		case 'W':
		{
			if(parc < 3) break;
			char msg[BUFSIZE];
			rb_strlcpy(msg, argv[2], sizeof(msg));
			pct_decode(msg);
			switch(argv[1][0])
			{
			case 'C':
				sendto_realops_snomask(SNO_GENERAL, L_ALL,
					"Discord bridge [CRIT]: %s", msg);
				ilog(L_MAIN, "discord [CRIT]: %s", msg);
				break;
			case 'W':
				sendto_realops_snomask(SNO_GENERAL, L_ALL,
					"Discord bridge [WARN]: %s", msg);
				ilog(L_MAIN, "discord [warn]: %s", msg);
				break;
			case 'I':
				ilog(L_MAIN, "discord [info]: %s", msg);
				break;
			default:
				ilog(L_MAIN, "discord [debug]: %s", msg);
				break;
			}
			break;
		}

		default:
			ilog(L_MAIN, "discord: unknown reply '%c'",
			     argv[0][0]);
			break;
		}
	}
}

/* -------------------------------------------------------------------------
 * h_privmsg_channel hook — forward IRC messages to Discord
 * ---------------------------------------------------------------------- */

static void
hook_discord_privmsg(void *vdata)
{
	hook_data_privmsg_channel *data = vdata;
	const char *discord_channel_id;
	char encoded[BUFSIZE];

	if(data->approved != 0)
		return; /* message was blocked upstream */

	/* Don't echo phantom-originated messages back to Discord. */
	if(data->source_p->flags & FLAGS_SERVICE)
		return;

	if(irc_to_discord == NULL)
		return;

	discord_channel_id = rb_dictionary_retrieve(irc_to_discord,
						    data->chptr->chname);
	if(discord_channel_id == NULL)
		return;

	pct_encode(data->text, encoded, sizeof(encoded));
	discord_send_message(discord_channel_id, data->source_p->name,
			     encoded);
}

/* -------------------------------------------------------------------------
 * Public interface
 * ---------------------------------------------------------------------- */

void
discord_send_message(const char *channel_id, const char *nick,
		     const char *text)
{
	if(discord_helper == NULL)
		return;
	rb_helper_write(discord_helper, "M %s %s :%s",
			channel_id, nick, text);
}

void
discord_send_typing(const char *channel_id)
{
	if(discord_helper == NULL)
		return;
	rb_helper_write(discord_helper, "T %s", channel_id);
}

/*
 * discord_config_clear - free existing config and reset to defaults.
 * Called from newconf.c begin callbacks so each rehash starts clean.
 */
void
discord_config_clear(void)
{
	rb_dlink_node *ptr, *next;

	rb_free(discord_config.token);
	rb_free(discord_config.guild_id);
	discord_config.token    = NULL;
	discord_config.guild_id = NULL;
	discord_config.enabled  = false;

	RB_DLINK_FOREACH_SAFE(ptr, next, discord_config.channel_maps.head)
	{
		rb_free(ptr->data);
		rb_dlinkDestroy(ptr, &discord_config.channel_maps);
	}
}

/*
 * init_discordproc - called from ircd startup (ircd/ircd.c).
 */
void
init_discordproc(void)
{
	phantom_by_nick = rb_dictionary_create("discord nick->client",
					       rb_strcasecmp);
	phantom_by_uid  = rb_dictionary_create("discord uid->client",
					       rb_strcasecmp);
	discord_to_irc  = rb_dictionary_create("discord->irc channel map",
					       rb_strcasecmp);
	irc_to_discord  = rb_dictionary_create("irc->discord channel map",
					       rb_strcasecmp);

	memset(&discord_config, 0, sizeof(discord_config));

	/* Register the h_privmsg_channel hook. */
	add_hook("privmsg_channel", hook_discord_privmsg);

	ilog(L_MAIN, "Discord bridge subsystem initialised");
}

/*
 * start_discord_bridge - called after config is fully loaded.
 * If a discord{} block exists with a token and guild_id, start discordd.
 */
void
start_discord_bridge(void)
{
	if(!discord_config.enabled)
		return;
	if(EmptyString(discord_config.token) ||
	   EmptyString(discord_config.guild_id))
	{
		ilog(L_MAIN, "discord: bridge enabled but token/guild_id missing");
		return;
	}

	build_channel_maps();
	start_discordd();
}

/*
 * rehash_discord_bridge - called on REHASH.
 * Re-sends config to discordd (which may reconnect if token changed).
 */
void
rehash_discord_bridge(void)
{
	build_channel_maps();
	discord_configure();
}
