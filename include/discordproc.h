/*
 * include/discordproc.h - Discord bridge helper process interface
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

#ifndef INCLUDED_discordproc_h
#define INCLUDED_discordproc_h

/*
 * Wire protocol — ircd <-> discordd (line-based, newline terminated)
 *
 * ircd -> discordd:
 *   C <token> <guild_id>              Configure (sent on start and rehash)
 *   M <channel_id> <nick> :<text>     Relay IRC message to a Discord channel
 *   T <channel_id>                    Relay typing indicator
 *
 * discordd -> ircd:
 *   G <guild_name>                    Gateway READY; guild_name is %-encoded
 *   P <channel_id> <user_id> <nick> <msgid> :<text>
 *                                     Discord message received
 *   Y <channel_id> <user_id> <nick>   Typing start
 *   D <channel_id> <msgid>            Message deleted
 *   E <channel_id> <msgid> :<text>    Message edited
 *   W <level> :<message>              Log/warning (level: D I W C)
 *
 * Field notes:
 *   <nick>        Discord username sanitised for IRC (spaces->_, non-ASCII
 *                 stripped, truncated to 30 chars)
 *   <msgid>       Discord message snowflake (64-bit decimal string)
 *   <channel_id>  Discord channel snowflake
 *   <user_id>     Discord user snowflake
 *   <%text>       %-encoded so spaces/newlines are safe in the field
 */

/* Maximum length of a Discord snowflake string (64-bit decimal) */
#define DISCORD_SNOWFLAKE_LEN   21
/* Maximum nick length we impose on Discord usernames bridged to IRC */
#define DISCORD_NICK_LEN        30

/* A mapping between one IRC channel and one Discord channel. */
struct DiscordChannelMap
{
	char irc_channel[CHANNELLEN + 1];
	char discord_channel_id[DISCORD_SNOWFLAKE_LEN];
};

/* Runtime configuration for the Discord bridge. */
struct DiscordConfig
{
	char   *token;            /* "Bot xxxx..." */
	char   *guild_id;         /* Discord guild snowflake */
	rb_dlink_list channel_maps; /* list of struct DiscordChannelMap */
	bool    enabled;
};

extern struct DiscordConfig discord_config;
extern rb_helper *discord_helper;

/* discordproc.c public interface */
void init_discordproc(void);
void start_discord_bridge(void);
void rehash_discord_bridge(void);
void discord_send_message(const char *channel_id, const char *nick,
			  const char *text);
void discord_send_typing(const char *channel_id);

/* Called from newconf.c config callbacks */
void discord_config_clear(void);

#endif /* INCLUDED_discordproc_h */
