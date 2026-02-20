/*
 *  charybdis: A slightly useful ircd.
 *  extban.c: extended ban types ($type:data)
 *
 * Copyright (C) 2006 charybdis development team
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
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "match.h"
#include "privilege.h"
#include "propertyset.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_user.h"

ExtbanFunc extban_table[256] = { NULL };

int
match_extban(const char *banstr, struct Client *client_p, struct Channel *chptr, long mode_type)
{
	const char *p;
	int invert = 0, result = EXTBAN_INVALID;
	ExtbanFunc f;

	if (*banstr != '$')
		return 0;
	p = banstr + 1;
	if (*p == '~')
	{
		invert = 1;
		p++;
	}
	f = extban_table[(unsigned char) irctolower(*p)];
	if (*p != '\0')
	{
		p++;
		if (*p == ':')
			p++;
		else
			p = NULL;
	}
	if (f != NULL)
		result = f(p, client_p, chptr, mode_type);
	else
		result = EXTBAN_INVALID;

	if (invert)
		return result == EXTBAN_NOMATCH;
	else
		return result == EXTBAN_MATCH;
}

int
valid_extban(const char *banstr, struct Client *client_p, struct Channel *chptr, long mode_type)
{
	const char *p;
	int result = EXTBAN_INVALID;
	ExtbanFunc f;

	if (*banstr != '$')
		return 0;
	p = banstr + 1;
	if (*p == '~')
		p++;
	f = extban_table[(unsigned char) irctolower(*p)];
	if (*p != '\0')
	{
		p++;
		if (*p == ':')
			p++;
		else
			p = NULL;
	}
	if (f != NULL)
		result = f(p, client_p, chptr, mode_type);
	else
		result = EXTBAN_INVALID;

	return result != EXTBAN_INVALID;
}

const char *
get_extban_string(void)
{
	static char e[256];
	int i, j;

	j = 0;
	for (i = 1; i < 256; i++)
		if (i == irctolower(i) && extban_table[i])
			e[j++] = i;
	e[j] = 0;
	return e;
}

/*
 * extban_is_enabled - returns non-zero if the extban type character is both
 * registered and enabled by ConfigFeatures.  Used when validating ban masks
 * before they are stored (e.g. the ACCESS command).
 */
int
extban_is_enabled(unsigned char type_char)
{
	type_char = (unsigned char)irctolower((int)type_char);
	if (extban_table[type_char] == NULL)
		return 0;
	switch (type_char)
	{
	case 'a': return ConfigFeatures.extban_account;
	case 'z': return ConfigFeatures.extban_ssl;
	case 'o': return ConfigFeatures.extban_oper;
	case 'r': return ConfigFeatures.extban_realname;
	case 's': return ConfigFeatures.extban_server;
	case 'm': return ConfigFeatures.extban_hostmask;
	case 'x': return ConfigFeatures.extban_extgecos;
	case 'u': return ConfigFeatures.extban_usermode;
	case 'g': return ConfigFeatures.extban_group;
	case 'j': return ConfigFeatures.extban_canjoin;
	case 'c': return ConfigFeatures.extban_channel;
	case '&':
	case '|': return ConfigFeatures.extban_combi;
	default:  return 1;
	}
}

/* -----------------------------------------------------------------------
 * Built-in extban handlers.  These cover the common client-attribute
 * checks and are always available without loading a module.  Optional
 * types that depend on external services or complex channel logic
 * ($g, $j, $c, $&/$|) remain as loadable modules in extensions/.
 * ----------------------------------------------------------------------- */

/* $a  -- any logged-in user; $a:<mask> matches account name */
static int
eb_account(const char *data, struct Client *client_p,
           struct Channel *chptr, long mode_type)
{
	if (!ConfigFeatures.extban_account)
		return EXTBAN_INVALID;
	(void)chptr;
	(void)mode_type;
	if (data == NULL)
		return EmptyString(client_p->user->suser) ? EXTBAN_NOMATCH : EXTBAN_MATCH;
	return match(data, client_p->user->suser) ? EXTBAN_MATCH : EXTBAN_NOMATCH;
}

/* $z  -- SSL/TLS users; $z:<fp> additionally requires that cert fingerprint */
static int
eb_ssl(const char *data, struct Client *client_p,
       struct Channel *chptr, long mode_type)
{
	if (!ConfigFeatures.extban_ssl)
		return EXTBAN_INVALID;
	(void)chptr;
	(void)mode_type;
	if (!IsSSLClient(client_p))
		return EXTBAN_NOMATCH;
	if (data != NULL)
	{
		if (EmptyString(client_p->certfp))
			return EXTBAN_NOMATCH;
		if (irccmp(data, client_p->certfp) != 0)
			return EXTBAN_NOMATCH;
	}
	return EXTBAN_MATCH;
}

/* $o  -- IRC operators; $o:<privset|priv> matches a specific privilege */
static int
eb_oper(const char *data, struct Client *client_p,
        struct Channel *chptr, long mode_type)
{
	if (!ConfigFeatures.extban_oper)
		return EXTBAN_INVALID;
	(void)chptr;
	(void)mode_type;
	if (data != NULL)
	{
		struct PrivilegeSet *set = privilegeset_get(data);
		if (set != NULL && client_p->user->privset == set)
			return EXTBAN_MATCH;
		return HasPrivilege(client_p, data) ? EXTBAN_MATCH : EXTBAN_NOMATCH;
	}
	return IsOper(client_p) ? EXTBAN_MATCH : EXTBAN_NOMATCH;
}

/* $r:<mask>  -- realname/gecos match; not valid in +e/+I */
static int
eb_realname(const char *data, struct Client *client_p,
            struct Channel *chptr, long mode_type)
{
	if (!ConfigFeatures.extban_realname)
		return EXTBAN_INVALID;
	(void)chptr;
	if (mode_type == CHFL_EXCEPTION || mode_type == CHFL_INVEX)
		return EXTBAN_INVALID;
	if (data == NULL)
		return EXTBAN_INVALID;
	return match(data, client_p->info) ? EXTBAN_MATCH : EXTBAN_NOMATCH;
}

/* $s:<mask>  -- server name match; not valid in +e/+I */
static int
eb_server(const char *data, struct Client *client_p,
          struct Channel *chptr, long mode_type)
{
	if (!ConfigFeatures.extban_server)
		return EXTBAN_INVALID;
	(void)chptr;
	if (mode_type == CHFL_EXCEPTION || mode_type == CHFL_INVEX)
		return EXTBAN_INVALID;
	if (data == NULL)
		return EXTBAN_INVALID;
	return match(data, me.name) ? EXTBAN_MATCH : EXTBAN_NOMATCH;
}

/* $m:<nick!user@host>  -- hostmask; most useful inside $& / $| */
static int
eb_hostmask(const char *data, struct Client *client_p,
            struct Channel *chptr, long mode_type)
{
	if (!ConfigFeatures.extban_hostmask)
		return EXTBAN_INVALID;
	(void)chptr;
	(void)mode_type;
	if (data == NULL)
		return EXTBAN_INVALID;
	return client_matches_mask(client_p, data) ? EXTBAN_MATCH : EXTBAN_NOMATCH;
}

/* $x:<nick!user@host#gecos>  -- full extended mask including realname */
static int
eb_extgecos(const char *data, struct Client *client_p,
            struct Channel *chptr, long mode_type)
{
	char buf[BUFSIZE];

	if (!ConfigFeatures.extban_extgecos)
		return EXTBAN_INVALID;
	(void)chptr;
	(void)mode_type;
	if (data == NULL)
		return EXTBAN_INVALID;

	snprintf(buf, BUFSIZE, "%s!%s@%s#%s",
	         client_p->name, client_p->username, client_p->host, client_p->info);
	if (match(data, buf))
		return EXTBAN_MATCH;

	if (IsDynSpoof(client_p))
	{
		snprintf(buf, BUFSIZE, "%s!%s@%s#%s",
		         client_p->name, client_p->username, client_p->orighost, client_p->info);
		if (match(data, buf))
			return EXTBAN_MATCH;
	}

	return EXTBAN_NOMATCH;
}

/* $u:<modes>  -- user mode match; +/- prefix notation, + assumed if absent */
static int
eb_usermode(const char *data, struct Client *client_p,
            struct Channel *chptr, long mode_type)
{
	int dir = MODE_ADD;
	unsigned int modes_ack = 0, modes_nak = 0;
	const char *p;

	if (!ConfigFeatures.extban_usermode)
		return EXTBAN_INVALID;
	(void)chptr;
	(void)mode_type;
	if (data == NULL)
		return EXTBAN_INVALID;

	for (p = data; *p != '\0'; p++)
	{
		switch (*p)
		{
		case '+': dir = MODE_ADD; break;
		case '-': dir = MODE_DEL; break;
		default:
			if (dir == MODE_DEL)
				modes_nak |= user_modes[(unsigned char)*p];
			else
				modes_ack |= user_modes[(unsigned char)*p];
			break;
		}
	}

	return ((client_p->umodes & modes_ack) == modes_ack &&
	        !(client_p->umodes & modes_nak)) ?
	       EXTBAN_MATCH : EXTBAN_NOMATCH;
}

/* $g:<mask>  -- group membership via MEMBER-OF user property (case-insensitive substring) */
static int
eb_group(const char *data, struct Client *client_p,
         struct Channel *chptr, long mode_type)
{
	if (!ConfigFeatures.extban_group)
		return EXTBAN_INVALID;
	(void)chptr;
	(void)mode_type;
	if (data == NULL)
		return EXTBAN_INVALID;
	struct Property *prop = propertyset_find(&client_p->user->prop_list, "member-of");
	if (prop == NULL)
		return EXTBAN_NOMATCH;
	return rb_strcasestr(prop->value, data) != NULL ? EXTBAN_MATCH : EXTBAN_NOMATCH;
}

/* $j:<channel>  -- matches users who are banned from (cannot join) the given channel */
static int
eb_canjoin(const char *data, struct Client *client_p,
           struct Channel *chptr, long mode_type)
{
	struct Channel *chptr2;
	int ret;
	static int recurse = 0;

	if (!ConfigFeatures.extban_canjoin)
		return EXTBAN_INVALID;
	(void)mode_type;
	if (recurse)
		return EXTBAN_INVALID;
	if (data == NULL)
		return EXTBAN_INVALID;
	chptr2 = find_channel(data);
	if (chptr2 == NULL || chptr2 == chptr)
		return EXTBAN_INVALID;
	if (chptr->chname[0] == '#' && data[0] == '&')
		return EXTBAN_INVALID;
	recurse = 1;
	ret = is_banned(chptr2, client_p, NULL, NULL, NULL) == CHFL_BAN ? EXTBAN_MATCH : EXTBAN_NOMATCH;
	recurse = 0;
	return ret;
}

/* $c:<channel>  -- matches users currently on the given channel */
static int
eb_channel(const char *data, struct Client *client_p,
           struct Channel *chptr, long mode_type)
{
	struct Channel *chptr2;

	if (!ConfigFeatures.extban_channel)
		return EXTBAN_INVALID;
	(void)mode_type;
	if (data == NULL)
		return EXTBAN_INVALID;
	chptr2 = find_channel(data);
	if (chptr2 == NULL)
		return EXTBAN_INVALID;
	if (chptr->chname[0] == '#' && data[0] == '&')
		return EXTBAN_INVALID;
	return IsMember(client_p, chptr2) ? EXTBAN_MATCH : EXTBAN_NOMATCH;
}

/* $& / $|  -- combination extbans (logical AND / OR of sub-bans) */
#define COMBI_RETURN_INVALID { combi_recursion_depth--; return EXTBAN_INVALID; }

static int combi_recursion_depth = 0;

static int eb_combi(const char *data, struct Client *client_p, struct Channel *chptr, long mode_type, bool is_and);

static int
eb_and(const char *data, struct Client *client_p, struct Channel *chptr, long mode_type)
{
	if (!ConfigFeatures.extban_combi)
		return EXTBAN_INVALID;
	return eb_combi(data, client_p, chptr, mode_type, true);
}

static int
eb_or(const char *data, struct Client *client_p, struct Channel *chptr, long mode_type)
{
	if (!ConfigFeatures.extban_combi)
		return EXTBAN_INVALID;
	return eb_combi(data, client_p, chptr, mode_type, false);
}

static int
eb_combi(const char *data, struct Client *client_p, struct Channel *chptr, long mode_type, bool is_and)
{
	const char *p, *banend;
	bool have_result = false;
	int allowed_nodes = 11;
	size_t datalen;

	if (combi_recursion_depth >= 5)
		return EXTBAN_INVALID;
	if (EmptyString(data))
		return EXTBAN_INVALID;

	datalen = strlen(data);
	if (datalen > BANLEN)
		return EXTBAN_INVALID;
	banend = data + datalen;

	if (data[0] == '(')
	{
		p = data + 1;
		banend--;
		if (*banend != ')')
			return EXTBAN_INVALID;
	}
	else
	{
		p = data;
	}

	if (banend == p)
		return EXTBAN_INVALID;

	combi_recursion_depth++;

	while (--allowed_nodes)
	{
		bool invert = false;
		char *child_data, child_data_buf[BANLEN];
		ExtbanFunc f;

		if (*p == '~')
		{
			invert = true;
			p++;
			if (p == banend)
				COMBI_RETURN_INVALID;
		}

		f = extban_table[(unsigned char)*p++];
		if (!f)
			COMBI_RETURN_INVALID;

		if (*p == ':')
		{
			unsigned int parencount = 0;
			bool escaped = false, done = false;
			char *o;

			p++;
			o = child_data = child_data_buf;
			while (true)
			{
				if (p == banend)
				{
					if (parencount)
						COMBI_RETURN_INVALID;
					break;
				}
				if (escaped)
				{
					if (*p != '(' && *p != ')' && *p != '\\' && *p != ',')
						*o++ = '\\';
					*o++ = *p++;
					escaped = false;
				}
				else
				{
					switch (*p)
					{
					case '\\': escaped = true; break;
					case '(':  parencount++; *o++ = *p; break;
					case ')':
						if (!parencount)
							COMBI_RETURN_INVALID;
						parencount--;
						*o++ = *p;
						break;
					case ',':
						if (parencount)
							*o++ = *p;
						else
							done = true;
						break;
					default: *o++ = *p; break;
					}
					if (done)
						break;
					p++;
				}
			}
			*o = '\0';
		}
		else
		{
			child_data = NULL;
		}

		if (!have_result)
		{
			int child_result = f(child_data, client_p, chptr, mode_type);
			if (child_result == EXTBAN_INVALID)
				COMBI_RETURN_INVALID;
			if (invert)
				child_result = child_result == EXTBAN_NOMATCH;
			else
				child_result = child_result == EXTBAN_MATCH;
			if (is_and ? !child_result : child_result)
				have_result = true;
		}

		if (p == banend)
			break;
		if (*p++ != ',')
			COMBI_RETURN_INVALID;
		if (p == banend)
			COMBI_RETURN_INVALID;
	}

	if (p != banend)
		COMBI_RETURN_INVALID;

	combi_recursion_depth--;

	if (is_and)
		return have_result ? EXTBAN_NOMATCH : EXTBAN_MATCH;
	else
		return have_result ? EXTBAN_MATCH : EXTBAN_NOMATCH;
}

/*
 * extban_init - register all built-in extban type handlers.
 * Must be called once at startup, after chmode_init().
 */
void
extban_init(void)
{
	extban_table['a'] = eb_account;  /* $a - account */
	extban_table['z'] = eb_ssl;      /* $z - SSL/TLS */
	extban_table['o'] = eb_oper;     /* $o - IRC operator */
	extban_table['r'] = eb_realname; /* $r - realname/gecos */
	extban_table['s'] = eb_server;   /* $s - server name */
	extban_table['m'] = eb_hostmask; /* $m - hostmask */
	extban_table['x'] = eb_extgecos; /* $x - extended mask with gecos */
	extban_table['u'] = eb_usermode; /* $u - user mode match */
	extban_table['g'] = eb_group;    /* $g - group membership (MEMBER-OF) */
	extban_table['j'] = eb_canjoin;  /* $j - banned from channel */
	extban_table['c'] = eb_channel;  /* $c - member of channel */
	extban_table['&'] = eb_and;      /* $& - logical AND combination */
	extban_table['|'] = eb_or;       /* $| - logical OR combination */
}
