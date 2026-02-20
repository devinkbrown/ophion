/************************************************************************
 *   IRC - Internet Relay Chat, src/match.c
 *   Copyright (C) 1990 Jarkko Oikarinen
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#include "stdinc.h"
#include "defaults.h"
#include "client.h"
#include "ircd.h"
#include "match.h"
#include "s_assert.h"


/* -----------------------------------------------------------------------
 * Compiled NFA for IRC wildcard matching.
 *
 * The compile step converts a mask into an array of atoms, collapsing
 * consecutive STARs.  The execute step simulates the NFA with a single
 * saved backtrack point (the most-recently-seen STAR), scanning the input
 * once per star per backtrack attempt.  This is equivalent to the classic
 * backtracking algorithm but structured without goto.
 *
 * Time complexity: O(|name| * |mask|) worst case, O(|name|) typical.
 *
 * Three wildcard sets are supported:
 *   compile_simple  —  * and ? only (match, mask_match)
 *   compile_esc     —  * ? @ # \s \X escapes (match_esc)
 *
 * mask_mode: A_QUEST does not match '*' in the input (mask_match).
 * ----------------------------------------------------------------------- */

#define MAX_ATOMS 1024

typedef enum
{
	A_STAR,     /* * – match zero or more characters  */
	A_QUEST,    /* ? – match any single character      */
	A_LETTER,   /* @ – match any letter  (match_esc)   */
	A_DIGIT,    /* # – match any digit   (match_esc)   */
	A_SPACE,    /* \s – match a space    (match_esc)   */
	A_LITERAL,  /* exact character (case-folded)        */
} atom_type_t;

typedef struct
{
	atom_type_t   type;
	unsigned char ch;   /* A_LITERAL: the case-folded byte */
} atom_t;

/* Compile a simple IRC wildcard pattern (* and ?) into atoms[]. */
static int
compile_simple(atom_t *atoms, int cap, const char *mask)
{
	int n = 0;
	for(const char *m = mask; *m && n < cap; m++)
	{
		if(*m == '*')
		{
			if(n > 0 && atoms[n - 1].type == A_STAR) continue; /* collapse */
			atoms[n++] = (atom_t){ A_STAR, 0 };
		}
		else if(*m == '?')
		{
			atoms[n++] = (atom_t){ A_QUEST, 0 };
		}
		else
		{
			atoms[n++] = (atom_t){ A_LITERAL,
			                       irctolower((unsigned char)*m) };
		}
	}
	return n;
}

/* Compile a match_esc extended-wildcard pattern into atoms[]. */
static int
compile_esc(atom_t *atoms, int cap, const char *mask)
{
	int n = 0;
	const unsigned char *m = (const unsigned char *)mask;

	while(*m && n < cap)
	{
		if(*m == '*')
		{
			while(*(m + 1) == '*') m++;   /* collapse */
			if(n > 0 && atoms[n - 1].type == A_STAR) { m++; continue; }
			atoms[n++] = (atom_t){ A_STAR, 0 };
		}
		else if(*m == '?') atoms[n++] = (atom_t){ A_QUEST,  0 };
		else if(*m == '@') atoms[n++] = (atom_t){ A_LETTER, 0 };
		else if(*m == '#') atoms[n++] = (atom_t){ A_DIGIT,  0 };
		else if(*m == '\\')
		{
			m++;
			if(!*m) break;                /* trailing backslash: ignore */
			if(*m == 's')
				atoms[n++] = (atom_t){ A_SPACE, 0 };
			else
				atoms[n++] = (atom_t){ A_LITERAL, irctolower(*m) };
		}
		else
		{
			atoms[n++] = (atom_t){ A_LITERAL, irctolower(*m) };
		}
		m++;
	}
	return n;
}

/*
 * exec_nfa — simulate the compiled NFA against `name`.
 *
 * mask_mode: if non-zero, A_QUEST does not match '*' in the input.
 *
 * Returns 1 on match, 0 on no match.
 */
static int
exec_nfa(const atom_t *atoms, int natoms, const char *name, int mask_mode)
{
	int ai = 0;             /* index into atoms[] */
	const char *n = name;   /* current position in input string */
	int star_ai = -1;       /* atom index after the most-recent STAR */
	const char *star_n = name; /* input position at the most-recent STAR */

	for(;;)
	{
		/* Absorb any consecutive STAR atoms, updating the backtrack point. */
		while(ai < natoms && atoms[ai].type == A_STAR)
		{
			star_ai = ai + 1;
			star_n  = n;
			ai++;
		}

		if(!*n)
		{
			/*
			 * Input exhausted.  Eat any trailing STARs (they match
			 * the empty suffix) and succeed iff pattern is also done.
			 */
			while(ai < natoms && atoms[ai].type == A_STAR) ai++;
			return ai >= natoms;
		}

		if(ai >= natoms)
		{
			/* Pattern exhausted but input remains — only a STAR can help. */
			if(star_ai < 0) return 0;
			ai = star_ai;
			n  = ++star_n;
			continue;
		}

		/* Attempt to match the current atom against *n. */
		int ok;
		unsigned char c = (unsigned char)*n;
		switch(atoms[ai].type)
		{
		case A_QUEST:
			ok = !mask_mode || (c != (unsigned char)'*');
			break;
		case A_LETTER:
			ok = IsLetter(c);
			break;
		case A_DIGIT:
			ok = IsDigit(c);
			break;
		case A_SPACE:
			ok = (c == (unsigned char)' ');
			break;
		case A_LITERAL:
			ok = (irctolower(c) == atoms[ai].ch);
			break;
		default: /* A_STAR: handled above */
			ok = 0;
			break;
		}

		if(ok)
		{
			ai++;
			n++;
		}
		else
		{
			/* Current atom failed — backtrack to the last STAR. */
			if(star_ai < 0) return 0;
			ai = star_ai;
			n  = ++star_n;
		}
	}
}

/** Check a string against a mask.
 * Traditional IRC wildcards: '*' matches zero or more characters,
 * '?' matches exactly one character.
 *
 * @param[in] mask  Wildcard-containing mask.
 * @param[in] name  String to check against mask.
 * @return 1 if mask matches name, 0 otherwise.
 */
int
match(const char *mask, const char *name)
{
	atom_t atoms[MAX_ATOMS];
	int    natoms;

	s_assert(mask != NULL);
	s_assert(name != NULL);

	natoms = compile_simple(atoms, MAX_ATOMS, mask);
	return exec_nfa(atoms, natoms, name, 0);
}

/** Check a mask against a mask.
 * Same as match(), but '?' in the pattern does not match '*' in the
 * input.  Used when comparing two wildcard masks for specificity.
 *
 * @param[in] mask  Existing wildcard-containing mask.
 * @param[in] name  New wildcard-containing mask.
 * @return 1 if name is equal to or more specific than mask, 0 otherwise.
 */
int
mask_match(const char *mask, const char *name)
{
	atom_t atoms[MAX_ATOMS];
	int    natoms;

	s_assert(mask != NULL);
	s_assert(name != NULL);

	natoms = compile_simple(atoms, MAX_ATOMS, mask);
	return exec_nfa(atoms, natoms, name, 1);
}

/** Check a string against an extended-wildcard mask.
 * Wildcards: '*' – zero or more chars; '?' – any char; '@' – any letter;
 * '#' – any digit; '\s' – space; '\X' – literal X.
 *
 * @param[in] mask  Extended wildcard mask.
 * @param[in] name  String to check.
 * @return 1 if mask matches name, 0 otherwise.
 */
int
match_esc(const char *mask, const char *name)
{
	atom_t atoms[MAX_ATOMS];
	int    natoms;

	if(!mask || !name)
		return 0;

	/* Fast path: bare "*" matches everything. */
	if(mask[0] == '*' && mask[1] == '\0')
		return 1;

	natoms = compile_esc(atoms, MAX_ATOMS, mask);
	return exec_nfa(atoms, natoms, name, 0);
}


int comp_with_mask(void *addr, void *dest, unsigned int mask)
{
	if (memcmp(addr, dest, mask / 8) == 0)
	{
		if (mask % 8 == 0)
			return 1;
		int n = mask / 8;
		unsigned char m = (unsigned char)(0xFF << (8 - (mask % 8)));
		if ((((unsigned char *) addr)[n] & m) == (((unsigned char *) dest)[n] & m))
			return 1;
	}
	return 0;
}

int comp_with_mask_sock(struct sockaddr *addr, struct sockaddr *dest, unsigned int mask)
{
	void *iaddr = NULL;
	void *idest = NULL;

	if (addr->sa_family == AF_INET)
	{
		iaddr = &((struct sockaddr_in *)(void *)addr)->sin_addr;
		idest = &((struct sockaddr_in *)(void *)dest)->sin_addr;
	}
	else
	{
		iaddr = &((struct sockaddr_in6 *)(void *)addr)->sin6_addr;
		idest = &((struct sockaddr_in6 *)(void *)dest)->sin6_addr;

	}

	return (comp_with_mask(iaddr, idest, mask));
}

/*
 * match_ips()
 *
 * Input - cidr ip mask, address
 */
int match_ips(const char *s1, const char *s2)
{
	struct rb_sockaddr_storage ipaddr, maskaddr;
	char mask[BUFSIZE];
	char address[HOSTLEN + 1];
	char *len;
	void *ipptr, *maskptr;
	int cidrlen, aftype;

	rb_strlcpy(mask, s1, sizeof(mask));
	rb_strlcpy(address, s2, sizeof(address));

	len = strrchr(mask, '/');
	if (len == NULL)
		return 0;

	*len++ = '\0';

	cidrlen = atoi(len);
	if (cidrlen <= 0)
		return 0;

	if (strchr(mask, ':') && strchr(address, ':'))
	{
		if (cidrlen > 128)
			return 0;

		aftype = AF_INET6;
		ipptr = &((struct sockaddr_in6 *)&ipaddr)->sin6_addr;
		maskptr = &((struct sockaddr_in6 *)&maskaddr)->sin6_addr;
	}
	else if (!strchr(mask, ':') && !strchr(address, ':'))
	{
		if (cidrlen > 32)
			return 0;

		aftype = AF_INET;
		ipptr = &((struct sockaddr_in *)&ipaddr)->sin_addr;
		maskptr = &((struct sockaddr_in *)&maskaddr)->sin_addr;
	}
	else
		return 0;

	if (rb_inet_pton(aftype, address, ipptr) <= 0)
		return 0;
	if (rb_inet_pton(aftype, mask, maskptr) <= 0)
		return 0;
	if (comp_with_mask(ipptr, maskptr, cidrlen))
		return 1;
	else
		return 0;
}

/* match_cidr()
 *
 * Input - mask, address
 * Ouput - 1 = Matched 0 = Did not match
 */

int match_cidr(const char *s1, const char *s2)
{
	struct rb_sockaddr_storage ipaddr, maskaddr;
	char mask[BUFSIZE];
	char address[NICKLEN + USERLEN + HOSTLEN + 6];
	char *ipmask;
	char *ip;
	char *len;
	void *ipptr, *maskptr;
	int cidrlen, aftype;

	rb_strlcpy(mask, s1, sizeof(mask));
	rb_strlcpy(address, s2, sizeof(address));

	ipmask = strrchr(mask, '@');
	if (ipmask == NULL)
		return 0;

	*ipmask++ = '\0';

	ip = strrchr(address, '@');
	if (ip == NULL)
		return 0;
	*ip++ = '\0';


	len = strrchr(ipmask, '/');
	if (len == NULL)
		return 0;

	*len++ = '\0';

	cidrlen = atoi(len);
	if (cidrlen <= 0)
		return 0;

	if (strchr(ip, ':') && strchr(ipmask, ':'))
	{
		if (cidrlen > 128)
			return 0;

		aftype = AF_INET6;
		ipptr = &((struct sockaddr_in6 *)&ipaddr)->sin6_addr;
		maskptr = &((struct sockaddr_in6 *)&maskaddr)->sin6_addr;
	}
	else if (!strchr(ip, ':') && !strchr(ipmask, ':'))
	{
		if (cidrlen > 32)
			return 0;

		aftype = AF_INET;
		ipptr = &((struct sockaddr_in *)&ipaddr)->sin_addr;
		maskptr = &((struct sockaddr_in *)&maskaddr)->sin_addr;
	}
	else
		return 0;

	if (rb_inet_pton(aftype, ip, ipptr) <= 0)
		return 0;
	if (rb_inet_pton(aftype, ipmask, maskptr) <= 0)
		return 0;
	if (comp_with_mask(ipptr, maskptr, cidrlen) && match(mask, address))
		return 1;
	else
		return 0;
}

/* collapse()
 *
 * collapses a string containing multiple *'s.
 */
char *collapse(char *pattern)
{
	char *p = pattern, *po = pattern;
	char c;
	int f = 0;

	if (p == NULL)
		return NULL;

	while ((c = *p++))
	{
		if (c == '*')
		{
			if (!(f & 1))
				*po++ = '*';
			f |= 1;
		}
		else
		{
			*po++ = c;
			f &= ~1;
		}
	}
	*po++ = 0;

	return pattern;
}

/* collapse_esc()
 *
 * The collapse() function with support for escaping characters
 */
char *collapse_esc(char *pattern)
{
	char *p = pattern, *po = pattern;
	char c;
	int f = 0;

	if (p == NULL)
		return NULL;

	while ((c = *p++))
	{
		if (!(f & 2) && c == '*')
		{
			if (!(f & 1))
				*po++ = '*';
			f |= 1;
		}
		else if (!(f & 2) && c == '\\')
		{
			*po++ = '\\';
			f |= 2;
		}
		else
		{
			*po++ = c;
			f &= ~3;
		}
	}
	*po++ = 0;
	return pattern;
}

/*
 * irccmp - case insensitive comparison of two 0 terminated strings.
 *
 *      returns  0, if s1 equal to s2
 *              <0, if s1 lexicographically less than s2
 *              >0, if s1 lexicographically greater than s2
 */
int irccmp(const char *s1, const char *s2)
{
	const unsigned char *str1 = (const unsigned char *)s1;
	const unsigned char *str2 = (const unsigned char *)s2;
	int res;

	s_assert(s1 != NULL);
	s_assert(s2 != NULL);

	while ((res = irctoupper(*str1) - irctoupper(*str2)) == 0)
	{
		if (*str1 == '\0')
			return 0;
		str1++;
		str2++;
	}
	return (res);
}

int ircncmp(const char *s1, const char *s2, int n)
{
	const unsigned char *str1 = (const unsigned char *)s1;
	const unsigned char *str2 = (const unsigned char *)s2;
	int res;
	s_assert(s1 != NULL);
	s_assert(s2 != NULL);

	while ((res = irctoupper(*str1) - irctoupper(*str2)) == 0)
	{
		str1++;
		str2++;
		n--;
		if (n == 0 || (*str1 == '\0' && *str2 == '\0'))
			return 0;
	}
	return (res);
}

void matchset_for_client(struct Client *who, struct matchset *m)
{
	unsigned hostn = 0;
	unsigned ipn = 0;

	struct sockaddr_in ip4;

	sprintf(m->host[hostn++], "%s!%s@%s", who->name, who->username, who->host);

	if (!IsIPSpoof(who))
	{
		sprintf(m->ip[ipn++], "%s!%s@%s", who->name, who->username, who->sockhost);
	}

	if (who->localClient->mangledhost != NULL)
	{
		/* if host mangling mode enabled, also check their real host */
		if (!strcmp(who->host, who->localClient->mangledhost))
		{
			sprintf(m->host[hostn++], "%s!%s@%s", who->name, who->username, who->orighost);
		}
		/* if host mangling mode not enabled and no other spoof,
		 * also check the mangled form of their host */
		else if (!IsDynSpoof(who))
		{
			sprintf(m->host[hostn++], "%s!%s@%s", who->name, who->username, who->localClient->mangledhost);
		}
	}
	if (!IsIPSpoof(who) && GET_SS_FAMILY(&who->localClient->ip) == AF_INET6 &&
			rb_ipv4_from_ipv6((const struct sockaddr_in6 *)&who->localClient->ip, &ip4))
	{
		int n = sprintf(m->ip[ipn], "%s!%s@", who->name, who->username);
		rb_inet_ntop_sock((struct sockaddr *)&ip4,
				m->ip[ipn] + n, sizeof m->ip[ipn] - n);
		ipn++;
	}

	for (int i = hostn; i < ARRAY_SIZE(m->host); i++)
	{
		m->host[i][0] = '\0';
	}
	for (int i = ipn; i < ARRAY_SIZE(m->ip); i++)
	{
		m->ip[i][0] = '\0';
	}
}

bool client_matches_mask(struct Client *who, const char *mask)
{
	static struct matchset ms;
	matchset_for_client(who, &ms);
	return matches_mask(&ms, mask);
}

bool matches_mask(const struct matchset *m, const char *mask)
{
	for (int i = 0; i < ARRAY_SIZE(m->host); i++)
	{
		if (m->host[i][0] == '\0')
			break;
		if (match(mask, m->host[i]))
			return true;
	}
	for (int i = 0; i < ARRAY_SIZE(m->ip); i++)
	{
		if (m->ip[i][0] == '\0')
			break;
		if (match(mask, m->ip[i]))
			return true;
		if (match_cidr(mask, m->ip[i]))
			return true;
	}
	return false;
}

const unsigned char irctolower_tab[] = {
	0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa,
	0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14,
	0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
	0x1e, 0x1f,
	' ', '!', '"', '#', '$', '%', '&', 0x27, '(', ')',
	'*', '+', ',', '-', '.', '/',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	':', ';', '<', '=', '>', '?',
	'@', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
	'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
	't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~',
	'_',
	'`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
	'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
	't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~',
	0x7f,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
	0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
	0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
	0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9,
	0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9,
	0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
	0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
	0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
	0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

const unsigned char irctoupper_tab[] = {
	0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa,
	0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14,
	0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
	0x1e, 0x1f,
	' ', '!', '"', '#', '$', '%', '&', 0x27, '(', ')',
	'*', '+', ',', '-', '.', '/',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	':', ';', '<', '=', '>', '?',
	'@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
	'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
	'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^',
	0x5f,
	'`', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
	'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
	'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^',
	0x7f,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
	0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
	0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
	0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9,
	0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9,
	0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
	0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
	0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
	0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

/*
 * CharAttrs table
 *
 * NOTE: RFC 1459 sez: anything but a ^G, comma, or space is allowed
 * for channel names
 */
unsigned int CharAttrs[] = {
/* 0  */ CNTRL_C,
/* 1  */ CNTRL_C | CHAN_C | NONEOS_C,
/* 2  */ CNTRL_C | CHAN_C | FCHAN_C | NONEOS_C,
/* 3  */ CNTRL_C | CHAN_C | FCHAN_C | NONEOS_C,
/* 4  */ CNTRL_C | CHAN_C | NONEOS_C,
/* 5  */ CNTRL_C | CHAN_C | NONEOS_C,
/* 6  */ CNTRL_C | CHAN_C | NONEOS_C,
/* 7 BEL */ CNTRL_C | NONEOS_C,
/* 8  \b */ CNTRL_C | CHAN_C | NONEOS_C,
/* 9  \t */ CNTRL_C | SPACE_C | CHAN_C | NONEOS_C,
/* 10 \n */ CNTRL_C | SPACE_C | CHAN_C | NONEOS_C | EOL_C,
/* 11 \v */ CNTRL_C | SPACE_C | CHAN_C | NONEOS_C,
/* 12 \f */ CNTRL_C | SPACE_C | CHAN_C | NONEOS_C,
/* 13 \r */ CNTRL_C | SPACE_C | CHAN_C | NONEOS_C | EOL_C,
/* 14 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 15 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 16 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 17 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 18 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 19 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 20 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 21 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 22 */ CNTRL_C | CHAN_C | FCHAN_C | NONEOS_C,
/* 23 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 24 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 25 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 26 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 27 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 28 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 29 */ CNTRL_C | CHAN_C | FCHAN_C | NONEOS_C,
/* 30 */ CNTRL_C | CHAN_C | NONEOS_C,
/* 31 */ CNTRL_C | CHAN_C | FCHAN_C | NONEOS_C,
/* SP */ PRINT_C | SPACE_C,
/* ! */ PRINT_C | KWILD_C | CHAN_C | NONEOS_C,
/* " */ PRINT_C | CHAN_C | NONEOS_C,
/* # */ PRINT_C | MWILD_C | CHANPFX_C | CHAN_C | NONEOS_C,
/* $ */ PRINT_C | CHAN_C | NONEOS_C,
/* % */ PRINT_C | CHAN_C | NONEOS_C,
/* & */ PRINT_C | CHANPFX_C | CHAN_C | NONEOS_C,
/* ' */ PRINT_C | CHAN_C | NONEOS_C,
/* ( */ PRINT_C | CHAN_C | NONEOS_C,
/* ) */ PRINT_C | CHAN_C | NONEOS_C,
/* * */ PRINT_C | KWILD_C | MWILD_C | CHAN_C | NONEOS_C,
/* + */ PRINT_C | CHAN_C | NONEOS_C,
/* , */ PRINT_C | NONEOS_C,
/* - */ PRINT_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* . */ PRINT_C | KWILD_C | CHAN_C | NONEOS_C | USER_C | HOST_C | SERV_C,
/* / */ PRINT_C | CHAN_C | NONEOS_C | HOST_C,
/* 0 */ PRINT_C | DIGIT_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* 1 */ PRINT_C | DIGIT_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* 2 */ PRINT_C | DIGIT_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* 3 */ PRINT_C | DIGIT_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* 4 */ PRINT_C | DIGIT_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* 5 */ PRINT_C | DIGIT_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* 6 */ PRINT_C | DIGIT_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* 7 */ PRINT_C | DIGIT_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* 8 */ PRINT_C | DIGIT_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* 9 */ PRINT_C | DIGIT_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* : */ PRINT_C | CHAN_C | NONEOS_C | HOST_C,
/* ; */ PRINT_C | CHAN_C | NONEOS_C,
/* < */ PRINT_C | CHAN_C | NONEOS_C,
/* = */ PRINT_C | CHAN_C | NONEOS_C,
/* > */ PRINT_C | CHAN_C | NONEOS_C,
/* ? */ PRINT_C | KWILD_C | MWILD_C | CHAN_C | NONEOS_C,
/* @ */ PRINT_C | KWILD_C | MWILD_C | CHAN_C | NONEOS_C,
/* A */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* B */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* C */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* D */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* E */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* F */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* G */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* H */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* I */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* J */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* K */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* L */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* M */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* N */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* O */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* P */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* Q */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* R */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* S */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* T */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* U */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* V */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* W */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* X */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* Y */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* Z */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* [ */ PRINT_C | ALPHA_C | NICK_C | CHAN_C | NONEOS_C | USER_C,
/* \ */ PRINT_C | ALPHA_C | NICK_C | CHAN_C | NONEOS_C | USER_C,
/* ] */ PRINT_C | ALPHA_C | NICK_C | CHAN_C | NONEOS_C | USER_C,
/* ^ */ PRINT_C | ALPHA_C | NICK_C | CHAN_C | NONEOS_C | USER_C,
/* _ */ PRINT_C | NICK_C | CHAN_C | NONEOS_C | USER_C,
/* ` */ PRINT_C | NICK_C | CHAN_C | NONEOS_C | USER_C,
/* a */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* b */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* c */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* d */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* e */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* f */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* g */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* h */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* i */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* j */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* k */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* l */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* m */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* n */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* o */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* p */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* q */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* r */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* s */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* t */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* u */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* v */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* w */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* x */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* y */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* z */ PRINT_C | ALPHA_C | LET_C | NICK_C | CHAN_C | NONEOS_C | USER_C | HOST_C,
/* { */ PRINT_C | ALPHA_C | NICK_C | CHAN_C | NONEOS_C | USER_C,
/* | */ PRINT_C | ALPHA_C | NICK_C | CHAN_C | NONEOS_C | USER_C,
/* } */ PRINT_C | ALPHA_C | NICK_C | CHAN_C | NONEOS_C | USER_C,
/* ~ */ PRINT_C | ALPHA_C | CHAN_C | NONEOS_C | USER_C,
/* del  */ CHAN_C | NONEOS_C,
/* 0x80 */ CHAN_C | NONEOS_C,
/* 0x81 */ CHAN_C | NONEOS_C,
/* 0x82 */ CHAN_C | NONEOS_C,
/* 0x83 */ CHAN_C | NONEOS_C,
/* 0x84 */ CHAN_C | NONEOS_C,
/* 0x85 */ CHAN_C | NONEOS_C,
/* 0x86 */ CHAN_C | NONEOS_C,
/* 0x87 */ CHAN_C | NONEOS_C,
/* 0x88 */ CHAN_C | NONEOS_C,
/* 0x89 */ CHAN_C | NONEOS_C,
/* 0x8A */ CHAN_C | NONEOS_C,
/* 0x8B */ CHAN_C | NONEOS_C,
/* 0x8C */ CHAN_C | NONEOS_C,
/* 0x8D */ CHAN_C | NONEOS_C,
/* 0x8E */ CHAN_C | NONEOS_C,
/* 0x8F */ CHAN_C | NONEOS_C,
/* 0x90 */ CHAN_C | NONEOS_C,
/* 0x91 */ CHAN_C | NONEOS_C,
/* 0x92 */ CHAN_C | NONEOS_C,
/* 0x93 */ CHAN_C | NONEOS_C,
/* 0x94 */ CHAN_C | NONEOS_C,
/* 0x95 */ CHAN_C | NONEOS_C,
/* 0x96 */ CHAN_C | NONEOS_C,
/* 0x97 */ CHAN_C | NONEOS_C,
/* 0x98 */ CHAN_C | NONEOS_C,
/* 0x99 */ CHAN_C | NONEOS_C,
/* 0x9A */ CHAN_C | NONEOS_C,
/* 0x9B */ CHAN_C | NONEOS_C,
/* 0x9C */ CHAN_C | NONEOS_C,
/* 0x9D */ CHAN_C | NONEOS_C,
/* 0x9E */ CHAN_C | NONEOS_C,
/* 0x9F */ CHAN_C | NONEOS_C,
/* 0xA0 */ CHAN_C | FCHAN_C | NONEOS_C,
/* 0xA1 */ CHAN_C | NONEOS_C,
/* 0xA2 */ CHAN_C | NONEOS_C,
/* 0xA3 */ CHAN_C | NONEOS_C,
/* 0xA4 */ CHAN_C | NONEOS_C,
/* 0xA5 */ CHAN_C | NONEOS_C,
/* 0xA6 */ CHAN_C | NONEOS_C,
/* 0xA7 */ CHAN_C | NONEOS_C,
/* 0xA8 */ CHAN_C | NONEOS_C,
/* 0xA9 */ CHAN_C | NONEOS_C,
/* 0xAA */ CHAN_C | NONEOS_C,
/* 0xAB */ CHAN_C | NONEOS_C,
/* 0xAC */ CHAN_C | NONEOS_C,
/* 0xAD */ CHAN_C | NONEOS_C,
/* 0xAE */ CHAN_C | NONEOS_C,
/* 0xAF */ CHAN_C | NONEOS_C,
/* 0xB0 */ CHAN_C | NONEOS_C,
/* 0xB1 */ CHAN_C | NONEOS_C,
/* 0xB2 */ CHAN_C | NONEOS_C,
/* 0xB3 */ CHAN_C | NONEOS_C,
/* 0xB4 */ CHAN_C | NONEOS_C,
/* 0xB5 */ CHAN_C | NONEOS_C,
/* 0xB6 */ CHAN_C | NONEOS_C,
/* 0xB7 */ CHAN_C | NONEOS_C,
/* 0xB8 */ CHAN_C | NONEOS_C,
/* 0xB9 */ CHAN_C | NONEOS_C,
/* 0xBA */ CHAN_C | NONEOS_C,
/* 0xBB */ CHAN_C | NONEOS_C,
/* 0xBC */ CHAN_C | NONEOS_C,
/* 0xBD */ CHAN_C | NONEOS_C,
/* 0xBE */ CHAN_C | NONEOS_C,
/* 0xBF */ CHAN_C | NONEOS_C,
/* 0xC0 */ CHAN_C | NONEOS_C,
/* 0xC1 */ CHAN_C | NONEOS_C,
/* 0xC2 */ CHAN_C | NONEOS_C,
/* 0xC3 */ CHAN_C | NONEOS_C,
/* 0xC4 */ CHAN_C | NONEOS_C,
/* 0xC5 */ CHAN_C | NONEOS_C,
/* 0xC6 */ CHAN_C | NONEOS_C,
/* 0xC7 */ CHAN_C | NONEOS_C,
/* 0xC8 */ CHAN_C | NONEOS_C,
/* 0xC9 */ CHAN_C | NONEOS_C,
/* 0xCA */ CHAN_C | NONEOS_C,
/* 0xCB */ CHAN_C | NONEOS_C,
/* 0xCC */ CHAN_C | NONEOS_C,
/* 0xCD */ CHAN_C | NONEOS_C,
/* 0xCE */ CHAN_C | NONEOS_C,
/* 0xCF */ CHAN_C | NONEOS_C,
/* 0xD0 */ CHAN_C | NONEOS_C,
/* 0xD1 */ CHAN_C | NONEOS_C,
/* 0xD2 */ CHAN_C | NONEOS_C,
/* 0xD3 */ CHAN_C | NONEOS_C,
/* 0xD4 */ CHAN_C | NONEOS_C,
/* 0xD5 */ CHAN_C | NONEOS_C,
/* 0xD6 */ CHAN_C | NONEOS_C,
/* 0xD7 */ CHAN_C | NONEOS_C,
/* 0xD8 */ CHAN_C | NONEOS_C,
/* 0xD9 */ CHAN_C | NONEOS_C,
/* 0xDA */ CHAN_C | NONEOS_C,
/* 0xDB */ CHAN_C | NONEOS_C,
/* 0xDC */ CHAN_C | NONEOS_C,
/* 0xDD */ CHAN_C | NONEOS_C,
/* 0xDE */ CHAN_C | NONEOS_C,
/* 0xDF */ CHAN_C | NONEOS_C,
/* 0xE0 */ CHAN_C | NONEOS_C,
/* 0xE1 */ CHAN_C | NONEOS_C,
/* 0xE2 */ CHAN_C | NONEOS_C,
/* 0xE3 */ CHAN_C | NONEOS_C,
/* 0xE4 */ CHAN_C | NONEOS_C,
/* 0xE5 */ CHAN_C | NONEOS_C,
/* 0xE6 */ CHAN_C | NONEOS_C,
/* 0xE7 */ CHAN_C | NONEOS_C,
/* 0xE8 */ CHAN_C | NONEOS_C,
/* 0xE9 */ CHAN_C | NONEOS_C,
/* 0xEA */ CHAN_C | NONEOS_C,
/* 0xEB */ CHAN_C | NONEOS_C,
/* 0xEC */ CHAN_C | NONEOS_C,
/* 0xED */ CHAN_C | NONEOS_C,
/* 0xEE */ CHAN_C | NONEOS_C,
/* 0xEF */ CHAN_C | NONEOS_C,
/* 0xF0 */ CHAN_C | NONEOS_C,
/* 0xF1 */ CHAN_C | NONEOS_C,
/* 0xF2 */ CHAN_C | NONEOS_C,
/* 0xF3 */ CHAN_C | NONEOS_C,
/* 0xF4 */ CHAN_C | NONEOS_C,
/* 0xF5 */ CHAN_C | NONEOS_C,
/* 0xF6 */ CHAN_C | NONEOS_C,
/* 0xF7 */ CHAN_C | NONEOS_C,
/* 0xF8 */ CHAN_C | NONEOS_C,
/* 0xF9 */ CHAN_C | NONEOS_C,
/* 0xFA */ CHAN_C | NONEOS_C,
/* 0xFB */ CHAN_C | NONEOS_C,
/* 0xFC */ CHAN_C | NONEOS_C,
/* 0xFD */ CHAN_C | NONEOS_C,
/* 0xFE */ CHAN_C | NONEOS_C,
/* 0xFF */ CHAN_C | NONEOS_C
};
