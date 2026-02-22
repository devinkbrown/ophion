/*	$$$: arc4random.c 2005/02/08 robert */
/*	$NetBSD: arc4random.c,v 1.5.2.1 2004/03/26 22:52:50 jmc Exp $	*/
/*	$OpenBSD: arc4random.c,v 1.6 2001/06/05 05:05:38 pvalchev Exp $	*/

/*
 * Arc4 random number generator for OpenBSD.
 * Copyright 1996 David Mazieres <dm@lcs.mit.edu>.
 *
 * Modification and redistribution in source and binary forms is
 * permitted provided that due credit is given to the author and the
 * OpenBSD project by leaving this copyright notice intact.
 */

/*
 * This code is derived from section 17.1 of Applied Cryptography,
 * second edition, which describes a stream cipher allegedly
 * compatible with RSA Labs "RC4" cipher (the actual description of
 * which is a trade secret).  The same algorithm is used as a stream
 * cipher called "arcfour" in Tatu Ylonen's ssh package.
 *
 * Here the stream cipher has been modified always to include the time
 * when initializing the state.  That makes it impossible to
 * regenerate the same random sequence twice, so this can't be used
 * for encryption, but will generate good random numbers.
 *
 * RC4 is a registered trademark of RSA Laboratories.
 *
 * Seed modernization (2026): use getrandom(2) (Linux 3.17+) for the
 * entropy source instead of opening /dev/urandom, avoiding fd
 * allocation, EINTR handling, and partial-read retry logic.
 */


#include <librb_config.h>
#include <rb_lib.h>

#if !defined(HAVE_OPENSSL) && !defined(HAVE_GNUTLS) && !defined(HAVE_MBEDTLS) && !defined(HAVE_ARC4RANDOM)

#include "arc4random.h"

#ifdef HAVE_GETRUSAGE
#include <sys/resource.h>
#endif

#if defined(__linux__)
#  include <sys/random.h>   /* getrandom(2), Linux 3.17+ */
#  define HAVE_GETRANDOM 1
#endif



struct arc4_stream
{
	uint8_t i;
	uint8_t j;
	uint8_t s[256];
};


static int rs_initialized;
static struct arc4_stream rs;

static inline void arc4_init(struct arc4_stream *);
static inline void arc4_addrandom(struct arc4_stream *, uint8_t *, int);
static void arc4_stir(struct arc4_stream *);
static inline uint8_t arc4_getbyte(struct arc4_stream *);
static inline uint32_t arc4_getword(struct arc4_stream *);

static inline void
arc4_init(struct arc4_stream *as)
{
	int n;

	for(n = 0; n < 256; n++)
		as->s[n] = n;
	as->i = 0;
	as->j = 0;
}

static inline void
arc4_addrandom(struct arc4_stream *as, uint8_t *dat, int datlen)
{
	int n;
	uint8_t si;

	as->i--;
	for(n = 0; n < 256; n++)
	{
		as->i = (as->i + 1);
		si = as->s[as->i];
		as->j = (as->j + si + dat[n % datlen]);
		as->s[as->i] = as->s[as->j];
		as->s[as->j] = si;
	}
	as->j = as->i;
}

static void
arc4_stir(struct arc4_stream *as)
{
	int n;
	uint8_t rnd[128];

#if defined(HAVE_GETRANDOM)
	/* Single atomic call — no fd allocation, no partial-read loop. */
	getrandom(rnd, sizeof(rnd), 0);
	arc4_addrandom(as, rnd, sizeof(rnd));
#else
	{
		int fd = open("/dev/urandom", O_RDONLY);
		if(fd != -1)
		{
			ssize_t r = read(fd, rnd, sizeof(rnd));
			close(fd);
			if(r > 0)
				arc4_addrandom(as, rnd, (int)r);
		}
	}
#endif
	memset(rnd, 0, sizeof(rnd));

	/*
	 * Throw away the first N words of output, as suggested in the
	 * paper "Weaknesses in the Key Scheduling Algorithm of RC4"
	 * by Fluher, Mantin, and Shamir.
	 * http://www.wisdom.weizmann.ac.il/~itsik/RC4/Papers/Rc4_ksa.ps
	 * N = 256 in our case.
	 */
	for(n = 0; n < 256 * 4; n++)
		arc4_getbyte(as);
}

static inline uint8_t
arc4_getbyte(struct arc4_stream *as)
{
	uint8_t si, sj;

	as->i = (as->i + 1);
	si = as->s[as->i];
	as->j = (as->j + si);
	sj = as->s[as->j];
	as->s[as->i] = sj;
	as->s[as->j] = si;
	return (as->s[(si + sj) & 0xff]);
}

static inline uint32_t
arc4_getword(struct arc4_stream *as)
{
	uint32_t val;
	val = arc4_getbyte(as) << 24;
	val |= arc4_getbyte(as) << 16;
	val |= arc4_getbyte(as) << 8;
	val |= arc4_getbyte(as);
	return val;
}

void
arc4random_stir(void)
{
	if(!rs_initialized)
	{
		arc4_init(&rs);
		rs_initialized = 1;
	}
	arc4_stir(&rs);
}

void
arc4random_addrandom(uint8_t *dat, int datlen)
{
	if(!rs_initialized)
		arc4random_stir();
	arc4_addrandom(&rs, dat, datlen);
}

uint32_t
arc4random(void)
{
	if(!rs_initialized)
		arc4random_stir();
	return arc4_getword(&rs);
}

#endif
