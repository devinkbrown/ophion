/*
 *  librb: a library used by ircd-ratbox and other things
 *  nossl.c: SSL/TLS stubs and PRNG bootstrap for no-TLS builds.
 *
 *  Copyright (C) 2007-2008 ircd-ratbox development team
 *  Copyright (C) 2007-2008 Aaron Sethman <androsyn@ratbox.org>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 */

#include <librb_config.h>
#include <rb_lib.h>

#if !defined(HAVE_OPENSSL) && !defined(HAVE_GNUTLS) && !defined(HAVE_MBEDTLS)

#include "arc4random.h"

#include <commio-int.h>
#include <commio-ssl.h>

/* ---------- PRNG --------------------------------------------------------- */

/*
 * Periodic re-stir for the bundled arc4random implementation.
 * Not needed (and not compiled) when the platform provides arc4random(),
 * which auto-seeds itself on every call.
 */
#ifndef HAVE_ARC4RANDOM
static void
rb_stir_arc4random(void *unused __attribute__((unused)))
{
	arc4random_stir();
}
#endif /* !HAVE_ARC4RANDOM */

int
rb_init_prng(const char *path __attribute__((unused)),
             prng_seed_t seed_type __attribute__((unused)))
{
#ifndef HAVE_ARC4RANDOM
	arc4random_stir();
	rb_event_addish("rb_stir_arc4random", rb_stir_arc4random, NULL, 300);
#endif
	return 1;
}

int
rb_get_random(void *buf, size_t length)
{
#ifdef HAVE_ARC4RANDOM_BUF
	arc4random_buf(buf, length);
#else
	/* Fallback: extract bytes from successive arc4random() words. */
	uint8_t  *out = buf;
	size_t    i;
	uint32_t  rnd = 0;
	for(i = 0; i < length; i++)
	{
		if(i % 4 == 0)
			rnd = arc4random();
		out[i] = (uint8_t)rnd;
		rnd >>= 8;
	}
#endif
	return 1;
}

/* ---------- SSL stubs ----------------------------------------------------- */

int
rb_init_ssl(void)
{
	errno = ENOSYS;
	return -1;
}

int
rb_setup_ssl_server(const char *cert       __attribute__((unused)),
                    const char *keyfile    __attribute__((unused)),
                    const char *dhfile     __attribute__((unused)),
                    const char *cipher_list __attribute__((unused)),
                    bool verify            __attribute__((unused)))
{
	errno = ENOSYS;
	return 0;
}

int
rb_ssl_listen(rb_fde_t *F        __attribute__((unused)),
              int backlog        __attribute__((unused)),
              int defer_accept   __attribute__((unused)))
{
	errno = ENOSYS;
	return -1;
}

ssize_t
rb_ssl_read(rb_fde_t *F   __attribute__((unused)),
            void *buf      __attribute__((unused)),
            size_t count   __attribute__((unused)))
{
	errno = ENOSYS;
	return -1;
}

ssize_t
rb_ssl_write(rb_fde_t *F      __attribute__((unused)),
             const void *buf  __attribute__((unused)),
             size_t count     __attribute__((unused)))
{
	errno = ENOSYS;
	return -1;
}

int
rb_supports_ssl(void)
{
	return 0;
}

int
rb_get_ssl_certfp(rb_fde_t *F                              __attribute__((unused)),
                  uint8_t certfp[RB_SSL_CERTFP_LEN]        __attribute__((unused)),
                  int method                                __attribute__((unused)))
{
	return 0;
}

int
rb_get_ssl_certfp_file(const char *filename                    __attribute__((unused)),
                       uint8_t certfp[RB_SSL_CERTFP_LEN]      __attribute__((unused)),
                       int method                              __attribute__((unused)))
{
	return 0;
}

unsigned int
rb_ssl_handshake_count(rb_fde_t *F __attribute__((unused)))
{
	return 0;
}

const char *
rb_get_ssl_strerror(rb_fde_t *F __attribute__((unused)))
{
	return "SSL/TLS not supported";
}

const char *
rb_ssl_get_cipher(rb_fde_t *F __attribute__((unused)))
{
	errno = ENOSYS;
	return NULL;
}

void
rb_get_ssl_info(char *buf __attribute__((unused)), size_t len __attribute__((unused)))
{
	snprintf(buf, len, "Not compiled with SSL support");
}

void
rb_ssl_clear_handshake_count(rb_fde_t *F __attribute__((unused))) {}

void
rb_ssl_shutdown(rb_fde_t *F __attribute__((unused))) {}

void
rb_ssl_accept_setup(rb_fde_t *F       __attribute__((unused)),
                    rb_fde_t *new_F   __attribute__((unused)),
                    struct sockaddr *st __attribute__((unused)),
                    int addrlen        __attribute__((unused))) {}

void
rb_ssl_start_accepted(rb_fde_t *new_F  __attribute__((unused)),
                      ACCB *cb         __attribute__((unused)),
                      void *data       __attribute__((unused)),
                      int timeout      __attribute__((unused))) {}

void
rb_ssl_start_connected(rb_fde_t *F      __attribute__((unused)),
                       CNCB *callback   __attribute__((unused)),
                       void *data       __attribute__((unused)),
                       int timeout      __attribute__((unused))) {}

void
rb_connect_tcp_ssl(rb_fde_t *F           __attribute__((unused)),
                   struct sockaddr *dest  __attribute__((unused)),
                   struct sockaddr *clocal __attribute__((unused)),
                   CNCB *callback         __attribute__((unused)),
                   void *data             __attribute__((unused)),
                   int timeout            __attribute__((unused))) {}

#endif /* !HAVE_OPENSSL && !HAVE_GNUTLS && !HAVE_MBEDTLS */
