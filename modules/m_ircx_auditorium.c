/*
 * modules/m_ircx_auditorium.c
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
 * IRCX Auditorium mode (+x)
 *
 * When enabled on a channel, normal (non-op) members cannot see each
 * other.  JOIN/PART notifications for non-ops are suppressed for other
 * non-ops, and NAMES only shows operators to regular members.
 *
 * The mode flag is dynamically allocated via cflag_add('x') so the core
 * channel functions use chmode_flags['x'] to detect auditorium channels.
 * When the module is not loaded, chmode_flags['x'] == 0 and no auditorium
 * filtering occurs.
 *
 * Note: +u is reserved for IRCX NOKNOCK mode per draft-pfenning-irc-extensions-04.
 */

#include "stdinc.h"
#include "channel.h"
#include "client.h"
#include "modules.h"
#include "chmode.h"

static const char ircx_auditorium_desc[] =
	"Provides IRCX auditorium channel mode (+x) that hides non-ops from each other";

static unsigned int MODE_AUDITORIUM;

static int
modinit(void)
{
	MODE_AUDITORIUM = cflag_add('x', chm_simple);
	if (MODE_AUDITORIUM == 0)
		return -1;

	return 0;
}

static void
moddeinit(void)
{
	cflag_orphan('x');
}

DECLARE_MODULE_AV2(ircx_auditorium, modinit, moddeinit, NULL, NULL, NULL, NULL, NULL, ircx_auditorium_desc);
