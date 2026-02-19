/*
 * modules/m_ircx_modes.c
 *
 * IRCX channel modes per draft-pfenning-irc-extensions-04.
 *
 * This module implements all channel modes defined in the IRCX draft:
 *
 *   +u  KNOCK      - Enables KNOCK notifications to channel hosts/owners
 *   +h  HIDDEN     - Channel not listed via LIST/LISTX but queryable by name
 *   +a  AUTHONLY   - Only authenticated (PASS/AUTH'd) users may join
 *                    (replaces charybdis +r REGONLY which is now +r REGISTERED)
 *   +d  CLONEABLE  - Channel creates numbered clones when full
 *   +E  CLONE      - Marks channel as a clone of a CLONEABLE channel
 *                     (IRCX +e, remapped to +E to avoid ban exception conflict)
 *   +r  REGISTERED - Channel is registered with services (oper/service-only)
 *                    (overrides charybdis REGONLY; use +a for auth-only joins)
 *                    Implies persistence (+P behavior)
 *   +f  NOFORMAT   - Raw text, clients should not format messages
 *   +z  SERVICE    - Indicates a service is monitoring the channel
 *
 * Visibility model (mutually exclusive):
 *   PUBLIC   - No mode flag (default).  Visible in LIST, all data queryable.
 *   PRIVATE  - +p (RFC1459).  Listed but properties restricted.
 *   HIDDEN   - +h (IRCX).  Not in LIST but queryable if name is known.
 *   SECRET   - +s (RFC1459).  Not visible to non-members at all.
 *
 * When +h is set, +p and +s are cleared.  When +p or +s is set, +h is cleared.
 * This mutual exclusivity follows the IRCX draft.
 *
 * Note: +f overrides the charybdis forwarding mode, +z overrides opmoderate,
 * and +r overrides charybdis REGONLY (use +a AUTHONLY instead).
 * The original modes are saved and restored when this module is unloaded.
 */

#include "stdinc.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "hook.h"
#include "ircd.h"
#include "match.h"
#include "msg.h"
#include "modules.h"
#include "numeric.h"
#include "parse.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "chmode.h"
#include "supported.h"

static const char ircx_modes_desc[] =
	"Provides all IRCX channel modes: +u (knock), +h (hidden), +a (authonly), "
	"+d (cloneable), +E (clone), +r (registered), +f (noformat), +z (service)";

/* Allocated mode bits */
static unsigned int MODE_KNOCK;	/* +u */
static unsigned int MODE_HIDDEN_IRCX;	/* +h */
static unsigned int MODE_AUTHONLY;	/* +a */
static unsigned int MODE_CLONEABLE;	/* +d */
static unsigned int MODE_CLONE;	/* +E (IRCX +e, remapped to avoid ban exception conflict) */

/* Overridden mode bits for +f, +r, and +z */
static unsigned int MODE_NOFORMAT;	/* +f (replaces forwarding) */
static unsigned int MODE_REGISTERED;	/* +r (replaces regonly) */
static unsigned int MODE_IRCX_SERVICE;	/* +z (replaces opmoderate) */

/* Saved original chmode_table entries for overridden modes */
static struct ChannelMode saved_mode_f;
static struct ChannelMode saved_mode_r;
static struct ChannelMode saved_mode_z;

/* Forward declarations */
static void chm_hidden_ircx(struct Client *source_p, struct Channel *chptr,
	int alevel, int parc, int *parn,
	const char **parv, int *errors, int dir, char c, long mode_type);

static void chm_ircx_service(struct Client *source_p, struct Channel *chptr,
	int alevel, int parc, int *parn,
	const char **parv, int *errors, int dir, char c, long mode_type);

static void chm_ircx_registered(struct Client *source_p, struct Channel *chptr,
	int alevel, int parc, int *parn,
	const char **parv, int *errors, int dir, char c, long mode_type);

/*
 * find_free_mode_bit - find an unused channel mode bitmask
 *
 * Replicates the logic of find_cflag_slot() which is static in chmode.c.
 */
static unsigned int
find_free_mode_bit(void)
{
	unsigned int all_flags = 0, bit;
	int i;

	for (i = 0; i < 256; i++)
		all_flags |= chmode_flags[i];

	for (bit = 1; bit && (all_flags & bit); bit <<= 1)
		;

	return bit;
}

/*
 * chm_hidden_ircx - HIDDEN channel mode handler (+h)
 *
 * Like chm_simple but enforces mutual exclusivity with +p and +s.
 * When +h is being set, +p (PRIVATE) and +s (SECRET) are cleared.
 */
static void
chm_hidden_ircx(struct Client *source_p, struct Channel *chptr,
	int alevel, int parc, int *parn,
	const char **parv, int *errors, int dir, char c, long mode_type)
{
	/* Delegate to chm_simple for permission checks and mode_changes */
	chm_simple(source_p, chptr, alevel, parc, parn, parv, errors, dir, c, mode_type);

	/*
	 * If we're adding +h, clear +p and +s for mutual exclusivity.
	 * We do this directly on the mode struct; the mode_changes
	 * array will propagate +h, and the cleared modes will be
	 * reflected on the next mode query.
	 */
	if (dir == MODE_ADD)
	{
		chptr->mode.mode &= ~(MODE_PRIVATE | MODE_SECRET);
	}
}

/*
 * chm_ircx_service - SERVICE channel mode handler (+z)
 *
 * Per IRCX spec: "This mode can only be set by the Chat Server."
 * Only IRC operators (sysops) can set this mode.
 */
static void
chm_ircx_service(struct Client *source_p, struct Channel *chptr,
	int alevel, int parc, int *parn,
	const char **parv, int *errors, int dir, char c, long mode_type)
{
	if (MyClient(source_p) && !IsOper(source_p))
	{
		if (!(*errors & 0x80000000))
		{
			sendto_one_numeric(source_p, ERR_NOPRIVILEGES,
				form_str(ERR_NOPRIVILEGES));
			*errors |= 0x80000000;
		}
		return;
	}

	chm_simple(source_p, chptr, alevel, parc, parn, parv, errors, dir, c, mode_type);
}

/*
 * chm_ircx_registered - REGISTERED channel mode handler (+r)
 *
 * Per IRCX spec: REGISTERED indicates a channel is registered with services.
 * Only IRC operators or services can set/unset this mode.
 * When +r is set, the channel persists when empty (implies +P behavior).
 *
 * This overrides charybdis +r (REGONLY / only-registered-users-can-join).
 * That functionality is now provided by +a (AUTHONLY) in IRCX.
 */
static void
chm_ircx_registered(struct Client *source_p, struct Channel *chptr,
	int alevel, int parc, int *parn,
	const char **parv, int *errors, int dir, char c, long mode_type)
{
	if (MyClient(source_p) && !IsOper(source_p))
	{
		if (!(*errors & 0x80000000))
		{
			sendto_one_numeric(source_p, ERR_NOPRIVILEGES,
				form_str(ERR_NOPRIVILEGES));
			*errors |= 0x80000000;
		}
		return;
	}

	chm_simple(source_p, chptr, alevel, parc, parn, parv, errors, dir, c, mode_type);

	/* +r implies persistence: set MODE_PERMANENT when adding */
	if (dir == MODE_ADD)
		chptr->mode.mode |= MODE_PERMANENT;
}

/*
 * Hook: can_join - enforce AUTHONLY (+a) restriction
 */
static void
h_ircx_modes_can_join(void *vdata)
{
	hook_data_channel *data = vdata;
	struct Client *source_p = data->client;
	struct Channel *chptr = data->chptr;

	if (data->approved != 0)
		return;

	/* +a (AUTHONLY): only authenticated users can join */
	if (MODE_AUTHONLY && (chptr->mode.mode & MODE_AUTHONLY))
	{
		/* Check if user is authenticated (has suser set) */
		if (!source_p->user || EmptyString(source_p->user->suser))
		{
			/* ERR_NEEDREGGEDNICK is the closest standard numeric */
			data->approved = ERR_NEEDREGGEDNICK;
			return;
		}
	}
}

/*
 * CLONEABLE (+d) behavior is implemented in core/m_join.c check_cloneable().
 * When a +d channel is full, the join path automatically creates/finds
 * numbered clone channels (#channel1, #channel2, etc.) with +E set.
 */

mapi_hfn_list_av1 ircx_modes_hfnlist[] = {
	{ "can_join", (hookfn) h_ircx_modes_can_join },
	{ NULL, NULL }
};

static int
ircx_modes_init(void)
{
	/*
	 * Register IRCX modes on available slots via cflag_add.
	 */

	/* +u: KNOCK - enables KNOCK notifications to channel hosts/owners */
	MODE_KNOCK = cflag_add('u', chm_simple);
	if (MODE_KNOCK == 0)
		return -1;

	/* +h: HIDDEN (custom handler for mutual exclusivity) */
	MODE_HIDDEN_IRCX = cflag_add('h', chm_hidden_ircx);
	if (MODE_HIDDEN_IRCX == 0)
		return -1;

	/* +a: AUTHONLY */
	MODE_AUTHONLY = cflag_add('a', chm_simple);
	if (MODE_AUTHONLY == 0)
		return -1;

	/* +d: CLONEABLE */
	MODE_CLONEABLE = cflag_add('d', chm_simple);
	if (MODE_CLONEABLE == 0)
		return -1;

	/* +E: CLONE (IRCX +e remapped to +E; +e is ban exceptions in charybdis)
	 * Per IRCX spec section 8.1.17: indicates this channel is a numbered
	 * clone of a CLONEABLE (+d) channel.  Set automatically by the server
	 * when a clone channel is created.  Oper-only set for manual use.
	 */
	MODE_CLONE = cflag_add('E', chm_simple);
	if (MODE_CLONE == 0)
		return -1;

	/*
	 * Override conflicting modes.  Save originals for clean unload.
	 */

	/* +f: NOFORMAT (replaces charybdis forwarding) */
	saved_mode_f = chmode_table[(unsigned char)'f'];
	MODE_NOFORMAT = find_free_mode_bit();
	if (MODE_NOFORMAT == 0)
		return -1;
	chmode_table[(unsigned char)'f'].set_func = chm_simple;
	chmode_table[(unsigned char)'f'].mode_type = MODE_NOFORMAT;

	/* +r: REGISTERED (replaces charybdis REGONLY; use +a for auth-only).
	 * Oper/service-only. Implies persistence (+P behavior).
	 */
	saved_mode_r = chmode_table[(unsigned char)'r'];
	MODE_REGISTERED = find_free_mode_bit();
	if (MODE_REGISTERED == 0)
		return -1;
	chmode_table[(unsigned char)'r'].set_func = chm_ircx_registered;
	chmode_table[(unsigned char)'r'].mode_type = MODE_REGISTERED;

	/* +z: SERVICE (replaces charybdis opmoderate) */
	saved_mode_z = chmode_table[(unsigned char)'z'];
	MODE_IRCX_SERVICE = find_free_mode_bit();
	if (MODE_IRCX_SERVICE == 0)
		return -1;
	chmode_table[(unsigned char)'z'].set_func = chm_ircx_service;
	chmode_table[(unsigned char)'z'].mode_type = MODE_IRCX_SERVICE;

	construct_cflags_strings();

	return 0;
}

static void
ircx_modes_deinit(void)
{
	/* Unregister dynamically allocated modes */
	cflag_orphan('u');
	cflag_orphan('h');
	cflag_orphan('a');
	cflag_orphan('d');
	cflag_orphan('E');

	/* Restore original +f, +r, and +z handlers */
	chmode_table[(unsigned char)'f'] = saved_mode_f;
	chmode_table[(unsigned char)'r'] = saved_mode_r;
	chmode_table[(unsigned char)'z'] = saved_mode_z;

	construct_cflags_strings();
}

DECLARE_MODULE_AV2(ircx_modes, ircx_modes_init, ircx_modes_deinit,
	NULL, NULL, ircx_modes_hfnlist, NULL, NULL, ircx_modes_desc);
