/*
 * ircd/flood.c — KICK / MODE / PROP operation flood controls
 *
 * Implements per-user global rate limiting for KICK, MODE, and PROP SET
 * operations.  Per-channel stricter limits can be set by channel operators
 * via PROP keys KICKFLOOD, MODEFLOOD, and PROPFLOOD (format "N/T").
 *
 * The effective limit for an operation in a given channel is the stricter
 * (lower rate) of the server-global limit and the channel PROP limit.
 * A lower rate means fewer operations per unit time (N/T ratio).
 */

#include "stdinc.h"
#include "client.h"
#include "channel.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "send.h"
#include "numeric.h"
#include "propertyset.h"
#include "flood.h"

/*
 * flood_exempt — returns true when the client should bypass operation flood
 * controls.  Mirrors the existing packet.c logic so all flood mechanisms
 * behave consistently:
 *
 *   • Clients with oper:god privilege are always exempt (god mode).
 *   • General IRC operators are exempt when no_oper_flood is configured.
 */
static inline bool
flood_exempt(struct Client *source_p)
{
	if(HasPrivilege(source_p, "oper:god"))
		return true;
	if(IsOperGeneral(source_p) && ConfigFileEntry.no_oper_flood)
		return true;
	return false;
}

/* -------------------------------------------------------------------------
 * parse_flood_prop
 *
 * Parse a flood PROP value of the form "N/T" into *count and *time_window.
 * Returns true on success, false if the value is malformed or zero.
 * ------------------------------------------------------------------------- */
static bool
parse_flood_prop(const char *value, int *count, int *time_window)
{
	int n, t;
	if(sscanf(value, "%d/%d", &n, &t) != 2 || n <= 0 || t <= 0)
		return false;
	*count       = n;
	*time_window = t;
	return true;
}

/* -------------------------------------------------------------------------
 * effective_limits
 *
 * Compute the effective (strictest) count/time pair from the server-global
 * config and an optional channel PROP override.
 *
 * Strictness: rate = count / time.  Lower rate = stricter.
 * Comparison: (chan_count / chan_time) < (srv_count / srv_time)
 *           ⟺  chan_count * srv_time < srv_count * chan_time
 * ------------------------------------------------------------------------- */
static void
effective_limits(struct Channel *chptr, const char *prop_key,
                 int srv_count, int srv_time,
                 int *eff_count, int *eff_time)
{
	*eff_count = srv_count;
	*eff_time  = srv_time;

	if(chptr == NULL || srv_count == 0)
		return;

	struct Property *prop = propertyset_find(&chptr->prop_list, prop_key);
	if(prop == NULL || prop->value == NULL)
		return;

	int chan_count, chan_time;
	if(!parse_flood_prop(prop->value, &chan_count, &chan_time))
		return;

	/* Use channel limit only if it is strictly stricter than server */
	if((long)chan_count * srv_time < (long)srv_count * chan_time)
	{
		*eff_count = chan_count;
		*eff_time  = chan_time;
	}
}

/* -------------------------------------------------------------------------
 * check_flood_generic
 *
 * Core flood-check logic.  Returns true (flooded) or false (OK).
 * Callers supply pointers to the per-user or per-membership counters.
 * ------------------------------------------------------------------------- */
static bool
check_flood_generic(struct Client *source_p,
                    time_t *last_time, int *count,
                    int eff_count, int eff_time,
                    const char *op_name)
{
	time_t now = rb_current_time();

	if(now - *last_time >= eff_time)
	{
		*count     = 0;
		*last_time = now;
	}

	(*count)++;

	if(*count > eff_count)
	{
		sendto_one_notice(source_p,
			":*** %s flood throttled (%d ops in %ds, limit %d/%ds) — slow down",
			op_name, *count, eff_time, eff_count, eff_time);
		return true;
	}
	return false;
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

bool
check_kick_flood(struct Client *source_p, struct Channel *chptr)
{
	if(!MyClient(source_p))
		return false;
	if(ConfigFileEntry.kick_flood_count == 0)
		return false;
	/* God-mode opers and general opers with no_oper_flood bypass all limits */
	if(flood_exempt(source_p))
		return false;

	/* Global check */
	struct LocalUser *lc = source_p->localClient;
	int eff_count, eff_time;
	effective_limits(chptr, "KICKFLOOD",
	                 ConfigFileEntry.kick_flood_count,
	                 ConfigFileEntry.kick_flood_time,
	                 &eff_count, &eff_time);

	/* Check server-global counter */
	if(check_flood_generic(source_p,
	                       &lc->flood_kick_time, &lc->flood_kick_count,
	                       ConfigFileEntry.kick_flood_count,
	                       ConfigFileEntry.kick_flood_time,
	                       "KICK"))
		return true;

	/* Check per-channel counter if channel has a stricter PROP */
	if(chptr != NULL &&
	   (eff_count != ConfigFileEntry.kick_flood_count ||
	    eff_time  != ConfigFileEntry.kick_flood_time))
	{
		struct membership *msptr = find_channel_membership(chptr, source_p);
		if(msptr != NULL &&
		   check_flood_generic(source_p,
		                       &msptr->flood_kick_time, &msptr->flood_kick_count,
		                       eff_count, eff_time, "KICK (channel)"))
			return true;
	}

	return false;
}

bool
check_mode_flood(struct Client *source_p, struct Channel *chptr)
{
	if(!MyClient(source_p))
		return false;
	if(ConfigFileEntry.mode_flood_count == 0)
		return false;
	if(flood_exempt(source_p))
		return false;

	struct LocalUser *lc = source_p->localClient;
	int eff_count, eff_time;
	effective_limits(chptr, "MODEFLOOD",
	                 ConfigFileEntry.mode_flood_count,
	                 ConfigFileEntry.mode_flood_time,
	                 &eff_count, &eff_time);

	if(check_flood_generic(source_p,
	                       &lc->flood_mode_time, &lc->flood_mode_count,
	                       ConfigFileEntry.mode_flood_count,
	                       ConfigFileEntry.mode_flood_time,
	                       "MODE"))
		return true;

	if(chptr != NULL &&
	   (eff_count != ConfigFileEntry.mode_flood_count ||
	    eff_time  != ConfigFileEntry.mode_flood_time))
	{
		struct membership *msptr = find_channel_membership(chptr, source_p);
		if(msptr != NULL &&
		   check_flood_generic(source_p,
		                       &msptr->flood_mode_time, &msptr->flood_mode_count,
		                       eff_count, eff_time, "MODE (channel)"))
			return true;
	}

	return false;
}

bool
check_prop_flood(struct Client *source_p, struct Channel *chptr)
{
	if(!MyClient(source_p))
		return false;
	if(ConfigFileEntry.prop_flood_count == 0)
		return false;
	if(flood_exempt(source_p))
		return false;

	struct LocalUser *lc = source_p->localClient;
	int eff_count, eff_time;
	effective_limits(chptr, "PROPFLOOD",
	                 ConfigFileEntry.prop_flood_count,
	                 ConfigFileEntry.prop_flood_time,
	                 &eff_count, &eff_time);

	if(check_flood_generic(source_p,
	                       &lc->flood_prop_time, &lc->flood_prop_count,
	                       ConfigFileEntry.prop_flood_count,
	                       ConfigFileEntry.prop_flood_time,
	                       "PROP"))
		return true;

	if(chptr != NULL &&
	   (eff_count != ConfigFileEntry.prop_flood_count ||
	    eff_time  != ConfigFileEntry.prop_flood_time))
	{
		struct membership *msptr = find_channel_membership(chptr, source_p);
		if(msptr != NULL &&
		   check_flood_generic(source_p,
		                       &msptr->flood_prop_time, &msptr->flood_prop_count,
		                       eff_count, eff_time, "PROP (channel)"))
			return true;
	}

	return false;
}
