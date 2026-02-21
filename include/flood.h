/*
 * include/flood.h — KICK / MODE / PROP operation flood controls
 *
 * Global limits are configured in general{}:
 *   kick_flood_count / kick_flood_time
 *   mode_flood_count / mode_flood_time
 *   prop_flood_count / prop_flood_time
 *
 * Per-channel stricter limits are read from channel PROP keys:
 *   KICKFLOOD = "N/T"   MODEFLOOD = "N/T"   PROPFLOOD = "N/T"
 *
 * When a flood limit is exceeded the function returns true and sends
 * a notice to the user; the caller should drop the command.
 */
#ifndef INCLUDED_flood_h
#define INCLUDED_flood_h

#include "stdinc.h"
#include "client.h"
#include "channel.h"

/*
 * check_kick_flood  — call before processing each KICK target.
 * check_mode_flood  — call before processing a client-sourced MODE command.
 * check_prop_flood  — call before processing a PROP SET operation.
 *
 * source_p : the local client issuing the command
 * chptr    : the target channel (may be NULL for the global check only)
 *
 * Returns true  if the client is over the effective flood limit (drop cmd).
 * Returns false if the client is within limits (proceed normally).
 *
 * IRC operators with no_oper_flood bypass all flood limits.
 */
bool check_kick_flood(struct Client *source_p, struct Channel *chptr);
bool check_mode_flood(struct Client *source_p, struct Channel *chptr);
bool check_prop_flood(struct Client *source_p, struct Channel *chptr);

#endif /* INCLUDED_flood_h */
