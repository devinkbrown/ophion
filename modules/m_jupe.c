/*
 * modules/m_jupe.c — JUPE and UNJUPE commands
 *
 * JUPE <servername> [:<reason>]
 *   Prevent a server from linking to the network.  If the named server is
 *   currently connected it is immediately SQUITted.  The name is added to an
 *   in-memory jupe list; any subsequent attempt by that server to link is
 *   refused until the jupe is removed.  A WALLOPS is broadcast network-wide.
 *
 *   Requires IRC operator status.
 *
 * UNJUPE <servername>
 *   Remove a jupe, allowing the server to link again.
 *   Requires IRC operator status.
 *
 * JUPELIST
 *   List all currently active jupes.
 *   Requires IRC operator status.
 *
 * Note: the jupe list lives in memory only and does not survive a daemon
 * restart.  For persistent server bans, use deny_server{} in ircd.conf.
 *
 * Copyright (c) 2026 Ophion development team. GPL v2.
 */

#include "stdinc.h"
#include "client.h"
#include "hash.h"
#include "modules.h"
#include "msg.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"
#include "snomask.h"
#include "ircd.h"
#include "logger.h"

static const char jupe_desc[] =
	"Provides JUPE, UNJUPE, and JUPELIST commands to block servers from linking";

static void mo_jupe    (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void mo_unjupe  (struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void mo_jupelist(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void moddeinit  (void);

struct Message jupe_msgtab = {
	"JUPE", 0, 0, 0, 0,
	{mg_unreg, {mo_jupe, 2}, mg_ignore, mg_ignore, mg_ignore, {mo_jupe, 2}}
};

struct Message unjupe_msgtab = {
	"UNJUPE", 0, 0, 0, 0,
	{mg_unreg, {mo_unjupe, 2}, mg_ignore, mg_ignore, mg_ignore, {mo_unjupe, 2}}
};

struct Message jupelist_msgtab = {
	"JUPELIST", 0, 0, 0, 0,
	{mg_unreg, {mo_jupelist, 1}, mg_ignore, mg_ignore, mg_ignore, {mo_jupelist, 1}}
};

mapi_clist_av1 jupe_clist[] = {
	&jupe_msgtab, &unjupe_msgtab, &jupelist_msgtab, NULL
};

DECLARE_MODULE_AV2(m_jupe, NULL, moddeinit, jupe_clist, NULL, NULL, NULL, NULL, jupe_desc);

/* =========================================================================
 * Jupe list
 * ========================================================================= */

struct jupe_entry {
	char server[HOSTLEN + 1];
	char reason[256];
	char set_by[NICKLEN + 1];
	time_t set_ts;
	rb_dlink_node node;
};

static rb_dlink_list jupe_list = { NULL, NULL, 0 };

static struct jupe_entry *
jupe_find(const char *server)
{
	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, jupe_list.head)
	{
		struct jupe_entry *j = ptr->data;
		if (irccmp(j->server, server) == 0)
			return j;
	}
	return NULL;
}

static struct jupe_entry *
jupe_add(const char *server, const char *reason, const char *set_by)
{
	struct jupe_entry *j = jupe_find(server);
	if (j != NULL)
	{
		/* Update existing jupe */
		rb_strlcpy(j->reason, reason, sizeof(j->reason));
		rb_strlcpy(j->set_by, set_by, sizeof(j->set_by));
		j->set_ts = rb_current_time();
		return j;
	}

	j = rb_malloc(sizeof(*j));
	rb_strlcpy(j->server, server, sizeof(j->server));
	rb_strlcpy(j->reason, reason, sizeof(j->reason));
	rb_strlcpy(j->set_by, set_by, sizeof(j->set_by));
	j->set_ts = rb_current_time();
	rb_dlinkAdd(j, &j->node, &jupe_list);
	return j;
}

static bool
jupe_remove(const char *server)
{
	struct jupe_entry *j = jupe_find(server);
	if (j == NULL)
		return false;
	rb_dlinkDelete(&j->node, &jupe_list);
	rb_free(j);
	return true;
}

/* =========================================================================
 * Public API — called from the SERVER command handler (s_serv.c / m_server.c)
 * to refuse links for juped server names.
 * ========================================================================= */

/*
 * jupe_check — return true if servername is currently juped.
 * Exported so the server-link code can call it.
 */
bool jupe_check(const char *server_name);
bool
jupe_check(const char *server_name)
{
	return jupe_find(server_name) != NULL;
}

/* =========================================================================
 * Module cleanup
 * ========================================================================= */

static void
moddeinit(void)
{
	rb_dlink_node *ptr, *next;
	RB_DLINK_FOREACH_SAFE(ptr, next, jupe_list.head)
	{
		struct jupe_entry *j = ptr->data;
		rb_dlinkDelete(ptr, &jupe_list);
		rb_free(j);
	}
}

/* =========================================================================
 * JUPE handler
 * ========================================================================= */

/*
 * mo_jupe — JUPE <servername> [:<reason>]
 *
 * parv[1] = server name to jupe
 * parv[2] = reason (optional)
 */
static void
mo_jupe(struct MsgBuf *msgbuf_p, struct Client *client_p,
	struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES,
			form_str(ERR_NOPRIVILEGES));
		return;
	}

	const char *server_name = parv[1];
	const char *reason      = (parc >= 3 && !EmptyString(parv[2]))
		? parv[2] : "No reason given";

	/* Server names must contain a dot (basic sanity check). */
	if (strchr(server_name, '.') == NULL)
	{
		sendto_one_notice(source_p,
			":Invalid server name \2%s\2 — must contain at least one dot.",
			server_name);
		return;
	}

	/* Refuse to jupe ourselves. */
	if (irccmp(server_name, me.name) == 0 ||
	    irccmp(server_name, me.id) == 0)
	{
		sendto_one_notice(source_p,
			":Cannot JUPE the local server.");
		return;
	}

	/* SQUIT any currently-connected server with this name. */
	struct Client *target_p = find_server(source_p, server_name);
	if (target_p != NULL && IsServer(target_p) && !IsMe(target_p))
	{
		sendto_realops_snomask(SNO_GENERAL, L_ALL,
			"JUPE: squitting \2%s\2 as part of jupe by \2%s\2: %s",
			server_name, source_p->name, reason);
		exit_client(target_p, &me, &me, reason);
	}

	/* Add (or update) the jupe. */
	jupe_add(server_name, reason, source_p->name);

	/* Global WALLOPS. */
	sendto_wallops_flags(UMODE_WALLOP, &me,
		"JUPE for \2%s\2 activated by \2%s\2: %s",
		server_name, source_p->name, reason);
	sendto_server(NULL, NULL, NOCAPS, NOCAPS,
		":%s WALLOPS :JUPE for %s activated by %s: %s",
		me.id, server_name, source_p->name, reason);

	sendto_realops_snomask(SNO_GENERAL, L_ALL,
		"JUPE: \2%s\2 juped by \2%s\2: %s",
		server_name, source_p->name, reason);

	sendto_one_notice(source_p,
		":JUPE for \2%s\2 is now active. Reason: %s",
		server_name, reason);

	ilog(L_MAIN, "JUPE %s by %s!%s@%s: %s",
		server_name,
		source_p->name, source_p->username, source_p->host,
		reason);
}

/* =========================================================================
 * UNJUPE handler
 * ========================================================================= */

/*
 * mo_unjupe — UNJUPE <servername>
 *
 * parv[1] = server name to unjupe
 */
static void
mo_unjupe(struct MsgBuf *msgbuf_p, struct Client *client_p,
	  struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES,
			form_str(ERR_NOPRIVILEGES));
		return;
	}

	const char *server_name = parv[1];

	if (!jupe_remove(server_name))
	{
		sendto_one_notice(source_p,
			":\2%s\2 is not currently juped.", server_name);
		return;
	}

	sendto_wallops_flags(UMODE_WALLOP, &me,
		"JUPE for \2%s\2 removed by \2%s\2",
		server_name, source_p->name);
	sendto_server(NULL, NULL, NOCAPS, NOCAPS,
		":%s WALLOPS :JUPE for %s removed by %s",
		me.id, server_name, source_p->name);

	sendto_realops_snomask(SNO_GENERAL, L_ALL,
		"JUPE: \2%s\2 unjuped by \2%s\2",
		server_name, source_p->name);

	sendto_one_notice(source_p,
		":JUPE for \2%s\2 has been removed.", server_name);

	ilog(L_MAIN, "UNJUPE %s by %s!%s@%s",
		server_name,
		source_p->name, source_p->username, source_p->host);
}

/* =========================================================================
 * JUPELIST handler
 * ========================================================================= */

/*
 * mo_jupelist — JUPELIST
 * Lists all active jupes.
 */
static void
mo_jupelist(struct MsgBuf *msgbuf_p, struct Client *client_p,
	    struct Client *source_p, int parc, const char *parv[])
{
	(void)msgbuf_p;
	(void)client_p;
	(void)parc;
	(void)parv;

	if (!IsOper(source_p))
	{
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES,
			form_str(ERR_NOPRIVILEGES));
		return;
	}

	if (rb_dlink_list_length(&jupe_list) == 0)
	{
		sendto_one_notice(source_p, ":No active jupes.");
		return;
	}

	sendto_one_notice(source_p, ":Active jupes:");

	rb_dlink_node *ptr;
	RB_DLINK_FOREACH(ptr, jupe_list.head)
	{
		struct jupe_entry *j = ptr->data;
		char timebuf[32];
		struct tm *tm_p = gmtime(&j->set_ts);
		strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S UTC", tm_p);

		sendto_one_notice(source_p,
			":  \2%s\2  set by \2%s\2 on %s — %s",
			j->server, j->set_by, timebuf, j->reason);
	}

	sendto_one_notice(source_p, ":End of JUPELIST.");
}
