/*
 * modules/m_memo.c — MEMO command (MemoServ functionality)
 *
 * MEMO SEND <account> <text>
 * MEMO LIST
 * MEMO READ <id>
 * MEMO DEL <id|ALL>
 * MEMO FORWARD <id> <account>
 *
 * Copyright (c) 2026 Ophion development team.  GPL v2.
 */

#include "stdinc.h"
#include "client.h"
#include "services.h"
#include "services_db.h"
#include "services_sync.h"
#include "msg.h"
#include "modules.h"
#include "send.h"
#include "numeric.h"
#include "channel.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "ircd.h"
#include "hash.h"

static const char memo_desc[] =
	"Provides MEMO command (MemoServ) for sending inter-account messages";

static void m_memo(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message memo_msgtab = {
	"MEMO", 0, 0, 0, 0,
	{mg_unreg, {m_memo, 2}, mg_ignore, mg_ignore, mg_ignore, {m_memo, 2}}
};

mapi_clist_av1 memo_clist[] = {
	&memo_msgtab, NULL
};

DECLARE_MODULE_AV2(memo, NULL, NULL, memo_clist, NULL, NULL, NULL, NULL, memo_desc);

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

/* Count memos currently stored for an account */
static int
count_memos_for(const char *account)
{
	rb_dlink_list list;
	rb_dlink_node *ptr, *next_ptr;
	int count = 0;

	memset(&list, 0, sizeof(list));
	if (!svc_db_memo_load_for(account, &list))
		return 0;

	count = (int) rb_dlink_length(&list);

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, list.head)
	{
		struct svc_memo *m = ptr->data;
		rb_dlinkDelete(ptr, &list);
		rb_free(m);
	}

	return count;
}

/* -------------------------------------------------------------------------
 * MEMO SEND <account> <text>
 * ------------------------------------------------------------------------- */
static void
memo_send(struct Client *source_p, int parc, const char *parv[])
{
	/* parv[0]=MEMO parv[1]=SEND parv[2]=account parv[3]=text */
	const char *target_name, *text;
	struct svc_account *target_acct;
	struct svc_memo *memo;
	struct Client *target_online;
	int count;

	if (parc < 4)
	{
		svc_notice(source_p, "MemoServ",
			"Usage: MEMO SEND <account> <text>");
		return;
	}

	target_name = parv[2];
	text        = parv[3];

	target_acct = svc_account_find(target_name);
	if (target_acct == NULL)
	{
		svc_notice(source_p, "MemoServ",
			"Account \2%s\2 does not exist.", target_name);
		return;
	}

	if (target_acct->flags & ACCT_NOMEMO)
	{
		svc_notice(source_p, "MemoServ",
			"\2%s\2 is not accepting memos.", target_name);
		return;
	}

	count = count_memos_for(target_acct->name);
	if (services.maxmemos > 0 && count >= services.maxmemos)
	{
		svc_notice(source_p, "MemoServ",
			"\2%s\2's memo box is full (%d/%d memos).",
			target_name, count, services.maxmemos);
		return;
	}

	memo = rb_malloc(sizeof(*memo));
	memo->id = 0; /* assigned by DB */
	rb_strlcpy(memo->to_account,   target_acct->name,            sizeof(memo->to_account));
	rb_strlcpy(memo->from_account, source_p->user->suser,        sizeof(memo->from_account));
	memo->sent_ts = rb_current_time();
	memo->read    = false;
	rb_strlcpy(memo->text, text, sizeof(memo->text));

	if (!svc_db_memo_insert(memo))
	{
		svc_notice(source_p, "MemoServ",
			"An internal error occurred; memo could not be saved.");
		rb_free(memo);
		return;
	}

	/* Notify target if online */
	target_online = find_named_client(target_acct->name);
	if (target_online == NULL)
	{
		/* Search all clients by suser */
		rb_dlink_node *ptr;
		RB_DLINK_FOREACH(ptr, lclient_list.head)
		{
			struct Client *c = ptr->data;
			if (IsPerson(c) && irccmp(c->user->suser, target_acct->name) == 0)
			{
				target_online = c;
				break;
			}
		}
	}

	if (target_online != NULL && IsPerson(target_online))
		svc_memo_deliver_notice(target_online, target_acct);

	svc_notice(source_p, "MemoServ",
		"Memo sent to \2%s\2.", target_acct->name);

	rb_free(memo);
}

/* -------------------------------------------------------------------------
 * MEMO LIST
 * ------------------------------------------------------------------------- */
static void
memo_list(struct Client *source_p)
{
	const char *account = source_p->user->suser;
	rb_dlink_list list;
	rb_dlink_node *ptr, *next_ptr;
	int n = 0;

	memset(&list, 0, sizeof(list));
	if (!svc_db_memo_load_for(account, &list))
	{
		svc_notice(source_p, "MemoServ",
			"Could not load memos (database error).");
		return;
	}

	if (rb_dlink_length(&list) == 0)
	{
		svc_notice(source_p, "MemoServ", "You have no memos.");
		return;
	}

	svc_notice(source_p, "MemoServ", "Your memos:");

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, list.head)
	{
		struct svc_memo *m = ptr->data;
		char datebuf[32];
		char preview[44];
		struct tm *tm_p;
		time_t ts;

		ts    = m->sent_ts;
		tm_p  = gmtime(&ts);
		strftime(datebuf, sizeof(datebuf), "%Y-%m-%d %H:%M", tm_p);

		/* 40-character preview */
		rb_strlcpy(preview, m->text, sizeof(preview));
		if (strlen(m->text) > 40)
		{
			preview[40] = '\0';
			rb_strlcat(preview, "...", sizeof(preview));
		}

		svc_notice(source_p, "MemoServ",
			"  ID %-5d  From %-20s %s %s  %s",
			m->id,
			m->from_account,
			m->read ? "    " : "[NEW]",
			datebuf,
			preview);

		rb_dlinkDelete(ptr, &list);
		rb_free(m);
		n++;
	}

	svc_notice(source_p, "MemoServ", "%d memo(s).", n);
}

/* -------------------------------------------------------------------------
 * MEMO READ <id>
 * ------------------------------------------------------------------------- */
static void
memo_read(struct Client *source_p, int parc, const char *parv[])
{
	const char *account = source_p->user->suser;
	int target_id;
	rb_dlink_list list;
	rb_dlink_node *ptr, *next_ptr;
	struct svc_memo *found = NULL;
	struct tm *tm_p;
	char datebuf[32];

	if (parc < 3)
	{
		svc_notice(source_p, "MemoServ", "Usage: MEMO READ <id>");
		return;
	}

	target_id = atoi(parv[2]);

	memset(&list, 0, sizeof(list));
	if (!svc_db_memo_load_for(account, &list))
	{
		svc_notice(source_p, "MemoServ",
			"Could not load memos (database error).");
		return;
	}

	RB_DLINK_FOREACH(ptr, list.head)
	{
		struct svc_memo *m = ptr->data;
		if (m->id == target_id)
		{
			found = m;
			break;
		}
	}

	if (found == NULL)
	{
		svc_notice(source_p, "MemoServ",
			"Memo #%d not found or does not belong to your account.", target_id);
	}
	else if (irccmp(found->to_account, account) != 0)
	{
		svc_notice(source_p, "MemoServ",
			"Memo #%d does not belong to your account.", target_id);
	}
	else
	{
		time_t ts = found->sent_ts;
		tm_p = gmtime(&ts);
		strftime(datebuf, sizeof(datebuf), "%Y-%m-%d %H:%M:%S UTC", tm_p);

		svc_notice(source_p, "MemoServ",
			"--- Memo #%d from \2%s\2 (%s) ---",
			found->id, found->from_account, datebuf);
		svc_notice(source_p, "MemoServ", "%s", found->text);
		svc_notice(source_p, "MemoServ", "--- End of memo ---");

		svc_db_memo_mark_read(found->id);
	}

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, list.head)
	{
		struct svc_memo *m = ptr->data;
		rb_dlinkDelete(ptr, &list);
		rb_free(m);
	}
}

/* -------------------------------------------------------------------------
 * MEMO DEL <id|ALL>
 * ------------------------------------------------------------------------- */
static void
memo_del(struct Client *source_p, int parc, const char *parv[])
{
	const char *account = source_p->user->suser;
	rb_dlink_list list;
	rb_dlink_node *ptr, *next_ptr;
	int deleted = 0;

	if (parc < 3)
	{
		svc_notice(source_p, "MemoServ", "Usage: MEMO DEL <id|ALL>");
		return;
	}

	memset(&list, 0, sizeof(list));
	if (!svc_db_memo_load_for(account, &list))
	{
		svc_notice(source_p, "MemoServ",
			"Could not load memos (database error).");
		return;
	}

	if (irccmp(parv[2], "ALL") == 0)
	{
		RB_DLINK_FOREACH_SAFE(ptr, next_ptr, list.head)
		{
			struct svc_memo *m = ptr->data;
			svc_db_memo_delete(m->id);
			deleted++;
			rb_dlinkDelete(ptr, &list);
			rb_free(m);
		}
		svc_notice(source_p, "MemoServ",
			"Deleted all %d memo(s).", deleted);
	}
	else
	{
		int target_id = atoi(parv[2]);
		bool found = false;

		RB_DLINK_FOREACH_SAFE(ptr, next_ptr, list.head)
		{
			struct svc_memo *m = ptr->data;
			if (m->id == target_id && irccmp(m->to_account, account) == 0)
			{
				svc_db_memo_delete(m->id);
				deleted = 1;
				found = true;
			}
			rb_dlinkDelete(ptr, &list);
			rb_free(m);
		}

		if (found)
			svc_notice(source_p, "MemoServ", "Memo #%d deleted.", target_id);
		else
			svc_notice(source_p, "MemoServ",
				"Memo #%d not found or does not belong to your account.", target_id);
	}
}

/* -------------------------------------------------------------------------
 * MEMO FORWARD <id> <account>
 * ------------------------------------------------------------------------- */
static void
memo_forward(struct Client *source_p, int parc, const char *parv[])
{
	const char *account = source_p->user->suser;
	int target_id;
	const char *dest_name;
	struct svc_account *dest_acct;
	rb_dlink_list list;
	rb_dlink_node *ptr, *next_ptr;
	struct svc_memo *found = NULL;
	struct svc_memo *fwd;
	char fwd_text[512];
	int count;

	if (parc < 4)
	{
		svc_notice(source_p, "MemoServ", "Usage: MEMO FORWARD <id> <account>");
		return;
	}

	target_id = atoi(parv[2]);
	dest_name = parv[3];

	dest_acct = svc_account_find(dest_name);
	if (dest_acct == NULL)
	{
		svc_notice(source_p, "MemoServ",
			"Account \2%s\2 does not exist.", dest_name);
		return;
	}

	if (dest_acct->flags & ACCT_NOMEMO)
	{
		svc_notice(source_p, "MemoServ",
			"\2%s\2 is not accepting memos.", dest_name);
		return;
	}

	count = count_memos_for(dest_acct->name);
	if (services.maxmemos > 0 && count >= services.maxmemos)
	{
		svc_notice(source_p, "MemoServ",
			"\2%s\2's memo box is full.", dest_name);
		return;
	}

	memset(&list, 0, sizeof(list));
	if (!svc_db_memo_load_for(account, &list))
	{
		svc_notice(source_p, "MemoServ",
			"Could not load memos (database error).");
		return;
	}

	RB_DLINK_FOREACH(ptr, list.head)
	{
		struct svc_memo *m = ptr->data;
		if (m->id == target_id && irccmp(m->to_account, account) == 0)
		{
			found = m;
			break;
		}
	}

	if (found == NULL)
	{
		RB_DLINK_FOREACH_SAFE(ptr, next_ptr, list.head)
		{
			struct svc_memo *m = ptr->data;
			rb_dlinkDelete(ptr, &list);
			rb_free(m);
		}
		svc_notice(source_p, "MemoServ",
			"Memo #%d not found or does not belong to your account.", target_id);
		return;
	}

	snprintf(fwd_text, sizeof(fwd_text),
		"Fwd from \2%s\2: %s", found->from_account, found->text);

	fwd = rb_malloc(sizeof(*fwd));
	fwd->id = 0;
	rb_strlcpy(fwd->to_account,   dest_acct->name, sizeof(fwd->to_account));
	rb_strlcpy(fwd->from_account, account,          sizeof(fwd->from_account));
	fwd->sent_ts = rb_current_time();
	fwd->read    = false;
	rb_strlcpy(fwd->text, fwd_text, sizeof(fwd->text));

	if (!svc_db_memo_insert(fwd))
	{
		svc_notice(source_p, "MemoServ",
			"An internal error occurred; memo could not be forwarded.");
		rb_free(fwd);
	}
	else
	{
		svc_notice(source_p, "MemoServ",
			"Memo #%d forwarded to \2%s\2.", target_id, dest_acct->name);
		rb_free(fwd);
	}

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, list.head)
	{
		struct svc_memo *m = ptr->data;
		rb_dlinkDelete(ptr, &list);
		rb_free(m);
	}
}

/* -------------------------------------------------------------------------
 * Main MEMO handler
 * ------------------------------------------------------------------------- */
static void
m_memo(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	const char *subcmd;

	if (!services.enabled)
	{
		sendto_one(source_p, form_str(ERR_UNKNOWNCOMMAND),
			me.name, source_p->name, "MEMO");
		return;
	}

	if (EmptyString(source_p->user->suser))
	{
		svc_notice(source_p, "MemoServ",
			"You must be identified to an account to use MEMO.");
		return;
	}

	subcmd = parv[1];

	if (irccmp(subcmd, "SEND") == 0)
	{
		memo_send(source_p, parc, parv);
		return;
	}

	if (irccmp(subcmd, "LIST") == 0)
	{
		memo_list(source_p);
		return;
	}

	if (irccmp(subcmd, "READ") == 0)
	{
		memo_read(source_p, parc, parv);
		return;
	}

	if (irccmp(subcmd, "DEL") == 0 || irccmp(subcmd, "DELETE") == 0)
	{
		memo_del(source_p, parc, parv);
		return;
	}

	if (irccmp(subcmd, "FORWARD") == 0 || irccmp(subcmd, "FWD") == 0)
	{
		memo_forward(source_p, parc, parv);
		return;
	}

	svc_notice(source_p, "MemoServ",
		"Unknown MEMO subcommand: \2%s\2.  Subcommands: SEND LIST READ DEL FORWARD",
		subcmd);
}
