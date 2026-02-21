/*
 * ircd/services_db.c — SQLite persistence layer for the Ophion services system
 *
 * Opens and manages a dedicated SQLite database (services.db) that stores
 * all NickServ accounts, ChanServ channel registrations, MemoServ messages,
 * and HostServ vhost offers.  Uses the SQLite3 amalgamation from bandb/
 * directly in-process — this is NOT the rsdb helper-process API used by bandb.
 *
 * On startup svc_db_init() creates the schema if it does not exist, then
 * loads every record into the in-memory radixtrees (svc_account_dict,
 * svc_nick_dict, svc_chanreg_dict) maintained by services_core.c.  All
 * subsequent write functions update both the in-memory store and the DB
 * atomically so the two never diverge.
 *
 * Copyright (c) 2026 Ophion development team.  GPL v2.
 */

#include "stdinc.h"
#include "hash.h"
#include "s_conf.h"
#include "ircd.h"
#include "logger.h"
#include "match.h"
#include "services.h"
#include "services_db.h"
#include <sqlite3.h>

/* -------------------------------------------------------------------------
 * Module-private state
 * ---------------------------------------------------------------------- */

static sqlite3 *svc_db = NULL;

/* -------------------------------------------------------------------------
 * Schema DDL
 *
 * All tables are created with IF NOT EXISTS so this is safe to run against
 * an already-populated database (upgrade migrations are handled elsewhere).
 * ---------------------------------------------------------------------- */

static const char svc_schema[] =
    "PRAGMA foreign_keys = ON;"

    "CREATE TABLE IF NOT EXISTS svc_accounts ("
    "  name             TEXT    PRIMARY KEY COLLATE NOCASE,"
    "  passhash         TEXT    NOT NULL DEFAULT '',"
    "  email            TEXT    NOT NULL DEFAULT '',"
    "  registered_ts    INTEGER NOT NULL,"
    "  last_seen_ts     INTEGER NOT NULL DEFAULT 0,"
    "  last_seen_nick   TEXT    NOT NULL DEFAULT '',"
    "  last_seen_host   TEXT    NOT NULL DEFAULT '',"
    "  flags            INTEGER NOT NULL DEFAULT 0,"
    "  oper_block       TEXT    NOT NULL DEFAULT '',"
    "  vhost            TEXT    NOT NULL DEFAULT '',"
    "  language         TEXT    NOT NULL DEFAULT 'en'"
    ");"

    "CREATE TABLE IF NOT EXISTS svc_nicks ("
    "  nick          TEXT    PRIMARY KEY COLLATE NOCASE,"
    "  account       TEXT    NOT NULL COLLATE NOCASE"
    "                        REFERENCES svc_accounts(name) ON DELETE CASCADE,"
    "  registered_ts INTEGER NOT NULL"
    ");"

    "CREATE TABLE IF NOT EXISTS svc_certfps ("
    "  account     TEXT    NOT NULL COLLATE NOCASE"
    "              REFERENCES svc_accounts(name) ON DELETE CASCADE,"
    "  fingerprint TEXT    NOT NULL,"
    "  added_ts    INTEGER NOT NULL,"
    "  PRIMARY KEY (account, fingerprint)"
    ");"

    "CREATE TABLE IF NOT EXISTS svc_access_masks ("
    "  account  TEXT    NOT NULL COLLATE NOCASE"
    "           REFERENCES svc_accounts(name) ON DELETE CASCADE,"
    "  mask     TEXT    NOT NULL,"
    "  added_ts INTEGER NOT NULL,"
    "  PRIMARY KEY (account, mask)"
    ");"

    "CREATE TABLE IF NOT EXISTS svc_metadata ("
    "  account TEXT NOT NULL COLLATE NOCASE"
    "          REFERENCES svc_accounts(name) ON DELETE CASCADE,"
    "  key     TEXT NOT NULL,"
    "  value   TEXT NOT NULL,"
    "  PRIMARY KEY (account, key)"
    ");"

    "CREATE TABLE IF NOT EXISTS svc_chanregs ("
    "  channel       TEXT    PRIMARY KEY COLLATE NOCASE,"
    "  founder       TEXT    NOT NULL COLLATE NOCASE,"
    "  successor     TEXT    NOT NULL DEFAULT '',"
    "  registered_ts INTEGER NOT NULL,"
    "  topic         TEXT    NOT NULL DEFAULT '',"
    "  topic_setter  TEXT    NOT NULL DEFAULT '',"
    "  topic_ts      INTEGER NOT NULL DEFAULT 0,"
    "  flags         INTEGER NOT NULL DEFAULT 0,"
    "  url           TEXT    NOT NULL DEFAULT '',"
    "  description   TEXT    NOT NULL DEFAULT '',"
    "  mlock_on      INTEGER NOT NULL DEFAULT 0,"
    "  mlock_off     INTEGER NOT NULL DEFAULT 0,"
    "  mlock_limit   INTEGER NOT NULL DEFAULT 0,"
    "  mlock_key     TEXT    NOT NULL DEFAULT ''"
    ");"

    "CREATE TABLE IF NOT EXISTS svc_chanaccess ("
    "  channel TEXT    NOT NULL COLLATE NOCASE"
    "          REFERENCES svc_chanregs(channel) ON DELETE CASCADE,"
    "  entity  TEXT    NOT NULL COLLATE NOCASE,"
    "  flags   INTEGER NOT NULL DEFAULT 0,"
    "  setter  TEXT    NOT NULL DEFAULT '',"
    "  set_ts  INTEGER NOT NULL DEFAULT 0,"
    "  PRIMARY KEY (channel, entity)"
    ");"

    "CREATE TABLE IF NOT EXISTS svc_memos ("
    "  id           INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  to_account   TEXT    NOT NULL COLLATE NOCASE,"
    "  from_account TEXT    NOT NULL,"
    "  sent_ts      INTEGER NOT NULL,"
    "  read         INTEGER NOT NULL DEFAULT 0,"
    "  text         TEXT    NOT NULL"
    ");"

    "CREATE TABLE IF NOT EXISTS svc_vhost_offers ("
    "  vhost       TEXT    PRIMARY KEY,"
    "  offered_by  TEXT    NOT NULL,"
    "  offered_ts  INTEGER NOT NULL"
    ");"

    /*
     * Secondary indexes — not created by the initial table DDL because the
     * tables only declare their PRIMARY KEY constraints.  These four indexes
     * cover the most common non-PK lookup patterns:
     *
     *   svc_nicks.account      — startup bulk-load "all nicks for account X"
     *   svc_certfps.fingerprint — SASL EXTERNAL cert lookup by raw fingerprint
     *   svc_memos.to_account    — MemoServ "get all memos for account X"
     *   svc_chanaccess.entity   — "all channels where entity has access"
     *
     * Without these, each such query does a full table scan; with them the
     * queries become single B-tree lookups — O(log n) instead of O(n).
     */
    "CREATE INDEX IF NOT EXISTS idx_svc_nicks_account"
    "    ON svc_nicks(account);"
    "CREATE INDEX IF NOT EXISTS idx_svc_certfps_fp"
    "    ON svc_certfps(fingerprint);"
    "CREATE INDEX IF NOT EXISTS idx_svc_memos_to_account"
    "    ON svc_memos(to_account);"
    "CREATE INDEX IF NOT EXISTS idx_svc_chanaccess_entity"
    "    ON svc_chanaccess(entity);";

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/*
 * db_exec — run a single-statement SQL string with no bound parameters.
 * Logs a warning and returns false on failure.
 */
static bool
db_exec(const char *sql)
{
	char *errmsg = NULL;

	if(sqlite3_exec(svc_db, sql, NULL, NULL, &errmsg) != SQLITE_OK)
	{
		ilog(L_MAIN, "services_db: sqlite3_exec error: %s (sql: %.80s)",
		     errmsg ? errmsg : "(null)", sql);
		sqlite3_free(errmsg);
		return false;
	}
	return true;
}

/*
 * db_step_norow — prepare, step, and finalize a statement that returns no
 * rows (INSERT / UPDATE / DELETE).  Returns false on error.
 */
static bool
db_step_norow(const char *sql)
{
	sqlite3_stmt *stmt;

	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
	{
		ilog(L_MAIN, "services_db: prepare error: %s",
		     sqlite3_errmsg(svc_db));
		return false;
	}
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if(rc != SQLITE_DONE)
	{
		ilog(L_MAIN, "services_db: step error: %s",
		     sqlite3_errmsg(svc_db));
		return false;
	}
	return true;
}

/* -------------------------------------------------------------------------
 * svc_db_init / svc_db_shutdown
 * ---------------------------------------------------------------------- */

bool
svc_db_init(const char *path)
{
	const char *db_path = (path && *path) ? path : services.db_path;

	/*
	 * SQLITE_OPEN_NOMUTEX — the IRCd is single-threaded; SQLite's default
	 * "serialised" threading model adds a pthread_mutex_lock/unlock pair
	 * around every API call.  NOMUTEX selects the "multi-thread" mode which
	 * skips those locks when only one thread uses each connection, cutting
	 * syscall overhead on every DB operation.
	 */
	if(sqlite3_open_v2(db_path, &svc_db,
	                   SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
	                   SQLITE_OPEN_NOMUTEX,
	                   NULL) != SQLITE_OK)
	{
		ilog(L_MAIN, "services_db: cannot open database '%s': %s",
		     db_path, sqlite3_errmsg(svc_db));
		sqlite3_close(svc_db);
		svc_db = NULL;
		return false;
	}

	/* Enable WAL for better concurrent read performance */
	sqlite3_exec(svc_db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);
	sqlite3_exec(svc_db, "PRAGMA synchronous = NORMAL;", NULL, NULL, NULL);
	sqlite3_exec(svc_db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);
	/*
	 * cache_size = -65536  →  64 MB page cache.
	 *   Keeps hot account and channel pages in RAM; the default 2 MB fills
	 *   up quickly on networks with tens of thousands of registrations.
	 *   Negative value is interpreted as kibibytes by SQLite.
	 *
	 * mmap_size = 134217728  →  128 MB memory-mapped I/O.
	 *   On Linux and BSD, SQLite maps this many bytes of the database file
	 *   into the process address space.  Reads from the mapped region go
	 *   directly from the kernel page cache to SQLite's btree without an
	 *   extra memcpy(), halving read latency for cold-cache startup loads.
	 *
	 * temp_store = MEMORY  →  all temporary tables go to RAM.
	 *   SQLite creates temp tables for complex JOINs and sorts; putting
	 *   them in memory eliminates /tmp file I/O entirely.
	 *
	 * busy_timeout = 5000  →  retry WAL locks for up to 5 seconds.
	 *   Prevents SQLITE_BUSY failures if a concurrent reader (e.g. a
	 *   backup tool) holds the WAL read lock during startup.
	 */
	sqlite3_exec(svc_db, "PRAGMA cache_size   = -65536;",    NULL, NULL, NULL);
	sqlite3_exec(svc_db, "PRAGMA mmap_size    = 134217728;", NULL, NULL, NULL);
	sqlite3_exec(svc_db, "PRAGMA temp_store   = MEMORY;",    NULL, NULL, NULL);
	sqlite3_exec(svc_db, "PRAGMA busy_timeout = 5000;",      NULL, NULL, NULL);

	/* Create schema if needed */
	char *errmsg = NULL;
	if(sqlite3_exec(svc_db, svc_schema, NULL, NULL, &errmsg) != SQLITE_OK)
	{
		ilog(L_MAIN, "services_db: schema creation failed: %s",
		     errmsg ? errmsg : "(null)");
		sqlite3_free(errmsg);
		sqlite3_close(svc_db);
		svc_db = NULL;
		return false;
	}

	ilog(L_MAIN, "services_db: opened database '%s'", db_path);

	if(!svc_db_account_load_all())
	{
		ilog(L_MAIN, "services_db: account load failed");
		return false;
	}

	if(!svc_db_chanreg_load_all())
	{
		ilog(L_MAIN, "services_db: chanreg load failed");
		return false;
	}

	return true;
}

void
svc_db_shutdown(void)
{
	if(svc_db == NULL)
		return;

	sqlite3_close(svc_db);
	svc_db = NULL;
	ilog(L_MAIN, "services_db: database closed");
}

/* -------------------------------------------------------------------------
 * Account persistence
 * ---------------------------------------------------------------------- */

bool
svc_db_account_load_all(void)
{
	static const char sql[] =
	    "SELECT name, passhash, email, registered_ts, last_seen_ts,"
	    "       last_seen_nick, last_seen_host, flags, oper_block,"
	    "       vhost, language"
	    "  FROM svc_accounts;";

	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
	{
		ilog(L_MAIN, "services_db: account_load_all prepare: %s",
		     sqlite3_errmsg(svc_db));
		return false;
	}

	int loaded = 0;
	while(sqlite3_step(stmt) == SQLITE_ROW)
	{
		struct svc_account *acct = rb_malloc(sizeof *acct);

		rb_strlcpy(acct->name,
		           (const char *)sqlite3_column_text(stmt, 0),
		           sizeof acct->name);
		rb_strlcpy(acct->passhash,
		           (const char *)sqlite3_column_text(stmt, 1),
		           sizeof acct->passhash);
		rb_strlcpy(acct->email,
		           (const char *)sqlite3_column_text(stmt, 2),
		           sizeof acct->email);
		acct->registered_ts = (time_t)sqlite3_column_int64(stmt, 3);
		acct->last_seen_ts  = (time_t)sqlite3_column_int64(stmt, 4);
		rb_strlcpy(acct->last_seen_nick,
		           (const char *)sqlite3_column_text(stmt, 5),
		           sizeof acct->last_seen_nick);
		rb_strlcpy(acct->last_seen_host,
		           (const char *)sqlite3_column_text(stmt, 6),
		           sizeof acct->last_seen_host);
		acct->flags = (uint32_t)sqlite3_column_int64(stmt, 7);
		rb_strlcpy(acct->oper_block,
		           (const char *)sqlite3_column_text(stmt, 8),
		           sizeof acct->oper_block);
		rb_strlcpy(acct->vhost,
		           (const char *)sqlite3_column_text(stmt, 9),
		           sizeof acct->vhost);
		rb_strlcpy(acct->language,
		           (const char *)sqlite3_column_text(stmt, 10),
		           sizeof acct->language);
		acct->dirty = false;

		rb_radixtree_add(svc_account_dict, acct->name, acct);
		loaded++;
	}
	sqlite3_finalize(stmt);

	/* Load nicks */
	{
		static const char nick_sql[] =
		    "SELECT nick, account, registered_ts FROM svc_nicks;";
		sqlite3_stmt *ns;
		if(sqlite3_prepare_v2(svc_db, nick_sql, -1, &ns, NULL) == SQLITE_OK)
		{
			while(sqlite3_step(ns) == SQLITE_ROW)
			{
				const char *nk =
				    (const char *)sqlite3_column_text(ns, 0);
				const char *an =
				    (const char *)sqlite3_column_text(ns, 1);
				time_t rts = (time_t)sqlite3_column_int64(ns, 2);

				struct svc_account *acct =
				    rb_radixtree_retrieve(svc_account_dict, an);
				if(acct == NULL)
					continue;

				struct svc_nick *sn = rb_malloc(sizeof *sn);
				rb_strlcpy(sn->nick, nk, sizeof sn->nick);
				rb_strlcpy(sn->account, an, sizeof sn->account);
				sn->registered_ts = rts;

				rb_dlinkAdd(sn, &sn->node, &acct->nicks);
				rb_radixtree_add(svc_nick_dict, sn->nick, sn);
			}
			sqlite3_finalize(ns);
		}
	}

	/* Load certfps */
	{
		static const char cfp_sql[] =
		    "SELECT account, fingerprint, added_ts FROM svc_certfps;";
		sqlite3_stmt *cs;
		if(sqlite3_prepare_v2(svc_db, cfp_sql, -1, &cs, NULL) == SQLITE_OK)
		{
			while(sqlite3_step(cs) == SQLITE_ROW)
			{
				const char *an =
				    (const char *)sqlite3_column_text(cs, 0);
				const char *fp =
				    (const char *)sqlite3_column_text(cs, 1);
				time_t ats = (time_t)sqlite3_column_int64(cs, 2);

				struct svc_account *acct =
				    rb_radixtree_retrieve(svc_account_dict, an);
				if(acct == NULL)
					continue;

				struct svc_certfp *scf = rb_malloc(sizeof *scf);
				rb_strlcpy(scf->fingerprint, fp,
				           sizeof scf->fingerprint);
				scf->added_ts = ats;

				rb_dlinkAdd(scf, &scf->node, &acct->certfps);
				/* Populate secondary O(1) certfp → account index */
				if(svc_certfp_dict != NULL)
					rb_radixtree_add(svc_certfp_dict,
					                 scf->fingerprint, acct);
			}
			sqlite3_finalize(cs);
		}
	}

	/* Load access masks */
	{
		static const char am_sql[] =
		    "SELECT account, mask, added_ts FROM svc_access_masks;";
		sqlite3_stmt *as;
		if(sqlite3_prepare_v2(svc_db, am_sql, -1, &as, NULL) == SQLITE_OK)
		{
			while(sqlite3_step(as) == SQLITE_ROW)
			{
				const char *an =
				    (const char *)sqlite3_column_text(as, 0);
				const char *mk =
				    (const char *)sqlite3_column_text(as, 1);
				time_t ats = (time_t)sqlite3_column_int64(as, 2);

				struct svc_account *acct =
				    rb_radixtree_retrieve(svc_account_dict, an);
				if(acct == NULL)
					continue;

				struct svc_accessmask *sam =
				    rb_malloc(sizeof *sam);
				memset(sam, 0, sizeof *sam);
				rb_strlcpy(sam->mask, mk, sizeof sam->mask);
				sam->added_ts = ats;

				rb_dlinkAdd(sam, &sam->node,
				            &acct->access_masks);
			}
			sqlite3_finalize(as);
		}
	}

	ilog(L_MAIN, "services_db: loaded %d accounts", loaded);
	return true;
}

bool
svc_db_account_save(struct svc_account *acct)
{
	if(svc_db == NULL || acct == NULL)
		return false;

	db_exec("BEGIN TRANSACTION;");

	/* Upsert the account row */
	{
		static const char sql[] =
		    "INSERT OR REPLACE INTO svc_accounts"
		    "  (name, passhash, email, registered_ts, last_seen_ts,"
		    "   last_seen_nick, last_seen_host, flags, oper_block,"
		    "   vhost, language)"
		    "  VALUES (?,?,?,?,?,?,?,?,?,?,?);";
		sqlite3_stmt *stmt;
		if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		{
			db_exec("ROLLBACK;");
			return false;
		}
		sqlite3_bind_text (stmt,  1, acct->name,           -1, SQLITE_STATIC);
		sqlite3_bind_text (stmt,  2, acct->passhash,       -1, SQLITE_STATIC);
		sqlite3_bind_text (stmt,  3, acct->email,          -1, SQLITE_STATIC);
		sqlite3_bind_int64(stmt,  4, (sqlite3_int64)acct->registered_ts);
		sqlite3_bind_int64(stmt,  5, (sqlite3_int64)acct->last_seen_ts);
		sqlite3_bind_text (stmt,  6, acct->last_seen_nick, -1, SQLITE_STATIC);
		sqlite3_bind_text (stmt,  7, acct->last_seen_host, -1, SQLITE_STATIC);
		sqlite3_bind_int64(stmt,  8, (sqlite3_int64)acct->flags);
		sqlite3_bind_text (stmt,  9, acct->oper_block,     -1, SQLITE_STATIC);
		sqlite3_bind_text (stmt, 10, acct->vhost,          -1, SQLITE_STATIC);
		sqlite3_bind_text (stmt, 11, acct->language,       -1, SQLITE_STATIC);

		int rc = sqlite3_step(stmt);
		sqlite3_finalize(stmt);
		if(rc != SQLITE_DONE)
		{
			ilog(L_MAIN, "services_db: account_save step: %s",
			     sqlite3_errmsg(svc_db));
			db_exec("ROLLBACK;");
			return false;
		}
	}

	/* Re-sync nicks: delete existing rows then re-insert current list */
	{
		static const char del_sql[] =
		    "DELETE FROM svc_nicks WHERE account = ?;";
		sqlite3_stmt *ds;
		if(sqlite3_prepare_v2(svc_db, del_sql, -1, &ds, NULL) == SQLITE_OK)
		{
			sqlite3_bind_text(ds, 1, acct->name, -1, SQLITE_STATIC);
			sqlite3_step(ds);
			sqlite3_finalize(ds);
		}

		static const char ins_sql[] =
		    "INSERT OR REPLACE INTO svc_nicks"
		    "  (nick, account, registered_ts) VALUES (?,?,?);";
		rb_dlink_node *ptr;
		RB_DLINK_FOREACH(ptr, acct->nicks.head)
		{
			struct svc_nick *sn = ptr->data;
			sqlite3_stmt *is;
			if(sqlite3_prepare_v2(svc_db, ins_sql, -1, &is,
			                      NULL) == SQLITE_OK)
			{
				sqlite3_bind_text (is, 1, sn->nick,    -1,
				                   SQLITE_STATIC);
				sqlite3_bind_text (is, 2, acct->name,  -1,
				                   SQLITE_STATIC);
				sqlite3_bind_int64(is, 3,
				    (sqlite3_int64)sn->registered_ts);
				sqlite3_step(is);
				sqlite3_finalize(is);
			}
		}
	}

	/* Re-sync certfps */
	{
		static const char del_sql[] =
		    "DELETE FROM svc_certfps WHERE account = ?;";
		sqlite3_stmt *ds;
		if(sqlite3_prepare_v2(svc_db, del_sql, -1, &ds, NULL) == SQLITE_OK)
		{
			sqlite3_bind_text(ds, 1, acct->name, -1, SQLITE_STATIC);
			sqlite3_step(ds);
			sqlite3_finalize(ds);
		}

		static const char ins_sql[] =
		    "INSERT OR REPLACE INTO svc_certfps"
		    "  (account, fingerprint, added_ts) VALUES (?,?,?);";
		rb_dlink_node *ptr;
		RB_DLINK_FOREACH(ptr, acct->certfps.head)
		{
			struct svc_certfp *scf = ptr->data;
			sqlite3_stmt *is;
			if(sqlite3_prepare_v2(svc_db, ins_sql, -1, &is,
			                      NULL) == SQLITE_OK)
			{
				sqlite3_bind_text (is, 1, acct->name,       -1,
				                   SQLITE_STATIC);
				sqlite3_bind_text (is, 2, scf->fingerprint, -1,
				                   SQLITE_STATIC);
				sqlite3_bind_int64(is, 3,
				    (sqlite3_int64)scf->added_ts);
				sqlite3_step(is);
				sqlite3_finalize(is);
			}
		}
	}

	/* Re-sync access masks */
	{
		static const char del_sql[] =
		    "DELETE FROM svc_access_masks WHERE account = ?;";
		sqlite3_stmt *ds;
		if(sqlite3_prepare_v2(svc_db, del_sql, -1, &ds, NULL) == SQLITE_OK)
		{
			sqlite3_bind_text(ds, 1, acct->name, -1, SQLITE_STATIC);
			sqlite3_step(ds);
			sqlite3_finalize(ds);
		}

		static const char ins_sql[] =
		    "INSERT OR REPLACE INTO svc_access_masks"
		    "  (account, mask, added_ts) VALUES (?,?,?);";
		rb_dlink_node *ptr;
		RB_DLINK_FOREACH(ptr, acct->access_masks.head)
		{
			struct svc_accessmask *sam = ptr->data;
			sqlite3_stmt *is;
			if(sqlite3_prepare_v2(svc_db, ins_sql, -1, &is,
			                      NULL) == SQLITE_OK)
			{
				sqlite3_bind_text (is, 1, acct->name, -1,
				                   SQLITE_STATIC);
				sqlite3_bind_text (is, 2, sam->mask,  -1,
				                   SQLITE_STATIC);
				sqlite3_bind_int64(is, 3,
				    (sqlite3_int64)sam->added_ts);
				sqlite3_step(is);
				sqlite3_finalize(is);
			}
		}
	}

	db_exec("COMMIT;");
	/*
	 * In SPLIT mode (hub unreachable) keep dirty=true so the reconnect
	 * handler in ms_svcsburst() can re-sync this record to the hub.
	 * In all other modes a successful save means the record is clean.
	 */
	if(services.mode == SVCS_MODE_SPLIT) {
		if(!acct->dirty)
			services.dirty_count++;
		acct->dirty = true;
	} else {
		acct->dirty = false;
	}
	return true;
}

bool
svc_db_account_delete(const char *name)
{
	if(svc_db == NULL || name == NULL)
		return false;

	/* Cascade via foreign keys handles nicks/certfps/access_masks/metadata */
	static const char sql[] =
	    "DELETE FROM svc_accounts WHERE name = ?;";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;
	sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if(rc != SQLITE_DONE)
	{
		ilog(L_MAIN, "services_db: account_delete: %s",
		     sqlite3_errmsg(svc_db));
		return false;
	}

	/* Remove from in-memory dict */
	struct svc_account *acct = rb_radixtree_delete(svc_account_dict, name);
	if(acct != NULL)
	{
		/* Remove grouped nicks from svc_nick_dict */
		rb_dlink_node *ptr, *nptr;
		RB_DLINK_FOREACH_SAFE(ptr, nptr, acct->nicks.head)
		{
			struct svc_nick *sn = ptr->data;
			rb_radixtree_delete(svc_nick_dict, sn->nick);
		}
		svc_account_free(acct);
	}
	return true;
}

bool
svc_db_account_update_lastseen(struct svc_account *acct)
{
	if(svc_db == NULL || acct == NULL)
		return false;

	static const char sql[] =
	    "UPDATE svc_accounts"
	    "   SET last_seen_ts = ?, last_seen_nick = ?, last_seen_host = ?"
	    " WHERE name = ?;";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;
	sqlite3_bind_int64(stmt, 1, (sqlite3_int64)acct->last_seen_ts);
	sqlite3_bind_text (stmt, 2, acct->last_seen_nick, -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt, 3, acct->last_seen_host, -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt, 4, acct->name,           -1, SQLITE_STATIC);

	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE);
}

/* -------------------------------------------------------------------------
 * Nick persistence
 * ---------------------------------------------------------------------- */

bool
svc_db_nick_add(const char *nick, const char *account_name)
{
	if(svc_db == NULL || nick == NULL || account_name == NULL)
		return false;

	struct svc_account *acct =
	    rb_radixtree_retrieve(svc_account_dict, account_name);
	if(acct == NULL)
		return false;

	static const char sql[] =
	    "INSERT INTO svc_nicks (nick, account, registered_ts) VALUES (?,?,?);";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;

	time_t now = rb_current_time();
	sqlite3_bind_text (stmt, 1, nick,         -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt, 2, account_name, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);

	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if(rc != SQLITE_DONE)
	{
		ilog(L_MAIN, "services_db: nick_add: %s", sqlite3_errmsg(svc_db));
		return false;
	}

	struct svc_nick *sn = rb_malloc(sizeof *sn);
	rb_strlcpy(sn->nick, nick, sizeof sn->nick);
	rb_strlcpy(sn->account, account_name, sizeof sn->account);
	sn->registered_ts = now;

	rb_dlinkAdd(sn, &sn->node, &acct->nicks);
	rb_radixtree_add(svc_nick_dict, sn->nick, sn);
	return true;
}

bool
svc_db_nick_delete(const char *nick)
{
	if(svc_db == NULL || nick == NULL)
		return false;

	static const char sql[] = "DELETE FROM svc_nicks WHERE nick = ?;";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;
	sqlite3_bind_text(stmt, 1, nick, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if(rc != SQLITE_DONE)
		return false;

	struct svc_nick *sn = rb_radixtree_delete(svc_nick_dict, nick);
	if(sn != NULL)
	{
		struct svc_account *acct =
		    rb_radixtree_retrieve(svc_account_dict, sn->account);
		if(acct != NULL)
			rb_dlinkFindDestroy(sn, &acct->nicks);
		rb_free(sn);
	}
	return true;
}

/* -------------------------------------------------------------------------
 * Certificate fingerprint persistence
 * ---------------------------------------------------------------------- */

bool
svc_db_certfp_add(const char *account_name, const char *certfp)
{
	if(svc_db == NULL || account_name == NULL || certfp == NULL)
		return false;

	struct svc_account *acct =
	    rb_radixtree_retrieve(svc_account_dict, account_name);
	if(acct == NULL)
		return false;

	static const char sql[] =
	    "INSERT INTO svc_certfps (account, fingerprint, added_ts)"
	    "  VALUES (?,?,?);";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;

	time_t now = rb_current_time();
	sqlite3_bind_text (stmt, 1, account_name, -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt, 2, certfp,       -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);

	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if(rc != SQLITE_DONE)
	{
		ilog(L_MAIN, "services_db: certfp_add: %s",
		     sqlite3_errmsg(svc_db));
		return false;
	}

	struct svc_certfp *scf = rb_malloc(sizeof *scf);
	rb_strlcpy(scf->fingerprint, certfp, sizeof scf->fingerprint);
	scf->added_ts = now;
	rb_dlinkAdd(scf, &scf->node, &acct->certfps);
	/* Keep secondary O(1) certfp → account index in sync */
	if(svc_certfp_dict != NULL)
		rb_radixtree_add(svc_certfp_dict, scf->fingerprint, acct);
	return true;
}

bool
svc_db_certfp_delete(const char *account_name, const char *certfp)
{
	if(svc_db == NULL || account_name == NULL || certfp == NULL)
		return false;

	static const char sql[] =
	    "DELETE FROM svc_certfps WHERE account = ? AND fingerprint = ?;";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;
	sqlite3_bind_text(stmt, 1, account_name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, certfp,       -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if(rc != SQLITE_DONE)
		return false;

	struct svc_account *acct =
	    rb_radixtree_retrieve(svc_account_dict, account_name);
	if(acct == NULL)
		return true; /* already gone from memory */

	rb_dlink_node *ptr, *nptr;
	RB_DLINK_FOREACH_SAFE(ptr, nptr, acct->certfps.head)
	{
		struct svc_certfp *scf = ptr->data;
		if(rb_strcasecmp(scf->fingerprint, certfp) == 0)
		{
			/* Keep secondary O(1) certfp → account index in sync */
			if(svc_certfp_dict != NULL)
				rb_radixtree_delete(svc_certfp_dict,
				                    scf->fingerprint);
			rb_dlinkDestroy(ptr, &acct->certfps);
			rb_free(scf);
			break;
		}
	}
	return true;
}

/* -------------------------------------------------------------------------
 * Channel registration persistence
 * ---------------------------------------------------------------------- */

bool
svc_db_chanreg_load_all(void)
{
	static const char sql[] =
	    "SELECT channel, founder, successor, registered_ts, topic,"
	    "       topic_setter, topic_ts, flags, url, description,"
	    "       mlock_on, mlock_off, mlock_limit, mlock_key"
	    "  FROM svc_chanregs;";

	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
	{
		ilog(L_MAIN, "services_db: chanreg_load_all prepare: %s",
		     sqlite3_errmsg(svc_db));
		return false;
	}

	int loaded = 0;
	while(sqlite3_step(stmt) == SQLITE_ROW)
	{
		struct svc_chanreg *reg = rb_malloc(sizeof *reg);

		rb_strlcpy(reg->channel,
		           (const char *)sqlite3_column_text(stmt, 0),
		           sizeof reg->channel);
		rb_strlcpy(reg->founder,
		           (const char *)sqlite3_column_text(stmt, 1),
		           sizeof reg->founder);
		rb_strlcpy(reg->successor,
		           (const char *)sqlite3_column_text(stmt, 2),
		           sizeof reg->successor);
		reg->registered_ts = (time_t)sqlite3_column_int64(stmt, 3);
		rb_strlcpy(reg->topic,
		           (const char *)sqlite3_column_text(stmt, 4),
		           sizeof reg->topic);
		rb_strlcpy(reg->topic_setter,
		           (const char *)sqlite3_column_text(stmt, 5),
		           sizeof reg->topic_setter);
		reg->topic_ts   = (time_t)sqlite3_column_int64(stmt, 6);
		reg->flags      = (uint32_t)sqlite3_column_int64(stmt, 7);
		rb_strlcpy(reg->url,
		           (const char *)sqlite3_column_text(stmt, 8),
		           sizeof reg->url);
		rb_strlcpy(reg->description,
		           (const char *)sqlite3_column_text(stmt, 9),
		           sizeof reg->description);
		reg->mlock_on    = (uint32_t)sqlite3_column_int64(stmt, 10);
		reg->mlock_off   = (uint32_t)sqlite3_column_int64(stmt, 11);
		reg->mlock_limit = (int)sqlite3_column_int(stmt, 12);
		rb_strlcpy(reg->mlock_key,
		           (const char *)sqlite3_column_text(stmt, 13),
		           sizeof reg->mlock_key);
		reg->dirty = false;

		rb_radixtree_add(svc_chanreg_dict, reg->channel, reg);
		loaded++;
	}
	sqlite3_finalize(stmt);

	/* Load channel access entries */
	{
		static const char ca_sql[] =
		    "SELECT channel, entity, flags, setter, set_ts"
		    "  FROM svc_chanaccess;";
		sqlite3_stmt *cas;
		if(sqlite3_prepare_v2(svc_db, ca_sql, -1, &cas, NULL) == SQLITE_OK)
		{
			while(sqlite3_step(cas) == SQLITE_ROW)
			{
				const char *ch =
				    (const char *)sqlite3_column_text(cas, 0);
				struct svc_chanreg *reg =
				    rb_radixtree_retrieve(svc_chanreg_dict, ch);
				if(reg == NULL)
					continue;

				struct svc_chanaccess *ca =
				    rb_malloc(sizeof *ca);
				memset(ca, 0, sizeof *ca);

				rb_strlcpy(ca->entity,
				    (const char *)sqlite3_column_text(cas, 1),
				    sizeof ca->entity);
				ca->flags  = (uint32_t)sqlite3_column_int64(cas, 2);
				rb_strlcpy(ca->setter,
				    (const char *)sqlite3_column_text(cas, 3),
				    sizeof ca->setter);
				ca->set_ts = (time_t)sqlite3_column_int64(cas, 4);

				rb_dlinkAdd(ca, &ca->node, &reg->access);
			}
			sqlite3_finalize(cas);
		}
	}

	ilog(L_MAIN, "services_db: loaded %d channel registrations", loaded);
	return true;
}

bool
svc_db_chanreg_save(struct svc_chanreg *reg)
{
	if(svc_db == NULL || reg == NULL)
		return false;

	db_exec("BEGIN TRANSACTION;");

	{
		static const char sql[] =
		    "INSERT OR REPLACE INTO svc_chanregs"
		    "  (channel, founder, successor, registered_ts, topic,"
		    "   topic_setter, topic_ts, flags, url, description,"
		    "   mlock_on, mlock_off, mlock_limit, mlock_key)"
		    "  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
		sqlite3_stmt *stmt;
		if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		{
			db_exec("ROLLBACK;");
			return false;
		}
		sqlite3_bind_text (stmt,  1, reg->channel,      -1, SQLITE_STATIC);
		sqlite3_bind_text (stmt,  2, reg->founder,      -1, SQLITE_STATIC);
		sqlite3_bind_text (stmt,  3, reg->successor,    -1, SQLITE_STATIC);
		sqlite3_bind_int64(stmt,  4, (sqlite3_int64)reg->registered_ts);
		sqlite3_bind_text (stmt,  5, reg->topic,        -1, SQLITE_STATIC);
		sqlite3_bind_text (stmt,  6, reg->topic_setter, -1, SQLITE_STATIC);
		sqlite3_bind_int64(stmt,  7, (sqlite3_int64)reg->topic_ts);
		sqlite3_bind_int64(stmt,  8, (sqlite3_int64)reg->flags);
		sqlite3_bind_text (stmt,  9, reg->url,          -1, SQLITE_STATIC);
		sqlite3_bind_text (stmt, 10, reg->description,  -1, SQLITE_STATIC);
		sqlite3_bind_int64(stmt, 11, (sqlite3_int64)reg->mlock_on);
		sqlite3_bind_int64(stmt, 12, (sqlite3_int64)reg->mlock_off);
		sqlite3_bind_int  (stmt, 13, reg->mlock_limit);
		sqlite3_bind_text (stmt, 14, reg->mlock_key,    -1, SQLITE_STATIC);

		int rc = sqlite3_step(stmt);
		sqlite3_finalize(stmt);
		if(rc != SQLITE_DONE)
		{
			ilog(L_MAIN, "services_db: chanreg_save: %s",
			     sqlite3_errmsg(svc_db));
			db_exec("ROLLBACK;");
			return false;
		}
	}

	/* Re-sync access list */
	{
		static const char del_sql[] =
		    "DELETE FROM svc_chanaccess WHERE channel = ?;";
		sqlite3_stmt *ds;
		if(sqlite3_prepare_v2(svc_db, del_sql, -1, &ds, NULL) == SQLITE_OK)
		{
			sqlite3_bind_text(ds, 1, reg->channel, -1, SQLITE_STATIC);
			sqlite3_step(ds);
			sqlite3_finalize(ds);
		}

		static const char ins_sql[] =
		    "INSERT OR REPLACE INTO svc_chanaccess"
		    "  (channel, entity, flags, setter, set_ts)"
		    "  VALUES (?,?,?,?,?);";
		rb_dlink_node *ptr;
		RB_DLINK_FOREACH(ptr, reg->access.head)
		{
			struct svc_chanaccess *ca = ptr->data;
			sqlite3_stmt *is;
			if(sqlite3_prepare_v2(svc_db, ins_sql, -1, &is,
			                      NULL) == SQLITE_OK)
			{
				sqlite3_bind_text (is, 1, reg->channel, -1,
				                   SQLITE_STATIC);
				sqlite3_bind_text (is, 2, ca->entity,   -1,
				                   SQLITE_STATIC);
				sqlite3_bind_int64(is, 3,
				    (sqlite3_int64)ca->flags);
				sqlite3_bind_text (is, 4, ca->setter,   -1,
				                   SQLITE_STATIC);
				sqlite3_bind_int64(is, 5,
				    (sqlite3_int64)ca->set_ts);
				sqlite3_step(is);
				sqlite3_finalize(is);
			}
		}
	}

	db_exec("COMMIT;");
	/* Same split-mode dirty-flag logic as svc_db_account_save() */
	if(services.mode == SVCS_MODE_SPLIT) {
		if(!reg->dirty)
			services.dirty_count++;
		reg->dirty = true;
	} else {
		reg->dirty = false;
	}
	return true;
}

bool
svc_db_chanreg_delete(const char *channel)
{
	if(svc_db == NULL || channel == NULL)
		return false;

	static const char sql[] =
	    "DELETE FROM svc_chanregs WHERE channel = ?;";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;
	sqlite3_bind_text(stmt, 1, channel, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE);
}

/* -------------------------------------------------------------------------
 * Channel access persistence
 * ---------------------------------------------------------------------- */

bool
svc_db_chanaccess_add(const char *channel, struct svc_chanaccess *ca)
{
	if(svc_db == NULL || channel == NULL || ca == NULL)
		return false;

	static const char sql[] =
	    "INSERT OR REPLACE INTO svc_chanaccess"
	    "  (channel, entity, flags, setter, set_ts)"
	    "  VALUES (?,?,?,?,?);";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;

	sqlite3_bind_text (stmt, 1, channel,    -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt, 2, ca->entity, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, (sqlite3_int64)ca->flags);
	sqlite3_bind_text (stmt, 4, ca->setter, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 5, (sqlite3_int64)ca->set_ts);

	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE);
}

bool
svc_db_chanaccess_delete(const char *channel, const char *entity)
{
	if(svc_db == NULL || channel == NULL || entity == NULL)
		return false;

	static const char sql[] =
	    "DELETE FROM svc_chanaccess WHERE channel = ? AND entity = ?;";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;
	sqlite3_bind_text(stmt, 1, channel, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, entity,  -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE);
}

/* -------------------------------------------------------------------------
 * Memo persistence
 * ---------------------------------------------------------------------- */

bool
svc_db_memo_insert(struct svc_memo *memo)
{
	if(svc_db == NULL || memo == NULL)
		return false;

	static const char sql[] =
	    "INSERT INTO svc_memos"
	    "  (to_account, from_account, sent_ts, read, text)"
	    "  VALUES (?,?,?,?,?);";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;

	sqlite3_bind_text (stmt, 1, memo->to_account,   -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt, 2, memo->from_account, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, (sqlite3_int64)memo->sent_ts);
	sqlite3_bind_int  (stmt, 4, memo->read ? 1 : 0);
	sqlite3_bind_text (stmt, 5, memo->text,         -1, SQLITE_STATIC);

	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if(rc != SQLITE_DONE)
		return false;

	memo->id = (int)sqlite3_last_insert_rowid(svc_db);
	return true;
}

bool
svc_db_memo_mark_read(int id)
{
	if(svc_db == NULL)
		return false;

	static const char sql[] =
	    "UPDATE svc_memos SET read = 1 WHERE id = ?;";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;
	sqlite3_bind_int(stmt, 1, id);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE);
}

bool
svc_db_memo_delete(int id)
{
	if(svc_db == NULL)
		return false;

	static const char sql[] = "DELETE FROM svc_memos WHERE id = ?;";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;
	sqlite3_bind_int(stmt, 1, id);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE);
}

bool
svc_db_memo_load_for(const char *account, rb_dlink_list *out)
{
	if(svc_db == NULL || account == NULL || out == NULL)
		return false;

	static const char sql[] =
	    "SELECT id, to_account, from_account, sent_ts, read, text"
	    "  FROM svc_memos"
	    " WHERE to_account = ?"
	    " ORDER BY id ASC;";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;
	sqlite3_bind_text(stmt, 1, account, -1, SQLITE_STATIC);

	while(sqlite3_step(stmt) == SQLITE_ROW)
	{
		struct svc_memo *m = rb_malloc(sizeof *m);

		m->id   = sqlite3_column_int(stmt, 0);
		rb_strlcpy(m->to_account,
		           (const char *)sqlite3_column_text(stmt, 1),
		           sizeof m->to_account);
		rb_strlcpy(m->from_account,
		           (const char *)sqlite3_column_text(stmt, 2),
		           sizeof m->from_account);
		m->sent_ts = (time_t)sqlite3_column_int64(stmt, 3);
		m->read    = (sqlite3_column_int(stmt, 4) != 0);
		rb_strlcpy(m->text,
		           (const char *)sqlite3_column_text(stmt, 5),
		           sizeof m->text);

		rb_dlinkAddTail(m, &m->node, out);
	}
	sqlite3_finalize(stmt);
	return true;
}

/* -------------------------------------------------------------------------
 * HostServ vhost offers
 * ---------------------------------------------------------------------- */

bool
svc_db_vhost_offer_add(const char *vhost, const char *offered_by)
{
	if(svc_db == NULL || vhost == NULL || offered_by == NULL)
		return false;

	static const char sql[] =
	    "INSERT OR REPLACE INTO svc_vhost_offers"
	    "  (vhost, offered_by, offered_ts) VALUES (?,?,?);";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;
	sqlite3_bind_text (stmt, 1, vhost,      -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt, 2, offered_by, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, (sqlite3_int64)rb_current_time());
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE);
}

bool
svc_db_vhost_offer_delete(const char *vhost)
{
	if(svc_db == NULL || vhost == NULL)
		return false;

	static const char sql[] =
	    "DELETE FROM svc_vhost_offers WHERE vhost = ?;";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;
	sqlite3_bind_text(stmt, 1, vhost, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE);
}

bool
svc_db_vhost_offers_load(rb_dlink_list *out)
{
	if(svc_db == NULL || out == NULL)
		return false;

	static const char sql[] =
	    "SELECT vhost, offered_by, offered_ts FROM svc_vhost_offers;";
	sqlite3_stmt *stmt;
	if(sqlite3_prepare_v2(svc_db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;

	while(sqlite3_step(stmt) == SQLITE_ROW)
	{
		struct svc_vhost_offer *vo = rb_malloc(sizeof *vo);
		rb_strlcpy(vo->vhost,
		           (const char *)sqlite3_column_text(stmt, 0),
		           sizeof vo->vhost);
		rb_strlcpy(vo->offered_by,
		           (const char *)sqlite3_column_text(stmt, 1),
		           sizeof vo->offered_by);
		vo->offered_ts = (time_t)sqlite3_column_int64(stmt, 2);
		rb_dlinkAddTail(vo, &vo->node, out);
	}
	sqlite3_finalize(stmt);
	return true;
}

/* -------------------------------------------------------------------------
 * Dirty-record flush (called after netsplit resolution)
 * ---------------------------------------------------------------------- */

/*
 * Callback for rb_radixtree_foreach: save any account marked dirty.
 */
struct flush_cb_state {
	int count;
};

static int
flush_account_cb(const char *key, void *data, void *privdata)
{
	(void)key;
	struct svc_account *acct = data;
	struct flush_cb_state *st = privdata;

	if(acct->dirty)
	{
		if(svc_db_account_save(acct))
		{
			acct->dirty = false;
			st->count++;
		}
	}
	return 0;
}

static int
flush_chanreg_cb(const char *key, void *data, void *privdata)
{
	(void)key;
	struct svc_chanreg *reg = data;
	struct flush_cb_state *st = privdata;

	if(reg->dirty)
	{
		if(svc_db_chanreg_save(reg))
		{
			reg->dirty = false;
			st->count++;
		}
	}
	return 0;
}

int
svc_db_flush_dirty(void)
{
	if(svc_db == NULL)
		return 0;

	struct flush_cb_state st = { .count = 0 };

	/*
	 * Do NOT wrap with an outer BEGIN/COMMIT here.  svc_db_account_save()
	 * and svc_db_chanreg_save() each manage their own transaction
	 * internally.  SQLite does not support nested transactions via BEGIN;
	 * the outer BEGIN would succeed, then each inner BEGIN would silently
	 * fail, causing the inner COMMIT to commit the outer transaction
	 * prematurely and leaving subsequent saves without a transaction.
	 *
	 * Each save is individually atomic.  For throughput-sensitive paths
	 * (e.g. large post-split dirty flushes) callers should prefer the
	 * S2S SVCSREG/SVCSCHAN burst path which batches records via TCP
	 * send-queue coalescing rather than individual SQLite transactions.
	 */
	rb_radixtree_foreach(svc_account_dict, flush_account_cb, &st);
	rb_radixtree_foreach(svc_chanreg_dict, flush_chanreg_cb, &st);

	if(st.count > 0)
		ilog(L_MAIN, "services_db: flushed %d dirty records", st.count);

	return st.count;
}
