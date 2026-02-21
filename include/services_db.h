/*
 * include/services_db.h — Services SQLite persistence layer
 *
 * Uses a dedicated SQLite database (services.db) separate from bandb.
 * All tables are prefixed with svc_.  The DB is opened directly via the
 * SQLite3 amalgamation already present in bandb/sqlite3.c.
 *
 * On startup, svc_db_init() creates the schema if missing, then loads
 * all records into the in-memory radixtrees (svc_account_dict, etc.).
 * All write functions update both the in-memory store and the DB.
 *
 * Copyright (c) 2026 Ophion development team.  GPL v2.
 */

#ifndef OPHION_SERVICES_DB_H
#define OPHION_SERVICES_DB_H

#include "services.h"

/* Open/create the database.  path may be NULL to use services.db_path. */
bool svc_db_init(const char *path);
void svc_db_shutdown(void);

/* ---- Account persistence ---- */
bool svc_db_account_load_all(void);
bool svc_db_account_save(struct svc_account *acct);
bool svc_db_account_delete(const char *name);
bool svc_db_account_update_lastseen(struct svc_account *acct);

/* ---- Nick persistence ---- */
bool svc_db_nick_add(const char *nick, const char *account_name);
bool svc_db_nick_delete(const char *nick);

/* ---- Certificate fingerprint persistence ---- */
bool svc_db_certfp_add(const char *account_name, const char *certfp);
bool svc_db_certfp_delete(const char *account_name, const char *certfp);

/* ---- Channel registration persistence ---- */
bool svc_db_chanreg_load_all(void);
bool svc_db_chanreg_save(struct svc_chanreg *reg);
bool svc_db_chanreg_delete(const char *channel);

/* ---- Channel access persistence ---- */
bool svc_db_chanaccess_add(const char *channel, struct svc_chanaccess *ca);
bool svc_db_chanaccess_delete(const char *channel, const char *entity);

/* ---- Memo persistence ---- */
bool svc_db_memo_insert(struct svc_memo *memo);
bool svc_db_memo_mark_read(int id);
bool svc_db_memo_delete(int id);
bool svc_db_memo_load_for(const char *account, rb_dlink_list *out);

/* ---- HostServ vhost offers ---- */
bool svc_db_vhost_offer_add(const char *vhost, const char *offered_by);
bool svc_db_vhost_offer_delete(const char *vhost);
bool svc_db_vhost_offers_load(rb_dlink_list *out);

/* ---- Bulk dirty-record sync after netsplit resolution ---- */
int  svc_db_flush_dirty(void);   /* returns count of dirty records written */

#endif /* OPHION_SERVICES_DB_H */
