/* src/rsdb_sqlite.h
 *   Contains the code for the sqlite database backend.
 *
 * Copyright (C) 2003-2006 Lee Hardy <leeh@leeh.co.uk>
 * Copyright (C) 2003-2006 ircd-ratbox development team
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1.Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * 2.Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3.The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
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
#include "stdinc.h"
#include "rsdb.h"

#include <sqlite3.h>

struct sqlite3 *rb_bandb;

rsdb_error_cb *error_cb;

static void
mlog(const char *errstr, ...)
{
	if(error_cb != NULL)
	{
		char buf[256];
		va_list ap;
		va_start(ap, errstr);
		vsnprintf(buf, sizeof(buf), errstr, ap);
		va_end(ap);
		error_cb(buf);
	}
	else
		exit(1);
}

int
rsdb_init(rsdb_error_cb * ecb)
{
	const char *bandb_dbpath_env;
	char dbpath[PATH_MAX];
	char errbuf[128];
	error_cb = ecb;

	/* try a path from the environment first, useful for basedir overrides */
	bandb_dbpath_env = getenv("BANDB_DBPATH");

	if(bandb_dbpath_env != NULL)
		rb_strlcpy(dbpath, bandb_dbpath_env, sizeof(dbpath));
	else
		rb_strlcpy(dbpath, DBPATH, sizeof(dbpath));

	if(sqlite3_open(dbpath, &rb_bandb) != SQLITE_OK)
	{
		snprintf(errbuf, sizeof(errbuf), "Unable to open sqlite database: %s",
			    sqlite3_errmsg(rb_bandb));
		mlog(errbuf);
		return -1;
	}
	if(access(dbpath, W_OK))
	{
		snprintf(errbuf, sizeof(errbuf),  "Unable to open sqlite database for write: %s", strerror(errno));
		mlog(errbuf);
		return -1;
	}

	/*
	 * Performance and reliability tuning.
	 *
	 * WAL journal mode: writers don't block readers, and readers don't
	 * block writers.  Much faster than the default DELETE mode for our
	 * write-then-list pattern.
	 *
	 * synchronous=NORMAL: flush at checkpoints rather than every commit.
	 * Safe enough for a ban database; the worst case is losing the last
	 * few bans on an unclean shutdown, which is acceptable.
	 *
	 * busy_timeout: let SQLite wait up to 5 s before returning
	 * SQLITE_BUSY, replacing the old manual 5×500 ms retry loops.
	 *
	 * cache_size: 8 MiB page cache avoids repeated disk reads for
	 * list-all-bans operations.
	 *
	 * mmap_size: 32 MiB memory-mapped I/O for faster sequential reads.
	 *
	 * temp_store=MEMORY: keep temporary tables in RAM.
	 */
	sqlite3_exec(rb_bandb, "PRAGMA journal_mode=WAL",   NULL, NULL, NULL);
	sqlite3_exec(rb_bandb, "PRAGMA synchronous=NORMAL", NULL, NULL, NULL);
	sqlite3_exec(rb_bandb, "PRAGMA busy_timeout=5000",  NULL, NULL, NULL);
	sqlite3_exec(rb_bandb, "PRAGMA cache_size=-8192",   NULL, NULL, NULL);
	sqlite3_exec(rb_bandb, "PRAGMA mmap_size=33554432", NULL, NULL, NULL);
	sqlite3_exec(rb_bandb, "PRAGMA temp_store=MEMORY",  NULL, NULL, NULL);

	return 0;
}

void
rsdb_shutdown(void)
{
	if(rb_bandb)
		sqlite3_close(rb_bandb);
}

const char *
rsdb_quote(const char *src)
{
	static char buf[BUFSIZE * 4];
	char *p = buf;

	/* cheap and dirty length check.. */
	if(strlen(src) >= (sizeof(buf) / 2))
		return NULL;

	while(*src)
	{
		if(*src == '\'')
			*p++ = '\'';

		*p++ = *src++;
	}

	*p = '\0';
	return buf;
}

static int
rsdb_callback_func(void *cbfunc, int argc, char **argv, char **colnames)
{
	rsdb_callback cb = (rsdb_callback)((uintptr_t)cbfunc);
	(cb) (argc, (const char **)(void *)argv);
	return 0;
}

void
rsdb_exec(rsdb_callback cb, const char *format, ...)
{
	static char buf[BUFSIZE * 4];
	va_list args;
	char *errmsg;
	unsigned int i;

	va_start(args, format);
	i = rs_vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	if(i >= sizeof(buf))
	{
		mlog("fatal error: length problem with compiling sql");
	}

	/* busy_timeout (set in rsdb_init) handles SQLITE_BUSY waits
	 * automatically; no manual retry loop is needed here. */
	if((i = sqlite3_exec(rb_bandb, buf, (cb ? rsdb_callback_func : NULL), (void *)((uintptr_t)cb), &errmsg)))
	{
		mlog("fatal error: problem with db file: %s", errmsg);
	}
}

/*
 * rsdb_exec_fetch / rsdb_exec_fetch_end
 *
 * The old implementation used sqlite3_get_table(), which is deprecated
 * since SQLite 3.x and loads the entire result set into a single flat
 * array managed by SQLite's allocator.  We now use sqlite3_prepare_v2()
 * + sqlite3_step() with rb_strdup()'d column values so that:
 *
 *   1. The result data is owned by us (freed in rsdb_exec_fetch_end).
 *   2. We iterate the result set one row at a time, avoiding the
 *      two-pass overhead of sqlite3_get_table().
 *   3. The deprecated API is no longer used.
 *
 * The rsdb_table layout seen by callers is unchanged:
 *   table.row[i][j]  — column j of data row i (NUL-terminated string).
 */
void
rsdb_exec_fetch(struct rsdb_table *table, const char *format, ...)
{
	static char buf[BUFSIZE * 4];
	va_list args;
	unsigned int fmtlen;
	sqlite3_stmt *stmt;
	int rc;
	int ncol;
	int capacity;

	va_start(args, format);
	fmtlen = rs_vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	table->row       = NULL;
	table->row_count = 0;
	table->col_count = 0;
	table->arg       = NULL;

	if(fmtlen >= sizeof(buf))
	{
		mlog("fatal error: length problem with compiling sql");
		return;
	}

	if(sqlite3_prepare_v2(rb_bandb, buf, -1, &stmt, NULL) != SQLITE_OK)
	{
		mlog("fatal error: sqlite3_prepare_v2 failed: %s",
		     sqlite3_errmsg(rb_bandb));
		return;
	}

	ncol             = sqlite3_column_count(stmt);
	table->col_count = ncol;

	capacity  = 16;
	table->row = rb_malloc(sizeof(char **) * capacity);

	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		int j;
		char **row;

		if(table->row_count >= capacity)
		{
			capacity *= 2;
			table->row = rb_realloc(table->row, sizeof(char **) * capacity);
		}

		row = rb_malloc(sizeof(char *) * ncol);
		for(j = 0; j < ncol; j++)
		{
			const char *val = (const char *)sqlite3_column_text(stmt, j);
			row[j] = rb_strdup(val ? val : "");
		}
		table->row[table->row_count++] = row;
	}

	sqlite3_finalize(stmt);

	if(rc != SQLITE_DONE)
	{
		mlog("fatal error: sqlite3_step failed: %s",
		     sqlite3_errmsg(rb_bandb));
	}

	if(table->row_count == 0)
	{
		rb_free(table->row);
		table->row = NULL;
	}
}

void
rsdb_exec_fetch_end(struct rsdb_table *table)
{
	int i, j;

	for(i = 0; i < table->row_count; i++)
	{
		for(j = 0; j < table->col_count; j++)
			rb_free(table->row[i][j]);
		rb_free(table->row[i]);
	}
	rb_free(table->row);

	table->row = NULL;
	/* row_count is intentionally left intact: callers (e.g. check_schema)
	 * inspect it after this call to decide whether a row was found. */
}

void
rsdb_transaction(rsdb_transtype type)
{
	if(type == RSDB_TRANS_START)
		rsdb_exec(NULL, "BEGIN TRANSACTION");
	else if(type == RSDB_TRANS_END)
		rsdb_exec(NULL, "COMMIT TRANSACTION");
}
