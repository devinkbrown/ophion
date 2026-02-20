/*
 * conf_parser.c: Hand-written recursive-descent configuration parser.
 *
 * Replaces the flex/bison pair (ircd_lexer.l + ircd_parser.y) with a single,
 * dependency-free C file.  Grammar is identical to the original.
 *
 * Grammar:
 *   conf       : (block | loadmodule)*
 *   block      : STRING QSTRING? '{' block_item* '}' ';'
 *   block_item : STRING '=' itemlist ';'
 *   itemlist   : single (',' single)*
 *   single     : oneitem ('..' oneitem)?
 *   oneitem    : QSTRING | NUMBER | timespec | STRING
 *   timespec   : NUMBER STRING (NUMBER STRING)* NUMBER?
 *   loadmodule : 'loadmodule' QSTRING ';'
 *
 * Globals provided for s_conf.c compatibility:
 *   int  lineno        -- current line number
 *   char conffilebuf[] -- current filename
 *   char *current_file -- pointer into conffilebuf
 *   char yy_linebuf[]  -- last input line (for yyerror)
 *   char yytext[]      -- last token text (compat stub)
 *   int  yyparse(void) -- parse conf_fbfile_in
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WE_ARE_MEMORY_C
#include "stdinc.h"
#include "ircd_defs.h"
#include "defaults.h"
#include "client.h"
#include "logger.h"
#include "modules.h"
#include "newconf.h"
#include "s_conf.h"

/* -----------------------------------------------------------------------
 * Globals required by s_conf.c / newconf.c / yyerror()
 * --------------------------------------------------------------------- */
int   lineno       = 1;
char  conffilebuf[BUFSIZE + 1];
char *current_file = conffilebuf;
char  yy_linebuf[16384];
char  yytext[1024];          /* compat stub -- declared extern in s_conf.c */

/* -----------------------------------------------------------------------
 * Include stack
 * --------------------------------------------------------------------- */
#define MAX_INCLUDE_DEPTH 10

typedef struct {
	FILE *fp;
	int   lineno;
	char  filename[BUFSIZE];
	char  cur_line[16384];
	int   cur_line_len;
} inc_frame_t;

static inc_frame_t  inc_stack[MAX_INCLUDE_DEPTH];
static int          inc_depth    = 0;
static FILE        *cur_fp       = NULL;

/* Current-line buffer -- copied to yy_linebuf on each newline. */
static char cur_line[16384];
static int  cur_line_len = 0;

/* Four-character pushback. */
static int pushback[4];
static int pb_len = 0;

static int
rd_getc(void)
{
	int c = (pb_len > 0) ? (unsigned char)pushback[--pb_len] : fgetc(cur_fp);
	if (c == '\n') {
		cur_line[cur_line_len] = '\0';
		rb_strlcpy(yy_linebuf, cur_line, sizeof(yy_linebuf));
		cur_line_len = 0;
		lineno++;
	} else if (c != EOF) {
		if (cur_line_len < (int)sizeof(cur_line) - 1)
			cur_line[cur_line_len++] = (char)c;
	}
	return c;
}

static void
rd_ungetc(int c)
{
	if (c == EOF || pb_len >= (int)(sizeof(pushback)/sizeof(pushback[0])))
		return;
	pushback[pb_len++] = c;
	if (c == '\n') lineno--;
	else if (cur_line_len > 0) cur_line_len--;
}

static void
cf_push_include(const char *filename)
{
	FILE *fp;
	if (inc_depth >= MAX_INCLUDE_DEPTH) {
		conf_report_error("Includes nested too deeply (max %d)", MAX_INCLUDE_DEPTH);
		return;
	}
	fp = fopen(filename, "r");
	if (fp == NULL) {
		char alt[BUFSIZE];
		snprintf(alt, sizeof(alt), "%s%c%s",
		         ircd_paths[IRCD_PATH_ETC], RB_PATH_SEPARATOR, filename);
		fp = fopen(alt, "r");
		if (fp == NULL) {
			conf_report_error("Include %s: %s.", filename, strerror(errno));
			return;
		}
	}
	inc_stack[inc_depth].fp           = cur_fp;
	inc_stack[inc_depth].lineno       = lineno;
	inc_stack[inc_depth].cur_line_len = cur_line_len;
	memcpy(inc_stack[inc_depth].cur_line, cur_line, (size_t)cur_line_len);
	rb_strlcpy(inc_stack[inc_depth].filename, current_file,
	           sizeof(inc_stack[inc_depth].filename));
	inc_depth++;
	cur_fp       = fp;
	lineno       = 1;
	cur_line_len = 0;
	pb_len       = 0;
	rb_strlcpy(conffilebuf, filename, sizeof(conffilebuf));
	current_file = conffilebuf;
}

static int
cf_pop_include(void)
{
	if (inc_depth <= 0) return 0;
	fclose(cur_fp);
	inc_depth--;
	cur_fp       = inc_stack[inc_depth].fp;
	lineno       = inc_stack[inc_depth].lineno;
	cur_line_len = inc_stack[inc_depth].cur_line_len;
	memcpy(cur_line, inc_stack[inc_depth].cur_line, (size_t)cur_line_len);
	rb_strlcpy(conffilebuf, inc_stack[inc_depth].filename, sizeof(conffilebuf));
	current_file = conffilebuf;
	return 1;
}

/* -----------------------------------------------------------------------
 * Time / size unit table
 * --------------------------------------------------------------------- */
static const struct { const char *name, *plural; time_t val; } ircd_times[] = {
	{"second",    "seconds",     1},
	{"minute",    "minutes",     60},
	{"hour",      "hours",       3600},
	{"day",       "days",        86400},
	{"week",      "weeks",       86400*7},
	{"fortnight", "fortnights",  86400*14},
	{"month",     "months",      86400*28},
	{"year",      "years",       86400*365},
	{"byte",      "bytes",       1},
	{"kb",        NULL,          1024},
	{"kbyte",     "kbytes",      1024},
	{"kilobyte",  "kilobytes",   1024},
	{"mb",        NULL,          1024*1024},
	{"mbyte",     "mbytes",      1024*1024},
	{"megabyte",  "megabytes",   1024*1024},
	{NULL, NULL, 0},
};

static time_t
conf_find_time(const char *name)
{
	for (int i = 0; ircd_times[i].name; i++)
		if (rb_strcasecmp(ircd_times[i].name, name) == 0 ||
		    (ircd_times[i].plural &&
		     rb_strcasecmp(ircd_times[i].plural, name) == 0))
			return ircd_times[i].val;
	return 0;
}

/* -----------------------------------------------------------------------
 * Yes/no table
 * --------------------------------------------------------------------- */
static const struct { const char *word; int val; } yesno_table[] = {
	{"yes",1},{"no",0},{"true",1},{"false",0},{"on",1},{"off",0},{NULL,0},
};
static int
conf_get_yesno(const char *str)
{
	for (int i = 0; yesno_table[i].word; i++)
		if (rb_strcasecmp(yesno_table[i].word, str) == 0)
			return yesno_table[i].val;
	return -1;
}

/* -----------------------------------------------------------------------
 * Tokenizer
 * --------------------------------------------------------------------- */
typedef enum {
	TOK_EOF=0, TOK_QSTRING, TOK_STRING, TOK_NUMBER,
	TOK_LOADMODULE, TOK_TWODOTS,
	TOK_LBRACE, TOK_RBRACE, TOK_SEMI, TOK_EQ, TOK_COMMA, TOK_OTHER,
} tok_t;

typedef struct { tok_t type; char str[1024]; int num; } token;

static token cur, peeked;
static int   have_peeked = 0;

static void skip_block_comment(void)
{
	int c, prev = 0;
	while ((c = rd_getc()) != EOF) {
		if (prev == '*' && c == '/') return;
		prev = c;
	}
	conf_report_error("EOF in block comment");
}

static void read_include_directive(void)
{
	int  c;
	char fname[BUFSIZE];
	int  fi = 0;
	char close_ch;

	while ((c = rd_getc()) != EOF && c != '\n' && isspace((unsigned char)c))
		;
	if      (c == '<') close_ch = '>';
	else if (c == '"') close_ch = '"';
	else {
		conf_report_error(".include requires <file> or \"file\"");
		while (c != EOF && c != '\n') c = rd_getc();
		return;
	}
	while ((c = rd_getc()) != EOF && c != close_ch && c != '\n')
		if (fi < (int)sizeof(fname) - 1) fname[fi++] = (char)c;
	fname[fi] = '\0';
	cf_push_include(fname);
}

static void
read_raw_token(token *t)
{
	int c;
retry:
	do { c = rd_getc(); } while (c != EOF && c != '\n' && isspace((unsigned char)c));
	if (c == '\n') goto retry;
	if (c == EOF) {
		if (cf_pop_include()) goto retry;
		t->type = TOK_EOF; return;
	}
	/* Hash comment */
	if (c == '#') {
		/* Peek for #include warning */
		char tmp[9] = ""; int ti = 0;
		int ch;
		while (ti < 7 && (ch = rd_getc()) != EOF && ch != '\n')
			tmp[ti++] = (char)tolower((unsigned char)ch);
		tmp[ti] = '\0';
		if (strncmp(tmp, "include", 7) == 0)
			conf_report_error("Use '.include' instead of '#include'");
		while (ch != EOF && ch != '\n') ch = rd_getc();
		goto retry;
	}
	/* Block comment */
	if (c == '/') {
		int next = rd_getc();
		if (next == '*') { skip_block_comment(); goto retry; }
		rd_ungetc(next);
		t->type = TOK_OTHER; t->str[0] = '/'; t->str[1] = '\0'; return;
	}
	/* Dot -- either '..', '.include', or lone '.' */
	if (c == '.') {
		int next = rd_getc();
		if (next == '.') { t->type = TOK_TWODOTS; return; }
		rd_ungetc(next);
		/* Try reading .include keyword */
		char word[BUFSIZE]; int wi = 0;
		word[wi++] = '.';
		int ch;
		while ((ch = rd_getc()) != EOF && (isalnum((unsigned char)ch) || ch == '_'))
			if (wi < (int)sizeof(word)-1) word[wi++] = (char)tolower((unsigned char)ch);
		word[wi] = '\0';
		if (ch != EOF) rd_ungetc(ch);
		if (strcmp(word, ".include") == 0) { read_include_directive(); goto retry; }
		t->type = TOK_OTHER; t->str[0] = '.'; t->str[1] = '\0'; return;
	}
	/* Integer */
	if (isdigit((unsigned char)c)) {
		int n = c - '0';
		while ((c = rd_getc()) != EOF && isdigit((unsigned char)c)) n = n*10 + (c-'0');
		if (c != EOF) rd_ungetc(c);
		t->type = TOK_NUMBER; t->num = n;
		snprintf(t->str, sizeof(t->str), "%d", n);
		return;
	}
	/* Quoted string */
	if (c == '"') {
		int qi = 0;
		while ((c = rd_getc()) != EOF && c != '"' && c != '\n') {
			if (c == '\\') { int e = rd_getc(); if (e == EOF) break; c = e; }
			if (qi < 1023) t->str[qi++] = (char)c;
		}
		if (c != '"') ilog(L_MAIN, "Unterminated quoted string, line %d", lineno);
		t->str[qi] = '\0'; t->type = TOK_QSTRING; return;
	}
	/* Identifier (case-folded to lowercase) */
	if (isalpha((unsigned char)c) || c == '_' || c == '~' || c == ':') {
		int si = 0;
		t->str[si++] = (char)tolower((unsigned char)c);
		while ((c = rd_getc()) != EOF && (isalnum((unsigned char)c) || c == '_' || c == ':'))
			if (si < 1023) t->str[si++] = (char)tolower((unsigned char)c);
		if (c != EOF) rd_ungetc(c);
		t->str[si] = '\0';
		t->type = (strcmp(t->str, "loadmodule") == 0) ? TOK_LOADMODULE : TOK_STRING;
		return;
	}
	/* Single-char punctuation */
	t->str[0] = (char)c; t->str[1] = '\0';
	switch (c) {
	case '{': t->type = TOK_LBRACE; break;
	case '}': t->type = TOK_RBRACE; break;
	case ';': t->type = TOK_SEMI;   break;
	case '=': t->type = TOK_EQ;     break;
	case ',': t->type = TOK_COMMA;  break;
	default:  t->type = TOK_OTHER;  break;
	}
}

static void
advance(void)
{
	if (have_peeked) { cur = peeked; have_peeked = 0; }
	else             read_raw_token(&cur);
	rb_strlcpy(yytext, cur.str, sizeof(yytext));
}


/* -----------------------------------------------------------------------
 * Parameter list helpers
 * --------------------------------------------------------------------- */
static conf_parm_t *cur_list = NULL;

static void
free_cur_list(conf_parm_t *list)
{
	if (!list) return;
	if (list->type == CF_STRING || list->type == CF_QSTRING) rb_free(list->v.string);
	else if (list->type == CF_FLIST) free_cur_list(list->v.list);
	if (list->next) free_cur_list(list->next);
	rb_free(list);
}

static void
add_cur_list_node(conf_parm_t *p)
{
	if (!cur_list) {
		cur_list = rb_malloc(sizeof(*cur_list));
		cur_list->type   = CF_FLIST;
		cur_list->next   = NULL;
		cur_list->v.list = p;
	} else {
		p->next          = cur_list->v.list;
		cur_list->v.list = p;
	}
}

static void
add_cur_list(int type, const char *str, int number)
{
	conf_parm_t *p = rb_malloc(sizeof(*p));
	p->next = NULL;
	p->type = type;
	switch (type) {
	case CF_INT: case CF_TIME: case CF_YESNO: p->v.number = number; break;
	case CF_STRING: case CF_QSTRING:          p->v.string = rb_strdup(str); break;
	}
	add_cur_list_node(p);
}

/* -----------------------------------------------------------------------
 * Recursive descent parser
 * --------------------------------------------------------------------- */
static void parse_block(void);
static void parse_block_item(void);
static void parse_itemlist(void);
static void parse_single(void);
static conf_parm_t *parse_oneitem(void);
static time_t parse_timespec(int first_n);

static void skip_to_semi(void)
{
	while (cur.type != TOK_SEMI && cur.type != TOK_EOF) advance();
	if (cur.type == TOK_SEMI) advance();
}

static void
parse_conf(void)
{
	advance();
	while (cur.type != TOK_EOF) {
		if (cur.type == TOK_LOADMODULE) {
			advance();
			if (cur.type != TOK_QSTRING) {
				conf_report_error("Expected filename after 'loadmodule'");
				skip_to_semi(); continue;
			}
			char *bn = rb_basename(cur.str);
			if (findmodule_byname(bn) == NULL)
				load_one_module(cur.str, MAPI_ORIGIN_EXTENSION, 0);
			rb_free(bn);
			advance();
			if (cur.type == TOK_SEMI) advance();
		} else if (cur.type == TOK_STRING) {
			parse_block();
		} else {
			conf_report_error("Unexpected token '%s' at top level", cur.str);
			advance();
		}
	}
}

static void
parse_block(void)
{
	char name[1024], label[1024];
	rb_strlcpy(name, cur.str, sizeof(name));
	advance();

	label[0] = '\0';
	if (cur.type == TOK_QSTRING || cur.type == TOK_STRING) {
		rb_strlcpy(label, cur.str, sizeof(label));
		advance();
	}

	if (cur.type != TOK_LBRACE) {
		conf_report_error("Expected '{' in block '%s', got '%s'", name, cur.str);
		while (cur.type != TOK_RBRACE && cur.type != TOK_EOF) advance();
		if (cur.type == TOK_RBRACE) advance();
		if (cur.type == TOK_SEMI)   advance();
		return;
	}
	advance();

	conf_start_block(name, label[0] ? label : NULL);

	while (cur.type != TOK_RBRACE && cur.type != TOK_EOF) {
		if (cur.type == TOK_STRING)
			parse_block_item();
		else {
			conf_report_error("Expected item or '}' in '%s', got '%s'", name, cur.str);
			advance();
		}
	}
	if (cur.type == TOK_RBRACE) advance();
	if (cur.type == TOK_SEMI)   advance();
	if (conf_cur_block) conf_end_block(conf_cur_block);
}

static void
parse_block_item(void)
{
	char key[1024];
	rb_strlcpy(key, cur.str, sizeof(key));
	advance();

	if (cur.type != TOK_EQ) {
		conf_report_error("Expected '=' after '%s'", key);
		skip_to_semi(); return;
	}
	advance();

	parse_itemlist();

	if (cur.type == TOK_SEMI) advance();
	else conf_report_error("Missing ';' after value for '%s'", key);

	if (conf_cur_block) conf_call_set(conf_cur_block, key, cur_list);
	if (cur_list) { free_cur_list(cur_list); cur_list = NULL; }
}

static void parse_itemlist(void)
{
	parse_single();
	while (cur.type == TOK_COMMA) { advance(); parse_single(); }
}

static void
parse_single(void)
{
	conf_parm_t *item1 = parse_oneitem();
	if (!item1) return;

	if (cur.type == TOK_TWODOTS) {
		advance();
		conf_parm_t *item2 = parse_oneitem();
		if (!item2) { add_cur_list_node(item1); return; }
		if (item1->type != CF_INT || item2->type != CF_INT) {
			conf_report_error("Both sides of '..' must be integers");
			rb_free(item1); rb_free(item2); return;
		}
		for (int i = item1->v.number; i <= item2->v.number; i++)
			add_cur_list(CF_INT, NULL, i);
		rb_free(item1); rb_free(item2);
	} else {
		add_cur_list_node(item1);
	}
}

static conf_parm_t *
parse_oneitem(void)
{
	conf_parm_t *p = rb_malloc(sizeof(*p));
	p->next = NULL;

	if (cur.type == TOK_QSTRING) {
		p->type = CF_QSTRING; p->v.string = rb_strdup(cur.str); advance(); return p;
	}
	if (cur.type == TOK_NUMBER) {
		int n = cur.num; advance();
		if (cur.type == TOK_STRING && conf_find_time(cur.str) != 0) {
			p->type = CF_TIME; p->v.number = (int)parse_timespec(n); return p;
		}
		p->type = CF_INT; p->v.number = n; return p;
	}
	if (cur.type == TOK_STRING) {
		int yn = conf_get_yesno(cur.str);
		if (yn >= 0) { p->type = CF_YESNO; p->v.number = yn; }
		else         { p->type = CF_STRING; p->v.string = rb_strdup(cur.str); }
		advance(); return p;
	}
	conf_report_error("Unexpected token '%s' in value", cur.str);
	rb_free(p); return NULL;
}

/* Called after first NUMBER n consumed; cur holds the unit STRING. */
static time_t
parse_timespec(int first_n)
{
	time_t total = (time_t)first_n * conf_find_time(cur.str);
	advance();  /* consume unit */

	while (cur.type == TOK_NUMBER) {
		int    n2 = cur.num; advance();
		if (cur.type == TOK_STRING) {
			time_t u2 = conf_find_time(cur.str);
			if (u2) { total += (time_t)n2 * u2; advance(); continue; }
			total += n2;  /* n2 is bare addend; leave cur for caller */
		} else {
			total += n2;  /* timespec number rule */
		}
		break;
	}
	return total;
}

/* -----------------------------------------------------------------------
 * Public entry point: yyparse() -- called from s_conf.c
 * --------------------------------------------------------------------- */
int
yyparse(void)
{
	cur_list    = NULL;
	have_peeked = 0;
	pb_len      = 0;
	cur_line_len = 0;
	cur_fp      = conf_fbfile_in;
	current_file = conffilebuf;
	parse_conf();
	return 0;
}
