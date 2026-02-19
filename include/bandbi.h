#ifndef INCLUDED_bandbi_h
#define INCLUDED_bandbi_h

struct Client;	/* forward declaration for use in parameter lists */

void init_bandb(void);

typedef enum
{
	BANDB_KLINE,
	BANDB_DLINE,
	BANDB_XLINE,
	BANDB_RESV,
	BANDB_GAG,
	LAST_BANDB_TYPE
} bandb_type;

void bandb_add(bandb_type, struct Client *source_p, const char *mask1,
	       const char *mask2, const char *reason, const char *oper_reason, int perm);
void bandb_del(bandb_type, const char *mask1, const char *mask2);
void bandb_rehash_bans(void);
void bandb_rehash_gags(void);

/*
 * hook_data_bandb_gag - data passed to the "bandb_gag_restore" hook.
 *
 * Fired once per GAG entry when the bandb helper sends its GAG list in
 * response to the W command.  Hold == 0 means permanent.
 */
typedef struct
{
	const char *mask;	/* user@host pattern */
	const char *setter;	/* oper who placed the gag */
	time_t hold;		/* absolute expiry (0 = permanent) */
} hook_data_bandb_gag;

#endif
