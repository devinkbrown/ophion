/*
 * ophion: a slightly less ancient ircd.
 * rb_sendbuf.h: Zero-copy chunk-based outgoing send queue.
 *
 * Two chunk types share a single ordered queue:
 *
 *   SENDBUF_CHUNK_LINE  — a reference-counted pointer into a shared
 *     buf_line_t (formatted IRC message).  No byte copy: the buf_line_t
 *     is kept alive by incrementing its refcount; the chunk owns that
 *     reference and releases it via rb_linebuf_unref() when the bytes
 *     are fully sent.
 *
 *   SENDBUF_CHUNK_BLOCK — an owned 4 KiB byte block for raw writes
 *     (e.g. SSL handshake data, PASS/SERVER lines, or future raw-byte
 *     paths).  Multiple consecutive rb_sendbuf_write() calls are packed
 *     into the same tail block before a new one is allocated.
 *
 * For the dominant fan-out workload (channel message → N clients):
 *   Old path: N × memcpy(~512 B) into block queue   ≈ 256 KB copied
 *   New path: N × refcount++ + chunk alloc           ≈ 0 B copied
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef RB_LIB_H
# error "Do not include rb_sendbuf.h directly; include rb_lib.h"
#endif

#ifndef RB_SENDBUF_H
#define RB_SENDBUF_H

/* ---- types --------------------------------------------------------------- */

/* Byte block for raw data and SSL paths. */
#define RB_SENDBUF_BLOCK_SIZE  4096

typedef struct rb_sendbuf_block
{
	char     buf[RB_SENDBUF_BLOCK_SIZE];
	uint16_t wpos;   /* next write offset; buf[0..wpos) contains data */
} rb_sendbuf_block_t;

/* Chunk type discriminator. */
#define SENDBUF_CHUNK_LINE  0   /* shared buf_line_t reference (zero-copy) */
#define SENDBUF_CHUNK_BLOCK 1   /* owned rb_sendbuf_block_t                */

/*
 * Unified queue entry.  rpos tracks how many bytes of this chunk have
 * already been sent (for partial-write recovery).
 *
 * LINE:  data lives at line->buf + rpos, total = line->len bytes.
 * BLOCK: data lives at block->buf + rpos, total = block->wpos bytes.
 */
typedef struct rb_sendbuf_chunk
{
	uint8_t  type;
	uint16_t rpos;   /* bytes consumed from this chunk so far */
	union
	{
		buf_line_t         *line;    /* SENDBUF_CHUNK_LINE  */
		rb_sendbuf_block_t *block;   /* SENDBUF_CHUNK_BLOCK */
	};
} rb_sendbuf_chunk_t;

/* The send queue itself.  A zero-initialised rb_sendbuf_t is valid (empty).
 * rb_malloc() already zeros, so no explicit init call is needed when the
 * struct is embedded in a zero-initialised LocalUser. */
typedef struct rb_sendbuf
{
	rb_dlink_list chunks;  /* ordered list of rb_sendbuf_chunk_t */
	size_t        len;     /* total queued bytes across all chunks */
} rb_sendbuf_t;

#define rb_sendbuf_len(sb)  ((sb)->len)

/* ---- API ----------------------------------------------------------------- */

void    rb_sendbuf_init(size_t heap_size);
void    rb_sendbuf_donebuf(rb_sendbuf_t *sb);

/* Append raw bytes (copied into block storage). */
int     rb_sendbuf_write(rb_sendbuf_t *sb, const void *data, size_t len);

/* Zero-copy: enqueue all terminated lines from a temporary buf_head_t by
 * taking a reference on each buf_line_t.  The caller may free the
 * buf_head_t immediately after; the bytes remain accessible via the refs. */
int     rb_sendbuf_write_linebuf(rb_sendbuf_t *sb, buf_head_t *linebuf);

/* Flush as much as possible to socket F.
 * Returns bytes written (> 0), 0 on EOF, or -1 with errno set on error. */
ssize_t rb_sendbuf_flush(rb_sendbuf_t *sb, rb_fde_t *F);

#endif /* RB_SENDBUF_H */
