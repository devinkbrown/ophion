/*
 * ophion: a slightly less ancient ircd.
 * rb_sendbuf.h: Byte-block send queue, replacing per-message buf_head_t
 *               for outgoing data.
 *
 * Instead of allocating one buf_line_t (~1 KB) per outgoing message, bytes
 * are packed into 4 KB blocks.  writev() is then called with at most
 * ceil(queued / BLOCK) segments – typically 1-3 – rather than one iovec
 * per message.  For a 500-member channel receiving 10 msg/s this reduces
 * writev segment count by ~100x and eliminates per-message heap allocations
 * for the send path.
 *
 * The receive path (rb_linebuf_parse / rb_linebuf_get) is unchanged.
 */

#ifndef RB_LIB_H
# error "Do not include rb_sendbuf.h directly; include rb_lib.h"
#endif

#ifndef RB_SENDBUF_H
#define RB_SENDBUF_H

/* Size of each backing block.  Must be a multiple of the largest IRC line
 * (LINEBUF_SIZE + CRLF = 1024 bytes), and a power-of-two is convenient for
 * alignment.  4 KB == one memory page. */
#define RB_SENDBUF_BLOCK_SIZE   4096

typedef struct rb_sendbuf_block
{
	char     buf[RB_SENDBUF_BLOCK_SIZE];
	uint16_t rpos;   /* read offset within buf  */
	uint16_t wpos;   /* write offset within buf */
} rb_sendbuf_block_t;

typedef struct rb_sendbuf
{
	rb_dlink_list blocks;    /* ordered list of rb_sendbuf_block_t */
	size_t        len;       /* total queued bytes across all blocks */
} rb_sendbuf_t;

/* Zero-initialised rb_sendbuf_t is a valid empty queue (len==0, blocks empty).
 * rb_malloc() already zeros, so no explicit newbuf call is needed when the
 * struct is embedded in a zero-initialised LocalUser. */

#define rb_sendbuf_len(sb)   ((sb)->len)

void    rb_sendbuf_init(size_t heap_size);
void    rb_sendbuf_donebuf(rb_sendbuf_t *sb);
int     rb_sendbuf_write(rb_sendbuf_t *sb, const void *data, size_t len);

/* Copy all lines from a (temporary) buf_head_t formatting buffer into sb.
 * Used by _send_linebuf() to transfer a formatted message to the client's
 * persistent send queue without keeping the buf_head_t alive. */
int     rb_sendbuf_write_linebuf(rb_sendbuf_t *sb, buf_head_t *linebuf);

ssize_t rb_sendbuf_flush(rb_sendbuf_t *sb, rb_fde_t *F);

#endif /* RB_SENDBUF_H */
