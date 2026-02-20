/*
 * ophion: a slightly less ancient ircd.
 * sendbuf.c: Byte-block send queue implementation.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <librb_config.h>
#include <rb_lib.h>
#include <commio-int.h>

static rb_bh *rb_sendbuf_heap;

void
rb_sendbuf_init(size_t heap_size)
{
	rb_sendbuf_heap = rb_bh_create(sizeof(rb_sendbuf_block_t), heap_size,
	                                "librb_sendbuf_heap");
}

/* Free all blocks and reset the queue to empty. */
void
rb_sendbuf_donebuf(rb_sendbuf_t *sb)
{
	while(sb->blocks.head != NULL)
	{
		rb_dlink_node *node = sb->blocks.head;
		rb_sendbuf_block_t *blk = node->data;
		rb_dlinkDestroy(node, &sb->blocks);
		rb_bh_free(rb_sendbuf_heap, blk);
	}
	sb->len = 0;
}

/* Append len bytes from data to the send queue, allocating blocks as needed.
 * Returns 0 on success, -1 on allocation failure. */
int
rb_sendbuf_write(rb_sendbuf_t *sb, const void *data, size_t len)
{
	const char *ptr = data;
	size_t remaining = len;

	while(remaining > 0)
	{
		rb_sendbuf_block_t *blk = NULL;

		/* Reuse the tail block if it has space. */
		if(sb->blocks.tail != NULL)
		{
			blk = sb->blocks.tail->data;
			if(blk->wpos == RB_SENDBUF_BLOCK_SIZE)
				blk = NULL;
		}

		if(blk == NULL)
		{
			blk = rb_bh_alloc(rb_sendbuf_heap);
			if(rb_unlikely(blk == NULL))
				return -1;
			blk->rpos = 0;
			blk->wpos = 0;
			rb_dlinkAddTailAlloc(blk, &sb->blocks);
		}

		size_t space = RB_SENDBUF_BLOCK_SIZE - blk->wpos;
		size_t copy  = remaining < space ? remaining : space;
		memcpy(blk->buf + blk->wpos, ptr, copy);
		blk->wpos  += (uint16_t)copy;
		ptr        += copy;
		remaining  -= copy;
		sb->len    += copy;
	}

	return 0;
}

/* Copy all lines from a temporary buf_head_t into sb.
 * Called by _send_linebuf() in ircd/send.c. */
int
rb_sendbuf_write_linebuf(rb_sendbuf_t *sb, buf_head_t *linebuf)
{
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, linebuf->list.head)
	{
		buf_line_t *line = ptr->data;
		if(rb_sendbuf_write(sb, line->buf, line->len) < 0)
			return -1;
	}
	return 0;
}

/* Attempt to flush queued bytes to socket F.
 *
 * Non-SSL: builds an iovec over all blocks and calls writev(), then
 *   advances/frees consumed blocks.
 * SSL / no writev: writes the first contiguous block segment only.
 *
 * Returns bytes written on success, 0 on EOF, -1 with errno set on error
 * (EWOULDBLOCK if nothing to write). */
ssize_t
rb_sendbuf_flush(rb_sendbuf_t *sb, rb_fde_t *F)
{
	if(sb->len == 0)
	{
		errno = EWOULDBLOCK;
		return -1;
	}

#ifdef HAVE_WRITEV
	if(!rb_fd_ssl(F))
	{
		struct rb_iovec vec[RB_UIO_MAXIOV];
		int nvec = 0;
		rb_dlink_node *ptr;
		ssize_t total;

		RB_DLINK_FOREACH(ptr, sb->blocks.head)
		{
			rb_sendbuf_block_t *blk = ptr->data;
			size_t avail = blk->wpos - blk->rpos;
			if(avail == 0)
				continue;
			vec[nvec].iov_base = blk->buf + blk->rpos;
			vec[nvec].iov_len  = avail;
			if(++nvec == RB_UIO_MAXIOV)
				break;
		}

		if(nvec == 0)
		{
			errno = EWOULDBLOCK;
			return -1;
		}

		total = rb_writev(F, vec, nvec);
		if(total <= 0)
			return total;

		/* Advance/free consumed blocks. */
		ssize_t remain = total;
		while(remain > 0 && sb->blocks.head != NULL)
		{
			rb_dlink_node *node = sb->blocks.head;
			rb_sendbuf_block_t *blk = node->data;
			size_t avail = blk->wpos - blk->rpos;

			if((size_t)remain >= avail)
			{
				remain -= (ssize_t)avail;
				rb_dlinkDestroy(node, &sb->blocks);
				rb_bh_free(rb_sendbuf_heap, blk);
			}
			else
			{
				blk->rpos += (uint16_t)remain;
				remain = 0;
			}
		}
		sb->len -= total;
		return total;
	}
#endif /* HAVE_WRITEV */

	/* SSL or no-writev fallback: write the first contiguous segment. */
	{
		rb_dlink_node *node = sb->blocks.head;
		rb_sendbuf_block_t *blk;
		ssize_t written;

		if(node == NULL)
		{
			errno = EWOULDBLOCK;
			return -1;
		}

		blk     = node->data;
		written = rb_write(F, blk->buf + blk->rpos, blk->wpos - blk->rpos);
		if(written <= 0)
			return written;

		blk->rpos += (uint16_t)written;
		sb->len   -= written;

		if(blk->rpos == blk->wpos)
		{
			rb_dlinkDestroy(node, &sb->blocks);
			rb_bh_free(rb_sendbuf_heap, blk);
		}
		return written;
	}
}
