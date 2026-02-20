/*
 * ophion: a slightly less ancient ircd.
 * sendbuf.c: Zero-copy chunk-based outgoing send queue.
 *
 * See rb_sendbuf.h for the design overview.
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

static rb_bh *rb_sendbuf_block_heap;
static rb_bh *rb_sendbuf_chunk_heap;

void
rb_sendbuf_init(size_t heap_size)
{
	rb_sendbuf_block_heap = rb_bh_create(sizeof(rb_sendbuf_block_t),
	                                     heap_size,
	                                     "librb_sendbuf_block_heap");
	rb_sendbuf_chunk_heap = rb_bh_create(sizeof(rb_sendbuf_chunk_t),
	                                     heap_size * 4,
	                                     "librb_sendbuf_chunk_heap");
}

/* Free all chunks.  LINE chunks release their buf_line_t ref; BLOCK chunks
 * free their block back to the pool. */
void
rb_sendbuf_donebuf(rb_sendbuf_t *sb)
{
	while(sb->chunks.head != NULL)
	{
		rb_dlink_node *node = sb->chunks.head;
		rb_sendbuf_chunk_t *chunk = node->data;

		if(chunk->type == SENDBUF_CHUNK_LINE)
			rb_linebuf_unref(chunk->line);
		else
			rb_bh_free(rb_sendbuf_block_heap, chunk->block);

		rb_dlinkDestroy(node, &sb->chunks);
		rb_bh_free(rb_sendbuf_chunk_heap, chunk);
	}
	sb->len = 0;
}

/* Append len bytes from data into block storage (copy path, used for raw
 * writes and SSL).  Multiple calls are packed into the same tail block
 * before a new block is allocated. */
int
rb_sendbuf_write(rb_sendbuf_t *sb, const void *data, size_t len)
{
	const char *ptr = data;
	size_t remaining = len;

	while(remaining > 0)
	{
		rb_sendbuf_chunk_t *chunk = NULL;
		rb_sendbuf_block_t *blk = NULL;

		/* Pack into the tail block if it has space and is a BLOCK chunk. */
		if(sb->chunks.tail != NULL)
		{
			rb_sendbuf_chunk_t *tail = sb->chunks.tail->data;
			if(tail->type == SENDBUF_CHUNK_BLOCK &&
			   tail->block->wpos < RB_SENDBUF_BLOCK_SIZE)
			{
				chunk = tail;
				blk = chunk->block;
			}
		}

		if(blk == NULL)
		{
			blk = rb_bh_alloc(rb_sendbuf_block_heap);
			if(rb_unlikely(blk == NULL))
				return -1;
			blk->wpos = 0;

			chunk = rb_bh_alloc(rb_sendbuf_chunk_heap);
			if(rb_unlikely(chunk == NULL))
			{
				rb_bh_free(rb_sendbuf_block_heap, blk);
				return -1;
			}
			chunk->type  = SENDBUF_CHUNK_BLOCK;
			chunk->rpos  = 0;
			chunk->block = blk;
			rb_dlinkAddTailAlloc(chunk, &sb->chunks);
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

/* Zero-copy enqueue: for each terminated buf_line_t in linebuf, take a
 * reference and add a CHUNK_LINE.  The caller may destroy the buf_head_t
 * immediately; the bytes stay alive via the refs until fully flushed. */
int
rb_sendbuf_write_linebuf(rb_sendbuf_t *sb, buf_head_t *linebuf)
{
	rb_dlink_node *ptr;

	RB_DLINK_FOREACH(ptr, linebuf->list.head)
	{
		buf_line_t *line = ptr->data;

		if(line->len <= 0 || !line->terminated)
			continue;

		rb_sendbuf_chunk_t *chunk = rb_bh_alloc(rb_sendbuf_chunk_heap);
		if(rb_unlikely(chunk == NULL))
			return -1;

		rb_linebuf_ref(line);      /* keep alive past buf_head_t destruction */
		chunk->type = SENDBUF_CHUNK_LINE;
		chunk->rpos = 0;
		chunk->line = line;
		rb_dlinkAddTailAlloc(chunk, &sb->chunks);
		sb->len += (size_t)line->len;
	}

	return 0;
}

/* ---- internal helpers ---------------------------------------------------- */

/* Advance chunks by `consumed` bytes, freeing fully-sent ones. */
static void
sendbuf_advance(rb_sendbuf_t *sb, ssize_t consumed)
{
	sb->len -= (size_t)consumed;

	while(consumed > 0 && sb->chunks.head != NULL)
	{
		rb_dlink_node *node = sb->chunks.head;
		rb_sendbuf_chunk_t *chunk = node->data;
		size_t avail;

		if(chunk->type == SENDBUF_CHUNK_LINE)
			avail = (size_t)chunk->line->len - chunk->rpos;
		else
			avail = (size_t)chunk->block->wpos - chunk->rpos;

		if((size_t)consumed >= avail)
		{
			consumed -= (ssize_t)avail;
			if(chunk->type == SENDBUF_CHUNK_LINE)
				rb_linebuf_unref(chunk->line);
			else
				rb_bh_free(rb_sendbuf_block_heap, chunk->block);
			rb_dlinkDestroy(node, &sb->chunks);
			rb_bh_free(rb_sendbuf_chunk_heap, chunk);
		}
		else
		{
			chunk->rpos += (uint16_t)consumed;
			consumed = 0;
		}
	}
}

/* ---- flush --------------------------------------------------------------- */

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

		RB_DLINK_FOREACH(ptr, sb->chunks.head)
		{
			rb_sendbuf_chunk_t *chunk = ptr->data;
			size_t avail;
			const char *base;

			if(chunk->type == SENDBUF_CHUNK_LINE)
			{
				avail = (size_t)chunk->line->len - chunk->rpos;
				base  = chunk->line->buf + chunk->rpos;
			}
			else
			{
				avail = (size_t)chunk->block->wpos - chunk->rpos;
				base  = chunk->block->buf + chunk->rpos;
			}

			if(avail == 0)
				continue;

			vec[nvec].iov_base = (void *)base;
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

		sendbuf_advance(sb, total);
		return total;
	}
#endif /* HAVE_WRITEV */

	/* SSL or no-writev fallback: write the first contiguous segment only. */
	{
		rb_dlink_node *node = sb->chunks.head;
		rb_sendbuf_chunk_t *chunk;
		const char *base;
		size_t avail;
		ssize_t written;

		if(node == NULL)
		{
			errno = EWOULDBLOCK;
			return -1;
		}

		chunk = node->data;
		if(chunk->type == SENDBUF_CHUNK_LINE)
		{
			base  = chunk->line->buf + chunk->rpos;
			avail = (size_t)chunk->line->len - chunk->rpos;
		}
		else
		{
			base  = chunk->block->buf + chunk->rpos;
			avail = (size_t)chunk->block->wpos - chunk->rpos;
		}

		written = rb_write(F, base, avail);
		if(written <= 0)
			return written;

		sendbuf_advance(sb, written);
		return written;
	}
}
