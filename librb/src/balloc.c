/*
 * ophion: a slightly less ancient ircd.
 * balloc.c: mmap-backed slab allocator.
 *
 * Replaces the old malloc-wrapper with a real slab allocator backed by
 * anonymous mmap().  Each rb_bh maintains a per-heap intrusive free list
 * over a set of mmap'd slabs.
 *
 *   Allocation:  O(1) – pop from free_head; grow by one slab when empty.
 *   Free:        O(1) – push to free_head.
 *   Destroy:     munmap() each slab – memory is actually returned to the OS.
 *
 * Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 * Copyright (C) 1996-2002 Hybrid Development Team
 * Copyright (C) 2002-2006 ircd-ratbox development team
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE 1
#include <librb_config.h>
#include <rb_lib.h>
#include <sys/mman.h>
#include <unistd.h>

/* MAP_ANON is the BSD name; MAP_ANONYMOUS is the Linux/POSIX name. */
#ifndef MAP_ANONYMOUS
# ifdef MAP_ANON
#  define MAP_ANONYMOUS MAP_ANON
# else
#  error "Neither MAP_ANONYMOUS nor MAP_ANON is available"
# endif
#endif

/* Intrusive singly-linked free list stored inside each free element.
 * The first sizeof(void*) bytes of a free element hold the next-free ptr. */
#define FREELIST_NEXT(p)  (*(void **)(p))

/* Round v up to the nearest multiple of align (align must be power-of-two). */
#define ALIGN_UP(v, align)  (((v) + (size_t)(align) - 1) & ~((size_t)(align) - 1))

/* Header embedded at the very start of every mmap'd slab. */
typedef struct rb_bh_slab
{
	rb_dlink_node node;     /* links into rb_bh.block_list; .data == this */
	size_t        map_size; /* total bytes mmap'd (for munmap) */
} rb_bh_slab_t;

/* Private definition of rb_bh (opaque to callers via rb_balloc.h). */
struct rb_bh
{
	rb_dlink_node hlist;          /* node in the global heap_lists registry */
	size_t        elemSize;       /* requested element size (for reporting) */
	size_t        elem_stride;    /* elemSize rounded up to pointer alignment */
	unsigned long elemsPerBlock;  /* elements per slab */
	size_t        data_off;       /* byte offset from slab start to first element */
	void         *free_head;      /* head of the intrusive free list */
	rb_dlink_list block_list;     /* list of rb_bh_slab_t* */
	size_t        nfree;          /* total free elements across all slabs */
	size_t        nused;          /* total allocated elements */
	char         *desc;
};

static rb_dlink_list *heap_lists;
static long           rb_page_size;

static void _rb_bh_fail(const char *reason, const char *file, int line)
	__attribute__((noreturn));
#define rb_bh_fail(x) _rb_bh_fail(x, __FILE__, __LINE__)

static void
_rb_bh_fail(const char *reason, const char *file, int line)
{
	rb_lib_log("rb_bh failure: %s (%s:%d)", reason, file, line);
	abort();
}

void
rb_init_bh(void)
{
	heap_lists   = rb_malloc(sizeof(rb_dlink_list));
	rb_page_size = sysconf(_SC_PAGESIZE);
	if(rb_page_size <= 0)
		rb_page_size = 4096;
}

/* Allocate one new slab, link it into bh->block_list, and push all its
 * elements onto bh->free_head (in reverse order for cache-friendly first use). */
static void
rb_bh_grow(rb_bh *bh)
{
	size_t slab_data = bh->data_off + bh->elem_stride * bh->elemsPerBlock;
	size_t map_size  = ALIGN_UP(slab_data, (size_t)rb_page_size);

	void *mem = mmap(NULL, map_size,
	                 PROT_READ | PROT_WRITE,
	                 MAP_PRIVATE | MAP_ANONYMOUS,
	                 -1, 0);
	if(mem == MAP_FAILED)
		rb_bh_fail("mmap failed in rb_bh_grow");

	rb_bh_slab_t *slab = mem;
	slab->map_size = map_size;
	rb_dlinkAdd(slab, &slab->node, &bh->block_list);

	/* Push in reverse order so the first alloc returns the lowest-address elem. */
	char *base = (char *)mem + bh->data_off;
	for(long i = (long)bh->elemsPerBlock - 1; i >= 0; --i)
	{
		void *elem = base + (size_t)i * bh->elem_stride;
		FREELIST_NEXT(elem) = bh->free_head;
		bh->free_head = elem;
	}
	bh->nfree += bh->elemsPerBlock;
}

rb_bh *
rb_bh_create(size_t elemsize, int elemsperblock, const char *desc)
{
	lrb_assert(elemsize > 0 && elemsperblock > 0);
	lrb_assert(elemsize >= sizeof(void *));

	if(elemsize == 0 || elemsperblock <= 0)
		rb_bh_fail("rb_bh_create: idiotic sizes");
	if(elemsize < sizeof(void *))
		rb_bh_fail("rb_bh_create: elemsize too small for free-list pointer");

	rb_bh *bh = rb_malloc(sizeof(rb_bh));
	if(bh == NULL)
		rb_bh_fail("rb_bh_create: rb_malloc failed");

	bh->elemSize      = elemsize;
	bh->elem_stride   = ALIGN_UP(elemsize, sizeof(void *));
	bh->elemsPerBlock = (unsigned long)elemsperblock;
	/* Ensure the data region starts after the slab header, aligned to stride. */
	bh->data_off      = ALIGN_UP(sizeof(rb_bh_slab_t), bh->elem_stride);
	bh->free_head     = NULL;
	bh->nfree         = 0;
	bh->nused         = 0;
	bh->desc          = (desc != NULL) ? rb_strdup(desc) : NULL;

	rb_dlinkAdd(bh, &bh->hlist, heap_lists);
	rb_bh_grow(bh);   /* pre-populate one slab */
	return bh;
}

void *
rb_bh_alloc(rb_bh *bh)
{
	lrb_assert(bh != NULL);
	if(rb_unlikely(bh == NULL))
		rb_bh_fail("rb_bh_alloc: bh == NULL");

	if(rb_unlikely(bh->free_head == NULL))
		rb_bh_grow(bh);

	void *elem    = bh->free_head;
	bh->free_head = FREELIST_NEXT(elem);
	bh->nfree--;
	bh->nused++;
	memset(elem, 0, bh->elemSize);
	return elem;
}

int
rb_bh_free(rb_bh *bh, void *ptr)
{
	lrb_assert(bh != NULL);
	lrb_assert(ptr != NULL);

	if(rb_unlikely(bh == NULL))
	{
		rb_lib_log("rb_bh_free: bh == NULL");
		return 1;
	}
	if(rb_unlikely(ptr == NULL))
	{
		rb_lib_log("rb_bh_free: ptr == NULL");
		return 1;
	}

	FREELIST_NEXT(ptr) = bh->free_head;
	bh->free_head = ptr;
	bh->nfree++;
	bh->nused--;
	return 0;
}

int
rb_bh_destroy(rb_bh *bh)
{
	if(bh == NULL)
		return 1;

	rb_dlinkDelete(&bh->hlist, heap_lists);

	/* munmap each slab; use rb_dlinkDelete (not Destroy) since the node is
	 * embedded inside the slab region that we're about to unmap. */
	while(bh->block_list.head != NULL)
	{
		rb_dlink_node *node     = bh->block_list.head;
		rb_bh_slab_t  *slab     = node->data;
		size_t         map_size = slab->map_size;
		rb_dlinkDelete(node, &bh->block_list);
		munmap(slab, map_size);
	}

	rb_free(bh->desc);
	rb_free(bh);
	return 0;
}

void
rb_bh_usage(rb_bh *bh, size_t *bused, size_t *bfree, size_t *bmemusage,
            const char **desc)
{
	if(bh == NULL)
	{
		if(bused)     *bused     = 0;
		if(bfree)     *bfree     = 0;
		if(bmemusage) *bmemusage = 0;
		if(desc)      *desc      = "no blockheap";
		return;
	}
	if(bused)     *bused     = bh->nused;
	if(bfree)     *bfree     = bh->nfree;
	if(bmemusage) *bmemusage = bh->nused * bh->elemSize;
	if(desc)      *desc      = bh->desc ? bh->desc : "(unnamed)";
}

void
rb_bh_usage_all(rb_bh_usage_cb *cb, void *data)
{
	rb_dlink_node *ptr;

	if(cb == NULL)
		return;

	RB_DLINK_FOREACH(ptr, heap_lists->head)
	{
		rb_bh  *bh        = ptr->data;
		size_t  heapalloc = (bh->nused + bh->nfree) * bh->elemSize;
		cb(bh->nused, bh->nfree,
		   bh->nused * bh->elemSize,
		   heapalloc,
		   bh->desc ? bh->desc : "(unnamed)",
		   data);
	}
}

void
rb_bh_total_usage(size_t *total_alloc, size_t *total_used)
{
	rb_dlink_node *ptr;
	size_t         talloc = 0, tused = 0;

	RB_DLINK_FOREACH(ptr, heap_lists->head)
	{
		rb_bh *bh  = ptr->data;
		talloc    += (bh->nused + bh->nfree) * bh->elemSize;
		tused     += bh->nused * bh->elemSize;
	}

	if(total_alloc) *total_alloc = talloc;
	if(total_used)  *total_used  = tused;
}
