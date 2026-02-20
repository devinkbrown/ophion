/*
 * ophion: a slightly less ancient ircd.
 * io_uring.c: Linux io_uring POLL_ADD event backend.
 *
 * Uses io_uring's IORING_OP_POLL_ADD in oneshot mode as a drop-in
 * replacement for epoll.  Each rb_fde_t with read or write interest gets
 * a POLL_ADD submission; the CQE fires, the handler is dispatched, and
 * the fd is re-armed if interest still exists after dispatch.
 *
 * Event scheduling (timers, signals) piggybacks on epoll's timerfd/
 * signalfd infrastructure — timerfd is just another pollable fd.
 *
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
#include <commio-int.h>
#include <event-int.h>

#if defined(HAVE_LIBURING)
#define USING_URING

#include <liburing.h>
#include <poll.h>

/* URING_F_PENDING: set in F->pflags when a POLL_ADD sqe is in-flight. */
#define URING_F_PENDING  (1 << 16)

/* Ring depth — must be power-of-two.  4096 covers max IRC connections easily. */
#define URING_RING_DEPTH 4096

static struct io_uring uring;

int
rb_init_netio_uring(void)
{
	if(io_uring_queue_init(URING_RING_DEPTH, &uring, 0) < 0)
		return -1;
	return 0;
}

/* Submit a POLL_ADD for F if it has any read/write interest. */
static void
rb_arm_uring(rb_fde_t *F)
{
	if(F->read_handler == NULL && F->write_handler == NULL)
		return;

	unsigned int mask = 0;
	if(F->read_handler)
		mask |= POLLIN;
	if(F->write_handler)
		mask |= POLLOUT;

	struct io_uring_sqe *sqe = io_uring_get_sqe(&uring);
	if(sqe == NULL)
	{
		/* SQ ring full; flush and retry once. */
		io_uring_submit(&uring);
		sqe = io_uring_get_sqe(&uring);
		if(sqe == NULL)
			return;
	}

	io_uring_prep_poll_add(sqe, F->fd, mask);
	io_uring_sqe_set_data(sqe, F);
	F->pflags |= URING_F_PENDING;
}

void
rb_setselect_uring(rb_fde_t *F, unsigned int type, PF *handler,
                   void *client_data)
{
	if(type & RB_SELECT_READ)
	{
		F->read_handler = handler;
		F->read_data    = client_data;
	}
	if(type & RB_SELECT_WRITE)
	{
		F->write_handler = handler;
		F->write_data    = client_data;
	}

	/* Arm a new poll only if nothing is outstanding.  If a poll is already
	 * in-flight, the CQE will arrive soon and re-arm with updated interest. */
	if(!(F->pflags & URING_F_PENDING))
		rb_arm_uring(F);
}

int
rb_select_uring(long delay)
{
	struct io_uring_cqe  *cqe;
	struct __kernel_timespec ts;
	unsigned int          head;
	unsigned int          count = 0;

	io_uring_submit(&uring);

	/* Wait for the first CQE (with optional timeout). */
	if(delay >= 0)
	{
		ts.tv_sec  =  delay / 1000;
		ts.tv_nsec = (delay % 1000) * 1000000L;
		io_uring_wait_cqe_timeout(&uring, &cqe, &ts);
	}
	else
	{
		io_uring_wait_cqe(&uring, &cqe);
	}

	/* Drain all available CQEs. */
	io_uring_for_each_cqe(&uring, head, cqe)
	{
		rb_fde_t *F = io_uring_cqe_get_data(cqe);
		count++;

		if(F == NULL || !IsFDOpen(F))
			continue;

		F->pflags &= ~URING_F_PENDING;

		int res = cqe->res;

		/* On error or hangup, fire both handlers if present. */
		if(res < 0 || (res & (POLLHUP | POLLERR | POLLNVAL)))
		{
			if(F->read_handler != NULL)
			{
				PF   *h = F->read_handler;
				void *d = F->read_data;
				F->read_handler = NULL;
				F->read_data    = NULL;
				h(F, d);
			}
			if(IsFDOpen(F) && F->write_handler != NULL)
			{
				PF   *h = F->write_handler;
				void *d = F->write_data;
				F->write_handler = NULL;
				F->write_data    = NULL;
				h(F, d);
			}
		}
		else
		{
			if((res & POLLIN) && F->read_handler != NULL)
			{
				PF   *h = F->read_handler;
				void *d = F->read_data;
				F->read_handler = NULL;
				F->read_data    = NULL;
				h(F, d);
			}
			if(IsFDOpen(F) && (res & POLLOUT) && F->write_handler != NULL)
			{
				PF   *h = F->write_handler;
				void *d = F->write_data;
				F->write_handler = NULL;
				F->write_data    = NULL;
				h(F, d);
			}
		}

		/* Re-arm if the handler(s) registered new interest. */
		if(IsFDOpen(F) && !(F->pflags & URING_F_PENDING))
			rb_arm_uring(F);
	}

	io_uring_cq_advance(&uring, count);
	return 0;
}

int
rb_setup_fd_uring(rb_fde_t *F __attribute__((unused)))
{
	return 0;
}

/* Event scheduling delegates to epoll's timerfd/signalfd path.
 * On Linux, timerfd is just another file descriptor — io_uring polls it
 * the same way it polls any other fd. */
void
rb_uring_init_event(void)
{
	rb_epoll_init_event();
}

int
rb_uring_sched_event(struct ev_entry *event, int when)
{
	return rb_epoll_sched_event(event, when);
}

void
rb_uring_unsched_event(struct ev_entry *event)
{
	rb_epoll_unsched_event(event);
}

int
rb_uring_supports_event(void)
{
	return rb_epoll_supports_event();
}

#else  /* !HAVE_LIBURING */

int  rb_init_netio_uring(void) { return -1; }
void rb_setselect_uring(rb_fde_t *F __attribute__((unused)),
                        unsigned int type __attribute__((unused)),
                        PF *handler __attribute__((unused)),
                        void *client_data __attribute__((unused))) {}
int  rb_select_uring(long delay __attribute__((unused))) { return -1; }
int  rb_setup_fd_uring(rb_fde_t *F __attribute__((unused))) { return 0; }
void rb_uring_init_event(void) {}
int  rb_uring_sched_event(struct ev_entry *event __attribute__((unused)),
                          int when __attribute__((unused))) { return 0; }
void rb_uring_unsched_event(struct ev_entry *event __attribute__((unused))) {}
int  rb_uring_supports_event(void) { return 0; }

#endif /* HAVE_LIBURING */
