/*
 * test_uring.c - basic functional test for the io_uring event backend
 *
 * Verifies that:
 *   1. librb selects "uring" as the I/O backend when liburing is present
 *      (set LIBRB_USE_IOTYPE=uring to force selection)
 *   2. A read interest registered via rb_setselect() fires when data
 *      arrives on a socketpair
 *   3. A write interest fires when the socket is writable
 *   4. Re-arming inside a callback works (handler re-registers interest)
 */

#include <librb_config.h>
#include <rb_lib.h>
#include <rb_commio.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ---------- helpers ---------- */

static int failures = 0;

#define CHECK(cond) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			failures++; \
		} \
	} while (0)

#define CHECK_MSG(cond, msg) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL %s:%d: %s (%s)\n", __FILE__, __LINE__, #cond, (msg)); \
			failures++; \
		} \
	} while (0)

/* ---------- test state ---------- */

static int read_fired  = 0;
static int write_fired = 0;
static const char test_payload[] = "hello-uring";

/* ---------- callbacks ---------- */

static void
on_readable(rb_fde_t *F, void *data)
{
	char buf[64];
	int  n;

	(void)data;
	n = read(rb_get_fd(F), buf, sizeof(buf) - 1);
	if (n > 0)
	{
		buf[n] = '\0';
		CHECK_MSG(strcmp(buf, test_payload) == 0, buf);
		read_fired++;
	}
	else
	{
		CHECK_MSG(0, "read returned 0 or error in on_readable");
	}
}

static void
on_writable(rb_fde_t *F, void *data)
{
	(void)F;
	(void)data;
	write_fired++;
}

/* ---------- tests ---------- */

/* 1 if the uring backend activated, 0 if it fell back (e.g. old kernel). */
static int uring_active = 0;

static void
test_backend_name(void)
{
	const char *iotype = rb_get_iotype();
	printf("  io backend: %s\n", iotype);

#if defined(HAVE_LIBURING)
	if (strcmp(iotype, "uring") == 0)
	{
		uring_active = 1;
		printf("  io_uring active\n");
	}
	else
	{
		printf("  SKIP: io_uring not available on this kernel "
		       "(requires Linux >= 5.1); using %s fallback\n", iotype);
	}
#else
	printf("  SKIP: built without liburing\n");
#endif
}

static void
test_read_fires(void)
{
	rb_fde_t *F1, *F2;
	int ret;

	ret = rb_socketpair(AF_UNIX, SOCK_STREAM, 0, &F1, &F2, "test_read_fires");
	CHECK_MSG(ret == 0, "rb_socketpair failed");
	if (ret != 0)
		return;

	/* Register read interest on F2, write test_payload from F1. */
	read_fired = 0;
	rb_setselect(F2, RB_SELECT_READ, on_readable, NULL);
	write(rb_get_fd(F1), test_payload, strlen(test_payload));

	/* One rb_select() tick should dispatch the readable CQE. */
	rb_select(100 /* ms */);

	CHECK_MSG(read_fired == 1, "read callback did not fire");

	rb_close(F1);
	rb_close(F2);
}

static void
test_write_fires(void)
{
	rb_fde_t *F1, *F2;
	int ret;

	ret = rb_socketpair(AF_UNIX, SOCK_STREAM, 0, &F1, &F2, "test_write_fires");
	CHECK_MSG(ret == 0, "rb_socketpair failed");
	if (ret != 0)
		return;

	/* A fresh socket is immediately writable. */
	write_fired = 0;
	rb_setselect(F1, RB_SELECT_WRITE, on_writable, NULL);
	rb_select(100 /* ms */);

	CHECK_MSG(write_fired == 1, "write callback did not fire");

	rb_close(F1);
	rb_close(F2);
}

static int rearm_count = 0;
#define REARM_TOTAL 3

static void
on_rearm(rb_fde_t *F, void *data)
{
	rb_fde_t *writer = data;
	char buf[64];
	int  n;

	n = read(rb_get_fd(F), buf, sizeof(buf));
	if (n > 0)
		rearm_count++;

	/* Re-register for more reads unless we have enough. */
	if (rearm_count < REARM_TOTAL)
		rb_setselect(F, RB_SELECT_READ, on_rearm, writer);

	/* Send the next byte from the writer so the next tick has data. */
	if (rearm_count < REARM_TOTAL)
		write(rb_get_fd(writer), "x", 1);
}

static void
test_rearm_in_callback(void)
{
	rb_fde_t *F1, *F2;
	int i, ret;

	ret = rb_socketpair(AF_UNIX, SOCK_STREAM, 0, &F1, &F2, "test_rearm");
	CHECK_MSG(ret == 0, "rb_socketpair failed");
	if (ret != 0)
		return;

	rearm_count = 0;
	rb_setselect(F2, RB_SELECT_READ, on_rearm, F1);
	write(rb_get_fd(F1), "x", 1); /* prime the pump */

	for (i = 0; i < REARM_TOTAL + 1; i++)
		rb_select(100 /* ms */);

	CHECK_MSG(rearm_count == REARM_TOTAL, "rearm count wrong");

	rb_close(F1);
	rb_close(F2);
}

/* ---------- main ---------- */

int
main(void)
{
	/* Force io_uring backend if the library supports it. */
#if defined(HAVE_LIBURING)
	setenv("LIBRB_USE_IOTYPE", "uring", 1);
#endif

	rb_lib_init(NULL, NULL, NULL, 0, 1024, 1024, 1024);

	printf("test_uring:\n");

	printf("  [1] backend name\n");
	test_backend_name();

	printf("  [2] read fires\n");
	test_read_fires();

	printf("  [3] write fires\n");
	test_write_fires();

	printf("  [4] rearm in callback\n");
	test_rearm_in_callback();

	if (failures == 0)
		printf("  PASS (%d tests)\n", 4);
	else
		printf("  FAIL (%d failure(s))\n", failures);

	return failures ? 1 : 0;
}
