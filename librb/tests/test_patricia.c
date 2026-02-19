/*
 * test_patricia.c - regression tests for the patricia trie implementation
 *
 * Covers:
 *  - basic insert / exact-match / best-match / remove
 *  - CIDR prefix matching
 *  - /0 prefix (was broken: treated as /maxbits before the fix)
 *  - IPv6 addresses
 *  - removal of leaf, one-child and two-child nodes
 */

#include <librb_config.h>
#include <rb_lib.h>
#include <rb_patricia.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ---------- helpers ---------- */

static int failures = 0;

#define CHECK(cond) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			failures++; \
		} \
	} while (0)

/* ---------- tests ---------- */

static void
test_basic_ipv4(void)
{
	rb_patricia_tree_t *tree = rb_new_patricia(RB_PATRICIA_MAXBITS);
	rb_patricia_node_t *n;

	n = make_and_lookup(tree, "192.168.1.1");
	CHECK(n != NULL);
	n->data = (void *)1UL;

	/* exact match returns the node */
	n = rb_match_exact_string(tree, "192.168.1.1");
	CHECK(n != NULL);
	CHECK(n->data == (void *)1UL);

	/* best match also returns it */
	n = rb_match_string(tree, "192.168.1.1");
	CHECK(n != NULL);

	/* a different host has no match */
	n = rb_match_exact_string(tree, "192.168.1.2");
	CHECK(n == NULL);

	rb_destroy_patricia(tree, NULL);
	printf("test_basic_ipv4: %s\n", failures ? "FAIL" : "pass");
}

static void
test_cidr_ipv4(void)
{
	int before = failures;
	rb_patricia_tree_t *tree = rb_new_patricia(RB_PATRICIA_MAXBITS);
	rb_patricia_node_t *n;

	n = make_and_lookup(tree, "10.0.0.0/24");
	CHECK(n != NULL);
	n->data = (void *)2UL;

	/* addresses inside the /24 must match */
	n = rb_match_string(tree, "10.0.0.1");
	CHECK(n != NULL);
	CHECK(n->data == (void *)2UL);

	n = rb_match_string(tree, "10.0.0.255");
	CHECK(n != NULL);

	/* address outside the /24 must not match */
	n = rb_match_string(tree, "10.0.1.0");
	CHECK(n == NULL);

	rb_destroy_patricia(tree, NULL);
	printf("test_cidr_ipv4: %s\n", failures == before ? "pass" : "FAIL");
}

/* Before the fix, ascii2prefix treated "/0" as "/maxbits" because of the
 * "bitlen <= 0" guard.  A /0 prefix must match every address in the family. */
static void
test_zero_prefix_ipv4(void)
{
	int before = failures;
	rb_patricia_tree_t *tree = rb_new_patricia(RB_PATRICIA_MAXBITS);
	rb_patricia_node_t *n;

	n = make_and_lookup(tree, "0.0.0.0/0");
	CHECK(n != NULL);
	if (n)
		n->data = (void *)3UL;

	n = rb_match_string(tree, "1.2.3.4");
	CHECK(n != NULL);
	CHECK(n != NULL && n->data == (void *)3UL);

	n = rb_match_string(tree, "255.255.255.255");
	CHECK(n != NULL);

	/* exact lookup of the /0 node itself */
	n = rb_match_exact_string(tree, "0.0.0.0/0");
	CHECK(n != NULL);

	rb_destroy_patricia(tree, NULL);
	printf("test_zero_prefix_ipv4: %s\n", failures == before ? "pass" : "FAIL");
}

static void
test_ipv6(void)
{
	int before = failures;
	rb_patricia_tree_t *tree = rb_new_patricia(RB_PATRICIA_MAXBITS);
	rb_patricia_node_t *n;

	n = make_and_lookup(tree, "2001:db8::/32");
	CHECK(n != NULL);
	if (n)
		n->data = (void *)4UL;

	n = rb_match_string(tree, "2001:db8::1");
	CHECK(n != NULL);
	CHECK(n != NULL && n->data == (void *)4UL);

	n = rb_match_string(tree, "2001:db9::1");
	CHECK(n == NULL);

	rb_destroy_patricia(tree, NULL);
	printf("test_ipv6: %s\n", failures == before ? "pass" : "FAIL");
}

static void
test_remove_leaf(void)
{
	int before = failures;
	rb_patricia_tree_t *tree = rb_new_patricia(RB_PATRICIA_MAXBITS);
	rb_patricia_node_t *n;

	make_and_lookup(tree, "10.0.0.1");
	make_and_lookup(tree, "10.0.0.2");

	n = rb_match_exact_string(tree, "10.0.0.1");
	CHECK(n != NULL);
	if (n)
		rb_patricia_remove(tree, n);

	/* removed node is gone */
	CHECK(rb_match_exact_string(tree, "10.0.0.1") == NULL);
	/* sibling survives */
	CHECK(rb_match_exact_string(tree, "10.0.0.2") != NULL);

	rb_destroy_patricia(tree, NULL);
	printf("test_remove_leaf: %s\n", failures == before ? "pass" : "FAIL");
}

static void
test_remove_only_node(void)
{
	int before = failures;
	rb_patricia_tree_t *tree = rb_new_patricia(RB_PATRICIA_MAXBITS);
	rb_patricia_node_t *n;

	n = make_and_lookup(tree, "192.0.2.1");
	CHECK(n != NULL);
	rb_patricia_remove(tree, n);

	CHECK(tree->head == NULL);
	CHECK(tree->num_active_node == 0);

	rb_destroy_patricia(tree, NULL);
	printf("test_remove_only_node: %s\n", failures == before ? "pass" : "FAIL");
}

static void
test_remove_with_child(void)
{
	int before = failures;
	rb_patricia_tree_t *tree = rb_new_patricia(RB_PATRICIA_MAXBITS);
	rb_patricia_node_t *n;

	/* insert a parent prefix and a more-specific */
	make_and_lookup(tree, "10.0.0.0/8");
	make_and_lookup(tree, "10.1.0.0/16");

	/* remove the /8 — the /16 child must be reachable afterwards */
	n = rb_match_exact_string(tree, "10.0.0.0/8");
	CHECK(n != NULL);
	if (n)
		rb_patricia_remove(tree, n);

	CHECK(rb_match_exact_string(tree, "10.0.0.0/8") == NULL);
	CHECK(rb_match_string(tree, "10.1.2.3") != NULL);

	rb_destroy_patricia(tree, NULL);
	printf("test_remove_with_child: %s\n", failures == before ? "pass" : "FAIL");
}

/* ---------- main ---------- */

int
main(void)
{
	/* minimal librb initialisation — no logging, no net I/O needed */
	rb_lib_init(NULL, NULL, NULL, 0, 1024, 1024, 256);

	test_basic_ipv4();
	test_cidr_ipv4();
	test_zero_prefix_ipv4();
	test_ipv6();
	test_remove_leaf();
	test_remove_only_node();
	test_remove_with_child();

	if (failures)
		fprintf(stderr, "\n%d test(s) FAILED\n", failures);
	else
		printf("\nAll tests passed.\n");

	return failures ? 1 : 0;
}
