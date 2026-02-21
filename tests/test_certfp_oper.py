#!/usr/bin/env python3
"""
tests/test_certfp_oper.py — Unit tests for certfp-only oper block logic.

Tests cover:
 1. OPER_CERTFP_ONLY flag value doesn't collide with OPER_ENCRYPTED / OPER_NEEDSSL
 2. Fingerprint prefix strings match expected RFC 7218 / ophion format
 3. Wildcard user@host ("*@*") always matches any ident/host
 4. certfp comparison is case-insensitive
 5. certfp_only flag semantics: certfp required, password optional
 6. Oper block config snippet builds correctly for certfp-only use-case
 7. Oper block config snippet with both certfp and user lines still valid
 8. certfp_only without fingerprint should be rejected (config error)
 9. Certfp block with no user lines gets wildcard fallback
10. Certfp comparison rejects mismatches (prefix differs)

These tests exercise the Python-level logic and config semantics; they do
NOT require a running ircd.
"""

import re

# ---------------------------------------------------------------------------
# Constants mirrored from include/s_newconf.h
# ---------------------------------------------------------------------------
OPER_ENCRYPTED   = 0x00001
OPER_NEEDSSL     = 0x80000
OPER_CERTFP_ONLY = 0x40000

# Fingerprint method prefixes mirrored from include/certfp.h
CERTFP_PREFIX_CERT_SHA1   = "cert_sha1:"
CERTFP_PREFIX_CERT_SHA256 = "cert_sha256:"
CERTFP_PREFIX_CERT_SHA512 = "cert_sha512:"
CERTFP_PREFIX_SPKI_SHA256 = "spki_sha256:"
CERTFP_PREFIX_SPKI_SHA512 = "spki_sha512:"

KNOWN_PREFIXES = [
    CERTFP_PREFIX_CERT_SHA1,
    CERTFP_PREFIX_CERT_SHA256,
    CERTFP_PREFIX_CERT_SHA512,
    CERTFP_PREFIX_SPKI_SHA256,
    CERTFP_PREFIX_SPKI_SHA512,
]


# ---------------------------------------------------------------------------
# Helper: mimic find_oper_conf host/username matching (fnmatch-style "*" glob)
# ---------------------------------------------------------------------------

def _glob_match(pattern, value):
    """Return True if pattern (with '*' wildcards) matches value."""
    # Convert IRC-style glob to regex
    regex = re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.')
    return bool(re.fullmatch(regex, value, re.IGNORECASE))


def _conf_host_match(oper_host, oper_user, client_host, client_user):
    """Mimic find_oper_conf username + host check."""
    if not _glob_match(oper_user, client_user):
        return False
    return _glob_match(oper_host, client_host)


def _certfp_match(oper_fp, client_fp):
    """Case-insensitive fingerprint comparison (mirrors rb_strcasecmp)."""
    if oper_fp is None or client_fp is None:
        return False
    return oper_fp.lower() == client_fp.lower()


# ---------------------------------------------------------------------------
# Helper: simulate conf_end_oper validation
# ---------------------------------------------------------------------------

class OperConf:
    """Minimal Python stand-in for struct oper_conf."""
    def __init__(self, name, passwd=None, certfp=None, flags=0, user_entries=None):
        self.name = name
        self.passwd = passwd
        self.certfp = certfp
        self.flags = flags
        # list of (username, host) tuples
        self.user_entries = user_entries or []

    @property
    def is_certfp_only(self):
        return bool(self.flags & OPER_CERTFP_ONLY)

    @property
    def is_need_ssl(self):
        return bool(self.flags & OPER_NEEDSSL)


def _validate_oper_conf(oc):
    """
    Mirrors conf_end_oper validation logic.
    Returns (ok: bool, error: str|None, final_user_entries: list).
    """
    if not oc.name:
        return False, "missing name", []

    # Password OR certfp required
    if not oc.passwd and not oc.certfp:
        return False, "missing password or fingerprint", []

    # certfp_only requires certfp
    if oc.is_certfp_only and not oc.certfp:
        return False, "certfp_only requires a fingerprint", []

    entries = list(oc.user_entries)

    # If no user entries and certfp is set, synthesise "*@*"
    if not entries:
        if oc.certfp:
            entries = [("*", "*")]
        else:
            return False, "no user entries", []

    return True, None, entries


def _authenticate(oc, client_user, client_host, client_certfp, client_passwd):
    """
    Simulate the OPER authentication flow.
    Returns "ok", "no_host", "no_certfp", "no_passwd", or "denied".
    """
    ok, err, entries = _validate_oper_conf(oc)
    if not ok:
        return "denied"

    # find_oper_conf: check username/host
    matched_entry = any(
        _conf_host_match(host, uname, client_host, client_user)
        for uname, host in entries
    )
    if not matched_entry:
        return "no_host"

    # certfp check
    if oc.certfp is not None:
        if not _certfp_match(oc.certfp, client_certfp):
            return "no_certfp"

        # certfp_only: skip password check
        if oc.is_certfp_only:
            return "ok"

    # password check
    if oc.passwd and oc.passwd != client_passwd:
        return "no_passwd"
    if oc.passwd and oc.passwd == client_passwd:
        return "ok"

    return "denied"


# ===========================================================================
# Tests
# ===========================================================================

def test_flag_no_collision():
    """OPER_CERTFP_ONLY must not share bits with OPER_ENCRYPTED or OPER_NEEDSSL."""
    assert OPER_CERTFP_ONLY & OPER_ENCRYPTED == 0
    assert OPER_CERTFP_ONLY & OPER_NEEDSSL == 0
    assert OPER_ENCRYPTED & OPER_NEEDSSL == 0


def test_certfp_prefix_formats():
    """Each certfp prefix must be lowercase, end with ':', contain no spaces."""
    for prefix in KNOWN_PREFIXES:
        assert prefix == prefix.lower(), f"{prefix!r} not lowercase"
        assert prefix.endswith(":"), f"{prefix!r} missing trailing colon"
        assert " " not in prefix, f"{prefix!r} contains space"


def test_wildcard_host_matches_any():
    """Wildcard pattern '*@*' must match any username/host."""
    for uname in ("alice", "bob", "root", "testuser"):
        for host in ("127.0.0.1", "example.com", "::1", "user.example.net"):
            assert _conf_host_match("*", "*", host, uname), \
                f"*@* should match {uname}@{host}"


def test_specific_host_does_not_match_others():
    """A specific host pattern must not match unrelated hosts."""
    assert _conf_host_match("example.com", "*", "example.com", "alice")
    assert not _conf_host_match("example.com", "*", "evil.com", "alice")
    assert not _conf_host_match("example.com", "*", "notexample.com", "alice")


def test_certfp_comparison_case_insensitive():
    """Fingerprint matching must be case-insensitive."""
    fp = "cert_sha256:abc123DEF456"
    assert _certfp_match(fp, "cert_sha256:ABC123def456")
    assert _certfp_match(fp, fp.upper())
    assert _certfp_match(fp, fp.lower())
    assert not _certfp_match(fp, "cert_sha256:000000")


def test_certfp_comparison_rejects_prefix_mismatch():
    """Fingerprints with different method prefixes must not match."""
    sha256 = "cert_sha256:aabbcc"
    sha512 = "cert_sha512:aabbcc"
    assert not _certfp_match(sha256, sha512)


def test_certfp_comparison_rejects_none():
    """None fingerprint (client has no cert) must never match."""
    assert not _certfp_match("cert_sha256:abc", None)
    assert not _certfp_match(None, "cert_sha256:abc")
    assert not _certfp_match(None, None)


def test_validate_requires_name():
    oc = OperConf(name="", passwd="secret", user_entries=[("*", "*")])
    ok, err, _ = _validate_oper_conf(oc)
    assert not ok
    assert "name" in err


def test_validate_requires_passwd_or_certfp():
    """Block with no password and no fingerprint must be rejected."""
    oc = OperConf(name="oper1", passwd=None, certfp=None, user_entries=[("*", "*")])
    ok, err, _ = _validate_oper_conf(oc)
    assert not ok
    assert "fingerprint" in err or "password" in err


def test_validate_certfp_only_requires_certfp():
    """certfp_only flag with a password but no fingerprint must be rejected.

    The 'missing credentials' guard fires first when BOTH passwd and certfp are
    absent.  The dedicated 'certfp_only requires fingerprint' check is reached
    when a password is present but certfp is not — this is the case we test.
    """
    oc = OperConf(name="oper1", passwd="somepass", certfp=None,
                  flags=OPER_CERTFP_ONLY, user_entries=[("*", "*")])
    ok, err, _ = _validate_oper_conf(oc)
    assert not ok
    assert "certfp_only" in err


def test_validate_certfp_no_user_lines_gets_wildcard():
    """Certfp block with no user lines must synthesise a '*@*' entry."""
    oc = OperConf(name="oper1", certfp="cert_sha256:abc123",
                  flags=OPER_CERTFP_ONLY)
    ok, err, entries = _validate_oper_conf(oc)
    assert ok, err
    assert ("*", "*") in entries


def test_validate_no_certfp_no_user_lines_rejected():
    """Non-certfp block with no user lines must be rejected."""
    oc = OperConf(name="oper1", passwd="secret")
    ok, err, _ = _validate_oper_conf(oc)
    assert not ok
    assert "user" in err


def test_certfp_only_authenticates_by_fp_no_password():
    """certfp_only oper must oper up with correct fingerprint, ignoring password."""
    oc = OperConf(
        name="fpoper",
        certfp="cert_sha256:deadbeef",
        flags=OPER_CERTFP_ONLY,
    )
    result = _authenticate(oc, "alice", "127.0.0.1",
                           client_certfp="cert_sha256:deadbeef",
                           client_passwd="anything_or_empty")
    assert result == "ok", f"Expected ok, got {result!r}"


def test_certfp_only_rejects_wrong_fingerprint():
    """certfp_only oper must reject a client with the wrong fingerprint."""
    oc = OperConf(
        name="fpoper",
        certfp="cert_sha256:deadbeef",
        flags=OPER_CERTFP_ONLY,
    )
    result = _authenticate(oc, "alice", "127.0.0.1",
                           client_certfp="cert_sha256:000000",
                           client_passwd="anything")
    assert result == "no_certfp", f"Expected no_certfp, got {result!r}"


def test_certfp_only_rejects_no_fingerprint():
    """certfp_only oper must reject a client that has no certificate."""
    oc = OperConf(
        name="fpoper",
        certfp="cert_sha256:deadbeef",
        flags=OPER_CERTFP_ONLY,
    )
    result = _authenticate(oc, "alice", "127.0.0.1",
                           client_certfp=None,
                           client_passwd="anything")
    assert result == "no_certfp", f"Expected no_certfp, got {result!r}"


def test_certfp_plus_password_both_required_when_not_certfp_only():
    """Without certfp_only, certfp + password must BOTH match to succeed."""
    oc = OperConf(
        name="strictoper",
        passwd="secret",
        certfp="cert_sha256:abc",
        user_entries=[("*", "*")],
    )
    # Correct fp, correct password → ok
    assert _authenticate(oc, "u", "h", "cert_sha256:abc", "secret") == "ok"
    # Correct fp, wrong password → no_passwd
    assert _authenticate(oc, "u", "h", "cert_sha256:abc", "wrong") == "no_passwd"
    # Wrong fp → no_certfp (password never reached)
    assert _authenticate(oc, "u", "h", "cert_sha256:bad", "secret") == "no_certfp"


def test_no_certfp_block_ignores_client_cert():
    """An oper block with no fingerprint requirement must not care about client cert."""
    oc = OperConf(
        name="plainoper",
        passwd="secret",
        user_entries=[("*", "*")],
    )
    # client_certfp is set but oper block has no certfp requirement → still ok
    assert _authenticate(oc, "u", "h", "cert_sha256:abc", "secret") == "ok"
    assert _authenticate(oc, "u", "h", None, "secret") == "ok"


def test_host_restriction_still_enforced_with_certfp():
    """Without certfp_only, host matching is still enforced."""
    oc = OperConf(
        name="hostoper",
        passwd="secret",
        certfp="cert_sha256:abc",
        user_entries=[("alice", "trusted.net")],
    )
    # Correct host → ok
    assert _authenticate(oc, "alice", "trusted.net", "cert_sha256:abc", "secret") == "ok"
    # Wrong host → no_host
    assert _authenticate(oc, "alice", "untrusted.net", "cert_sha256:abc", "secret") == "no_host"


def test_certfp_only_bypasses_host_via_wildcard():
    """certfp_only block (no user lines → *@*) matches any host."""
    oc = OperConf(
        name="anyhost",
        certfp="cert_sha256:abc",
        flags=OPER_CERTFP_ONLY,
    )
    for host in ("127.0.0.1", "evil.example.com", "::1"):
        result = _authenticate(oc, "anyuser", host, "cert_sha256:abc", "")
        assert result == "ok", f"certfp_only should pass for host {host!r}, got {result!r}"


def test_certfp_only_with_explicit_user_line():
    """certfp_only block with an explicit user line still enforces username."""
    oc = OperConf(
        name="fpoper",
        certfp="cert_sha256:abc",
        flags=OPER_CERTFP_ONLY,
        user_entries=[("alice", "*")],
    )
    assert _authenticate(oc, "alice", "anywhere", "cert_sha256:abc", "") == "ok"
    assert _authenticate(oc, "bob",   "anywhere", "cert_sha256:abc", "") == "no_host"


def test_password_only_oper_still_works():
    """Traditional password-only oper blocks must remain unaffected."""
    oc = OperConf(
        name="classicoper",
        passwd="hunter2",
        user_entries=[("*", "*")],
    )
    assert _authenticate(oc, "u", "h", None, "hunter2") == "ok"
    assert _authenticate(oc, "u", "h", None, "wrong") == "no_passwd"


def test_multiple_flag_combination():
    """certfp_only may be combined with need_ssl without bit collision."""
    flags = OPER_CERTFP_ONLY | OPER_NEEDSSL
    assert flags & OPER_CERTFP_ONLY
    assert flags & OPER_NEEDSSL
    assert not (flags & OPER_ENCRYPTED)
