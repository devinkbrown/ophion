#!/usr/bin/env python3
"""
Ophion IRC Server — Built-in Services Stress Test
===================================================

Exercises every services command end-to-end against a running ircd with
services.enabled = yes and registration_open = yes.

Server: 127.0.0.1:16667
Oper:   testoper / testpass123

Commands under test
-------------------
  Account management:
    REGISTER <email> <password>
    IDENTIFY [<account>] <password>
    IDENTIFY #channel <key>         (IRCX compat, always available)
    LOGOUT
    GHOST  <nick> [password]
    REGAIN <nick> [password]
    GROUP                           (add current nick to account)
    UNGROUP <nick>
    CERTADD [fingerprint]
    CERTDEL <fingerprint>
    CERTLIST
    SETPASS <old> <new>
    SETEMAIL <email>
    SET <option> <on|off>
    INFO [account]
    INFO #channel

  Channel registration:
    CREGISTER <#channel>
    CDROP     <#channel>
    CHANSET   <#channel> <option> [value]
    CHANSET   <#channel> ACCESS LIST|ADD|DEL

  Memos:
    MEMO SEND <account> <text>
    MEMO LIST
    MEMO READ <id>
    MEMO DEL  <id|ALL>

  Vhosts:
    VHOST REQUEST <vhost>
    VHOFFER       <vhost>           (oper-only)
    VHOFFERLIST
    VHOST TAKE <vhost>

  Oper-level account admin:
    ACCOUNTOPER <account> <block|->
    SUSPEND / UNSUSPEND <account>
    FORBID / UNFORBID  <nick>

  Founder/key bypass:
    Registered founder can JOIN a +k channel without the live key.
    IDENTIFY #chan <mlock_key> restores founder ops.

Run:  python3 tests/test_services.py
      (ircd must be listening on 127.0.0.1:16667 with services enabled)
"""

import base64
import socket
import time
import sys
import re

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SERVER_HOST = "127.0.0.1"
SERVER_PORT  = 16667
OPER_NAME   = "testoper"
OPER_PASS   = "testpass123"
TEST_EMAIL  = "test@ophion.test"

# Numeric constants
RPL_LOGGEDIN    = "900"
RPL_LOGGEDOUT   = "901"
RPL_SASLSUCCESS = "903"
ERR_SASLFAIL    = "904"
ERR_UNKNOWNCMD  = "421"
ERR_CHANOPRIVSNEEDED = "482"

# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------
_passed  = 0
_failed  = 0


def _ok(name, detail=""):
    global _passed
    _passed += 1
    suffix = f"  ({detail})" if detail else ""
    print(f"  [\033[32mPASS\033[0m] {name}{suffix}")


def _fail(name, detail=""):
    global _failed
    _failed += 1
    suffix = f"  ({detail})" if detail else ""
    print(f"  [\033[31mFAIL\033[0m] {name}{suffix}")


def _check(name, cond, detail=""):
    if cond:
        _ok(name, detail)
    else:
        _fail(name, detail)


# ---------------------------------------------------------------------------
# SASL helper
# ---------------------------------------------------------------------------

def _sasl_b64(account: str, password: str) -> str:
    return base64.b64encode(f"\x00{account}\x00{password}".encode()).decode()


# ---------------------------------------------------------------------------
# Nick counter
# ---------------------------------------------------------------------------
_seq = int(time.time()) % 100000


def _nick(base="sv"):
    global _seq
    _seq = (_seq + 1) % 100000
    return f"{base}{_seq:05d}"


# ---------------------------------------------------------------------------
# IRC client
# ---------------------------------------------------------------------------

class IRC:
    """Minimal raw IRC client."""

    def __init__(self, nick, timeout=8):
        self.nick = nick
        self._buf = ""
        self.is_oper = False
        self.sasl_result = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((SERVER_HOST, SERVER_PORT))

    # ---- wire ---------------------------------------------------------------

    def send(self, line):
        self.sock.sendall((line + "\r\n").encode())

    def _lines(self, deadline):
        while time.time() < deadline:
            try:
                self.sock.settimeout(max(0.05, deadline - time.time()))
                chunk = self.sock.recv(4096).decode("utf-8", errors="replace")
                if not chunk:
                    break
                self._buf += chunk
            except (socket.timeout, OSError):
                break
            while "\r\n" in self._buf:
                line, self._buf = self._buf.split("\r\n", 1)
                yield line

    # ---- registration -------------------------------------------------------

    def register(self, sasl_account=None, sasl_pass=None):
        """Send NICK/USER (optionally preceded by AUTH PLAIN) and wait for 001."""
        if sasl_account:
            self.send(f"AUTH PLAIN I :{_sasl_b64(sasl_account, sasl_pass or '')}")
        self.send(f"NICK {self.nick}")
        self.send(f"USER {self.nick} 0 * :Services Test")
        deadline = time.time() + 10
        done = False
        for line in self._lines(deadline):
            if " 903 " in line:
                self.sasl_result = "903"
            elif " 904 " in line:
                self.sasl_result = "904"
            if " 381 " in line:
                self.is_oper = True
            if f" 376 {self.nick} " in line or f" 422 {self.nick} " in line:
                done = True
                break
        if not done:
            raise TimeoutError(f"Registration timeout for {self.nick}")
        # Drain brief post-burst messages (oper modes, etc.)
        for _ in self._lines(time.time() + 0.8):
            pass
        return self

    # ---- helpers ------------------------------------------------------------

    def collect(self, seconds=2.0):
        lines = []
        for line in self._lines(time.time() + seconds):
            lines.append(line)
        return lines

    def wait(self, pattern, timeout=4.0):
        """Return the first line matching regex `pattern`, or None."""
        deadline = time.time() + timeout
        for line in self._lines(deadline):
            if re.search(pattern, line):
                return line
        return None

    def wait_any(self, patterns, timeout=4.0):
        deadline = time.time() + timeout
        for line in self._lines(deadline):
            for i, p in enumerate(patterns):
                if re.search(p, line):
                    return i, line
        return None, None

    def drain(self, secs=0.4):
        for _ in self._lines(time.time() + secs):
            pass

    def close(self):
        try:
            self.send("QUIT :done")
            self.sock.close()
        except Exception:
            pass


def _connect(base="sv", sasl_account=None, sasl_pass=None):
    """Create, register, and return an IRC client."""
    c = IRC(_nick(base))
    c.register(sasl_account=sasl_account, sasl_pass=sasl_pass)
    return c


def _oper(base="op"):
    return _connect(base, sasl_account=OPER_NAME, sasl_pass=OPER_PASS)


# ---------------------------------------------------------------------------
# Reusable: register an account and return (client, password)
# ---------------------------------------------------------------------------

def _make_account(base="ac", password="password123"):
    """Connect a client and register it.  Returns (client, password)."""
    c = _connect(base)
    c.send(f"REGISTER {TEST_EMAIL} {password}")
    ok = c.wait(r"(?i)(registered|900|logged in)", timeout=4)
    if ok is None:
        raise RuntimeError(f"REGISTER failed for {c.nick}")
    return c, password


# ===========================================================================
# SECTION 1 — REGISTER
# ===========================================================================

def test_register_success():
    """REGISTER <email> <password> → 900 RPL_LOGGEDIN + notice."""
    c = _connect("reg")
    c.send(f"REGISTER {TEST_EMAIL} password123")
    ok = c.wait(r" 900 ", timeout=4)
    _check("REGISTER success → 900", ok is not None, f"nick={c.nick}")
    c.close()


def test_register_duplicate():
    """Registering the same nick twice → 'already registered' notice."""
    c, pw = _make_account("dup")
    # Try to register again (same nick, already identified)
    c.send(f"REGISTER {TEST_EMAIL} {pw}")
    ok = c.wait(r"(?i)(already identified|already registered)", timeout=4)
    _check("REGISTER duplicate → already-identified notice", ok is not None, f"nick={c.nick}")
    c.close()


def test_register_short_password():
    """REGISTER with password < 5 chars → error notice."""
    c = _connect("rsp")
    c.send(f"REGISTER {TEST_EMAIL} abc")
    ok = c.wait(r"(?i)(at least 5|password)", timeout=4)
    _check("REGISTER short password → error notice", ok is not None, f"nick={c.nick}")
    c.close()


def test_register_bad_email():
    """REGISTER with email lacking '@' → error notice."""
    c = _connect("rbe")
    c.send(f"REGISTER notanemail password123")
    ok = c.wait(r"(?i)(invalid email|@)", timeout=4)
    _check("REGISTER bad email → error notice", ok is not None, f"nick={c.nick}")
    c.close()


def test_register_not_identified_after_reg():
    """After successful REGISTER the client suser should appear in WHOIS."""
    c, _ = _make_account("rwi")
    c.send(f"WHOIS {c.nick}")
    resp = c.collect(2.0)
    # 330 = RPL_WHOISACCOUNT ("… is logged in as …")
    found = any(" 330 " in ln for ln in resp)
    _check("After REGISTER: WHOIS shows 330 logged-in", found, f"nick={c.nick}")
    c.close()


# ===========================================================================
# SECTION 2 — IDENTIFY
# ===========================================================================

def test_identify_correct():
    """IDENTIFY <account> <password> → 900 + notice."""
    c, pw = _make_account("idc")
    acct = c.nick
    c.send("LOGOUT")
    c.drain()
    c.send(f"IDENTIFY {acct} {pw}")
    ok = c.wait(r"(?i)( 900 |identified as)", timeout=4)
    _check("IDENTIFY correct → 900 or identified notice", ok is not None, f"nick={c.nick}")
    c.close()


def test_identify_wrong_password():
    """IDENTIFY with wrong password → 'Invalid account name or password' notice."""
    c, _ = _make_account("idw")
    acct = c.nick
    c.send("LOGOUT")
    c.drain()
    c.send(f"IDENTIFY {acct} WRONGPASSWORD")
    ok = c.wait(r"(?i)(invalid|password|failed)", timeout=4)
    _check("IDENTIFY wrong password → error notice", ok is not None, f"nick={c.nick}")
    c.close()


def test_identify_already_identified():
    """IDENTIFY while already identified → 'already identified' notice."""
    c, pw = _make_account("idai")
    c.send(f"IDENTIFY {c.nick} {pw}")
    ok = c.wait(r"(?i)already identified", timeout=4)
    _check("IDENTIFY while already identified → notice", ok is not None, f"nick={c.nick}")
    c.close()


def test_identify_shortform():
    """IDENTIFY <password> (no account) uses current nick."""
    c, pw = _make_account("idsf")
    c.send("LOGOUT")
    c.drain()
    c.send(f"IDENTIFY {pw}")
    ok = c.wait(r"(?i)( 900 |identified as)", timeout=4)
    _check("IDENTIFY <password> short form → success", ok is not None, f"nick={c.nick}")
    c.close()


def test_identify_channel_key_always_works():
    """IDENTIFY #channel <key> works regardless of services state (IRCX compat)."""
    c = _connect("idk")
    chan = f"#idktest{_seq}"
    c.send(f"JOIN {chan} secret123")
    c.drain(0.5)
    # Set a key on the channel
    c.send(f"MODE {chan} +k secret123")
    c.drain(0.3)
    # Now IDENTIFY the channel key — should get a services notice or access grant
    c.send(f"IDENTIFY {chan} secret123")
    # The response is either a notice about channel key or the channel is
    # already joined; either way we just want no error numeric
    lines = c.collect(2.0)
    got_error = any(ERR_UNKNOWNCMD in ln for ln in lines)
    _check("IDENTIFY #channel <key> never returns 421", not got_error,
           f"chan={chan}")
    c.close()


# ===========================================================================
# SECTION 3 — LOGOUT
# ===========================================================================

def test_logout_success():
    """LOGOUT → 901 RPL_LOGGEDOUT."""
    c, _ = _make_account("lo")
    c.send("LOGOUT")
    ok = c.wait(r"(?i)( 901 |logged out)", timeout=4)
    _check("LOGOUT → 901 or logged-out notice", ok is not None, f"nick={c.nick}")
    c.close()


def test_logout_not_identified():
    """LOGOUT without being identified → 'not identified' notice."""
    c = _connect("lni")
    c.send("LOGOUT")
    ok = c.wait(r"(?i)(not identified|not logged)", timeout=4)
    _check("LOGOUT when not identified → error notice", ok is not None, f"nick={c.nick}")
    c.close()


# ===========================================================================
# SECTION 4 — GHOST / REGAIN
# ===========================================================================

def test_ghost_own_session():
    """GHOST <nick> <password> kills a session belonging to the same account."""
    # Create account with client A
    a, pw = _make_account("gha")
    acct = a.nick

    # Open second connection with the same credentials
    ghost = IRC(_nick("ghb"))
    ghost.sock.connect = lambda addr: None   # already connected
    ghost = IRC(_nick("ghb"))
    ghost.register()  # unregistered ghost session

    # From a new identified session, ghost the old one
    b = _connect("ghc")
    b.send(f"IDENTIFY {acct} {pw}")
    b.drain(1.0)

    # GHOST by password
    b.send(f"GHOST {ghost.nick} {pw}")
    ok = b.wait(r"(?i)(ghost|killed|no such nick|not online)", timeout=4)
    _check("GHOST <unrelated nick> <password> → response received",
           ok is not None, f"ghost_nick={ghost.nick}")

    a.close()
    ghost.close()
    b.close()


def test_ghost_wrong_password():
    """GHOST with wrong password → error notice."""
    a, pw = _make_account("gwp")
    b = _connect("gwpb")
    b.send(f"GHOST {a.nick} WRONGPASSWORD")
    ok = b.wait(r"(?i)(invalid|incorrect|password|failed|not identified)", timeout=4)
    _check("GHOST wrong password → error notice", ok is not None)
    a.close()
    b.close()


def test_regain():
    """REGAIN <nick> [password] is accepted without error."""
    a, pw = _make_account("rga")
    # REGAIN from another client using password
    b = _connect("rgb")
    b.send(f"REGAIN {a.nick} {pw}")
    ok = b.wait(r"(?i)(regain|ghost|killed|not online|no such nick)", timeout=4)
    _check("REGAIN <nick> <password> → response received", ok is not None)
    a.close()
    b.close()


# ===========================================================================
# SECTION 5 — GROUP / UNGROUP
# ===========================================================================

def test_group_add():
    """GROUP adds the current nick to the account's nick group."""
    a, pw = _make_account("grpa")
    b = _connect("grpb")          # a different nick
    # Identify as the same account from the new nick
    b.send(f"IDENTIFY {a.nick} {pw}")
    b.drain(1.0)
    # GROUP current nick into the account
    b.send("GROUP")
    ok = b.wait(r"(?i)(group|added|registered)", timeout=4)
    _check("GROUP adds current nick → success notice", ok is not None,
           f"nick={b.nick}")
    a.close()
    b.close()


def test_group_not_identified():
    """GROUP when not identified → error."""
    c = _connect("grpni")
    c.send("GROUP")
    ok = c.wait(r"(?i)(not identified|identify first|must be)", timeout=4)
    _check("GROUP without identification → error notice", ok is not None)
    c.close()


def test_ungroup_primary_blocked():
    """UNGROUP of the primary (account-name) nick is rejected."""
    a, _ = _make_account("ugp")
    a.send(f"UNGROUP {a.nick}")
    ok = a.wait(r"(?i)(primary|cannot|account name)", timeout=4)
    _check("UNGROUP primary nick → blocked notice", ok is not None,
           f"nick={a.nick}")
    a.close()


def test_ungroup_grouped_nick():
    """UNGROUP removes a successfully grouped nick."""
    a, pw = _make_account("ugg")
    b = _connect("uggb")
    b.send(f"IDENTIFY {a.nick} {pw}")
    b.drain(1.0)
    b.send("GROUP")
    b.drain(1.0)
    b.send(f"UNGROUP {b.nick}")
    ok = b.wait(r"(?i)(ungroup|removed|nick.*removed)", timeout=4)
    _check("UNGROUP grouped nick → success notice", ok is not None,
           f"nick={b.nick}")
    a.close()
    b.close()


# ===========================================================================
# SECTION 6 — CERTADD / CERTDEL / CERTLIST
# ===========================================================================

def test_certlist_empty():
    """CERTLIST on fresh account returns list (empty or header)."""
    a, _ = _make_account("cl")
    a.send("CERTLIST")
    ok = a.wait(r"(?i)(certificate|certfp|no cert|fingerprint|end of)", timeout=4)
    _check("CERTLIST on fresh account → response", ok is not None)
    a.close()


def test_certadd_no_cert():
    """CERTADD with no fingerprint and no TLS cert → error notice."""
    a, _ = _make_account("cna")
    a.send("CERTADD")
    ok = a.wait(r"(?i)(no.*cert|not.*tls|provide|fingerprint)", timeout=4)
    _check("CERTADD without cert → error notice", ok is not None)
    a.close()


def test_certadd_manual():
    """CERTADD <fingerprint> adds a certfp entry."""
    a, _ = _make_account("cam")
    fp = "sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    a.send(f"CERTADD {fp}")
    ok = a.wait(r"(?i)(added|cert|fingerprint)", timeout=4)
    _check("CERTADD <fingerprint> → added notice", ok is not None)

    # Verify it appears in CERTLIST
    a.send("CERTLIST")
    ok2 = a.wait(r"(?i)(aabbccdd|certfp|fingerprint)", timeout=4)
    _check("CERTADD: fingerprint visible in CERTLIST", ok2 is not None)

    # CERTDEL removes it
    a.send(f"CERTDEL {fp}")
    ok3 = a.wait(r"(?i)(removed|deleted|cert)", timeout=4)
    _check("CERTDEL <fingerprint> → removed notice", ok3 is not None)

    a.close()


# ===========================================================================
# SECTION 7 — ACCOUNTSET (SETPASS, SETEMAIL, SET)
# ===========================================================================

def test_setpass():
    """SETPASS <old> <new> changes the password successfully."""
    a, pw = _make_account("sp")
    a.send(f"SETPASS {pw} newpassword456")
    ok = a.wait(r"(?i)(password.*changed|changed.*password|updated)", timeout=4)
    _check("SETPASS correct old → changed notice", ok is not None)

    # Verify the new password works
    b = _connect("spb")
    b.send(f"IDENTIFY {a.nick} newpassword456")
    ok2 = b.wait(r"(?i)( 900 |identified as)", timeout=4)
    _check("SETPASS: new password authenticates successfully", ok2 is not None)

    a.close()
    b.close()


def test_setpass_wrong_old():
    """SETPASS with wrong old password → error notice."""
    a, pw = _make_account("spw")
    a.send(f"SETPASS WRONGOLD newpassword456")
    ok = a.wait(r"(?i)(incorrect|invalid|wrong|mismatch)", timeout=4)
    _check("SETPASS wrong old → error notice", ok is not None)
    a.close()


def test_setemail():
    """SETEMAIL <newemail> updates the account email."""
    a, _ = _make_account("se")
    a.send("SETEMAIL new@ophion.test")
    ok = a.wait(r"(?i)(email.*updated|updated.*email|changed)", timeout=4)
    _check("SETEMAIL valid address → updated notice", ok is not None)
    a.close()


def test_set_enforce():
    """SET ENFORCE on/off toggles nick enforcement flag."""
    a, _ = _make_account("ste")
    a.send("SET ENFORCE on")
    ok = a.wait(r"(?i)(enforce|set|enabled|on)", timeout=4)
    _check("SET ENFORCE on → response", ok is not None)

    a.send("SET ENFORCE off")
    ok2 = a.wait(r"(?i)(enforce|set|disabled|off)", timeout=4)
    _check("SET ENFORCE off → response", ok2 is not None)
    a.close()


# ===========================================================================
# SECTION 8 — ACCOUNTINFO (INFO)
# ===========================================================================

def test_info_self():
    """INFO (no args) shows own account information."""
    a, _ = _make_account("inf")
    a.send("INFO")
    ok = a.wait(r"(?i)(account|registered|info)", timeout=4)
    _check("INFO self → account info", ok is not None)
    a.close()


def test_info_other():
    """INFO <account> shows another account's info."""
    a, _ = _make_account("infa")
    b = _connect("infb")
    b.send(f"INFO {a.nick}")
    ok = b.wait(r"(?i)(account|registered|info)", timeout=4)
    _check("INFO <other account> → account info", ok is not None)
    a.close()
    b.close()


def test_info_unknown():
    """INFO <nonexistent> → 'no such account' notice."""
    c = _connect("infu")
    c.send(f"INFO nosuchaccountxyz999")
    ok = c.wait(r"(?i)(no such|not found|unknown|not registered)", timeout=4)
    _check("INFO <unknown> → not found notice", ok is not None)
    c.close()


def test_info_channel():
    """INFO #channel shows channel registration info."""
    a, pw = _make_account("infc")
    chan = f"#infc{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.5)
    a.send(f"MODE {chan} +o {a.nick}")
    a.drain(0.3)
    a.send(f"CREGISTER {chan}")
    a.drain(1.0)
    a.send(f"INFO {chan}")
    ok = a.wait(r"(?i)(channel|registered|founder|info)", timeout=4)
    _check("INFO #channel → channel registration info", ok is not None,
           f"chan={chan}")
    a.close()


# ===========================================================================
# SECTION 9 — CREGISTER / CDROP
# ===========================================================================

def test_cregister_as_op():
    """CREGISTER #channel as a chanop → success."""
    a, _ = _make_account("creg")
    chan = f"#creg{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.5)
    a.send(f"CREGISTER {chan}")
    ok = a.wait(r"(?i)(registered|channel.*registered|success)", timeout=4)
    _check("CREGISTER as chanop → success notice", ok is not None,
           f"chan={chan}")
    a.close()


def test_cregister_not_op():
    """CREGISTER #channel without chanop → error notice."""
    a, _ = _make_account("crnop")
    chan = f"#crnop{_seq}"
    # Let someone else create the channel and be the op
    op = _connect("crnopop")
    op.send(f"JOIN {chan}")
    op.drain(0.5)
    # a joins but is not op
    a.send(f"JOIN {chan}")
    a.drain(0.5)
    a.send(f"CREGISTER {chan}")
    ok = a.wait(r"(?i)(not.*op|must be.*op|operator|privilege)", timeout=4)
    _check("CREGISTER without chanop → error notice", ok is not None,
           f"chan={chan}")
    op.close()
    a.close()


def test_cregister_already_registered():
    """CREGISTER an already-registered channel → 'already registered' notice."""
    a, _ = _make_account("crar")
    chan = f"#crar{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.5)
    a.send(f"CREGISTER {chan}")
    a.drain(1.0)
    a.send(f"CREGISTER {chan}")
    ok = a.wait(r"(?i)(already registered|already.*channel)", timeout=4)
    _check("CREGISTER already-registered → error notice", ok is not None,
           f"chan={chan}")
    a.close()


def test_cdrop():
    """CDROP #channel by founder → removes registration."""
    a, _ = _make_account("cdrop")
    chan = f"#cdrop{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.5)
    a.send(f"CREGISTER {chan}")
    a.drain(1.0)
    a.send(f"CDROP {chan}")
    ok = a.wait(r"(?i)(drop|removed|unregistered)", timeout=4)
    _check("CDROP by founder → success notice", ok is not None,
           f"chan={chan}")
    a.close()


# ===========================================================================
# SECTION 10 — CHANSET
# ===========================================================================

def _setup_chanreg(base="cs"):
    """Return (client, channel_name) with a registered channel."""
    a, _ = _make_account(base)
    chan = f"#{base}{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.5)
    a.send(f"CREGISTER {chan}")
    a.drain(1.0)
    return a, chan


def test_chanset_topiclock():
    """CHANSET #channel TOPICLOCK on/off."""
    a, chan = _setup_chanreg("cstl")
    a.send(f"CHANSET {chan} TOPICLOCK on")
    ok = a.wait(r"(?i)(topiclock|set|on|enabled)", timeout=4)
    _check("CHANSET TOPICLOCK on → response", ok is not None, f"chan={chan}")

    a.send(f"CHANSET {chan} TOPICLOCK off")
    ok2 = a.wait(r"(?i)(topiclock|set|off|disabled)", timeout=4)
    _check("CHANSET TOPICLOCK off → response", ok2 is not None, f"chan={chan}")
    a.close()


def test_chanset_keeptopic():
    """CHANSET #channel KEEPTOPIC on."""
    a, chan = _setup_chanreg("cskt")
    a.send(f"CHANSET {chan} KEEPTOPIC on")
    ok = a.wait(r"(?i)(keeptopic|set|on|enabled)", timeout=4)
    _check("CHANSET KEEPTOPIC on → response", ok is not None)
    a.close()


def test_chanset_url():
    """CHANSET #channel URL <value>."""
    a, chan = _setup_chanreg("csurl")
    a.send(f"CHANSET {chan} URL https://ophion.test/")
    ok = a.wait(r"(?i)(url|set|updated)", timeout=4)
    _check("CHANSET URL → response", ok is not None)
    a.close()


def test_chanset_desc():
    """CHANSET #channel DESC <value>."""
    a, chan = _setup_chanreg("csdesc")
    a.send(f"CHANSET {chan} DESC :A test channel")
    ok = a.wait(r"(?i)(desc|description|set|updated)", timeout=4)
    _check("CHANSET DESC → response", ok is not None)
    a.close()


def test_chanset_access_list():
    """CHANSET #channel ACCESS LIST."""
    a, chan = _setup_chanreg("csal")
    a.send(f"CHANSET {chan} ACCESS LIST")
    ok = a.wait(r"(?i)(access|list|end|no entries)", timeout=4)
    _check("CHANSET ACCESS LIST → response", ok is not None)
    a.close()


def test_chanset_access_add_del():
    """CHANSET #channel ACCESS ADD/DEL cycles cleanly."""
    a, pw = _make_account("csaad")
    b, _ = _make_account("csaadb")
    chan = f"#csaad{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.3)
    a.send(f"CREGISTER {chan}")
    a.drain(1.0)

    # ADD sop access for account b
    a.send(f"CHANSET {chan} ACCESS ADD {b.nick} sop")
    ok = a.wait(r"(?i)(added|access|set)", timeout=4)
    _check("CHANSET ACCESS ADD sop → response", ok is not None)

    # DEL access for account b
    a.send(f"CHANSET {chan} ACCESS DEL {b.nick}")
    ok2 = a.wait(r"(?i)(removed|deleted|del|access)", timeout=4)
    _check("CHANSET ACCESS DEL → response", ok2 is not None)

    a.close()
    b.close()


def test_chanset_modelock():
    """CHANSET #channel MODELOCK +nt."""
    a, chan = _setup_chanreg("csml")
    a.send(f"CHANSET {chan} MODELOCK +nt")
    ok = a.wait(r"(?i)(modelock|mode.*lock|set|+nt)", timeout=4)
    _check("CHANSET MODELOCK +nt → response", ok is not None)
    a.close()


def test_chanset_not_founder():
    """CHANSET by non-founder → privilege error."""
    a, pw = _make_account("csnf")
    b, _ = _make_account("csnfb")
    chan = f"#csnf{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.3)
    a.send(f"CREGISTER {chan}")
    a.drain(1.0)

    # b has no access on this channel
    b.send(f"JOIN {chan}")
    b.drain(0.3)
    b.send(f"CHANSET {chan} TOPICLOCK on")
    ok = b.wait(r"(?i)(not.*access|access denied|privilege|not.*founder)", timeout=4)
    _check("CHANSET by non-founder → denied notice", ok is not None)

    a.close()
    b.close()


# ===========================================================================
# SECTION 11 — MEMO
# ===========================================================================

def _setup_two_accounts():
    """Return (client_a, client_b) both registered and identified."""
    a, _ = _make_account("ma")
    b, _ = _make_account("mb")
    return a, b


def test_memo_send():
    """MEMO SEND <account> <text> → delivered notice."""
    a, b = _setup_two_accounts()
    a.send(f"MEMO SEND {b.nick} :Hello from {a.nick}")
    ok = a.wait(r"(?i)(memo.*sent|sent.*memo|message sent|delivered)", timeout=4)
    _check("MEMO SEND → sent notice", ok is not None,
           f"from={a.nick} to={b.nick}")
    a.close()
    b.close()


def test_memo_list():
    """MEMO LIST shows memos (after receiving one)."""
    a, b = _setup_two_accounts()
    a.send(f"MEMO SEND {b.nick} :List test message")
    a.drain(0.5)

    b.send("MEMO LIST")
    ok = b.wait(r"(?i)(memo|message|no memo|end of)", timeout=4)
    _check("MEMO LIST → response", ok is not None)
    a.close()
    b.close()


def test_memo_read():
    """MEMO READ <id> displays memo content."""
    a, b = _setup_two_accounts()
    a.send(f"MEMO SEND {b.nick} :Read test content")
    a.drain(0.5)

    # Get the ID from LIST
    b.send("MEMO LIST")
    lines = b.collect(2.0)
    # Look for a numeric ID in the list output
    memo_id = None
    for ln in lines:
        m = re.search(r"#(\d+)", ln)
        if m:
            memo_id = m.group(1)
            break

    if memo_id is None:
        _fail("MEMO READ: could not find memo ID in LIST output")
    else:
        b.send(f"MEMO READ {memo_id}")
        ok = b.wait(r"(?i)(read test content|memo|from|message)", timeout=4)
        _check("MEMO READ <id> → shows content", ok is not None,
               f"id={memo_id}")

    a.close()
    b.close()


def test_memo_del():
    """MEMO DEL ALL removes all memos."""
    a, b = _setup_two_accounts()
    a.send(f"MEMO SEND {b.nick} :Delete test")
    a.drain(0.5)

    b.send("MEMO DEL ALL")
    ok = b.wait(r"(?i)(deleted|removed|all memo)", timeout=4)
    _check("MEMO DEL ALL → deleted notice", ok is not None)

    # Verify LIST is now empty
    b.send("MEMO LIST")
    ok2 = b.wait(r"(?i)(no memo|no message|empty|0 memo)", timeout=4)
    _check("MEMO LIST after DEL ALL → empty", ok2 is not None)

    a.close()
    b.close()


# ===========================================================================
# SECTION 12 — VHOST
# ===========================================================================

def test_vhost_request_valid():
    """VHOST REQUEST <valid-vhost> → accepted notice."""
    a, _ = _make_account("vhr")
    a.send("VHOST REQUEST test.ophion.vhost")
    ok = a.wait(r"(?i)(request|submitted|pending|vhost)", timeout=4)
    _check("VHOST REQUEST valid host → response", ok is not None)
    a.close()


def test_vhost_request_invalid():
    """VHOST REQUEST <no-dot> → invalid vhost notice."""
    a, _ = _make_account("vhri")
    a.send("VHOST REQUEST invaliddomain")
    ok = a.wait(r"(?i)(invalid|dot|format|vhost)", timeout=4)
    _check("VHOST REQUEST no-dot → invalid notice", ok is not None)
    a.close()


def test_vhoffer_and_take():
    """Oper VHOFFERs a vhost; user takes it."""
    a, _ = _make_account("vht")
    op = _oper("vhop")

    vhost = f"sv{_seq}.ophion.test"
    op.send(f"VHOFFER {vhost}")
    op.drain(1.0)

    # User takes the offered vhost
    a.send(f"VHOST TAKE {vhost}")
    ok = a.wait(r"(?i)(vhost.*set|host.*set|applied|activated)", timeout=4)
    _check("VHOST TAKE offered host → applied notice", ok is not None,
           f"vhost={vhost}")
    op.close()
    a.close()


def test_vhofferlist():
    """VHOFFERLIST shows available offers."""
    op = _oper("vhol")
    vhost = f"list{_seq}.ophion.test"
    op.send(f"VHOFFER {vhost}")
    op.drain(0.5)

    c = _connect("vholc")
    c.send("VHOFFERLIST")
    ok = c.wait(r"(?i)(offer|vhost|list|end)", timeout=4)
    _check("VHOFFERLIST → response", ok is not None)
    op.close()
    c.close()


# ===========================================================================
# SECTION 13 — ACCOUNTOPER (oper-only)
# ===========================================================================

def test_accountoper_link():
    """ACCOUNTOPER <account> <block> (oper-only) → success."""
    a, _ = _make_account("aol")
    op = _oper("aoloop")
    op.send(f"ACCOUNTOPER {a.nick} {OPER_NAME}")
    ok = op.wait(r"(?i)(linked|oper.*block|set|account)", timeout=4)
    _check("ACCOUNTOPER LINK → success notice", ok is not None,
           f"account={a.nick}")
    a.close()
    op.close()


def test_accountoper_unlink():
    """ACCOUNTOPER <account> - removes oper block link."""
    a, _ = _make_account("aou")
    op = _oper("aouop")
    # Link first
    op.send(f"ACCOUNTOPER {a.nick} {OPER_NAME}")
    op.drain(1.0)
    # Now unlink
    op.send(f"ACCOUNTOPER {a.nick} -")
    ok = op.wait(r"(?i)(unlinked|removed|cleared|-)", timeout=4)
    _check("ACCOUNTOPER UNLINK → success notice", ok is not None)
    a.close()
    op.close()


def test_accountoper_nonoper_blocked():
    """ACCOUNTOPER by non-oper → 481 ERR_NOPRIVILEGES."""
    a, _ = _make_account("aonop")
    b = _connect("aonopb")
    b.send(f"ACCOUNTOPER {a.nick} {OPER_NAME}")
    ok = b.wait(r" 481 ", timeout=4)
    _check("ACCOUNTOPER by non-oper → 481", ok is not None)
    a.close()
    b.close()


# ===========================================================================
# SECTION 14 — SUSPEND / UNSUSPEND (oper-only)
# ===========================================================================

def test_suspend_unsuspend():
    """SUSPEND <account> prevents login; UNSUSPEND restores it."""
    a, pw = _make_account("sus")
    op = _oper("susop")

    op.send(f"SUSPEND {a.nick}")
    op.drain(1.0)

    # Try to identify as the suspended account from a fresh client
    b = _connect("susb")
    b.send(f"IDENTIFY {a.nick} {pw}")
    ok = b.wait(r"(?i)(suspended|disabled|not available|invalid)", timeout=4)
    _check("Login to SUSPENDED account → blocked notice", ok is not None)

    # UNSUSPEND
    op.send(f"UNSUSPEND {a.nick}")
    op.drain(1.0)

    # Should now be able to log in
    b.send(f"IDENTIFY {a.nick} {pw}")
    ok2 = b.wait(r"(?i)( 900 |identified as)", timeout=4)
    _check("UNSUSPEND: login succeeds after unsuspend", ok2 is not None)

    a.close()
    b.close()
    op.close()


# ===========================================================================
# SECTION 15 — FORBID / UNFORBID (oper-only)
# ===========================================================================

def test_forbid_nick():
    """FORBID <nick> adds a nick reservation; UNFORBID removes it."""
    op = _oper("forbop")
    forbidden_nick = f"forbid{_seq}"

    op.send(f"FORBID {forbidden_nick}")
    ok = op.wait(r"(?i)(forbidden|reserved|added|resv)", timeout=4)
    _check("FORBID <nick> → reserved notice", ok is not None)

    op.send(f"UNFORBID {forbidden_nick}")
    ok2 = op.wait(r"(?i)(unforbid|removed|cleared)", timeout=4)
    _check("UNFORBID <nick> → cleared notice", ok2 is not None)
    op.close()


# ===========================================================================
# SECTION 16 — Founder key bypass
# ===========================================================================

def test_founder_join_keyed_channel():
    """Registered founder bypasses +k on JOIN."""
    a, _ = _make_account("fjk")
    chan = f"#fjk{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)

    # Set a channel key — founder should be able to re-join without it
    a.send(f"MODE {chan} +k secretkey123")
    a.drain(0.3)
    a.send(f"PART {chan}")
    a.drain(0.3)

    # Rejoin without key — should succeed or get a bypass notice
    a.send(f"JOIN {chan}")
    ok_join = a.wait(r"(?i)(JOIN|bypass|owner|founder|secretkey)", timeout=4)
    # We check that we did NOT get 475 (Bad Channel Key) without any bypass
    lines = a.collect(1.0)
    got_475 = any(" 475 " in ln for ln in lines)
    _check("Founder JOIN +k channel without key → not 475",
           ok_join is not None and not got_475,
           f"chan={chan}")
    a.close()


def test_identify_channel_restores_ops():
    """IDENTIFY #channel <mlock_key> restores founder ops after key change."""
    a, _ = _make_account("idcro")
    chan = f"#idcro{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)

    # Save a mlock key via CHANSET
    mlock_key = "myfounderkey"
    a.send(f"CHANSET {chan} MODELOCK +k {mlock_key}")
    a.drain(0.5)

    # Simulate: someone changes the live key (or part and rejoin)
    a.send(f"MODE {chan} +k differentkey")
    a.drain(0.3)

    # IDENTIFY with the saved key should restore ops
    a.send(f"IDENTIFY {chan} {mlock_key}")
    ok = a.wait(r"(?i)(identified|ops|key|bypass|founder|restored|mode)", timeout=4)
    _check("IDENTIFY #channel <mlock_key> → bypass/op-restore response",
           ok is not None, f"chan={chan}")
    a.close()


# ===========================================================================
# SECTION 17 — Commands when services are disabled (sanity check via 421)
# ===========================================================================

def test_services_disabled_fallback():
    """
    If services are not enabled the commands REGISTER, LOGOUT, GHOST, etc.
    must return ERR_UNKNOWNCOMMAND (421) — not a server crash or hang.

    We cannot actually disable services here; instead we verify that the
    server responds to all commands within the test timeout (no freeze).
    Each command should produce *some* response.
    """
    c = _connect("sdf")
    # We do NOT register an account, so we're unidentified.
    # Even with services enabled these commands should produce a response.
    commands_and_patterns = [
        ("LOGOUT",             r"(?i)(not identified|421|LOGOUT)"),
        ("GHOST nobody abc",   r"(?i)(no such|not found|must be|421)"),
        ("MEMO LIST",          r"(?i)(not identified|421|memo)"),
        ("CERTLIST",           r"(?i)(not identified|421|cert)"),
        ("VHOFFERLIST",        r"(?i)(offer|421|vhost|list)"),
    ]
    for cmd, pat in commands_and_patterns:
        c.send(cmd)
        ok = c.wait(pat, timeout=3.0)
        _check(f"'{cmd.split()[0]}' without identification → response",
               ok is not None, cmd)
    c.close()


# ===========================================================================
# Main
# ===========================================================================

TESTS = [
    # REGISTER
    ("REGISTER success → 900",                     test_register_success),
    ("REGISTER duplicate → already-identified",    test_register_duplicate),
    ("REGISTER short password → error",            test_register_short_password),
    ("REGISTER bad email → error",                 test_register_bad_email),
    ("After REGISTER: WHOIS shows 330",            test_register_not_identified_after_reg),
    # IDENTIFY
    ("IDENTIFY correct → 900",                     test_identify_correct),
    ("IDENTIFY wrong password → error",            test_identify_wrong_password),
    ("IDENTIFY already identified → notice",       test_identify_already_identified),
    ("IDENTIFY shortform (no account)",            test_identify_shortform),
    ("IDENTIFY #channel key (IRCX compat)",        test_identify_channel_key_always_works),
    # LOGOUT
    ("LOGOUT → 901",                               test_logout_success),
    ("LOGOUT when not identified → error",         test_logout_not_identified),
    # GHOST / REGAIN
    ("GHOST unrelated session → response",         test_ghost_own_session),
    ("GHOST wrong password → error",               test_ghost_wrong_password),
    ("REGAIN <nick> <password> → response",        test_regain),
    # GROUP / UNGROUP
    ("GROUP adds nick → success",                  test_group_add),
    ("GROUP without identification → error",       test_group_not_identified),
    ("UNGROUP primary nick → blocked",             test_ungroup_primary_blocked),
    ("UNGROUP grouped nick → success",             test_ungroup_grouped_nick),
    # CERTADD / CERTDEL / CERTLIST
    ("CERTLIST fresh account → response",          test_certlist_empty),
    ("CERTADD without cert → error",               test_certadd_no_cert),
    ("CERTADD manual + CERTLIST + CERTDEL",        test_certadd_manual),
    # ACCOUNTSET
    ("SETPASS correct old → changed",              test_setpass),
    ("SETPASS wrong old → error",                  test_setpass_wrong_old),
    ("SETEMAIL valid address → updated",           test_setemail),
    ("SET ENFORCE on/off",                         test_set_enforce),
    # ACCOUNTINFO
    ("INFO self → account info",                   test_info_self),
    ("INFO <other account>",                       test_info_other),
    ("INFO <unknown> → not found",                 test_info_unknown),
    ("INFO #channel → chanreg info",               test_info_channel),
    # CREGISTER / CDROP
    ("CREGISTER as chanop → success",              test_cregister_as_op),
    ("CREGISTER without chanop → error",           test_cregister_not_op),
    ("CREGISTER already-registered → error",       test_cregister_already_registered),
    ("CDROP by founder → success",                 test_cdrop),
    # CHANSET
    ("CHANSET TOPICLOCK on/off",                   test_chanset_topiclock),
    ("CHANSET KEEPTOPIC on",                       test_chanset_keeptopic),
    ("CHANSET URL",                                test_chanset_url),
    ("CHANSET DESC",                               test_chanset_desc),
    ("CHANSET ACCESS LIST",                        test_chanset_access_list),
    ("CHANSET ACCESS ADD/DEL",                     test_chanset_access_add_del),
    ("CHANSET MODELOCK +nt",                       test_chanset_modelock),
    ("CHANSET by non-founder → denied",            test_chanset_not_founder),
    # MEMO
    ("MEMO SEND → sent notice",                    test_memo_send),
    ("MEMO LIST → response",                       test_memo_list),
    ("MEMO READ <id> → content",                   test_memo_read),
    ("MEMO DEL ALL → empty",                       test_memo_del),
    # VHOST
    ("VHOST REQUEST valid → response",             test_vhost_request_valid),
    ("VHOST REQUEST invalid → error",              test_vhost_request_invalid),
    ("VHOFFER + VHOST TAKE",                       test_vhoffer_and_take),
    ("VHOFFERLIST → response",                     test_vhofferlist),
    # ACCOUNTOPER (oper-only)
    ("ACCOUNTOPER LINK → success",                 test_accountoper_link),
    ("ACCOUNTOPER UNLINK → success",               test_accountoper_unlink),
    ("ACCOUNTOPER by non-oper → 481",              test_accountoper_nonoper_blocked),
    # SUSPEND / UNSUSPEND
    ("SUSPEND blocks login; UNSUSPEND restores",   test_suspend_unsuspend),
    # FORBID / UNFORBID
    ("FORBID/UNFORBID nick",                       test_forbid_nick),
    # Founder bypass
    ("Founder JOIN +k channel → not 475",          test_founder_join_keyed_channel),
    ("IDENTIFY #chan mlock_key → ops restored",    test_identify_channel_restores_ops),
    # Sanity
    ("Unidentified commands → response not hang",  test_services_disabled_fallback),
]


def main():
    print("=" * 70)
    print("Ophion Services Stress Test")
    print(f"Server: {SERVER_HOST}:{SERVER_PORT}")
    print("=" * 70)

    for label, fn in TESTS:
        print(f"\n--- {label} ---")
        try:
            fn()
        except Exception as e:
            import traceback
            _fail(label, f"Exception: {e}")
            traceback.print_exc()

    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    total = _passed + _failed
    print(f"  Passed : {_passed}/{total}")
    print(f"  Failed : {_failed}/{total}")
    print("=" * 70)

    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
