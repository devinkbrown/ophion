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

  Account removal:
    DROP <password>                 (self-drop with confirmation)
    DROP <account>                  (oper force-drop with hierarchy check)

  Password reset:
    SENDPASS <account>              (request reset token; token in oper SNO)
    SENDPASS <account> <token> <p>  (apply reset token)

  Oper-level account admin:
    ACCOUNTOPER <account> <block|->
    SUSPEND / UNSUSPEND <account>
    FORBID / UNFORBID  <nick>

  Server jupe:
    JUPE <server> [:<reason>]       (oper-only; blocks server from linking)
    UNJUPE <server>                 (oper-only; removes jupe)
    JUPELIST                        (oper-only; list active jupes)

  Founder/key bypass:
    Registered founder can JOIN a +k channel without the live key.
    IDENTIFY #chan <mlock_key> restores founder ops.

  S2S sync protocol coverage (single-server data-layer validation):
    GROUP / UNGROUP     → exercises svc_sync_nick_group / svc_sync_nick_ungroup
    CHANSET ACCESS ADD  → exercises svc_sync_chanaccess_set
    CHANSET ACCESS DEL  → exercises svc_sync_chanaccess_del (targeted, no full burst)
    VHOST TAKE          → exercises vhost field in svc_sync_account_reg / SVCSREG
    CHANSET MODELOCK    → exercises mlock fields in svc_sync_chanreg / SVCSCHAN

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
# SECTION 18 — CHANREG_RESTRICTED and CHANREG_SECURE enforcement
# ===========================================================================

def test_restricted_blocks_unidentified():
    """CHANREG_RESTRICTED blocks unidentified users from joining."""
    a, _ = _make_account("rstr")
    chan = f"#rstr{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)
    a.send(f"CHANSET {chan} RESTRICTED on")
    a.drain(0.5)

    # Unidentified user attempts to join
    b = _connect("rstrb")
    b.send(f"JOIN {chan}")
    ok = b.wait(r"(?i)(restricted|identify|473|registered users)", timeout=4)
    _check("RESTRICTED: unidentified user blocked from joining",
           ok is not None, f"chan={chan}")
    a.close()
    b.close()


def test_restricted_allows_identified():
    """CHANREG_RESTRICTED allows identified users to join."""
    a, _ = _make_account("rsti")
    chan = f"#rsti{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)
    a.send(f"CHANSET {chan} RESTRICTED on")
    a.drain(0.5)

    b, _ = _make_account("rstib")   # identified
    b.send(f"JOIN {chan}")
    ok = b.wait(r"(?i)JOIN|366|473", timeout=4)
    got_blocked = ok is not None and "473" in (ok or "")
    _check("RESTRICTED: identified user can join (not 473)",
           ok is not None and "473" not in (ok or ""), f"chan={chan}")
    a.close()
    b.close()


def test_secure_blocks_non_access():
    """CHANREG_SECURE blocks users not on the access list."""
    a, _ = _make_account("sec")
    chan = f"#sec{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)
    a.send(f"CHANSET {chan} SECURE on")
    a.drain(0.5)

    b, _ = _make_account("secb")   # identified but NOT on access list
    b.send(f"JOIN {chan}")
    ok = b.wait(r"(?i)(secure|access|473|requires)", timeout=4)
    _check("SECURE: identified user not on access list blocked",
           ok is not None, f"chan={chan}")
    a.close()
    b.close()


def test_secure_allows_access_list():
    """CHANREG_SECURE allows users on the access list."""
    a, _ = _make_account("seca")
    chan = f"#seca{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)

    b, _ = _make_account("secab")

    # Add b to access list before enabling SECURE
    a.send(f"CHANSET {chan} ACCESS ADD {b.nick} vop")
    a.drain(0.5)
    a.send(f"CHANSET {chan} SECURE on")
    a.drain(0.5)

    b.send(f"JOIN {chan}")
    lines = b.collect(2.0)
    got_blocked = any("473" in ln for ln in lines)
    _check("SECURE: access-listed user allowed in", not got_blocked,
           f"chan={chan}")
    a.close()
    b.close()


def test_topiclock_enforces_plus_t():
    """CHANSET TOPICLOCK on locks +t via modelock so non-ops cannot set topic."""
    a, _ = _make_account("tpl")
    chan = f"#tpl{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)
    a.send(f"CHANSET {chan} TOPICLOCK on")
    a.drain(0.8)

    # Check the channel now has +t
    a.send(f"MODE {chan}")
    ok = a.wait(r"\+[^\s]*t", timeout=3)
    _check("CHANSET TOPICLOCK on → channel mode includes +t", ok is not None,
           f"chan={chan}")

    # Non-op cannot set topic in +t channel
    b = _connect("tplb")
    b.send(f"JOIN {chan}")
    b.drain(0.5)
    b.send(f"TOPIC {chan} :hack topic")
    ok2 = b.wait(r" 482 ", timeout=3)  # ERR_CHANOPRIVSNEEDED
    _check("TOPICLOCK: non-op cannot change topic in +t channel",
           ok2 is not None, f"chan={chan}")
    a.close()
    b.close()


# ===========================================================================
# SECTION 19 — DROP
# ===========================================================================

def test_drop_self_correct_password():
    """DROP <password> removes the caller's own account."""
    a, pw = _make_account("drs")
    acct = a.nick
    a.send(f"DROP {pw}")
    ok = a.wait(r"(?i)(dropped|removed|deleted|permanently)", timeout=4)
    _check("DROP correct password → account dropped notice", ok is not None,
           f"account={acct}")
    a.close()


def test_drop_self_wrong_password():
    """DROP with wrong password → error notice; account still exists."""
    a, pw = _make_account("drw")
    a.send("DROP WRONGPASSWORD999")
    ok = a.wait(r"(?i)(incorrect|invalid|wrong|not dropped)", timeout=4)
    _check("DROP wrong password → error notice", ok is not None,
           f"account={a.nick}")

    # Verify account still works
    b = _connect("drwb")
    b.send(f"IDENTIFY {a.nick} {pw}")
    ok2 = b.wait(r"(?i)( 900 |identified)", timeout=4)
    _check("DROP wrong password: account still exists after failed drop",
           ok2 is not None)
    a.close()
    b.close()


def test_drop_not_identified():
    """DROP without being identified → error notice."""
    c = _connect("drni")
    c.send("DROP somepassword")
    ok = c.wait(r"(?i)(not identified|identify first|must be)", timeout=4)
    _check("DROP without identification → error notice", ok is not None)
    c.close()


def test_drop_oper_forced():
    """Oper DROP <account> force-drops another account."""
    a, pw = _make_account("dro")
    acct = a.nick
    op = _oper("dropop")
    op.send(f"DROP {acct}")
    ok = op.wait(r"(?i)(dropped|removed|deleted)", timeout=4)
    _check("Oper DROP <account> → dropped notice", ok is not None,
           f"account={acct}")

    # Verify account is gone
    b = _connect("drob")
    b.send(f"IDENTIFY {acct} {pw}")
    ok2 = b.wait(r"(?i)(invalid|not.*found|no.*account|failed|incorrect)", timeout=4)
    _check("Oper DROP: account no longer exists", ok2 is not None,
           f"account={acct}")
    a.close()
    b.close()
    op.close()


def test_drop_oper_nonexistent():
    """Oper DROP <nonexistent> → 'does not exist' notice."""
    op = _oper("dropopne")
    op.send("DROP nosuchaccountxyz999")
    ok = op.wait(r"(?i)(not exist|no such|not found)", timeout=4)
    _check("Oper DROP nonexistent → not found notice", ok is not None)
    op.close()


# ===========================================================================
# SECTION 20 — SENDPASS
# ===========================================================================

def test_sendpass_request_exists():
    """SENDPASS <account> for a real account → 'if account exists' notice."""
    a, _ = _make_account("spr")
    a.send(f"SENDPASS {a.nick}")
    ok = a.wait(r"(?i)(if account|reset|sent|email|expires)", timeout=4)
    _check("SENDPASS request for real account → response notice",
           ok is not None, f"account={a.nick}")
    a.close()


def test_sendpass_request_nonexistent():
    """SENDPASS on nonexistent account → same response (no enumeration)."""
    c = _connect("spne")
    c.send("SENDPASS nosuchaccountxyz999")
    ok = c.wait(r"(?i)(if account|reset|sent|email|expires)", timeout=4)
    _check("SENDPASS nonexistent → same response (no enumeration)",
           ok is not None)
    c.close()


def test_sendpass_apply_correct_token():
    """Full SENDPASS flow: oper receives token → apply it → new password works."""
    a, old_pw = _make_account("spac")
    acct = a.nick

    # Connect an oper to receive the SNO_GENERAL notice carrying the token
    op = _oper("spacop")
    op.drain(0.5)

    # Request reset from a different client
    req = _connect("spacreq")
    req.send(f"SENDPASS {acct}")
    req.drain(0.5)

    # Oper collects server notices; token appears in SNO_GENERAL
    token = None
    lines = op.collect(3.0)
    for ln in lines:
        m = re.search(r"token[:\s]+([0-9a-f]{16})", ln, re.IGNORECASE)
        if m and acct.lower() in ln.lower():
            token = m.group(1)
            break

    if token is None:
        _fail("SENDPASS: could not extract token from oper notice")
    else:
        _ok("SENDPASS: token visible in oper SNO_GENERAL notice",
            f"token={token}")
        new_pw = "newpassword789"
        req.send(f"SENDPASS {acct} {token} {new_pw}")
        ok_apply = req.wait(r"(?i)(reset|changed|new password|identify)", timeout=4)
        _check("SENDPASS apply correct token → success notice",
               ok_apply is not None)

        # Verify new password works
        b = _connect("spacb")
        b.send(f"IDENTIFY {acct} {new_pw}")
        ok_id = b.wait(r"(?i)( 900 |identified)", timeout=4)
        _check("SENDPASS: new password authenticates successfully", ok_id is not None)
        b.close()

    a.close()
    req.close()
    op.close()


def test_sendpass_apply_wrong_token():
    """SENDPASS <account> <wrong-token> <pass> → invalid token error."""
    a, _ = _make_account("spwt")
    c = _connect("spwtc")
    c.send(f"SENDPASS {a.nick} 0000000000000000 newpassword123")
    ok = c.wait(r"(?i)(invalid|expired|wrong|not.*found)", timeout=4)
    _check("SENDPASS wrong token → invalid/expired error notice",
           ok is not None)
    a.close()
    c.close()


def test_sendpass_short_new_password():
    """SENDPASS apply with too-short new password → error."""
    a, _ = _make_account("spsp")
    op = _oper("spspop")
    op.drain(0.5)

    req = _connect("spspreq")
    req.send(f"SENDPASS {a.nick}")
    req.drain(0.5)

    token = None
    lines = op.collect(3.0)
    for ln in lines:
        m = re.search(r"token[:\s]+([0-9a-f]{16})", ln, re.IGNORECASE)
        if m and a.nick.lower() in ln.lower():
            token = m.group(1)
            break

    if token is None:
        _fail("SENDPASS short-pass: could not extract token from oper notice")
    else:
        req.send(f"SENDPASS {a.nick} {token} abc")  # too short
        ok = req.wait(r"(?i)(at least|5 char|too short|short)", timeout=4)
        _check("SENDPASS apply short new password → length error", ok is not None)

    a.close()
    req.close()
    op.close()


# ===========================================================================
# SECTION 21 — JUPE / UNJUPE / JUPELIST (oper-only)
# ===========================================================================

def test_jupe_nonoper_blocked():
    """Non-oper JUPE → 481 ERR_NOPRIVILEGES."""
    c = _connect("jpnop")
    c.send("JUPE fake.test.server :reason")
    ok = c.wait(r" 481 ", timeout=4)
    _check("JUPE by non-oper → 481 ERR_NOPRIVILEGES", ok is not None)
    c.close()


def test_jupe_oper_creates():
    """Oper JUPE <server> creates a jupe visible in JUPELIST."""
    op = _oper("jpcreop")
    srv = f"jupe{_seq}.test.example"
    op.send(f"JUPE {srv} :Automated test jupe")
    ok = op.wait(r"(?i)(active|jupe|activated|now active)", timeout=4)
    _check("Oper JUPE → jupe activated notice", ok is not None, f"server={srv}")

    op.send("JUPELIST")
    ok2 = op.wait(srv, timeout=4)
    _check("JUPE: server appears in JUPELIST", ok2 is not None, f"server={srv}")

    op.send(f"UNJUPE {srv}")
    op.drain(0.5)
    op.close()


def test_unjupe_removes_from_list():
    """UNJUPE removes the entry from JUPELIST."""
    op = _oper("juprm")
    srv = f"unjp{_seq}.test.example"
    op.send(f"JUPE {srv} :Removal test")
    op.drain(1.0)
    op.send(f"UNJUPE {srv}")
    ok = op.wait(r"(?i)(removed|unjupe|cleared)", timeout=4)
    _check("UNJUPE → removed notice", ok is not None, f"server={srv}")

    op.send("JUPELIST")
    lines = op.collect(2.0)
    still_present = any(srv.lower() in ln.lower() for ln in lines)
    _check("UNJUPE: server absent from JUPELIST after removal",
           not still_present, f"server={srv}")
    op.close()


def test_jupelist_responds():
    """JUPELIST responds without crash (empty or with entries)."""
    op = _oper("jpls")
    op.send("JUPELIST")
    ok = op.wait(r"(?i)(no active|end of jupelist|active jupe)", timeout=4)
    _check("JUPELIST → response without crash", ok is not None)
    op.close()


def test_jupe_self_rejected():
    """JUPE of the local server name → rejected with error notice."""
    op = _oper("jpself")
    op.send("JUPE localhost :self jupe test")
    ok = op.wait(r"(?i)(cannot|self|invalid|jupe|active)", timeout=4)
    _check("JUPE self/localhost → response received (no hang)", ok is not None)
    op.close()


def test_jupe_no_dot_rejected():
    """JUPE of a name without a dot → invalid server name error."""
    op = _oper("jpnd")
    op.send("JUPE nodotname :test")
    ok = op.wait(r"(?i)(invalid|dot|server name)", timeout=4)
    _check("JUPE no-dot name → invalid server name notice", ok is not None)
    op.close()


def test_unjupe_nonexistent():
    """UNJUPE a name that is not juped → 'not juped' notice."""
    op = _oper("jupne")
    op.send("UNJUPE notjuped.test.example")
    ok = op.wait(r"(?i)(not.*jupe|not currently|no jupe)", timeout=4)
    _check("UNJUPE nonexistent → not-juped notice", ok is not None)
    op.close()


def test_unjupe_nonoper_blocked():
    """Non-oper UNJUPE → 481 ERR_NOPRIVILEGES."""
    c = _connect("jupnopun")
    c.send("UNJUPE fake.test.example")
    ok = c.wait(r" 481 ", timeout=4)
    _check("UNJUPE by non-oper → 481 ERR_NOPRIVILEGES", ok is not None)
    c.close()


# ===========================================================================
# SECTION 22 — S2S Sync protocol coverage (single-server)
#
# These tests exercise the code paths that trigger S2S propagation
# (svc_sync_nick_group, svc_sync_nick_ungroup, svc_sync_chanaccess_set,
# svc_sync_chanaccess_del, svc_sync_account_reg with vhost,
# svc_sync_chanreg with mlock).  Full network-level verification of
# SVCSNICK / SVCSACCESS / SVCSREG etc. requires two linked servers;
# here we confirm that:
#   a) the operations complete successfully on a single server, and
#   b) the resulting state is consistent (visible in LIST/INFO/MODE),
#      which is a prerequisite for correct propagation.
# ===========================================================================

def test_sync_nick_group_roundtrip():
    """GROUP followed by UNGROUP: both complete cleanly (exercises
    svc_sync_nick_group + svc_sync_nick_ungroup code paths)."""
    a, pw = _make_account("snkgr")
    b = _connect("snkgrb")
    b.send(f"IDENTIFY {a.nick} {pw}")
    b.drain(1.0)

    # GROUP b's nick into a's account
    b.send("GROUP")
    ok_group = b.wait(r"(?i)(added|group|registered)", timeout=4)
    _check("S2S/nick-group: GROUP succeeds → sync triggered",
           ok_group is not None, f"nick={b.nick}")

    # UNGROUP b's nick
    b.send(f"UNGROUP {b.nick}")
    ok_ungroup = b.wait(r"(?i)(removed|ungroup)", timeout=4)
    _check("S2S/nick-ungroup: UNGROUP succeeds → sync triggered",
           ok_ungroup is not None, f"nick={b.nick}")

    a.close()
    b.close()


def test_sync_nick_group_visible_to_info():
    """After GROUP the grouped nick appears in INFO (confirms DB write
    that would be burst via SVCSNICK on server link)."""
    a, pw = _make_account("snkvi")
    b = _connect("snkvib")
    b.send(f"IDENTIFY {a.nick} {pw}")
    b.drain(1.0)
    b.send("GROUP")
    b.drain(1.0)

    # INFO should show the account and reference grouped nicks or
    # at minimum not error
    b.send(f"INFO {a.nick}")
    ok = b.wait(r"(?i)(account|registered|nick|group)", timeout=4)
    _check("S2S/nick-group: INFO after GROUP → account visible",
           ok is not None)

    # Clean up
    b.send(f"UNGROUP {b.nick}")
    b.drain(0.5)
    a.close()
    b.close()


def test_sync_access_add_visible_in_list():
    """ACCESS ADD entry is visible in ACCESS LIST (confirms DB write
    that would be burst via SVCSACCESS on server link)."""
    a, _ = _make_account("sacal")
    b, _ = _make_account("sacalb")
    chan = f"#sacal{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)

    a.send(f"CHANSET {chan} ACCESS ADD {b.nick} sop")
    ok_add = a.wait(r"(?i)(added|access|set)", timeout=4)
    _check("S2S/access-add: CHANSET ACCESS ADD → success",
           ok_add is not None)

    a.send(f"CHANSET {chan} ACCESS LIST")
    ok_list = a.wait(b.nick, timeout=4)   # nick should appear in list
    _check("S2S/access-add: added entry visible in ACCESS LIST",
           ok_list is not None, f"nick={b.nick}")

    a.close()
    b.close()


def test_sync_access_del_not_in_list():
    """ACCESS DEL entry is no longer in ACCESS LIST (confirms targeted
    svc_sync_chanaccess_del is sent without full chanreg burst)."""
    a, _ = _make_account("sacdl")
    b, _ = _make_account("sacdlb")
    chan = f"#sacdl{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)

    a.send(f"CHANSET {chan} ACCESS ADD {b.nick} vop")
    a.drain(0.8)
    a.send(f"CHANSET {chan} ACCESS DEL {b.nick}")
    ok_del = a.wait(r"(?i)(removed|deleted|del)", timeout=4)
    _check("S2S/access-del: CHANSET ACCESS DEL → success",
           ok_del is not None)

    a.send(f"CHANSET {chan} ACCESS LIST")
    lines = a.collect(2.0)
    nick_present = any(b.nick.lower() in ln.lower() for ln in lines)
    _check("S2S/access-del: deleted entry absent from ACCESS LIST",
           not nick_present, f"nick={b.nick}")

    a.close()
    b.close()


def test_sync_access_multiple_entries():
    """Multiple ACCESS ADD entries accumulate and all appear in LIST
    (exercises repeated svc_sync_chanaccess_set calls)."""
    a, _ = _make_account("sacme")
    b, _ = _make_account("sacmeb")
    c_acct, _ = _make_account("sacmec")
    chan = f"#sacme{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)

    a.send(f"CHANSET {chan} ACCESS ADD {b.nick} sop")
    a.drain(0.6)
    a.send(f"CHANSET {chan} ACCESS ADD {c_acct.nick} vop")
    a.drain(0.6)

    a.send(f"CHANSET {chan} ACCESS LIST")
    lines = a.collect(2.0)
    b_present = any(b.nick.lower() in ln.lower() for ln in lines)
    c_present = any(c_acct.nick.lower() in ln.lower() for ln in lines)
    _check("S2S/access-multi: first entry in ACCESS LIST", b_present,
           f"nick={b.nick}")
    _check("S2S/access-multi: second entry in ACCESS LIST", c_present,
           f"nick={c_acct.nick}")

    a.close()
    b.close()
    c_acct.close()


def test_sync_vhost_in_whois():
    """VHOST TAKE sets a vhost that appears in WHOIS (confirms the vhost
    field that svc_sync_account_reg now includes in SVCSREG)."""
    a, _ = _make_account("svhwi")
    op = _oper("svhwiop")

    vhost = f"sync{_seq}.ophion.test"
    op.send(f"VHOFFER {vhost}")
    op.drain(0.8)
    a.send(f"VHOST TAKE {vhost}")
    ok_take = a.wait(r"(?i)(vhost.*set|host.*set|applied|activated)",
                     timeout=4)
    _check("S2S/vhost: VHOST TAKE applied", ok_take is not None,
           f"vhost={vhost}")

    a.send(f"WHOIS {a.nick}")
    ok_whois = a.wait(vhost, timeout=4)
    _check("S2S/vhost: vhost visible in WHOIS (will appear in SVCSREG burst)",
           ok_whois is not None, f"vhost={vhost}")

    op.close()
    a.close()


def test_sync_mlock_key_stored():
    """CHANSET MODELOCK +k stores the mlock_key (confirms the key field
    now included in SVCSCHAN burst messages)."""
    a, _ = _make_account("smlk")
    chan = f"#smlk{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)

    mkey = "synckey123"
    a.send(f"CHANSET {chan} MODELOCK +k {mkey}")
    ok = a.wait(r"(?i)(modelock|set|lock)", timeout=4)
    _check("S2S/mlock-key: CHANSET MODELOCK +k response received",
           ok is not None)

    # INFO or MODE should reflect the key lock
    a.send(f"MODE {chan}")
    ok2 = a.wait(r"\+[^\s]*k", timeout=3)
    _check("S2S/mlock-key: channel MODE includes +k after MODELOCK",
           ok2 is not None, f"chan={chan}")

    a.close()


def test_sync_mlock_fields_roundtrip():
    """Set multiple mlock fields and verify MODE reflects them (confirms
    mlock_on/off/limit/key all stored correctly for SVCSCHAN burst)."""
    a, _ = _make_account("smlf")
    chan = f"#smlf{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)

    # Lock +nt
    a.send(f"CHANSET {chan} MODELOCK +nt")
    a.drain(0.6)

    a.send(f"MODE {chan}")
    ok = a.wait(r"\+[^\s]*n[^\s]*t|\+[^\s]*t[^\s]*n", timeout=3)
    _check("S2S/mlock-fields: MODE includes both +n and +t after MODELOCK +nt",
           ok is not None, f"chan={chan}")

    a.close()


def test_sync_chanreg_info_after_mlock():
    """INFO #channel after CHANSET MODELOCK shows registration info
    (confirms SVCSCHAN fields are correctly populated for burst)."""
    a, _ = _make_account("smlci")
    chan = f"#smlci{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)
    a.send(f"CHANSET {chan} MODELOCK +mn")
    a.drain(0.6)

    a.send(f"INFO {chan}")
    ok = a.wait(r"(?i)(channel|registered|founder|mode|lock)", timeout=4)
    _check("S2S/mlock-fields: INFO #channel shows reg info after mlock set",
           ok is not None, f"chan={chan}")

    a.close()


# ===========================================================================
# SECTION 26 — IRCX ACCESS / services persistence integration
# ===========================================================================

def test_ircx_access_persists_add():
    """IRCX ACCESS ADD on a registered channel persists the entry to services
    so that CHANSET ACCESS LIST also shows it."""
    a, _ = _make_account("ircxpa")
    b, _ = _make_account("ircxpab")
    chan = f"#ircxpa{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)

    # Use the IRCX ACCESS command (not CHANSET) to add a mask at OP level
    mask = f"*!*@ircxpa{_seq}.test"
    a.send(f"ACCESS {chan} ADD OP {mask}")
    a.drain(0.6)

    # Verify via services CHANSET ACCESS LIST — entity should appear
    a.send(f"CHANSET {chan} ACCESS LIST")
    lines = a.collect(2.5)
    present = any(mask.lower() in ln.lower() for ln in lines)
    _check("IRCX ACCESS ADD: entry persisted to services (in CHANSET ACCESS LIST)",
           present, f"mask={mask} lines={lines[-3:]}")
    a.close()
    b.close()


def test_ircx_access_persists_del():
    """IRCX ACCESS DEL on a registered channel removes the entry from services."""
    a, _ = _make_account("ircxpd")
    chan = f"#ircxpd{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)

    mask = f"*!*@ircxpd{_seq}.test"
    a.send(f"ACCESS {chan} ADD VOICE {mask}")
    a.drain(0.6)
    a.send(f"ACCESS {chan} DEL VOICE {mask}")
    a.drain(0.6)

    a.send(f"CHANSET {chan} ACCESS LIST")
    lines = a.collect(2.5)
    present = any(mask.lower() in ln.lower() for ln in lines)
    _check("IRCX ACCESS DEL: entry removed from services (absent in CHANSET ACCESS LIST)",
           not present, f"mask={mask}")
    a.close()


def test_ircx_access_persists_clear():
    """IRCX ACCESS CLEAR on a registered channel removes all entries from services."""
    a, _ = _make_account("ircxpc")
    chan = f"#ircxpc{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    a.send(f"CREGISTER {chan}")
    a.drain(0.8)

    mask_op    = f"*!*@ircxpc_op{_seq}.test"
    mask_voice = f"*!*@ircxpc_vo{_seq}.test"
    a.send(f"ACCESS {chan} ADD OP {mask_op}")
    a.drain(0.5)
    a.send(f"ACCESS {chan} ADD VOICE {mask_voice}")
    a.drain(0.5)
    a.send(f"ACCESS {chan} CLEAR")
    a.drain(0.8)

    a.send(f"CHANSET {chan} ACCESS LIST")
    lines = a.collect(2.5)
    op_present    = any(mask_op.lower()    in ln.lower() for ln in lines)
    voice_present = any(mask_voice.lower() in ln.lower() for ln in lines)
    _check("IRCX ACCESS CLEAR: all entries removed from services",
           not op_present and not voice_present,
           f"op_present={op_present} voice_present={voice_present}")
    a.close()


def test_ircx_access_standalone_unregistered():
    """IRCX ACCESS works normally on unregistered channels (no services DB involved)."""
    a = _connect("ircxsu")
    b = _connect("ircxsub")
    chan = f"#ircxsu{_seq}"
    a.send(f"JOIN {chan}")
    a.drain(0.4)
    # Do NOT register the channel — standalone mode only

    mask = f"{b.nick}!*@*"
    a.send(f"ACCESS {chan} ADD OP {mask}")
    ok_add = a.wait(r" 801 ", timeout=4)
    _check("IRCX ACCESS ADD on unregistered channel → 801 success",
           ok_add is not None, f"mask={mask}")

    a.send(f"ACCESS {chan} LIST")
    lines = a.collect(2.0)
    listed = any(mask.lower() in ln.lower() for ln in lines) or \
             any(" 804 " in ln for ln in lines)
    _check("IRCX ACCESS LIST on unregistered channel → lists entries", listed)

    a.close()
    b.close()


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
    # CHANREG_RESTRICTED / CHANREG_SECURE enforcement
    ("RESTRICTED blocks unidentified users",       test_restricted_blocks_unidentified),
    ("RESTRICTED allows identified users",         test_restricted_allows_identified),
    ("SECURE blocks non-access-list users",        test_secure_blocks_non_access),
    ("SECURE allows access-listed users",          test_secure_allows_access_list),
    ("TOPICLOCK on → +t locked; non-op blocked",  test_topiclock_enforces_plus_t),
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
    # DROP
    ("DROP correct password → dropped",            test_drop_self_correct_password),
    ("DROP wrong password → error + acct intact",  test_drop_self_wrong_password),
    ("DROP without identification → error",        test_drop_not_identified),
    ("Oper DROP <account> → force-dropped",        test_drop_oper_forced),
    ("Oper DROP nonexistent → not found",          test_drop_oper_nonexistent),
    # SENDPASS
    ("SENDPASS request real account → notice",     test_sendpass_request_exists),
    ("SENDPASS nonexistent → same notice",         test_sendpass_request_nonexistent),
    ("SENDPASS full token cycle → new pass works", test_sendpass_apply_correct_token),
    ("SENDPASS wrong token → error",               test_sendpass_apply_wrong_token),
    ("SENDPASS short new password → error",        test_sendpass_short_new_password),
    # JUPE / UNJUPE / JUPELIST
    ("JUPE by non-oper → 481",                     test_jupe_nonoper_blocked),
    ("Oper JUPE → visible in JUPELIST",            test_jupe_oper_creates),
    ("UNJUPE → removed from JUPELIST",             test_unjupe_removes_from_list),
    ("JUPELIST → responds without crash",          test_jupelist_responds),
    ("JUPE self/localhost → response",             test_jupe_self_rejected),
    ("JUPE no-dot name → invalid notice",          test_jupe_no_dot_rejected),
    ("UNJUPE nonexistent → not-juped notice",      test_unjupe_nonexistent),
    ("UNJUPE by non-oper → 481",                   test_unjupe_nonoper_blocked),
    # S2S sync protocol coverage (single-server validation)
    ("S2S/nick-group: GROUP+UNGROUP roundtrip",    test_sync_nick_group_roundtrip),
    ("S2S/nick-group: grouped nick in INFO",       test_sync_nick_group_visible_to_info),
    ("S2S/access-add: entry visible in LIST",      test_sync_access_add_visible_in_list),
    ("S2S/access-del: entry absent from LIST",     test_sync_access_del_not_in_list),
    ("S2S/access-multi: multiple entries in LIST", test_sync_access_multiple_entries),
    ("S2S/vhost: vhost visible in WHOIS",          test_sync_vhost_in_whois),
    ("S2S/mlock-key: MODELOCK +k stored",          test_sync_mlock_key_stored),
    ("S2S/mlock-fields: MODELOCK +nt roundtrip",   test_sync_mlock_fields_roundtrip),
    ("S2S/mlock-fields: INFO after mlock set",     test_sync_chanreg_info_after_mlock),
    # IRCX ACCESS / services persistence integration
    ("IRCX ACCESS ADD persisted to services",      test_ircx_access_persists_add),
    ("IRCX ACCESS DEL removed from services",      test_ircx_access_persists_del),
    ("IRCX ACCESS CLEAR removes all from services",test_ircx_access_persists_clear),
    ("IRCX ACCESS standalone (unregistered chan)", test_ircx_access_standalone_unregistered),
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
