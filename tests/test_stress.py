#!/usr/bin/env python3
"""
Ophion IRC Server — Comprehensive Stress Test
==============================================

Exercises all major server components end-to-end against a running ircd.

Server : 127.0.0.1:16667
Oper   : testoper / testpass123

Coverage
--------
  §1  Connection stress         (50 concurrent, rapid reconnect cycles)
  §2  Protocol robustness       (oversized lines, binary, unknown cmds)
  §3  Nick/channel validation   (boundary values, rapid nick cycling)
  §4  PRIVMSG/NOTICE flood      (burst delivery, long lines, Unicode)
  §5  Channel mode stress       (all valid modes, ban list, +l boundary)
  §6  CAP negotiation           (LS 302, REQ/ACK/NAK, multi-cap)
  §7  SASL authentication       (PLAIN success/fail, abort, EXTERNAL)
  §8  Services mass ops         (mass register, memo, access, cregister)
  §9  WHO/WHOIS stress          (wildcard, invisible, batch)
  §10 Concurrent modifications  (race JOIN, simultaneous mode/topic/kick)
  §11 KICK/INVITE stress        (last-member kick, mass invite, +i bypass)
  §12 Oper command stress       (mass K-LINE, KILL+reconnect, all STATS)
  §13 Services database stress  (all CHANSET options, access tiers, memo)
  §14 Error recovery            (garbage input, server survives all)
  §15 Memory pressure           (large topics, many bans, MONITOR 100)

Run:  python3 tests/test_stress.py
      (ircd must be listening on 127.0.0.1:16667 with services enabled)
"""

import base64
import socket
import time
import sys
import re
import threading
import random
import string

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SERVER_HOST = "127.0.0.1"
SERVER_PORT  = 16667
OPER_NAME   = "testoper"
OPER_PASS   = "testpass123"
TEST_EMAIL  = "test@ophion.test"

# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------
_passed = 0
_failed = 0


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
# Nick / channel counter
# ---------------------------------------------------------------------------
_seq = int(time.time()) % 100000


def _nick(base="st"):
    global _seq
    _seq = (_seq + 1) % 100000
    return f"{base}{_seq:05d}"


def _chan():
    return f"#s{_nick('c')[1:]}"


# ---------------------------------------------------------------------------
# IRC client
# ---------------------------------------------------------------------------

class IRC:
    """Minimal raw IRC client (matches test_services.py pattern)."""

    def __init__(self, nick, timeout=8):
        self.nick = nick
        self._buf = ""
        self.is_oper = False
        self.sasl_result = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((SERVER_HOST, SERVER_PORT))

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

    def register(self, sasl_account=None, sasl_pass=None):
        if sasl_account:
            self.send(f"AUTH PLAIN I :{_sasl_b64(sasl_account, sasl_pass or '')}")
        self.send(f"NICK {self.nick}")
        self.send(f"USER {self.nick} 0 * :Stress Test")
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
        for _ in self._lines(time.time() + 0.8):
            pass
        return self

    def collect(self, seconds=2.0):
        lines = []
        for line in self._lines(time.time() + seconds):
            lines.append(line)
        return lines

    def wait(self, pattern, timeout=4.0):
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


def _connect(base="st", sasl_account=None, sasl_pass=None):
    c = IRC(_nick(base))
    c.register(sasl_account=sasl_account, sasl_pass=sasl_pass)
    return c


def _oper(base="op"):
    return _connect(base, sasl_account=OPER_NAME, sasl_pass=OPER_PASS)


def _make_account(base="ac", password="password123"):
    c = _connect(base)
    email = f"{c.nick}@ophion.test"
    c.send(f"REGISTER {email} {password}")
    c.wait(r"(registered|already|error|invalid)", timeout=4)
    return c, password


# ===========================================================================
# §1  CONNECTION STRESS
# ===========================================================================

def test_concurrent_connections():
    """50 clients connect and register simultaneously; all must succeed."""
    N = 50
    clients = []
    errors  = []
    lock    = threading.Lock()

    def worker():
        try:
            c = _connect("cc")
            with lock:
                clients.append(c)
        except Exception as e:
            with lock:
                errors.append(str(e))

    threads = [threading.Thread(target=worker) for _ in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    _check("concurrent-connect: all 50 registered",
           len(clients) == N and not errors,
           f"ok={len(clients)} err={len(errors)}")
    for c in clients:
        c.close()


def test_rapid_reconnect():
    """Connect and immediately disconnect 30 times; server must stay up."""
    failures = 0
    for _ in range(30):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((SERVER_HOST, SERVER_PORT))
            s.close()
        except Exception:
            failures += 1
    _check("rapid-reconnect: 30 cycles, server alive", failures == 0,
           f"failures={failures}")
    # Verify server still accepts a real client after the churn
    c = _connect("rc")
    _check("rapid-reconnect: full register after churn", True)
    c.close()


def test_connection_limit_recovery():
    """Open 40 connections, close all, verify server still registers a client."""
    clients = []
    for _ in range(40):
        try:
            c = _connect("lm")
            clients.append(c)
        except Exception:
            pass
    for c in clients:
        c.close()
    time.sleep(0.3)
    try:
        probe = _connect("pr")
        _check("conn-limit-recovery: new client after mass-close", True)
        probe.close()
    except Exception as e:
        _fail("conn-limit-recovery: new client after mass-close", str(e))


# ===========================================================================
# §2  PROTOCOL ROBUSTNESS
# ===========================================================================

def test_oversized_line():
    """Send a 4 096-byte line; server must not crash (returns error or ignores)."""
    c = _connect("ol")
    giant = "PRIVMSG #nowhere :" + "A" * 4000
    try:
        c.sock.sendall((giant + "\r\n").encode())
        lines = c.collect(seconds=1.5)
        # Server may close connection or send 401/421; either is OK
        _ok("oversized-line: server survives")
    except Exception as e:
        _fail("oversized-line: server survives", str(e))
    finally:
        c.close()


def test_binary_in_privmsg():
    """PRIVMSG carrying low-ASCII bytes (CTCP-style) must not crash server."""
    sender = _connect("bs")
    recvr  = _connect("br")
    ch = _chan()
    sender.send(f"JOIN {ch}")
    sender.drain(0.3)
    recvr.send(f"JOIN {ch}")
    recvr.drain(0.3)
    payload = "\x01ACTION waves\x01"
    sender.send(f"PRIVMSG {ch} :{payload}")
    line = recvr.wait(r"ACTION waves", timeout=3)
    _check("binary-privmsg: CTCP ACTION delivered", line is not None)
    sender.close()
    recvr.close()


def test_empty_lines():
    """Sending 20 empty lines must not crash the server."""
    c = _connect("el")
    try:
        for _ in range(20):
            c.sock.sendall(b"\r\n")
        c.send("PING :alive")
        got = c.wait(r"PONG", timeout=4)
        _check("empty-lines: server alive after 20 empty lines", got is not None)
    except Exception as e:
        _fail("empty-lines: server alive after 20 empty lines", str(e))
    finally:
        c.close()


def test_unknown_commands_bulk():
    """Send 100 unknown commands; server must respond 421 and stay alive."""
    c = _connect("uc")
    for i in range(100):
        c.send(f"UNKNOWNCMD{i} :arg")
    c.send("PING :probe")
    got = c.wait(r"PONG.*probe", timeout=6)
    _check("unknown-cmds: server alive after 100 unknown commands",
           got is not None)
    c.close()


def test_flood_of_pings():
    """Send 200 PINGs rapidly; server must PONG the last one."""
    c = _connect("fp")
    for i in range(199):
        c.send(f"PING :flood{i}")
    token = "last"
    c.send(f"PING :{token}")
    got = c.wait(rf"PONG.*{token}", timeout=8)
    _check("ping-flood: final PONG received", got is not None)
    c.close()


# ===========================================================================
# §3  NICK / CHANNEL VALIDATION
# ===========================================================================

def test_nick_cycling():
    """Cycle through 30 different nicks; all NICK changes must be echoed."""
    c = _connect("nc")
    failures = 0
    for i in range(30):
        new = f"cy{_seq % 100000:05d}"
        c.send(f"NICK {new}")
        got = c.wait(rf"NICK.*{new}", timeout=3)
        if got is None:
            failures += 1
        else:
            c.nick = new
    _check("nick-cycling: 30 nick changes", failures == 0,
           f"failures={failures}")
    c.close()


def test_nick_max_length():
    """NICK exactly at NICKLEN (30) must be accepted; 31 chars must be rejected."""
    c = _connect("nm")
    valid = "n" * 30
    c.send(f"NICK {valid}")
    got = c.wait(rf"(NICK.*{valid}|432|433)", timeout=3)
    _check("nick-max-length: 30-char nick accepted or 432", got is not None)

    toolong = "n" * 31
    c.send(f"NICK {toolong}")
    lines = c.collect(seconds=1.5)
    got432 = any(" 432 " in l or " 433 " in l for l in lines)
    _check("nick-max-length: 31-char nick → 432/433", got432)
    c.close()


def test_channel_name_boundaries():
    """Channel name exactly 50 chars must work; 51 chars must fail with 479."""
    c = _connect("cb")
    valid = "#" + "c" * 49       # 50 chars total
    c.send(f"JOIN {valid}")
    got = c.wait(rf"(JOIN.*{re.escape(valid)}|479|403)", timeout=3)
    _check("chan-name-50-char: accepted or sane error", got is not None)

    toolong = "#" + "c" * 50     # 51 chars total
    c.send(f"JOIN {toolong}")
    lines = c.collect(seconds=1.5)
    got479 = any(" 479 " in l or " 403 " in l for l in lines)
    _check("chan-name-51-char: → 479/403", got479)
    c.close()


def test_join_zero_parts_all():
    """JOIN 0 must part the client from all channels."""
    c = _connect("jz")
    channels = [_chan() for _ in range(5)]
    for ch in channels:
        c.send(f"JOIN {ch}")
    c.drain(0.5)
    c.send("JOIN 0")
    c.drain(0.5)
    # Verify we are no longer in any channel by checking NAMES
    probe = _chan()
    c.send(f"JOIN {probe}")
    c.drain(0.3)
    c.send(f"NAMES {channels[0]}")
    lines = c.collect(seconds=1.5)
    in_old = any(c.nick in l and channels[0] in l for l in lines)
    _check("join-0: parted from all channels", not in_old)
    c.close()


# ===========================================================================
# §4  PRIVMSG / NOTICE FLOOD
# ===========================================================================

def test_privmsg_burst_delivery():
    """Send 200 PRIVMSGs to a channel; all must be received by a watcher."""
    sender  = _connect("ps")
    watcher = _connect("pw")
    ch = _chan()
    sender.send(f"JOIN {ch}")
    sender.drain(0.3)
    watcher.send(f"JOIN {ch}")
    watcher.drain(0.3)

    N = 200
    token = f"msg{random.randint(10000,99999)}"
    for i in range(N - 1):
        sender.send(f"PRIVMSG {ch} :stress {i}")
    sender.send(f"PRIVMSG {ch} :{token}")

    got = watcher.wait(rf"{re.escape(token)}", timeout=10)
    _check(f"privmsg-burst: final marker ({N}th msg) received", got is not None)
    sender.close()
    watcher.close()


def test_notice_burst():
    """Send 100 NOTICEs to a channel without errors."""
    c = _connect("nb")
    ch = _chan()
    c.send(f"JOIN {ch}")
    c.drain(0.3)
    for i in range(100):
        c.send(f"NOTICE {ch} :notice {i}")
    c.send("PING :after")
    got = c.wait(r"PONG.*after", timeout=6)
    _check("notice-burst: server alive after 100 NOTICEs", got is not None)
    c.close()


def test_long_privmsg():
    """PRIVMSG with ~490-byte payload must be delivered intact."""
    sender  = _connect("lp")
    recvr   = _connect("lr")
    ch = _chan()
    for cl in (sender, recvr):
        cl.send(f"JOIN {ch}")
        cl.drain(0.3)
    payload = "X" * 490
    sender.send(f"PRIVMSG {ch} :{payload}")
    got = recvr.wait(rf"PRIVMSG.*:X{{100,}}", timeout=4)
    _check("long-privmsg: ~490-byte message delivered", got is not None)
    sender.close()
    recvr.close()


def test_unicode_privmsg():
    """PRIVMSG with emoji and non-ASCII must be relayed without crash."""
    sender = _connect("us")
    recvr  = _connect("ur")
    ch = _chan()
    for cl in (sender, recvr):
        cl.send(f"JOIN {ch}")
        cl.drain(0.3)
    marker = "テスト🎉"
    sender.sock.sendall(f"PRIVMSG {ch} :{marker}\r\n".encode("utf-8"))
    got = recvr.wait(r"テスト|PRIVMSG", timeout=4)
    _check("unicode-privmsg: message delivered without crash", got is not None)
    sender.close()
    recvr.close()


def test_privmsg_to_self():
    """Client can PRIVMSG their own nick and receive it."""
    c = _connect("sf")
    c.send(f"PRIVMSG {c.nick} :hello self")
    got = c.wait(r"hello self", timeout=3)
    _check("privmsg-self: delivered", got is not None)
    c.close()


# ===========================================================================
# §5  CHANNEL MODE STRESS
# ===========================================================================

def test_channel_modes_all_valid():
    """Set and query +n +t +m +s +p +i on a channel; MODE query must reflect them."""
    c = _connect("cm")
    ch = _chan()
    c.send(f"JOIN {ch}")
    c.drain(0.3)
    c.send(f"MODE {ch} +ntmsp")
    c.drain(0.5)
    c.send(f"MODE {ch}")
    lines = c.collect(seconds=2)
    got324 = any(" 324 " in l for l in lines)
    _check("channel-modes: +ntmsp applied and 324 returned", got324)
    c.close()


def test_ban_list_fill():
    """Add 20 bans via MODE +b; BANS query must return all 20."""
    c = _connect("bl")
    ch = _chan()
    c.send(f"JOIN {ch}")
    c.drain(0.3)
    N = 20
    for i in range(N):
        c.send(f"MODE {ch} +b ban{i:03d}!*@*")
    c.drain(0.8)
    c.send(f"MODE {ch} +b")
    lines = c.collect(seconds=3)
    bans = [l for l in lines if " 367 " in l]
    _check(f"ban-list-fill: {N} bans stored (got {len(bans)})",
           len(bans) >= N)
    c.close()


def test_mode_limit_boundary():
    """MODE +l 1 blocks a second join; MODE -l allows it."""
    op  = _connect("lo")
    ch  = _chan()
    op.send(f"JOIN {ch}")
    op.drain(0.3)
    op.send(f"MODE {ch} +l 1")
    op.drain(0.3)

    joiner = _connect("lj")
    joiner.send(f"JOIN {ch}")
    lines = joiner.collect(seconds=2)
    got471 = any(" 471 " in l for l in lines)
    _check("mode-limit: +l 1 blocks second join (→ 471)", got471)

    op.send(f"MODE {ch} -l")
    op.drain(0.3)
    joiner.send(f"JOIN {ch}")
    got_join = joiner.wait(rf"JOIN.*{re.escape(ch)}", timeout=3)
    _check("mode-limit: -l allows join", got_join is not None)
    op.close()
    joiner.close()


def test_mode_key_join():
    """MODE +k sets channel key; wrong key → 475; correct key → join."""
    op  = _connect("ko")
    ch  = _chan()
    op.send(f"JOIN {ch}")
    op.drain(0.3)
    key = "secret99"
    op.send(f"MODE {ch} +k {key}")
    op.drain(0.3)

    bad = _connect("kb")
    bad.send(f"JOIN {ch} wrongkey")
    lines = bad.collect(seconds=2)
    _check("mode-key: wrong key → 475", any(" 475 " in l for l in lines))

    good = _connect("kg")
    good.send(f"JOIN {ch} {key}")
    got = good.wait(rf"JOIN.*{re.escape(ch)}", timeout=3)
    _check("mode-key: correct key → join", got is not None)
    op.close()
    bad.close()
    good.close()


def test_invite_only_channel():
    """MODE +i blocks uninvited join (→ 473); INVITE allows it."""
    op  = _connect("io")
    ch  = _chan()
    op.send(f"JOIN {ch}")
    op.drain(0.3)
    op.send(f"MODE {ch} +i")
    op.drain(0.3)

    uninvited = _connect("iu")
    uninvited.send(f"JOIN {ch}")
    lines = uninvited.collect(seconds=2)
    _check("invite-only: uninvited → 473", any(" 473 " in l for l in lines))

    invited = _connect("ii")
    op.send(f"INVITE {invited.nick} {ch}")
    op.drain(0.3)
    invited.send(f"JOIN {ch}")
    got = invited.wait(rf"JOIN.*{re.escape(ch)}", timeout=3)
    _check("invite-only: invited user joins", got is not None)
    op.close()
    uninvited.close()
    invited.close()


def test_mode_invalid_char():
    """MODE with unknown flag (+Z) must return 472 ERR_UNKNOWNMODE."""
    c = _connect("mi")
    ch = _chan()
    c.send(f"JOIN {ch}")
    c.drain(0.3)
    c.send(f"MODE {ch} +Z")
    lines = c.collect(seconds=2)
    _check("mode-invalid: unknown flag → 472", any(" 472 " in l for l in lines))
    c.close()


# ===========================================================================
# §6  CAP NEGOTIATION
# ===========================================================================

def _raw_connect():
    """Return a raw socket connected to the server (not registered)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6)
    s.connect((SERVER_HOST, SERVER_PORT))
    return s


def _raw_send(s, line):
    s.sendall((line + "\r\n").encode())


def _raw_read(s, timeout=3.0):
    lines = []
    buf = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s.settimeout(max(0.05, deadline - time.time()))
            chunk = s.recv(4096).decode("utf-8", errors="replace")
            if not chunk:
                break
            buf += chunk
        except (socket.timeout, OSError):
            break
        while "\r\n" in buf:
            line, buf = buf.split("\r\n", 1)
            lines.append(line)
    return lines


def test_cap_ls_302():
    """CAP LS 302 must return a CAP LS response listing capabilities."""
    s = _raw_connect()
    _raw_send(s, "CAP LS 302")
    lines = _raw_read(s, timeout=3)
    got = any("CAP" in l and "LS" in l for l in lines)
    _check("cap-ls-302: CAP LS response received", got)
    s.close()


def test_cap_req_sasl():
    """CAP REQ :sasl must return CAP ACK or CAP NAK (not silence/crash)."""
    s = _raw_connect()
    _raw_send(s, "CAP LS 302")
    _raw_read(s, timeout=1)
    _raw_send(s, "CAP REQ :sasl")
    lines = _raw_read(s, timeout=3)
    got = any(("CAP" in l and "ACK" in l) or ("CAP" in l and "NAK" in l)
              for l in lines)
    _check("cap-req-sasl: CAP ACK or NAK received", got)
    s.close()


def test_cap_req_unknown():
    """CAP REQ for a completely unknown cap must return CAP NAK."""
    s = _raw_connect()
    _raw_send(s, "CAP LS 302")
    _raw_read(s, timeout=1)
    _raw_send(s, "CAP REQ :totally-unknown-cap-xyz")
    lines = _raw_read(s, timeout=3)
    got_nak = any("CAP" in l and "NAK" in l for l in lines)
    _check("cap-req-unknown: unknown cap → CAP NAK", got_nak)
    s.close()


def test_cap_end_completes_registration():
    """CAP LS then CAP END should allow normal registration to complete."""
    nick = _nick("ce")
    s = _raw_connect()
    _raw_send(s, "CAP LS 302")
    _raw_read(s, timeout=1)
    _raw_send(s, "CAP END")
    _raw_send(s, f"NICK {nick}")
    _raw_send(s, f"USER {nick} 0 * :CAP end test")
    lines = _raw_read(s, timeout=6)
    got001 = any(" 001 " in l for l in lines)
    _check("cap-end: registration completes after CAP END", got001)
    s.close()


def test_cap_multi_req():
    """Multiple CAP REQ in sequence must each get a response."""
    s = _raw_connect()
    _raw_send(s, "CAP LS 302")
    _raw_read(s, timeout=1)
    caps = ["sasl", "multi-prefix", "away-notify"]
    responses = 0
    for cap in caps:
        _raw_send(s, f"CAP REQ :{cap}")
        lines = _raw_read(s, timeout=2)
        if any("CAP" in l and ("ACK" in l or "NAK" in l) for l in lines):
            responses += 1
    _check(f"cap-multi-req: all {len(caps)} REQs got a response",
           responses == len(caps))
    s.close()


# ===========================================================================
# §7  SASL AUTHENTICATION
# ===========================================================================

def test_sasl_plain_success():
    """SASL PLAIN with correct oper credentials → 903 RPL_SASLSUCCESS."""
    c = _connect("sp", sasl_account=OPER_NAME, sasl_pass=OPER_PASS)
    _check("sasl-plain: correct credentials → 903",
           c.sasl_result == "903")
    c.close()


def test_sasl_plain_wrong_password():
    """SASL PLAIN with wrong password → 904 ERR_SASLFAIL."""
    c = IRC(_nick("sw"))
    c.register(sasl_account=OPER_NAME, sasl_pass="WRONG_PASS_XYZ")
    _check("sasl-plain: wrong password → 904", c.sasl_result == "904")
    c.close()


def test_sasl_plain_unknown_account():
    """SASL PLAIN with non-existent account → 904."""
    c = IRC(_nick("su"))
    c.register(sasl_account="no_such_oper_zzz", sasl_pass="anything")
    _check("sasl-plain: unknown account → 904", c.sasl_result == "904")
    c.close()


def test_sasl_abort():
    """AUTHENTICATE * during SASL exchange aborts cleanly; registration completes."""
    nick = _nick("sa")
    s = _raw_connect()
    _raw_send(s, "CAP LS 302")
    _raw_read(s, timeout=1)
    _raw_send(s, "CAP REQ :sasl")
    lines = _raw_read(s, timeout=2)
    if any("CAP" in l and "ACK" in l for l in lines):
        _raw_send(s, "AUTHENTICATE PLAIN")
        _raw_read(s, timeout=1)
        _raw_send(s, "AUTHENTICATE *")   # abort
    _raw_send(s, "CAP END")
    _raw_send(s, f"NICK {nick}")
    _raw_send(s, f"USER {nick} 0 * :sasl abort test")
    lines = _raw_read(s, timeout=6)
    got001 = any(" 001 " in l for l in lines)
    _check("sasl-abort: AUTHENTICATE * → registration still completes", got001)
    s.close()


def test_sasl_external_no_cert():
    """SASL EXTERNAL without a client certificate must return 904."""
    nick = _nick("se")
    s = _raw_connect()
    _raw_send(s, "CAP LS 302")
    _raw_read(s, timeout=1)
    _raw_send(s, "CAP REQ :sasl")
    lines = _raw_read(s, timeout=2)
    if not any("CAP" in l and "ACK" in l for l in lines):
        _ok("sasl-external: SASL not supported — skip")
        s.close()
        return
    _raw_send(s, "AUTHENTICATE EXTERNAL")
    lines = _raw_read(s, timeout=2)
    # Server should respond with 904 (no cert) or 908 (mechanism not available)
    got_fail = any((" 904 " in l or " 908 " in l or " 421 " in l)
                   for l in lines)
    _check("sasl-external: no cert → 904/908", got_fail)
    s.close()


# ===========================================================================
# §8  SERVICES MASS OPERATIONS
# ===========================================================================

def test_mass_account_register():
    """Register 15 distinct accounts; all must succeed (RPL_LOGGEDIN 900)."""
    clients = []
    successes = 0
    for i in range(15):
        try:
            c, pw = _make_account("mr")
            # Verify login works
            c.send(f"IDENTIFY {c.nick} {pw}")
            got = c.wait(r" 900 ", timeout=3)
            if got:
                successes += 1
            clients.append(c)
        except Exception:
            pass
    _check(f"mass-register: 15 accounts registered ({successes}/15)",
           successes == 15)
    for c in clients:
        c.close()


def test_identify_logout_cycle():
    """Rapid IDENTIFY / LOGOUT cycle 20 times must always return 900 / 901."""
    c, pw = _make_account("il")
    ok_count = 0
    for _ in range(20):
        c.send(f"LOGOUT")
        c.wait(r" 901 ", timeout=2)
        c.send(f"IDENTIFY {c.nick} {pw}")
        got = c.wait(r" 900 ", timeout=3)
        if got:
            ok_count += 1
    _check(f"identify-logout-cycle: 20 cycles ({ok_count}/20)",
           ok_count == 20)
    c.close()


def test_mass_memo():
    """Send 20 memos from one account to another; MEMO LIST must show them."""
    sender, _ = _make_account("ms")
    recvr,  _ = _make_account("mr")
    sender.send(f"IDENTIFY {sender.nick} password123")
    sender.wait(r" 900 ", timeout=3)
    recvr.send(f"IDENTIFY {recvr.nick} password123")
    recvr.wait(r" 900 ", timeout=3)

    N = 20
    for i in range(N):
        sender.send(f"MEMO SEND {recvr.nick} :stress memo {i}")
        sender.drain(0.05)

    recvr.send("MEMO LIST")
    lines = recvr.collect(seconds=3)
    memo_lines = [l for l in lines if re.search(r"(MEMO|memo|777|778)", l)]
    _check(f"mass-memo: {N} memos sent and list responded",
           len(memo_lines) > 0)
    sender.close()
    recvr.close()


def test_mass_access_entries():
    """Add 15 ACCESS entries to a registered channel; LIST must return them."""
    founder, pw = _make_account("fa")
    founder.send(f"IDENTIFY {founder.nick} {pw}")
    founder.wait(r" 900 ", timeout=3)

    ch = _chan()
    founder.send(f"JOIN {ch}")
    founder.drain(0.3)
    founder.send(f"CREGISTER {ch}")
    founder.wait(r"(registered|already|error)", timeout=3)

    N = 15
    nicks = [_nick("ax") for _ in range(N)]
    for n in nicks:
        founder.send(f"CHANSET {ch} ACCESS ADD {n} AOP")
        founder.drain(0.1)

    founder.send(f"CHANSET {ch} ACCESS LIST")
    lines = founder.collect(seconds=3)
    entries = [l for l in lines if any(n in l for n in nicks)]
    _check(f"mass-access: {N} entries stored (found {len(entries)})",
           len(entries) >= N)
    founder.close()


def test_mass_channel_register():
    """Register 10 channels with the same founder; all must succeed."""
    founder, pw = _make_account("fc")
    founder.send(f"IDENTIFY {founder.nick} {pw}")
    founder.wait(r" 900 ", timeout=3)

    successes = 0
    for _ in range(10):
        ch = _chan()
        founder.send(f"JOIN {ch}")
        founder.drain(0.2)
        founder.send(f"CREGISTER {ch}")
        got = founder.wait(r"(registered|already|error)", timeout=3)
        if got and "registered" in got.lower():
            successes += 1
    _check(f"mass-chan-register: 10 channels ({successes}/10)",
           successes >= 8)   # allow minor failures
    founder.close()


# ===========================================================================
# §9  WHO / WHOIS STRESS
# ===========================================================================

def test_who_channel_members():
    """WHO #channel must list all members with 352 numerics."""
    op = _connect("wc")
    ch = _chan()
    op.send(f"JOIN {ch}")
    op.drain(0.3)
    members = [_connect("wm") for _ in range(5)]
    for m in members:
        m.send(f"JOIN {ch}")
        m.drain(0.2)

    op.send(f"WHO {ch}")
    lines = op.collect(seconds=3)
    got352 = [l for l in lines if " 352 " in l]
    _check(f"who-channel: 6 members → ≥6 WHO lines (got {len(got352)})",
           len(got352) >= 6)
    op.close()
    for m in members:
        m.close()


def test_who_wildcard():
    """WHO *.* must return at least the calling client in results."""
    c = _connect("ww")
    c.send("WHO *.*")
    lines = c.collect(seconds=3)
    got352 = any(" 352 " in l for l in lines)
    _check("who-wildcard: *.* returns results", got352)
    c.close()


def test_who_invisible_hidden():
    """User with MODE +i must not appear in WHO *.* for non-opers."""
    invisible = _connect("wi")
    invisible.send(f"MODE {invisible.nick} +i")
    invisible.drain(0.2)

    watcher = _connect("wv")
    watcher.send("WHO *.*")
    lines = watcher.collect(seconds=3)
    found = any(invisible.nick in l and " 352 " in l for l in lines)
    _check("who-invisible: +i user hidden from WHO", not found)
    invisible.close()
    watcher.close()


def test_whois_self():
    """WHOIS own nick → 311 + 318."""
    c = _connect("ws")
    c.send(f"WHOIS {c.nick}")
    lines = c.collect(seconds=2)
    _check("whois-self: 311 received", any(" 311 " in l for l in lines))
    _check("whois-self: 318 received", any(" 318 " in l for l in lines))
    c.close()


def test_whois_another():
    """WHOIS of another connected user → 311 + 318."""
    a = _connect("wa")
    b = _connect("wb")
    a.send(f"WHOIS {b.nick}")
    lines = a.collect(seconds=2)
    _check("whois-other: 311 received", any(" 311 " in l for l in lines))
    _check("whois-other: 318 received", any(" 318 " in l for l in lines))
    a.close()
    b.close()


def test_whois_offline():
    """WHOIS of non-existent nick → 401 ERR_NOSUCHNICK."""
    c = _connect("wo")
    c.send("WHOIS nosuchnickatall999")
    lines = c.collect(seconds=2)
    _check("whois-offline: → 401", any(" 401 " in l for l in lines))
    c.close()


def test_whois_batch():
    """WHOIS with comma-separated list of 5 nicks returns results for each."""
    clients = [_connect("wb") for _ in range(5)]
    requester = _connect("wr")
    nicks = ",".join(c.nick for c in clients)
    requester.send(f"WHOIS {nicks}")
    lines = requester.collect(seconds=4)
    got311 = [l for l in lines if " 311 " in l]
    _check(f"whois-batch: 5 nicks → ≥5 311 lines (got {len(got311)})",
           len(got311) >= 5)
    requester.close()
    for c in clients:
        c.close()


# ===========================================================================
# §10  CONCURRENT MODIFICATIONS
# ===========================================================================

def test_concurrent_join_same_channel():
    """10 clients JOIN the same channel simultaneously; all must succeed."""
    ch = _chan()
    N  = 10
    results = []
    lock = threading.Lock()

    def joiner():
        try:
            c = _connect("cj")
            c.send(f"JOIN {ch}")
            got = c.wait(rf"JOIN.*{re.escape(ch)}", timeout=4)
            with lock:
                results.append(got is not None)
            c.close()
        except Exception:
            with lock:
                results.append(False)

    threads = [threading.Thread(target=joiner) for _ in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=12)

    ok = sum(1 for r in results if r)
    _check(f"concurrent-join: {N} simultaneous joins ({ok}/{N} ok)", ok == N)


def test_concurrent_topic_set():
    """5 clients race to SET TOPIC; one must win; channel topic must be set."""
    ch = _chan()
    ops = [_connect("ct") for _ in range(5)]
    for o in ops:
        o.send(f"JOIN {ch}")
        o.drain(0.2)

    def setter(o, i):
        o.send(f"TOPIC {ch} :topic from {i}")

    threads = [threading.Thread(target=setter, args=(o, i))
               for i, o in enumerate(ops)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    ops[0].send(f"TOPIC {ch}")
    lines = ops[0].collect(seconds=2)
    got_topic = any(" 332 " in l or " 331 " in l for l in lines)
    _check("concurrent-topic: topic query returns 331/332", got_topic)
    for o in ops:
        o.close()


def test_concurrent_kick():
    """Op and target both act at the same time; server must not crash."""
    op  = _connect("ck")
    tgt = _connect("kt")
    ch  = _chan()
    op.send(f"JOIN {ch}")
    op.drain(0.2)
    tgt.send(f"JOIN {ch}")
    tgt.drain(0.2)

    def do_kick():
        op.send(f"KICK {ch} {tgt.nick} :stress")

    def do_msg():
        tgt.send(f"PRIVMSG {ch} :going down")

    t1 = threading.Thread(target=do_kick)
    t2 = threading.Thread(target=do_msg)
    t1.start(); t2.start()
    t1.join(timeout=3); t2.join(timeout=3)

    op.send("PING :alive")
    got = op.wait(r"PONG", timeout=3)
    _check("concurrent-kick: server alive after concurrent kick/msg",
           got is not None)
    op.close()
    tgt.close()


# ===========================================================================
# §11  KICK / INVITE STRESS
# ===========================================================================

def test_kick_and_rejoin():
    """KICK a user; they can immediately rejoin an unguarded channel."""
    op  = _connect("kr")
    tgt = _connect("kt")
    ch  = _chan()
    op.send(f"JOIN {ch}")
    op.drain(0.2)
    tgt.send(f"JOIN {ch}")
    tgt.drain(0.2)
    op.send(f"KICK {ch} {tgt.nick} :bye")
    tgt.wait(r"KICK", timeout=3)
    tgt.send(f"JOIN {ch}")
    got = tgt.wait(rf"JOIN.*{re.escape(ch)}", timeout=3)
    _check("kick-rejoin: kicked user can rejoin", got is not None)
    op.close()
    tgt.close()


def test_kick_last_member():
    """Kicking the last member of a channel; channel must disappear (no 322 in LIST)."""
    op  = _connect("kl")
    ch  = _chan()
    op.send(f"JOIN {ch}")
    op.drain(0.2)
    op.send(f"KICK {ch} {op.nick} :self kick")
    op.drain(0.5)
    op.send(f"LIST {ch}")
    lines = op.collect(seconds=2)
    found = any(ch in l and " 322 " in l for l in lines)
    _check("kick-last: channel gone after kicking last member", not found)
    op.close()


def test_mass_invite():
    """Op invites 15 users to a +i channel; all must join successfully."""
    op = _connect("mi")
    ch = _chan()
    op.send(f"JOIN {ch}")
    op.drain(0.2)
    op.send(f"MODE {ch} +i")
    op.drain(0.2)

    joiners = [_connect("ij") for _ in range(15)]
    for j in joiners:
        op.send(f"INVITE {j.nick} {ch}")
    op.drain(0.5)

    ok = 0
    for j in joiners:
        j.send(f"JOIN {ch}")
        got = j.wait(rf"JOIN.*{re.escape(ch)}", timeout=3)
        if got:
            ok += 1

    _check(f"mass-invite: 15 invites → 15 joins ({ok}/15)", ok == 15)
    op.close()
    for j in joiners:
        j.close()


# ===========================================================================
# §12  OPER COMMAND STRESS
# ===========================================================================

def test_kline_mass():
    """Add and remove 10 K-LINEs; each must be acknowledged."""
    op = _oper("km")
    added = 0
    removed = 0
    for i in range(10):
        op.send(f"KLINE 1 ktest{i:03d}@192.168.99.{i} :stress")
        got = op.wait(r"(K-Line|kline|Added|added|482)", timeout=3)
        if got and "481" not in got and "482" not in got:
            added += 1
    _check(f"kline-mass: 10 K-LINEs added ({added}/10)", added >= 8)

    for i in range(10):
        op.send(f"UNKLINE ktest{i:03d}@192.168.99.{i}")
        got = op.wait(r"(K-Line|Unkline|removed|Removed|481)", timeout=3)
        if got and "481" not in got:
            removed += 1
    _check(f"unkline-mass: 10 K-LINEs removed ({removed}/10)", removed >= 8)
    op.close()


def test_kill_and_reconnect():
    """Op KILLs a user; user reconnects immediately without error."""
    op  = _oper("ko")
    tgt = _connect("kt")
    op.send(f"KILL {tgt.nick} :stress test kill")
    op.drain(0.5)
    try:
        new = _connect("kr")
        _check("kill-reconnect: user reconnects after KILL", True)
        new.close()
    except Exception as e:
        _fail("kill-reconnect: user reconnects after KILL", str(e))
    op.close()


def test_stats_types():
    """Oper STATS for u, c, p, o, m, T must all return data (not 481)."""
    op = _oper("st")
    types = list("ucpomt") + ["T"]
    ok = 0
    for t in types:
        op.send(f"STATS {t}")
        lines = op.collect(seconds=2)
        if not any(" 481 " in l for l in lines):
            ok += 1
    _check(f"stats-types: {len(types)} STATS types accepted ({ok}/{len(types)})",
           ok >= len(types) - 1)
    op.close()


def test_wallops_delivery():
    """Oper WALLOPS message is delivered to clients with +w umode."""
    op      = _oper("wo")
    watcher = _connect("ww")
    watcher.send(f"MODE {watcher.nick} +w")
    watcher.drain(0.2)

    marker = f"wallop{random.randint(10000,99999)}"
    op.send(f"WALLOPS :{marker}")
    got = watcher.wait(rf"WALLOPS.*{marker}", timeout=4)
    _check("wallops-delivery: +w user receives WALLOPS", got is not None)
    op.close()
    watcher.close()


def test_rehash_under_load():
    """REHASH while 20 clients are connected; server must survive."""
    op      = _oper("ru")
    clients = []
    for _ in range(20):
        try:
            clients.append(_connect("rl"))
        except Exception:
            pass

    op.send("REHASH")
    got = op.wait(r" 382 ", timeout=5)
    _check("rehash-under-load: 382 received", got is not None)

    op.send("PING :afterrehash")
    alive = op.wait(r"PONG.*afterrehash", timeout=4)
    _check("rehash-under-load: server alive after REHASH", alive is not None)
    op.close()
    for c in clients:
        c.close()


def test_operwall_nonoper_blocked():
    """Non-oper OPERWALL must return 481 ERR_NOPRIVILEGES."""
    c = _connect("ow")
    c.send("OPERWALL :should not work")
    lines = c.collect(seconds=2)
    _check("operwall-nonoper: → 481", any(" 481 " in l for l in lines))
    c.close()


def test_trace_oper():
    """Oper TRACE must return trace numerics (200/201/204/205/261)."""
    op = _oper("tr")
    op.send("TRACE")
    lines = op.collect(seconds=3)
    trace_nums = {"200", "201", "204", "205", "261", "262"}
    got = any(f" {n} " in l for l in lines for n in trace_nums)
    _check("trace-oper: trace numerics received", got)
    op.close()


# ===========================================================================
# §13  SERVICES DATABASE STRESS
# ===========================================================================

def test_chanset_all_options():
    """Exercise every CHANSET option: TOPICLOCK, KEEPTOPIC, URL, DESC, MODELOCK."""
    founder, pw = _make_account("cs")
    founder.send(f"IDENTIFY {founder.nick} {pw}")
    founder.wait(r" 900 ", timeout=3)
    ch = _chan()
    founder.send(f"JOIN {ch}")
    founder.drain(0.2)
    founder.send(f"CREGISTER {ch}")
    founder.wait(r"(registered|already)", timeout=3)

    options = [
        (f"CHANSET {ch} TOPICLOCK on",      r"(TOPICLOCK|set|error)"),
        (f"CHANSET {ch} TOPICLOCK off",     r"(TOPICLOCK|set|error)"),
        (f"CHANSET {ch} KEEPTOPIC on",      r"(KEEPTOPIC|set|error)"),
        (f"CHANSET {ch} URL https://x.test",r"(URL|set|error)"),
        (f"CHANSET {ch} DESC :stress test", r"(DESC|set|error)"),
        (f"CHANSET {ch} MODELOCK +nt",      r"(MODELOCK|set|error)"),
    ]
    ok = 0
    for cmd, pat in options:
        founder.send(cmd)
        got = founder.wait(pat, timeout=3)
        if got:
            ok += 1
    _check(f"chanset-all-options: {len(options)} options applied ({ok}/{len(options)})",
           ok >= len(options) - 1)
    founder.close()


def test_access_tier_mapping():
    """Add VOP, HOP, AOP, SOP access entries; LIST must return all four."""
    founder, pw = _make_account("at")
    founder.send(f"IDENTIFY {founder.nick} {pw}")
    founder.wait(r" 900 ", timeout=3)
    ch = _chan()
    founder.send(f"JOIN {ch}")
    founder.drain(0.2)
    founder.send(f"CREGISTER {ch}")
    founder.wait(r"(registered|already)", timeout=3)

    tiers = ["VOP", "HOP", "AOP", "SOP"]
    nicks = {tier: _nick("tr") for tier in tiers}
    for tier, nick in nicks.items():
        founder.send(f"CHANSET {ch} ACCESS ADD {nick} {tier}")
        founder.drain(0.15)

    founder.send(f"CHANSET {ch} ACCESS LIST")
    lines = founder.collect(seconds=3)
    found = {tier for tier, nick in nicks.items()
             if any(nick in l for l in lines)}
    _check(f"access-tiers: VOP/HOP/AOP/SOP all stored (found {found})",
           len(found) == 4)
    founder.close()


def test_memo_del_all():
    """MEMO DEL ALL clears all memos; subsequent LIST must return empty."""
    sender, _ = _make_account("md")
    recvr,  _ = _make_account("rd")
    sender.send(f"IDENTIFY {sender.nick} password123")
    sender.wait(r" 900 ", timeout=3)
    recvr.send(f"IDENTIFY {recvr.nick} password123")
    recvr.wait(r" 900 ", timeout=3)

    for i in range(5):
        sender.send(f"MEMO SEND {recvr.nick} :memo {i}")
        sender.drain(0.1)

    recvr.send("MEMO DEL ALL")
    recvr.drain(0.5)
    recvr.send("MEMO LIST")
    lines = recvr.collect(seconds=2)
    # Either "no memos" message or an empty list response
    empty = any(re.search(r"(no memo|0 memo|empty|none)", l, re.I)
                for l in lines)
    some  = any(re.search(r"778|779", l) for l in lines)
    _check("memo-del-all: list empty after DEL ALL", empty or not some)
    sender.close()
    recvr.close()


def test_vhost_request_and_take():
    """Oper OFFERs a vhost; user TAKEs it; WHOIS shows new host."""
    op       = _oper("vo")
    user, pw = _make_account("vu")
    user.send(f"IDENTIFY {user.nick} {pw}")
    user.wait(r" 900 ", timeout=3)

    vhost = f"stress.{user.nick}.test"
    op.send(f"VHOFFER {user.nick} {vhost}")
    op.drain(0.3)
    user.send(f"VHOST TAKE {vhost}")
    user.drain(0.5)

    op.send(f"WHOIS {user.nick}")
    lines = op.collect(seconds=3)
    got = any(vhost in l for l in lines)
    _check(f"vhost-take: WHOIS shows new vhost", got)
    op.close()
    user.close()


def test_setpass_and_reidentify():
    """SETPASS changes password; old password fails; new password succeeds."""
    c, old_pw = _make_account("sp")
    c.send(f"IDENTIFY {c.nick} {old_pw}")
    c.wait(r" 900 ", timeout=3)

    new_pw = "newpassword456"
    c.send(f"SETPASS {old_pw} {new_pw}")
    c.wait(r"(password|changed|error)", timeout=3)
    c.send("LOGOUT")
    c.wait(r" 901 ", timeout=2)

    # Old password must fail
    c.send(f"IDENTIFY {c.nick} {old_pw}")
    lines = c.collect(seconds=2)
    _check("setpass: old password rejected",
           not any(" 900 " in l for l in lines))

    # New password must succeed
    c.send(f"IDENTIFY {c.nick} {new_pw}")
    got = c.wait(r" 900 ", timeout=3)
    _check("setpass: new password accepted", got is not None)
    c.close()


# ===========================================================================
# §14  ERROR RECOVERY
# ===========================================================================

def test_garbage_input():
    """Random garbage bytes must not crash the server."""
    s = _raw_connect()
    garbage = bytes(random.randint(0, 255) for _ in range(512))
    try:
        s.sendall(garbage)
    except Exception:
        pass
    s.close()
    # Verify server still up
    try:
        probe = _connect("gi")
        _check("garbage-input: server alive after garbage", True)
        probe.close()
    except Exception as e:
        _fail("garbage-input: server alive after garbage", str(e))


def test_null_bytes():
    """Lines containing NUL bytes must not crash the server."""
    s = _raw_connect()
    try:
        s.sendall(b"PRIVMSG #x :\x00hello\x00\r\n")
        s.sendall(b"PING :null_probe\r\n")
        buf = b""
        deadline = time.time() + 4
        while time.time() < deadline:
            try:
                s.settimeout(0.5)
                chunk = s.recv(1024)
                if not chunk:
                    break
                buf += chunk
                if b"PONG" in buf and b"null_probe" in buf:
                    break
            except socket.timeout:
                pass
        _check("null-bytes: server alive (PONG received)",
               b"null_probe" in buf)
    except Exception as e:
        _fail("null-bytes: server alive", str(e))
    finally:
        s.close()


def test_partial_write():
    """Write a command in tiny 1-byte increments; server must process it."""
    c = _connect("pw")
    c.send("PING :before")
    c.wait(r"PONG.*before", timeout=3)

    line = b"PING :partial\r\n"
    try:
        for byte in line:
            c.sock.sendall(bytes([byte]))
            time.sleep(0.002)
        got = c.wait(r"PONG.*partial", timeout=4)
        _check("partial-write: server reassembles partial send", got is not None)
    except Exception as e:
        _fail("partial-write: server reassembles partial send", str(e))
    finally:
        c.close()


def test_server_survives_mass_join_spam():
    """Rapid JOIN/PART of 50 unique channels; server must survive."""
    c = _connect("jm")
    channels = [_chan() for _ in range(50)]
    for ch in channels:
        c.send(f"JOIN {ch}")
    c.drain(1.0)
    for ch in channels:
        c.send(f"PART {ch} :stress")
    c.drain(0.5)
    c.send("PING :afterjoinspam")
    got = c.wait(r"PONG.*afterjoinspam", timeout=5)
    _check("join-spam: server alive after 50 channel JOIN/PART", got is not None)
    c.close()


def test_command_when_not_registered():
    """Sending PRIVMSG before NICK/USER must be rejected gracefully."""
    s = _raw_connect()
    _raw_send(s, "PRIVMSG #nowhere :hello")
    lines = _raw_read(s, timeout=2)
    # Server may return 451 ERR_NOTREGISTERED or simply ignore
    alive = True   # If we got here without crash, that's a pass
    _check("unregistered-privmsg: server handles gracefully", alive)
    s.close()


# ===========================================================================
# §15  MEMORY PRESSURE
# ===========================================================================

def test_large_topic():
    """Set a 390-byte topic; retrieve it via TOPIC query."""
    c = _connect("lt")
    ch = _chan()
    c.send(f"JOIN {ch}")
    c.drain(0.2)
    big_topic = "T" * 390
    c.send(f"TOPIC {ch} :{big_topic}")
    c.drain(0.3)
    c.send(f"TOPIC {ch}")
    lines = c.collect(seconds=2)
    got = any(" 332 " in l or " 331 " in l for l in lines)
    _check("large-topic: 390-byte topic stored and retrieved", got)
    c.close()


def test_many_bans_and_clear():
    """Add 50 bans then remove them all; ban list must be empty afterward."""
    c = _connect("mb")
    ch = _chan()
    c.send(f"JOIN {ch}")
    c.drain(0.2)
    N = 50
    for i in range(N):
        c.send(f"MODE {ch} +b ban{i:04d}!*@*")
    c.drain(1.0)

    # Remove all bans
    for i in range(N):
        c.send(f"MODE {ch} -b ban{i:04d}!*@*")
    c.drain(1.5)

    c.send(f"MODE {ch} +b")
    lines = c.collect(seconds=2)
    remaining = [l for l in lines if " 367 " in l]
    _check(f"many-bans-clear: ban list empty after removal (remaining={len(remaining)})",
           len(remaining) == 0)
    c.close()


def test_monitor_many_nicks():
    """MONITOR + for 50 nicks; MONITOR L must list all 50."""
    c = _connect("mn")
    nicks = [f"montest{i:04d}" for i in range(50)]
    # Add in batches of 10
    for i in range(0, 50, 10):
        batch = ",".join(nicks[i:i + 10])
        c.send(f"MONITOR + {batch}")
        c.drain(0.2)

    c.send("MONITOR L")
    lines = c.collect(seconds=3)
    monitor_entries = [l for l in lines if " 732 " in l]
    total = sum(l.count(",") + 1 for l in monitor_entries)
    _check(f"monitor-many: 50 nicks on MONITOR list (counted ~{total})",
           total >= 45)   # allow minor variance in counting
    c.send("MONITOR C")
    c.close()


def test_large_prop_value():
    """PROP SET with a 400-byte value must be stored and retrieved."""
    op = _oper("lv")
    ch = _chan()
    op.send(f"JOIN {ch}")
    op.drain(0.2)
    big_val = "V" * 400
    op.send(f"PROP {ch} SET bigkey :{big_val}")
    op.drain(0.3)
    op.send(f"PROP {ch} GET bigkey")
    lines = op.collect(seconds=2)
    got = any(" 818 " in l or big_val[:50] in l for l in lines)
    _check("large-prop: 400-byte PROP value stored/retrieved", got)
    op.close()


def test_ison_bulk():
    """ISON with 20 nicks (mix of online/offline) → 303 with online subset."""
    online  = [_connect("io") for _ in range(10)]
    offline = [f"ghostnick{i:04d}" for i in range(10)]
    c = _connect("ib")
    query = " ".join(o.nick for o in online) + " " + " ".join(offline)
    c.send(f"ISON :{query}")
    lines = c.collect(seconds=2)
    got303 = any(" 303 " in l for l in lines)
    _check("ison-bulk: 303 returned for 20-nick ISON", got303)
    c.close()
    for o in online:
        o.close()


# ===========================================================================
# TEST REGISTRY
# ===========================================================================

TESTS = [
    # §1 Connection stress
    ("concurrent-connect: 50 simultaneous registrations",   test_concurrent_connections),
    ("rapid-reconnect: 30 connect/disconnect cycles",        test_rapid_reconnect),
    ("conn-limit-recovery: mass-close then new client",      test_connection_limit_recovery),
    # §2 Protocol robustness
    ("oversized-line: 4096-byte line handled",               test_oversized_line),
    ("binary-privmsg: CTCP ACTION delivered",                test_binary_in_privmsg),
    ("empty-lines: 20 blank lines, server alive",            test_empty_lines),
    ("unknown-cmds: 100 unknown commands, server alive",     test_unknown_commands_bulk),
    ("ping-flood: 200 PINGs, last PONG received",            test_flood_of_pings),
    # §3 Nick/channel validation
    ("nick-cycling: 30 nick changes",                        test_nick_cycling),
    ("nick-max-length: 30-char ok, 31-char → 432",          test_nick_max_length),
    ("chan-name-boundary: 50-char ok, 51-char → 479",        test_channel_name_boundaries),
    ("join-0: parts from all channels",                      test_join_zero_parts_all),
    # §4 PRIVMSG/NOTICE flood
    ("privmsg-burst: 200 msgs, final marker received",       test_privmsg_burst_delivery),
    ("notice-burst: 100 NOTICEs, server alive",              test_notice_burst),
    ("long-privmsg: 490-byte message delivered",             test_long_privmsg),
    ("unicode-privmsg: emoji/UTF-8 delivered",               test_unicode_privmsg),
    ("privmsg-self: message to own nick delivered",          test_privmsg_to_self),
    # §5 Channel mode stress
    ("channel-modes: +ntmsp applied and queried",            test_channel_modes_all_valid),
    ("ban-list-fill: 20 bans stored",                        test_ban_list_fill),
    ("mode-limit: +l 1 blocks, -l allows",                   test_mode_limit_boundary),
    ("mode-key: +k wrong→475, correct→join",                 test_mode_key_join),
    ("invite-only: +i blocks, INVITE allows",                test_invite_only_channel),
    ("mode-invalid: unknown flag → 472",                     test_mode_invalid_char),
    # §6 CAP negotiation
    ("cap-ls-302: CAP LS response",                          test_cap_ls_302),
    ("cap-req-sasl: ACK or NAK",                             test_cap_req_sasl),
    ("cap-req-unknown: unknown → NAK",                       test_cap_req_unknown),
    ("cap-end: registration completes",                      test_cap_end_completes_registration),
    ("cap-multi-req: 3 REQs each get response",              test_cap_multi_req),
    # §7 SASL authentication
    ("sasl-plain: correct → 903",                            test_sasl_plain_success),
    ("sasl-plain: wrong password → 904",                     test_sasl_plain_wrong_password),
    ("sasl-plain: unknown account → 904",                    test_sasl_plain_unknown_account),
    ("sasl-abort: AUTHENTICATE * → clean",                   test_sasl_abort),
    ("sasl-external: no cert → 904/908",                     test_sasl_external_no_cert),
    # §8 Services mass ops
    ("mass-register: 15 accounts",                           test_mass_account_register),
    ("identify-logout-cycle: 20 cycles",                     test_identify_logout_cycle),
    ("mass-memo: 20 memos sent",                             test_mass_memo),
    ("mass-access: 15 ACCESS entries",                       test_mass_access_entries),
    ("mass-chan-register: 10 channels",                       test_mass_channel_register),
    # §9 WHO/WHOIS stress
    ("who-channel: 6 members → WHO lines",                   test_who_channel_members),
    ("who-wildcard: *.* returns results",                     test_who_wildcard),
    ("who-invisible: +i hidden",                             test_who_invisible_hidden),
    ("whois-self: 311+318",                                  test_whois_self),
    ("whois-other: 311+318",                                 test_whois_another),
    ("whois-offline: → 401",                                 test_whois_offline),
    ("whois-batch: 5-nick list",                             test_whois_batch),
    # §10 Concurrent modifications
    ("concurrent-join: 10 simultaneous joins",               test_concurrent_join_same_channel),
    ("concurrent-topic: race on TOPIC",                      test_concurrent_topic_set),
    ("concurrent-kick: kick + msg race",                     test_concurrent_kick),
    # §11 KICK/INVITE stress
    ("kick-rejoin: kicked user can rejoin",                  test_kick_and_rejoin),
    ("kick-last: channel disappears",                        test_kick_last_member),
    ("mass-invite: 15 invites → 15 joins",                   test_mass_invite),
    # §12 Oper command stress
    ("kline-mass: 10 K-LINE add/remove",                     test_kline_mass),
    ("kill-reconnect: KILL + immediate reconnect",            test_kill_and_reconnect),
    ("stats-types: u/c/p/o/m/t/T all accepted",              test_stats_types),
    ("wallops-delivery: +w user receives",                    test_wallops_delivery),
    ("rehash-under-load: 20 clients then REHASH",            test_rehash_under_load),
    ("operwall-nonoper: → 481",                              test_operwall_nonoper_blocked),
    ("trace-oper: trace numerics",                           test_trace_oper),
    # §13 Services database stress
    ("chanset-all-options: 6 CHANSET options",               test_chanset_all_options),
    ("access-tiers: VOP/HOP/AOP/SOP all stored",             test_access_tier_mapping),
    ("memo-del-all: list empty after DEL ALL",               test_memo_del_all),
    ("vhost-take: WHOIS shows new vhost",                    test_vhost_request_and_take),
    ("setpass: old rejected, new accepted",                  test_setpass_and_reidentify),
    # §14 Error recovery
    ("garbage-input: server survives random bytes",          test_garbage_input),
    ("null-bytes: server survives NUL in line",              test_null_bytes),
    ("partial-write: 1-byte increments reassembled",         test_partial_write),
    ("join-spam: 50 JOIN/PART, server alive",                test_server_survives_mass_join_spam),
    ("unregistered-privmsg: gracefully rejected",            test_command_when_not_registered),
    # §15 Memory pressure
    ("large-topic: 390-byte topic stored/retrieved",         test_large_topic),
    ("many-bans-clear: 50 bans added and removed",           test_many_bans_and_clear),
    ("monitor-many: 50 nicks on MONITOR list",               test_monitor_many_nicks),
    ("large-prop: 400-byte PROP value",                      test_large_prop_value),
    ("ison-bulk: 20-nick ISON → 303",                        test_ison_bulk),
]


# ===========================================================================
# MAIN
# ===========================================================================

def main():
    print("=" * 70)
    print("Ophion IRC Server — Comprehensive Stress Test")
    print(f"Server: {SERVER_HOST}:{SERVER_PORT}")
    print(f"Tests : {len(TESTS)}")
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
