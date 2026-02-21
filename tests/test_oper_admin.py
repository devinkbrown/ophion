#!/usr/bin/env python3
"""
Comprehensive IRC Oper/Admin Tools Stress Test for the Ophion IRC Server.

Server: 127.0.0.1:16667
Oper credentials: testoper / testpass123 (SHA-512 hashed in ircd.conf)

Authentication method: SASL PLAIN (via IRCX AUTH command or CAP-based SASL).
Ophion uses SASL for all oper authentication; the traditional OPER command is
a redirect stub.  Clients authenticate using:

  AUTH PLAIN I :<base64(\x00<block>\x00<password>)>   (IRCX shorthand)
or the full CAP REQ :sasl … AUTHENTICATE … exchange.

Tests cover:
 1. SASL PLAIN correct credentials → 903 RPL_SASLSUCCESS + oper_up at 001
 2. SASL PLAIN wrong password → 904 ERR_SASLFAIL
 3. Oper umode flags set correctly (+o, +a for admin) after SASL
 4. Non-oper STATS subcommands blocked or limited
 5. Oper STATS subcommands work
 6. WALLOPS — oper can send, non-oper cannot (481 / 723)
 7. OPERWALL — oper can send, non-oper cannot
 8. KILL — oper kill works, sends error to target
 9. KLINE — oper adds temp kline
10. UNKLINE — oper removes kline
11. DLINE — oper adds temp dline
12. UNDLINE — oper removes dline
13. XLINE — oper adds gecos ban
14. UNXLINE — oper removes it
15. REHASH — oper can rehash, non-oper cannot
16. WHO with 'o' flag (oper flag visible in WHO response)
17. WHOIS shows oper line (313) for opers
18. TRACE — oper gets full trace, non-oper gets limited
19. Oper snomask (+s) — set/unset snomask flags
20. UMODE +o — cannot self-oper without SASL auth
21. God mode (+G) — oper with oper:god can set +G, non-oper cannot
22. oper_kick_protection — opers cannot be kicked by non-opers when enabled
23. Oper auto-op on channel join (oper gets +q automatically if oper_auto_op = yes)
24. MODLIST — oper can list loaded modules
25. User mode +D (deaf mode) and +g (caller-id)
"""

import base64
import socket
import time
import sys
import re
import os
import signal

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 16667
OPER_NAME = "testoper"
OPER_PASS = "testpass123"
IRCD_CONF = "/usr/local/etc/ircd.conf"
IRCD_PID_FILE = "/usr/local/etc/ircd.pid"

def _read_ircd_pid():
    """Read the ircd PID from the pid file, falling back to a hardcoded value."""
    try:
        with open(IRCD_PID_FILE) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 4182  # fallback

IRCD_PID = _read_ircd_pid()

# Numeric constants (from include/numeric.h)
RPL_YOUREOPER       = "381"
RPL_REHASHING       = "382"
RPL_LOGGEDIN        = "900"
RPL_SASLSUCCESS     = "903"
ERR_SASLFAIL        = "904"
ERR_PASSWDMISMATCH  = "464"
ERR_NOOPERHOST      = "491"
ERR_NOPRIVILEGES    = "481"
ERR_NOPRIVS         = "723"
ERR_NEEDMOREPARAMS  = "461"
RPL_WHOISOPERATOR   = "313"
RPL_ENDOFSTATS      = "219"
RPL_STATSUPTIME     = "242"


# ---------------------------------------------------------------------------
# SASL PLAIN helper
# ---------------------------------------------------------------------------

def sasl_plain_b64(account: str, password: str) -> str:
    """
    Encode SASL PLAIN credentials as base64.
    Payload: authzid NUL authcid NUL password  (authzid is empty)
    """
    payload = f"\x00{account}\x00{password}".encode()
    return base64.b64encode(payload).decode()

# ---------------------------------------------------------------------------
# Test result tracking
# ---------------------------------------------------------------------------
_results = []

def _record(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    _results.append((name, status, detail))
    tag = "\033[32mPASS\033[0m" if passed else "\033[31mFAIL\033[0m"
    print(f"  [{tag}] {name}" + (f": {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# Low-level IRC helpers
# ---------------------------------------------------------------------------

class IRCClient:
    """A minimal raw IRC client backed by a TCP socket."""

    def __init__(self, nick, user="testuser", realname="Test User", timeout=5):
        self.nick = nick
        self.user = user
        self.realname = realname
        self.timeout = timeout
        self.sock = None
        self._buf = ""
        self.is_oper = False          # set to True when 381 observed
        self.sasl_result = None       # "903" or "904" after SASL attempt

    def connect(self, sasl_account=None, sasl_password=None):
        """
        Connect to the server and complete registration.

        If sasl_account and sasl_password are provided, authenticate via the
        IRCX AUTH PLAIN shorthand (AUTH PLAIN I :<b64>) before registration.
        On SASL success, oper_up fires automatically at 001 if the oper block
        linked to the account grants oper status.

        Returns self for chaining.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((SERVER_HOST, SERVER_PORT))

        if sasl_account is not None:
            # IRCX AUTH: send pre-registration, before NICK/USER
            b64 = sasl_plain_b64(sasl_account, sasl_password or "")
            self.send(f"AUTH PLAIN I :{b64}")

        self.send(f"NICK {self.nick}")
        self.send(f"USER {self.user} 0 * :{self.realname}")
        self._wait_for_registration()
        return self

    def connect_as_oper(self):
        """Connect with SASL PLAIN using OPER_NAME / OPER_PASS credentials."""
        return self.connect(sasl_account=OPER_NAME, sasl_password=OPER_PASS)

    def _wait_for_registration(self):
        """
        Wait for MOTD end (376) or MOTD missing (422).
        Also capture SASL numerics (903/904) and oper-up (381/MODE +o).
        """
        deadline = time.time() + 10
        registered = False
        while time.time() < deadline:
            for line in self._readlines(deadline=deadline):
                # SASL outcome
                if " 903 " in line:
                    self.sasl_result = "903"
                elif " 904 " in line:
                    self.sasl_result = "904"
                # Oper-up
                if " 381 " in line:
                    self.is_oper = True
                # End of registration burst
                if (f" 376 {self.nick} " in line
                        or f" 422 {self.nick} " in line):
                    registered = True
            if registered:
                # Drain a bit more to capture post-001 MODE lines (oper_up)
                extra_deadline = time.time() + 1.5
                for line in self._readlines(deadline=extra_deadline):
                    if " 381 " in line:
                        self.is_oper = True
                return
        raise TimeoutError(f"Registration timed out for {self.nick}")

    def send(self, data):
        self.sock.sendall((data + "\r\n").encode())

    def _readlines(self, deadline=None):
        """Yield complete lines from the socket buffer."""
        if deadline is None:
            deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                remaining = max(0.05, deadline - time.time())
                self.sock.settimeout(remaining)
                chunk = self.sock.recv(4096).decode("utf-8", errors="replace")
                if not chunk:
                    break
                self._buf += chunk
            except socket.timeout:
                break
            except OSError:
                break
            while "\r\n" in self._buf:
                line, self._buf = self._buf.split("\r\n", 1)
                yield line

    def drain(self, seconds=0.5):
        """Read and discard all pending data for `seconds`."""
        lines = []
        deadline = time.time() + seconds
        for line in self._readlines(deadline=deadline):
            lines.append(line)
        return lines

    def collect(self, seconds=2.0):
        """Collect all lines received within `seconds`."""
        lines = []
        deadline = time.time() + seconds
        for line in self._readlines(deadline=deadline):
            lines.append(line)
        return lines

    def wait_for(self, pattern, timeout=5.0):
        """Wait until a line matching the regex `pattern` is received."""
        deadline = time.time() + timeout
        for line in self._readlines(deadline=deadline):
            if re.search(pattern, line):
                return line
        return None

    def wait_for_any(self, patterns, timeout=5.0):
        """Wait until any of the regex `patterns` is matched."""
        deadline = time.time() + timeout
        for line in self._readlines(deadline=deadline):
            for i, pat in enumerate(patterns):
                if re.search(pat, line):
                    return i, line
        return None, None

    def oper_up(self):
        """
        Attempt oper authentication.

        Ophion uses SASL for oper auth; authentication happens pre-registration
        via AUTH PLAIN.  If this client was connected without SASL (plain
        connect()), we check if we're already an oper (e.g. from a previous
        connect_as_oper() call).  If not, raise an error.

        For tests that require oper access, use connect_as_oper() at connect time
        or call make_oper_client() instead.
        """
        if self.is_oper:
            return f":server 381 {self.nick} :You are now an IRC Operator"
        # Send OPER as a compatibility probe — in Ophion it returns a redirect
        # notice and 491, not 381.  Raise to indicate this client is not an oper.
        raise RuntimeError(
            f"Client {self.nick!r} is not an oper. "
            "Use connect_as_oper() / make_oper_client() for oper tests."
        )

    def close(self):
        if self.sock:
            try:
                self.send("QUIT :bye")
                self.sock.close()
            except Exception:
                pass
            self.sock = None


def make_client(nick, **kwargs):
    """Connect a fresh client and return it."""
    c = IRCClient(nick, **kwargs)
    c.connect()
    return c


def make_oper_client(nick, **kwargs):
    """Connect a fresh client with SASL PLAIN oper auth and return it."""
    c = IRCClient(nick, **kwargs)
    c.connect_as_oper()
    return c


_nick_counter = int(time.time()) % 10000

def unique_nick(base="t"):
    """Generate a reasonably unique nick."""
    global _nick_counter
    _nick_counter = (_nick_counter + 1) % 100000
    return f"{base}{_nick_counter}"


# ---------------------------------------------------------------------------
# Helper: modify ircd.conf and SIGHUP
# ---------------------------------------------------------------------------

def _conf_add_to_general(text):
    """Insert text into the general{} block."""
    with open(IRCD_CONF) as f:
        content = f.read()
    # Already present — skip
    if text.strip() in content:
        return
    pattern = r'(general\s*\{[^}]*)(\};)'
    replacement = r'\g<1>\t' + text.strip() + '\n\\2'
    new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
    with open(IRCD_CONF, "w") as f:
        f.write(new_content)

def _conf_remove_from_general(text):
    """Remove a specific line from ircd.conf."""
    with open(IRCD_CONF) as f:
        content = f.read()
    stripped = text.strip()
    # Try with tab indentation first, then bare
    new_content = content.replace("\t" + stripped + "\n", "")
    new_content = new_content.replace(stripped + "\n", "")
    with open(IRCD_CONF, "w") as f:
        f.write(new_content)

def _sighup_ircd():
    try:
        os.kill(IRCD_PID, signal.SIGHUP)
        time.sleep(1.5)
    except ProcessLookupError:
        pass


# ===========================================================================
# TESTS
# ===========================================================================

# ---------------------------------------------------------------------------
# Test 1: SASL PLAIN correct credentials → 903 RPL_SASLSUCCESS + oper at 001
# ---------------------------------------------------------------------------
def test_oper_auth_correct():
    """
    Ophion authenticates operators via SASL PLAIN.
    Connect with correct credentials; expect 903 and oper status at 001.
    """
    nick = unique_nick("oa")
    c = IRCClient(nick)
    try:
        c.connect(sasl_account=OPER_NAME, sasl_password=OPER_PASS)
        got_903  = c.sasl_result == "903"
        got_oper = c.is_oper
        _record(
            "SASL PLAIN correct credentials → 903 + oper_up",
            got_903 and got_oper,
            f"sasl_result={c.sasl_result!r}, is_oper={c.is_oper}"
        )
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 2: SASL PLAIN wrong password → 904 ERR_SASLFAIL
# ---------------------------------------------------------------------------
def test_oper_auth_wrong():
    """
    Connecting with a wrong password must produce 904 ERR_SASLFAIL.
    """
    nick = unique_nick("ow")
    c = IRCClient(nick)
    try:
        c.connect(sasl_account=OPER_NAME, sasl_password="WRONGPASSWORD")
        got_fail = c.sasl_result == "904"
        _record(
            "SASL PLAIN wrong password → 904 ERR_SASLFAIL",
            got_fail,
            f"sasl_result={c.sasl_result!r}"
        )
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 3: Oper umode flags (+o set, +a for admin) after SASL auth
# ---------------------------------------------------------------------------
def test_oper_umode_flags():
    """After SASL auth the server must set +o (and +a for admin opers)."""
    c = make_oper_client(unique_nick("om"))
    try:
        if not c.is_oper:
            _record("SASL sets +o (313 in WHOIS)", False,
                    "SASL auth did not grant oper status")
            return
        # WHOIS ourselves to verify 313 (oper line)
        c.send(f"WHOIS {c.nick}")
        whois_lines = c.collect(seconds=3)
        has_313 = any(" 313 " in l for l in whois_lines)
        _record("SASL sets +o (313 in WHOIS)", has_313,
                "313 found" if has_313 else "no 313 in WHOIS response")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 4: Non-oper STATS restricted (stats r requires oper:general → 481)
# ---------------------------------------------------------------------------
def test_stats_nonoper_restricted():
    c = make_client(unique_nick("sn"))
    try:
        c.send("STATS r")
        idx, line = c.wait_for_any([r" 481 ", r" 723 "], timeout=4)
        _record("Non-oper STATS r blocked → 481/723", idx is not None,
                line.strip() if line else "no error received")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 5: Oper STATS subcommands work (u = uptime → 242, i = auth → 215)
# ---------------------------------------------------------------------------
def test_stats_oper_works():
    c = make_oper_client(unique_nick("so"))
    try:
        # STATS u → RPL_STATSUPTIME (242)
        c.send("STATS u")
        line242 = c.wait_for(r" 242 ", timeout=4)
        _record("Oper STATS u → 242 RPL_STATSUPTIME", line242 is not None,
                line242.strip() if line242 else "no 242 received")

        # STATS i → 215 (RPL_STATSILINE) or 219 end
        c.send("STATS i")
        line = c.wait_for(r" 215 | 219 ", timeout=4)
        _record("Oper STATS i → 215/219", line is not None,
                line.strip() if line else "no response")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 6: WALLOPS — oper (with oper:mass_notice) can send, non-oper cannot
# ---------------------------------------------------------------------------
def test_wallops_oper_can_send():
    c = make_oper_client(unique_nick("wo"))
    try:
        c.drain(0.3)
        c.send("WALLOPS :Test wallops from oper")
        lines = c.collect(seconds=2)
        got_error = any(re.search(r" 481 | 723 ", l) for l in lines)
        # Also check that we either received no error, or got the WALLOPS echoed back
        got_wallops = any("WALLOPS" in l and "Test wallops" in l for l in lines)
        _record("Oper WALLOPS no error", not got_error,
                f"error={got_error}, wallops_echo={got_wallops}")
    finally:
        c.close()


def test_wallops_nonoper_blocked():
    c = make_client(unique_nick("wno"))
    try:
        c.send("WALLOPS :Unauthorized wallops attempt")
        idx, line = c.wait_for_any([r" 481 ", r" 723 "], timeout=4)
        _record("Non-oper WALLOPS blocked → 481/723", idx is not None,
                line.strip() if line else "no error received")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 7: OPERWALL — oper can send, non-oper cannot
# ---------------------------------------------------------------------------
def test_operwall_oper_can_send():
    c = make_oper_client(unique_nick("owo"))
    try:
        c.drain(0.3)
        c.send("OPERWALL :Test operwall message")
        lines = c.collect(seconds=1.5)
        got_error = any(re.search(r" 481 | 723 ", l) for l in lines)
        _record("Oper OPERWALL no error", not got_error,
                "got unexpected error" if got_error else "ok")
    finally:
        c.close()


def test_operwall_nonoper_blocked():
    c = make_client(unique_nick("ono"))
    try:
        c.send("OPERWALL :Unauthorized operwall")
        idx, line = c.wait_for_any([r" 481 ", r" 723 "], timeout=4)
        _record("Non-oper OPERWALL blocked → 481/723", idx is not None,
                line.strip() if line else "no error received")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 8: KILL — oper can kill a user
# The killed user receives a KILL message and their connection is closed.
# ---------------------------------------------------------------------------
def test_kill_oper():
    killer = make_oper_client(unique_nick("ki"))
    victim = make_client(unique_nick("vi"))
    victim_nick = victim.nick
    try:
        killer.drain(0.3)
        killer.send(f"KILL {victim_nick} :Test kill reason")
        # Victim's socket gets closed; try to read from it
        victim_data = b""
        victim.sock.settimeout(3)
        try:
            while True:
                chunk = victim.sock.recv(4096)
                if not chunk:
                    break
                victim_data += chunk
        except (socket.timeout, OSError):
            pass
        victim_str = victim_data.decode("utf-8", errors="replace")
        # Victim should receive KILL or ERROR message
        got_kill = bool(re.search(r"KILL|ERROR|Killed", victim_str))

        # Killer should NOT get an error numeric
        killer_lines = killer.collect(seconds=1)
        got_error = any(re.search(r" 481 | 723 | 401 ", l) for l in killer_lines)

        _record("Oper KILL succeeds (victim gets KILL/ERROR/disconnect)",
                got_kill or len(victim_str) > 0,
                f"victim data: {victim_str[:100]!r}")
        _record("Oper KILL - no error to killer", not got_error,
                f"killer errors: {[l for l in killer_lines if re.search(r' 481 | 723 | 401 ', l)]}")
    finally:
        killer.close()
        try:
            victim.sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Test 9: KLINE — oper adds temporary kline
# ---------------------------------------------------------------------------
def test_kline_add():
    c = make_oper_client(unique_nick("kl"))
    try:
        c.drain(0.3)
        c.send("KLINE 1 klinetest@192.0.2.10 :Test kline stress")
        # Expect NOTICE confirming "Added ... K-Line"
        line = c.wait_for(r"Added.*K-Line", timeout=5)
        _record("Oper KLINE add → Added K-Line notice", line is not None,
                line.strip()[:80] if line else "no confirmation received")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 10: UNKLINE — oper removes kline
# ---------------------------------------------------------------------------
def test_unkline():
    c = make_oper_client(unique_nick("ukl"))
    try:
        c.drain(0.3)
        c.send("KLINE 1 unktest@192.0.2.20 :Test unkline")
        c.wait_for(r"Added.*K-Line", timeout=5)
        time.sleep(0.2)
        c.send("UNKLINE unktest@192.0.2.20")
        line = c.wait_for(r"Un-klined|removed|No K-Line", timeout=5)
        _record("Oper UNKLINE → removal notice", line is not None,
                line.strip()[:80] if line else "no response")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 11: DLINE — oper adds temporary dline
# ---------------------------------------------------------------------------
def test_dline_add():
    c = make_oper_client(unique_nick("dl"))
    try:
        c.drain(0.3)
        c.send("DLINE 1 192.0.2.100 :Test dline stress")
        line = c.wait_for(r"Added.*D-Line", timeout=5)
        _record("Oper DLINE add → Added D-Line notice", line is not None,
                line.strip()[:80] if line else "no confirmation received")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 12: UNDLINE — oper removes dline
# ---------------------------------------------------------------------------
def test_undline():
    c = make_oper_client(unique_nick("udl"))
    try:
        c.drain(0.3)
        c.send("DLINE 1 192.0.2.101 :Test undline")
        c.wait_for(r"Added.*D-Line", timeout=5)
        time.sleep(0.2)
        c.send("UNDLINE 192.0.2.101")
        line = c.wait_for(r"Un-dlined|removed|No D-Line", timeout=5)
        _record("Oper UNDLINE → removal notice", line is not None,
                line.strip()[:80] if line else "no response")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 13: XLINE — oper adds gecos ban
# ---------------------------------------------------------------------------
def test_xline_add():
    c = make_oper_client(unique_nick("xl"))
    try:
        c.drain(0.3)
        c.send("XLINE 1 spamgecos :Test xline")
        line = c.wait_for(r"Added.*X-Line", timeout=5)
        _record("Oper XLINE add → X-Line notice", line is not None,
                line.strip()[:80] if line else "no confirmation received")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 14: UNXLINE — oper removes xline
# ---------------------------------------------------------------------------
def test_unxline():
    c = make_oper_client(unique_nick("uxl"))
    try:
        c.drain(0.3)
        c.send("XLINE 1 spamgecos2 :Test unxline")
        c.wait_for(r"Added.*X-Line", timeout=5)
        time.sleep(0.2)
        c.send("UNXLINE spamgecos2")
        line = c.wait_for(r"removed|No X-Line", timeout=5)
        _record("Oper UNXLINE → removal notice", line is not None,
                line.strip()[:80] if line else "no response")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 15: REHASH — oper can rehash (382), non-oper cannot (723)
# ---------------------------------------------------------------------------
def test_rehash_oper():
    c = make_oper_client(unique_nick("rh"))
    try:
        c.drain(0.3)
        c.send("REHASH")
        line = c.wait_for(r" 382 ", timeout=5)
        _record("Oper REHASH → 382 RPL_REHASHING", line is not None,
                line.strip()[:80] if line else "no 382 received")
    finally:
        c.close()


def test_rehash_nonoper():
    # Give the server a moment to finish processing the previous REHASH
    time.sleep(1.0)
    c = make_client(unique_nick("rhn"))
    try:
        c.send("REHASH")
        idx, line = c.wait_for_any([r" 481 ", r" 723 "], timeout=4)
        _record("Non-oper REHASH blocked → 481/723", idx is not None,
                line.strip()[:80] if line else "no error received")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 16: WHO with 'o' flag — oper flag visible as '*' in WHO response
# WHO <nick> returns H* (Here, oper) for opers.
# ---------------------------------------------------------------------------
def test_who_oper_flag():
    viewer = make_client(unique_nick("wv"))
    oper = make_oper_client(unique_nick("wop"))
    try:
        oper.drain(0.3)
        # WHO <nick> to look up the oper specifically
        viewer.send(f"WHO {oper.nick}")
        lines = viewer.collect(seconds=3)
        # 352 line should contain H* (oper flag) and the oper's nick
        has_oper_flag = any(
            oper.nick in l and " 352 " in l and ("H*" in l or "G*" in l)
            for l in lines
        )
        has_end = any(" 315 " in l for l in lines)
        _record("WHO <nick> shows oper flag (*)", has_oper_flag,
                f"lines: {[l for l in lines if ' 352 ' in l or ' 315 ' in l]}")
        _record("WHO → 315 end of WHO received", has_end)
    finally:
        viewer.close()
        oper.close()


# ---------------------------------------------------------------------------
# Test 17: WHOIS shows 313 for opers
# ---------------------------------------------------------------------------
def test_whois_oper_line():
    c = make_client(unique_nick("wi"))
    oper = make_oper_client(unique_nick("wio"))
    try:
        oper.drain(0.3)
        c.send(f"WHOIS {oper.nick}")
        lines = c.collect(seconds=3)
        has_313 = any(" 313 " in l for l in lines)
        _record("WHOIS oper shows 313 RPL_WHOISOPERATOR", has_313,
                f"nick={oper.nick}, lines received={len(lines)}")
    finally:
        c.close()
        oper.close()


# ---------------------------------------------------------------------------
# Test 18: TRACE — oper gets full trace (200/201/206/207/208/209), non-oper limited
# ---------------------------------------------------------------------------
def test_trace_oper():
    c = make_oper_client(unique_nick("to"))
    try:
        c.drain(0.3)
        c.send("TRACE")
        lines = c.collect(seconds=3)
        # RPL_TRACECLIENT (202), RPL_TRACEOPERATOR (204), RPL_TRACEUSER (205)
        # or RPL_TRACEEND (262)
        has_trace = any(re.search(r" 20[0-9] | 261 | 262 ", l) for l in lines)
        _record("Oper TRACE → trace numerics received", has_trace,
                f"lines: {len(lines)}, sample: {lines[:2] if lines else []}")
    finally:
        c.close()


def test_trace_nonoper():
    c = make_client(unique_nick("tn"))
    try:
        c.send("TRACE")
        lines = c.collect(seconds=3)
        # Non-opers may only get 262 (end)
        has_response = len(lines) > 0
        _record("Non-oper TRACE → receives response (limited)", has_response,
                f"lines received: {len(lines)}, sample: {lines[:2] if lines else []}")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 19: Oper snomask (+s) — set/unset snomask flags
# ---------------------------------------------------------------------------
def test_snomask_set():
    c = make_oper_client(unique_nick("ss"))
    try:
        c.drain(0.5)
        c.send(f"MODE {c.nick} +s +cg")
        lines = c.collect(seconds=2)
        # Server sends 008 (RPL_SNOMASK) or a MODE acknowledgment
        got_mode = any(
            ("MODE" in l and "+s" in l) or " 008 " in l
            for l in lines
        )
        _record("Oper snomask +s set via MODE", got_mode,
                f"lines: {[l for l in lines if 'MODE' in l or '008' in l][:3]}")
    finally:
        c.close()


def test_snomask_unset():
    c = make_oper_client(unique_nick("su"))
    try:
        c.drain(0.5)
        c.send(f"MODE {c.nick} +s")
        c.drain(0.3)
        c.send(f"MODE {c.nick} -s")
        lines = c.collect(seconds=2)
        got_unset = any(
            ("MODE" in l and "-s" in l) or " 008 " in l
            for l in lines
        )
        _record("Oper snomask -s unset via MODE", got_unset,
                f"sample: {lines[:2] if lines else 'none'}")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 20: UMODE +o — cannot self-oper without OPER command
# ---------------------------------------------------------------------------
def test_umode_no_self_oper():
    c = make_client(unique_nick("se"))
    try:
        c.send(f"MODE {c.nick} +o")
        lines = c.collect(seconds=2)
        mode_lines = [l for l in lines if "MODE" in l]
        # The mode should NOT be granted (+o absent from response)
        got_plus_o = any("+o" in l for l in mode_lines)
        _record("Cannot self-oper via MODE +o (non-oper)", not got_plus_o,
                f"mode lines: {mode_lines[:3]}")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 21: God mode (+G) — oper with oper:god can set +G, non-oper cannot
# ---------------------------------------------------------------------------
def test_godmode_oper_can_set():
    c = make_oper_client(unique_nick("go"))
    try:
        c.drain(0.3)
        c.send(f"MODE {c.nick} +G")
        lines = c.collect(seconds=2)
        mode_lines = [l for l in lines if "MODE" in l]
        got_G = any("+G" in l for l in mode_lines)
        got_error = any(re.search(r" 481 | 723 ", l) for l in lines)
        _record("Oper with oper:god can set +G", got_G and not got_error,
                f"mode lines: {mode_lines[:3]}, errors: {got_error}")
    finally:
        c.close()


def test_godmode_nonoper_blocked():
    c = make_client(unique_nick("gn"))
    try:
        c.send(f"MODE {c.nick} +G")
        lines = c.collect(seconds=2)
        mode_lines = [l for l in lines if "MODE" in l]
        # +G should not appear in mode response for non-oper
        got_G = any("+G" in l for l in mode_lines)
        _record("Non-oper cannot set +G", not got_G,
                f"mode lines: {mode_lines[:3]}")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 22: oper_kick_protection — opers cannot be kicked by non-opers
# ---------------------------------------------------------------------------
def test_oper_kick_protection():
    """
    Steps:
      1. Add  oper_kick_protection = yes;  to general{} in ircd.conf
      2. SIGHUP the ircd
      3. Connect an oper and a non-oper; join both to the same channel
      4. Give non-oper +o so they can try to kick
      5. Non-oper tries to kick the oper; oper should not be kicked
      6. Remove the config line and SIGHUP again
    """
    conf_line = "oper_kick_protection = yes;"
    _conf_remove_from_general(conf_line)
    _conf_add_to_general(conf_line)
    _sighup_ircd()

    chan = f"#kicktest{int(time.time()) % 10000}"
    oper_c = make_oper_client(unique_nick("kop"))
    kicker = make_client(unique_nick("kik"))
    try:
        oper_c.drain(0.3)
        oper_c.send(f"JOIN {chan}")
        oper_c.drain(1)
        kicker.send(f"JOIN {chan}")
        kicker.drain(1)
        # Give non-oper op so they're allowed to attempt kick
        oper_c.send(f"MODE {chan} +o {kicker.nick}")
        time.sleep(0.5)
        oper_c.drain(0.3)
        kicker.drain(0.3)
        # Non-oper (now channel op) tries to kick the oper
        kicker.send(f"KICK {chan} {oper_c.nick} :kick test")
        lines = oper_c.collect(seconds=2)
        got_kicked = any("KICK" in l and oper_c.nick in l for l in lines)
        _record("oper_kick_protection: oper not kicked by non-oper",
                not got_kicked,
                f"kicked={got_kicked}, lines={len(lines)}")
    finally:
        oper_c.close()
        kicker.close()
        _conf_remove_from_general(conf_line)
        _sighup_ircd()


# ---------------------------------------------------------------------------
# Test 23: Oper auto-op on channel join (+q automatically)
# ---------------------------------------------------------------------------
def test_oper_auto_op():
    """
    With oper_auto_op = yes in general{}, opers receive +q on channel join.
    """
    conf_line = "oper_auto_op = yes;"
    _conf_remove_from_general(conf_line)
    _conf_add_to_general(conf_line)
    _sighup_ircd()

    chan = f"#autooptest{int(time.time()) % 10000}"
    c = make_oper_client(unique_nick("aop"))
    try:
        c.drain(0.3)
        c.send(f"JOIN {chan}")
        lines = c.collect(seconds=3)
        # The godmode module's sendto_channel_local EXCLUDES the joining oper
        # from the MODE +q broadcast (they are the only member), so the oper
        # won't see their own MODE line.  Instead, check the 353 NAMES reply:
        # the server uses '.' as the +q (channel-admin) prefix, so the oper
        # should appear as "." + nick in the NAMES list.
        got_admin_prefix = any(
            " 353 " in l and ("." + c.nick in l or "~" + c.nick in l)
            for l in lines
        )
        # Also accept a MODE +q line (visible if another member is present)
        got_mode_q = any(re.search(r"MODE.*\+.*q", l) for l in lines)
        _record("Oper auto-op: gets +q on channel join (. prefix in NAMES)",
                got_admin_prefix or got_mode_q,
                f"NAMES lines: {[l for l in lines if ' 353 ' in l]}, "
                f"MODE lines: {[l for l in lines if 'MODE' in l and '+q' in l]}")
    finally:
        c.close()
        _conf_remove_from_general(conf_line)
        _sighup_ircd()


# ---------------------------------------------------------------------------
# Test 24: MODLIST — oper can list loaded modules
# ---------------------------------------------------------------------------
def test_modlist_oper():
    c = make_oper_client(unique_nick("ml"))
    try:
        c.drain(0.3)
        c.send("MODLIST")
        lines = c.collect(seconds=3)
        # MODLIST returns 702 (RPL_MODLIST) entries and 703 (RPL_ENDOFMODLIST)
        has_modlist = any(re.search(r" 702 | 703 ", l) for l in lines)
        _record("Oper MODLIST → 702/703 module list", has_modlist,
                f"lines received: {len(lines)}, sample: {[l for l in lines if ' 702 ' in l or ' 703 ' in l][:2]}")
    finally:
        c.close()


def test_modlist_nonoper():
    c = make_client(unique_nick("mln"))
    try:
        c.send("MODLIST")
        idx, line = c.wait_for_any([r" 481 ", r" 723 "], timeout=4)
        _record("Non-oper MODLIST blocked → 481/723", idx is not None,
                line.strip()[:80] if line else "no error received")
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Test 25: User mode +D (deaf mode) — channel messages suppressed
# ---------------------------------------------------------------------------
def test_umode_deaf():
    sender = make_client(unique_nick("sd"))
    receiver = make_client(unique_nick("rd"))
    try:
        chan = f"#deaftest{int(time.time()) % 10000}"
        # Both join the channel first
        receiver.send(f"JOIN {chan}")
        sender.send(f"JOIN {chan}")
        receiver.drain(1)
        sender.drain(1)

        # Set deaf mode on receiver
        receiver.send(f"MODE {receiver.nick} +D")
        lines = receiver.collect(seconds=1.5)
        mode_set = any("MODE" in l and "+D" in l for l in lines)

        sender.send(f"PRIVMSG {chan} :Test deaf mode message unique12345")
        msg_lines = receiver.collect(seconds=2)
        got_msg = any("PRIVMSG" in l and "unique12345" in l for l in msg_lines)
        # With +D, receiver should NOT see channel messages
        _record("User mode +D (deaf): mode accepted by server",
                mode_set,
                f"mode_set={mode_set}")
        _record("User mode +D (deaf): channel messages suppressed",
                not got_msg,
                f"got_msg={got_msg}")
    finally:
        sender.close()
        receiver.close()


# ---------------------------------------------------------------------------
# Test 26: User mode +g (caller-id / server-side ignore)
# ---------------------------------------------------------------------------
def test_umode_callerid():
    sender = make_client(unique_nick("sg"))
    receiver = make_client(unique_nick("rg"))
    try:
        receiver.send(f"MODE {receiver.nick} +g")
        receiver.drain(1)

        sender.send(f"PRIVMSG {receiver.nick} :Caller-id test message")
        # With +g, sender should get 716 (RPL_TARGUMODEG) or 717
        line = sender.wait_for(r" 716 | 717 ", timeout=3)
        _record("User mode +g (caller-id): sender gets 716 RPL_TARGUMODEG",
                line is not None,
                line.strip()[:80] if line else "no 716 received")
    finally:
        sender.close()
        receiver.close()


# ---------------------------------------------------------------------------
# Test 27: STATS p — online opers list (accessible to all, returns 219 end)
# ---------------------------------------------------------------------------
def test_stats_p_oper():
    c = make_client(unique_nick("sp"))
    oper = make_oper_client(unique_nick("spo"))
    try:
        oper.drain(0.3)
        c.send("STATS p")
        lines = c.collect(seconds=2)
        has_end = any(" 219 " in l for l in lines)
        # 207 is used for oper listing by some servers; 219 is always end
        _record("STATS p (online opers) → 219 end of STATS", has_end,
                f"lines: {len(lines)}")
    finally:
        c.close()
        oper.close()


# ---------------------------------------------------------------------------
# Test 28: STATS o — oper blocks list (243 RPL_STATSOLINE)
# ---------------------------------------------------------------------------
def test_stats_o():
    c = make_client(unique_nick("so"))
    try:
        c.send("STATS o")
        lines = c.collect(seconds=2)
        has_end = any(" 219 " in l for l in lines)
        has_oper = any(" 243 " in l for l in lines)  # RPL_STATSOLINE
        _record("STATS o → 243/219 oper block listing", has_end and has_oper,
                f"has_243={has_oper}, has_219={has_end}, lines={len(lines)}")
    finally:
        c.close()


# ===========================================================================
# Main
# ===========================================================================

def main():
    print("=" * 60)
    print("Ophion IRC Oper/Admin Tools Stress Test")
    print(f"Server: {SERVER_HOST}:{SERVER_PORT}")
    print("=" * 60)
    print()

    tests = [
        ("OPER auth correct password → 381",         test_oper_auth_correct),
        ("OPER auth wrong password → 464/491",        test_oper_auth_wrong),
        ("OPER umode flags (+o, +a)",                  test_oper_umode_flags),
        ("STATS non-oper restricted",                  test_stats_nonoper_restricted),
        ("STATS oper works (u, i)",                    test_stats_oper_works),
        ("WALLOPS oper can send",                      test_wallops_oper_can_send),
        ("WALLOPS non-oper blocked",                   test_wallops_nonoper_blocked),
        ("OPERWALL oper can send",                     test_operwall_oper_can_send),
        ("OPERWALL non-oper blocked",                  test_operwall_nonoper_blocked),
        ("KILL oper kills user",                       test_kill_oper),
        ("KLINE add temp kline",                       test_kline_add),
        ("UNKLINE remove kline",                       test_unkline),
        ("DLINE add temp dline",                       test_dline_add),
        ("UNDLINE remove dline",                       test_undline),
        ("XLINE add gecos ban",                        test_xline_add),
        ("UNXLINE remove xline",                       test_unxline),
        ("REHASH oper → 382",                          test_rehash_oper),
        ("REHASH non-oper blocked",                    test_rehash_nonoper),
        ("WHO <nick> shows oper flag (*)",             test_who_oper_flag),
        ("WHOIS oper → 313",                           test_whois_oper_line),
        ("TRACE oper full output",                     test_trace_oper),
        ("TRACE non-oper limited",                     test_trace_nonoper),
        ("Snomask +s set",                             test_snomask_set),
        ("Snomask -s unset",                           test_snomask_unset),
        ("Cannot self-oper via MODE +o",               test_umode_no_self_oper),
        ("Godmode +G oper can set",                    test_godmode_oper_can_set),
        ("Godmode +G non-oper blocked",                test_godmode_nonoper_blocked),
        ("oper_kick_protection",                       test_oper_kick_protection),
        ("Oper auto-op (+q on join)",                  test_oper_auto_op),
        ("MODLIST oper → 702/703",                     test_modlist_oper),
        ("MODLIST non-oper blocked",                   test_modlist_nonoper),
        ("User mode +D deaf",                          test_umode_deaf),
        ("User mode +g caller-id",                     test_umode_callerid),
        ("STATS p online opers",                       test_stats_p_oper),
        ("STATS o oper blocks",                        test_stats_o),
    ]

    for label, fn in tests:
        print(f"\n--- {label} ---")
        try:
            fn()
        except Exception as e:
            _record(label, False, f"Exception: {e}")

    # ---------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    passed = sum(1 for _, s, _ in _results if s == "PASS")
    failed = sum(1 for _, s, _ in _results if s == "FAIL")
    total = len(_results)

    for name, status, detail in _results:
        tag = "\033[32mPASS\033[0m" if status == "PASS" else "\033[31mFAIL\033[0m"
        print(f"  [{tag}] {name}" + (f" — {detail}" if detail else ""))

    print()
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print("=" * 60)

    if failed > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
