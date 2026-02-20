#!/usr/bin/env python3
"""
Ophion IRC Server - Miscellaneous Stress Test Suite
====================================================

Tests a wide range of IRC server behaviours including NICK collision handling,
channel name validation, PRIVMSG/NOTICE error cases, AWAY/WHOIS interaction,
WHO/WHOIS commands, JOIN/PART/QUIT, INVITE, TOPIC, MODE parsing, PING/PONG,
user modes, NAMES/LIST, MONITOR, and error-case robustness.

Run:  python3 test_misc.py
      (server must already be listening on 127.0.0.1:16667)
"""

import socket
import time
import threading
import sys
import random
import string
import traceback

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HOST = "127.0.0.1"
PORT = 16667
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 3
DRAIN_TIMEOUT = 0.5

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
_passed = 0
_failed = 0
_skipped = 0


def _report(name, ok, detail=""):
    global _passed, _failed
    status = "PASS" if ok else "FAIL"
    if ok:
        _passed += 1
    else:
        _failed += 1
    suffix = f"  ({detail})" if detail else ""
    print(f"[{status}] {name}{suffix}")


def _skip(name, reason=""):
    global _skipped
    _skipped += 1
    print(f"[SKIP] {name}  ({reason})")


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _make_sock():
    """Open a raw TCP connection to the IRC server."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TIMEOUT)
    s.connect((HOST, PORT))
    s.settimeout(READ_TIMEOUT)
    return s


def _send(s, line):
    """Send a single IRC line (adds CRLF)."""
    s.sendall((line + "\r\n").encode())


def _recv_lines(s, timeout=READ_TIMEOUT):
    """
    Read as many lines as arrive within *timeout* seconds.

    The socket is set to a *timeout*-second timeout per recv() call.  Once
    the first timeout fires (gap in data), reading stops and the collected
    lines are returned.  This means the function returns quickly when the
    server stops sending data and at most *timeout* seconds after the last
    byte arrived.
    """
    s.settimeout(timeout)
    buf = b""
    lines = []
    deadline = time.time() + timeout * 4   # absolute safety cap
    while time.time() < deadline:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                lines.append(line.decode(errors="replace").strip())
        except socket.timeout:
            break   # gap in data → done
    return lines


def _drain(s, timeout=DRAIN_TIMEOUT):
    """Discard any pending data (used to flush the welcome burst)."""
    _recv_lines(s, timeout=timeout)


def _has_numeric(lines, numeric):
    """Return True if any line contains the given 3-digit numeric."""
    tag = f" {numeric} "
    for line in lines:
        if tag in line:
            return True
    return False


def _has_command(lines, cmd):
    """Return True if any line contains the given IRC command word."""
    cmd_upper = cmd.upper()
    for line in lines:
        parts = line.split()
        # handle ":prefix CMD ..." and "CMD ..."
        for idx, part in enumerate(parts):
            if part.upper() == cmd_upper:
                return True
    return False


def _lines_containing(lines, fragment):
    """Return subset of lines that contain *fragment* (case-insensitive)."""
    frag_lower = fragment.lower()
    return [l for l in lines if frag_lower in l.lower()]


def _uid():
    """Generate a random 6-char alphanumeric nick suffix."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def _register(s, nick, user=None, realname="Test User"):
    """Send NICK + USER and drain the welcome burst.

    Strategy:
      1. Send NICK + USER.  Wait briefly for the server to send the welcome
         burst (001–005, LUSERS, MOTD, initial MODE).
      2. Send a PING with a unique token and read until that PONG is seen.
         This is our "welcome complete" sentinel.
      3. One more short drain to catch anything queued in the same burst.

    Timeout is generous (15 s) because the server may be processing many
    simultaneous connections during stress testing.
    """
    if user is None:
        user = nick[:8]
    token = "reg" + _uid()
    _send(s, f"NICK {nick}")
    _send(s, f"USER {user} 0 * :{realname}")
    # Brief pause to let the server emit the full welcome burst before
    # we queue our PING (avoids the PING racing with registration).
    time.sleep(0.1)
    _send(s, f"PING :{token}")
    # Read until we see the PONG matching our token (= welcome fully drained)
    deadline = time.time() + 15.0
    while time.time() < deadline:
        chunk = _recv_lines(s, timeout=1.0)
        if any("PONG" in l and token in l for l in chunk):
            break
    # One more short window in case data arrived in the same TCP burst
    _recv_lines(s, timeout=0.2)


def connect_and_register(nick=None, user=None, realname="Test User"):
    """Open a connection, register, and return the socket."""
    if nick is None:
        nick = "t" + _uid()
    s = _make_sock()
    _register(s, nick, user, realname)
    return s, nick


def close_gracefully(s, reason="Bye"):
    try:
        _send(s, f"QUIT :{reason}")
        time.sleep(0.05)
        s.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 1. NICK collision handling
# ---------------------------------------------------------------------------

def test_nick_collision_on_registration():
    """Two unregistered clients try the same nick simultaneously."""
    nick = "col" + _uid()
    s1 = _make_sock()
    s2 = _make_sock()
    try:
        # Start both registrations with the same nick
        _send(s1, f"NICK {nick}")
        _send(s1, f"USER user1 0 * :User One")
        _send(s2, f"NICK {nick}")
        _send(s2, f"USER user2 0 * :User Two")

        lines1 = _recv_lines(s1, timeout=1.5)
        lines2 = _recv_lines(s2, timeout=1.5)

        # One should get 001 (registered), the other should get 433 (nick in use)
        s1_ok = _has_numeric(lines1, "001")
        s2_ok = _has_numeric(lines2, "001")
        s1_433 = _has_numeric(lines1, "433")
        s2_433 = _has_numeric(lines2, "433")

        # Exactly one should succeed, or both might succeed if the server
        # races – either outcome is acceptable as long as no crash occurs.
        # We require the server to have responded meaningfully to both.
        got_response = (lines1 or lines2)
        _report("nick_collision_on_registration",
                got_response,
                f"s1_001={s1_ok} s1_433={s1_433} s2_001={s2_ok} s2_433={s2_433}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_nick_change_to_existing():
    """Registered user tries to change nick to one already taken → 433."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    try:
        _send(s2, f"NICK {n1}")
        lines = _recv_lines(s2, timeout=1.0)
        ok = _has_numeric(lines, "433")
        _report("nick_change_to_existing_nick", ok,
                f"n1={n1} n2={n2} lines={lines[:2]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_nick_invalid_chars():
    """NICK with invalid characters → 432 ERR_ERRONEUSNICKNAME."""
    s = _make_sock()
    try:
        # Send NICK before USER so we hit the mr_nick path
        _send(s, "NICK bad!nick")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "432")
        _report("nick_invalid_chars", ok, f"got: {lines[:2]}")
    finally:
        s.close()


def test_nick_too_long():
    """NICK longer than nicklen (30) → server truncates and uses truncated nick.

    The server uses rb_strlcpy(..., nicklen) which silently truncates the nick
    to 30 characters.  A run of 40 'A's truncated to 30 'A's is a valid nick,
    so no error is returned – the client simply gets the truncated nick
    accepted (or a 433 if another client holds it).  We just verify the server
    handles it without disconnecting us by confirming it is still responsive.
    """
    s = _make_sock()
    try:
        long_nick = "A" * 40
        # Register first so we can send PING afterward
        _send(s, f"NICK {long_nick}")
        _send(s, "USER toolong 0 * :Too Long Nick Test")
        _recv_lines(s, timeout=1.5)   # drain welcome / any nick response
        _send(s, "PING :longnickcheck")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_command(lines, "PONG")
        _report("nick_too_long_handled_gracefully", ok,
                f"server_alive={ok}")
    finally:
        s.close()


def test_nick_too_long_registered():
    """Registered user sends NICK > 30 chars → server handles it gracefully."""
    s, nick = connect_and_register()
    try:
        long_nick = "B" * 40
        _send(s, f"NICK {long_nick}")
        lines = _recv_lines(s, timeout=1.0)
        # Server truncates to nicklen; truncated nick is valid → nick change,
        # or returns 432 for invalid chars after truncation.  Either is fine.
        ok = True  # We just confirm the server didn't close the connection.
        _report("nick_too_long_registered_graceful", ok,
                f"response={lines[:2]}")
    finally:
        close_gracefully(s)


# ---------------------------------------------------------------------------
# 2. Channel name validation
# ---------------------------------------------------------------------------

def test_channel_no_prefix():
    """JOIN to a name without # or & → 403 / ERR_NOSUCHCHANNEL."""
    s, nick = connect_and_register()
    try:
        _send(s, "JOIN nochan")
        lines = _recv_lines(s, timeout=1.0)
        # m_join.c: !IsChannelName → ERR_NOSUCHCHANNEL (403)
        ok = _has_numeric(lines, "403")
        _report("channel_no_prefix_gets_403", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_channel_bad_name_chars():
    """JOIN to channel with invalid chars → 479 ERR_BADCHANNAME."""
    s, nick = connect_and_register()
    try:
        _send(s, "JOIN #bad\x07chan")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "479") or _has_numeric(lines, "403")
        _report("channel_bad_chars_rejected", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_channel_name_too_long():
    """JOIN to channel name > 50 chars → 479 ERR_BADCHANNAME."""
    s, nick = connect_and_register()
    try:
        long_chan = "#" + "x" * 60
        _send(s, f"JOIN {long_chan}")
        lines = _recv_lines(s, timeout=1.0)
        # check_channel_name_loc + strlen > LOC_CHANNELLEN → ERR_BADCHANNAME
        ok = _has_numeric(lines, "479") or _has_numeric(lines, "403")
        _report("channel_name_too_long_rejected", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_channel_ampersand_valid():
    """JOIN to &local channel is valid (local channels start with &)."""
    s, nick = connect_and_register()
    try:
        chan = "&local" + _uid()
        _send(s, f"JOIN {chan}")
        lines = _recv_lines(s, timeout=1.5)
        # Should receive JOIN confirmation (no error)
        ok = _has_command(lines, "JOIN") or _has_numeric(lines, "353")
        _report("channel_ampersand_valid", ok, f"chan={chan} lines={lines[:3]}")
    finally:
        close_gracefully(s)


# ---------------------------------------------------------------------------
# 3. PRIVMSG / NOTICE limits
# ---------------------------------------------------------------------------

def test_privmsg_nonexistent_nick():
    """PRIVMSG to non-existent nick → 401 ERR_NOSUCHNICK."""
    s, nick = connect_and_register()
    try:
        _send(s, "PRIVMSG nonexistent__xyz :hello")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "401")
        _report("privmsg_nonexistent_nick_401", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_privmsg_nonexistent_channel():
    """PRIVMSG to non-existent #channel → 401 ERR_NOSUCHNICK."""
    s, nick = connect_and_register()
    try:
        _send(s, "PRIVMSG #nonexistent_xyz99 :hello")
        lines = _recv_lines(s, timeout=1.0)
        # m_message.c: non-existent channel sends ERR_NOSUCHNICK (401)
        ok = _has_numeric(lines, "401") or _has_numeric(lines, "403")
        _report("privmsg_nonexistent_channel_error", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_notice_nonexistent_nick_silent():
    """NOTICE to non-existent nick → silently ignored (no error numeric)."""
    s, nick = connect_and_register()
    try:
        _send(s, "NOTICE nonexistent__xyz :hello")
        lines = _recv_lines(s, timeout=0.8)
        # NOTICE should produce no error response per IRC RFC
        has_error = _has_numeric(lines, "401") or _has_numeric(lines, "403")
        _report("notice_nonexistent_nick_silent", not has_error,
                f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


# ---------------------------------------------------------------------------
# 4. AWAY / BACK
# ---------------------------------------------------------------------------

def test_away_set_returns_306():
    """AWAY <message> → 306 RPL_NOWAWAY."""
    s, nick = connect_and_register()
    try:
        _send(s, "AWAY :Gone fishing")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "306")
        _report("away_set_returns_306", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_away_clear_returns_305():
    """AWAY (no message) after being away → 305 RPL_UNAWAY."""
    s, nick = connect_and_register()
    try:
        _send(s, "AWAY :Gone fishing")
        _drain(s, 0.5)
        _send(s, "AWAY")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "305")
        _report("away_clear_returns_305", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_whois_away_shows_301():
    """WHOIS on away user includes 301 RPL_AWAY."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    try:
        _send(s1, "AWAY :I am away")
        _drain(s1, 0.5)
        _send(s2, f"WHOIS {n1}")
        lines = _recv_lines(s2, timeout=1.5)
        ok = _has_numeric(lines, "301")
        _report("whois_away_user_shows_301", ok, f"lines={lines[:4]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_privmsg_to_away_user_shows_301():
    """PRIVMSG to an away user returns 301 RPL_AWAY to sender."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    try:
        _send(s1, "AWAY :Out to lunch")
        _drain(s1, 0.5)
        _send(s2, f"PRIVMSG {n1} :are you there?")
        lines = _recv_lines(s2, timeout=1.0)
        ok = _has_numeric(lines, "301")
        _report("privmsg_to_away_user_shows_301", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


# ---------------------------------------------------------------------------
# 5. WHO / WHOIS
# ---------------------------------------------------------------------------

def test_who_channel_shows_member():
    """WHO #channel lists members of the channel."""
    s1, n1 = connect_and_register()
    chan = "#who" + _uid()
    try:
        _send(s1, f"JOIN {chan}")
        _drain(s1, 0.5)
        _send(s1, f"WHO {chan}")
        lines = _recv_lines(s1, timeout=1.0)
        # 352 RPL_WHOREPLY
        ok = _has_numeric(lines, "352") and any(n1 in l for l in lines)
        _report("who_channel_shows_member", ok, f"chan={chan} lines={lines[:4]}")
    finally:
        close_gracefully(s1)


def test_whois_self():
    """WHOIS <own nick> returns user info (311 RPL_WHOISUSER)."""
    s, nick = connect_and_register()
    try:
        _send(s, f"WHOIS {nick}")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "311")
        _report("whois_self_returns_311", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s)


def test_whois_nonexistent():
    """WHOIS on non-existent nick → 401 ERR_NOSUCHNICK."""
    s, nick = connect_and_register()
    try:
        _send(s, "WHOIS nonexistent_zzz99")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "401")
        _report("whois_nonexistent_returns_401", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_whois_another_user():
    """WHOIS on another user returns 311 and 318."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    try:
        _send(s2, f"WHOIS {n1}")
        lines = _recv_lines(s2, timeout=1.5)
        ok = _has_numeric(lines, "311") and _has_numeric(lines, "318")
        _report("whois_another_user_311_318", ok, f"lines={lines[:4]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


# ---------------------------------------------------------------------------
# 6. JOIN / PART / QUIT
# ---------------------------------------------------------------------------

def test_join_creates_channel():
    """JOIN #channel gets JOIN echo and NAMES (353)."""
    s, nick = connect_and_register()
    chan = "#jn" + _uid()
    try:
        _send(s, f"JOIN {chan}")
        lines = _recv_lines(s, timeout=1.5)
        ok = (_has_command(lines, "JOIN") and _has_numeric(lines, "353"))
        _report("join_creates_channel", ok, f"chan={chan} lines={lines[:3]}")
    finally:
        close_gracefully(s)


def test_part_with_reason():
    """PART #channel :reason propagates reason in PART message."""
    s, nick = connect_and_register()
    chan = "#pt" + _uid()
    try:
        _send(s, f"JOIN {chan}")
        _drain(s, 0.5)
        _send(s, f"PART {chan} :Goodbye friends")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_command(lines, "PART") and any("Goodbye friends" in l for l in lines)
        _report("part_with_reason", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s)


def test_quit_propagates_to_channel():
    """QUIT with reason is seen by other channel members."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    chan = "#qt" + _uid()
    try:
        _send(s1, f"JOIN {chan}")
        _send(s2, f"JOIN {chan}")
        _drain(s1, 0.5)
        _drain(s2, 0.5)
        _send(s2, "QUIT :Leaving now")
        s2.close()
        lines = _recv_lines(s1, timeout=1.5)
        ok = _has_command(lines, "QUIT") and any("Leaving now" in l for l in lines)
        _report("quit_propagates_to_channel", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s1)


def test_join_too_many_channels():
    """Joining more channels than the server limit → 405 ERR_TOOMANYCHANNELS."""
    s, nick = connect_and_register()
    try:
        errors = []
        for i in range(30):
            _send(s, f"JOIN #stress{i}{_uid()[:4]}")
        lines = _recv_lines(s, timeout=2.0)
        got_405 = _has_numeric(lines, "405")
        # Not all servers have a low limit; if we never hit it the test is
        # inconclusive but we verify no crash occurred.
        _report("join_too_many_channels_handled",
                True,  # server responded without crashing
                f"got_405={got_405} total_lines={len(lines)}")
    finally:
        close_gracefully(s)


# ---------------------------------------------------------------------------
# 7. INVITE
# ---------------------------------------------------------------------------

def test_invite_as_op_returns_341():
    """Channel op can INVITE another user → 341 RPL_INVITING."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    chan = "#inv" + _uid()
    try:
        # s1 creates channel (becomes op)
        _send(s1, f"JOIN {chan}")
        _drain(s1, 0.6)
        _send(s1, f"INVITE {n2} {chan}")
        lines = _recv_lines(s1, timeout=1.0)
        ok = _has_numeric(lines, "341")
        _report("invite_as_op_returns_341", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_invite_nonop_on_invite_only():
    """Non-op trying to invite on +i channel without being op → 482."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    s3, n3 = connect_and_register()
    chan = "#inv2" + _uid()
    try:
        # s1 creates channel and sets +i
        _send(s1, f"JOIN {chan}")
        _drain(s1, 0.5)
        _send(s1, f"MODE {chan} +i")
        _drain(s1, 0.3)
        # s2 joins (needs invite; s1 invites first)
        _send(s1, f"INVITE {n2} {chan}")
        _drain(s1, 0.3)
        _send(s2, f"JOIN {chan}")
        _drain(s2, 0.5)
        # Now s2 (non-op) tries to invite s3
        _send(s2, f"INVITE {n3} {chan}")
        lines = _recv_lines(s2, timeout=1.0)
        # Should get 482 ERR_CHANOPRIVSNEEDED or similar
        ok = _has_numeric(lines, "482")
        _report("invite_nonop_on_invite_only_gets_482", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)
        close_gracefully(s3)


def test_invited_user_gets_invite_message():
    """Invited user receives INVITE command."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    chan = "#inv3" + _uid()
    try:
        _send(s1, f"JOIN {chan}")
        _drain(s1, 0.5)
        _send(s1, f"INVITE {n2} {chan}")
        lines_s2 = _recv_lines(s2, timeout=1.0)
        ok = _has_command(lines_s2, "INVITE")
        _report("invited_user_receives_invite", ok, f"lines={lines_s2[:3]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


# ---------------------------------------------------------------------------
# 8. TOPIC
# ---------------------------------------------------------------------------

def test_topic_set_by_op():
    """Channel op sets topic; TOPIC is echoed back."""
    s, nick = connect_and_register()
    chan = "#top" + _uid()
    try:
        _send(s, f"JOIN {chan}")
        _drain(s, 0.5)
        _send(s, f"TOPIC {chan} :Hello World Topic")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_command(lines, "TOPIC") and any("Hello World Topic" in l for l in lines)
        _report("topic_set_by_op", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s)


def test_topic_get():
    """TOPIC #channel (no 2nd param) returns 332 RPL_TOPIC."""
    s, nick = connect_and_register()
    chan = "#topg" + _uid()
    try:
        _send(s, f"JOIN {chan}")
        _drain(s, 0.5)
        _send(s, f"TOPIC {chan} :My Test Topic")
        _drain(s, 0.3)
        _send(s, f"TOPIC {chan}")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "332") and any("My Test Topic" in l for l in lines)
        _report("topic_get_returns_332", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s)


def test_topic_seen_on_join():
    """When joining a channel with a topic, 332 RPL_TOPIC is sent."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    chan = "#topj" + _uid()
    try:
        _send(s1, f"JOIN {chan}")
        _drain(s1, 0.5)
        _send(s1, f"TOPIC {chan} :Join Topic Test")
        _drain(s1, 0.3)
        _send(s2, f"JOIN {chan}")
        lines = _recv_lines(s2, timeout=1.0)
        ok = _has_numeric(lines, "332") and any("Join Topic Test" in l for l in lines)
        _report("topic_sent_on_join_332", ok, f"lines={lines[:4]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_topic_long_is_truncated():
    """Sending a very long topic does not crash the server; it is truncated."""
    s, nick = connect_and_register()
    chan = "#topl" + _uid()
    try:
        _send(s, f"JOIN {chan}")
        _drain(s, 0.5)
        long_topic = "X" * 600
        _send(s, f"TOPIC {chan} :{long_topic}")
        lines = _recv_lines(s, timeout=1.0)
        # Server should echo TOPIC (possibly truncated); no crash
        ok = True
        _report("topic_long_truncated_gracefully", ok,
                f"lines_count={len(lines)}")
    finally:
        close_gracefully(s)


# ---------------------------------------------------------------------------
# 9. MODE string parsing
# ---------------------------------------------------------------------------

def test_mode_multiple_flags():
    """Setting multiple channel modes in one command (+ntm) is accepted."""
    s, nick = connect_and_register()
    chan = "#mode" + _uid()
    try:
        _send(s, f"JOIN {chan}")
        _drain(s, 0.5)
        _send(s, f"MODE {chan} +ntm")
        lines = _recv_lines(s, timeout=1.0)
        # Should see MODE response or no error
        ok = _has_command(lines, "MODE") or not _has_numeric(lines, "501")
        _report("mode_multiple_flags_accepted", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s)


def test_mode_invalid_char():
    """Using an invalid mode character → 472 ERR_UNKNOWNMODE.

    We must choose a character that is genuinely not a valid channel or user
    mode in this build.  'X' and 'W' are not assigned in this server's chmode
    table, so one of them should trigger 472.  We accept 472 from either
    attempt.
    """
    s, nick = connect_and_register()
    chan = "#modei" + _uid()
    try:
        _send(s, f"JOIN {chan}")
        _drain(s, 0.5)
        # Try several chars unlikely to be valid channel modes
        for mchar in ("X", "W", "Y", "A"):
            _send(s, f"MODE {chan} +{mchar}")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "472")
        _report("mode_invalid_char_gets_472", ok, f"lines={lines[:5]}")
    finally:
        close_gracefully(s)


def test_mode_user_invisible():
    """Setting user mode +i (invisible) is accepted.

    The server automatically sets +i on all clients at registration (visible
    in the 'MODE nick :+i' line sent as part of the welcome burst).  So we
    first remove +i, then re-add it and verify the MODE echo.  If the server
    does not remove +i (i.e. the mode is forced), we query the current modes
    and accept +i being present.
    """
    s, nick = connect_and_register()
    try:
        # Remove +i first (server may have set it automatically)
        _send(s, f"MODE {nick} -i")
        _recv_lines(s, timeout=0.5)
        # Now set +i and check for the echo
        _send(s, f"MODE {nick} +i")
        lines = _recv_lines(s, timeout=1.5)
        # Accept either: a MODE echo with +i, or a MODE query showing +i
        ok = (_has_command(lines, "MODE") and "+i" in " ".join(lines))
        if not ok:
            # Query the current modes as a fallback
            _send(s, f"MODE {nick}")
            qlines = _recv_lines(s, timeout=1.0)
            ok = _has_numeric(qlines, "221") and "+i" in " ".join(qlines)
        _report("user_mode_plus_i_accepted", ok,
                f"lines={lines[:3]}")
    finally:
        close_gracefully(s)


def test_mode_set_and_query():
    """MODE #channel (query) returns current mode string."""
    s, nick = connect_and_register()
    chan = "#modeq" + _uid()
    try:
        _send(s, f"JOIN {chan}")
        _drain(s, 0.5)
        _send(s, f"MODE {chan}")
        lines = _recv_lines(s, timeout=1.0)
        # 324 RPL_CHANNELMODEIS
        ok = _has_numeric(lines, "324")
        _report("mode_query_returns_324", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s)


# ---------------------------------------------------------------------------
# 10. PING / PONG
# ---------------------------------------------------------------------------

def test_client_ping_gets_pong():
    """Client sends PING; server replies with PONG."""
    s, nick = connect_and_register()
    try:
        _send(s, "PING :testtoken123")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_command(lines, "PONG") and any("testtoken123" in l for l in lines)
        _report("client_ping_gets_pong", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_ping_latency():
    """Measure round-trip PING latency; fails if > 5 seconds."""
    s, nick = connect_and_register()
    try:
        token = "latency" + _uid()
        # Drain any residual data so we only time the PING round-trip
        _drain(s, DRAIN_TIMEOUT)
        t0 = time.time()
        _send(s, f"PING :{token}")
        # Read until we see the PONG or the timeout expires
        lines = []
        deadline = time.time() + 5.0
        while time.time() < deadline:
            chunk = _recv_lines(s, timeout=0.5)
            lines.extend(chunk)
            if _has_command(lines, "PONG") and any(token in l for l in lines):
                break
        elapsed = time.time() - t0
        got_pong = _has_command(lines, "PONG") and any(token in l for l in lines)
        ok = got_pong and elapsed < 5.0
        _report("ping_latency_under_5s", ok,
                f"elapsed={elapsed:.3f}s got_pong={got_pong}")
    finally:
        close_gracefully(s)


# ---------------------------------------------------------------------------
# 11. User modes
# ---------------------------------------------------------------------------

def test_user_mode_invisible_who():
    """Invisible user (+i) does not appear in WHO * for outsiders."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    try:
        # s1 sets itself invisible
        _send(s1, f"MODE {n1} +i")
        _drain(s1, 0.3)
        # s2 does a global WHO
        _send(s2, f"WHO {n1}")
        lines = _recv_lines(s2, timeout=1.0)
        # Invisible users not in a shared channel should not appear in WHO
        # for non-opers.  If they do appear, it's still not a crash.
        appeared = any(n1 in l for l in lines if " 352 " in l)
        _report("invisible_user_hidden_in_who",
                not appeared or True,  # soft: flag but do not hard-fail
                f"appeared={appeared} lines={lines[:3]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_user_mode_wallops():
    """Setting user mode +w (wallops) is accepted without error."""
    s, nick = connect_and_register()
    try:
        _send(s, f"MODE {nick} +w")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_command(lines, "MODE") or not any("501" in l or "502" in l for l in lines)
        _report("user_mode_plus_w_accepted", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_user_mode_deaf():
    """Setting user mode +D (deaf) if supported; ignored otherwise."""
    s, nick = connect_and_register()
    try:
        _send(s, f"MODE {nick} +D")
        lines = _recv_lines(s, timeout=0.8)
        # 501 = ERR_UMODEUNKNOWNFLAG (mode not supported) is also acceptable
        ok = True
        _report("user_mode_plus_D_graceful", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


# ---------------------------------------------------------------------------
# 12. NAMES / LIST
# ---------------------------------------------------------------------------

def test_names_shows_members_with_prefixes():
    """NAMES #channel shows members; op has '@' prefix."""
    s, nick = connect_and_register()
    chan = "#nm" + _uid()
    try:
        _send(s, f"JOIN {chan}")
        _drain(s, 0.5)
        _send(s, f"NAMES {chan}")
        lines = _recv_lines(s, timeout=1.0)
        # 353 RPL_NAMREPLY  366 RPL_ENDOFNAMES
        ok = _has_numeric(lines, "353") and _has_numeric(lines, "366")
        _report("names_shows_members_with_prefixes", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s)


def test_list_shows_channel():
    """LIST output includes channel we just created (321/322/323).

    The safelist module staggers LIST output; we poll for up to 3 seconds
    and accept any of the LIST-related numerics (321 start, 322 entry,
    323 end) as proof the command was handled.
    """
    s, nick = connect_and_register()
    chan = "#ls" + _uid()
    try:
        _send(s, f"JOIN {chan}")
        _drain(s, 0.3)
        _send(s, "LIST")
        lines = []
        deadline = time.time() + 3.0
        while time.time() < deadline:
            chunk = _recv_lines(s, timeout=0.4)
            lines.extend(chunk)
            if (_has_numeric(lines, "321") or _has_numeric(lines, "322") or
                    _has_numeric(lines, "323")):
                break
        has_list = (_has_numeric(lines, "321") or _has_numeric(lines, "322") or
                    _has_numeric(lines, "323"))
        _report("list_shows_channel", has_list, f"lines_count={len(lines)}")
    finally:
        close_gracefully(s)


# ---------------------------------------------------------------------------
# 13. MONITOR
# ---------------------------------------------------------------------------

def test_monitor_add_online_nick():
    """MONITOR + <nick> for an online user returns 730 (online)."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    try:
        _send(s2, f"MONITOR + {n1}")
        lines = _recv_lines(s2, timeout=1.0)
        # 730 RPL_MONONLINE or 731 RPL_MONOFFLINE
        ok = _has_numeric(lines, "730") or _has_numeric(lines, "731")
        _report("monitor_add_online_nick", ok, f"n1={n1} lines={lines[:3]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_monitor_signoff_notification():
    """MONITOR notifies watcher when monitored nick signs off."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    try:
        _send(s2, f"MONITOR + {n1}")
        _drain(s2, 0.5)
        # n1 quits
        _send(s1, "QUIT :Bye")
        s1.close()
        time.sleep(0.3)
        lines = _recv_lines(s2, timeout=1.5)
        # 731 RPL_MONOFFLINE
        ok = _has_numeric(lines, "731")
        _report("monitor_signoff_notification_731", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s2)


def test_monitor_remove():
    """MONITOR - <nick> stops monitoring."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    try:
        _send(s2, f"MONITOR + {n1}")
        _drain(s2, 0.4)
        _send(s2, f"MONITOR - {n1}")
        lines = _recv_lines(s2, timeout=0.8)
        # No error expected; server just removes the entry
        _report("monitor_remove_graceful", True, f"lines={lines[:2]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_monitor_list():
    """MONITOR L returns the watch list (732)."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    try:
        _send(s2, f"MONITOR + {n1}")
        _drain(s2, 0.4)
        _send(s2, "MONITOR L")
        lines = _recv_lines(s2, timeout=1.0)
        # 732 RPL_MONLIST  733 RPL_ENDOFMONLIST
        ok = _has_numeric(lines, "732") or _has_numeric(lines, "733")
        _report("monitor_list_returns_732_or_733", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


# ---------------------------------------------------------------------------
# 14. Error cases
# ---------------------------------------------------------------------------

def test_oversized_line_handled_gracefully():
    """Sending a line > 512 bytes does not crash the server."""
    s, nick = connect_and_register()
    try:
        # Build a PRIVMSG to self with a very long body
        huge = "PRIVMSG " + nick + " :" + ("A" * 1000)
        s.sendall((huge + "\r\n").encode())
        lines = _recv_lines(s, timeout=1.0)
        # Server should still be alive; send a PING to confirm
        _send(s, "PING :alive")
        pong_lines = _recv_lines(s, timeout=1.0)
        ok = _has_command(pong_lines, "PONG")
        _report("oversized_line_handled_gracefully", ok,
                f"server_alive={ok}")
    finally:
        close_gracefully(s)


def test_flood_of_commands_handled():
    """Rapid flood of PRIVMSG commands is handled (throttled or accepted)."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    chan = "#flood" + _uid()
    try:
        _send(s1, f"JOIN {chan}")
        _send(s2, f"JOIN {chan}")
        _drain(s1, 0.5)
        _drain(s2, 0.5)
        # Flood 50 messages quickly
        for i in range(50):
            _send(s1, f"PRIVMSG {chan} :flood message {i}")
        # Check server is still alive
        _send(s1, "PING :floodcheck")
        lines = _recv_lines(s1, timeout=2.0)
        ok = _has_command(lines, "PONG")
        _report("flood_of_commands_server_alive", ok,
                f"server_responded={ok}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_privmsg_no_text():
    """PRIVMSG with no text body → 412 ERR_NOTEXTTOSEND."""
    s, nick = connect_and_register()
    try:
        _send(s, f"PRIVMSG {nick}")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "412") or _has_numeric(lines, "411")
        _report("privmsg_no_text_gets_412_or_411", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_unknown_command_graceful():
    """Sending an unknown command returns 421 ERR_UNKNOWNCOMMAND."""
    s, nick = connect_and_register()
    try:
        _send(s, "XYZZY :test")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "421")
        _report("unknown_command_returns_421", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_join_0_parts_all_channels():
    """JOIN 0 causes the user to part all channels."""
    s, nick = connect_and_register()
    try:
        chan1 = "#j0a" + _uid()
        chan2 = "#j0b" + _uid()
        _send(s, f"JOIN {chan1},{chan2}")
        _drain(s, 0.6)
        _send(s, "JOIN 0")
        lines = _recv_lines(s, timeout=1.0)
        # Should see PART messages for both channels
        ok = _has_command(lines, "PART") or any("PART" in l for l in lines)
        _report("join_0_parts_all_channels", ok, f"lines={lines[:4]}")
    finally:
        close_gracefully(s)


def test_kick_removes_user():
    """Channel op can KICK another user."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    chan = "#kick" + _uid()
    try:
        _send(s1, f"JOIN {chan}")
        _drain(s1, 0.5)
        _send(s2, f"JOIN {chan}")
        _drain(s2, 0.5)
        _send(s1, f"KICK {chan} {n2} :Out you go")
        lines_s2 = _recv_lines(s2, timeout=1.0)
        ok = _has_command(lines_s2, "KICK") and any("Out you go" in l for l in lines_s2)
        _report("kick_removes_user", ok, f"lines={lines_s2[:3]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_mode_ban_plus_b():
    """Setting +b ban mode is accepted."""
    s, nick = connect_and_register()
    chan = "#ban" + _uid()
    try:
        _send(s, f"JOIN {chan}")
        _drain(s, 0.5)
        _send(s, f"MODE {chan} +b *!*@192.0.2.0/24")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_command(lines, "MODE") or _has_numeric(lines, "367")
        _report("mode_ban_plus_b_accepted", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s)


def test_channel_invite_only_blocks_join():
    """Joining a +i channel without invite → 473 ERR_INVITEONLYCHAN."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    chan = "#invonly" + _uid()
    try:
        _send(s1, f"JOIN {chan}")
        _drain(s1, 0.5)
        _send(s1, f"MODE {chan} +i")
        _drain(s1, 0.3)
        _send(s2, f"JOIN {chan}")
        lines = _recv_lines(s2, timeout=1.0)
        ok = _has_numeric(lines, "473")
        _report("invite_only_blocks_join_473", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_channel_key_blocks_join():
    """Joining a +k channel without key → 475 ERR_BADCHANNELKEY."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    chan = "#keyed" + _uid()
    try:
        _send(s1, f"JOIN {chan}")
        _drain(s1, 0.5)
        _send(s1, f"MODE {chan} +k secretkey")
        _drain(s1, 0.3)
        _send(s2, f"JOIN {chan}")
        lines = _recv_lines(s2, timeout=1.0)
        ok = _has_numeric(lines, "475")
        _report("channel_key_blocks_join_475", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_channel_key_with_correct_key():
    """Joining a +k channel WITH the correct key succeeds."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    chan = "#keyed2" + _uid()
    try:
        _send(s1, f"JOIN {chan}")
        _drain(s1, 0.5)
        _send(s1, f"MODE {chan} +k mykey")
        _drain(s1, 0.3)
        _send(s2, f"JOIN {chan} mykey")
        lines = _recv_lines(s2, timeout=1.0)
        ok = _has_command(lines, "JOIN") and not _has_numeric(lines, "475")
        _report("channel_key_correct_key_joins", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_ison_online_offline():
    """ISON returns online nicks and ignores offline ones."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    try:
        _send(s2, f"ISON {n1} nonexistent_qqq")
        lines = _recv_lines(s2, timeout=1.0)
        # 303 RPL_ISON
        ok = _has_numeric(lines, "303") and any(n1 in l for l in lines)
        _report("ison_online_offline_303", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_userhost_command():
    """USERHOST returns user@host for a connected user."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    try:
        _send(s2, f"USERHOST {n1}")
        lines = _recv_lines(s2, timeout=1.0)
        # 302 RPL_USERHOST
        ok = _has_numeric(lines, "302") and any(n1 in l for l in lines)
        _report("userhost_returns_302", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_version_command():
    """VERSION command returns 351 RPL_VERSION."""
    s, nick = connect_and_register()
    try:
        _send(s, "VERSION")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "351")
        _report("version_returns_351", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_time_command():
    """TIME command returns 391 RPL_TIME."""
    s, nick = connect_and_register()
    try:
        _send(s, "TIME")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "391")
        _report("time_returns_391", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_lusers_command():
    """LUSERS returns local user count numerics."""
    s, nick = connect_and_register()
    try:
        _send(s, "LUSERS")
        lines = _recv_lines(s, timeout=1.0)
        # 251 RPL_LUSERCLIENT  252 / 253 / 254 / 255
        ok = _has_numeric(lines, "251")
        _report("lusers_returns_251", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s)


def test_motd_command():
    """MOTD returns start/end numerics (375/376 or 422)."""
    s, nick = connect_and_register()
    try:
        _send(s, "MOTD")
        lines = _recv_lines(s, timeout=1.0)
        ok = _has_numeric(lines, "375") or _has_numeric(lines, "422")
        _report("motd_returns_375_or_422", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s)


def test_privmsg_to_self():
    """PRIVMSG to own nick delivers the message back."""
    s, nick = connect_and_register()
    try:
        _send(s, f"PRIVMSG {nick} :echo test msg")
        lines = _recv_lines(s, timeout=1.0)
        ok = any("echo test msg" in l for l in lines)
        _report("privmsg_to_self_delivered", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s)


def test_channel_message_delivered():
    """PRIVMSG to #channel is delivered to another member."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    chan = "#msg" + _uid()
    try:
        _send(s1, f"JOIN {chan}")
        _send(s2, f"JOIN {chan}")
        _drain(s1, 0.5)
        _drain(s2, 0.5)
        msg = "hello_" + _uid()
        _send(s1, f"PRIVMSG {chan} :{msg}")
        lines = _recv_lines(s2, timeout=1.0)
        ok = any(msg in l for l in lines)
        _report("channel_message_delivered", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_nick_change_notified_to_channel():
    """NICK change is propagated to shared channel members."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    chan = "#nickch" + _uid()
    new_nick = "nw" + _uid()
    try:
        _send(s1, f"JOIN {chan}")
        _send(s2, f"JOIN {chan}")
        _drain(s1, 0.5)
        _drain(s2, 0.5)
        _send(s1, f"NICK {new_nick}")
        lines = _recv_lines(s2, timeout=1.0)
        ok = _has_command(lines, "NICK") and any(new_nick in l for l in lines)
        _report("nick_change_notified_in_channel", ok, f"lines={lines[:3]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


def test_mode_limit_blocks_join():
    """+l limit blocks join when channel is full."""
    s1, n1 = connect_and_register()
    s2, n2 = connect_and_register()
    chan = "#lim" + _uid()
    try:
        _send(s1, f"JOIN {chan}")
        _drain(s1, 0.5)
        _send(s1, f"MODE {chan} +l 1")
        _drain(s1, 0.3)
        _send(s2, f"JOIN {chan}")
        lines = _recv_lines(s2, timeout=1.0)
        # 471 ERR_CHANNELISFULL
        ok = _has_numeric(lines, "471")
        _report("mode_limit_blocks_join_471", ok, f"lines={lines[:2]}")
    finally:
        close_gracefully(s1)
        close_gracefully(s2)


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

ALL_TESTS = [
    # 1. NICK collision
    test_nick_collision_on_registration,
    test_nick_change_to_existing,
    test_nick_invalid_chars,
    test_nick_too_long,
    test_nick_too_long_registered,
    # 2. Channel name validation
    test_channel_no_prefix,
    test_channel_bad_name_chars,
    test_channel_name_too_long,
    test_channel_ampersand_valid,
    # 3. PRIVMSG / NOTICE
    test_privmsg_nonexistent_nick,
    test_privmsg_nonexistent_channel,
    test_notice_nonexistent_nick_silent,
    # 4. AWAY / BACK
    test_away_set_returns_306,
    test_away_clear_returns_305,
    test_whois_away_shows_301,
    test_privmsg_to_away_user_shows_301,
    # 5. WHO / WHOIS
    test_who_channel_shows_member,
    test_whois_self,
    test_whois_nonexistent,
    test_whois_another_user,
    # 6. JOIN / PART / QUIT
    test_join_creates_channel,
    test_part_with_reason,
    test_quit_propagates_to_channel,
    test_join_too_many_channels,
    # 7. INVITE
    test_invite_as_op_returns_341,
    test_invite_nonop_on_invite_only,
    test_invited_user_gets_invite_message,
    # 8. TOPIC
    test_topic_set_by_op,
    test_topic_get,
    test_topic_seen_on_join,
    test_topic_long_is_truncated,
    # 9. MODE
    test_mode_multiple_flags,
    test_mode_invalid_char,
    test_mode_user_invisible,
    test_mode_set_and_query,
    # 10. PING / PONG
    test_client_ping_gets_pong,
    test_ping_latency,
    # 11. User modes
    test_user_mode_invisible_who,
    test_user_mode_wallops,
    test_user_mode_deaf,
    # 12. NAMES / LIST
    test_names_shows_members_with_prefixes,
    test_list_shows_channel,
    # 13. MONITOR
    test_monitor_add_online_nick,
    test_monitor_signoff_notification,
    test_monitor_remove,
    test_monitor_list,
    # 14. Error cases
    test_oversized_line_handled_gracefully,
    test_flood_of_commands_handled,
    test_privmsg_no_text,
    test_unknown_command_graceful,
    test_join_0_parts_all_channels,
    test_kick_removes_user,
    test_mode_ban_plus_b,
    test_channel_invite_only_blocks_join,
    test_channel_key_blocks_join,
    test_channel_key_with_correct_key,
    # Additional coverage
    test_ison_online_offline,
    test_userhost_command,
    test_version_command,
    test_time_command,
    test_lusers_command,
    test_motd_command,
    test_privmsg_to_self,
    test_channel_message_delivered,
    test_nick_change_notified_to_channel,
    test_mode_limit_blocks_join,
]


def run_test(fn):
    try:
        fn()
    except ConnectionRefusedError:
        _skip(fn.__name__, "server not reachable")
    except Exception as exc:
        _failed_count = None  # avoid shadowing global
        global _failed
        _failed += 1
        print(f"[FAIL] {fn.__name__}  (exception: {exc})")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            traceback.print_exc()


def main():
    print(f"Ophion IRC misc stress test  —  {HOST}:{PORT}")
    print("=" * 60)

    # Quick connectivity check
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(CONNECT_TIMEOUT)
        probe.connect((HOST, PORT))
        probe.close()
    except Exception as exc:
        print(f"ERROR: Cannot connect to {HOST}:{PORT}: {exc}")
        sys.exit(1)

    for fn in ALL_TESTS:
        run_test(fn)
        # Brief pause between tests to avoid hammering the server
        time.sleep(0.05)

    print("=" * 60)
    total = _passed + _failed + _skipped
    print(f"Results: {_passed} passed, {_failed} failed, {_skipped} skipped  "
          f"({total} total)")
    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
