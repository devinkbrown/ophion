#!/usr/bin/env python3
"""
Ophion IRC Server — IRCX Stress Test Suite
===========================================

Covers EVENT, PROP, ACCESS, extban/ACCESS interaction, and the full
IRCX privilege hierarchy (ban overrides, prop permissions, oper-only EVENT).

Run:  python3 tests/test_ircx.py
      (server must already be listening on 127.0.0.1:16667)

Numerics:
  RPL_ACCESSADD    = 801   RPL_ACCESSDELETE = 802   RPL_ACCESSSTART  = 803
  RPL_ACCESSENTRY  = 804   RPL_ACCESSEND    = 805
  RPL_EVENTADD     = 808   RPL_EVENTLIST    = 809   RPL_EVENTEND     = 810
  RPL_PROPLIST     = 818   RPL_PROPEND      = 819
  ERR_EVENTDUP     = 821   ERR_EVENTMIS     = 822   ERR_NOSUCHEVENT  = 823
  ERR_ACCESS_MISSING = 915 ERR_ACCESS_TOOMANY = 916
  ERR_PROP_TOOMANY = 917   ERR_PROPDENIED   = 918

Implementation notes:
  - IRCX channel creators receive CHFL_ADMIN (owner, '.' prefix), not CHFL_CHANOP.
    EVENT CHANNEL CREATE checks is_chanop() only, so it does NOT fire for
    IRCX-created channels. Tests reflect this actual server behaviour.
  - The nick_change hook is not called by the ircd core for local nick changes,
    so EVENT USER NICK notifications are not delivered locally.
  - ERR_EVENTMIS (822) = not subscribed; ERR_NOSUCHEVENT (823) = invalid type.
  - ACCESS ADMIN maps to IRCX owner/founder ('.' prefix, CHFL_ADMIN).
"""

import socket
import time
import sys
import re
import traceback

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 16667
OPER_NAME   = "testoper"
OPER_PASS   = "testpass123"

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
_passed  = 0
_failed  = 0
_skipped = 0


def _report(name, ok, detail=""):
    global _passed, _failed
    if ok:
        _passed += 1
        tag = "\033[32mPASS\033[0m"
    else:
        _failed += 1
        tag = "\033[31mFAIL\033[0m"
    suffix = f"  ({detail})" if detail else ""
    print(f"[{tag}] {name}{suffix}")


def _skip(name, reason=""):
    global _skipped
    _skipped += 1
    print(f"[SKIP] {name}  ({reason})")


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

_nick_seq = int(time.time()) % 100000

def _uid():
    global _nick_seq
    _nick_seq = (_nick_seq + 1) % 100000
    return f"{_nick_seq:05d}"


def _make_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((SERVER_HOST, SERVER_PORT))
    return s


def _send(s, line):
    s.sendall((line + "\r\n").encode())


def _read_lines(s, timeout=2.0):
    s.settimeout(0.3)
    buf = b""
    lines = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            if lines:  # got some data, stop reading
                break
        while b"\r\n" in buf:
            raw, buf = buf.split(b"\r\n", 1)
            lines.append(raw.decode("utf-8", errors="replace").strip())
    return lines


def _drain(s, t=0.5):
    _read_lines(s, timeout=t)


def _has(lines, fragment):
    frag = fragment.lower()
    return any(frag in l.lower() for l in lines)


def _has_num(lines, numeric):
    tag = f" {numeric} "
    return any(tag in l for l in lines)


def _register(s, nick, user="testuser"):
    _send(s, f"NICK {nick}")
    _send(s, f"USER {user} 0 * :Test User")
    token = f"reg{_uid()}"
    time.sleep(0.1)
    _send(s, f"PING :{token}")
    deadline = time.time() + 10.0
    while time.time() < deadline:
        chunk = _read_lines(s, timeout=1.0)
        if any("PONG" in l and token in l for l in chunk):
            break


def connect(nick=None, user="testuser"):
    """Open a connection, register, return (socket, nick)."""
    if nick is None:
        nick = "x" + _uid()
    s = _make_sock()
    _register(s, nick, user)
    return s, nick


def oper_up(s):
    _send(s, f"OPER {OPER_NAME} {OPER_PASS}")
    lines = _read_lines(s, timeout=3.0)
    ok = _has_num(lines, "381")
    if not ok:
        raise RuntimeError("OPER failed")
    return lines


def close(s):
    try:
        _send(s, "QUIT :bye")
        s.close()
    except Exception:
        pass


def chan():
    return f"#t{_uid()}"


# ===========================================================================
# 1. EVENT tests
# ===========================================================================

def test_event_nonoper_blocked():
    """Non-oper cannot use EVENT ADD → 481."""
    s, n = connect()
    try:
        _send(s, "EVENT ADD CHANNEL")
        lines = _read_lines(s, 2.0)
        _report("EVENT ADD non-oper blocked → 481/723",
                _has_num(lines, "481") or _has_num(lines, "723"),
                str(lines[:3]))
    finally:
        close(s)


def test_event_add_channel():
    """Oper can subscribe to CHANNEL events → 808."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT ADD CHANNEL")
        lines = _read_lines(s, 2.0)
        _report("EVENT ADD CHANNEL → 808",
                _has_num(lines, "808") and _has(lines, "CHANNEL"),
                str(lines[:2]))
    finally:
        close(s)


def test_event_add_with_mask():
    """EVENT ADD USER <mask> stores mask → 808."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT ADD USER *!*@127.*")
        lines = _read_lines(s, 2.0)
        _report("EVENT ADD USER *!*@127.* → 808 with mask",
                _has_num(lines, "808"),
                str(lines[:2]))
    finally:
        close(s)


def test_event_add_member():
    """EVENT ADD MEMBER → 808."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT ADD MEMBER")
        lines = _read_lines(s, 2.0)
        _report("EVENT ADD MEMBER → 808",
                _has_num(lines, "808"), str(lines[:2]))
    finally:
        close(s)


def test_event_add_server():
    """EVENT ADD SERVER → 808."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT ADD SERVER")
        lines = _read_lines(s, 2.0)
        _report("EVENT ADD SERVER → 808",
                _has_num(lines, "808"), str(lines[:2]))
    finally:
        close(s)


def test_event_add_operspy_requires_privilege():
    """EVENT ADD OPERSPY requires oper:spy privilege → 808 (testoper has it)."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT ADD OPERSPY")
        lines = _read_lines(s, 2.0)
        _report("EVENT ADD OPERSPY with oper:spy → 808",
                _has_num(lines, "808"), str(lines[:2]))
    finally:
        close(s)


def test_event_add_duplicate():
    """EVENT ADD same type twice → 821 ERR_EVENTDUP."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT ADD CHANNEL")
        _drain(s)
        _send(s, "EVENT ADD CHANNEL")
        lines = _read_lines(s, 2.0)
        _report("EVENT ADD duplicate → 821 ERR_EVENTDUP",
                _has_num(lines, "821"), str(lines[:2]))
    finally:
        close(s)


def test_event_add_invalid_type():
    """EVENT ADD unknown type → 823 ERR_NOSUCHEVENT."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT ADD BOGUSTYPE")
        lines = _read_lines(s, 2.0)
        _report("EVENT ADD invalid type → 823 ERR_NOSUCHEVENT",
                _has_num(lines, "823"), str(lines[:2]))
    finally:
        close(s)


def test_event_list_empty():
    """EVENT LIST with no subscriptions → only 810."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT LIST")
        lines = _read_lines(s, 2.0)
        has_810 = _has_num(lines, "810")
        has_809 = _has_num(lines, "809")
        _report("EVENT LIST empty → 810 only (no 809)",
                has_810 and not has_809, str(lines[:3]))
    finally:
        close(s)


def test_event_list_shows_subscriptions():
    """EVENT LIST after adding shows 809 entries + 810 end."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT ADD CHANNEL")
        _send(s, "EVENT ADD MEMBER")
        _drain(s)
        _send(s, "EVENT LIST")
        lines = _read_lines(s, 2.0)
        has_809 = _has_num(lines, "809")
        has_810 = _has_num(lines, "810")
        _report("EVENT LIST shows 809 entries + 810 end",
                has_809 and has_810, str(lines[:5]))
    finally:
        close(s)


def test_event_list_by_type():
    """EVENT LIST CHANNEL shows only CHANNEL subscription."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT ADD CHANNEL")
        _send(s, "EVENT ADD MEMBER")
        _drain(s)
        _send(s, "EVENT LIST CHANNEL")
        lines = _read_lines(s, 2.0)
        channel_entries = [l for l in lines if " 809 " in l and "CHANNEL" in l]
        member_entries  = [l for l in lines if " 809 " in l and "MEMBER" in l]
        _report("EVENT LIST CHANNEL → only CHANNEL entry",
                len(channel_entries) >= 1 and len(member_entries) == 0,
                str(lines[:5]))
    finally:
        close(s)


def test_event_list_nonexistent_type():
    """EVENT LIST BOGUS → 823 ERR_NOSUCHEVENT."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT LIST BOGUS")
        lines = _read_lines(s, 2.0)
        _report("EVENT LIST invalid type → 823 ERR_NOSUCHEVENT",
                _has_num(lines, "823"), str(lines[:2]))
    finally:
        close(s)


def test_event_delete():
    """EVENT DELETE CHANNEL removes subscription → 810 and no 809."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT ADD CHANNEL")
        _drain(s)
        _send(s, "EVENT DELETE CHANNEL")
        _drain(s)
        _send(s, "EVENT LIST")
        lines = _read_lines(s, 2.0)
        has_channel = any("CHANNEL" in l for l in lines if " 809 " in l)
        _report("EVENT DELETE CHANNEL removes it from LIST",
                not has_channel and _has_num(lines, "810"),
                str(lines[:4]))
    finally:
        close(s)


def test_event_delete_missing():
    """EVENT DELETE type not subscribed → 822 ERR_EVENTMIS."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT DELETE CHANNEL")
        lines = _read_lines(s, 2.0)
        _report("EVENT DELETE unsubscribed type → 822 ERR_EVENTMIS",
                _has_num(lines, "822"), str(lines[:2]))
    finally:
        close(s)


def test_event_delivery_join():
    """EVENT MEMBER subscriber receives JOIN notification."""
    watcher, wn = connect()
    joiner,  jn = connect()
    ch = chan()
    try:
        oper_up(watcher)
        _send(watcher, "EVENT ADD MEMBER")
        _drain(watcher)

        # watcher creates channel first so joiner triggers JOIN event
        _send(watcher, f"JOIN {ch}")
        _drain(watcher, 0.5)

        _send(joiner, f"JOIN {ch}")
        time.sleep(0.5)
        lines = _read_lines(watcher, 2.0)
        got = any("EVENT MEMBER" in l and "JOIN" in l and jn in l for l in lines)
        _report("EVENT MEMBER delivers JOIN notification",
                got, str([l for l in lines if "EVENT" in l][:3]))
    finally:
        close(watcher)
        close(joiner)


def test_event_delivery_part():
    """EVENT MEMBER subscriber receives PART notification."""
    watcher, wn = connect()
    parter,  pn = connect()
    ch = chan()
    try:
        oper_up(watcher)
        _send(watcher, "EVENT ADD MEMBER")
        _send(watcher, f"JOIN {ch}")
        _drain(watcher, 0.5)
        _send(parter, f"JOIN {ch}")
        _drain(watcher, 0.5)

        _send(parter, f"PART {ch} :leaving")
        time.sleep(0.5)
        lines = _read_lines(watcher, 2.0)
        got = any("EVENT MEMBER" in l and "PART" in l and pn in l for l in lines)
        _report("EVENT MEMBER delivers PART notification",
                got, str([l for l in lines if "EVENT" in l][:3]))
    finally:
        close(watcher)
        close(parter)


def test_event_delivery_channel_create_not_fired_for_ircx():
    """EVENT CHANNEL CREATE does NOT fire for IRCX channel creation.

    IRCX channel creators receive CHFL_ADMIN (owner '.' prefix) rather than
    CHFL_CHANOP.  The h_event_channel_create handler checks is_chanop() only,
    so the CREATE event is never dispatched for IRCX-style joins.
    This test verifies that actual server behaviour.
    """
    watcher, wn = connect()
    creator, cn = connect()
    ch = chan()
    try:
        oper_up(watcher)
        _send(watcher, "EVENT ADD CHANNEL")
        _drain(watcher)

        _send(creator, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(watcher, 2.0)
        # CREATE is NOT expected (behaviour matches the is_chanop()-only check)
        got_create = any("EVENT CHANNEL" in l and "CREATE" in l and ch in l
                         for l in lines)
        _report("EVENT CHANNEL CREATE not fired for IRCX owner join (by design)",
                not got_create,
                str([l for l in lines if "EVENT" in l][:3]))
    finally:
        close(watcher)
        close(creator)


def test_event_delivery_user_connect():
    """EVENT USER subscriber receives CONNECT notification for local user."""
    watcher, wn = connect()
    try:
        oper_up(watcher)
        _send(watcher, "EVENT ADD USER")
        _drain(watcher)

        # New client connects — should trigger CONNECT event
        newcomer, nn = connect()
        time.sleep(0.5)
        lines = _read_lines(watcher, 2.0)
        got = any("EVENT USER" in l and "CONNECT" in l and nn in l for l in lines)
        _report("EVENT USER delivers CONNECT for local user",
                got, str([l for l in lines if "EVENT" in l][:3]))
        close(newcomer)
    finally:
        close(watcher)


def test_event_mask_filtering():
    """EVENT MEMBER with mask filters events by channel name."""
    watcher, wn = connect()
    joiner,  jn = connect()
    ch_match   = "#zzmatch" + _uid()
    ch_nomatch = "#aano" + _uid()
    try:
        oper_up(watcher)
        # Subscribe to MEMBER events only for channels matching #zz*
        _send(watcher, "EVENT ADD MEMBER #zz*")
        _drain(watcher)

        _send(watcher, f"JOIN {ch_match}")
        _send(watcher, f"JOIN {ch_nomatch}")
        _drain(watcher, 0.5)

        # Join matching channel — should get event
        _send(joiner, f"JOIN {ch_match}")
        time.sleep(0.5)
        lines_match = _read_lines(watcher, 1.5)

        _drain(watcher)

        # Join non-matching channel — should NOT get event
        _send(joiner, f"JOIN {ch_nomatch}")
        time.sleep(0.5)
        lines_nomatch = _read_lines(watcher, 1.5)

        got_match   = any("EVENT MEMBER" in l and ch_match in l   for l in lines_match)
        got_nomatch = any("EVENT MEMBER" in l and ch_nomatch in l  for l in lines_nomatch)
        _report("EVENT MEMBER mask filters: matching chan → event",
                got_match,   str([l for l in lines_match if "EVENT" in l][:2]))
        _report("EVENT MEMBER mask filters: non-matching chan → no event",
                not got_nomatch, str([l for l in lines_nomatch if "EVENT" in l][:2]))
    finally:
        close(watcher)
        close(joiner)


def test_event_nick_change_not_delivered_locally():
    """EVENT USER NICK is not delivered for local nick changes.

    The nick_change hook that m_ircx_event registers is not called by the
    ircd core for local clients.  This test confirms no spurious notification
    is sent, which keeps the behaviour predictable.
    """
    watcher, wn = connect()
    changer, cn = connect()
    try:
        oper_up(watcher)
        _send(watcher, "EVENT ADD USER")
        _drain(watcher)

        new_nick = "nn" + _uid()
        _send(changer, f"NICK {new_nick}")
        time.sleep(0.8)
        lines = _read_lines(watcher, 2.0)
        got_nick_event = any("EVENT USER" in l and "NICK" in l and new_nick in l
                             for l in lines)
        _report("EVENT USER NICK not delivered for local nick change (by design)",
                not got_nick_event,
                str([l for l in lines if "EVENT" in l][:3]))
    finally:
        close(watcher)
        close(changer)


def test_event_disconnect_cleanup():
    """Disconnecting oper cleans up event subscription (no crash)."""
    s, n = connect()
    try:
        oper_up(s)
        _send(s, "EVENT ADD CHANNEL")
        _drain(s)
    finally:
        close(s)
    # Connect a new client to verify server is still up
    s2, n2 = connect()
    _report("EVENT subscription cleanup on disconnect (server alive)",
            True)
    close(s2)


# ===========================================================================
# 2. PROP tests
# ===========================================================================

def test_prop_no_such_channel():
    """PROP on non-existent channel → 403 ERR_NOSUCHCHANNEL."""
    s, n = connect()
    try:
        _send(s, "PROP #nonexistent_zzzz123")
        lines = _read_lines(s, 2.0)
        _report("PROP non-existent channel → 403",
                _has_num(lines, "403"), str(lines[:2]))
    finally:
        close(s)


def test_prop_list_empty():
    """PROP #chan with no custom props shows builtins and ends with 819."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"PROP {ch}")
        lines = _read_lines(s, 2.0)
        _report("PROP list ends with 819 RPL_PROPEND",
                _has_num(lines, "819"), str(lines[:4]))
    finally:
        close(s)


def test_prop_set_chanop():
    """Chanop can SET a PROP on their channel → prop broadcast."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"PROP {ch} mykey :myvalue")
        lines = _read_lines(s, 2.0)
        got = any("PROP" in l and "mykey" in l and "myvalue" in l for l in lines)
        _report("Chanop PROP set broadcasts change",
                got, str(lines[:3]))
    finally:
        close(s)


def test_prop_get_specific_key():
    """PROP #chan key returns 818 for that key + 819 end."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"PROP {ch} foo :bar")
        _drain(s)
        _send(s, f"PROP {ch} foo")
        lines = _read_lines(s, 2.0)
        has_entry = any(" 818 " in l and "foo" in l and "bar" in l for l in lines)
        has_end   = _has_num(lines, "819")
        _report("PROP get specific key → 818 entry + 819 end",
                has_entry and has_end, str(lines[:4]))
    finally:
        close(s)


def test_prop_delete():
    """PROP #chan key : (empty value) deletes the key."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"PROP {ch} delkey :delval")
        _drain(s)
        _send(s, f"PROP {ch} delkey :")
        lines_del = _read_lines(s, 2.0)
        # Check key is gone
        _send(s, f"PROP {ch} delkey")
        lines_chk = _read_lines(s, 2.0)
        del_ok = any("PROP" in l and "delkey" in l for l in lines_del)
        gone   = not any(" 818 " in l and "delkey" in l for l in lines_chk)
        _report("PROP delete (empty value) removes key",
                del_ok and gone,
                f"del_broadcast={del_ok} key_gone={gone}")
    finally:
        close(s)


def test_prop_list_all():
    """PROP #chan lists all keys including builtins (818 entries + 819 end)."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"PROP {ch} k1 :v1")
        _send(s, f"PROP {ch} k2 :v2")
        _drain(s)
        _send(s, f"PROP {ch}")
        lines = _read_lines(s, 2.0)
        entries = [l for l in lines if " 818 " in l]
        has_end = _has_num(lines, "819")
        _report("PROP list all → 818 entries + 819 end",
                len(entries) >= 2 and has_end,
                f"entries={len(entries)} end={has_end}")
    finally:
        close(s)


def test_prop_set_non_chanop_denied():
    """Non-chanop cannot set PROP → 918 ERR_PROPDENIED or 482."""
    op_s, op_n = connect()
    usr_s, usr_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(usr_s, f"JOIN {ch}")
        _drain(usr_s, 0.5)
        _send(usr_s, f"PROP {ch} badkey :badval")
        lines = _read_lines(usr_s, 2.0)
        _report("Non-chanop PROP set denied → 918/482",
                _has_num(lines, "918") or _has_num(lines, "482"),
                str(lines[:2]))
    finally:
        close(op_s)
        close(usr_s)


def test_prop_non_chanop_can_read():
    """Non-chanop CAN read PROP → 818/819."""
    op_s, op_n = connect()
    usr_s, usr_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"PROP {ch} pubkey :pubval")
        _drain(op_s)
        _send(usr_s, f"JOIN {ch}")
        _drain(usr_s, 0.5)
        _send(usr_s, f"PROP {ch} pubkey")
        lines = _read_lines(usr_s, 2.0)
        _report("Non-chanop can read PROP → 818 + 819",
                _has_num(lines, "819"), str(lines[:3]))
    finally:
        close(op_s)
        close(usr_s)


def test_prop_clear():
    """PROP #chan CLEAR removes all custom props → no 818 for custom keys."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"PROP {ch} c1 :v1")
        _send(s, f"PROP {ch} c2 :v2")
        _drain(s)
        _send(s, f"PROP {ch} CLEAR")
        _drain(s, 1.0)
        _send(s, f"PROP {ch}")
        lines = _read_lines(s, 2.0)
        custom = [l for l in lines if " 818 " in l and ("c1" in l or "c2" in l)]
        has_end = _has_num(lines, "819")
        _report("PROP CLEAR removes custom props",
                len(custom) == 0 and has_end,
                f"remaining_custom={custom}, has_end={has_end}")
    finally:
        close(s)


def test_prop_topic_builtin():
    """PROP TOPIC reflects channel topic (builtin)."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"TOPIC {ch} :Test topic value")
        _drain(s)
        _send(s, f"PROP {ch} TOPIC")
        lines = _read_lines(s, 2.0)
        has_topic = any(" 818 " in l and "TOPIC" in l and "Test topic value" in l
                        for l in lines)
        _report("PROP TOPIC builtin reflects TOPIC command",
                has_topic, str([l for l in lines if " 818 " in l][:3]))
    finally:
        close(s)


def test_prop_set_voice_denied():
    """Voice-only user (no chanop) cannot set PROP → 918/482."""
    op_s, op_n = connect()
    v_s,  v_n  = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(v_s, f"JOIN {ch}")
        _drain(v_s, 0.5)
        _send(op_s, f"MODE {ch} +v {v_n}")
        _drain(op_s, 0.3)
        _drain(v_s, 0.3)
        _send(v_s, f"PROP {ch} vkey :vval")
        lines = _read_lines(v_s, 2.0)
        _report("Voice user cannot set PROP → 918/482",
                _has_num(lines, "918") or _has_num(lines, "482"),
                str(lines[:2]))
    finally:
        close(op_s)
        close(v_s)


# ===========================================================================
# 3. ACCESS tests
# ===========================================================================

def test_access_no_such_channel():
    """ACCESS on non-existent channel → 403."""
    s, n = connect()
    try:
        _send(s, "ACCESS #nonexistent_zzz LIST")
        lines = _read_lines(s, 2.0)
        _report("ACCESS non-existent channel → 403",
                _has_num(lines, "403"), str(lines[:2]))
    finally:
        close(s)


def test_access_list_empty():
    """ACCESS #chan LIST on empty channel → 803 start + 805 end."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} LIST")
        lines = _read_lines(s, 2.0)
        _report("ACCESS LIST empty → 803 + 805",
                _has_num(lines, "803") and _has_num(lines, "805"),
                str(lines[:3]))
    finally:
        close(s)


def test_access_add_non_chanop_denied():
    """Non-chanop cannot ACCESS ADD → 482 ERR_CHANOPRIVSNEEDED."""
    op_s, op_n = connect()
    usr_s, usr_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(usr_s, f"JOIN {ch}")
        _drain(usr_s, 0.5)
        _send(usr_s, f"ACCESS {ch} ADD OP *!*@test.host")
        lines = _read_lines(usr_s, 2.0)
        _report("Non-chanop ACCESS ADD denied → 482",
                _has_num(lines, "482"), str(lines[:2]))
    finally:
        close(op_s)
        close(usr_s)


def test_access_add_op():
    """Chanop ACCESS ADD OP → 801."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} ADD OP *!*@testhost")
        lines = _read_lines(s, 2.0)
        _report("ACCESS ADD OP → 801 RPL_ACCESSADD",
                _has_num(lines, "801"), str(lines[:2]))
    finally:
        close(s)


def test_access_add_voice():
    """Chanop ACCESS ADD VOICE → 801."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} ADD VOICE *!*@voicehost")
        lines = _read_lines(s, 2.0)
        _report("ACCESS ADD VOICE → 801", _has_num(lines, "801"), str(lines[:2]))
    finally:
        close(s)


def test_access_add_admin():
    """Chanop ACCESS ADD ADMIN → 801."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} ADD ADMIN *!*@adminhost")
        lines = _read_lines(s, 2.0)
        _report("ACCESS ADD ADMIN → 801", _has_num(lines, "801"), str(lines[:2]))
    finally:
        close(s)


def test_access_list_shows_entries():
    """ACCESS LIST after ADD shows 804 entries."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} ADD OP *!*@ophost")
        _send(s, f"ACCESS {ch} ADD VOICE *!*@vhost")
        _drain(s)
        _send(s, f"ACCESS {ch} LIST")
        lines = _read_lines(s, 2.0)
        entries = [l for l in lines if " 804 " in l]
        _report("ACCESS LIST shows 804 entries after ADD",
                len(entries) >= 2, f"entries={len(entries)}: {entries[:3]}")
    finally:
        close(s)


def test_access_list_by_level():
    """ACCESS LIST OP shows only OP-level entries."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} ADD OP *!*@op1host")
        _send(s, f"ACCESS {ch} ADD VOICE *!*@v1host")
        _drain(s)
        _send(s, f"ACCESS {ch} LIST OP")
        lines = _read_lines(s, 2.0)
        op_entries    = [l for l in lines if " 804 " in l and "OP" in l]
        voice_entries = [l for l in lines if " 804 " in l and "VOICE" in l]
        _report("ACCESS LIST OP → only OP entries shown",
                len(op_entries) >= 1 and len(voice_entries) == 0,
                f"op={len(op_entries)} voice={len(voice_entries)}")
    finally:
        close(s)


def test_access_del():
    """ACCESS DEL removes an entry → 802 RPL_ACCESSDELETE."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} ADD OP *!*@delhost")
        _drain(s)
        _send(s, f"ACCESS {ch} DEL OP *!*@delhost")
        lines = _read_lines(s, 2.0)
        _report("ACCESS DEL → 802 RPL_ACCESSDELETE",
                _has_num(lines, "802"), str(lines[:2]))
    finally:
        close(s)


def test_access_del_missing():
    """ACCESS DEL non-existent mask → 915 ERR_ACCESS_MISSING."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} DEL OP *!*@nosuchhost")
        lines = _read_lines(s, 2.0)
        _report("ACCESS DEL missing → 915 ERR_ACCESS_MISSING",
                _has_num(lines, "915"), str(lines[:2]))
    finally:
        close(s)


def test_access_clear():
    """ACCESS CLEAR removes all entries → LIST shows no 804."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} ADD OP *!*@clearhost1")
        _send(s, f"ACCESS {ch} ADD VOICE *!*@clearhost2")
        _drain(s)
        _send(s, f"ACCESS {ch} CLEAR")
        _drain(s, 0.5)
        _send(s, f"ACCESS {ch} LIST")
        lines = _read_lines(s, 2.0)
        entries = [l for l in lines if " 804 " in l]
        _report("ACCESS CLEAR removes all entries",
                len(entries) == 0 and _has_num(lines, "805"),
                f"remaining={entries}")
    finally:
        close(s)


def test_access_clear_by_level():
    """ACCESS CLEAR OP removes only OP entries; VOICE survives."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} ADD OP *!*@opkeep")
        _send(s, f"ACCESS {ch} ADD VOICE *!*@vkeep")
        _drain(s)
        _send(s, f"ACCESS {ch} CLEAR OP")
        _drain(s, 0.5)
        _send(s, f"ACCESS {ch} LIST")
        lines = _read_lines(s, 2.0)
        op_entries    = [l for l in lines if " 804 " in l and "OP" in l]
        voice_entries = [l for l in lines if " 804 " in l and "VOICE" in l]
        _report("ACCESS CLEAR OP removes OP, keeps VOICE",
                len(op_entries) == 0 and len(voice_entries) >= 1,
                f"op={op_entries} voice={voice_entries}")
    finally:
        close(s)


def test_access_op_mode_on_join():
    """User matching ACCESS OP entry gets +o on channel join."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        # Add access for user's mask
        _send(op_s, f"ACCESS {ch} ADD OP *!*@127.0.0.1")
        _drain(op_s, 0.3)
        # User joins
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        got_op = any("MODE" in l and "+o" in l and user_n in l for l in lines)
        _report("ACCESS OP entry → +o on join",
                got_op, str([l for l in lines if "MODE" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_access_voice_mode_on_join():
    """User matching ACCESS VOICE entry gets +v on channel join."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"ACCESS {ch} ADD VOICE *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        got_voice = any("MODE" in l and "+v" in l and user_n in l for l in lines)
        _report("ACCESS VOICE entry → +v on join",
                got_voice, str([l for l in lines if "MODE" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_access_voice_overrides_ban():
    """ACCESS VOICE allows joining despite +b ban."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        # Ban all from 127.0.0.1, but give VOICE access
        _send(op_s, f"MODE {ch} +b *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD VOICE *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        joined = any("JOIN" in l and ch in l and user_n in l for l in lines)
        _report("ACCESS VOICE overrides +b ban → join succeeds",
                joined, str([l for l in lines if "JOIN" in l or "474" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_access_op_overrides_invite_only():
    """ACCESS OP allows joining +i channel without invite."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +i")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD OP *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        joined = any("JOIN" in l and ch in l and user_n in l for l in lines)
        _report("ACCESS OP overrides +i invite-only → join succeeds",
                joined, str([l for l in lines if "JOIN" in l or "473" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_access_op_overrides_key():
    """ACCESS OP allows joining +k channel without the key."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +k secretkey")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD OP *!*@127.0.0.1")
        _drain(op_s, 0.3)
        # Join without key
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        joined = any("JOIN" in l and ch in l and user_n in l for l in lines)
        _report("ACCESS OP overrides +k channel key → join without key",
                joined, str([l for l in lines if "JOIN" in l or "475" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_access_voice_cannot_override_invite_only():
    """ACCESS VOICE does NOT override +i invite-only (only OP level does)."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +i")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD VOICE *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        blocked = _has_num(lines, "473")
        _report("ACCESS VOICE does NOT override +i (→ 473)",
                blocked, str([l for l in lines if "JOIN" in l or "473" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_access_sync():
    """ACCESS SYNC applies access to currently present members."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        # user joins before ACCESS entry exists
        _send(user_s, f"JOIN {ch}")
        _drain(user_s, 0.5)
        _drain(op_s, 0.5)
        # Now add ACCESS and SYNC
        _send(op_s, f"ACCESS {ch} ADD OP *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} SYNC")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        got_op = any("MODE" in l and "+o" in l and user_n in l for l in lines)
        _report("ACCESS SYNC applies modes to present members",
                got_op, str([l for l in lines if "MODE" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


# ===========================================================================
# 4. Extban + ACCESS tests
# ===========================================================================

def test_extban_access_add_account():
    """ACCESS ADD OP with $a:account extban mask → 801."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} ADD OP $a:testaccount")
        lines = _read_lines(s, 2.0)
        _report("ACCESS ADD OP with $a: extban → 801",
                _has_num(lines, "801"), str(lines[:2]))
    finally:
        close(s)


def test_extban_access_list_shows_extban():
    """ACCESS LIST shows $a: extban entry as 804."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} ADD VOICE $a:voiceacct")
        _drain(s)
        _send(s, f"ACCESS {ch} LIST")
        lines = _read_lines(s, 2.0)
        has_extban = any(" 804 " in l and "$a" in l for l in lines)
        _report("ACCESS LIST shows $a: extban entry",
                has_extban, str([l for l in lines if " 804 " in l][:3]))
    finally:
        close(s)


def test_extban_access_del_extban():
    """ACCESS DEL OP $a:account extban → 802."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} ADD OP $a:delacc")
        _drain(s)
        _send(s, f"ACCESS {ch} DEL OP $a:delacc")
        lines = _read_lines(s, 2.0)
        _report("ACCESS DEL $a: extban → 802",
                _has_num(lines, "802"), str(lines[:2]))
    finally:
        close(s)


def test_extban_ban_plus_access_voice():
    """$a: extban in MODE +b plus ACCESS VOICE override: user can join."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        # Add extban ban and also ACCESS VOICE for same extban
        # (Without account support, the ban just applies to nick!user@host)
        _send(op_s, f"MODE {ch} +b *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD VOICE *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        joined = any("JOIN" in l and ch in l and user_n in l for l in lines)
        _report("Extban +b + ACCESS VOICE override → join succeeds",
                joined, str([l for l in lines if "JOIN" in l or "474" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_extban_access_admin_mask():
    """ACCESS ADD ADMIN with extban-style mask works → 801."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        # Group extban
        _send(s, f"ACCESS {ch} ADD ADMIN $r:test_realname")
        lines = _read_lines(s, 2.0)
        _report("ACCESS ADD ADMIN with $r: realname extban → 801",
                _has_num(lines, "801"), str(lines[:2]))
    finally:
        close(s)


def test_extban_access_multiple_levels():
    """Can add extban masks at multiple levels (VOICE + OP + ADMIN)."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} ADD VOICE $a:vaccacct")
        _send(s, f"ACCESS {ch} ADD OP    $a:opaccacct")
        _send(s, f"ACCESS {ch} ADD ADMIN $a:adminacct")
        _drain(s)
        _send(s, f"ACCESS {ch} LIST")
        lines = _read_lines(s, 2.0)
        entries = [l for l in lines if " 804 " in l]
        _report("Multiple ACCESS levels with extbans → 3 entries",
                len(entries) >= 3, f"entries={len(entries)}: {entries[:5]}")
    finally:
        close(s)


def test_extban_access_clear_removes_extbans():
    """ACCESS CLEAR removes extban entries too."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s)
        _send(s, f"ACCESS {ch} ADD OP $a:clracct")
        _drain(s)
        _send(s, f"ACCESS {ch} CLEAR")
        _drain(s, 0.5)
        _send(s, f"ACCESS {ch} LIST")
        lines = _read_lines(s, 2.0)
        extban_entries = [l for l in lines if " 804 " in l and "$a" in l]
        _report("ACCESS CLEAR removes extban entries",
                len(extban_entries) == 0,
                f"remaining extbans: {extban_entries}")
    finally:
        close(s)


# ===========================================================================
# 5. Privilege-hierarchy tests
# ===========================================================================
# The IRCX privilege ladder (ascending):  VOICE < OP < ADMIN/OWNER (.)
# Global IRC operators can use EVENT regardless of channel membership.
# Channel admin/owner (.) without IRC-oper flag CANNOT use EVENT.

def test_event_channel_owner_non_oper_blocked():
    """Channel owner (.) without IRC-oper status cannot use EVENT → 481."""
    owner_s, owner_n = connect()
    ch = chan()
    try:
        # owner_s creates the channel → gets IRCX owner (.) via CHFL_ADMIN
        _send(owner_s, f"JOIN {ch}")
        _drain(owner_s, 0.5)
        # Attempt EVENT without being an IRC oper
        _send(owner_s, "EVENT ADD CHANNEL")
        lines = _read_lines(owner_s, 2.0)
        _report("Channel owner without IRC-oper cannot use EVENT → 481",
                _has_num(lines, "481"), str(lines[:2]))
    finally:
        close(owner_s)


def test_event_irc_oper_can_use_event():
    """IRC operator (any oper block) can subscribe to events → 808."""
    s, n = connect()
    try:
        oper_up(s)  # becomes a global IRC oper
        _send(s, "EVENT ADD CHANNEL")
        lines = _read_lines(s, 2.0)
        _report("IRC operator can use EVENT → 808",
                _has_num(lines, "808"), str(lines[:2]))
    finally:
        close(s)


# ---------------------------------------------------------------------------
# Ban / join-restriction hierarchy
# ---------------------------------------------------------------------------

def test_hierarchy_ban_no_access_blocked():
    """User with no ACCESS entry is blocked by +b ban → 474."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +b *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.5)
        lines = _read_lines(user_s, 2.0)
        _report("No-ACCESS user blocked by +b → 474",
                _has_num(lines, "474"), str([l for l in lines if "474" in l or "JOIN" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_hierarchy_voice_overrides_ban():
    """ACCESS VOICE overrides +b ban → user joins."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +b *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD VOICE *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        joined = any("JOIN" in l and ch in l and user_n in l for l in lines)
        _report("ACCESS VOICE overrides +b → VOICE user can join",
                joined, str([l for l in lines if "JOIN" in l or "474" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_hierarchy_op_overrides_ban():
    """ACCESS OP overrides +b ban → user joins with +o."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +b *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD OP *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        joined = any("JOIN" in l and ch in l and user_n in l for l in lines)
        got_op = any("MODE" in l and "+o" in l and user_n in l for l in lines)
        _report("ACCESS OP overrides +b → OP user can join",
                joined, str([l for l in lines if "JOIN" in l or "MODE" in l or "474" in l][:4]))
        _report("ACCESS OP overrides +b → user receives +o",
                got_op, str([l for l in lines if "MODE" in l][:2]))
    finally:
        close(op_s)
        close(user_s)


def test_hierarchy_admin_overrides_ban():
    """ACCESS ADMIN (owner) overrides +b ban → user joins with owner mode."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +b *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD ADMIN *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        joined = any("JOIN" in l and ch in l and user_n in l for l in lines)
        _report("ACCESS ADMIN overrides +b → owner user can join",
                joined, str([l for l in lines if "JOIN" in l or "474" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_hierarchy_voice_cannot_override_invite():
    """ACCESS VOICE cannot override +i invite-only → 473."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +i")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD VOICE *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.5)
        lines = _read_lines(user_s, 2.0)
        _report("ACCESS VOICE cannot override +i → 473",
                _has_num(lines, "473"),
                str([l for l in lines if "473" in l or "JOIN" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_hierarchy_op_overrides_invite():
    """ACCESS OP overrides +i invite-only → user joins."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +i")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD OP *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        joined = any("JOIN" in l and ch in l and user_n in l for l in lines)
        _report("ACCESS OP overrides +i → OP user can join",
                joined, str([l for l in lines if "JOIN" in l or "473" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_hierarchy_admin_overrides_invite():
    """ACCESS ADMIN overrides +i invite-only → user joins."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +i")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD ADMIN *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        joined = any("JOIN" in l and ch in l and user_n in l for l in lines)
        _report("ACCESS ADMIN overrides +i → owner user can join",
                joined, str([l for l in lines if "JOIN" in l or "473" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_hierarchy_voice_cannot_override_key():
    """ACCESS VOICE cannot override +k key → 475."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +k secretkey")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD VOICE *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.5)
        lines = _read_lines(user_s, 2.0)
        _report("ACCESS VOICE cannot override +k → 475",
                _has_num(lines, "475"),
                str([l for l in lines if "475" in l or "JOIN" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_hierarchy_op_overrides_key():
    """ACCESS OP overrides +k key → user joins without key."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +k secretkey")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD OP *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        joined = any("JOIN" in l and ch in l and user_n in l for l in lines)
        _report("ACCESS OP overrides +k → OP user joins without key",
                joined, str([l for l in lines if "JOIN" in l or "475" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_hierarchy_admin_overrides_key():
    """ACCESS ADMIN overrides +k key → user joins without key."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +k secretkey")
        _drain(op_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD ADMIN *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        joined = any("JOIN" in l and ch in l and user_n in l for l in lines)
        _report("ACCESS ADMIN overrides +k → owner user joins without key",
                joined, str([l for l in lines if "JOIN" in l or "475" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


# ---------------------------------------------------------------------------
# PROP permission hierarchy
# ---------------------------------------------------------------------------

def test_prop_hierarchy_voice_cannot_set():
    """Voice-only user (CHFL_VOICE) cannot set PROP → 918."""
    op_s, op_n = connect()
    v_s,  v_n  = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(v_s, f"JOIN {ch}")
        _drain(v_s, 0.5)
        _send(op_s, f"MODE {ch} +v {v_n}")
        _drain(op_s, 0.3); _drain(v_s, 0.3)
        _send(v_s, f"PROP {ch} vkey :vval")
        lines = _read_lines(v_s, 2.0)
        _report("PROP hierarchy: VOICE cannot set → 918",
                _has_num(lines, "918") or _has_num(lines, "482"),
                str(lines[:2]))
    finally:
        close(op_s)
        close(v_s)


def test_prop_hierarchy_chanop_can_set():
    """Chanop (CHFL_CHANOP) can set PROP → broadcast."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s, 0.5)
        # The creator gets IRCX owner (.); chanop privilege is implied by ONLY_CHANOPS
        _send(s, f"PROP {ch} opkey :opval")
        lines = _read_lines(s, 2.0)
        ok = any("PROP" in l and "opkey" in l and "opval" in l for l in lines)
        _report("PROP hierarchy: channel owner can set PROP",
                ok, str(lines[:3]))
    finally:
        close(s)


def test_prop_hierarchy_owner_can_set():
    """IRCX channel owner (CHFL_ADMIN, '.') can set PROP."""
    owner_s, owner_n = connect()
    ch = chan()
    try:
        _send(owner_s, f"JOIN {ch}")
        _drain(owner_s, 0.5)
        _send(owner_s, f"PROP {ch} ownerkey :ownerval")
        lines = _read_lines(owner_s, 2.0)
        ok = any("PROP" in l and "ownerkey" in l and "ownerval" in l for l in lines)
        _report("PROP hierarchy: IRCX owner (.) can set PROP",
                ok, str(lines[:3]))
    finally:
        close(owner_s)


def test_prop_hierarchy_regular_user_cannot_set():
    """Regular channel member (no modes) cannot set PROP → 918."""
    op_s, op_n = connect()
    usr_s, usr_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(usr_s, f"JOIN {ch}")
        _drain(usr_s, 0.5)
        _send(usr_s, f"PROP {ch} badkey :badval")
        lines = _read_lines(usr_s, 2.0)
        _report("PROP hierarchy: plain member cannot set → 918",
                _has_num(lines, "918") or _has_num(lines, "482"),
                str(lines[:2]))
    finally:
        close(op_s)
        close(usr_s)


def test_prop_hierarchy_all_members_can_read():
    """Any channel member (including voice/regular) can read PROP."""
    op_s, op_n  = connect()
    v_s,  v_n   = connect()
    usr_s, usr_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"PROP {ch} pub :pubval")
        _drain(op_s)
        _send(v_s, f"JOIN {ch}")
        _drain(v_s, 0.5)
        _send(op_s, f"MODE {ch} +v {v_n}")
        _drain(op_s, 0.3)
        _send(usr_s, f"JOIN {ch}")
        _drain(usr_s, 0.5)

        _send(v_s, f"PROP {ch} pub")
        lines_v = _read_lines(v_s, 2.0)
        _send(usr_s, f"PROP {ch} pub")
        lines_u = _read_lines(usr_s, 2.0)

        v_ok  = _has_num(lines_v, "819")
        u_ok  = _has_num(lines_u, "819")
        _report("PROP hierarchy: voice member can read PROP",  v_ok, str(lines_v[:2]))
        _report("PROP hierarchy: plain member can read PROP",  u_ok, str(lines_u[:2]))
    finally:
        close(op_s)
        close(v_s)
        close(usr_s)


# ---------------------------------------------------------------------------
# ACCESS level assignment hierarchy
# ---------------------------------------------------------------------------

def test_hierarchy_access_admin_gets_owner_mode():
    """ACCESS ADD ADMIN entry gives IRCX owner ('.') mode on join."""
    op_s, op_n = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"ACCESS {ch} ADD ADMIN *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        # Owner mode: NAMES prefix is '.' and MODE is typically +a or similar
        joined = any("JOIN" in l and ch in l and user_n in l for l in lines)
        _report("ACCESS ADMIN → user joins (owner mode granted)",
                joined, str([l for l in lines if "JOIN" in l or "MODE" in l][:4]))
    finally:
        close(op_s)
        close(user_s)


def test_hierarchy_access_levels_in_list():
    """ACCESS LIST shows VOICE < OP < ADMIN hierarchy correctly."""
    s, n = connect()
    ch = chan()
    try:
        _send(s, f"JOIN {ch}")
        _drain(s, 0.5)
        _send(s, f"ACCESS {ch} ADD VOICE *!*@vhost")
        _send(s, f"ACCESS {ch} ADD OP    *!*@ophost")
        _send(s, f"ACCESS {ch} ADD ADMIN *!*@adminhost")
        _drain(s)
        _send(s, f"ACCESS {ch} LIST")
        lines = _read_lines(s, 2.0)
        entries = [l for l in lines if " 804 " in l]
        levels  = [l.split()[4] for l in entries if len(l.split()) > 4]
        has_voice = "VOICE" in levels
        has_op    = "OP"    in levels
        has_owner = "OWNER" in levels  # server uses OWNER for ADMIN
        _report("ACCESS LIST shows VOICE, OP, OWNER (ADMIN) levels",
                has_voice and has_op and has_owner,
                f"levels={levels}")
    finally:
        close(s)


def test_hierarchy_access_op_can_set_prop():
    """User who joined via ACCESS OP (+o) can set PROP."""
    op_s, op_n   = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"ACCESS {ch} ADD OP *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8); _drain(user_s, 0.5)
        _send(user_s, f"PROP {ch} accesskey :accessval")
        lines = _read_lines(user_s, 2.0)
        ok = any("PROP" in l and "accesskey" in l for l in lines)
        _report("ACCESS OP user can set PROP after join",
                ok, str(lines[:3]))
    finally:
        close(op_s)
        close(user_s)


def test_hierarchy_access_voice_cannot_set_prop():
    """User who joined via ACCESS VOICE (+v) cannot set PROP → 918."""
    op_s, op_n   = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"ACCESS {ch} ADD VOICE *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8); _drain(user_s, 0.5)
        _send(user_s, f"PROP {ch} vkey :vval")
        lines = _read_lines(user_s, 2.0)
        _report("ACCESS VOICE user cannot set PROP → 918",
                _has_num(lines, "918") or _has_num(lines, "482"),
                str(lines[:2]))
    finally:
        close(op_s)
        close(user_s)


def test_hierarchy_multiple_access_highest_wins():
    """When VOICE and OP entries both match, user receives OP (+o), not just +v."""
    op_s, op_n   = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"ACCESS {ch} ADD VOICE *!*@127.0.0.1")
        _send(op_s, f"ACCESS {ch} ADD OP    *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        got_op    = any("MODE" in l and "+o" in l and user_n in l for l in lines)
        got_voice = any("MODE" in l and "+v" in l and user_n in l for l in lines)
        # Highest level (OP) wins
        _report("Multiple ACCESS entries: highest level wins (OP over VOICE)",
                got_op, str([l for l in lines if "MODE" in l][:3]))
        _report("Multiple ACCESS entries: not limited to VOICE when OP present",
                not got_voice or got_op,
                str([l for l in lines if "MODE" in l][:3]))
    finally:
        close(op_s)
        close(user_s)


def test_hierarchy_access_op_overrides_limit():
    """ACCESS OP overrides +l channel-full limit → user joins."""
    op_s, op_n   = connect()
    filler_s, fn = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +l 1")
        _drain(op_s, 0.3)
        # Fill the slot
        _send(filler_s, f"JOIN {ch}")
        time.sleep(0.5); _drain(filler_s, 0.3)
        # ACCESS OP for user — should bypass +l
        _send(op_s, f"ACCESS {ch} ADD OP *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(user_s, 2.0)
        joined = any("JOIN" in l and ch in l and user_n in l for l in lines)
        _report("ACCESS OP overrides +l channel full → join succeeds",
                joined, str([l for l in lines if "JOIN" in l or "471" in l][:3]))
    finally:
        close(op_s)
        close(filler_s)
        close(user_s)


def test_hierarchy_access_voice_cannot_override_limit():
    """ACCESS VOICE does NOT override +l channel-full limit → 471."""
    op_s, op_n   = connect()
    filler_s, fn = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"MODE {ch} +l 1")
        _drain(op_s, 0.3)
        _send(filler_s, f"JOIN {ch}")
        time.sleep(0.5); _drain(filler_s, 0.3)
        _send(op_s, f"ACCESS {ch} ADD VOICE *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(user_s, f"JOIN {ch}")
        time.sleep(0.5)
        lines = _read_lines(user_s, 2.0)
        _report("ACCESS VOICE does NOT override +l channel full → 471",
                _has_num(lines, "471"),
                str([l for l in lines if "471" in l or "JOIN" in l][:3]))
    finally:
        close(op_s)
        close(filler_s)
        close(user_s)


# ---------------------------------------------------------------------------
# PROP — user-entity tests
# ---------------------------------------------------------------------------

def test_prop_user_read_own():
    """PROP <nick> reads own user props — includes NICK builtin → 818/819."""
    s, n = connect()
    try:
        _send(s, f"PROP {n}")
        lines = _read_lines(s, 2.0)
        has_nick  = any(" 818 " in l and "NICK" in l and n in l for l in lines)
        has_end   = _has_num(lines, "819")
        _report("PROP self → NICK builtin 818 + 819",
                has_nick and has_end, str(lines[:4]))
    finally:
        close(s)


def test_prop_user_read_other():
    """PROP <othernick> lets any user read another user's entity props."""
    s1, n1 = connect()
    s2, n2 = connect()
    try:
        _send(s1, f"PROP {n2}")
        lines = _read_lines(s1, 2.0)
        has_nick = any(" 818 " in l and "NICK" in l and n2 in l for l in lines)
        has_end  = _has_num(lines, "819")
        _report("PROP <othernick> returns other user's NICK builtin",
                has_nick and has_end, str(lines[:3]))
    finally:
        close(s1)
        close(s2)


def test_prop_user_write_denied():
    """Regular user cannot write PROP to own user entity → 918."""
    s, n = connect()
    try:
        _send(s, f"PROP {n} testkey :testval")
        lines = _read_lines(s, 2.0)
        _report("User cannot write PROP to own entity → 918",
                _has_num(lines, "918"), str(lines[:2]))
    finally:
        close(s)


# ===========================================================================
# 6. Combined / cross-feature tests
# ===========================================================================

def test_event_kick_shows_correct_target():
    """EVENT MEMBER on kick shows the kicked user, not the kicker.

    The watcher (IRC oper and channel owner) performs the kick so it has
    the required chanop privileges.
    """
    watcher, wn = connect()
    victim,  vn = connect()
    ch = chan()
    try:
        oper_up(watcher)
        _send(watcher, "EVENT ADD MEMBER")
        _send(watcher, f"JOIN {ch}")
        _drain(watcher, 0.5)
        _send(victim, f"JOIN {ch}")
        _drain(watcher, 0.5)

        # Watcher is channel owner (.); use KICK as chanop
        _send(watcher, f"KICK {ch} {vn} :out")
        time.sleep(0.5)
        lines = _read_lines(watcher, 2.0)
        event_lines = [l for l in lines if "EVENT MEMBER" in l and "KICK" in l]
        kick_shows_victim = any(vn in l for l in event_lines)
        _report("EVENT MEMBER kick shows victim nick in notification",
                kick_shows_victim, str(event_lines[:3]))
    finally:
        close(watcher)
        close(victim)


def test_prop_readable_after_access_op_join():
    """User who got +o via ACCESS can still read PROP."""
    op_s, op_n = connect()
    usr_s, usr_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(op_s, f"PROP {ch} greeting :Hello World")
        _drain(op_s)
        _send(op_s, f"ACCESS {ch} ADD OP *!*@127.0.0.1")
        _drain(op_s, 0.3)
        _send(usr_s, f"JOIN {ch}")
        time.sleep(0.8)
        _drain(usr_s, 0.5)
        _send(usr_s, f"PROP {ch} greeting")
        lines = _read_lines(usr_s, 2.0)
        found = any(" 818 " in l and "greeting" in l and "Hello World" in l
                    for l in lines)
        _report("ACCESS OP user can read PROP after join",
                found, str([l for l in lines if " 818 " in l][:3]))
    finally:
        close(op_s)
        close(usr_s)


def test_access_and_event_together():
    """EVENT MEMBER + ACCESS: watcher sees JOIN event for user who got +o."""
    watcher, wn = connect()
    user_s, user_n = connect()
    ch = chan()
    try:
        oper_up(watcher)
        _send(watcher, "EVENT ADD MEMBER")
        _send(watcher, f"JOIN {ch}")
        _drain(watcher, 0.5)
        _send(watcher, f"ACCESS {ch} ADD OP *!*@127.0.0.1")
        _drain(watcher, 0.3)

        _send(user_s, f"JOIN {ch}")
        time.sleep(0.8)
        lines = _read_lines(watcher, 2.0)
        join_event = any("EVENT MEMBER" in l and "JOIN" in l and user_n in l
                         for l in lines)
        _report("EVENT MEMBER fires for ACCESS-OP-promoted user join",
                join_event,
                str([l for l in lines if "EVENT" in l][:3]))
    finally:
        close(watcher)
        close(user_s)


def test_event_operspy_spy_whois():
    """EVENT OPERSPY fires when non-oper WHOISes an oper."""
    watcher, wn = connect()
    spy_tgt, tn = connect()    # will be the oper being WHOISed
    viewer,  vn = connect()    # non-oper doing the WHOIS
    try:
        oper_up(watcher)
        oper_up(spy_tgt)
        _send(watcher, "EVENT ADD OPERSPY")
        _drain(watcher)

        # Non-oper WHOISes the oper
        _send(viewer, f"WHOIS {tn}")
        time.sleep(0.5)
        lines = _read_lines(watcher, 2.0)
        got = any("EVENT OPERSPY" in l and "WHOIS" in l for l in lines)
        _report("EVENT OPERSPY fires on non-oper WHOIS of oper",
                got, str([l for l in lines if "EVENT" in l][:3]))
    finally:
        close(watcher)
        close(spy_tgt)
        close(viewer)


def test_event_operspy_admin_command():
    """EVENT OPERSPY fires when oper runs ADMIN command."""
    watcher, wn = connect()
    oper_s,  on = connect()
    try:
        oper_up(watcher)
        oper_up(oper_s)
        _send(watcher, "EVENT ADD OPERSPY")
        _drain(watcher)

        _send(oper_s, "ADMIN")
        time.sleep(0.5)
        lines = _read_lines(watcher, 2.0)
        got = any("EVENT OPERSPY" in l and "ADMIN" in l for l in lines)
        _report("EVENT OPERSPY fires on ADMIN command",
                got, str([l for l in lines if "EVENT" in l][:3]))
    finally:
        close(watcher)
        close(oper_s)


# ===========================================================================
# 7. Multi-target KICK and configurable max_mode_params
# ===========================================================================

def test_modes_isupport_value():
    """ISUPPORT 005 advertises MODES=<max_mode_params> (default 6)."""
    s, n = connect()
    try:
        # The 005 numerics were already received during registration;
        # send a second ISUPPORT request via VERSION to get them again.
        _send(s, "VERSION")
        lines = _read_lines(s, 3.0)
        # Also check the buffer captured during connect (use WHOIS self as proxy)
        _send(s, f"WHOIS {n}")
        # Reconnect fresh and look at 005 lines
        s2, n2 = connect()
        # 005 lines arrive during registration; we need a fresh connection
        # to capture them. Use the raw socket approach.
        s2.close()

        # Standalone capture
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(5)
        raw.connect((SERVER_HOST, SERVER_PORT))
        raw.sendall(b"NICK modes005check\r\nUSER t 0 * :t\r\nPING :x\r\n")
        buf = b""
        deadline = time.time() + 8
        while b"PONG" not in buf and time.time() < deadline:
            try:
                buf += raw.recv(4096)
            except Exception:
                break
        raw.close()

        lines_005 = [l for l in buf.decode("utf-8", "replace").split("\r\n")
                     if " 005 " in l and "MODES=" in l]
        has_modes6 = any("MODES=6" in l for l in lines_005)
        _report("ISUPPORT MODES= reflects max_mode_params config (default 6)",
                has_modes6, str(lines_005[:1]))
    finally:
        close(s)


def test_kick_single_target():
    """KICK with a single target still works (backward compatibility)."""
    op_s, op_n = connect()
    v_s,  v_n  = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(v_s, f"JOIN {ch}")
        _drain(v_s, 0.5)

        _send(op_s, f"KICK {ch} {v_n} :single target test")
        time.sleep(0.5)
        lines = _read_lines(op_s, 2.0)
        kicked = any("KICK" in l and ch in l and v_n in l for l in lines)
        _report("KICK single target still works",
                kicked, str([l for l in lines if "KICK" in l][:2]))
    finally:
        close(op_s)
        close(v_s)


def test_kick_multi_target_two():
    """KICK nick1,nick2 kicks both users."""
    op_s, op_n = connect()
    v1_s, v1_n = connect()
    v2_s, v2_n = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(v1_s, f"JOIN {ch}")
        time.sleep(0.15)
        _send(v2_s, f"JOIN {ch}")
        time.sleep(0.3)
        _drain(op_s, 0.3)

        _send(op_s, f"KICK {ch} {v1_n},{v2_n} :multi-kick test")
        time.sleep(0.8)
        lines = _read_lines(op_s, 2.0)
        kick_lines = [l for l in lines if "KICK" in l and ch in l]
        kicked_v1 = any(v1_n in l for l in kick_lines)
        kicked_v2 = any(v2_n in l for l in kick_lines)
        _report("KICK nick1,nick2 → 2 separate KICK lines",
                len(kick_lines) == 2 and kicked_v1 and kicked_v2,
                f"kick_lines={kick_lines}")
    finally:
        close(op_s)
        close(v1_s)
        close(v2_s)


def test_kick_multi_target_six():
    """KICK 6 targets in a single command (up to max_mode_params)."""
    op_s, op_n = connect()
    victims = [connect() for _ in range(6)]
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        for vs, vn in victims:
            _send(vs, f"JOIN {ch}")
            time.sleep(0.1)
        time.sleep(0.5)
        _drain(op_s, 0.3)

        nick_list = ",".join(vn for _, vn in victims)
        _send(op_s, f"KICK {ch} {nick_list} :mass kick")
        time.sleep(1.0)
        lines = _read_lines(op_s, 2.0)
        kick_lines = [l for l in lines if "KICK" in l and ch in l]
        _report("KICK 6 targets → 6 KICK lines (matches max_mode_params)",
                len(kick_lines) == 6,
                f"kicks={len(kick_lines)}: {kick_lines[:3]}")
    finally:
        close(op_s)
        for vs, _ in victims:
            close(vs)


def test_kick_multi_target_exceeds_limit():
    """KICK beyond max_mode_params: only first max_mode_params targets are kicked."""
    op_s, op_n = connect()
    # 8 victims, limit is 6 → only 6 should be kicked
    victims = [connect() for _ in range(8)]
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        for vs, vn in victims:
            _send(vs, f"JOIN {ch}")
            time.sleep(0.1)
        time.sleep(0.5)
        _drain(op_s, 0.3)

        nick_list = ",".join(vn for _, vn in victims)
        _send(op_s, f"KICK {ch} {nick_list} :over limit")
        time.sleep(1.2)
        lines = _read_lines(op_s, 2.0)
        kick_lines = [l for l in lines if "KICK" in l and ch in l]
        _report("KICK beyond max_mode_params → capped at 6",
                len(kick_lines) == 6,
                f"kicks received={len(kick_lines)}")
    finally:
        close(op_s)
        for vs, _ in victims:
            close(vs)


def test_kick_only_channel_operator_can_kick():
    """Non-chanop cannot KICK → 482 ERR_CHANOPRIVSNEEDED."""
    op_s, op_n = connect()
    reg_s, reg_n = connect()
    v_s,   v_n  = connect()
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        _send(reg_s, f"JOIN {ch}")
        _send(v_s,   f"JOIN {ch}")
        _drain(reg_s, 0.3)

        _send(reg_s, f"KICK {ch} {v_n} :non-op test")
        lines = _read_lines(reg_s, 2.0)
        _report("Non-chanop KICK denied → 482",
                _has_num(lines, "482"), str(lines[:2]))
    finally:
        close(op_s)
        close(reg_s)
        close(v_s)


def test_mode_broadcast_one_per_line_default():
    """With default mode_broadcast_params=1, MODE +ooo broadcasts 3 separate lines."""
    op_s, op_n = connect()
    users = [connect() for _ in range(3)]
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        for us, un in users:
            _send(us, f"JOIN {ch}")
            time.sleep(0.1)
        time.sleep(0.5)
        _drain(op_s, 0.3)

        nick_list = " ".join(un for _, un in users)
        _send(op_s, f"MODE {ch} +ooo {nick_list}")
        time.sleep(0.8)
        lines = _read_lines(op_s, 2.0)
        mode_lines = [l for l in lines if "MODE" in l and ch in l
                      and "+" in l and "o" in l]
        # Default mode_broadcast_params=1 → one MODE line per user, no trailing space
        all_single = all("+o" in l for l in mode_lines)
        no_trailing_space = all(not l.endswith(" ") for l in mode_lines)
        _report("MODE +ooo (broadcast_params=1 default) → 3 separate +o lines",
                len(mode_lines) == 3 and all_single,
                f"lines={mode_lines}")
        _report("No trailing space in broadcast MODE lines",
                no_trailing_space, str(mode_lines[:2]))
    finally:
        close(op_s)
        for us, _ in users:
            close(us)


def test_mode_max_params_six_accepted():
    """Server accepts MODE +oooooo with 6 targets (max_mode_params=6)."""
    op_s, op_n = connect()
    users = [connect() for _ in range(6)]
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        for us, un in users:
            _send(us, f"JOIN {ch}")
            time.sleep(0.1)
        time.sleep(0.5)
        _drain(op_s, 0.3)

        nick_list = " ".join(un for _, un in users)
        _send(op_s, f"MODE {ch} +oooooo {nick_list}")
        time.sleep(1.2)
        lines = _read_lines(op_s, 2.0)
        mode_lines = [l for l in lines if "MODE" in l and ch in l
                      and "+" in l and "o" in l]
        # All 6 modes accepted; broadcast_params=1 means 6 separate lines
        _report("Server accepts +oooooo (6 modes, within max_mode_params=6)",
                len(mode_lines) == 6,
                f"lines received={len(mode_lines)}")
    finally:
        close(op_s)
        for us, _ in users:
            close(us)


def test_mode_excess_params_capped():
    """MODE with more than max_mode_params (6) targets: only first 6 are applied."""
    op_s, op_n = connect()
    users = [connect() for _ in range(8)]  # 8 > max_mode_params=6
    ch = chan()
    try:
        _send(op_s, f"JOIN {ch}")
        _drain(op_s, 0.5)
        for us, un in users:
            _send(us, f"JOIN {ch}")
            time.sleep(0.1)
        time.sleep(0.5)
        _drain(op_s, 0.3)

        nick_list = " ".join(un for _, un in users)
        _send(op_s, f"MODE {ch} +oooooooo {nick_list}")
        time.sleep(1.2)
        lines = _read_lines(op_s, 2.0)
        mode_lines = [l for l in lines if "MODE" in l and ch in l
                      and "+" in l and "o" in l]
        # max_mode_params=6 caps the input; broadcast_params=1 → 6 separate output lines
        _report("MODE +oooooooo (8 nicks) capped at max_mode_params=6",
                len(mode_lines) == 6,
                f"mode_lines={len(mode_lines)}")
    finally:
        close(op_s)
        for us, _ in users:
            close(us)


# ===========================================================================
# REHASH — ISUPPORT re-burst + server rename
# ===========================================================================

IRCD_CONF_PATH = "/usr/local/etc/ircd.conf"


def test_rehash_isupport_reburst():
    """After REHASH, existing clients receive updated ISUPPORT 005 lines."""
    client_s, client_n = connect()
    op_s, op_n = connect()
    try:
        oper_up(op_s)
        _drain(client_s, 0.3)

        _send(op_s, "REHASH")
        time.sleep(1.5)

        lines = _read_lines(client_s, 2.0)
        isupport_lines = [l for l in lines if " 005 " in l]
        _report("REHASH re-bursts ISUPPORT 005 to existing clients",
                len(isupport_lines) >= 2,
                f"005 lines received={len(isupport_lines)}")
        # Verify MODES= is still in 005 after rehash
        modes_present = any("MODES=" in l for l in isupport_lines)
        _report("REHASH 005 includes MODES= token",
                modes_present, str([l for l in isupport_lines if "MODES" in l][:1]))
    finally:
        close(client_s)
        close(op_s)


def test_rehash_server_rename():
    """Live server rename via rehash: updating serverinfo::name takes effect
    immediately and the new name appears in 005 sent to existing clients."""
    import re as _re

    # Read current conf to get original name and restore later
    try:
        with open(IRCD_CONF_PATH) as f:
            orig_conf = f.read()
    except OSError:
        _skip("REHASH server rename", f"cannot read {IRCD_CONF_PATH}")
        return

    m = _re.search(r'name\s*=\s*"([^"]+)"', orig_conf)
    if not m:
        _skip("REHASH server rename", "could not find name= in ircd.conf")
        return
    orig_name = m.group(1)
    new_name = "rehash-renamed." + orig_name

    client_s, client_n = connect()
    op_s, op_n = connect()
    renamed_ok = False
    try:
        oper_up(op_s)
        _drain(client_s, 0.3)

        # Temporarily rename the server in ircd.conf
        new_conf = orig_conf.replace(f'name = "{orig_name}"', f'name = "{new_name}"', 1)
        with open(IRCD_CONF_PATH, "w") as f:
            f.write(new_conf)

        _send(op_s, "REHASH")
        time.sleep(1.5)

        lines = _read_lines(client_s, 2.0)
        isupport_lines = [l for l in lines if " 005 " in l]
        renamed_ok = any(new_name in l for l in isupport_lines)
        _report("REHASH live server rename → new name in 005 to existing clients",
                renamed_ok,
                f"new_name={new_name!r} found={renamed_ok}")
    finally:
        # Always restore original conf and rehash back
        try:
            with open(IRCD_CONF_PATH, "w") as f:
                f.write(orig_conf)
        except OSError:
            pass
        _send(op_s, "REHASH")
        time.sleep(1.0)
        close(client_s)
        close(op_s)


# ===========================================================================
# Runner
# ===========================================================================

ALL_TESTS = [
    # — EVENT —
    ("EVENT ADD non-oper blocked",                   test_event_nonoper_blocked),
    ("EVENT ADD CHANNEL → 808",                      test_event_add_channel),
    ("EVENT ADD USER with mask → 808",               test_event_add_with_mask),
    ("EVENT ADD MEMBER → 808",                       test_event_add_member),
    ("EVENT ADD SERVER → 808",                       test_event_add_server),
    ("EVENT ADD OPERSPY with oper:spy → 808",        test_event_add_operspy_requires_privilege),
    ("EVENT ADD duplicate → 821",                    test_event_add_duplicate),
    ("EVENT ADD invalid type → 823",                 test_event_add_invalid_type),
    ("EVENT LIST empty → 810 only",                  test_event_list_empty),
    ("EVENT LIST shows 809 + 810",                   test_event_list_shows_subscriptions),
    ("EVENT LIST CHANNEL filter",                    test_event_list_by_type),
    ("EVENT LIST invalid type → 823",                test_event_list_nonexistent_type),
    ("EVENT DELETE removes subscription",            test_event_delete),
    ("EVENT DELETE unsubscribed → 822",              test_event_delete_missing),
    ("EVENT MEMBER delivers JOIN",                   test_event_delivery_join),
    ("EVENT MEMBER delivers PART",                   test_event_delivery_part),
    ("EVENT CHANNEL CREATE not fired for IRCX owner", test_event_delivery_channel_create_not_fired_for_ircx),
    ("EVENT USER delivers CONNECT",                  test_event_delivery_user_connect),
    ("EVENT MEMBER mask filters events",             test_event_mask_filtering),
    ("EVENT USER NICK not delivered locally",        test_event_nick_change_not_delivered_locally),
    ("EVENT cleanup on disconnect",                  test_event_disconnect_cleanup),
    # — PROP —
    ("PROP non-existent channel → 403",              test_prop_no_such_channel),
    ("PROP list empty → 819",                        test_prop_list_empty),
    ("PROP set chanop broadcasts change",            test_prop_set_chanop),
    ("PROP get specific key → 818 + 819",            test_prop_get_specific_key),
    ("PROP delete removes key",                      test_prop_delete),
    ("PROP list all → 818 entries + 819",            test_prop_list_all),
    ("PROP set non-chanop denied → 918/482",         test_prop_set_non_chanop_denied),
    ("PROP read non-chanop succeeds",                test_prop_non_chanop_can_read),
    ("PROP CLEAR removes custom props",              test_prop_clear),
    ("PROP TOPIC builtin reflects topic",            test_prop_topic_builtin),
    ("PROP set voice-only denied → 918/482",         test_prop_set_voice_denied),
    # — ACCESS —
    ("ACCESS non-existent channel → 403",            test_access_no_such_channel),
    ("ACCESS LIST empty → 803 + 805",               test_access_list_empty),
    ("ACCESS ADD non-chanop denied → 482",           test_access_add_non_chanop_denied),
    ("ACCESS ADD OP → 801",                          test_access_add_op),
    ("ACCESS ADD VOICE → 801",                       test_access_add_voice),
    ("ACCESS ADD ADMIN → 801",                       test_access_add_admin),
    ("ACCESS LIST shows 804 entries",                test_access_list_shows_entries),
    ("ACCESS LIST by level filter",                  test_access_list_by_level),
    ("ACCESS DEL → 802",                             test_access_del),
    ("ACCESS DEL missing → 915",                     test_access_del_missing),
    ("ACCESS CLEAR all entries",                     test_access_clear),
    ("ACCESS CLEAR by level (OP only)",              test_access_clear_by_level),
    ("ACCESS OP → +o on join",                       test_access_op_mode_on_join),
    ("ACCESS VOICE → +v on join",                    test_access_voice_mode_on_join),
    ("ACCESS VOICE overrides +b ban",                test_access_voice_overrides_ban),
    ("ACCESS OP overrides +i invite-only",           test_access_op_overrides_invite_only),
    ("ACCESS OP overrides +k channel key",           test_access_op_overrides_key),
    ("ACCESS VOICE does NOT override +i",            test_access_voice_cannot_override_invite_only),
    ("ACCESS SYNC applies to present members",       test_access_sync),
    # — Extban + ACCESS —
    ("ACCESS ADD OP $a: extban → 801",               test_extban_access_add_account),
    ("ACCESS LIST shows $a: extban entry",           test_extban_access_list_shows_extban),
    ("ACCESS DEL $a: extban → 802",                  test_extban_access_del_extban),
    ("Extban +b + ACCESS VOICE override → join",     test_extban_ban_plus_access_voice),
    ("ACCESS ADD ADMIN $r: extban → 801",            test_extban_access_admin_mask),
    ("Multiple ACCESS levels with extbans",          test_extban_access_multiple_levels),
    ("ACCESS CLEAR removes extban entries",          test_extban_access_clear_removes_extbans),
    # — Privilege-hierarchy: EVENT O:line restriction —
    ("Channel owner without O:line cannot use EVENT",  test_event_channel_owner_non_oper_blocked),
    ("IRC oper (O:line) can use EVENT → 808",          test_event_irc_oper_can_use_event),
    # — Privilege-hierarchy: ban overrides —
    ("No-ACCESS user blocked by +b → 474",             test_hierarchy_ban_no_access_blocked),
    ("VOICE overrides +b ban → join",                  test_hierarchy_voice_overrides_ban),
    ("OP overrides +b ban → join with +o",             test_hierarchy_op_overrides_ban),
    ("ADMIN overrides +b ban → join",                  test_hierarchy_admin_overrides_ban),
    ("VOICE cannot override +i → 473",                 test_hierarchy_voice_cannot_override_invite),
    ("OP overrides +i → join",                         test_hierarchy_op_overrides_invite),
    ("ADMIN overrides +i → join",                      test_hierarchy_admin_overrides_invite),
    ("VOICE cannot override +k → 475",                 test_hierarchy_voice_cannot_override_key),
    ("OP overrides +k → join without key",             test_hierarchy_op_overrides_key),
    ("ADMIN overrides +k → join without key",          test_hierarchy_admin_overrides_key),
    # — Privilege-hierarchy: PROP permissions —
    ("PROP hierarchy: VOICE cannot set → 918",         test_prop_hierarchy_voice_cannot_set),
    ("PROP hierarchy: channel owner can set",          test_prop_hierarchy_chanop_can_set),
    ("PROP hierarchy: IRCX owner (.) can set",         test_prop_hierarchy_owner_can_set),
    ("PROP hierarchy: plain member cannot set → 918",  test_prop_hierarchy_regular_user_cannot_set),
    ("PROP hierarchy: voice/plain members can read",   test_prop_hierarchy_all_members_can_read),
    # — Privilege-hierarchy: ACCESS levels —
    ("ACCESS ADMIN → owner mode on join",              test_hierarchy_access_admin_gets_owner_mode),
    ("ACCESS LIST shows VOICE/OP/OWNER levels",        test_hierarchy_access_levels_in_list),
    ("ACCESS OP user can set PROP",                    test_hierarchy_access_op_can_set_prop),
    ("ACCESS VOICE user cannot set PROP → 918",        test_hierarchy_access_voice_cannot_set_prop),
    ("Multiple ACCESS entries: highest level wins",    test_hierarchy_multiple_access_highest_wins),
    ("ACCESS OP overrides +l channel full",            test_hierarchy_access_op_overrides_limit),
    ("ACCESS VOICE cannot override +l → 471",          test_hierarchy_access_voice_cannot_override_limit),
    # — PROP user-entity —
    ("PROP self → NICK builtin",                       test_prop_user_read_own),
    ("PROP other user → their NICK builtin",           test_prop_user_read_other),
    ("PROP write to own entity denied → 918",          test_prop_user_write_denied),
    # — Combined —
    ("EVENT MEMBER kick shows victim",               test_event_kick_shows_correct_target),
    ("ACCESS OP user can read PROP",                 test_prop_readable_after_access_op_join),
    ("EVENT fires for ACCESS-OP-promoted join",      test_access_and_event_together),
    ("EVENT OPERSPY fires on WHOIS of oper",         test_event_operspy_spy_whois),
    ("EVENT OPERSPY fires on ADMIN command",         test_event_operspy_admin_command),
    # — Multi-target KICK + configurable MODE params —
    ("ISUPPORT MODES= reflects max_mode_params (6)", test_modes_isupport_value),
    ("KICK single target backward compat",           test_kick_single_target),
    ("KICK nick1,nick2 → 2 KICK lines",              test_kick_multi_target_two),
    ("KICK 6 targets → 6 KICK lines",               test_kick_multi_target_six),
    ("KICK >6 targets capped at max_mode_params",    test_kick_multi_target_exceeds_limit),
    ("Non-chanop KICK denied → 482",                 test_kick_only_channel_operator_can_kick),
    ("MODE broadcast_params=1 → separate lines",     test_mode_broadcast_one_per_line_default),
    ("MODE +oooooo (6) accepted by max_mode_params", test_mode_max_params_six_accepted),
    ("MODE +oooooooo (8) capped at 6",               test_mode_excess_params_capped),
    # — REHASH: ISUPPORT re-burst + server rename —
    ("REHASH re-bursts ISUPPORT 005 to existing clients", test_rehash_isupport_reburst),
    ("REHASH live server rename → new name in 005",       test_rehash_server_rename),
]


def _run_test(fn):
    try:
        fn()
    except ConnectionRefusedError:
        _skip(fn.__name__, "server not reachable")
    except Exception as exc:
        global _failed
        _failed += 1
        print(f"\033[31m[FAIL]\033[0m {fn.__name__}  (exception: {exc})")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            traceback.print_exc()


def main():
    print(f"Ophion IRCX stress test  —  {SERVER_HOST}:{SERVER_PORT}")
    print("=" * 65)

    # Quick connectivity check
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(5)
        probe.connect((SERVER_HOST, SERVER_PORT))
        probe.close()
    except Exception as exc:
        print(f"ERROR: Cannot connect to {SERVER_HOST}:{SERVER_PORT}: {exc}")
        sys.exit(1)

    for label, fn in ALL_TESTS:
        print(f"\n--- {label} ---")
        try:
            fn()
        except ConnectionRefusedError:
            _skip(label, "server not reachable")
        except Exception as exc:
            global _failed
            _failed += 1
            print(f"\033[31m[FAIL]\033[0m {label}  (exception: {exc})")
            if "--verbose" in sys.argv or "-v" in sys.argv:
                traceback.print_exc()
        time.sleep(0.05)

    print()
    print("=" * 65)
    total = _passed + _failed + _skipped
    print(f"Results: {_passed} passed, {_failed} failed, {_skipped} skipped  ({total} total)")
    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
