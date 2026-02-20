#!/usr/bin/env python3
"""
wsockd stress test suite
========================
Tests the rewritten wsockd WebSocket helper daemon in isolation by
acting as both the ircd (control socket / plain-IRC side) and a
WebSocket client simultaneously.

IPC protocol (matching wsproc.c / wsockd.c):
  ircd→wsockd: 'A' + uint32_t(conn_id) + 2 FDs via SCM_RIGHTS
                  F[0] = WebSocket socket (client-facing)
                  F[1] = plain-IRC socket (ircd-facing)
  wsockd→ircd: 'D' + uint32_t(conn_id) + NUL-terminated reason

Run:
  python3 tests/test_wsockd.py
  (builds wsockd if necessary via ninja first)
"""

import array
import base64
import hashlib
import os
import socket
import struct
import subprocess
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REPO_ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WSOCKD_PATH = os.path.join(REPO_ROOT, "builddir", "wsockd", "wsockd")
WS_MAGIC    = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# ---------------------------------------------------------------------------
# Results tracking
# ---------------------------------------------------------------------------
_passed = _failed = 0

def _ok(name):
    global _passed
    _passed += 1
    print(f"  \033[32m✓\033[0m {name}")

def _fail(name, detail=""):
    global _failed
    _failed += 1
    print(f"  \033[31m✗\033[0m {name}" + (f": {detail}" if detail else ""))

def assert_test(name, cond, detail=""):
    if cond:
        _ok(name)
    else:
        _fail(name, detail)

# ---------------------------------------------------------------------------
# WebSocket helpers
# ---------------------------------------------------------------------------
def ws_accept_key(client_key: str) -> str:
    digest = hashlib.sha1((client_key + WS_MAGIC).encode()).digest()
    return base64.b64encode(digest).decode()

def ws_upgrade_request(key: str, extra: str = "") -> bytes:
    return (
        f"GET / HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"{extra}"
        f"\r\n"
    ).encode()

def ws_frame(opcode: int, payload: bytes, *, masked: bool = True, rsv: int = 0) -> bytes:
    """Encode one WebSocket frame."""
    b0 = 0x80 | (rsv << 4) | (opcode & 0xF)  # FIN=1
    plen = len(payload)
    if plen < 126:
        b1_len = plen
        ext = b""
    elif plen < 65536:
        b1_len = 126
        ext = struct.pack(">H", plen)
    else:
        b1_len = 127
        ext = struct.pack(">Q", plen)

    if masked:
        mk = os.urandom(4)
        b1 = 0x80 | b1_len
        masked_payload = bytes(b ^ mk[i % 4] for i, b in enumerate(payload))
        return bytes([b0, b1]) + ext + mk + masked_payload
    else:
        b1 = b1_len
        return bytes([b0, b1]) + ext + payload

def ws_recv_frame(sock: socket.socket, timeout: float = 2.0):
    """
    Read one complete WebSocket frame.
    Returns (opcode, payload) or None on error/timeout.
    """
    sock.settimeout(timeout)
    try:
        hdr = _recv_exact(sock, 2)
        if hdr is None:
            return None
        opcode = hdr[0] & 0xF
        masked  = (hdr[1] >> 7) & 1
        length  = hdr[1] & 0x7F
        if length == 126:
            ext = _recv_exact(sock, 2)
            length = struct.unpack(">H", ext)[0]
        elif length == 127:
            ext = _recv_exact(sock, 8)
            length = struct.unpack(">Q", ext)[0]
        if masked:
            mk = _recv_exact(sock, 4)
        data = _recv_exact(sock, length) or b""
        if masked:
            data = bytes(b ^ mk[i % 4] for i, b in enumerate(data))
        return opcode, data
    except (socket.timeout, OSError):
        return None

def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

# ---------------------------------------------------------------------------
# wsockd IPC harness
# ---------------------------------------------------------------------------
class WsockdHarness:
    """
    Manages one wsockd subprocess.
    Provides new_conn() to create mock client+ircd socket pairs and
    register them with wsockd via the 'A' IPC command.
    """

    def __init__(self):
        # AF_UNIX SOCK_DGRAM pair: [0]=our/ircd side, [1]=wsockd side
        self._ctl  = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._pipe_r, self._pipe_w = os.pipe()
        self._next_id = 1
        self._lock = threading.Lock()
        self._proc = None

    def start(self) -> "WsockdHarness":
        if not os.path.isfile(WSOCKD_PATH):
            subprocess.run(
                ["ninja", "-C", os.path.join(REPO_ROOT, "builddir"), "wsockd/wsockd"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        env = os.environ.copy()
        env["CTL_FD"]   = str(self._ctl[1].fileno())
        env["CTL_PIPE"] = str(self._pipe_r)
        env["CTL_PPID"] = str(os.getpid())
        self._proc = subprocess.Popen(
            [WSOCKD_PATH],
            env=env,
            pass_fds=(self._ctl[1].fileno(), self._pipe_r),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._ctl[1].close()
        os.close(self._pipe_r)
        time.sleep(0.15)   # let wsockd enter its event loop
        return self

    def new_conn(self):
        """
        Create a mock connection and register it with wsockd.

        Returns (ws_sock, plain_sock, conn_id):
          ws_sock   – our WebSocket client end; talk WebSocket protocol here
          plain_sock – our ircd end; read/write raw IRC lines here
        """
        with self._lock:
            conn_id = self._next_id
            self._next_id += 1

        # ws_pair[0]   = our "browser" WebSocket end
        # ws_pair[1]   = wsockd's mod_fd  (F[0] in the 'A' command)
        ws_pair    = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        # plain_pair[0] = wsockd's plain_fd (F[1] in the 'A' command)
        # plain_pair[1] = our "ircd" plain IRC end
        plain_pair = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        # 'A' command: opcode + conn_id (native-endian uint32, matching buf_to_uint32)
        buf = b"A" + struct.pack("=I", conn_id)
        fds = [ws_pair[1].fileno(), plain_pair[0].fileno()]
        ancdata = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                    array.array("i", fds).tobytes())]
        self._ctl[0].sendmsg([buf], ancdata)

        ws_pair[1].close()
        plain_pair[0].close()

        time.sleep(0.05)   # let wsockd accept the connection
        return ws_pair[0], plain_pair[1], conn_id

    def stop(self):
        if self._proc:
            self._proc.terminate()
            self._proc.wait(timeout=2)

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


# ---------------------------------------------------------------------------
# Helper: perform a valid WebSocket handshake
# ---------------------------------------------------------------------------
def do_handshake(sock: socket.socket, extra: str = "") -> bool:
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(ws_upgrade_request(key, extra))
    sock.settimeout(2.0)
    try:
        resp = sock.recv(4096)
    except socket.timeout:
        return False
    return b"101" in resp


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
def run_all(h: WsockdHarness):

    # ── 1. Valid handshake ─────────────────────────────────────────────────
    ws, pl, _ = h.new_conn()
    key = base64.b64encode(os.urandom(16)).decode()
    ws.sendall(ws_upgrade_request(key))
    resp = ws.recv(4096).decode(errors="replace")
    assert_test(
        "Valid handshake → 101 + correct Sec-WebSocket-Accept",
        "101" in resp and ws_accept_key(key) in resp,
        resp[:120],
    )
    ws.close(); pl.close()

    # ── 2. Missing Upgrade header → 400 ───────────────────────────────────
    ws, pl, _ = h.new_conn()
    ws.sendall(
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    )
    resp = ws.recv(4096)
    assert_test("Missing Upgrade: websocket → HTTP 400", b"400" in resp, resp[:80])
    ws.close(); pl.close()

    # ── 3. Wrong version → 400 ────────────────────────────────────────────
    ws, pl, _ = h.new_conn()
    ws.sendall(
        b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Version: 8\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    )
    resp = ws.recv(4096)
    assert_test("Wrong Sec-WebSocket-Version (8) → HTTP 400", b"400" in resp, resp[:80])
    ws.close(); pl.close()

    # ── 4. Sec-WebSocket-Protocol: irc echoed ─────────────────────────────
    ws, pl, _ = h.new_conn()
    key = base64.b64encode(os.urandom(16)).decode()
    ws.sendall(ws_upgrade_request(key, "Sec-WebSocket-Protocol: irc\r\n"))
    resp = ws.recv(4096).decode(errors="replace")
    assert_test(
        "Sec-WebSocket-Protocol: irc echoed in 101 response",
        "101" in resp and "Sec-WebSocket-Protocol: irc" in resp,
        resp[:200],
    )
    ws.close(); pl.close()

    # ── 5. Sec-WebSocket-Protocol without irc → not echoed ────────────────
    ws, pl, _ = h.new_conn()
    key = base64.b64encode(os.urandom(16)).decode()
    ws.sendall(ws_upgrade_request(key, "Sec-WebSocket-Protocol: chat\r\n"))
    resp = ws.recv(4096).decode(errors="replace")
    assert_test(
        "Unsupported subprotocol not echoed (still 101)",
        "101" in resp and "Sec-WebSocket-Protocol" not in resp,
        resp[:200],
    )
    ws.close(); pl.close()

    # ── 6. Split TCP handshake ─────────────────────────────────────────────
    ws, pl, _ = h.new_conn()
    key  = base64.b64encode(os.urandom(16)).decode()
    req  = ws_upgrade_request(key)
    mid  = len(req) // 2
    ws.sendall(req[:mid])
    time.sleep(0.05)
    ws.sendall(req[mid:])
    ws.settimeout(2.0)
    resp = ws.recv(4096).decode(errors="replace")
    assert_test(
        "Handshake split across two TCP segments handled correctly",
        "101" in resp and ws_accept_key(key) in resp,
        resp[:120],
    )
    ws.close(); pl.close()

    # ── 7. Normal masked TEXT frame forwarded to plain socket ──────────────
    ws, pl, _ = h.new_conn()
    assert do_handshake(ws)
    ws.sendall(ws_frame(0x1, b"NICK alice\r\n"))
    pl.settimeout(2.0)
    try:
        data = pl.recv(1024)
        assert_test("Masked TEXT frame forwarded to plain-IRC socket",
                    b"NICK" in data, data[:80])
    except socket.timeout:
        _fail("Masked TEXT frame forwarded to plain-IRC socket", "timeout")
    ws.close(); pl.close()

    # ── 8. Zero-length TEXT frame (was: closes connection) ────────────────
    ws, pl, _ = h.new_conn()
    assert do_handshake(ws)
    ws.sendall(ws_frame(0x1, b""))           # zero-length — must not close
    ws.sendall(ws_frame(0x1, b"PING :probe\r\n"))
    pl.settimeout(2.0)
    try:
        data = pl.recv(1024)
        assert_test("Zero-length TEXT frame: connection stays open",
                    b"PING" in data, data[:80])
    except socket.timeout:
        _fail("Zero-length TEXT frame: connection stays open",
              "connection closed or data never arrived")
    ws.close(); pl.close()

    # ── 9. IRC line from plain socket wrapped in WebSocket frame ──────────
    ws, pl, _ = h.new_conn()
    assert do_handshake(ws)
    pl.sendall(b":server 001 alice :Welcome\r\n")
    frame = ws_recv_frame(ws)
    assert_test(
        "Plain-IRC line wrapped in TEXT frame and sent to WebSocket client",
        frame is not None and frame[0] == 0x1 and b"Welcome" in frame[1],
        str(frame),
    )
    ws.close(); pl.close()

    # ── 10. PING → PONG with matching payload ─────────────────────────────
    ws, pl, _ = h.new_conn()
    assert do_handshake(ws)
    ping_payload = b"keepalive-" + os.urandom(4)
    ws.sendall(ws_frame(0x9, ping_payload))
    frame = ws_recv_frame(ws)
    assert_test(
        "PING → PONG with identical payload (RFC 6455 §5.5.3)",
        frame is not None and frame[0] == 0xA and frame[1] == ping_payload,
        str(frame),
    )
    ws.close(); pl.close()

    # ── 11. Zero-length PING → PONG ───────────────────────────────────────
    ws, pl, _ = h.new_conn()
    assert do_handshake(ws)
    ws.sendall(ws_frame(0x9, b""))
    frame = ws_recv_frame(ws)
    assert_test(
        "Zero-length PING → PONG (no crash on empty payload)",
        frame is not None and frame[0] == 0xA,
        str(frame),
    )
    ws.close(); pl.close()

    # ── 12. RSV bits set → CLOSE 1002 ────────────────────────────────────
    ws, pl, _ = h.new_conn()
    assert do_handshake(ws)
    ws.sendall(ws_frame(0x1, b"NICK x\r\n", rsv=0x4))  # RSV1=1
    frame = ws_recv_frame(ws)
    if frame and frame[0] == 0x8:
        code = struct.unpack(">H", frame[1][:2])[0] if len(frame[1]) >= 2 else 0
        assert_test("Non-zero RSV bits → CLOSE frame 1002",
                    code == 1002, f"got code {code}")
    else:
        _fail("Non-zero RSV bits → CLOSE frame 1002",
              f"no CLOSE received, got: {frame}")
    ws.close(); pl.close()

    # ── 13. CLOSE frame → echoed CLOSE (RFC 6455 §5.5.1) ─────────────────
    ws, pl, _ = h.new_conn()
    assert do_handshake(ws)
    ws.sendall(ws_frame(0x8, struct.pack(">H", 1000) + b"normal close"))
    frame = ws_recv_frame(ws)
    assert_test(
        "Received CLOSE → CLOSE echoed back before teardown",
        frame is not None and frame[0] == 0x8,
        str(frame),
    )
    ws.close(); pl.close()

    # ── 14. Huge frame (>65535 bytes) → CLOSE 1009 ───────────────────────
    ws, pl, _ = h.new_conn()
    assert do_handshake(ws)
    ws.sendall(ws_frame(0x1, b"X" * 65537))
    frame = ws_recv_frame(ws, timeout=4.0)
    if frame and frame[0] == 0x8:
        code = struct.unpack(">H", frame[1][:2])[0] if len(frame[1]) >= 2 else 0
        assert_test("Frame >65535 bytes → CLOSE 1009 (message too big)",
                    code == 1009, f"got code {code}")
    else:
        _fail("Frame >65535 bytes → CLOSE 1009", f"got: {frame}")
    ws.close(); pl.close()

    # ── 15. Oversized HTTP headers → 400 ─────────────────────────────────
    ws, pl, _ = h.new_conn()
    junk_header = "X-Junk: " + "A" * 4000 + "\r\n"
    ws.sendall(ws_upgrade_request("dGhlIHNhbXBsZSBub25jZQ==", junk_header))
    resp = ws.recv(4096)
    assert_test("Oversized HTTP headers (>4096 bytes) → HTTP 400",
                b"400" in resp, resp[:80])
    ws.close(); pl.close()

    # ── 16. Concurrent handshakes ─────────────────────────────────────────
    N = 40
    errors = []
    lock  = threading.Lock()

    def _concurrent(idx):
        try:
            w, p, _ = h.new_conn()
            key = base64.b64encode(os.urandom(16)).decode()
            w.sendall(ws_upgrade_request(key))
            w.settimeout(3.0)
            resp = w.recv(4096)
            if b"101" not in resp:
                with lock:
                    errors.append(f"#{idx}: no 101")
            else:
                w.sendall(ws_frame(0x1, f"NICK user{idx}\r\n".encode()))
            w.close(); p.close()
        except Exception as e:
            with lock:
                errors.append(f"#{idx}: {e}")

    threads = [threading.Thread(target=_concurrent, args=(i,)) for i in range(N)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=10.0)
    assert_test(
        f"Concurrent handshakes ({N} simultaneous)",
        len(errors) == 0,
        "; ".join(errors[:3]),
    )

    # ── 17. Throughput ─────────────────────────────────────────────────────
    ws, pl, _ = h.new_conn()
    assert do_handshake(ws)
    N_msg = 500
    t0 = time.monotonic()
    for i in range(N_msg):
        ws.sendall(ws_frame(0x1, f"PRIVMSG #ch :msg {i}\r\n".encode()))
    pl.settimeout(5.0)
    received = 0
    buf = b""
    try:
        while received < N_msg:
            chunk = pl.recv(65536)
            if not chunk:
                break
            buf += chunk
            received = buf.count(b"\n")
    except socket.timeout:
        pass
    elapsed = time.monotonic() - t0
    assert_test(
        f"Throughput: {N_msg} frames forwarded "
        f"({received}/{N_msg} received, {N_msg/elapsed:.0f} msg/s)",
        received >= int(N_msg * 0.99),
        f"only {received}/{N_msg}",
    )
    ws.close(); pl.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"wsockd stress test  —  {WSOCKD_PATH}")
    print("=" * 60)

    if not os.path.isfile(WSOCKD_PATH):
        print("Building wsockd first …")
        subprocess.run(
            ["ninja", "-C", os.path.join(REPO_ROOT, "builddir"), "wsockd/wsockd"],
            check=True,
        )

    with WsockdHarness() as h:
        run_all(h)

    print()
    total = _passed + _failed
    print(f"Results: {_passed}/{total} passed", end="")
    if _failed:
        print(f"  ({_failed} FAILED)")
        sys.exit(1)
    else:
        print("  — all passed")
