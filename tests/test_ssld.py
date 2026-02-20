#!/usr/bin/env python3
"""
ssld TLS stress test suite
===========================
Tests the wolfSSL-backed ssld helper daemon in isolation by acting as both
the ircd (control socket / plain-IRC side) and a TLS client simultaneously.

IPC protocol (matching sslproc.c / ssld.c):
  ircd→ssld: 'K\0<cert>\0<key>\0<dhparam>\0<ciphers>\0<verify>'   configure keys
  ircd→ssld: 'A' + uint32_t(conn_id) + 2 FDs via SCM_RIGHTS
                   F[0] = TLS socket (client-facing, to be SSL-accepted)
                   F[1] = plain socket (ircd-facing)
  ssld→ircd: 'O' + uint32_t(conn_id)                              handshake OK
             'C' + uint32_t(id) + cipher_string + NUL             cipher info
             'F' + uint32_t(id) + uint32_t(method) + uint32_t(len) + bytes  certfp
             'D' + uint32_t(conn_id) + NUL-term reason            disconnected

Run:
  python3 tests/test_ssld.py
  (ssld must be built first: ninja -C build)
"""

import array
import hashlib
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REPO_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SSLD_PATHS = [
    os.path.join(REPO_ROOT, "build", "ssld", "ssld"),
    os.path.join(REPO_ROOT, "builddir", "ssld", "ssld"),
]
SSLD_PATH  = next((p for p in SSLD_PATHS if os.path.exists(p)), None)

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
    msg = f"  \033[31m✗\033[0m {name}"
    if detail:
        msg += f": {detail}"
    print(msg)

def assert_test(name, cond, detail=""):
    if cond:
        _ok(name)
    else:
        _fail(name, detail)


# ---------------------------------------------------------------------------
# Certificate generation via openssl CLI
# ---------------------------------------------------------------------------

def _generate_selfsigned_cert(tmpdir):
    """Generate a self-signed RSA cert+key via the openssl CLI."""
    cert_path = os.path.join(tmpdir, "server.crt")
    key_path  = os.path.join(tmpdir, "server.key")
    subprocess.run(
        [
            "openssl", "req", "-x509",
            "-newkey", "rsa:2048",
            "-keyout", key_path,
            "-out", cert_path,
            "-days", "365",
            "-nodes",
            "-subj", "/CN=ssld-test",
        ],
        check=True,
        capture_output=True,
    )
    return cert_path, key_path


def _cert_fingerprint_sha256(cert_path):
    """Return the raw DER-SHA256 fingerprint bytes of a PEM cert file."""
    result = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-outform", "DER"],
        capture_output=True, check=True,
    )
    return hashlib.sha256(result.stdout).digest()


# ---------------------------------------------------------------------------
# SCM_RIGHTS helpers
# ---------------------------------------------------------------------------

def _send_fds(sock, data: bytes, fds):
    """Send *data* with file descriptors *fds* over a Unix socket."""
    fd_arr = array.array('i', fds)
    sock.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fd_arr)])

def _recv_msg(sock, bufsize=4096, timeout=3.0):
    """Receive a plain datagram from a Unix socket."""
    sock.settimeout(timeout)
    try:
        return sock.recv(bufsize)
    except socket.timeout:
        return b""


# ---------------------------------------------------------------------------
# SsldHarness
# ---------------------------------------------------------------------------

class SsldHarness:
    """Manages a single ssld subprocess plus a Unix-datagram control socket pair."""

    def __init__(self, cert_path, key_path):
        self.cert_path = cert_path
        self.key_path  = key_path
        self._conn_id  = 0

        self.ctl_harness, self.ctl_ssld = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_DGRAM
        )
        self._pipe_r, self._pipe_w = os.pipe()

        env = os.environ.copy()
        env["CTL_FD"]   = str(self.ctl_ssld.fileno())
        env["CTL_PIPE"] = str(self._pipe_r)
        env["CTL_PPID"] = str(os.getpid())

        self._proc = subprocess.Popen(
            [SSLD_PATH],
            env=env,
            pass_fds=(self.ctl_ssld.fileno(), self._pipe_r),
            close_fds=True,
        )
        self.ctl_ssld.close()
        os.close(self._pipe_r)

        # Configure TLS keys
        nul = b'\x00'
        cmd = (
            b'K' + nul +
            cert_path.encode() + nul +
            key_path.encode()  + nul +
            nul +    # dhparam = ""
            nul +    # cipher_list = ""
            b'0'     # verify = false
        )
        self.ctl_harness.sendall(cmd)
        time.sleep(0.1)   # give ssld time to load the cert

    def new_conn(self):
        """
        Create a socketpair for TLS and one for plain text, pass the TLS
        server side and plain ssld side to ssld via SCM_RIGHTS.
        Returns (conn_id, tls_client_sock, plain_ircd_sock).
        """
        self._conn_id += 1
        cid = self._conn_id

        tls_client, tls_server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        plain_ircd, plain_ssld = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        hdr = b'A' + struct.pack("=I", cid)
        _send_fds(self.ctl_harness, hdr, [tls_server.fileno(), plain_ssld.fileno()])

        tls_server.close()
        plain_ssld.close()

        return cid, tls_client, plain_ircd

    def drain_ctl(self, conn_id=None, timeout=3.0):
        """Drain messages until 'O' for conn_id (or any 'O' if None)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            buf = _recv_msg(self.ctl_harness, timeout=max(0.05, remaining))
            if not buf:
                continue
            cmd = chr(buf[0])
            rid = struct.unpack("=I", buf[1:5])[0] if len(buf) >= 5 else None
            if cmd == 'O' and (conn_id is None or rid == conn_id):
                return True
            if cmd == 'D' and (conn_id is None or rid == conn_id):
                return False
        return False

    def close(self):
        self.ctl_harness.close()
        os.close(self._pipe_w)
        self._proc.wait(timeout=3)


# ---------------------------------------------------------------------------
# TLS client helper
# ---------------------------------------------------------------------------

def _tls_ctx(cert_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cert_path)
    ctx.check_hostname = False
    return ctx

def _do_tls(raw_sock, ctx):
    return ctx.wrap_socket(raw_sock, server_side=False, server_hostname="ssld-test")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_basic_handshake(h, ctx):
    cid, raw, plain = h.new_conn()
    try:
        tls = _do_tls(raw, ctx)
        ok = h.drain_ctl(conn_id=cid)
        assert_test("basic TLS handshake completes", ok)
        tls.close()
    except Exception as e:
        assert_test("basic TLS handshake completes", False, str(e))
    finally:
        plain.close()


def test_cipher_info(h, ctx):
    """ssld sends 'C' cipher message before 'O'."""
    cid, raw, plain = h.new_conn()
    try:
        tls = _do_tls(raw, ctx)
        found_cipher = False
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            buf = _recv_msg(h.ctl_harness, timeout=0.3)
            if not buf:
                continue
            if buf[0:1] == b'C':
                found_cipher = True
            if buf[0:1] == b'O':
                break
        assert_test("cipher-info 'C' message received before 'O'", found_cipher)
        tls.close()
    except Exception as e:
        assert_test("cipher-info 'C' message received before 'O'", False, str(e))
    finally:
        plain.close()


def test_client_to_plain(h, ctx):
    """Data from TLS client arrives decrypted on plain FD."""
    cid, raw, plain = h.new_conn()
    try:
        tls = _do_tls(raw, ctx)
        h.drain_ctl(conn_id=cid)
        msg = b"NICK alice\r\n"
        tls.sendall(msg)
        plain.settimeout(3.0)
        got = b""
        while len(got) < len(msg):
            chunk = plain.recv(1024)
            if not chunk:
                break
            got += chunk
        assert_test("client→ssld→plain data", got == msg, repr(got))
        tls.close()
    except Exception as e:
        assert_test("client→ssld→plain data", False, str(e))
    finally:
        plain.close()


def test_plain_to_client(h, ctx):
    """Data written to plain FD is encrypted and received by TLS client."""
    cid, raw, plain = h.new_conn()
    try:
        tls = _do_tls(raw, ctx)
        h.drain_ctl(conn_id=cid)
        msg = b":irc.example.net 001 alice :Welcome!\r\n"
        plain.sendall(msg)
        tls.settimeout(3.0)
        got = b""
        while len(got) < len(msg):
            chunk = tls.recv(1024)
            if not chunk:
                break
            got += chunk
        assert_test("plain→ssld→client data", got == msg, repr(got))
        tls.close()
    except Exception as e:
        assert_test("plain→ssld→client data", False, str(e))
    finally:
        plain.close()


def test_bad_tls_rejected(h):
    """A non-TLS client sending garbage is rejected cleanly."""
    cid, raw, plain = h.new_conn()
    try:
        raw.sendall(b"NICK foo\r\nUSER foo 0 * :foo\r\n")
        raw.close()
        buf = _recv_msg(h.ctl_harness, timeout=2.0)
        # Either no message or a 'D' disconnect
        ok = (not buf) or (buf[0:1] == b'D')
        assert_test("non-TLS client rejected", ok)
    except Exception as e:
        assert_test("non-TLS client rejected", False, str(e))
    finally:
        plain.close()


def test_bidirectional(h, ctx):
    """Bidirectional IRC-line exchange over TLS."""
    cid, raw, plain = h.new_conn()
    try:
        tls = _do_tls(raw, ctx)
        h.drain_ctl(conn_id=cid)

        lines = [f"PING :{i}\r\n".encode() for i in range(30)]
        total = sum(len(l) for l in lines)

        # client → plain
        for line in lines:
            tls.sendall(line)
        plain.settimeout(5.0)
        got = b""
        while len(got) < total:
            chunk = plain.recv(4096)
            if not chunk:
                break
            got += chunk
        assert_test("bidirectional: 30 lines client→plain",
                    got == b"".join(lines), f"{len(got)}/{total} bytes")

        # plain → client
        for line in lines:
            plain.sendall(line)
        tls.settimeout(5.0)
        got2 = b""
        while len(got2) < total:
            chunk = tls.recv(4096)
            if not chunk:
                break
            got2 += chunk
        assert_test("bidirectional: 30 lines plain→client",
                    got2 == b"".join(lines), f"{len(got2)}/{total} bytes")

        tls.close()
    except Exception as e:
        assert_test("bidirectional: 30 lines client→plain", False, str(e))
        assert_test("bidirectional: 30 lines plain→client", False, str(e))
    finally:
        plain.close()


def test_large_message(h, ctx):
    """256 KiB payload survives TLS chunking."""
    cid, raw, plain = h.new_conn()
    try:
        tls = _do_tls(raw, ctx)
        h.drain_ctl(conn_id=cid)
        payload = os.urandom(256 * 1024)
        tls.sendall(payload)
        plain.settimeout(10.0)
        got = b""
        while len(got) < len(payload):
            chunk = plain.recv(65536)
            if not chunk:
                break
            got += chunk
        assert_test("256 KiB payload over TLS",
                    got == payload, f"{len(got)}/{len(payload)} bytes")
        tls.close()
    except Exception as e:
        assert_test("256 KiB payload over TLS", False, str(e))
    finally:
        plain.close()


def test_graceful_close(h, ctx):
    """Closing TLS session triggers 'D' disconnect notification."""
    cid, raw, plain = h.new_conn()
    try:
        tls = _do_tls(raw, ctx)
        h.drain_ctl(conn_id=cid)
        tls.close()
        # Expect 'D' for this conn_id
        found = False
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            buf = _recv_msg(h.ctl_harness, timeout=0.3)
            if buf and buf[0:1] == b'D' and len(buf) >= 5:
                if struct.unpack("=I", buf[1:5])[0] == cid:
                    found = True
                    break
        assert_test("graceful close → 'D' notification", found)
    except Exception as e:
        assert_test("graceful close → 'D' notification", False, str(e))
    finally:
        try:
            plain.close()
        except Exception:
            pass


def test_concurrent_handshakes(h, ctx, n=20):
    """N concurrent TLS handshakes all complete successfully."""
    conns = [h.new_conn() for _ in range(n)]
    results = [None] * n

    def do_hs(idx, cid, raw, plain):
        try:
            tls = _do_tls(raw, ctx)
            results[idx] = ('ok', tls, plain, cid)
        except Exception as e:
            results[idx] = ('err', str(e))
            try:
                plain.close()
            except Exception:
                pass

    threads = [
        threading.Thread(target=do_hs, args=(i, cid, raw, plain))
        for i, (cid, raw, plain) in enumerate(conns)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    opens = 0
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline and opens < n:
        buf = _recv_msg(h.ctl_harness, timeout=0.2)
        if buf and buf[0:1] == b'O':
            opens += 1

    success = sum(1 for r in results if r and r[0] == 'ok')
    assert_test(f"{n} concurrent TLS handshakes",
                success == n and opens == n,
                f"{success} clients OK, {opens} 'O' messages")

    for r in results:
        if r and r[0] == 'ok':
            try:
                r[1].close()
            except Exception:
                pass
            try:
                r[2].close()
            except Exception:
                pass


def test_throughput(h, ctx, n=500):
    """500 IRC lines sent through TLS all arrive on the plain FD."""
    cid, raw, plain = h.new_conn()
    try:
        tls = _do_tls(raw, ctx)
        h.drain_ctl(conn_id=cid)

        lines = [f":a!b@c PRIVMSG #ch :msg {i}\r\n".encode() for i in range(n)]
        total = sum(len(l) for l in lines)

        def sender():
            for line in lines:
                tls.sendall(line)

        t = threading.Thread(target=sender)
        t.start()

        plain.settimeout(30.0)
        got = b""
        while len(got) < total:
            chunk = plain.recv(65536)
            if not chunk:
                break
            got += chunk
        t.join(timeout=5)

        assert_test(f"throughput: {n} messages over TLS",
                    got == b"".join(lines),
                    f"{len(got)}/{total} bytes")
        tls.close()
    except Exception as e:
        assert_test(f"throughput: {n} messages over TLS", False, str(e))
    finally:
        plain.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if SSLD_PATH is None:
        print("ERROR: ssld binary not found. Build first: ninja -C build")
        sys.exit(1)

    print(f"Using ssld: {SSLD_PATH}")

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path, key_path = _generate_selfsigned_cert(tmpdir)
        print(f"Self-signed cert: {cert_path}")

        ctx = _tls_ctx(cert_path)
        h   = SsldHarness(cert_path, key_path)

        print("\nRunning ssld TLS stress tests:")
        try:
            test_basic_handshake(h, ctx)
            test_cipher_info(h, ctx)
            test_client_to_plain(h, ctx)
            test_plain_to_client(h, ctx)
            test_bad_tls_rejected(h)
            test_bidirectional(h, ctx)
            test_large_message(h, ctx)
            test_graceful_close(h, ctx)
            test_concurrent_handshakes(h, ctx, n=20)
            test_throughput(h, ctx, n=500)
        finally:
            h.close()

    total = _passed + _failed
    print(f"\n{_passed}/{total} tests passed")
    if _failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
