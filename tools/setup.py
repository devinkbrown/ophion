#!/usr/bin/env python3
"""
Ophion IRC Server — Interactive Setup & Configuration Manager
=============================================================
Quickly configure your server, manage operators, server links, SSL/TLS,
and keep-alive cron jobs — without editing ircd.conf by hand.

Modes (first-time wizard):
  simple       — minimal required settings to get the server running
  intermediate — common optional settings (flood limits, logging, etc.)
  advanced     — every configurable option

Also provides menus to:
  • Edit server info, ports, general limits
  • Add / remove / list operator{} blocks with full privset customization
  • Add / remove / list connect{} server link blocks (password or certfp auth)
  • Set up SSL/TLS with a self-signed cert or Let's Encrypt
  • Install a crontab entry to keep the server running

Usage:
  python3 setup.py [--config /path/to/ircd.conf] [--mode simple|intermediate|advanced]
  python3 setup.py --manage       # manage an existing config
"""

import sys
import os
import re
import subprocess
import shutil
import argparse
import datetime
import hashlib
import hmac
import struct
import base64

# ---------------------------------------------------------------------------
# Default config path
# ---------------------------------------------------------------------------
DEFAULT_CONF = "/usr/local/etc/ircd.conf"
DEFAULT_TLS_DIR = "/usr/local/etc/tls"

# ---------------------------------------------------------------------------
# Built-in privset definitions (shown as suggestions)
# ---------------------------------------------------------------------------
PRIVSET_PRESETS = {
    "full": (
        "oper:general, oper:global_kill, oper:local_kill, oper:kline, oper:unkline,\n"
        "\t\toper:rehash, oper:admin, oper:die, oper:spy, oper:operwall,\n"
        "\t\toper:remoteban, oper:privs, auspex:oper, auspex:hostname,\n"
        "\t\tusermode:servnotice, oper:god, oper:xline, oper:mass_notice"
    ),
    "standard": (
        "oper:general, oper:global_kill, oper:local_kill, oper:kline, oper:unkline,\n"
        "\t\toper:rehash, oper:operwall, oper:remoteban, oper:privs,\n"
        "\t\tauspex:oper, auspex:hostname, usermode:servnotice"
    ),
    "helpop": (
        "oper:general, oper:local_kill, auspex:oper, auspex:hostname,\n"
        "\t\tusermode:servnotice"
    ),
}

# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------

def _bold(t):   return f"\033[1m{t}\033[0m"
def _green(t):  return f"\033[32m{t}\033[0m"
def _yellow(t): return f"\033[33m{t}\033[0m"
def _red(t):    return f"\033[31m{t}\033[0m"
def _cyan(t):   return f"\033[36m{t}\033[0m"

def section(title):
    print()
    print(_cyan("=" * 62))
    print(_cyan(f"  {title}"))
    print(_cyan("=" * 62))

def subsection(title):
    print()
    print(_bold(f"--- {title} ---"))

def info(msg):  print(f"  {_yellow('ℹ')}  {msg}")
def ok(msg):    print(f"  {_green('✓')}  {msg}")
def warn(msg):  print(f"  {_yellow('⚠')}  {msg}")
def err(msg):   print(f"  {_red('✗')}  {msg}")

def prompt(question, default=None, choices=None):
    hint = ""
    if choices:
        hint = f" [{'/'.join(choices)}]"
    elif default is not None:
        hint = f" [{default}]"
    while True:
        try:
            val = input(f"  {_bold(question)}{hint}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); sys.exit(0)
        if not val and default is not None:
            return default
        if choices:
            if val.lower() in [c.lower() for c in choices]:
                return val.lower()
            print(f"  {_red('Please choose:')} {', '.join(choices)}")
            continue
        if val:
            return val
        print(f"  {_red('This field is required.')}")

def prompt_yn(question, default="yes"):
    ans = prompt(question, default=default, choices=["yes", "no"])
    return ans.lower() in ("yes", "y")

def prompt_int(question, default=None, min_val=None, max_val=None):
    hint = f" [{default}]" if default is not None else ""
    while True:
        try:
            val = input(f"  {_bold(question)}{hint}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); sys.exit(0)
        if not val and default is not None:
            return default
        try:
            n = int(val)
        except ValueError:
            print(f"  {_red('Please enter a number.')}")
            continue
        if min_val is not None and n < min_val:
            print(f"  {_red(f'Minimum: {min_val}')}"); continue
        if max_val is not None and n > max_val:
            print(f"  {_red(f'Maximum: {max_val}')}"); continue
        return n

# ---------------------------------------------------------------------------
# Password hashing — built-in SHA-512 crypt (no external tools required)
# ---------------------------------------------------------------------------

def _sha512_crypt(password, salt=None):
    """
    Pure-Python SHA-512 crypt ($6$) implementation.
    Produces the same output as `mkpasswd -m sha-512` or `openssl passwd -6`.
    """
    if salt is None:
        import os as _os
        raw = _os.urandom(12)
        # base64url-like alphabet used by crypt
        _b64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        salt = ''.join(_b64[b % 64] for b in raw)[:16]

    if isinstance(password, str):
        password = password.encode()
    if isinstance(salt, str):
        salt = salt.encode()

    # Try the standard library first (fastest, always correct)
    try:
        import crypt as _crypt
        return _crypt.crypt(password.decode(), f'$6${salt.decode()}$')
    except Exception:
        pass

    # Fall back to subprocess (mkpasswd or openssl)
    for cmd in [
        ["mkpasswd", "-m", "sha-512", "--salt", salt.decode(), password.decode()],
        ["openssl", "passwd", "-6", "-salt", salt.decode(), password.decode()],
    ]:
        prog = shutil.which(cmd[0])
        if prog:
            r = subprocess.run([prog] + cmd[1:], capture_output=True, text=True)
            if r.returncode == 0:
                return r.stdout.strip()

    # Pure Python fallback (slower but dependency-free)
    return _sha512_crypt_pure(password, salt)


def _sha512_crypt_pure(password, salt):
    """
    Pure-Python SHA-512 crypt as specified in:
    https://www.akkadia.org/docs/SHA-crypt.txt
    """
    ROUNDS_DEFAULT = 5000
    HASH = hashlib.sha512
    B64  = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def b64_encode(b):
        out = []
        for i in range(0, len(b), 3):
            chunk = b[i:i+3]
            while len(chunk) < 3:
                chunk += b'\x00'
            v = chunk[0] | (chunk[1] << 8) | (chunk[2] << 16)
            for _ in range(4):
                out.append(B64[v & 0x3f])
                v >>= 6
        return ''.join(out)

    def _sha512_crypt_inner(password, salt, rounds=ROUNDS_DEFAULT):
        # Steps from SHA-crypt spec
        # Step 1-4
        A = HASH(password + salt + password).digest()
        # Step 5-8
        B = HASH(password + salt)
        # Step 9
        for _ in range(len(password) // 64):
            B.update(A)
        B.update(A[:len(password) % 64])
        B = B.digest()
        # Step 10
        Bdigest = B
        C = HASH(password)
        for _ in range(len(password)):
            C.update(Bdigest)
        C = C.digest()
        # Step 11
        P = b''
        plen = len(password)
        while plen:
            P += C[:min(plen, 64)]
            plen -= 64
        P = P[:len(password)]
        # Step 12-14
        S = b''
        slen = 16 + A[0]
        while slen:
            S += hashlib.sha512(salt + B).digest()[:min(slen, 64)]
            slen -= 64
        S = S[:16 + A[0]]
        # Step 21: rounds of SHA-512
        C2 = A
        for i in range(rounds):
            Cn = HASH()
            Cn.update(P if (i % 2) else C2)
            if i % 3:
                Cn.update(S)
            if i % 7:
                Cn.update(P)
            Cn.update(C2 if (i % 2) else P)
            C2 = Cn.digest()
        # Permuted output
        perm = [42,21,0,1,22,43,44,23,2,3,24,45,46,25,4,5,26,47,48,27,6,
                7,28,49,50,29,8,9,30,51,52,31,10,11,32,53,54,33,12,13,34,
                55,56,35,14,15,36,57,58,37,16,17,38,59,60,39,18,19,40,61,
                62,41,20,63]
        final = bytes(C2[p] for p in perm)
        return final

    rounds = ROUNDS_DEFAULT
    h = _sha512_crypt_inner(password, salt, rounds)
    encoded = _b64_sha512(h)
    return f"$6${salt.decode()}${encoded}"


def _b64_sha512(h):
    B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    def enc3(a, b, c, n):
        v = a | (b << 8) | (c << 16)
        return ''.join(B64[(v >> (6*i)) & 0x3f] for i in range(n))
    return (
        enc3(h[0],  h[21], h[42], 4) + enc3(h[22], h[43], h[1],  4) +
        enc3(h[44], h[2],  h[23], 4) + enc3(h[3],  h[24], h[45], 4) +
        enc3(h[25], h[46], h[4],  4) + enc3(h[5],  h[26], h[47], 4) +
        enc3(h[48], h[6],  h[27], 4) + enc3(h[28], h[49], h[7],  4) +
        enc3(h[8],  h[29], h[50], 4) + enc3(h[30], h[51], h[9],  4) +
        enc3(h[10], h[31], h[52], 4) + enc3(h[32], h[53], h[11], 4) +
        enc3(h[12], h[33], h[54], 4) + enc3(h[34], h[55], h[13], 4) +
        enc3(h[14], h[35], h[56], 4) + enc3(h[36], h[57], h[15], 4) +
        enc3(h[16], h[37], h[58], 4) + enc3(h[38], h[59], h[17], 4) +
        enc3(h[18], h[39], h[60], 4) + enc3(h[40], h[61], h[19], 4) +
        enc3(h[20], h[41], h[62], 4) + enc3(0,      0,     h[63], 2)
    )


def get_password(label="Password", allow_plain=True):
    """
    Prompt for a password and optionally hash it.
    Returns (hash_or_plain, is_encrypted) tuple.
    """
    pw = prompt(label)
    if allow_plain:
        encrypt = prompt_yn("Encrypt this password (recommended)?", default="yes")
    else:
        encrypt = True
    if encrypt:
        hashed = _sha512_crypt(pw)
        ok(f"SHA-512 hash: {hashed[:30]}...")
        return hashed, True
    else:
        warn("Storing password in PLAINTEXT — only use this on trusted networks.")
        return pw, False


# ---------------------------------------------------------------------------
# Certificate fingerprint helper
# ---------------------------------------------------------------------------

def get_cert_fingerprint(cert_path):
    """Return SHA-512 fingerprint of a PEM certificate file."""
    openssl = shutil.which("openssl")
    if not openssl:
        warn("openssl not found; cannot compute fingerprint automatically.")
        return None
    r = subprocess.run(
        [openssl, "x509", "-noout", "-fingerprint", "-sha512", "-in", cert_path],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        # "SHA512 Fingerprint=AA:BB:CC:..." → strip colons and lower-case
        m = re.search(r'Fingerprint=([0-9A-F:]+)', r.stdout, re.IGNORECASE)
        if m:
            return m.group(1).replace(":", "").lower()
    return None


# ---------------------------------------------------------------------------
# TLS / SSL helpers
# ---------------------------------------------------------------------------

def setup_selfsigned(tls_dir, server_name):
    """Generate a self-signed cert+key pair."""
    openssl = shutil.which("openssl")
    if not openssl:
        err("openssl not found.  Install it and run again.")
        return None, None
    os.makedirs(tls_dir, exist_ok=True)
    cert = os.path.join(tls_dir, "server.crt")
    key  = os.path.join(tls_dir, "server.key")
    r = subprocess.run([
        openssl, "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", key, "-out", cert,
        "-days", "3650", "-nodes",
        "-subj", f"/CN={server_name}",
    ], capture_output=True, text=True)
    if r.returncode == 0:
        ok(f"Self-signed cert: {cert}")
        ok(f"Private key:      {key}")
        return cert, key
    else:
        err(f"openssl failed:\n{r.stderr}")
        return None, None


def _certbot_install():
    """Try to install certbot if not present."""
    if shutil.which("certbot"):
        return True
    info("certbot not found.  Attempting to install...")
    for install_cmd in [
        ["apt-get", "install", "-y", "certbot"],
        ["yum",     "install", "-y", "certbot"],
        ["dnf",     "install", "-y", "certbot"],
    ]:
        pkg_mgr = shutil.which(install_cmd[0])
        if pkg_mgr:
            r = subprocess.run([pkg_mgr] + install_cmd[1:],
                               capture_output=True, text=True)
            if r.returncode == 0 and shutil.which("certbot"):
                ok("certbot installed successfully.")
                return True
    err("Could not install certbot automatically.")
    info("Install it manually:  sudo apt install certbot  or  sudo yum install certbot")
    return False


def setup_letsencrypt(tls_dir, domain, email=None, webroot=None, port=80):
    """Obtain a Let's Encrypt certificate via certbot."""
    if not _certbot_install():
        return None, None

    os.makedirs(tls_dir, exist_ok=True)
    certbot = shutil.which("certbot")

    cmd = [certbot, "certonly", "--non-interactive", "--agree-tos"]
    if email:
        cmd += ["--email", email]
    else:
        cmd += ["--register-unsafely-without-email"]

    if webroot:
        cmd += ["--webroot", "--webroot-path", webroot, "-d", domain]
    else:
        cmd += ["--standalone", "--http-01-port", str(port), "-d", domain]

    info(f"Running: {' '.join(cmd)}")
    r = subprocess.run(cmd)
    if r.returncode != 0:
        err("certbot failed.  Check the output above.")
        return None, None

    # Symlink into tls_dir
    le_dir = f"/etc/letsencrypt/live/{domain}"
    cert = os.path.join(le_dir, "fullchain.pem")
    key  = os.path.join(le_dir, "privkey.pem")
    if os.path.exists(cert) and os.path.exists(key):
        ok(f"Certificate: {cert}")
        ok(f"Private key: {key}")
        return cert, key
    err(f"Could not find certificate files under {le_dir}.")
    return None, None


def setup_renew_crontab(domain):
    """Add a crontab entry to auto-renew Let's Encrypt certs."""
    line = f"0 3 * * 1 certbot renew --quiet --post-hook 'pkill -HUP ophion || true'"
    _add_crontab_line(line, "letsencrypt-renew")
    ok("Weekly Let's Encrypt renewal cron job installed.")


# ---------------------------------------------------------------------------
# Keep-alive crontab
# ---------------------------------------------------------------------------

def setup_keepalive_crontab(conf_path, run_as="daemon"):
    """Add a crontab entry that restarts ophion if it is not running."""
    binary = shutil.which("ophion") or "/usr/local/bin/ophion"
    logfile = "/usr/local/logs/ircd-out.log"
    line = (
        f"* * * * * pgrep -x ophion > /dev/null || "
        f"su -s /bin/sh {run_as} -c "
        f"'nohup {binary} -foreground -configfile {conf_path} "
        f">> {logfile} 2>&1 &'"
    )
    _add_crontab_line(line, "ophion-keepalive")
    ok("Ophion keep-alive cron job installed (checks every minute).")
    info("The server will be restarted automatically if it stops.")


def _add_crontab_line(line, tag):
    """Add a line to root's crontab if not already present."""
    r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    existing = r.stdout if r.returncode == 0 else ""
    if line in existing or f"ophion-{tag}" in existing:
        info("Crontab entry already present — skipping.")
        return
    new_cron = existing.rstrip() + f"\n# ophion-{tag}\n{line}\n"
    subprocess.run(["crontab", "-"], input=new_cron, text=True)


# ---------------------------------------------------------------------------
# Config parser
# ---------------------------------------------------------------------------

class IrcdConf:
    def __init__(self, path):
        self.path = path
        if os.path.exists(path):
            with open(path) as f:
                self.text = f.read()
        else:
            self.text = ""

    def _get_block(self, block_type, name=None):
        if name:
            pat = re.compile(
                rf'{block_type}\s+"?{re.escape(name)}"?\s*\{{([^}}]*)\}}',
                re.DOTALL | re.IGNORECASE
            )
        else:
            pat = re.compile(
                rf'{block_type}\s*\{{([^}}]*)\}}',
                re.DOTALL | re.IGNORECASE
            )
        m = pat.search(self.text)
        return m.group(0) if m else None

    def _upsert_key_in_block(self, block, key, value):
        pat = re.compile(rf'(\s*{re.escape(key)}\s*=\s*)[^;]*;', re.IGNORECASE)
        if pat.search(block):
            return pat.sub(rf'\g<1>{value};', block)
        return block.rstrip().rstrip('}').rstrip() + f'\n\t{key} = {value};\n}}'

    # ---- serverinfo -------------------------------------------------------

    def upsert_serverinfo(self, name=None, description=None,
                          network_name=None, nicklen=None,
                          default_max_clients=None):
        block = self._get_block("serverinfo")
        if not block:
            block = 'serverinfo {\n};\n'
            self.text += '\n' + block
        new = block
        if name:           new = self._upsert_key_in_block(new, 'name',     f'"{name}"')
        if description:    new = self._upsert_key_in_block(new, 'description', f'"{description}"')
        if network_name:   new = self._upsert_key_in_block(new, 'network_name', f'"{network_name}"')
        if nicklen:        new = self._upsert_key_in_block(new, 'nicklen',   str(nicklen))
        if default_max_clients:
            new = self._upsert_key_in_block(new, 'default_max_clients', str(default_max_clients))
        self.text = self.text.replace(block, new, 1)

    def upsert_serverinfo_tls(self, cert_path, key_path):
        block = self._get_block("serverinfo")
        if not block:
            return
        new = self._upsert_key_in_block(block, 'ssl_cert', f'"{cert_path}"')
        new = self._upsert_key_in_block(new,   'ssl_private_key', f'"{key_path}"')
        new = self._upsert_key_in_block(new,   'ssl_dh_params',   f'"{os.path.dirname(cert_path)}/dh4096.pem"')
        self.text = self.text.replace(block, new, 1)

    # ---- listen -----------------------------------------------------------

    def upsert_listen(self, port, tls=False):
        if re.search(rf'port\s*=\s*{port}\s*;', self.text):
            return
        tls_line = '\n\tssl = yes;' if tls else ''
        self.text += f'\nlisten {{\n\tport = {port};{tls_line}\n}};\n'

    # ---- classes + auth ---------------------------------------------------

    def upsert_class(self, name, ping_time="5 minutes",
                     max_number=4096, sendq="1 megabyte", number_per_ip=10):
        if self._get_block("class", name):
            return
        self.text += (
            f'\nclass "{name}" {{\n'
            f'\tping_time = {ping_time};\n'
            f'\tnumber_per_ip = {number_per_ip};\n'
            f'\tmax_number = {max_number};\n'
            f'\tsendq = {sendq};\n'
            f'}};\n'
        )

    def upsert_auth(self):
        if re.search(r'auth\s*\{', self.text, re.IGNORECASE):
            return
        self.text += (
            '\nauth {\n'
            '\tuser = "*@*";\n'
            '\tclass = "users";\n'
            '\tflags = exceed_limit, no_tilde;\n'
            '};\n'
        )

    # ---- general ----------------------------------------------------------

    def upsert_general_key(self, key, value):
        block = self._get_block("general")
        if not block:
            block = 'general {\n};\n'
            self.text += '\n' + block
        new = self._upsert_key_in_block(block, key, value)
        self.text = self.text.replace(block, new, 1)

    # ---- operators --------------------------------------------------------

    def list_operators(self):
        return re.findall(r'operator\s+"([^"]+)"', self.text, re.IGNORECASE)

    def add_operator(self, name, password_or_hash, user_mask,
                     privset, cls="opers", is_encrypted=True,
                     certfp=None):
        self.remove_operator(name)
        pw_line = (f'\tpassword = "{password_or_hash}";\n'
                   if not certfp else
                   f'\tpassword = "{password_or_hash}";\n'
                   f'\tcertfp = "{certfp}";\n')
        enc_comment = "" if is_encrypted else "\t/* password is stored in plaintext */\n"
        self.text += (
            f'\n/* {name} — added {datetime.date.today()} */\n'
            f'operator "{name}" {{\n'
            f'\tuser = "{user_mask}";\n'
            f'{enc_comment}'
            f'{pw_line}'
            f'\tprivset = "{privset}";\n'
            f'\tclass = "{cls}";\n'
            f'}};\n'
        )

    def remove_operator(self, name):
        self.text = re.sub(
            rf'(?:/\*[^*]*\*/\s*)?operator\s+"{re.escape(name)}"\s*\{{[^}}]*\}};?\s*',
            '', self.text, flags=re.DOTALL | re.IGNORECASE
        )

    def list_privsets(self):
        return re.findall(r'privset\s+"([^"]+)"', self.text, re.IGNORECASE)

    def add_privset(self, name, privs):
        self.remove_privset(name)
        self.text += f'\nprivset "{name}" {{\n\tprivs = {privs};\n}};\n'

    def remove_privset(self, name):
        self.text = re.sub(
            rf'privset\s+"{re.escape(name)}"\s*\{{[^}}]*\}};?\s*',
            '', self.text, flags=re.DOTALL | re.IGNORECASE
        )

    # ---- server links -----------------------------------------------------

    def list_servers(self):
        return re.findall(r'connect\s+"([^"]+)"', self.text, re.IGNORECASE)

    def add_server(self, name, host, send_password, accept_password,
                   port=6667, hub_mask="*", cls="server",
                   flags="encrypted, topicburst",
                   certfp=None,
                   send_is_plain=False, accept_is_plain=False):
        self.remove_server(name)
        certfp_line = f'\tcertfp = "{certfp}";\n' if certfp else ""
        plain_note  = (
            "\t/* WARNING: plaintext password — only for trusted internal links */\n"
            if send_is_plain or accept_is_plain else ""
        )
        self.text += (
            f'\n/* Server link: {name} — added {datetime.date.today()} */\n'
            f'connect "{name}" {{\n'
            f'\thost = "{host}";\n'
            f'{plain_note}'
            f'\tsend_password = "{send_password}";\n'
            f'\taccept_password = "{accept_password}";\n'
            f'{certfp_line}'
            f'\tport = {port};\n'
            f'\thub_mask = "{hub_mask}";\n'
            f'\tclass = "{cls}";\n'
            f'\tflags = {flags};\n'
            f'}};\n'
        )

    def remove_server(self, name):
        self.text = re.sub(
            rf'(?:/\*[^*]*\*/\s*)?connect\s+"{re.escape(name)}"\s*\{{[^}}]*\}};?\s*',
            '', self.text, flags=re.DOTALL | re.IGNORECASE
        )

    # ---- persistence ------------------------------------------------------

    def save(self, backup=True):
        if backup and os.path.exists(self.path):
            bak = self.path + ".bak." + datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            shutil.copy2(self.path, bak)
            ok(f"Backup written to {bak}")
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w") as f:
            f.write(self.text)
        ok(f"Configuration saved to {self.path}")


# ---------------------------------------------------------------------------
# Setup menus
# ---------------------------------------------------------------------------

def menu_serverinfo(conf, mode):
    section("Server Information")
    info("Server name: dotted (irc.example.net) or short dotless (ircxserver01).")

    cur_block = conf._get_block("serverinfo") or ""
    cur_name  = (re.search(r'name\s*=\s*"([^"]+)"', cur_block) or type('', (), {'group': lambda s,n: 'irc.example.net'})()).group(1)
    name = prompt("Server name", default=cur_name)
    desc = net = nicklen = max_clients = None
    if mode in ("intermediate", "advanced"):
        desc = prompt("Description", default="Ophion IRC Server")
        net  = prompt("Network name", default="IRCXNet")
    if mode == "advanced":
        nicklen     = prompt_int("Max nick length", default=30, min_val=9, max_val=32)
        max_clients = prompt_int("Max clients", default=4096, min_val=1)
    conf.upsert_serverinfo(name=name, description=desc, network_name=net,
                           nicklen=nicklen, default_max_clients=max_clients)
    ok(f"Server name: '{name}'")


def menu_listen(conf, mode):
    section("Listen Port(s)")
    port = prompt_int("Plain IRC port", default=6667, min_val=1, max_val=65535)
    conf.upsert_listen(port, tls=False)
    ok(f"Plain port {port} added")
    if mode != "simple":
        if prompt_yn("Add a TLS/SSL port?", default="no"):
            tls_port = prompt_int("TLS port", default=6697, min_val=1, max_val=65535)
            conf.upsert_listen(tls_port, tls=True)
            ok(f"TLS port {tls_port} added")


def menu_classes_auth(conf, _mode):
    section("Client Classes & Auth")
    conf.upsert_class("users", max_number=4096)
    conf.upsert_class("opers", max_number=10, sendq="1 megabyte", number_per_ip=10)
    conf.upsert_class("server", max_number=10, sendq="2 megabytes", number_per_ip=10)
    conf.upsert_auth()
    ok("Default classes (users/opers/server) and wildcard auth added")


def menu_general(conf, mode):
    section("General Settings")
    conf.upsert_general_key("no_oper_flood", "yes")

    if mode == "simple":
        conf.upsert_general_key("disable_auth", "yes")
        ok("Basic general settings applied")
        return

    conf.upsert_general_key(
        "disable_auth",
        "yes" if prompt_yn("Disable ident auth?", "yes") else "no"
    )

    if mode in ("intermediate", "advanced"):
        subsection("Client Flood Limits")
        conf.upsert_general_key("client_flood_burst_max",
            str(prompt_int("client_flood_burst_max", default=5, min_val=1)))
        conf.upsert_general_key("client_flood_burst_rate",
            str(prompt_int("client_flood_burst_rate", default=40, min_val=1)))

        subsection("KICK / MODE / PROP Flood Controls")
        info("Set count to 0 to disable.  Opers with oper:god or no_oper_flood are exempt.")
        for op in ("kick", "mode", "prop"):
            count = prompt_int(f"{op}_flood_count (0=off)", default=0, min_val=0)
            conf.upsert_general_key(f"{op}_flood_count", str(count))
            if count > 0:
                conf.upsert_general_key(f"{op}_flood_time",
                    str(prompt_int(f"{op}_flood_time (seconds)", default=10, min_val=1)))

    if mode == "advanced":
        subsection("MODE Parameters")
        conf.upsert_general_key("max_mode_params",
            str(prompt_int("max_mode_params", default=6, min_val=1, max_val=32)))
        conf.upsert_general_key("mode_broadcast_params",
            str(prompt_int("mode_broadcast_params (0=grouped)", default=0, min_val=0)))

    ok("General settings saved")


# ---------------------------------------------------------------------------
# SSL/TLS menu
# ---------------------------------------------------------------------------

def menu_tls(conf, mode):
    section("SSL / TLS Configuration")

    block = conf._get_block("serverinfo") or ""
    cur_name = (re.search(r'name\s*=\s*"([^"]+)"', block) or
                type('', (), {'group': lambda s, n: ''})()).group(1)

    print("  1) Use a self-signed certificate (easy, no domain required)")
    print("  2) Use Let's Encrypt (requires a public domain + port 80 access)")
    print("  3) Use existing certificate files (enter paths manually)")
    print("  0) Skip TLS setup")
    choice = prompt("Choice", default="0", choices=["0","1","2","3"])

    if choice == "0":
        return

    tls_dir = prompt("Directory to store TLS files", default=DEFAULT_TLS_DIR)

    if choice == "1":
        name = cur_name or prompt("Server name for the certificate")
        cert, key = setup_selfsigned(tls_dir, name)
        _gen_dh(tls_dir)

    elif choice == "2":
        domain = cur_name or prompt("Domain name (must have DNS pointing here)")
        email  = prompt("Email address for Let's Encrypt (or press Enter to skip)", default="")
        email  = email if email else None

        webroot = None
        if prompt_yn("Use webroot mode (if a web server is running on port 80)?", default="no"):
            webroot = prompt("Webroot path", default="/var/www/html")
        else:
            p80 = prompt_int("Standalone HTTP port", default=80, min_val=1)
            webroot = None

        cert, key = setup_letsencrypt(tls_dir, domain, email=email,
                                      webroot=webroot, port=p80 if not webroot else 80)
        if cert and key:
            if prompt_yn("Install weekly auto-renewal cron job?", default="yes"):
                setup_renew_crontab(domain)
        _gen_dh(tls_dir)

    elif choice == "3":
        cert = prompt("Path to certificate file (PEM)")
        key  = prompt("Path to private key file (PEM)")

    if choice in ("1","2","3") and cert and key:
        conf.upsert_serverinfo_tls(cert, key)
        ok(f"TLS configured: cert={cert}  key={key}")
        info("Add ssl=yes; to your listen{} blocks to enable TLS on a port.")


def _gen_dh(tls_dir):
    """Generate DH parameters if openssl is available."""
    openssl = shutil.which("openssl")
    if not openssl:
        return
    dh_path = os.path.join(tls_dir, "dh4096.pem")
    if os.path.exists(dh_path):
        return
    info("Generating DH parameters (4096-bit, this may take a minute)…")
    r = subprocess.run([openssl, "dhparam", "-out", dh_path, "4096"],
                       capture_output=True)
    if r.returncode == 0:
        ok(f"DH params: {dh_path}")


# ---------------------------------------------------------------------------
# Operators menu
# ---------------------------------------------------------------------------

def menu_operators(conf):
    while True:
        section("Operators / Admins")
        ops = conf.list_operators()
        print(f"  Defined: {', '.join(ops) if ops else 'none'}")
        print()
        print("  1) Add / update operator")
        print("  2) Remove operator")
        print("  3) List operators")
        print("  4) Manage privsets")
        print("  0) Back")

        choice = prompt("Choice", default="0", choices=["0","1","2","3","4"])
        if choice == "0":
            break

        elif choice == "1":
            subsection("Add / Update Operator")
            name      = prompt("Operator nick")
            user_mask = prompt("User mask", default="*@*")

            # Password
            pw, is_enc = get_password("Operator password", allow_plain=True)

            # certfp
            certfp = None
            if prompt_yn("Also authenticate with a TLS certificate fingerprint (certfp)?",
                         default="no"):
                certfp_input = prompt("Certificate SHA-512 fingerprint (hex, no colons), or path to cert file")
                if os.path.exists(certfp_input):
                    certfp = get_cert_fingerprint(certfp_input)
                    if certfp:
                        ok(f"Fingerprint: {certfp[:20]}...")
                    else:
                        certfp = certfp_input
                else:
                    certfp = certfp_input.replace(":", "").lower()

            # Privset
            print()
            print("  Privset presets:")
            for k in PRIVSET_PRESETS:
                print(f"    {k}")
            existing = conf.list_privsets()
            if existing:
                print(f"  Existing privsets: {', '.join(existing)}")

            ps_choice = prompt("Privset", default="standard",
                               choices=list(PRIVSET_PRESETS.keys()) + ["custom"] +
                                       (["existing"] if existing else []))

            if ps_choice == "custom":
                privs = prompt("Enter privs (comma-separated)")
                privset_name = prompt("Privset name", default=f"{name}privs")
                conf.add_privset(privset_name, privs)
            elif ps_choice == "existing":
                privset_name = prompt("Which privset?", choices=existing)
            else:
                privset_name = f"{name}privs"
                conf.add_privset(privset_name, PRIVSET_PRESETS[ps_choice])

            conf.add_operator(name, pw, user_mask, privset_name,
                              is_encrypted=is_enc, certfp=certfp)
            ok(f"Operator '{name}' saved with privset '{privset_name}'")

        elif choice == "2":
            ops = conf.list_operators()
            if not ops:
                info("No operators to remove."); continue
            name = prompt("Operator to remove", choices=ops)
            if prompt_yn(f"Remove '{name}'?", default="no"):
                conf.remove_operator(name)
                ok(f"Removed '{name}'")

        elif choice == "3":
            ops = conf.list_operators()
            for o in ops:
                print(f"    • {o}")
            if not ops:
                info("None defined.")

        elif choice == "4":
            menu_privsets(conf)


def menu_privsets(conf):
    while True:
        subsection("Privsets")
        pvs = conf.list_privsets()
        print(f"  Defined: {', '.join(pvs) if pvs else 'none'}")
        print()
        print("  1) Add / update privset")
        print("  2) Remove privset")
        print("  0) Back")
        choice = prompt("Choice", default="0", choices=["0","1","2"])
        if choice == "0": break
        elif choice == "1":
            name = prompt("Privset name")
            print()
            print("  Available privileges:")
            print("  oper:general  oper:global_kill  oper:local_kill  oper:kline")
            print("  oper:unkline  oper:rehash  oper:admin  oper:die  oper:spy")
            print("  oper:operwall oper:remoteban  oper:privs  oper:god  oper:xline")
            print("  auspex:oper   auspex:hostname   usermode:servnotice")
            privs = prompt("Privs (comma-separated)")
            conf.add_privset(name, privs)
            ok(f"Privset '{name}' saved")
        elif choice == "2":
            pvs = conf.list_privsets()
            if not pvs:
                info("None defined."); continue
            name = prompt("Privset to remove", choices=pvs)
            if prompt_yn(f"Remove '{name}'?", default="no"):
                conf.remove_privset(name)
                ok(f"Removed '{name}'")


# ---------------------------------------------------------------------------
# Server links menu
# ---------------------------------------------------------------------------

def menu_servers(conf):
    while True:
        section("Server Links (connect blocks)")
        servers = conf.list_servers()
        print(f"  Defined: {', '.join(servers) if servers else 'none'}")
        print()
        print("  1) Add server link")
        print("  2) Remove server link")
        print("  3) List server links")
        print("  0) Back")

        choice = prompt("Choice", default="0", choices=["0","1","2","3"])
        if choice == "0": break

        elif choice == "1":
            subsection("Add Server Link")
            info("Both servers must have matching connect{} blocks pointing at each other.")
            name = prompt("Remote server name (e.g. hub.example.net or ircxleaf01)")
            host = prompt("Remote host / IP")
            port = prompt_int("Port", default=6667, min_val=1, max_val=65535)

            # Authentication method
            print()
            print("  Authentication method:")
            print("  1) Encrypted password (SHA-512 hash — recommended)")
            print("  2) Plaintext password (use only on trusted LANs)")
            print("  3) Certificate fingerprint (certfp) only")
            print("  4) Certificate fingerprint + password")
            auth_choice = prompt("Auth method", default="1", choices=["1","2","3","4"])

            certfp = None
            send_plain = accept_plain = False

            if auth_choice in ("1","2"):
                send_pass, _ = get_password("Password WE send to them",
                                            allow_plain=(auth_choice=="2"))
                accept_raw, accept_enc = get_password("Password THEY send to us",
                                                       allow_plain=(auth_choice=="2"))
                accept_pass = accept_raw
                accept_plain = not accept_enc
                send_plain   = (auth_choice == "2")

            elif auth_choice == "3":
                certfp_input = prompt("Their certificate fingerprint (hex) or path to their cert")
                if os.path.exists(certfp_input):
                    certfp = get_cert_fingerprint(certfp_input)
                else:
                    certfp = certfp_input.replace(":", "").lower()
                send_pass = accept_pass = "*"   # dummy; certfp takes precedence

            elif auth_choice == "4":
                send_pass, _  = get_password("Password WE send", allow_plain=False)
                accept_pass, accept_enc = get_password("Password THEY send", allow_plain=False)
                accept_plain = not accept_enc
                certfp_input = prompt("Their certificate fingerprint (hex) or cert path")
                if os.path.exists(certfp_input):
                    certfp = get_cert_fingerprint(certfp_input)
                else:
                    certfp = certfp_input.replace(":", "").lower()

            hub_mask = prompt("Hub mask", default="*")
            flags    = prompt("Flags", default="encrypted, topicburst")

            conf.upsert_class("server", max_number=10, sendq="2 megabytes", number_per_ip=10)
            conf.add_server(
                name=name, host=host,
                send_password=send_pass,
                accept_password=accept_pass,
                port=port, hub_mask=hub_mask, flags=flags,
                certfp=certfp,
                send_is_plain=send_plain,
                accept_is_plain=accept_plain,
            )
            ok(f"Server link '{name}' added")
            if certfp:
                info(f"certfp: {certfp[:32]}...")
                info("Make sure you have the correct certificate installed.")

        elif choice == "2":
            servers = conf.list_servers()
            if not servers:
                info("None to remove."); continue
            name = prompt("Server to remove", choices=servers)
            if prompt_yn(f"Remove '{name}'?", default="no"):
                conf.remove_server(name)
                ok(f"Removed '{name}'")

        elif choice == "3":
            for s in conf.list_servers():
                print(f"    • {s}")
            if not conf.list_servers():
                info("None defined.")


# ---------------------------------------------------------------------------
# Keep-alive menu
# ---------------------------------------------------------------------------

def menu_keepalive(conf):
    section("Keep-Alive (Crontab)")
    info("Install a crontab entry that restarts Ophion if it crashes.")
    run_as = prompt("Run server as user", default="daemon")
    setup_keepalive_crontab(conf.path, run_as=run_as)


# ---------------------------------------------------------------------------
# Top-level management menu (existing config)
# ---------------------------------------------------------------------------

def menu_main(conf):
    while True:
        section("Ophion IRC — Configuration Manager")
        print(f"  Config: {_bold(conf.path)}")
        ops     = conf.list_operators()
        servers = conf.list_servers()
        print(f"  Operators: {len(ops)} ({', '.join(ops) or 'none'})")
        print(f"  Servers:   {len(servers)} ({', '.join(servers) or 'none'})")
        print()
        print("  1) Edit server info (name, description, network)")
        print("  2) Edit listen ports")
        print("  3) Edit flood & general limits")
        print("  4) Manage operators / admins")
        print("  5) Manage server links")
        print("  6) SSL / TLS setup (self-signed or Let's Encrypt)")
        print("  7) Install keep-alive crontab")
        print("  8) Save & exit")
        print("  0) Exit without saving")

        choice = prompt("Choice", default="8",
                        choices=["0","1","2","3","4","5","6","7","8"])
        if choice == "0":
            if prompt_yn("Exit WITHOUT saving?", default="no"):
                sys.exit(0)
        elif choice == "1": menu_serverinfo(conf, "advanced")
        elif choice == "2": menu_listen(conf, "advanced")
        elif choice == "3": menu_general(conf, "advanced")
        elif choice == "4": menu_operators(conf)
        elif choice == "5": menu_servers(conf)
        elif choice == "6": menu_tls(conf, "advanced")
        elif choice == "7": menu_keepalive(conf)
        elif choice == "8":
            conf.save()
            break


# ---------------------------------------------------------------------------
# First-time wizard
# ---------------------------------------------------------------------------

def wizard_new(conf, mode):
    print()
    print(_bold("═" * 62))
    print(_bold("  Ophion IRC Server — First-Time Setup Wizard"))
    print(_bold(f"  Mode: {mode.upper()}"))
    print(_bold("═" * 62))

    menu_serverinfo(conf, mode)
    menu_listen(conf, mode)
    menu_classes_auth(conf, mode)
    menu_general(conf, mode)

    if mode != "simple":
        section("SSL / TLS")
        if prompt_yn("Set up TLS/SSL now?", default="no"):
            menu_tls(conf, mode)

    section("IRC Operator Account")
    if prompt_yn("Add an IRC operator account now?", default="yes"):
        menu_operators(conf)

    if mode != "simple":
        section("Server Links")
        if prompt_yn("Add a server link (connect block)?", default="no"):
            menu_servers(conf)

    section("Keep-Alive")
    if prompt_yn("Install a crontab to auto-restart the server if it stops?",
                 default="no"):
        menu_keepalive(conf)

    section("Save Configuration")
    conf.save()

    print()
    print(_bold("Setup complete!"))
    print(f"  Start the server:  ophion -configfile {conf.path}")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Ophion IRC server setup / configuration manager"
    )
    parser.add_argument("--config", "-c", default=DEFAULT_CONF,
                        help=f"Path to ircd.conf (default: {DEFAULT_CONF})")
    parser.add_argument("--mode", "-m",
                        choices=["simple", "intermediate", "advanced"], default=None,
                        help="Wizard mode")
    parser.add_argument("--manage", action="store_true",
                        help="Open management menu for an existing config")
    args = parser.parse_args()

    conf = IrcdConf(args.config)

    if args.manage or (os.path.exists(args.config) and not args.mode):
        menu_main(conf)
        return

    if args.mode:
        mode = args.mode
    else:
        print()
        print(_bold("No existing configuration found.  Running first-time setup wizard."))
        print()
        print("  simple       — just the essentials to get the server running")
        print("  intermediate — common settings (flood controls, TLS, etc.)")
        print("  advanced     — full control over every option")
        mode = prompt("Setup mode", default="simple",
                      choices=["simple", "intermediate", "advanced"])

    wizard_new(conf, mode)


if __name__ == "__main__":
    main()
