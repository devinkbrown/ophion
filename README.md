# Ophion

Ophion is an IRC server for communities and teams, forked from
charybdis and extended with:

 * comprehensive IRCv3 support (see below),
 * the patent-unencumbered parts of the IRCX protocol
   (draft-pfenning-irc-extensions-04),
 * automatic SID generation and SVSSID collision negotiation for
   zero-config server linking,
 * reverse-DNS toggle (`rdns_lookups = yes|no`) for fast deployments,
 * websocket transport support,
 * per-operation flood controls (KICK, MODE, PROP) with per-channel
   overrides via channel PROP keys, and oper/god-mode bypass,
 * dotless server names (`ircxserver01`, `leaf01`, etc.),
 * built-in permanently-reserved names (system, server, services, …),
 * automatic nick force-rename when a server link name collides with
   an existing user nickname, and
 * an interactive setup and configuration manager (`tools/setup.py`).

## IRCv3 Support

Ophion implements a broad set of IRCv3 capabilities. Capabilities marked
with (module) are provided by loadable modules and can be enabled or
disabled independently.

### Client Capabilities

| Capability | Module | Description |
|------------|--------|-------------|
| `account-notify` | core | Notifies clients when a user's account changes |
| `account-tag` | cap_account_tag | Adds account name as a message tag |
| `away-notify` | core | Notifies clients when a user goes/returns from away |
| `batch` | core | Groups related messages together |
| `cap-notify` | core | Notifies clients of capability changes |
| `chghost` | core | Notifies clients of hostname/username changes |
| `echo-message` | core | Echoes sent messages back to the sender |
| `extended-join` | core | Includes account and realname in JOIN messages |
| `invite-notify` | core | Notifies channel members when someone is invited |
| `labeled-response` | core | Associates responses with the command that caused them |
| `message-tags` | cap_message_tags | Enables message tags and the TAGMSG command |
| `msgid` | m_chathistory | Unique message identifiers on PRIVMSG/NOTICE |
| `multi-prefix` | core | Shows all prefix modes in NAMES and WHO |
| `sasl` | m_sasl_core | SASL authentication |
| `server-time` | cap_server_time | Adds server timestamp to messages |
| `setname` | core | Allows clients to change their realname |
| `standard-replies` | core | Standardised error/warning/note replies |
| `sts` | cap_sts | Strict Transport Security |
| `tls` | m_starttls | STARTTLS for connection encryption |
| `userhost-in-names` | core | Includes full user@host in NAMES replies |
| `draft/chathistory` | m_chathistory | Message history retrieval |
| `draft/event-playback` | m_chathistory | Event playback within history batches |
| `draft/multiline` | m_multiline | Multi-line message batches |
| `draft/read-marker` | m_read_marker | Read position synchronisation across sessions |
| `draft/typing` | core | Typing indicator notifications |

### IRCv3 Commands

| Command | Module | Description |
|---------|--------|-------------|
| `TAGMSG` | cap_message_tags | Send a message with tags but no text body |
| `SETNAME` | m_setname | Change your realname (GECOS) |
| `CHATHISTORY` | m_chathistory | Retrieve message history for a target |
| `MARKREAD` | m_read_marker | Get/set the read-marker position for a target |

### CHATHISTORY Subcommands

The `CHATHISTORY` command (requires `draft/chathistory` capability)
supports the following subcommands:

- `LATEST <target> * <limit>` -- most recent messages
- `LATEST <target> timestamp=<ts> <limit>` -- messages since a timestamp
- `BEFORE <target> timestamp=<ts> <limit>` -- messages before a timestamp
- `AFTER <target> timestamp=<ts> <limit>` -- messages after a timestamp
- `AROUND <target> timestamp=<ts> <limit>` -- messages around a timestamp
- `BETWEEN <target> timestamp=<ts1> timestamp=<ts2> <limit>` -- messages between two timestamps
- `TARGETS timestamp=<ts1> timestamp=<ts2> <limit>` -- list targets with recent history

Messages are delivered inside a `batch` of type `chathistory`. The server
advertises `CHATHISTORY=100` and `MSGREFTYPES=timestamp` in ISUPPORT.

### MARKREAD Command

The `MARKREAD` command (requires `draft/read-marker` capability) synchronises
the last-read position of a channel or DM across multiple sessions.

- `MARKREAD <target>` -- query the stored read marker
- `MARKREAD <target> timestamp=<ts>` -- update the read marker

Timestamps are monotonically increasing; stale updates are silently ignored
and the server replies with the newer stored value. On channel JOIN, the
server automatically sends a MARKREAD for the channel. Markers are stored
in-memory per-connection and cleared on disconnect.

### Multiline Messages (draft/multiline)

The `draft/multiline` capability (module m_multiline) allows clients to send
messages spanning multiple protocol lines, grouped inside a BATCH:

```
BATCH +ref draft/multiline <target>
@batch=ref PRIVMSG <target> :line 1
@batch=ref PRIVMSG <target> :line 2
@batch=ref;draft/multiline-concat PRIVMSG <target> :continued
BATCH -ref
```

- Lines with the `draft/multiline-concat` tag are appended to the previous
  line without a line break.
- Multiline-capable recipients receive the full BATCH; non-multiline
  clients receive merged fallback lines.
- Limits: `max-bytes=40000`, `max-lines=100` (advertised in the capability
  value).
- Supports both PRIVMSG and NOTICE (but not mixed within a single batch).
- Echo-message is fully supported for both multiline and fallback paths.

### ISUPPORT Tokens

The following ISUPPORT tokens are added by IRCv3 modules:

| Token | Value | Description |
|-------|-------|-------------|
| `CHATHISTORY` | `100` | Maximum messages per history request |
| `MSGREFTYPES` | `timestamp` | Supported message reference types |

## Oper Authentication

IRC operator authentication uses SASL, not the traditional OPER command.
Operators authenticate **during connection registration** (before the 001
Welcome) and receive oper status automatically.  The OPER command is a stub
that prints a notice directing users to SASL.

### Methods

| Method | Command | When to use |
|--------|---------|-------------|
| SASL PLAIN | `AUTHENTICATE PLAIN` | Password-based (any modern client) |
| SASL EXTERNAL | `AUTHENTICATE EXTERNAL` | TLS certificate fingerprint only |
| IRCX AUTH (shorthand) | `AUTH PLAIN I :…` / `AUTH EXTERNAL I` | Single-command alternative; no `CAP REQ :sasl` needed |

### SASL PLAIN (password)

```
CAP REQ :sasl
AUTHENTICATE PLAIN
AUTHENTICATE <base64(\0<blockname>\0<password>)>
```

Most clients (WeeChat, HexChat, irssi, ZNC) configure this natively via
their SASL settings.  Use the oper block name as the username.

### SASL EXTERNAL (certificate)

Requires a TLS connection with a client certificate.  The oper block must
have `certfp_only = yes` and a matching `fingerprint =` line.

```
AUTHENTICATE EXTERNAL
AUTHENTICATE =          # "=" triggers auto-discovery
```

### ircd.conf quick-start

```
# Password-based oper
operator "godoper" {
    user = "*@127.0.0.1";
    password = "$6$...mkpasswd -m sha512 output...";
    flags = encrypted;
    snomask = "+Zbfkrsuy";
    privset = "admin";
};

# Certificate-only oper (no password; any host)
operator "certoper" {
    fingerprint = "cert_sha256:deadbeef...64hexchars...";
    flags = certfp_only;
    snomask = "+Zbfkrsuy";
    privset = "admin";
};
```

Get your certificate fingerprint:

```sh
openssl x509 -in client.crt -noout -sha256 -fingerprint \
  | tr -d ':' | tr 'A-Z' 'a-z' \
  | sed 's/.*=//; s/^/cert_sha256:/'
```

See `doc/features/sasl.txt` for the full protocol reference and
`doc/reference.conf` for all operator block options.

## IRCX Protocol Support

Ophion implements channel modes, user modes, and commands from the IRCX
specification (draft-pfenning-irc-extensions-04). All IRCX features are
provided as loadable modules and can be enabled/disabled independently.

### IRCX Pre-registration Probe (ISIRCX)

Per §3 of the IRCX draft, a client may probe for IRCX support before
completing registration by sending:

```
MODE <nick> ISIRCX
```

or the shorter form `MODE ISIRCX`.  Ophion responds with `800 RPL_IRCX`
to confirm support.  All other `MODE` usage before registration still
returns `451 ERR_NOTREGISTERED`.

### IRCX Channel-context Nick Targeting (PRIVMSG)

Ophion supports IRCX-style targeted channel messages:

```
PRIVMSG #channel nick1 nick2 :message text
```

Each named nick must be a member of the channel; non-members receive
`441 ERR_USERNOTINCHANNEL`.  The message is delivered privately to each
target with the channel name as context, letting clients display it in
the channel window.

### IRCX Channel Modes

| Mode | Name | IRCX Spec | Description |
|------|------|-----------|-------------|
| `+a` | AUTHONLY | 8.1.15 | Only authenticated (services-identified) users may join |
| `+d` | CLONEABLE | 8.1.16 | Channel creates numbered clones when full |
| `+E` | CLONE | 8.1.17 | Marks channel as a clone of a CLONEABLE channel (IRCX `+e` remapped to avoid ban exception conflict); when a new clone is created the server broadcasts `CLONE #parent #clone` to all members of the parent channel |
| `+f` | NOFORMAT | 8.1.10 | Raw text only, clients should not apply formatting |
| `+h` | HIDDEN | 8.1.3 | Not in LIST/LISTX but queryable if channel name is known |
| `+u` | KNOCK | 8.1.9 | Enables KNOCK notifications to channel hosts/owners |
| `+w` | NOWHISPER | - | Disables the WHISPER command in the channel |
| `+x` | AUDITORIUM | 8.1.12 | Only operators visible; JOIN/PART/QUIT hidden for non-ops |
| `+z` | SERVICE | 8.1.14 | Indicates a service is monitoring the channel (oper-only) |

#### Channel Visibility Model

The IRCX draft defines four mutually exclusive visibility levels:

| Visibility | Mode | Description |
|------------|------|-------------|
| PUBLIC | (none) | Default. Visible in LIST, all data queryable. |
| PRIVATE | `+p` | Listed, but properties restricted to non-members. |
| HIDDEN | `+h` | Not in LIST, but queryable if channel name is known. |
| SECRET | `+s` | Not visible to non-members at all. |

When `+h` is set, `+p` and `+s` are automatically cleared. These modes
are mutually exclusive per the IRCX draft.

### IRCX User Modes

| Mode | Name | IRCX Spec | Description |
|------|------|-----------|-------------|
| `+z` | GAG | 7.2 | Silences user globally; all messages silently discarded. Oper-only set/unset. |

### IRCX Commands

| Command | Module | Description |
|---------|--------|-------------|
| `AUTH` | m_ircx_auth | IRCX authentication mechanism |
| `CREATE` | m_ircx_create | Create channel with initial modes (fails if channel exists) |
| `LISTX` | m_ircx_listx | Extended channel listing with properties and modes |
| `PROP` | m_ircx_prop | Get/set/list properties on channels, users, and accounts |
| `WHISPER` | m_ircx_whisper | Private message to a specific channel member |
| `ACCESS` | m_ircx_access | Channel access list management (OWNER/HOST/VOICE/DENY/GRANT); persists to services DB for registered channels |
| `EVENT` | m_ircx_event | Oper event subscription system (CHANNEL/MEMBER/USER/SERVER) |
| `GAG` | m_ircx_oper | Toggle or set GAG mode on a user (oper-only) |
| `OPFORCE` | m_ircx_oper | Unified oper channel force: JOIN/OP/KICK/MODE (oper+admin) |

### Property System (PROP)

The PROP command provides a key-value property system for channels and users.

#### PROP Verb Reference

| Form | Verb | Description |
|------|------|-------------|
| `PROP #chan` | list | List all properties (custom and built-in) — returns 818/819 |
| `PROP #chan key` | get | Read a single named property — returns 818/819 or **919** if absent |
| `PROP #chan key*` | list | Wildcard GET (returns all matching keys; empty result = 819 only) |
| `PROP #chan key :value` | set | Write a property value (chanop or higher required) |
| `PROP #chan key :` | delete | Delete a property by writing an empty value |

> **Note on `919 ERR_PROP_MISSING`:** Reading a specific, non-wildcard key that
> does not exist returns `919 ERR_PROP_MISSING` rather than an empty 819 end.
> Wildcard patterns and the delete form (`key :`) are exempt — an empty wildcard
> result is valid, and deleting a non-existent key is a harmless no-op.

The PROP command provides a key-value property system for channels and users.

**User profile properties** (m_ircx_prop_user_profile):
`URL`, `GENDER`, `PICTURE`, `LOCATION`, `BIO`, `REALNAME`, `EMAIL`

**Channel built-in properties** (m_ircx_prop_channel_builtins):

| Property | Access | Description |
|----------|--------|-------------|
| `OID` | read-only | Object ID (channel name) |
| `NAME` | read-only | Channel name |
| `CREATION` | read-only | Channel creation timestamp (Unix) |
| `TOPIC` | read-only | Mirrors the current channel topic |
| `MEMBERCOUNT` | read-only | Current member count |
| `MEMBERKEY` | chanop read/write | Mirrors `+k` channel key |
| `MEMBERLIMIT` | chanop read/write | Mirrors `+l` member limit; writing sets/clears `+l` |
| `PICS` | chanop read/write | Content-rating string (e.g. `"GA"`, `"PG"`, `"R"`) |
| `LAG` | chanop read/write | Per-channel fake-lag in seconds (integer 0–2); adds fake send delay for all channel messages |
| `CLIENT` | chanop-only read/write | Arbitrary channel metadata string; hidden from non-operators |

**Channel keys** (m_ircx_prop_ownerkey, m_ircx_prop_opkey):
`OWNERKEY`, `OPKEY` -- grant channel-admin (+q) or chanop (+o) on join

**Entity properties**: Account, channel, and user entity properties
via m_ircx_prop_entity_account, m_ircx_prop_entity_channel,
m_ircx_prop_entity_user.

**Microsoft Comic Chat** (m_ircx_comic):
`MCC` (character data), `MCCGUID` (character GUID), `MCCEX` (expression/gesture data).
Advertised via ISUPPORT `COMICCHAT`. Enables full Microsoft Chat/Comic Chat
character metadata support.

### IRCX Module List

All IRCX functionality is provided by loadable modules in `modules/`:

| Module | Description |
|--------|-------------|
| m_ircx_access | ACCESS command and channel access lists |
| m_ircx_auditorium | Auditorium mode (+x) |
| m_ircx_auth | AUTH command |
| m_ircx_base | IRCX base protocol negotiation |
| m_ircx_comic | Microsoft Comic Chat character metadata |
| m_ircx_create | CREATE command |
| m_ircx_event | EVENT command for oper monitoring |
| m_ircx_listx | LISTX extended channel listing |
| m_ircx_modes | Core IRCX channel modes (+u/+h/+a/+d/+E/+f/+z) |
| m_ircx_oper | GAG user mode (+z) and OPFORCE command |
| m_ircx_prop | PROP command core |
| m_ircx_prop_ownerkey | OWNERKEY channel property |
| m_ircx_prop_channel_builtins | OID/NAME/CREATION/TOPIC/MEMBERCOUNT/MEMBERKEY/MEMBERLIMIT/PICS/LAG/CLIENT properties |
| m_ircx_prop_entity_account | Account entity properties |
| m_ircx_prop_entity_channel | Channel entity properties |
| m_ircx_prop_entity_user | User entity properties |
| m_ircx_prop_member_of | MEMBER_OF channel property |
| m_ircx_prop_onjoin | ONJOIN channel property |
| m_ircx_prop_onpart | ONPART channel property |
| m_ircx_prop_opkey | OPKEY channel property |
| m_ircx_prop_user_profile | User profile properties |
| m_ircx_whisper | WHISPER command and +w mode |

## Flood Controls

Ophion provides per-operation rate limiting for KICK, MODE, and PROP SET
operations, in addition to the existing packet-level flood controls.

### Server-global limits (ircd.conf `general{}`)

```
kick_flood_count = 5;   /* max KICKs per window          */
kick_flood_time  = 15;  /* window size in seconds         */
mode_flood_count = 10;
mode_flood_time  = 30;
prop_flood_count = 10;
prop_flood_time  = 30;
```

Setting a count to `0` disables the corresponding limit.

### Per-channel overrides (PROP keys)

Channel operators can apply a _stricter_ (lower-rate) limit for their channel
by setting the `KICKFLOOD`, `MODEFLOOD`, or `PROPFLOOD` PROP key in `N/T`
format (N operations per T seconds):

```
PROP #chan SET KICKFLOOD 3/10
PROP #chan SET MODEFLOOD 5/60
```

The effective limit for any operation is the stricter of the server-global
and per-channel limits.

### Oper bypass

 * Clients with the `oper:god` privilege are always exempt.
 * General IRC operators are exempt when `no_oper_flood = yes` is set in
   `general{}`.

## Server Linking

Ophion supports TS6 server linking with automatic SID generation:

 * If no `sid =` is set in `serverinfo{}`, a SID is deterministically
   derived from the server name using FNV-1a (12,960 possible values).
 * The `AUTOSID` capability is advertised during the CAPAB exchange.
 * When a connecting server's auto-generated SID collides with one
   already on the network, the hub sends `SVSSID :<new_sid>` to assign
   an available SID before disconnecting.  The leaf adopts the new SID
   and reconnects automatically.
 * Explicit `sid = "XYZ";` in `serverinfo{}` always takes precedence.

### Dotless server names

Server names do not require a domain suffix.  Simple hostnames like
`ircxserver01` or `leaf02` are fully supported.  When a dotless name collides
with an existing user nickname, the user is automatically force-renamed and
notified; the link is not rejected.

Dotless names are checked against the RESV system (channel operator RESVs)
**and** a set of permanently built-in reserved names that can never be used
as a server name or user nickname:

| Reserved | Reserved | Reserved |
|----------|----------|----------|
| system   | server   | services |
| global   | localhost | ircd    |

### Minimal link configuration

```
/* hub */
class "servers" { ping_time = 30; max_number = 20; sendq = 2097152; };
connect "leaf.example.com" {
    host = "10.0.0.2";
    send_password = "linkpass";
    accept_password = "linkpass";
    port = 6667;
    class = "servers";
};

/* leaf */
connect "hub.example.com" {
    host = "10.0.0.1";
    send_password = "linkpass";
    accept_password = "linkpass";
    port = 6667;
    class = "servers";
};
```

### Configuration

 * `rdns_lookups = yes|no` in `general{}` — disable reverse DNS
   lookups for faster connections (defaults to `yes`).
 * Server names may be simple hostnames without dots (`leaf01`, `ircxserver01`).

## Configuration Tool

`tools/setup.py` is an interactive setup and configuration manager.
It edits `ircd.conf` without destroying comments or custom formatting,
and covers every day-to-day admin task without requiring manual config
file editing.

### Quick start

```sh
# First-time setup wizard
python3 tools/setup.py --config /usr/local/etc/ircd.conf

# Manage an existing configuration
python3 tools/setup.py --config /usr/local/etc/ircd.conf --manage
```

### Wizard modes

| Mode | Description |
|------|-------------|
| `simple` | Essential settings only (server name, admin, one port, one oper) |
| `intermediate` | Adds flood limits, TLS, server links |
| `advanced` | Full access to all settings, privsets, certfp, Let's Encrypt |

### Features

 * **Server info** — name, description, network name, admin contacts.
 * **Listen ports** — add/remove plain, TLS, and WebSocket listeners.
 * **Flood limits** — KICK/MODE/PROP flood counts and window sizes.
 * **Operators** — add, remove, list operators; choose from suggested
   privsets (`oper`, `admin`, `god`) or define custom ones.  Supports
   both encrypted (SHA-512 crypt) and plaintext passwords, plus CertFP
   fingerprint authentication.
 * **Server links** — add, remove, list connect blocks.  Supports
   encrypted password, plaintext password, CertFP-only, and
   CertFP + password authentication.
 * **TLS / SSL** — generate self-signed certificates or obtain a free
   certificate from Let's Encrypt (certbot is auto-installed if absent
   on apt/yum/dnf systems).  DH parameters are generated automatically.
 * **Keep-alive crontab** — installs a one-liner cron job that restarts
   Ophion every minute if it is not running.
 * **Password hashing** — SHA-512 crypt is computed in-process using
   the Python standard library, `mkpasswd`, or `openssl passwd -6` as
   available.  No external tools are required.
 * **CertFP fingerprint** — computes the SHA-512 fingerprint of a PEM
   certificate file for use in `operator{}` or `connect{}` blocks.

## Building

### Prerequisites

Ophion requires the following tools and libraries at build time:

| Dependency | Minimum version | Purpose |
|------------|-----------------|---------|
| [Meson](https://mesonbuild.com/) | 0.56 | Build system |
| [Ninja](https://ninja-build.org/) | 1.8 | Build executor |
| GCC or Clang | GCC 9 / Clang 10 | C compiler (C11 required) |
| OpenSSL or wolfSSL | OpenSSL 1.1 | TLS + SASL crypto |
| SQLite3 | 3.35 | Services database |
| libsodium | 1.0.18 | Optional: NaCl-based crypto (for extensions) |
| Python 3.8+ | — | Setup wizard (`ophion-setup`) |

**Debian/Ubuntu:**

```sh
apt-get install build-essential meson ninja-build \
    libssl-dev libsqlite3-dev python3
```

**Fedora/RHEL:**

```sh
dnf install gcc meson ninja-build \
    openssl-devel sqlite-devel python3
```

**macOS (Homebrew):**

```sh
brew install meson ninja openssl sqlite python3
```

### Build Steps

```sh
# 1. Configure
meson setup build

# 2. Compile
ninja -C build

# 3. Install (default prefix: /usr/local)
ninja -C build install

# 4. Install to a custom prefix
meson setup build --prefix=/opt/ophion
ninja -C build install
```

After installation the following layout is created under the prefix:

```
bin/
  ophion           — the ircd binary
  ophion-setup     — interactive setup and configuration tool
  mkpasswd         — password hash helper (SHA-512 crypt)
etc/
  ircd.conf        — main server configuration
  tls/             — default TLS certificate directory
lib/
  ophion/modules/  — core modules (.so)
  ophion/extensions/ — optional extensions (.so)
logs/              — default log directory
```

### Build Options

Pass `-D<option>=<value>` to `meson setup`:

| Option | Default | Description |
|--------|---------|-------------|
| `prefix` | `/usr/local` | Installation root |
| `sysconfdir` | `$prefix/etc` | Config file location |
| `localstatedir` | `$prefix` | Writable runtime data |
| `b_ndebug` | `false` | Disable debug assertions |
| `b_lto` | `false` | Link-time optimisation |

Example:

```sh
meson setup build --prefix=/opt/ophion -Db_lto=true -Db_ndebug=true
```

### Running Without Installing

```sh
ninja -C build
# Launch directly from the build tree:
./build/ircd/ophion -configfile ircd/ircd.conf.example -foreground
```

---

## Configuration Tool

`ophion-setup` (installed to `bin/ophion-setup` after `ninja install`) is an
interactive setup and configuration manager.  It edits `ircd.conf` in-place
without destroying comments or custom formatting.

### Running the Tool

```sh
# First-time setup wizard (after install)
ophion-setup

# Manage an existing installation
ophion-setup --config /usr/local/etc/ircd.conf --manage

# Run directly from the source tree (uses build-tree paths)
python3 tools/setup.py --config /path/to/ircd.conf
```

When run from the installed location, `ophion-setup` automatically uses the
installation's `etc/` and `logs/` directories as defaults.  Pass `--config`
to override.

### First-Time Wizard

On first run (or with `--new`), the wizard asks a series of guided questions
and writes a complete `ircd.conf`:

```
$ ophion-setup

  ============================================================
  Ophion IRC Server — Setup Wizard
  ============================================================

  Mode: [simple | intermediate | advanced]
```

| Wizard mode | What it covers |
|-------------|----------------|
| `simple` | Server name, network, admin info, one port (6667), one oper |
| `intermediate` | + TLS listener, flood limits, server linking |
| `advanced` | Full: privsets, certfp opers, Let's Encrypt, services tuning |

The wizard covers these sections in order:

1. **General settings** — server name, description, network name, admin contact
2. **Ports** — plain (6667), TLS (6697), WebSocket listeners
3. **Flood controls** — KICK, MODE, PROP counts and time windows
4. **Operators** — at least one oper block; supports SHA-512 password or certfp
5. **Server links** — optional connect blocks for multi-server networks
6. **Services** — nick/channel registration, memos, vhosts (see below)
7. **TLS** — self-signed certificate generation or Let's Encrypt integration
8. **Keep-alive** — optional cron job to auto-restart Ophion if it dies

### Interactive Management Menu

Re-run with `--manage` to enter the management menu at any time:

```
  1) Edit general settings
  2) Manage ports (add/remove listeners)
  3) Configure flood controls
  4) Manage operators (add/remove oper blocks)
  5) Manage server links (connect blocks)
  6) Configure TLS/SSL
  7) Configure keep-alive (cron)
  8) Configure services (nick/channel registration)
  9) Save & exit
```

### Services Configuration

The `services {}` block enables the built-in services layer (NickServ,
ChanServ, MemoServ, and VHost management).  The wizard prompts for:

| Setting | Default | Description |
|---------|---------|-------------|
| `enabled` | `yes` | Enable or disable services entirely |
| `hub` | `no` | Set to `yes` on hub servers that relay SVCSSYNC bursts |
| `db_path` | `$etc/services.db` | Path to the SQLite3 services database |
| `nick_expire_days` | `30` | Days before an unvisited nick registration expires (0 = never) |
| `chan_expire_days` | `60` | Days before an unused channel registration expires (0 = never) |
| `enforce_delay_secs` | `30` | Grace period (seconds) before a nick is force-renamed after login conflict |
| `maxnicks` | `10` | Maximum grouped nicks per account |
| `maxmemos` | `20` | Maximum stored memos per account |
| `registration_open` | `yes` | Allow new user registrations (set `no` to freeze signups) |

The resulting block in `ircd.conf`:

```
services {
    enabled             = yes;
    hub                 = no;
    db_path             = "/usr/local/etc/services.db";
    nick_expire_days    = 30;
    chan_expire_days    = 60;
    enforce_delay_secs  = 30;
    maxnicks            = 10;
    maxmemos            = 20;
    registration_open   = yes;
};
```

### Feature Summary

| Feature | Description |
|---------|-------------|
| **Server info** | Name, description, network, admin contacts |
| **Listen ports** | Add/remove plain, TLS, and WebSocket listeners |
| **Flood limits** | KICK/MODE/PROP flood counts and window sizes |
| **Operators** | Add, remove, list operators; SHA-512 password or certfp |
| **Server links** | Add, remove, list connect blocks; cleartext, encrypted, or certfp-only auth |
| **Services** | Full services block configuration via guided prompts |
| **TLS / SSL** | Self-signed certificate or Let's Encrypt (certbot auto-installed on apt/dnf) |
| **Keep-alive** | Cron job that restarts Ophion if it is not running |
| **Password hashing** | SHA-512 crypt computed in-process; no external tools required |
| **CertFP fingerprint** | Computes SHA-512 fingerprint of a PEM certificate for oper/connect blocks |

---

## Documentation

Detailed operator and user documentation is available in `doc/oper-guide/`.

See `doc/modes.txt` for a quick reference of all modes including IRCX modes.
See `doc/reference.conf` for a comprehensive configuration reference.
