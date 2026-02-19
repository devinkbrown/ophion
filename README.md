# Ophion

Ophion is an IRC server for communities and teams, forked from
charybdis and extended with:

 * IRCv3.2 and portions of the IRCv3 living standard,
 * the patent-unencumbered parts of the IRCX protocol
   (draft-pfenning-irc-extensions-04),
 * automatic SID generation and SVSSID collision negotiation for
   zero-config server linking,
 * reverse-DNS toggle (`rdns_lookups = yes|no`) for fast deployments,
 * and websocket transport support.

Come chat with us at irc.ophion.dev #ophion.

## IRCX Protocol Support

Ophion implements channel modes, user modes, and commands from the IRCX
specification (draft-pfenning-irc-extensions-04). All IRCX features are
provided as loadable modules and can be enabled/disabled independently.

### IRCX Channel Modes

| Mode | Name | IRCX Spec | Description |
|------|------|-----------|-------------|
| `+a` | AUTHONLY | 8.1.15 | Only authenticated (services-identified) users may join |
| `+d` | CLONEABLE | 8.1.16 | Channel creates numbered clones when full |
| `+E` | CLONE | 8.1.17 | Marks channel as a clone of a CLONEABLE channel (IRCX `+e` remapped to avoid ban exception conflict) |
| `+f` | NOFORMAT | 8.1.10 | Raw text only, clients should not apply formatting (overrides charybdis forwarding mode) |
| `+h` | HIDDEN | 8.1.3 | Not in LIST/LISTX but queryable if channel name is known |
| `+u` | KNOCK | 8.1.9 | Enables KNOCK notifications to channel hosts/owners |
| `+w` | NOWHISPER | - | Disables the WHISPER command in the channel |
| `+x` | AUDITORIUM | 8.1.12 | Only operators visible; JOIN/PART/QUIT hidden for non-ops |
| `+z` | SERVICE | 8.1.14 | Indicates a service is monitoring the channel (oper-only, overrides charybdis opmoderate) |

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
| `ACCESS` | m_ircx_access | Channel access list management (OWNER/HOST/VOICE/DENY/GRANT) |
| `EVENT` | m_ircx_event | Oper event subscription system (CHANNEL/MEMBER/USER/SERVER) |
| `GAG` | m_ircx_oper | Toggle or set GAG mode on a user (oper-only) |
| `OPFORCE` | m_ircx_oper | Unified oper channel force: JOIN/OP/KICK/MODE (oper+admin) |

### Property System (PROP)

The PROP command provides a key-value property system for channels and users:

**User profile properties** (m_ircx_prop_user_profile):
`URL`, `GENDER`, `PICTURE`, `LOCATION`, `BIO`, `REALNAME`, `EMAIL`

**Channel built-in properties** (m_ircx_prop_channel_builtins):
`TOPIC`, `MEMBERCOUNT`, `CREATION` (read-only computed properties)

**Channel keys** (m_ircx_prop_adminkey, m_ircx_prop_opkey):
`ADMINKEY`, `OPKEY`

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
| m_ircx_prop_adminkey | ADMINKEY channel property |
| m_ircx_prop_channel_builtins | TOPIC/MEMBERCOUNT/CREATION properties |
| m_ircx_prop_entity_account | Account entity properties |
| m_ircx_prop_entity_channel | Channel entity properties |
| m_ircx_prop_entity_user | User entity properties |
| m_ircx_prop_member_of | MEMBER_OF channel property |
| m_ircx_prop_onjoin | ONJOIN channel property |
| m_ircx_prop_onpart | ONPART channel property |
| m_ircx_prop_opkey | OPKEY channel property |
| m_ircx_prop_user_profile | User profile properties |
| m_ircx_whisper | WHISPER command and +w mode |

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

## Building

Ophion uses the Meson build system:

```sh
meson setup builddir
ninja -C builddir
ninja -C builddir install
```

## Documentation

Detailed operator and user documentation is available in `doc/oper-guide/`.

See `doc/modes.txt` for a quick reference of all modes including IRCX modes.
See `doc/reference.conf` for a comprehensive configuration reference.
