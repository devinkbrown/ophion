# Ophion

Ophion is an IRC server for communities and teams, forked from
charybdis and extended with:

 * comprehensive IRCv3 support (see below),
 * the patent-unencumbered parts of the IRCX protocol
   (draft-pfenning-irc-extensions-04),
 * automatic SID generation and SVSSID collision negotiation for
   zero-config server linking,
 * reverse-DNS toggle (`rdns_lookups = yes|no`) for fast deployments,
 * and websocket transport support.

Come chat with us at irc.ophion.dev #ophion.

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
| `draft/typing` | core | Typing indicator notifications |

### IRCv3 Commands

| Command | Module | Description |
|---------|--------|-------------|
| `TAGMSG` | cap_message_tags | Send a message with tags but no text body |
| `SETNAME` | m_setname | Change your realname (GECOS) |
| `CHATHISTORY` | m_chathistory | Retrieve message history for a target |

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

### ISUPPORT Tokens

The following ISUPPORT tokens are added by IRCv3 modules:

| Token | Value | Description |
|-------|-------|-------------|
| `CHATHISTORY` | `100` | Maximum messages per history request |
| `MSGREFTYPES` | `timestamp` | Supported message reference types |

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
