Channel modes
=============

Channel modes are determined by the various plugins loaded by the
server. The following consists only of a base list of common modes:
your server may have more plugins available, which you can see with
the following server command, depending on your IRC client::

  /QUOTE HELP CMODE

or::

  /RAW HELP CMODE

Standard channel modes
~~~~~~~~~~~~~~~~~~~~~~

``+b``, channel ban
-------------------

Bans take one parameter which can take several forms. The most common
form is ``+b nick!user@host``. The wildcards ``*`` and ``?`` are
allowed, matching zero-or-more, and exactly-one characters
respectively. The masks will be trimmed to fit the maximum allowable
length for the relevant element.  Bans are also checked against the IP
address, even if it resolved or is spoofed. CIDR is supported, like
``*!*@10.0.0.0/8``. This is most useful with IPv6. Bans are not
checked against the real hostname behind any kind of spoof, except if
host mangling is in use (e.g.  ``extensions/ip_cloaking.so``): if the
user's host is mangled, their real hostname is checked additionally,
and if a user has no spoof but could enable mangling, the mangled form
of their hostname is checked additionally. Hence, it is not possible
to evade bans by toggling host mangling.

The second form (extban) is ``+b $type`` or ``+b $type:data``. type is
a single character (case insensitive) indicating the type of match,
optionally preceded by a tilde (``~``) to negate the comparison. data
depends on type.  Each type is loaded as a module. The available types
(if any) are listed in the ``EXTBAN`` token of the 005
(``RPL_ISUPPORT``) numeric. See ``doc/extban.txt`` in the source
distribution or ``HELP EXTBAN`` for more information.

If no parameter is given, the list of bans is returned. All users can
use this form. The plus sign should also be omitted.

Matching users will not be allowed to join the channel or knock on it.
If they are already on the channel, they may not send to it or change
their nick.

``+c``, colour filter
---------------------

This cmode activates the colour filter for the channel. This filters out
bold, underline, reverse video, beeps, mIRC colour codes, and ANSI
escapes. Note that escape sequences will usually leave cruft sent to the
channel, just without the escape characters themselves.

``+e``, ban exemption
---------------------

This mode takes one parameter of the same form as bans, which overrides
``+b`` and ``+q`` bans for all clients it matches.

This can be useful if it is necessary to ban an entire ISP due to
persistent abuse, but some users from that ISP should still be allowed
in. For example::

  /mode #channel +be *!*@*.example.com *!*someuser@host3.example.com

Only channel operators can see ``+e`` changes or request the list.

``+f``, NOFORMAT (IRCX)
-----------------------

.. note:: This mode is provided by the ``m_ircx_modes`` module.

Per IRCX draft section 8.1.10, when ``+f`` is set, messages in this
channel contain raw text only. IRC clients should not apply formatting
(colors, bold, underline, etc.) to messages in this channel. This is
useful for channels dedicated to code, logs, or data transfer.

``+F``, allow anybody to forward to this
----------------------------------------

When this mode is set, anybody may set a forward from a channel they
have ops in to this channel. Otherwise they have to have ops in this
channel.

``+g``, allow anybody to invite
-------------------------------

When this mode is set, anybody may use the ``INVITE`` command on the channel
in question. When it is unset, only channel operators may use the ``INVITE``
command.

When this mode is set together with ``+i``, ``+j``, ``+l`` or ``+r``, all channel
members can influence who can join.

``+i``, invite only
-------------------

When this cmode is set, no client can join the channel unless they have
an invex (``+I``) or are invited with the ``INVITE`` command.

``+I``, invite exception (invex)
--------------------------------

This mode takes one parameter of the same form as bans. Matching clients
do not need to be invited to join the channel when it is invite-only
(``+i``). Unlike the ``INVITE`` command, this does not override ``+j``, ``+l`` and ``+r``.

Only channel operators can see ``+I`` changes or request the list.

``+j``, join throttling
-----------------------

This mode takes one parameter of the form n:t, where n and t are
positive integers. Only n users may join in each period of t seconds.

Invited users can join regardless of ``+j``, but are counted as normal.

Due to propagation delays between servers, more users may be able to
join (by racing for the last slot on each server).

``+k``, key (channel password)
------------------------------

Taking one parameter, when set, this mode requires a user to supply the
key in order to join the channel: ``/JOIN #channel key``.

``+l``, channel member limit
----------------------------

Takes one numeric parameter, the number of users which are allowed to be
in the channel before further joins are blocked. Invited users may join
regardless.

Due to propagation delays between servers, more users may be able to
join (by racing for the last slot on each server).

``+L``, large ban list
----------------------

Channels with this mode will be allowed larger banlists (by default, 500
instead of 50 entries for ``+b``, ``+q``, ``+e`` and ``+I`` together). Only network
operators with resv privilege may set this mode.

``+M``, opmoderate
------------------

When ``+M`` is set, the effects of ``+m``, ``+b`` and ``+q`` are relaxed. For each
message, if that message would normally be blocked by one of these
modes, it is instead sent to all channel operators.

``+m``, moderated
-----------------

When a channel is set ``+m``, only users with ``+o`` or ``+v`` on the channel can
send to it.

Users can still knock on the channel or change their nick.

``+n``, no external messages
----------------------------

When set, this mode prevents users from sending to the channel without
being in it themselves. This is recommended.

``+o``, channel operator
------------------------

This mode takes one parameter, a nick, and grants or removes channel
operator privilege to that user. Channel operators have full control
over the channel, having the ability to set all channel modes except ``+L``
and ``+P``, and kick users. Like voiced users, channel operators can always
send to the channel, overriding ``+b``, ``+m`` and ``+q`` modes and the per-channel
flood limit. In most clients channel operators are marked with an '@'
sign.

The privilege is lost if the user leaves the channel or server in any
way.

Most networks will run channel registration services (e.g. ChanServ)
which ensure the founder (and users designated by the founder) can
always gain channel operator privileges and provide some features to
manage the channel.

``+p``, paranoid channel / PRIVATE (IRCX)
------------------------------------------

When set, the ``KNOCK`` command cannot be used on the channel to request an
invite, and users will not be shown the channel in ``WHOIS`` replies unless
they are on it.

Per the IRCX draft (section 8.1.2), ``+p`` marks a channel as PRIVATE.
The channel appears in ``LIST`` output, but its properties (topic, member
count) may be restricted from non-members.

``+p`` is mutually exclusive with ``+h`` (HIDDEN) per the IRCX visibility
model. Setting ``+p`` or ``+s`` will clear ``+h`` if the IRCX modes module
is loaded.

``+P``, permanent channel
-------------------------

Channels with this mode (which is accessible only to network operators
with resv privilege) set will not be destroyed when the last user
leaves.

This makes it less likely modes, bans and the topic will be lost and
makes it harder to abuse network splits, but also causes more unwanted
restoring of old modes, bans and topics after long splits.

``+q``, channel admin
---------------------

.. note:: In Ophion, ``+q`` is a **membership status mode** (channel admin,
          prefix ``~``), not the quiet ban-like mode found in standard
          charybdis.  Users with ``+q`` are channel administrators.

This mode takes one parameter (a nick) and grants or removes channel-admin
status to that user.  Channel admins have the highest privilege level within
a channel (``CHFL_ADMIN``) and can perform all chanop operations as well as
grant or remove ``+q`` and ``+o`` from other users.

Setting or removing ``+q`` requires the source to already have
``CHFL_ADMIN`` access (i.e., be a channel admin or have god mode with an
admin-level ceiling).

When ``oper_auto_op = yes`` is set in ``ircd.conf``, IRC operators and
server admins automatically receive ``+q`` on channel join (unless they have
the ``oper:auto_op`` privilege, which limits them to ``+o`` instead).

In most clients channel admins are marked with a ``~`` (tilde) prefix.

The privilege is lost if the user leaves the channel or server.

``+Q``, block forwarded users
-----------------------------

Channels with this mode set are not valid targets for forwarding. Any
attempt to forward to this channel will be ignored, and the user will be
handled as if the attempt was never made (by sending them the relevant
error message).

This does not affect the ability to set ``+y``.

``+r``, block unidentified
--------------------------

When set, this mode prevents unidentified users from joining. Invited
users can still join.

``+s``, secret channel / SECRET (IRCX)
---------------------------------------

When set, this mode prevents the channel from appearing in the output of
the ``LIST``, ``WHO`` and ``WHOIS`` command by users who are not on it. Also, the
server will refuse to answer ``WHO``, ``NAMES``, ``TOPIC`` and ``LIST`` queries from
users not on the channel.

Per the IRCX draft (section 8.1.4), ``+s`` marks a channel as SECRET.
This is the most restrictive visibility level -- the channel is not
visible to non-members in any way.

``+s`` is mutually exclusive with ``+h`` (HIDDEN) per the IRCX visibility
model.

``+t``, topic limit
-------------------

When set, this mode prevents users who are not channel operators from
changing the topic.

``+v``, voice
-------------

This mode takes one parameter, a nick, and grants or removes voice
privilege to that user. Voiced users can always send to the channel,
overriding ``+b``, ``+m`` and ``+q`` modes and the per-channel flood limit. In most
clients voiced users are marked with a plus sign.

The privilege is lost if the user leaves the channel or server in any
way.

``+y``, channel forwarding
--------------------------

This mode takes one parameter, the name of a channel (``+y
#channel``). If the channel also has the ``+i`` cmode set, and
somebody attempts to join without either being explicitly invited, or
having an invex (``+I``), then they will instead join the channel
named in the mode parameter.

``+z``, SERVICE (IRCX)
-----------------------

.. note:: This mode is provided by the ``m_ircx_modes`` module.

Per IRCX draft section 8.1.14, indicates that a service (bot, monitor,
or automated agent) is monitoring this channel. This mode can only be
set by IRC operators (sysops). It is informational -- it tells users
that a service is present and may be logging or responding to activity.

IRCX channel modes
~~~~~~~~~~~~~~~~~~

The following modes are provided by the ``m_ircx_modes`` module
(``modules/m_ircx_modes.c``). They implement channel modes defined in
the IRCX draft specification (draft-pfenning-irc-extensions-04).

``+a``, AUTHONLY (IRCX)
------------------------

Per IRCX draft section 8.1.15, when ``+a`` is set, only authenticated
users may join the channel. A user is considered authenticated if they
have identified to services (i.e., their services account name is set).
Unauthenticated users receive ``ERR_NEEDREGGEDNICK`` (477) when they
attempt to join.

This is useful for channels that require verified identity, such as
private team channels or moderated discussion forums.

``+d``, CLONEABLE (IRCX)
--------------------------

Per IRCX draft section 8.1.16, when ``+d`` is set on a channel, the
channel is marked as cloneable. When the channel reaches its member
limit (``+l``), the server may automatically create numbered clone
channels (e.g., ``#chat`` -> ``#chat1``, ``#chat2``, etc.) and redirect
new joiners to the clone.

Currently, the ``+d`` flag is registered and can be set/queried, but the
automatic clone creation behavior is designed to be implemented by
services or extended in a future update. The clone channels themselves
are marked with ``+E``.

``+E``, CLONE (IRCX)
---------------------

Per IRCX draft section 8.1.17, marks a channel as a numbered clone of
a CLONEABLE (``+d``) channel. This flag is set automatically by the
server when a clone channel is created due to overflow on a ``+d``
channel.

.. note:: The IRCX draft uses ``+e`` for CLONE, but since ``+e`` is
          used for ban exceptions in the charybdis lineage,
          CLONE has been remapped to ``+E`` to avoid the conflict.

``+h``, HIDDEN (IRCX)
-----------------------

Per IRCX draft section 8.1.3, when ``+h`` is set, the channel is
hidden from ``LIST`` and ``LISTX`` output for non-members. However,
unlike ``+s`` (SECRET), the channel can still be queried by name --
users who know the channel name can view its properties and join it
(subject to other restrictions).

**Visibility model (mutually exclusive):**

The IRCX draft defines four visibility levels for channels:

==========  ====  ==========================================
Visibility  Mode  Description
==========  ====  ==========================================
PUBLIC      none  Default. Visible in LIST, all data queryable.
PRIVATE     ``+p``  Listed, but properties restricted to non-members.
HIDDEN      ``+h``  Not in LIST, but queryable if name is known.
SECRET      ``+s``  Not visible to non-members at all.
==========  ====  ==========================================

These are mutually exclusive. When ``+h`` is set, ``+p`` and ``+s``
are automatically cleared. When ``+p`` or ``+s`` is set by other means,
the mutual exclusivity should be observed.

``+u``, KNOCK (IRCX)
----------------------

Per IRCX draft section 8.1.9, when ``+u`` is set, KNOCK notifications
are enabled for the channel. Channel hosts and owners will receive
notifications when a user uses the ``KNOCK`` command to request entry.

Without ``+u`` set, the ``KNOCK`` command will be rejected for this
channel. This allows channel operators to opt-in to receiving knock
requests.

``+x``, AUDITORIUM (IRCX)
---------------------------

Per IRCX draft section 8.1.12, when ``+x`` is set, the channel operates
in auditorium mode. Non-operator members cannot see each other in the
channel -- only channel operators are visible in ``NAMES`` and ``WHO``
output. JOIN, PART, and QUIT messages from non-operators are suppressed
for other non-operators.

This is ideal for large announcement channels, lectures, or events where
only the presenters/operators should be visible.

Provided by the ``m_ircx_auditorium`` module.

``+w``, NOWHISPER (IRCX)
--------------------------

When ``+w`` is set, the IRCX ``WHISPER`` command is disabled for the
channel. WHISPER allows sending a message to a specific channel member
via the channel (visible only to that member), similar to a private
message but routed through the channel context.

Provided by the ``m_ircx_whisper`` module.
