Oper privileges
===============

These are specified in privset{}.

oper:admin, server administrator
--------------------------------

Various privileges intended for server administrators. Among other
things, this automatically sets umode +a and allows loading modules.

oper:die, die and restart
-------------------------

This grants permission to use ``DIE`` and ``RESTART``, shutting down or
restarting the server.

oper:global\_kill, global kill
------------------------------

Allows using ``KILL`` on users on any server.

oper:hidden, hide from /stats p
-------------------------------

This privilege currently does nothing, but was designed to hide bots
from /stats p so users will not message them for help.

oper:hidden\_admin, hidden administrator
----------------------------------------

This grants everything granted to the oper:admin privilege, except the
ability to set umode +a. If both oper:admin and oper:hidden\_admin are
possessed, umode +a can still not be used.

oper:kline, kline and dline
---------------------------

Allows using ``KLINE`` and ``DLINE``, to ban users by user@host mask or IP
address.

oper:local\_kill, kill local users
----------------------------------

This grants permission to use ``KILL`` on users on the same server,
disconnecting them from the network.

oper:mass\_notice, global notices and wallops
---------------------------------------------

Allows using server name ($$mask) and hostname ($#mask) masks in ``NOTICE``
and ``PRIVMSG`` to send a message to all matching users, and allows using
the ``WALLOPS`` command to send a message to all users with umode +w set.

oper:operwall, send/receive operwall
------------------------------------

Allows using the ``OPERWALL`` command and umode +z to send and receive
operwalls.

oper:rehash, rehash
-------------------

Allows using the ``REHASH`` command, to rehash various configuration files
or clear certain lists.

oper:remoteban, set remote bans
-------------------------------

This grants the ability to use the ON argument on ``DLINE``/``KLINE``/``XLINE``/``RESV``
and ``UNDLINE``/``UNKLINE``/``UNXLINE``/``UNRESV`` to set and unset bans on other
servers, and the server argument on ``REHASH``. This is only allowed if the
oper may perform the action locally, and if the remote server has a
shared{} block.

.. note:: If a cluster{} block is present, bans are sent remotely even
          if the oper does not have oper:remoteban privilege.

oper:resv, channel control
--------------------------

This allows using /resv, /unresv and changing the channel modes +L and
+P.

oper:routing, remote routing
----------------------------

This allows using the third argument of the ``CONNECT`` command, to instruct
another server to connect somewhere, and using ``SQUIT`` with an argument
that is not locally connected. (In both cases all opers with +w set will
be notified.)

oper:spy, use operspy
---------------------

This allows using ``/mode !#channel``, ``/whois !nick``, ``/who !#channel``,
``/chantrace !#channel``, ``/topic !#channel``, ``/who !mask``, ``/masktrace
!user@host :gecos`` and ``/scan umodes +modes-modes global list`` to see
through secret channels, invisible users, etc.

All operspy usage is broadcasted to opers with snomask ``+Z`` set (on the
entire network) and optionally logged. If you grant this to anyone, it
is a good idea to establish concrete policies describing what it is to
be used for, and what not.

If ``operspy_dont_care_user_info`` is enabled, ``/who mask`` is operspy
also, and ``/who !mask``, ``/who mask``, ``/masktrace !user@host :gecos`` and ``/scan
umodes +modes-modes global list`` do not generate ``+Z`` notices or logs.

oper:unkline, unkline and undline
---------------------------------

Allows using ``UNKLINE`` and ``UNDLINE``.

oper:xline, xline and unxline
-----------------------------

Allows using ``XLINE`` and ``UNXLINE``, to ban/unban users by realname.

oper:god, god mode
------------------

Allows the operator to activate god mode (umode ``+G``).  When god mode is
enabled the operator can:

- Join any channel regardless of bans, keys, invite-only, limits, or other
  restrictions.
- Change any channel mode even without being a member or having channel-op
  status.
- Kick any user from any channel.
- Send to any channel regardless of moderation (``+m``, ``+n``) or bans.
- Modify any channel PROP (property) from outside the channel.
- Modify any channel ACCESS entry from outside the channel.

All god mode actions are logged to the oper snomask (``+s``/``+g``) for
auditing.  The access level granted by god mode is subject to the oper's
configured channel ceiling (see ``oper:auto_op`` and ``oper:auto_admin``
below).

Provided by the ``m_ircx_oper_godmode`` module.

oper:auto\_op, channel-operator auto-join level
------------------------------------------------

When this privilege is present in an oper's privset **without**
``oper:auto_admin``, the oper automatically joins channels with ``+o``
(channel-operator) when ``oper_auto_op = yes`` in ``ircd.conf``.

Crucially, this also sets the oper's **channel access ceiling** to
``CHFL_CHANOP``.  Even in god mode (``+G``), this oper cannot:

- Grant or remove ``+q`` (channel-admin) status from any user.
- Perform any operation requiring admin-level (``CHFL_ADMIN``) access.
- Exceed chanop level when modifying channel properties (PROPs).

They can still kick users, set ``+o``/``+v``/``+b``, and do all other
chanop-level operations.

IRC server admins (``IsAdmin``) are **never** subject to this ceiling;
the privilege is only meaningful for non-admin IRC operators.

Provided by the ``m_ircx_oper_godmode`` module.

oper:auto\_admin, channel-admin auto-join level
------------------------------------------------

When this privilege is present, the oper automatically joins channels with
``+q`` (channel-admin, prefix ``~``) when ``oper_auto_op = yes`` in
``ircd.conf``.  This gives full ``CHFL_ADMIN`` channel access with no
ceiling.

``oper:auto_admin`` overrides ``oper:auto_op`` if both are present in the
same privset.

Not required if the global ``oper_auto_op = yes`` and the oper does not
have ``oper:auto_op`` (the default level without any per-oper override is
already ``+q``).

Provided by the ``m_ircx_oper_godmode`` module.

Example privset configuration::

    privset "chanop_oper" {
        privs = oper:local_kill, oper:routing, oper:auto_op;
    };

    privset "server_admin" {
        extends = "chanop_oper";
        privs = oper:god, oper:auto_admin;
    };

snomask:nick\_changes, see nick changes
---------------------------------------

Allows using snomask ``+n`` to see local client nick changes. This is
designed for monitor bots.
