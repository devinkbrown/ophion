User Commands
=============

Standard IRC commands are not listed here. Several of the commands in
the operator commands chapter can also be used by normal users.

ACCEPT
------

::

   ACCEPT nick, -nick, ...

Adds or removes users from your accept list for umode +g and +R. Users
are automatically removed when they quit, split or change nick.

::

   ACCEPT *

Lists all users on your accept list.

Support of this command is indicated by the ``CALLERID`` token in
``RPL_ISUPPORT`` (005); the optional parameter indicates the letter of the
“only allow accept users to send private messages” umode, otherwise +g.
In charybdis this is always +g.

CNOTICE
-------

::

   CNOTICE nick channel :text

Providing you are opped (+o) or voiced (+v) in channel, and nick is a
member of channel, ``CNOTICE`` generates a ``NOTICE`` towards nick.

``CNOTICE`` bypasses any anti-spam measures in place. If you get “Targets
changing too fast, message dropped”, you should probably use this
command, for example sending a notice to every user joining a certain
channel.

As of charybdis 3.1, ``NOTICE`` automatically behaves as ``CNOTICE`` if you are
in a channel fulfilling the conditions.

Support of this command is indicated by the ``CNOTICE`` token in
``RPL_ISUPPORT`` (005).

CPRIVMSG
--------

::

   CPRIVMSG nick channel :text

Providing you are opped (+o) or voiced (+v) in channel, and nick is a
member of channel, ``CPRIVMSG`` generates a ``PRIVMSG`` towards nick.

``CPRIVMSG`` bypasses any anti-spam measures in place. If you get “Targets
changing too fast, message dropped”, you should probably use this
command.

As of charybdis 3.1, ``PRIVMSG`` automatically behaves as ``CPRIVMSG`` if you
are in a channel fulfilling the conditions.

Support of this command is indicated by the ``CPRIVMSG`` token in
``RPL_ISUPPORT`` (005).

FINDFORWARDS
------------

::

   FINDFORWARDS channel

.. note:: This command is only available if the ``m_findforwards.so``
          extension is loaded.

Displays which channels forward to the given channel (via cmode +y). If
there are very many channels the list will be truncated.

You must be a channel operator on the channel or an IRC operator to use
this command.

HELP
----

::

   HELP [topic]

Displays help information. topic can be ``INDEX``, ``CREDITS``, ``UMODE``, ``CMODE``,
``SNOMASK`` or a command name.

There are separate help files for users and opers. Opers can use ``UHELP``
to query the user help files.

IDENTIFY
--------

::

   IDENTIFY parameters...

.. note:: This command is only available if the ``m_identify.so``
          extension is loaded.

Sends an identify command to either NickServ or ChanServ. If the first
parameter starts with #, the command is sent to ChanServ, otherwise to
NickServ. The word ``IDENTIFY``, a space and all parameters are concatenated
and sent as a ``PRIVMSG`` to the service. If the service is not online or
does not have umode +S set, no message will be sent.

The exact syntax for this command depends on the services package in
use.

KNOCK
-----

::

   KNOCK channel

Requests an invite to the given channel. The channel must be locked
somehow (``+ikl``), must not be ``+p``, and you may not be banned or quieted.
Also, this command is rate limited.

When the IRCX modes module is loaded, KNOCK additionally requires that
the channel has ``+u`` (KNOCK) mode set. Without ``+u``, the KNOCK request
is rejected -- this allows channel operators to opt-in to receiving
knock notifications per the IRCX draft specification.

If successful, all channel operators will receive a 710 numeric. The
recipient field of this numeric is the channel.

Support of this command is indicated by the ``KNOCK`` token in ``RPL_ISUPPORT``
(005).

MONITOR
-------

Server side notify list. This list contains nicks. When a user connects,
quits with a listed nick or changes to or from a listed nick, you will
receive a 730 numeric if the nick went online and a 731 numeric if the
nick went offline.

Support of this command is indicated by the ``MONITOR`` token in
``RPL_ISUPPORT`` (005); the parameter indicates the maximum number of
nicknames you may have in your monitor list.

You may only use this command once per second.

More details can be found in ``doc/monitor.txt`` in the source
distribution.

::

   MONITOR + nick, ...

Adds nicks to your monitor list. You will receive 730 and 731 numerics
for the nicks.

::

   MONITOR - nick, ...

Removes nicks from your monitor list. No output is generated for this
command.

::

   MONITOR C

Clears your monitor list. No output is generated for this command.

::

   MONITOR L

Lists all nicks on your monitor list, using 732 numerics and ending with
a 733 numeric.

::

   MONITOR S

Shows status for all nicks on your monitor list, using 730 and 731
numerics.

IRCX user commands
~~~~~~~~~~~~~~~~~~

The following commands are provided by IRCX modules and are available
to all users (unless otherwise noted). These implement functionality
defined in the IRCX draft specification (draft-pfenning-irc-extensions-04).

AUTH
----

::

   AUTH <mechanism> <sequence> [token]

IRCX authentication command. Provides an alternative authentication
mechanism to the standard ``PASS`` command, supporting extensible
authentication via SASL-like mechanisms.

Provided by the ``m_ircx_auth`` module.

CREATE
------

::

   CREATE <channel> [modes]

Creates a channel with the specified initial modes. Unlike ``JOIN``,
``CREATE`` will fail if the channel already exists, ensuring the creator
gets the intended initial state. The creator is granted channel operator
status.

Provided by the ``m_ircx_create`` module.

LISTX
------

::

   LISTX [pattern]

Extended channel listing command per the IRCX specification. Returns
channel information in an extended format including channel properties,
modes, and member counts.

Channels with ``+h`` (HIDDEN) mode are excluded from ``LISTX`` output for
non-members. Channels with ``+s`` (SECRET) are excluded as per standard
IRC behavior.

Provided by the ``m_ircx_listx`` module.

PROP
----

::

   PROP <target> [key [value]]
   PROP <target> *

IRCX property system. Allows getting, setting, and listing properties
on channels and users.

``PROP <target>``
    List all properties on the target (channel or user).

``PROP <target> *``
    List all properties on the target (explicit wildcard).

``PROP <target> <key>``
    Get the value of a specific property.

``PROP <target> <key> <value>``
    Set a property value on the target.

``PROP <target> <key> :``
    Clear/delete a property.

**Channel properties** (via ``m_ircx_prop_channel_builtins``):
    ``TOPIC``, ``MEMBERCOUNT``, ``CREATION`` -- read-only computed properties,
    plus any custom properties set via ``PROP``.

**User profile properties** (via ``m_ircx_prop_user_profile``):
    ``URL``, ``GENDER``, ``PICTURE``, ``LOCATION``, ``BIO``, ``REALNAME``,
    ``EMAIL`` -- users can only set their own profile properties. Maximum
    200 characters per value.

**Microsoft Comic Chat properties** (via ``m_ircx_comic``):
    ``MCC`` (character data, max 1024 chars), ``MCCGUID`` (character GUID,
    max 64 chars), ``MCCEX`` (expression/gesture data). These enable
    Microsoft Comic Chat/Microsoft Chat character metadata support.

**Channel keys** (via ``m_ircx_prop_adminkey`` / ``m_ircx_prop_opkey``):
    ``ADMINKEY`` and ``OPKEY`` -- special channel access properties.

Provided by the ``m_ircx_prop`` module and its sub-modules.

WHISPER
-------

::

   WHISPER <channel> <nick> :<message>

Sends a private message to a specific member of a channel, routed
through the channel context. The message is visible only to the
target user. Both the sender and target must be members of the
channel.

If the channel has ``+w`` (NOWHISPER) mode set, ``WHISPER`` is disabled
for that channel.

Provided by the ``m_ircx_whisper`` module.

ACCESS
------

::

   ACCESS <channel> ADD <level> <mask> [ttl]
   ACCESS <channel> DELETE <mask>
   ACCESS <channel> LIST
   ACCESS <channel> CLEAR <level>

IRCX channel access list management. Provides a persistent, structured
access control system for channels, separate from the traditional ban/
exception/invex lists.

**Access levels:**

``OWNER``
    Channel owner. Full control including the ability to manage other
    owners.

``HOST``
    Channel host (operator equivalent). Can manage the channel,
    kick users, and set modes.

``VOICE``
    Automatic voice on join.

``DENY``
    Denied access. User cannot join the channel (linked to the
    channel ban list).

``GRANT``
    Granted access. User can bypass restrictions to join.

Provided by the ``m_ircx_access`` module.
