Scope of this document
======================

This document describes the commands and functions available to
operators in the Ophion IRC server.

Ophion is a websocket-first IRC server forked from charybdis,
implementing IRCv3.2, parts of the IRCv3 living standard, and
relevant patent-unencumbered parts of the IRCX specification
(draft-pfenning-irc-extensions-04).

While this document may be of some interest to the users of Ophion
servers, it is intended as a reference for network staff.

Heritage
--------

Ophion is based on charybdis, which is based on ircd-ratbox 2.1.4.
This document, and various ideas for features, have been taken from
dancer-ircd/hyperion, the ircd used on freenode, mainly written by
Andrew Suffield and Jilles Tjoelker.

IRCX extensions
---------------

Ophion implements the following IRCX features from
draft-pfenning-irc-extensions-04:

**Channel modes:**
    ``+u`` (KNOCK), ``+h`` (HIDDEN), ``+a`` (AUTHONLY),
    ``+d`` (CLONEABLE), ``+E`` (CLONE), ``+f`` (NOFORMAT),
    ``+z`` (SERVICE), ``+x`` (AUDITORIUM), ``+w`` (NOWHISPER)

**User modes:**
    ``+z`` (GAG) -- global user silencing, oper-only

**Commands:**
    ``AUTH``, ``CREATE``, ``LISTX``, ``PROP``, ``WHISPER``,
    ``ACCESS``, ``EVENT``, ``GAG``, ``OPFORCE``

**Property system (PROP):**
    Channel properties, user profile properties, entity properties,
    Microsoft Comic Chat character metadata (MCC/MCCGUID/MCCEX)

**Access control (ACCESS):**
    Structured channel access lists with OWNER, HOST, VOICE, DENY,
    and GRANT levels

See the channel modes, user modes, and commands chapters for detailed
documentation of each feature.
