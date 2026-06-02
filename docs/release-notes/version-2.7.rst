:orphan:

===========
Version 2.7
===========

Note that this release does not support Python 3.0. Python 3.0 will only be
supported in mod_wsgi 3.0.

Features Changed
----------------

1. Set timeout on socket connection between Apache server child process and
daemon process earlier to catch any blocking problems in initial handshake
between the processes. This will make code more tolerant of any unexpected
issues with socket communications.

Bug Fixes
---------

1. Wasn't possible to set CFLAGS from environment variable when running the
'configure' script.
