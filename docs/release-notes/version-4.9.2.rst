:orphan:

=============
Version 4.9.2
=============

Bugs Fixed
----------

* When using ``mod_wsgi-express`` in daemon mode, and source code reloading
  was enabled, an invalid URL path which contained a byte sequence which
  could not be decoded as UTF-8 was causing a process crash.
