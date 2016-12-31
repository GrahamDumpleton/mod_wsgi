==============
Version 4.5.12
==============

Version 4.5.12 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.12

Bugs Fixed
----------

* When the ``pip install`` method is used to compile the module for
  Windows, the ``mod_wsgi-express module-config`` command was generating
  the wrong DLL path for ``LoadFile`` directive for Python 3.4, as well as
  possibly older Python versions.

New Features
------------

* When using ``pip install`` on Windows, in addition to looking in the
  directory ``C:\Apache24`` for an Apache installation, it will now also
  check ``C:\Apache22`` and ``C:\Apache2``. It is recommended though that
  you use Apache 2.4. If your Apache installation is elsewhere, you can
  still set the ``MOD_WSGI_APACHE_ROOTDIR`` environment variable to its
  location. The environment variable should be set in your shell before
  running ``pip install mod_wsgi`` and should be set in a way that exports
  it to child processes run from the shell.

* Added ``restart-interval`` option to ``WSGIDaemonProcess`` for restarting
  daemon mode processes after a set time. If ``graceful-timeout`` option is
  also specified, active requests will be given a chance to complete, while
  still accepting new requests. If within the grace period the process
  becomes idle, a shutdown will occur immediately. In the case of no grace
  period being specified, or the grace period expiring, the normal shutdown
  sequence will occur. The option is also available in ``mod_wsgi-express``
  as ``--restart-interval``.
