=============
Version 4.5.6
=============

Version 4.5.6 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.6

Bugs Fixed
----------

1. Reinstanted change to associate any messages logged via ``sys.stdout``
   and ``sys.stderr`` back to the request so that Apache can log them
   with the correct request log ID. This change was added in 4.5.4, but
   was reverted in 4.5.5 as the change was causing process crashes under
   Python 3.

New Features
------------

1. Added ``startup-timeout`` option to ``WSGIDaemonProcess`` directive.
   If set and the first loading of the WSGI application script file
   fails, then if no subsequent attempt to load it succeeds within the
   specified startup timeout, the daemon process will be restarted. When
   configuring mod_wsgi directly, the option is not enabled by default.
   The option is exposed via ``mod_wsgi-express`` with a default value
   of 15 seconds.

   This would be used where running the Django web framework and there is
   a risk of the database not being available, causing Django initialisation
   to fail. Django doesn't allow initialisation to be performed a second
   time in the same process, meaning it will then constantly fail. Use of
   startup timeout will allow the process to be restarted in face of such
   constant startup failures. If the database is available when the
   process is restarted, then next time the process starts, everything
   should be fine.

   Do note that this option should preferably only be used where the one
   WSGI application has been delegated to a WSGI daemon process. This is
   because if multiple WSGI applications are hosted out of the daemon
   process group, be they in the same application group or distinct ones,
   as soon as any one of them loads successfully, then the startup timeout
   is disabled, meaning that if a subsequent one loaded is constantly
   failing, then a process restart will not occur. Best practice is to
   delegate each WSGI application to a distinct daemon process group.
