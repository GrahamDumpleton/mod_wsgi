=============
Version 4.4.2
=============

Version 4.4.2 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.2

Known Issues
------------

1. Although the makefiles for building mod_wsgi on Windows have now been
updated for the new source code layout, some issues are being seen with
mod_wsgi on Apache 2.4. These issues are still being investigated. As
most new changes in 4.X relate to mod_wsgi daemon mode, which is not
supported under Windows, you should keep using the last available binary
for version 3.X on Windows instead. Binaries compiled by a third party
can be obtained from:

* http://www.lfd.uci.edu/~gohlke/pythonlibs/#mod_wsgi

Features Changed
----------------

1. The ``--ssl-port`` option has been deprecated in favour of the option
``--https-port``. Strictly speaking SSL no longer exists and has been
supplanted with TLS. The 'S' in 'HTTPS' is actually meant to mean secure
and not 'SSL'. So change name of option to properly match terminoligy.

2. The name of the startup log was changed such that naming was consistent
with how logs are normally named with Apache. That is ``startup_log``
instead of ``startup.log``, thereby matching convention with ``error_log``
and ``access_log``.

Bugs Fixed
----------

1. When a default language was specified using the ``locale`` option to
the ``WSGIDaemonProcess`` directive or the ``--locale`` option to
``mod_wsgi-express``, if it did not actually match a locale supported by
the operating system, that the locale couldn't be set wasn't logged. Such
a message is now logged along with a suggestion to use ``C.UTF-8`` as a
fallback locale if the intent is to have ``UTF-8`` support.

2. When using the ``--https-only`` option with ``mod_wsgi-express``, a HTTP
request was not being redirected to be a HTTPS request when there were no
server aliases specified.
