==============
Version 4.4.22
==============

Version 4.4.22 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.22

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. Stack traces logged at ``INFO`` level when a request timeout occurred
were not displaying correctly when Python 3 was being used. It is possible
that the logging code could also have caused the process to then crash as
the process was shutting down.

2. When using the ``--url-alias`` option with ``mod_wsgi-express`` and the
target directory had a trailing slash, that trailing slash was being
incorrectly dropped. This would cause URL lookup to fail when the URL for
the directory was a sub URL and also had a trailing slash.

New Features
------------

1. When using ``mod_wsgi-express``, rewrite rules can now be added into the
``rewrite.conf`` file located under the server root directory. An alternate
location for the rewrite rules can be specified using the ``--rewrite-rules``
option.

Note that the rewrite rules are included within a ``Directory`` block of
the Apache configuration file, for the document root directory. Any rules
therefore needs to be written so as to work in this context.

If you need to debug the rewrite rules and are using Apache 2.4, the
easiest way to enable rewrite logging is to use the ``--log-level`` option
with the quoted value of ``'info rewrite:trace8'``.
