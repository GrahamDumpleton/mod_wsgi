=============
Version 4.2.0
=============

Version 4.2.0 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.2.0.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

New Features
------------

1. Added ``mod_wsgi.server_metrics()`` function which provides access to a
dictionary of data derived from the Apache worker scoreboard. In effect this
provides access to the same information that is used to create the Apache
server status page.

Note that if ``mod_status`` is not loaded into Apache, or the compile time
configuration of Apache prohibits the scoreboard from being available, this
function will return ``None``.

Also be aware that only partial information about worker status, and no
information about requests, will be returned if the ``ExtendedStatus``
directive is not also set to ``On``.

Although ``mod_status`` needs to be loaded, it is not necessary to enable
any URL to expose the server status page.

2. Added support for a platform plugin for New Relic to ``mod_wsgi-express``
which will report server status information up to New Relic if the
``--with-newrelic`` option is supplied when running mod_wsgi express.

That same option also enables the New Relic Python agent. If you only want
one or the other, you can instead use the ``--with-newrelic-agent`` and
``--with-newrelic-platform`` options.

The feature of ``mod_wsgi-express`` for reporting data up to the New Relic
Platform is dependent upon the separate ``mod_wsgi-metrics`` package being
installed.
