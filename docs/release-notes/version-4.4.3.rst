=============
Version 4.4.3
=============

Version 4.4.3 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.3

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

1. The ``--lang`` option to ``mod_wsgi-express`` has been deprecated. Any
default language locale setting should be set exclusively using the
``--locale`` option.

2. The behaviour of the ``--locale`` option to ``mod_wsgi-express`` has
changed. Previously if this option was not defined, then both of the locales
``en_US.UTF-8`` and ``C.UTF-8`` have at times been hardwired as the default
locale. These locales are though not always present. As a consequence, a
new algorithm is now used.

If the ``--locale`` option is supplied, the argument will be used as the
locale. If no argument is supplied, the default locale for the executing
``mod_wsgi-express`` process will be used. If that however is ``C`` or
``POSIX``, then an attempt will be made to use either the ``en_US.UTF-8``
or ``C.UTF-8`` locales and if that is not possible only then fallback to
the default locale of the ``mod_wsgi-express`` process.

In other words, unless you override the default language locale, an attempt
is made to use an English language locale with ``UTF-8`` encoding.

3. Unless the process name is overridden using ``--process-name`` option
to ``mod_wsgi-express``, the Apache parent and child worker process will
be given a name such as ``httpd (mod_wsgi-express)`` making them more
easily distinguishable from a traditional Apache installation.

Bugs Fixed
----------

1. The ``mod_wsgi-express`` script would fail on startup if the user had
a corresponding group ID which didn't actually match an existing group in
the groups file and no override group was being specified. When this
occurs, the group will now be specified as ``#nnn`` where ``nnn`` is the
group ID.

New Features
------------

1. Added ``--process-name`` option to ``mod_wsgi-express`` to allow the
name of the Apache parent process to be overridden as it would be displayed
in ``ps``. This is necessary under some process manager systems where it
looks for a certain name, but with shell script wrappers and exec calls
happening around ``mod_wsgi-express`` the name would change.
