=============
Version 4.4.6
=============

Version 4.4.6 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.6

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. Apache 2.2.29 and 2.4.11 introduce additional fields to the request
structure ``request_rec`` due to CVE-2013-5704. The addition of these
fields will cause versions of mod_wsgi from 4.4.0-4.4.5 to crash when used
in mod_wsgi daemon mode and mod_wsgi isn't initialising the new structure
members.

If you are upgrading your Apache installation to those versions or later
versions, you must also update to mod_wsgi version 4.4.6. The mod_wsgi
4.4.6 source code must have also been compiled against the newer Apache
version.

In recompiling mod_wsgi 4.4.6 source code against the newer Apache versions
the source code is able to detect the new fields exist at compile time by
checking a compile time version number.

One problem that can arise is that where a CVE is raised for a security
issue, Linux distributions will back port the change to older Apache
versions. When they do this though, the compile time version number isn't
changed, so mod_wsgi cannot detect at compile time when built against
Apache versions with the backport that the additional fields exist.

To combat this problem, mod_wsgi will do some runtime checks which look at
the actual size of ``request_rec`` and calculate whether the additional
fields have been added by way of a backported change. In this case mod_wsgi
will then set the fields as necessary.

As a final fail safe for forward compatibility. If the current mod_wsgi
source code is compiled against a version of Apache which doesn't have the
CVE change applied, it will pad the ``request_rec`` and optimistically set
the fields anyway. This is to deal with the situation where mod_wsgi is
compiled against an older Apache and then that Apache is upgraded to one
with the CVE change, but mod_wsgi is not recompiled so that the additional
fields can be detected at compile time.

2. Override ``LC_ALL`` environment variable when ``locale`` option to the
``WSGIDaemonProcess`` directive. It is not always sufficient to just call
``setlocale()`` as some Python code, including interpreter initialisation
can still consult the original ``LC_ALL`` environment variable. In this
case this can result in an undesired file system encoding still being
selected.

New Features
------------

1. Added ``--enable-gdb`` option to ``mod_wsgi-express`` for when running
in debug mode. With this option set, Apache will be started up within
``gdb`` allowing the debug of process crashes on startup or while handling
requests. If the ``gdb`` program is not in ``PATH``, the ``--gdb-executable``
option can be set to give its location.
