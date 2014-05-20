=============
Version 4.1.0
=============

With version 4.1.0 of mod_wsgi, a switch to a X.Y.Z version numbering
scheme from the existing X.Y scheme is being made. This is to enable a
much quicker release cycle with more incremental changes.

The working version of mod_wsgi 4.1.0 can currently be obtained by checking
it out from the source code repository.

  https://github.com/GrahamDumpleton/mod_wsgi/tree/feature/4.1

Alternatively, it can be downloaded as a tar.gz file from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/feature/4.1.tar.gz

Note that mod_wsgi 4.1.0 was originally derived from mod_wsgi 3.1. It has
though all changes from later releases in the 3.X branch. Thus also see:

* :doc:`version-3.2`
* :doc:`version-3.3`
* :doc:`version-3.4`
* :doc:`version-3.5`

Bugs Fixed
----------

1. If a UNIX signal received by daemon mode process while still being
initialised to signal that it should be shutdown, the process could crash
rather than shutdown properly due to not registering the signal pipe
prior to registering signal handler.

2. Python doesn't initialise codes in sub interpreters automatically which
in some cases could cause code running in WSGI script to fail due to lack
of encoding for Unicode strings when converting them. The error message
in this case was::

  LookupError: no codec search functions registered: can't find encoding

The 'ascii' encoding is now forcibly loaded when initialising sub interpreters
to get Python to initialise codecs.

Features Removed
----------------

1. No longer support the use of mod_python in conjunction with mod_wsgi.
When this is attempted an error is forced and Apache will not be able to
start. An error message is logged in main Apache error log.

2. No longer support the use of Apache 1.3. Minimum requirement is now
Apache 2.0.

Features Changed
----------------

1. Use of kernel ``sendfile()`` function by ``wsgi.file_wrapper`` is now
off by default. This was originally always on for embedded mode and
completely disabled for daemon mode. Use of this feature can be enabled for
either mode using ``WSGIEnableSendfile`` directive, setting it to ``On`` to
enable it.

The default is now off because kernel ``sendfile()`` is not always able to
work on all file objects. Some instances where it will not work are
described for the Apache ``EnableSendfile`` directive.

  http://httpd.apache.org/docs/2.2/mod/core.html#enablesendfile

Although Apache has use of ``sendfile()`` enabled by default for static
files, they are moving to having it off by default in future version of
Apache. This change is being made because of the problems which arise and
users not knowing how to debug it and solve it.

Thus also erring on side of caution and having it off by default but
allowing more knowledgeable users to enable it where they know always using
file objects which will work with ``sendfile()``.

2. The ``HTTPS`` variable is no longer set within the WSGI environment. The
authoritative indicator of whether a SSL connection is used is
``wsgi.url_scheme`` and a WSGI compliant application should check for
``wsgi.url_scheme``. The only reason that ``HTTPS`` was supplied at all was
because early Django versions supporting WSGI interface weren't correctly
using ``wsgi.url_scheme``. Instead they were expecting to see ``HTTPS`` to
exist.

This change will cause non conformant WSGI applications to finally break.
This possibly includes some Django versions prior to Django version 1.0.

Note that you can still set ``HTTPS`` in Apache configuration using the
``SetEnv`` or ``SetEnvIf`` directive, or via a rewrite rule. In that case,
that will override what ``wsgi.url_scheme`` is set to and once
``wsgi.url_scheme`` is set appropriately, the ``HTTPS`` variable will be
removed from the set of variables passed through to the WSGI environment.

3. The ``wsgi.version`` variable has been reverted to 1.0 to conform to the
WSGI PEP 3333 specification. It was originally set to 1.1 on expectation
that revised specification would use 1.1 but that didn't come to be.

New Features
------------

1. Add ``supplementary-groups`` option to ``WSGIDaemonProcess`` to allow
group membership to be overridden and specified comma separate list of
groups used instead.

2. Add a ``graceful-timeout`` option to ``WSGIDaemonProcess``. This option
is applied in a number of circumstances.

When ``maximum-requests`` and this option are used together, when maximum
requests is reached, rather than immediately shutdown, potentially
interupting active requests if they don't finished with shutdown timeout,
can specify a separate graceful shutdown period. If the all requests are
completed within this time frame then will shutdown immediately, otherwise
normal forced shutdown kicks in. In some respects this is just allowing a
separate shutdown timeout on cases where requests could be interrupted and
could avoid it if possible.

When ``cpu-time-limit`` and this option are used together, when CPU time
limit reached, rather than immediately shutdown, potentially interupting
active requests if they don't finished with shutdown timeout, can specify a
separate graceful shutdown period.

3. Add potentially graceful process restart option for daemon processes
when sent a graceful restart signal. Signal is usually ``SIGUSR1`` but is
platform dependent as using same signal as Apache would use. If the
``graceful-timeout`` option had been provided to ``WSGIDaemonProcess``,
then the process will attempt graceful shutdown first based on the that
timeout, otherwise normal shutdown procedure used as if received a
``SIGTERM``.

4. Add ``memory-limit`` option to ``WSGIDaemonProcess`` to allow memory
usage of daemon processes to be restricted. This will have no affect on
some platforms as ``RLIMIT_AS``/``RLIMIT_DATA`` with ``setrlimit()`` isn't
always implemented. For example MacOS X and older Linux kernel versions do
not implement this feature. You will need to test whether this feature
works or not before depending on it.

5. Add ``virtual-memory-limit`` option to ``WSGIDaemonProcess`` to allow
virtual memory usage of daemon processes to be restricted. This will have
no affect on some platforms as ``RLIMIT_VMEM`` with ``setrlimit()`` isn't
always implemented. You will need to test whether this feature works or not
before depending on it.

6. Access, authentication and authorisation hooks now have additional keys
in the environ dictionary for ``mod_ssl.is_https`` and
``mod_ssl.var_lookup``. These equate to callable functions provided by
``mod_ssl`` for determining if the client connection to Apache used SSL and
what the values of variables specified in the SSL certifcates, server or
client, are. These are only available if Apache 2.0 or later is being used.

7. For Python 2.6 and above, the ``WSGIDontWriteBytecode`` directive can be
used at global scope in Apache configuration to disable writing of all byte
code files, ie., .pyc, by the Python interpreter when it imports Python
code files. To disable writing of byte code files, set directive to ``On``.

Note that this doesn't prevent existing byte code files on disk being used
in preference to the corresponding Python code files. Thus you should first
remove ``.pyc`` files from web application directories if relying on this
option to ensure that ``.py`` file is always used.
