=============
Version 4.1.0
=============

With version 4.1.0 of mod_wsgi, a switch to a X.Y.Z version numbering
scheme from the existing X.Y scheme is being made. This is to enable a
much quicker release cycle with more incremental changes.

Version 4.1.0 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.1.0.tar.gz

Note that mod_wsgi 4.1.0 was originally derived from mod_wsgi 3.1. It has
though all changes from later releases in the 3.X branch. Thus also see:

* :doc:`version-3.2`
* :doc:`version-3.3`
* :doc:`version-3.4`
* :doc:`version-3.5`

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. If a UNIX signal received by daemon mode process while still being
initialised to signal that it should be shutdown, the process could crash
rather than shutdown properly due to not registering the signal pipe
prior to registering signal handler.

2. Python doesn't initialise codecs in sub interpreters automatically which
in some cases could cause code running in WSGI script to fail due to lack
of encoding for Unicode strings when converting them. The error message
in this case was::

  LookupError: no codec search functions registered: can't find encoding

The 'ascii' encoding is now forcibly loaded when initialising sub interpreters
to get Python to initialise codecs.

3. Fixed reference counting bug under Python 3 in SSL ``var_lookup()``
function which can be used from an auth handler to look up SSL variables.

4. The ``WWW-Authenticate`` headers returned from a WSGI application when
run under daemon mode are now always preserved as is.

Because of previously using an internal routine of Apache, way back in time
the values of multiple ``WWW-Authenticate`` headers would be merged when
there was more than one. This would cause an issue with some browsers.

A workaround was subsequently implemented above the Apache routine to break
apart the merged header to create separate ones again, however, if the
value of a header validly had a ',' in it, this would cause the header
value to be broken apart where it wasn't meant to. This could issues with
some type of ``WWW-Authenticate`` headers.

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

4. The ``inactivity-timeout`` option to ``WSGIDaemonProcess`` now only
results in the daemon process being restarted after the idle timeout period
where there are no active requests. Previously it would also interrupt a
long running request. See the new ``request-timeout`` option for a way of
interrupting long running, potentially blocked requests and restarting
the process.

5. If the ``home`` option is used with ``WSGIDaemonProcess``, in addition
to that directory being made the current working directory for the process,
an empty string will be added to the start of the Python module search
path. This causes Python to look in the current working directory for
Python modules when they are being imported.

This behaviour brings things into line with what happens when running the
Python interpreter from the command line. You must though be using the
``home`` option for this to come into play.

Do not that if your application then changes the working directory, it
will start looking in the new current working directory and not that which
is specified by the ``home`` option. This again mirrors what the normal
Python command line interpreter does.

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

8. Add ``request-timeout`` option to ``WSGIDaemonProcess`` to allow a
separate timeout to be applied on how long a request is allowed to run for
before the daemon process is automatically restarted to interrupt the
request.

This is to counter the possibility that a request may become blocked on
some backend service, thereby using up available requests threads and
preventing other requests to be handled.

In the case of a single threaded process, then the timeout will happen at
the specified time duration from the start of the request being handled.

Applying such a timeout in the case of a multithreaded process is more
problematic as doing a restart when a single requests exceeds the timeout
could unduly interfere with with requests which just commenced.

In the case of a multi threaded process, what is instead done is to take
the total of the current running time of all requests and divide that by
the number of threads handling requests in that process. When this average
time exceeds the time specified, then the process will be restarted.

This strategy for a multithreaded process means that individual requests
can actually run longer than the specified timeout and a restart will only
be performed when the overall capacity of the processes appears to be
getting consumed by a number of concurrent long running requests, or when
a specific requests has been blocked for an excessively long time.

The intent of this is to allow the process to still keep handling requests
and only perform a restart when the available capacity of the process to
handle more requests looks to be potentially on the decline.

9. Add ``connect-timeout`` option to ``WSGIDaemonProcess`` to allow a
timeout to be specified on how long the Apache child worker processes should
wait on being able to obtain a connection to the mod_wsgi daemon process.

As UNIX domain sockets are used, connections should always succeed, however
there have been some incidences seen which could only be explained by the
operating system hanging on the initial connect call without being added to
the daemon process socket listener queue. As such the timeout has been
added. The timeout defaults to 15 seconds.

This timeout also now dictates how long the Apache child worker process
will attempt to get a connection to the daemon process when the connection
is refused due to the daemon socket listener queue being full. Previously
how long connection attempts were tried was based on an internal retry
count rather than a configurable timeout.

10. Add ``socket-timeout`` option to ``WSGIDaemonProcess`` to allow the
timeout on indvidual read/writes on the socket connection between the
Apache child worker and the daemon process to be specified separately to
the Apache ``Timeout`` directive.

If this option is not specified, it will default to the value of the Apache
``Timeout`` directive.

11. Add ``queue-timeout`` option to ``WSGIDaemonProcess`` to allow a
request to be aborted if it never got handed off to a mod_wsgi daemon
process within the specified time. When this occurs a '503 Service
Unavailable' response will be returned.

This is to allow one to control what to do when backlogging of requests
occurs. If the daemon process is overloaded and getting behind, then it is
more than likely that a user will have given up on the request anyway if
they have to wait too long. This option allows you to specify that a
request that was queued up waiting for too long is discarded, allowing any
transient backlog to be quickly discarded and not simply cause the daemon
process to become even more backlogged.

12. Add ``listen-backlog`` option to ``WSGIDaemonProcess`` to allow the
daemon process socket listener backlog size to be specified. By default
this limit is 100, although this is actually a hint, as different operating
systems can have different limits on the maximum value or otherwise treat
it in special ways.

13. Add ``WSGIPythonHashSeed`` directive to allow Python behaviour related
to initial hash seed to be overridden when the interpreter supports it.

This is equivalent to setting the ``PYTHONHASHSEED`` environment variable
and should be set to either ``random`` or a number in the range in range
``[0; 4294967295]``.

14. Implemented a new streamlined way of installing mod_wsgi as a Python
package using a setup.py file or from PyPi. This includes a
``mod_wsgi-express`` script that can then be used to start up
Apache/mod_wsgi with an auto generated configuration on port 8000.

This makes it easy to run up Apache for development without interfering
with the main Apache on the system and without having to worry about
configuring Apache. Command line options can be used to override behaviour.

Once the ``mod_wsgi`` package has been installed into your Python
installation, you can run::

    mod_wsgi-express start-server

Then open your browser on the listed URL. This will verify that everything
is working. Enter CTRL-C to exit the server and shut it down.

You can now point it at a specific WSGI application script file::

    mod_wsgi-express start-server wsgi.py

For options run::

    mod_wsgi-express start-server --help

If you already have another web server running on port 8000, you can
override the port to be used using the ``--port`` option::

    mod_wsgi-express start-server wsgi.py --port 8001

15. Implemented a Django application plugin to add a ``runmodwsgi`` command
to the Django management command script. This allows the automatic run up
of the new mod_wsgi express script, with it hosting the Django web site the
plugin was added to.

To enable, once the ``mod_wsgi`` package has been installed into your
Python installation, add ``mod_wsgi.server`` to the ``INSTALLED_APPS``
setting in your Django settings file.

After having run the ``collectstatic`` Django management command, you
can then run::

    python manage.py runmodwsgi

For options run::

    python manage.py runmodwsgi --help

To enable automatic code reloading in a development setting, use the
option::

    python manage.py runmodwsgi --reload-on-changes

16. The maximum size that a response header/value can be that is returned
from a WSGI application under daemon mode can now be configured. The
default size has also now been increased from 8192 bytes to 32768 bytes.
The name of the option to ``WSGIDaemonProcess`` to set the buffer size used
is ``header-buffer-size``.
