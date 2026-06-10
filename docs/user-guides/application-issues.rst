==================
Application Issues
==================

Although installation and configuration of mod_wsgi may be successful,
there are a range of issues that can impact on specific WSGI applications.
These problems can arise for various reasons, including conflicts between
an application and other Apache modules or non WSGI applications hosted by
Apache, a WSGI application not being portable, use of Python modules that
are not fully compatible with the way that mod_wsgi uses Python sub
interpreters, or dependence on a specific operating system execution
environment.

The purpose of this document is to capture problems that can arise,
including workarounds where available, related to the actual running of a
WSGI application.

If you are having a problem which doesn't seem to be covered by this
document, also make sure you see :doc:`../user-guides/installation-issues`
and :doc:`../user-guides/configuration-issues`.

Access Rights Of Apache User
----------------------------

For most Apache installations the web server is initially started up as
the ``root`` user. This is necessary as operating systems will block non
root applications from making use of Internet ports below 1024. A web
server responding to HTTP and HTTPS requests on the standard ports will
need to be able to acquire ports 80 and 443.

Once the web server has acquired these ports and forked off child
processes to handle any requests, the user that the child processes run as
will be switched to a non privileged user. The actual name of this user
varies from one system to another with some commonly used names being
``apache``, ``httpd``, ``www-data``, and ``www``. As well as the user
being switched, the web server will also normally switch to an alternate
group.

If running a WSGI application in embedded mode, the user and group that
the Apache child processes run as will be inherited by the application. To
determine which user and group would be used the main Apache configuration
files should be consulted. The particular configuration directives which
control this are ``User`` and ``Group``. For example::

    User www-data
    Group www-data

Because this user is non privileged and will generally be different to the
user that owns the files for a specific WSGI application, it is important
that such files and the directories which contain them are accessible to
others. If the files are not readable or the directories not searchable,
the web server will not be able to see or read the files and execution of
the WSGI application will fail at some point.

As well as being able to read files, if a WSGI application needs to be
able to create or edit files, it will be necessary to create a special
directory which it can use to create files in and which is owned by the
same user that Apache is running as. Any files contained in the directory
which it needs to edit should also be owned by the user that Apache is
run as, or group privileges used in some way to ensure the application
will have the required access to update the file.

Refrain from ever using directories or files which have been made writable
to anyone as this could compromise security. Also be aware that if hosting
multiple applications under the same web server, they will all run as the
same user and so it will be possible for each to both see and modify each
other's files. If this is an issue, the applications should be hosted in
separate daemon process groups so that each can run as a different user,
or hosted on different web servers running as different users, or on
different systems. Alternatively, any data required or updated by the
application should be hosted in a database with separate accounts for
each application.

Issues related to access rights can in general be avoided if daemon mode
of mod_wsgi is used to run a WSGI application. This is because in daemon
mode the user and group that the processes run as can be overridden and
set to alternate values via the ``user`` and ``group`` options to the
WSGIDaemonProcess directive. Note however the additional issues related
to the ``HOME`` environment variable as described below.

Secure Variants Of UNIX
-----------------------

In addition to the constraints imposed by Apache running as a distinct
user, some variants of UNIX have features whereby access privileges for a
specific user may be even further restricted. Examples include SELinux on
RHEL/Fedora and AppArmor on Ubuntu. In such systems, the user that Apache
runs as is typically restricted to only being able to access quite
specific parts of the file system as well as possibly other resources or
operating system library features.

Basic SELinux/AppArmor configuration for getting mod_wsgi running at all
is covered in :doc:`../user-guides/configuration-issues`. The notes here
relate to additional issues that can show up at application runtime even
after the basic configuration is in place.

The extra security checks of such a system may present problems with
loading C extension modules at runtime for Python. SELinux has been seen
to cause errors of the form::

    ImportError: <path to .so>: failed to map segment from shared object: \
     Permission denied

If you suspect that an issue may be caused by SELinux, you could
temporarily try disabling it and doing a restart to verify whether it is
the cause, but always re-enable it. The standard tools for working out
which boolean or context needs to be adjusted are ``ausearch`` against
``/var/log/audit/audit.log`` and ``audit2allow``.

Application Working Directory
-----------------------------

When Apache is started it is typically run such that the current working
directory for the application is the root directory, although the actual
directory may vary dependent on the system or any extra security system in
place.

Importantly, the current working directory will generally never have any
direct relationship to any specific WSGI application. As a result, an
application should never assume that it can use relative path names for
accessing the filesystem. All paths used should always be absolute path
names.

An application should also never change the current working directory and
then assume that it can then use relative paths. This is because other
applications being hosted on the same web server may assume they can do
the same thing with the result that you can never be sure what the current
working directory may actually be.

You should not even assume that it is safe to change the working directory
immediately prior to a specific operation, as use of multithreading can
mean that another application could change it even before you get to
perform the operation which depended on the current working directory
being the value you set it to.

In the case of Python, if needing to use relative paths in order to make
it easier to relocate an application, one can determine the directory
that a specific code module is located in using
``os.path.dirname(__file__)``. A full path name can then be constructed
by using ``os.path.join()`` to merge the relative path with the directory
name where the module was located.

Another option is to take the directory part of the ``SCRIPT_FILENAME``
variable from the WSGI environment as the base directory. The only other
alternative is to rely on a centralised configuration file so that all
absolute path names are at least defined in the one place.

Although it is preferable that an application never make assumptions
about what the current working directory is, if for some reason the
application cannot be changed the daemon mode of mod_wsgi could be used.
This will work as an initial current working directory for the process
can be specified as the ``home`` option to the WSGIDaemonProcess
directive used to configure the daemon process. Because the working
directory applies to the whole process however, only the application
requiring this working directory should be delegated to run within the
context of that daemon process.

Application Environment Variables
---------------------------------

When Python sub interpreters are created, each has its own copy of any
modules which are loaded. They also each have their own copy of the set
of environment variables inherited by the process and found in
``os.environ``.

Problems can arise with the use of ``os.environ`` though, due to the
fact that updates to ``os.environ`` are pushed back into the set of
process environment variables. This means that if the Python sub
interpreter which corresponds to another application group is created
after ``os.environ`` has been updated, the new value for that
environment variable will be inherited by the new Python sub interpreter.

It would seem at first that this is not a problem when a WSGI
application is configured by a single mandatory environment variable,
since each application's WSGI script file would set that variable
unconditionally and override any value inherited from another
application. That assumption breaks down when the application uses
``os.environ.setdefault()`` rather than direct assignment.

The most common real-world case is Django. Django's generated
``wsgi.py`` sets ``DJANGO_SETTINGS_MODULE`` using ``setdefault``::

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mysite.settings")

When two Django instances are hosted in the same Apache process, the
first ``wsgi.py`` to load successfully sets the variable. Because
``os.environ`` writes are pushed back into the process environment,
when mod_wsgi creates the sub interpreter for the second instance the
new ``os.environ`` is populated from the process environment and
already contains the first instance's settings module name. The second
``wsgi.py``'s ``setdefault`` call is therefore a no-op, and the second
Django instance ends up loading the first instance's settings.

The failure mode is sometimes obvious — an ``ImportError`` if the
first instance's settings module is not importable inside the second
instance — but is often silent: requests for the second site are
served using the first site's database, ``ALLOWED_HOSTS``, middleware
and so on. Symptoms can include requests appearing to be served by the
wrong project, sessions and CSRF tokens behaving inconsistently, and
``Site``/``ALLOWED_HOSTS`` checks failing in ways that look random.

The simplest fix at the application level is to replace ``setdefault``
with direct assignment in the WSGI script file::

    os.environ["DJANGO_SETTINGS_MODULE"] = "mysite.settings"

The more robust fix is to run each Django instance in its own daemon
process group via WSGIDaemonProcess so that each gets its own process
and its own process environment.

Where use of environment variables can be problematic in a more
general way is where there are multiple environment variables that
can be set, with some being optional, and where non overlapping sets
of variables are used to configure different modes. If two
applications hosted in the same process each set a different subset
of such variables, the second to load will inherit the first's
variables in addition to its own and behave incorrectly.

Because of this potential leakage of environment variables between Python
sub interpreters, it is preferable that WSGI applications not rely on
environment variables for configuration.

A further reason that environment variables should not be used for
configuration is that it then becomes impossible to host two instances of
the same WSGI application component within the same Python sub
interpreter if each would require a different value be set for the same
environment variable. Note that this also applies to other means of
hosting WSGI applications besides mod_wsgi and is not mod_wsgi specific.

As a consequence, because Django relies on
``DJANGO_SETTINGS_MODULE`` being set, it is also impossible to host
two Django instances configured for different settings modules within
a single Python sub interpreter. Where there are multiple instances of
Django that need to run on the same web server, they must run in
separate Python sub interpreters — and, given the ``setdefault`` issue
described above, ideally in separate processes via daemon mode.

The default behaviour of mod_wsgi is to run different WSGI application
scripts within the context of different Python sub interpreters. As
such, the requirement for separate sub interpreters is met by default;
the remaining failure mode is the ``setdefault`` interaction across
sub interpreters within the same process, which is why daemon mode
with one process group per Django site is the recommended deployment
pattern.

The preferred way of configuring a WSGI application is for the
application to be a class instance which at the point of initialisation
is provided with its configuration data as an argument. Alternatively,
or in conjunction with this, configuration information can be passed
through to the WSGI application in the WSGI environment. Variables in
the WSGI environment could be set by a WSGI middleware component, or
from the Apache configuration files using the ``SetEnv`` directive.

Configuring an application when it is first constructed, or by supplying
the configuration information through the WSGI environment variables, is
thus the only way to ensure that a WSGI application is portable between
different means of hosting WSGI applications. These problems can also be
avoided by using daemon mode of mod_wsgi and delegating each WSGI
application instance to a distinct daemon process group.

Timezone and Locale Settings
----------------------------

More insidious than the problem of leakage of application environment
variable settings between sub interpreters, is where an environment
variable is required by operating system libraries to set behaviour.

This is a problem because applications running in different sub
interpreters could set the process environment variable to be different
values. Rather than each seeing behaviour consistent with the setting
they used, all applications will see behaviour reflecting the setting as
determined by the last application to initialise itself.

Process environment variables where this can be a problem are the ``TZ``
environment variable for setting the timezone, and the ``LANG``,
``LC_TYPE``, ``LC_COLLATE``, ``LC_TIME`` and ``LC_MESSAGES`` environment
variables for setting the locale and language settings.

The result of this is that you cannot host multiple WSGI applications in
the same process, even if running in different sub interpreters, if they
require different settings for timezone, locale and/or language.

In this situation you would have no choice but to use mod_wsgi daemon
mode and delegate applications requiring different settings to different
daemon process groups. Alternatively, completely different instances of
Apache should be used.

Timezones and the Apache Error Log
----------------------------------

A related, but more visible, consequence of the timezone issue described
above shows up in the Apache error log itself rather than in application
behaviour.

Apache prefixes each line it writes to the error log with a timestamp.
That timestamp is formatted by the process which emits the line, using
that process's current timezone as determined by the ``TZ`` environment
variable. The Apache parent process and the child worker processes
normally retain the timezone Apache was started with, but a WSGI
application running in daemon mode is able to change the timezone of the
mod_wsgi daemon process it runs in.

The most common way this happens is Django. When ``TIME_ZONE`` is set in a
Django project's settings, Django assigns ``os.environ["TZ"]`` and then
calls ``time.tzset()``. Because ``tzset()`` acts on the whole process, the
daemon process from that point on formats all of its log line timestamps,
both those written by Apache for that process and those written by the
application's own logging, in the application's timezone.

The Apache child worker processes are a separate matter. In daemon mode
the child worker processes are the ones which accept the request and
proxy it to the daemon process, and they continue to use the timezone
inherited from the Apache parent process. A request therefore touches two
processes with potentially different timezones: the ``wsgi:error`` lines
written by the daemon process are stamped in the application's timezone,
while lines written by the child worker process for the same request,
such as ``ssl:info`` messages, are stamped in the parent process's
timezone. Because both go to the same error log, the leading timestamps
appear to jump backwards and forwards between the two timezones depending
on which process emitted each line. For example, on a host where Apache
was started in ``Europe/Berlin`` but the Django site sets
``TIME_ZONE = "UTC"``::

    21:33:00 ... [wsgi:error] ... (daemon process, application TZ=UTC)
    22:33:05 ... [ssl:info]  ... (Apache child worker process, Apache TZ)

This is confusing to read but is not in itself a malfunction. The
underlying events occur at the same real instant; only the timezone used
to format them differs. The behaviour is independent of which Apache MPM
is in use, since it derives from the daemon process having a different
process-wide ``TZ`` value than the child worker processes, not from
threading.

The only effective fix is to make the Apache parent process start with the
same timezone the application uses, so that the parent, the child worker
processes and the daemon process all agree. Set ``TZ`` in the environment
Apache is started from, for example in the Apache ``envvars`` file or the
systemd unit for the service::

    export TZ=UTC

Setting it to ``UTC`` is usually the most convenient choice, since it
matches the default for many applications, including Django when
``TIME_ZONE`` is left at its ``UTC`` default. If the application uses a
different timezone, set ``TZ`` to that same timezone instead.

Where you are not able to change how Apache is started, a log format
directive offers a partial mitigation, though not a cure. It is worth
being clear about its limits, because reaching for the log configuration
is the natural first instinct. No ``ErrorLogFormat`` or ``CustomLog`` /
``LogFormat`` option can force these timestamps to a fixed zone such as
UTC; ``%t`` is always formatted from the emitting process's local time,
derived from ``TZ``. What a log format *can* do is make the timezone of
each line explicit, so that lines stamped by processes in different
timezones can be told apart rather than silently misread.

In an ``ErrorLogFormat`` the ``%t`` field accepts a small set of single
letter options inside the braces:

* ``%t`` produces the default ``ctime`` style, ``Fri Jun 05 08:42:44 2026``.
* ``%{u}t`` is the same but with microseconds. This is what the Apache
  default ``ErrorLogFormat`` uses.
* the ``c`` option switches to the compact ISO 8601 form,
  ``2026-06-05 08:42:36``.
* the ``z`` option (Apache 2.4.58 and later) appends the numeric timezone
  offset, ``+1000``.

The options combine, so ``%{cu}t`` is compact ISO 8601 with microseconds
but still no offset, and ``%{cuz}t`` is that with the offset added on the
end.

To keep the familiar default layout and simply add the timezone offset,
take the Apache default ``ErrorLogFormat`` and change its ``%{u}t`` field
to ``%{uz}t``::

    ErrorLogFormat "[%{uz}t] [%-m:%l] [pid %P:tid %T] %7F: %E: [client\ %a] %M% ,\ referer\ %{Referer}i"

A line then looks like the following, identical to the default apart from
the trailing ``+1000``::

    [Fri Jun 05 08:42:29.986168 2026 +1000] [mpm_event:notice] [pid 37192:tid 140704575428864] AH00489: ...

If you prefer the compact ISO 8601 timestamp, use ``%{cuz}t`` instead::

    ErrorLogFormat "[%{cuz}t] [%-m:%l] [pid %P:tid %T] %7F: %E: [client\ %a] %M% ,\ referer\ %{Referer}i"

    [2026-06-05 08:42:36.978307 +1000] [mpm_event:notice] [pid 37243:tid 140704575428864] AH00489: ...

A word of caution about the syntax. The ``c``, ``u`` and ``z`` letters are
options, not ``strftime`` conversions, and must appear directly inside the
braces with no leading ``%``. If you write ``%{%cuz}t`` instead of
``%{cuz}t``, the leading ``%`` switches the field into ``strftime`` mode,
where ``%c`` expands to the C library's locale date and time and the
remaining ``uz`` is copied through literally, producing nonsense such as
``Fri Jun  5 08:42:25 2026uz``.

This distinction also matters across platforms. The ``c``, ``u`` and ``z``
options are formatted by Apache itself and behave identically on Linux,
macOS and Windows. The ``strftime`` forms, such as ``%{%d/%b/%Y %T}t``,
are passed to the platform C library's ``strftime(3)``, whose set of
supported conversions varies; Windows in particular omits or alters
several of them, with ``%z`` for example yielding a timezone name rather
than a numeric offset. Preferring ``%{cuz}t`` over a hand written
``strftime`` string therefore also gives consistent output everywhere.

Adding the offset lets the two timezones be distinguished, but it does not
make them consistent. The only way to have every process agree remains to
start the Apache parent process with the same ``TZ`` the application uses,
as described above.

All of the above concerns the error log specifically. The access log does
not suffer the same silent confusion, for two reasons. First, its default
format already includes the timezone offset: the standard ``common`` and
``combined`` ``LogFormat`` definitions use ``%t``, which mod_log_config
renders in Common Log Format, with the offset built in::

    ::1 - - [05/Jun/2026:09:07:53 +1000] "GET / HTTP/1.1" 200 12

Second, in daemon mode the access log is written by the Apache child worker
process, since that is where mod_log_config runs as it proxies the
request. The worker keeps the Apache parent's ``TZ`` and never runs the
application, so its timezone cannot be changed by the application's call to
``tzset()``. Access log lines therefore stay in one consistent timezone,
unlike error log lines which mix the daemon process's application timezone
with the worker process's timezone. The access log timestamp is still
local time rather than UTC, so the parent-process ``TZ`` fix is still what
to reach for if UTC is required, but the access log never exhibits the
silent, hard to spot divergence that the error log does.

Be aware also that this only addresses divergence between processes. If a
single daemon process hosts multiple sub interpreters that set different
timezones, the process-global ``TZ`` value is shared and the last sub
interpreter to initialise wins, exactly as described in the previous
section. The only robust solution there remains delegating applications
that require different timezones to separate daemon process groups.

User HOME Environment Variable
------------------------------

If Apache is started automatically as ``root`` when a machine is first
booted it would inherit the ``HOME`` environment variable of the
``root`` user. If however Apache is started by a non privileged user via
the ``sudo`` command, it would inherit the ``HOME`` of the user who
started it, unless the ``-H`` option had been supplied to ``sudo``. With
``-H``, the ``HOME`` of the ``root`` user would again be used.

Because the value of ``HOME`` can vary based on how Apache has been
started, an application running in embedded mode should not depend on
``HOME``.

Unfortunately, parts of the Python standard library do use ``HOME`` as
an authoritative source of information. In particular, ``os.path.expanduser()``
gives precedence to the value of ``HOME`` over the home directory as
obtained from the user password database entry, which means it can yield
incorrect results when ``HOME`` is set to whatever ``root`` or the
invoking user happened to have.

The only way to guarantee that ``HOME`` is set to a sensible value in
embedded mode is to set it explicitly at the start of the WSGI script
file before anything else is done::

    import os, pwd
    os.environ["HOME"] = pwd.getpwuid(os.getuid()).pw_dir

In daemon mode the value of ``HOME`` is automatically reset to
correspond to the home directory of the user that the daemon process is
running as. This is not done for embedded mode because the Apache child
processes are shared with other Apache modules and it is not appropriate
that mod_wsgi should be changing the same environment that is used by
those other modules.

For some consistency in the environment inherited by applications running
in embedded mode, it is recommended that ``sudo -H`` always be used when
restarting Apache from a non root account.

Application Global Variables
----------------------------

Because the Python sub interpreter which hosts a WSGI application is
retained in memory between requests, any global data is effectively
persistent and can be used to carry state forward from one request to the
next. On UNIX systems however, Apache will normally use multiple
processes to handle requests and each such process will have its own
global data.

This means that although global data can be used, it can only be used
to cache data which can be safely reused within the context of that
single process. You cannot use global data as a means of holding
information that must be visible to any request handler no matter which
process it runs in.

If data must be visible to all request handlers across all Apache
processes, then it will be necessary to store the data in the filesystem
directly, or using a database. Alternatively, shared memory can be
employed by using a package such as memcached or Redis.

Because your WSGI application can be spread across multiple processes,
one must also be very careful in respect of local caching mechanisms
employed by database connector objects. If such an adapter is quite
aggressive in its caching, it is possible that a specific process may
end up with an out of date view of data from a database where one of the
other processes has since changed the data. The result may be that
requests handled in different processes may give different results.

The problems described above can be alleviated to a degree by using
daemon mode of mod_wsgi and restricting to one the number of daemon
processes in the process group. This will ensure that all requests are
serviced by the same process. If the data is only held in memory, it
would however obviously be lost when Apache is restarted or the daemon
process is restarted due to a maximum number of requests being reached.

Writing To Standard Output
--------------------------

A portable WSGI application should not write to standard output. That is,
an application should not use ``print`` without redirecting output to an
alternate stream, and should not write directly to ``sys.stdout``.

This is necessary as an underlying WSGI adapter hosting the application
may use standard output as the means of communicating a response back to
a web server. This technique is for example used when WSGI is hosted
within a CGI script.

Under mod_wsgi the default behaviour is that anything written to
``sys.stdout`` is redirected through the Apache logging system and ends
up in the main Apache error log. The restriction that earlier mod_wsgi
versions imposed (raising ``IOError: sys.stdout access restricted by
mod_wsgi``) is off by default and has been since mod_wsgi 3.0. See
:doc:`../configuration-directives/WSGIRestrictStdout` for the directive
that can re-enable the restriction if required.

Even though mod_wsgi will let writes to ``sys.stdout`` succeed by
redirecting them to the error log, application code should still prefer
``sys.stderr`` (or proper logging) explicitly::

    import sys

    def function():
        print("application debug", file=sys.stderr)

Application code should also not make assumptions about the environment
it is executing in by checking whether ``sys.stdout`` is a tty.

For further information about options for logging error messages and
other debugging information from a WSGI application running under
mod_wsgi see :doc:`../user-guides/debugging-techniques`.

Reading From Standard Input
---------------------------

A portable WSGI application should not read from standard input. That is,
an application should not read directly from ``sys.stdin``, either
directly or indirectly.

This is necessary as an underlying WSGI adapter hosting the application
may use standard input as the means of receiving a request from a web
server. This technique is for example used when WSGI is hosted within a
CGI script.

Under mod_wsgi the default behaviour is that ``sys.stdin`` is whatever
the hosting process inherits — typically a closed or ``/dev/null``
stream — so reads will return no data rather than raising an exception.
The restriction that earlier mod_wsgi versions imposed (raising
``IOError: sys.stdin access restricted by mod_wsgi``) is off by default
and has been since mod_wsgi 3.0. See
:doc:`../configuration-directives/WSGIRestrictStdin` for the directive
that can re-enable the restriction if required.

The lack of usable standard input means interactive debuggers such as
``pdb`` cannot be driven through ``sys.stdin`` in the normal mod_wsgi
case. Apache normally uses multiple processes and child processes have
no controlling terminal. To run an interactive debugger you must run
Apache in single-process debug mode by shutting down your normal
instance and invoking ``httpd`` directly::

    httpd -X

For more details on using interactive debuggers in the context of
mod_wsgi see :doc:`../user-guides/debugging-techniques`.

Registration Of Signal Handlers
-------------------------------

Web servers upon which WSGI applications are hosted use signals to
control their operation. Apache in particular uses ``SIGTERM``,
``SIGINT``, ``SIGHUP``, ``SIGWINCH`` and ``SIGUSR1``. mod_wsgi daemon
mode also relies on signals for shutdown, restart and request-recycling
behaviour.

If a WSGI application were to register its own signal handlers it could
interfere with the operation of the underlying web server, preventing it
from being shut down or restarted properly, and similarly interfering
with mod_wsgi daemon process recycling. As a general rule therefore, no
WSGI application component should attempt to register its own signal
handlers.

To enforce this, mod_wsgi by default intercepts all attempts to register
signal handlers and ignores them. As notification that this is being
done, a message is logged to the Apache error log of the form::

    Ignoring Python signal handler registration for signal 1 in WSGI \
    process; mod_wsgi manages signals.

A Python stack traceback identifying where the registration was
attempted is logged immediately after the message. Both the message
and the traceback are emitted at ``info`` level, so the LogLevel needs
to be raised for mod_wsgi to see them — for example ``LogLevel warn
wsgi:info``.

If for some reason a WSGI application genuinely needs to install a signal
handler, the restriction can be disabled by setting the directive::

    WSGIRestrictSignal Off

See :doc:`../configuration-directives/WSGIRestrictSignal` for the full
behaviour, including the requirement that any handler registration must
be performed from the main thread (typically via WSGIImportScript).

Pickling of Python Objects
--------------------------

The script files that mod_wsgi uses as the entry point for a WSGI
application, although containing Python code, are not treated exactly
the same as a Python code module. This has implications when it comes to
using the ``pickle`` module in conjunction with objects contained within
the WSGI application script file.

In practice what this means is that neither function objects, class
objects nor instances of classes which are defined in a WSGI application
script file should be stored using the ``pickle`` module.

In order to ensure that no strange problems are likely to occur, it is
suggested that only basic builtin Python types — scalars, tuples, lists
and dictionaries — be stored using the ``pickle`` module from a WSGI
application script file. That is, avoid any type of object which has
user-defined code associated with it.

The technical reasons for the limitations in the use of the ``pickle``
module in conjunction with WSGI application script files are further
discussed in :doc:`../user-guides/issues-with-pickle-module`. Note that
the limitations do not apply to standard Python modules and packages
imported from within a WSGI application script file from directories on
the standard Python module search path.

.. _python-simplified-gil-state-api:

Multiple Python Sub Interpreters
--------------------------------

By default mod_wsgi runs each WSGI application in its own Python sub
interpreter (application group), which provides isolation between
applications hosted on the same Apache instance. While this works well
for pure-Python code, some C extension modules are not designed to work
correctly outside the main Python interpreter. Two distinct categories
of failure are common.

The first category is C extensions that use the simplified GIL state
API (``PyGILState_Ensure`` / ``PyGILState_Release``) and assume that
the "current" interpreter is the main interpreter. When such code
runs in a sub interpreter, the result is typically a deadlock or
process crash. The same kind of failure can also be triggered by
extensions that hold raw references to the main interpreter's state
in static variables.

The second category is C extensions that cache Python objects (type
objects, callables, module references) at module-load time and reuse
those cached references from sub interpreters loaded later. Because
those objects belong to whichever interpreter loaded the extension
first, using them from another interpreter mixes code and data across
interpreter boundaries. The most visible consequences are
``isinstance()`` checks failing because the type object is not the local
type object, file or socket objects raising errors when used from a
different interpreter, and outright crashes when the originating
interpreter has since been destroyed.

The most prominent extensions affected today are NumPy, SciPy and
modules built on top of them, but the issue is not limited to those
packages — it can show up in any C extension whose author did not
explicitly design for sub interpreter use.

The standard workaround is to force the affected WSGI application to
run in the main Python interpreter by setting::

    WSGIApplicationGroup %{GLOBAL}

If multiple WSGI applications need this and need to remain isolated from
each other, run each in its own daemon process group — the daemon
process gets its own main interpreter. The full trade-off (single shared
namespace versus per-application isolation) is described in the
"WSGIApplicationGroup and C extension modules" section of
:doc:`../user-guides/configuration-issues`.

Memory Constrained VPS Systems
------------------------------

Virtual Private Server (VPS) systems typically have constraints imposed
on them in regard to the amount of memory or resources they are able to
use. The two relevant ones for mod_wsgi are usually:

*Memory Limit*
    Maximum virtual memory size a VPS/context can allocate.

*Context RSS Limit*
    Maximum resident memory size a VPS/context can allocate.

When the summary virtual memory size used by the VPS exceeds the Memory
Limit, processes can't allocate the required memory and will fail in
unexpected ways. The general recommendation is that Context RSS Limit be
set to one third of Memory Limit.

Some VPS providers however set too restrictive a value on the Memory
Limit, such that virtual memory use will exceed the Memory Limit even
before actual resident use approaches Context RSS Limit.

This is especially a problem on Linux, which uses a default per-thread
stack size of 8MB. When using a multi-threaded Apache MPM (worker or
event), or mod_wsgi daemon mode with multiple worker threads, the
amount of virtual memory reserved for thread stacks adds up quickly and
can exceed an artificially low Memory Limit.

If your VPS Memory Limit is being exceeded by the amount of virtual
memory set aside by all applications running in the VPS, you can lower
the per-thread stack size in two places.

For Apache child process threads (used in embedded mode and to dispatch
requests to daemons), use the Apache ``ThreadStackSize`` directive::

    ThreadStackSize 524288

For mod_wsgi daemon process worker threads, use the ``stack-size``
option to WSGIDaemonProcess::

    WSGIDaemonProcess example stack-size=524288

If a WSGI application creates its own threads for performing background
activities, it is also preferable that they override the stack size set
aside for that thread::

    import threading
    threading.stack_size(524288)

Another option is to override the process stack size, which Linux
inherits as the per-thread stack size in the absence of an explicit
override. If you are using a standard Apache distribution, this can be
done by adding to the ``envvars`` file for the Apache installation::

    ulimit -s 512

If using a customised Apache installation, the ``envvars`` file may not
exist; in that case the limit can be set in the systemd unit or other
startup mechanism for the Apache service.

Although 512KB is given here as an example, you may in practice need to
adjust this higher if you are using third party C extension modules for
Python which allocate significant amounts of memory on the stack.
