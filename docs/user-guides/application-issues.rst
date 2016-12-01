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

The purpose of this document is to capture all the known problems that can
arise, including workarounds if available, related to the actual running
of a WSGI application.

Note that the majority of these issues are not unique to mod_wsgi and would
also affect mod_python as well. This is because they arise due to the fact
that the Python interpreter is being embedded within the Apache server
itself. Unlike mod_python, in mod_wsgi there are ways of avoiding many of
the problems by using daemon mode.

If you are having a problem which doesn't seem to be covered by this
document, also make sure you see :doc:`../user-guides/installation-issues`
and :doc:`../user-guides/configuration-issues`.

Access Rights Of Apache User
----------------------------

For most Apache installations the web server is initially started up as
the root user. This is necessary as operating systems will block non root
applications from making use of Internet ports below 1024. A web server
responding to HTTP and HTTPS requests on the standard ports will need to
be able to acquire ports 80 and 443.

Once the web server has acquired these ports and forked off child processes
to handle any requests, the user that the child processes run as will be
switched to a non privileged user. The actual name of this user varies from
one system to another with some commonly used names being 'apache',
'httpd', 'www', and 'wwwserv'. As well as the user being switched, the web
server will also normally switch to an alternate group.

If running a WSGI application in embedded mode with mod_wsgi, the user and
group that the Apache child processes run as will be inherited by the
application. To determine which user and group would be used the main
Apache configuration files should be consulted. The particular
configuration directives which control this are ``User`` and ``Group``.
For example::

    User www
    Group www

Because this user is non privileged and will generally be different to the
user that owns the files for a specific WSGI application, it is important
that such files and the directories which contain them are accessible to
others. If the files are not readable or the directories not searchable,
the web server will not be able to see or read the files and execution of
the WSGI application will fail at some point.

As well as being able to read files, if a WSGI application needs to be able
to create or edit files, it will be necessary to create a special directory
which it can use to create files in and which is owned by the same user
that Apache is running as. Any files contained in the directory which it
needs to edit should also be owned by the user that Apache is run as, or
group privileges used in some way to ensure the application will have the
required access to update the file.

One example of where access rights can be a problem in Python is with
Python eggs which need to be unpacked at runtime by a WSGI application.
This issue arises with Trac because of its ability for plugins to be
packaged as Python eggs. Pylons with its focus on being able to support
Python eggs in its deployment mechanism can also be affected. Because
of the growing reliance on Python eggs however, the issue could arise
for any WSGI application where you have installed Python eggs in their
zipped up form rather than their unpacked form.

If your WSGI application is affected by this problem in relation to Python
eggs, you would generally see a Python exception similar to the following
occuring and being logged in the Apache error logs::

    ExtractionError: Can't extract file(s) to egg cache

    The following error occurred while trying to extract file(s) to the
    Python egg cache:

    [Errno 13] Permission denied: '/var/www/.python-eggs'

    The Python egg cache directory is currently set to:

      /var/www/.python-eggs

    Perhaps your account does not have write access to this directory?
    You can change the cache directory by setting the PYTHON_EGG_CACHE
    environment variable to point to an accessible directory.

To avoid this particular problem you can set the 'PYTHON_EGG_CACHE' cache
environment variable at the start of the WSGI application script file. The
environment variable should be set to a directory which is owned and/or
writable by the user that Apache runs as::

    import os
    os.environ['PYTHON_EGG_CACHE'] = '/usr/local/pylons/python-eggs'

Alternatively, if using mod_wsgi 2.0, one could also use the WSGIPythonEggs
directive for applications running in embedded mode, or the 'python-eggs'
option to the WSGIDaemonProcess directive when using daemon mode.

Note that you should refrain from ever using directories or files which
have been made writable to anyone as this could compromise security. Also
be aware that if hosting multiple applications under the same web server,
they will all run as the same user and so it will be possible for each to
both see and modify each others files. If this is an issue, you should host
the applications on different web servers running as different users or on
different systems. Alternatively, any data required or updated by the
application should be hosted in a database with separate accounts for each
application.

Issues related to access rights can in general be avoided if daemon mode
of mod_wsgi is used to run a WSGI application. This is because in daemon
mode the user and group that the processes run as can be overridden and set
to alternate values. Do however note additional issues related to 'HOME'
environment variable as described below.

Secure Variants Of UNIX
-----------------------

In addition to the constraints imposed by Apache running as a distinct
user, some variants of UNIX have features whereby access privileges for a
specific user may be even further restricted. One example of such a system
is SELinux. In such a system, the user that Apache runs as is typically
restricted to only being able to access quite specific parts of the file
system as well as possibly other resources or operating system library
features.

If running such a system you will need to change the configuration for the
security system to allow both mod_wsgi and you application to do what is
required.

As an example, the extra security checks of such a system may present
problems if the version of Python you are using only provides a static
library and not a shared library. If you experience an error similar to::

    Cannot load /etc/httpd/modules/mod_wsgi.so into server: \
     /etc/httpd/modules/mod_wsgi.so: cannot restore segment prot after reloc: \
     Permission denied

you will either need to configure the security system appropriately to
allow that memory relocations in static code to work, or you would need to
make sure that you reinstall Python such that it provides a shared library
and rebuild mod_wsgi. Other issues around only having a static variant of
the Python library available are described in section 'Lack Of Python
Shared Library' of :doc:`../user-guides/installation-issues`.

Even where a shared library is used, SELinux has also resulted in similar
memory related errors when loading C extension modules at run time for
Python::

    ImportError: /opt/python2.6/lib/python2.6/lib-dynload/itertools.so: \
     failed to map segment from shared object: Permission denied

All up, configuring SELinux is a bit of a black art and so you are wise
to do your research.

For some information about using mod_wsgi in a SELinux enabled environment
check out:

  * http://www.packtpub.com/article/selinux-secured-web-hosting-python-based-web-applications
  * http://www.globalherald.net/jb01/weblog/21.html
  * http://blog.endpoint.com/2010/02/selinux-httpd-modwsgi-26-rhel-centos-5.html

Overall, if you don't have a specific need for SELinux, it is suggested
you consider disabling it if it gives you problems.

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
applications being hosted on the same web server may assume they can do the
same thing with the result that you can never be sure what the current
working directory may actually be.

You should not even assume that it is safe to change the working directory
immediately prior to a specific operation, as use of multithreading can
mean that another application could change it even before you get to
perform the operation which depended on the current working directory
being the value you set it to.

In the case of Python, if needing to use relative paths in order to make it
easier to relocate an application, one can determine the directory that a
specific code module is located in using ``os.path.dirname(__file__)``. A
full path name can then be constructed by using ``os.path.join()`` to
merge the relative path with the directory name where the module was
located.

Another option is to take the directory part of the ``SCRIPT_FILENAME``
variable from the WSGI environment as the base directory. The only other
alternative is to rely on a centralised configuration file so that all
absolute path names are at least defined in the one place.

Although it is preferable that an application never make assumptions about
what the current working directory is, if for some reason the application
cannot be changed the daemon mode of mod_wsgi could be used. This will work
as an initial current working directory for the process can be specified as
an option to the WSGIDaemonProcess directive used to configure the daemon
process. Because the working directory applies to the whole process
however, only the application requiring this working directory should be
delegated to run within the context of that daemon process.

Application Environment Variables
---------------------------------

When Python sub interpreters are created, each has its own copy of any
modules which are loaded. They also each have their own copy of the set of
environment variables inherited by the process and found in ``os.environ``.

Problems can arise with the use of ``os.environ`` though, due to the fact
that updates to ``os.environ`` are pushed back into the set of process
environment variables. This means that if the Python sub interpreter which
corresponds to another application group is created after ``os.environ``
has been updated, the new value for that environment variable will be
inherited by the new Python sub interpreter.

This would not generally be a problem where a WSGI application is
configured using a single mandatory environment variable, as the WSGI
application script file for each application instance would be required to
set it, thereby overriding any value inherited from another application
instance via the process environment variables.

As example, Django relies on the ``DJANGO_SETTINGS_MODULE`` environment
variable being set to be the name of the Python module containing Django's
configuration settings. So long as each WSGI script file sets this variable
all will be okay.

Where use of environment variables can be problematic though is where there
are multiple environment variables that can be set, with some being
optional and non overlapping sets of variables are used to configure
different modes.

As example, Trac can be configured to host a single project by setting the
``TRAC_ENV`` environment variable. Alternatively, Trac can be configured
to host a group of projects by setting the ``TRAC_ENV_PARENT_DIR``
environment variable. If both variables are set at the same time, then
``TRAC_ENV`` takes precedence.

If now within the one process you have a Trac instance of each type in
different Python sub interpreters, if that using ``TRAC_ENV`` loads
first, when the other is loaded it will inherit ``TRAC_ENV`` from the
first and that will override ``TRAC_ENV_PARENT_DIR``. The end result is
that both sites point at the same single project, rather than the first
being for the single project and the other being the group of projects.

Because of this potential leakage of environment variables between Python
sub interpreters, it is preferable that WSGI applications not rely on
environment variables for configuration.

A further reason that environment variables should not be used for
configuration is that it then becomes impossible to host two instances of
the same WSGI application component within the same Python sub interpreter
if each would require a different value be set for the same environment
variable. Note that this also applies to other means of hosting WSGI
applications besides mod_wsgi and is not mod_wsgi specific.

As a consequence, because Django relies on the ``DJANGO_SETTINGS_MODULE``
environment variable being set to be the name of the Python module
containing Django's configuration settings, it would be impossible to host
two Django instances in the same Python sub interpreter. It is thus
important that where there are multiple instances of Django that need to be
run on the same web server, that they run in separate Python sub
interpreters.

As it stands the default behaviour of mod_wsgi is to run different WSGI
application scripts within the context of different Python sub
interpreters. As such, this limitation in Django does not present as an
immediate problem, however it should be kept in mind when attempting to
merge multiple WSGI applications into one application group under one
Python sub interpreter to try and limit memory use by avoiding duplicate
instances of modules in memory.

The prefered way of configuring a WSGI application is for the application
to be a class instance which at the point of initialisation is provided
with its configuration data as an argument. Alternatively, or in
conjunction with this, configuration information can be passed through to
the WSGI application in the WSGI environment. Variables in the WSGI
environment could be set by a WSGI middleware component, or from the Apache
configuration files using the ``SetEnv`` directive.

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
values. Rather than each seeing behaviour consistant with the setting they
used, all applications will see behaviour reflecting the setting as
determined by the last application to initialise itself.

Process environment variables where this can be a problem are the 'TZ'
environment variable for setting the timezone, and the 'LANG', 'LC_TYPE',
'LC_COLLATE', 'LC_TIME' and 'LC_MESSAGES' environment variables for setting
the locale and language settings.

The result of this, is that you cannot host multiple WSGI applications in
the same process, even if running in different sub interpreters, if they
require different settings for timezone, locale and/or language.

In this situation you would have no choice but to use mod_wsgi daemon mode
and delegate applications requiring different settings to different daemon
process groups. Alternatively, completely different instances of Apache
should be used.

User HOME Environment Variable
------------------------------

If Apache is started automatically as 'root' when a machine is first booted
it would inherit the user 'HOME' environment variable setting of the 'root'
user. If however, Apache is started by a non privileged user via the 'sudo'
command, it would inherit the 'HOME' environment variable of the user who
started it, unless the ``-H`` option had been supplied to 'sudo'. In the case
of the ``-H`` option being supplied, the 'HOME' environment variable of the
'root' user would again be used.

Because the value of the 'HOME' environment variable can vary based on how
Apache has been started, an application should not therefore depend on the
'HOME' environment variable.

Unfortunately, parts of the Python standard library do use the 'HOME'
environment variable as an authoritative source of information. In
particular, the 'os.expanduser()' function gives precedence to the value of
the 'HOME' environment variable over the home directory as obtained from
the user password database entry::

    if 'HOME' not in os.environ:
        import pwd
        userhome = pwd.getpwuid(os.getuid()).pw_dir
    else:
        userhome = os.environ['HOME']

That the 'os.expanduser()' function does this means it can yield incorrect
results. Since the 'setuptools' package uses 'os.expanduser()' on UNIX
systems to calculate where to store Python EGGS, the location it tries to
use can change based on who started Apache and how.

The only way to guarantee that the 'HOME' environment variable is set to a
sensible value is for it to be set explicitly at the start of the WSGI
script file before anything else is done::

    import os, pwd
    os.environ["HOME"] = pwd.getpwuid(os.getuid()).pw_dir

In mod_wsgi 2.0, if using daemon mode the value of the 'HOME' environment
variable will be automatically reset to correspond to the home directory of
the user that the daemon process is running as. This is not done for
embedded mode however, due to the fact that the Apache child processes are
shared with other Apache modules and it is not seen as appropriate that
mod_wsgi should be changing the same environment that is used by these
other unrelated modules.

For some consistency in the environment inherited by applications running
in embedded mode, it is therefore recommended that 'sudo -H' at least always
be used when restarting Apache from a non root account.

Application Global Variables
----------------------------

Because the Python sub interpreter which hosts a WSGI application is
retained in memory between requests, any global data is effectively
persistent and can be used to carry state forward from one request to the
next. On UNIX systems however, Apache will normally use multiple processes
to handle requests and each such process will have its own global data.

This means that although global data can be used, it can only be used
to cache data which can be safely reused within the context of that single
process. You cannot use global data as a means of holding information that
must be visible to any request handler no matter which process it runs in.

If data must be visible to all request handlers across all Apache
processes, then it will be necessary to store the data in the filesystem
directly, or using a database. Alternatively, shared memory can be employed
by using a package such as memcached.

Because your WSGI application can be spread across multiple process, one
must also be very careful in respect of local caching mechanisms employed
by database connector objects. If such an adapter is quite agressive in its
caching, it is possible that a specific process may end up with an out of
date view of data from a database where one of the other processes has
since changed the data. The result may be that requests handled in different
processes may give different results.

The problems described above can be alleviated to a degree by using daemon
mode of mod_wsgi and restricting to one the number of daemon processes in
the process group. This will ensure that all requests are serviced by the
same process. If the data is only held in memory, it would however obviously
be lost when Apache is restarted or the daemon process is restarted due to
a maximum number of requests being reached.

Writing To Standard Output
--------------------------

No WSGI application component which claims to be portable should write to
standard output. That is, an application should not use the Python ``print``
statement without directing output to some alternate stream. An application
should also not write directly to ``sys.stdout``.

This is necessary as an underlying WSGI adapter hosting the application
may use standard output as the means of communicating a response back to a
web server. This technique is for example used when WSGI is hosted within a
CGI script.

Ideally any WSGI adapter which uses ``sys.stdout`` in this way should
cache a reference to ``sys.stdout`` for its own use and then replace it
with a reference to ``sys.stderr``. There is however nothing in the WSGI
specification that requires this or recommends it, so one can't therefore
rely on it being done.

In order to highlight non portable WSGI application components which write
to or use standard output in some way, mod_wsgi prior to version 3.0
replaced ``sys.stdout`` with an object which will raise an exception when
any attempt is made to write to or make use of standard output::

    IOError: sys.stdout access restricted by mod_wsgi

If the WSGI application you are using fails due to use of standard output
being restricted and you cannot change the application or configure it
to behave differently, you have one of two options. The first option is to
replace ``sys.stdout`` with ``sys.stderr`` at the start of your WSGI
application script file::

    import sys
    sys.stdout = sys.stderr

This will have the affect of directing any data written to standard output
to standard error. Such data sent to standard error is then directed through
the Apache logging system and will appear in the main Apache error log file.

The second option is to remove the restriction on using standard output
imposed by mod_wsgi using a configuration directive::

    WSGIRestrictStdout Off

This configuration directive must appear at global scope within the Apache
configuration file outside of any VirtualHost container directives. It
will remove the restriction on using standard output from all Python sub
interpreters that mod_wsgi creates. There is no way using the configuration
directive to remove the restriction from only one Python sub interpreter.

When the restriction is not imposed, any data written to standard output
will also be directed through the Apache logging system and will appear in
the main Apache error log file.

Ideally though, code should never use the 'print' statement without
redirecting the output to 'sys.stderr'. Thus if the code can be changed,
then it should be made to use something like::

    import sys

    def function():
        print >> sys.stderr, "application debug"
            ...

Also, note that code should ideally not be making assumptions about the
environment it is executing in, eg., whether it is running in an
interactive mode, by asking whether standard output is a tty. In other
words, calling 'isatty()' will cause a similar error with mod_wsgi. If such
code is a library module, the code should be providing a way to
specifically flag that it is a non interactive application and not use
magic to determine whether that is the case or not.

For further information about options for logging error messages and other
debugging information from a WSGI application running under mod_wsgi see
section 'Apache Error Log Files' of :doc:`../user-guides/debugging-techniques`.

WSGI applications which are known to write data to standard output in their
default configuration are CherryPy and TurboGears. Some plugins for Trac
also have this problem. Thus one of these two techniques described above to
remove the restriction, should be used in conjunction with these WSGI
applications. Alternatively, those applications will need to be configured
not to output log messages via standard output.

Note that the restrictions on writing to stdout were removed in mod_wsgi
3.0 because it was found that people couldn't be bothered to fix their
code. Instead they just used the documented workarounds, thereby
propogating their non portable WSGI application code. As such, since people
just couldn't care, stopped promoting the idea of writing portable WSGI
applications.

Reading From Standard Input
---------------------------

No general purpose WSGI application component which claims to be portable
should read from standard input. That is, an application should not read
directly from ``sys.stdin`` either directly or indirectly.

This is necessary as an underlying WSGI adapter hosting the application may
use standard input as the means of receiving a request from a web server.
This technique is for example used when WSGI is hosted within a CGI script.

Ideally any WSGI adapter which uses ``sys.stdin`` in this way should
cache a reference to ``sys.stdin`` for its own use and then replace it
with an instance of ``StringIO.StringIO`` wrapped around an empty string
such that reading from standard input would always give the impression that
there is no input data available. There is however nothing in the WSGI
specification that requires this or recommends it, so one can't therefore
rely on it being done.

In order to highlight non portable WSGI application components which try
and read from or otherwise use standard input, mod_wsgi prior to version
3.0 replaced ``sys.stdin`` with an object which will raise an exception
when any attempt is made to read from standard input or otherwise
manipulate or reference the object::

    IOError: sys.stdin access restricted by mod_wsgi

This restriction on standard input will however prevent the use of
interactive debuggers for Python such as ``pdb``. It can also interfere
with Python modules which use the ``isatty()`` method of ``sys.stdin``
to determine whether an application is being run within an interactive
session.

If it is required to be able to run such debuggers or other code which
requires interactive input, the restriction on using standard input can be
removed using a configuration directive::

    WSGIRestrictStdin Off

This configuration directive must appear at global scope within the Apache
configuration file outside of any VirtualHost container directives. It
will remove the restriction on using standard input from all Python sub
interpreters that mod_wsgi creates. There is no way using the configuration
directive to remove the restriction from only one Python sub interpreter.

Note however that removing the restriction serves no purpose unless you
also run the Apache web server in single process debug mode. This is
because Apache normally makes use of multiple processes and would close
standard input to prevent any process trying to read from standard input.

To run Apache in single process debug mode and thus allow an interactive
Python debugger such as ``pdb`` to be used, your Apache instance should
be shutdown and then the ``httpd`` program run explicitly::

    httpd -X

For more details on using interactive debuggers in the context of mod_wsgi
see documentation on :doc:`../user-guides/debugging-techniques`.

Note that the restrictions on reading from stdin were removed in mod_wsgi
3.0 because it was found that people couldn't be bothered to fix their
code. Instead they just used the documented workarounds, thereby
propogating their non portable WSGI application code. As such, since people
just couldn't care, stopped promoting the idea of writing portable WSGI
applications.

Registration Of Signal Handlers
-------------------------------

Web servers upon which WSGI applications are hosted more often than not use
signals to control their operation. The Apache web server in particular
uses various signals to control its operation including the signals
``SIGTERM``, ``SIGINT``, ``SIGHUP``, ``SIGWINCH`` and ``SIGUSR1``.

If a WSGI application were to register their own signal handlers it is
quite possible that they will interfere with the operation of the
underlying web server, preventing it from being shutdown or restarted
properly. As a general rule therefore, no WSGI application component should
attempt to register its own signal handlers.

In order to actually enforce this, mod_wsgi will intercept all attempts
to register signal handlers and cause the registration to be ignored.
As warning that this is being done, a message will be logged to the Apache
error log file of the form::

    mod_wsgi (pid=123): Callback registration for signal 1 ignored.

If there is some very good reason that this feature should be disabled and
signal handler registrations honoured, then the behaviour can be reversed
using a configuration directive::

    WSGIRestrictSignal Off

This configuration directive must appear at global scope within the Apache
configuration file outside of any VirtualHost container directives. It
will remove the restriction on signal handlers from all Python sub
interpreters that mod_wsgi creates. There is no way using the configuration
directive to remove the restriction from only one Python sub interpreter.

WSGI applications which are known to register conflicting signal handlers
are CherryPy and TurboGears. If the ability to use signal handlers is
reenabled when using these packages it prevents the shutdown and restart
sequence of Apache from working properly and the main Apache process is
forced to explicitly terminate the Apache child processes rather than
waiting for them to perform an orderly shutdown. Similar issues will occur
when using features of mod_wsgi daemon mode to recycle processes when a set
number of requests has been reached or an inactivity timer has expired.

Pickling of Python Objects
--------------------------

The script files that mod_wsgi uses as the entry point for a WSGI
application, although containing Python code, are not treated exactly the
same as a Python code module. This has implications when it comes to using
the 'pickle' module in conjunction which objects contained within the WSGI
application script file.

In practice what this means is that neither function objects, class objects
or instances of classes which are defined in a WSGI application script file
should be stored using the "pickle" module.

In order to ensure that no strange problems at all are likely to occur, it
is suggested that only basic builtin Python types, ie., scalars, tuples,
lists and dictionaries, be stored using the "pickle" module from a WSGI
application script file. That is, avoid any type of object which has user
defined code associated with it.

The technical reasons for the limitations in the use of the "pickle" module
in conjunction with WSGI application script files are further discussed in
the document :doc:`../user-guides/issues-with-pickle-module`. Note
that the limitations do not apply to standard Python modules and packages
imported from within a WSGI application script file from directories on the
standard Python module search path.

Expat Shared Library Conflicts
------------------------------

One of the Python modules which comes standard with Python is the 'pyexpat'
module. This contains a Python wrapper for the popular 'expat' library. So
as to avoid dependencies on third party packages the Python package actually
contains a copy of the 'expat' library source code and embeds it within the
'pyexpat' module.

Prior to Python 2.5, there was however no attempt to properly namespace the
public functions within the 'expat' library source code. The problem this
causes with mod_wsgi is that Apache itself also provides its own copy of
and makes use of the 'expat' library. Because the Apache version of the
'expat' library is loaded first, it will always be used in preference to
the version contained with the Python 'pyexpat' module.

As a result, if the 'pyexpat' module is loaded into a WSGI application and
the version of the 'expat' library included with Python is markedly
different in some way to the Apache version, it can cause Apache to crash
with a segmentation fault. It is thus important to ensure that Apache and
Python use a compatible version of the 'expat' library to avoid this
problem.

For further technical discussion of this issue and how to determine which
version of the 'expat' library both Apache and Python use, see the document
:doc:`../user-guides/issues-with-expat-library`.

MySQL Shared Library Conflicts
------------------------------

Shared library version conflicts can also occur with the MySQL client
libraries. In this case the conflict is usually between an Apache module
that uses MySQL directly such as mod_auth_mysql or mod_dbd_mysql, or an
Apache module that indirectly uses MySQL such as PHP, and the Python
'MySQLdb' module. The result of conflicting library versions can be Apache
crashing, or incorrect results beings returned from the MySQL client
library for certain types of operations.

To ascertain if there is a conflict, you need to determine which versions
of the shared library each package is attempting to use. This can be done
by running, on Linux, the 'ldd' command to list the library dependencies.
This should be done on any Apache modules that are being loaded, any PHP
modules and the Python ``_mysql`` C extension module::

    $ ldd /usr/lib/python2.3/site-packages/_mysql.so | grep mysql
        libmysqlclient_r.so.15 => /usr/lib/libmysqlclient_r.so.15 (0xb7d52000)

    $ ldd /usr/lib/httpd/modules/mod_*.so | grep mysql
        libmysqlclient.so.12 => /usr/lib/libmysqlclient.so.12 (0xb7f00000)

    $ ldd /usr/lib/php4/*.so | grep mysql
    /usr/lib/php4/mysql.so:
        libmysqlclient.so.10 => /usr/lib/mysql/libmysqlclient.so.10 (0xb7f6e000)

If there is a difference in the version of the MySQL client library, or
one version is reentrant and the other isn't, you will need to recompile
one or both of the packages such that they use the same library.

SSL Shared Library Conflicts
----------------------------

When Apache is built, if it cannot find an existing SSL library that it can
use or isn't told where one is that it should use, it will use a SSL
library which comes with the Apache source code. When this SSL code is
compiled it will be statically linked into the actual Apache executable. To
determine if the SSL code is static rather than dynamically loaded from a
shared library, on Linux, the 'ldd' command can be used to list the library
dependencies. If an SSL library is listed, then code will not be statically
compiled into Apache::

    $ ldd /usr/local/apache/bin/httpd | grep ssl
        libssl.so.0.9.8 => /usr/lib/i686/cmov/libssl.so.0.9.8 (0xb79ab000)

Where a Python module now uses a SSL library, such as a database client
library with SSL support, they would typically always obtain SSL code from
a shared library. When however the SSL library functions have also been
compiled statically into Apache, they can conflict and interfere with those
from the SSL shared library being used by the Python module. Such conflicts
can cause core dumps, or simply make it appear that SSL support in either
Apache or the Python module is not working.

Python modules where this is known to cause a problem are, any database
client modules which include support for connecting to the database using
an SSL connection, and the Python 'hashlib' module introduced in Python
2.5.

In the case of the 'hashlib' module it will fail to load the internal C
extension module called ``_hashlib`` because of the conflict. That
``_hashlib`` module couldn't be loaded is however not raised as an
exception, and instead the code will fallback to attempting to load the
older ``_md5`` module. In Python 2.5 however, this older ``_md5``
module is not generally compiled and so the following error will occur::

    ImportError: No module named _md5

To resolve this problem it would be necessary to rebuild Apache and use the
``--with-ssl`` option to 'configure' to specify the location of the distinct
SSL library that is being used by the Python modules.

Note that it has also been suggested that the !ImportError above can also
be caused due to the 'python-hashlib' package not being installed. This
might be the case on Linux systems where this module was separated from the
main Python package.

Python MD5 Hash Module Conflict
-------------------------------

Python provides in the form of the 'md5' module, routines for calculating
MD5 message-digest fingerprint (checksum) values for arbitrary data. This
module is often used in Python web frameworks for generating cookie values
to be associated with client session information.

If a WSGI application uses this module, it is however possible that a
conflict can arise if PHP is also being loaded into Apache. The end result
of the conflict will be that the 'md5' module in Python can given incorrect
results for hash values. For example, the same value may be returned no
matter what the input data, or an incorrect or random value can be returned
even for the same data. In the worst case scenario the process may crash.

As might be expected this can cause session based login schemes such as
commonly employed by Python web frameworks such as Django, TurboGears or
Trac to fail in strange ways.

The underlying trigger for all these problems appears to be a clash between
the Python 'md5' module and the 'libmhash2' library used by the PHP 'mhash'
module, or possibly also other PHP modules relying on md5 routines for
cryptography such as the LDAP module for PHP.

This clash has come about because because md5 source code in Python was
replaced with an alternate version when it was packaged for Debian. This
version did not include in the "md5.h" header file some preprocessor
defines to rename the md5 functions with a namespace prefix specific to
Python::

    #define MD5Init _PyDFSG_MD5Init
    #define MD5Update _PyDFSG_MD5Update
    #define MD5Final _PyDFSG_MD5Final
    #define MD5Transform _PyDFSG_MD5Transform

    void MD5Init(struct MD5Context *context);
    void MD5Update(struct MD5Context *context, md5byte const *buf, unsigned len);
    void MD5Final(unsigned char digest[16], struct MD5Context *context);

As a result, the symbols in the md5 module ended up being::

    $ nm -D /usr/lib/python2.4/lib-dynload/md5.so | grep MD5
    0000000000001b30 T MD5Final
    0000000000001380 T MD5Init
    00000000000013b0 T MD5Transform
    0000000000001c10 T MD5Update

The symbols then clashed directly with the non namespaced symbols present
in the 'libmhash2' library::

    $ nm -D /usr/lib/libmhash.so.2 | grep MD5
    00000000000069b0 T MD5Final
    0000000000006200 T MD5Init
    0000000000006230 T MD5Transform
    0000000000006a80 T MD5Update

In Python 2.5 the md5 module is implemented in a different way and thus
this problem should only occur with older versions of Python. For those
older versions of Python, the only workaround for this problem at the
present time is to disable the loading of the 'mhash' module or other PHP
modules which use the 'libmhash2' library. This will avoid the problem
with the Python 'md5' module, obviously however, not loading these modules
into PHP may cause some PHP programs which rely on them to fail.

The actual cause of this problem having now been identified a patch has been
produced and is recorded in Debian ticket:

  * http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=440272
   
It isn't know when an updated Debian package for Python may be produced.

Python 'pysqlite' Symbol Conflict
---------------------------------

Certain versions of 'pysqlite' module defined a global symbol 'cache_init'.
This symbol clashes with a similarly named symbol present in the Apache
mod_cache module. As a result of the clash, the two modules being loaded at
the same time can cause the Apache process to crash or the following Python
exception to be raised::

    SystemError: NULL result without error in PyObject_Call

This problem is mentioned in pysqlite ticket:

  * http://www.initd.org/tracker/pysqlite/ticket/174

and the release notes for version 2.3.3:

  * http://www.initd.org/tracker/pysqlite/wiki/2.3.3_Changelog
    
of pysqlite To avoid the problem upgrade to pysqlite 2.3.3 or later.

Python Simplified GIL State API
-------------------------------

In an attempt to simplify management of thread state objects when coding C
extension modules for Python, Python 2.3 introduced the simplified API for
GIL state management. Unfortunately, this API will only work if the code is
running against the very first Python sub interpreter created when Python
is initialised.

Because mod_wsgi by default assigns a Python sub interpreter to each WSGI
application based on the virtual host and application mount point, code
would normally never be executed within the context of the first Python sub
interpreter created, instead a distinct Python sub interpreter would be
used.

The consequences of attempting to use a C extension module for Python which
is implemented against the simplified API for GIL state management in
any sub interpreter besides the first, is that the code is likely to
deadlock or crash the process. The only way around this issue is to ensure
that any WSGI application which makes use of C extension modules which use
this API, only runs in the very first Python sub interpreter created when
Python is initialised.

To force a specific WSGI application to be run within the very first Python
sub interpreter created when Python is initialised, the WSGIApplicationGroup
directive should be used and the group set to '%{GLOBAL}'::

    WSGIApplicationGroup %{GLOBAL}

Extension modules for which this is known to be necessary are any which
have been developed using SWIG and for which the ``-threads`` option was
supplied to 'swig' when the bindings were generated. One example of this is
the 'dbxml' module, a Python wrapper for the Berkeley Database, previously
developed by !SleepyCat Software, but now managed by Oracle. Another package
believed to have this problem in certain use cases is Xapian.

There is also a bit of a question mark over the Python Subversion bindings.
This package also uses SWIG, however it is only some versions that appear
to require that the very first sub interpreter created when Python is
initialised be used. It is currently believed that this may be more to do
with coding problems than with the ``-threads`` option being passed to the
'swig' command when the bindings were generated.

For all the affected packages, as described above it is believed though
that they will work when application group is set to force the application
to run in the first interpreter created by Python as described above.

Another option for packages which use SWIG generated bindings is not to use
the ``-threads`` option when 'swig' is used to generate the bindings. This
will avoid any problems and allow the package to be used in any sub
interpreter. Do be aware though that by disabling thread support in SWIG
bindings, that the GIL isn't released when C code is entered. The
consequences of this are that if the C code blocks, the whole Python
interpreter environment running in that process will be blocked, even
requests being handled within other threads in different sub interpreters.

Reloading Python Interpreters
-----------------------------

*Note: The "Interpreter" reload mechanism has been removed in mod_wsgi
version 2.0. This is because the problems with third party modules didn't
make it a viable option. Its continued presence was simply complicating the
addition of new features. As an alternative, daemon mode of mod_wsgi should
be used and the "Process" reload mechanism added with mod_wsgi 2.0.*

To make it possible to modify a WSGI application and have the whole
application reloaded without restarting the Apache web server, mod_wsgi
provides an interpreter reloading feature. This specific feature is enabled
using the WSGIReloadMechanism directive, setting it to the value
'Interpreter' instead of its default value of 'Module'::

    WSGIReloadMechanism Interpreter

When this option is selected and script reloading is also enabled, when the
WSGI application script file is modified, the next request which arrives
will result in the Python sub interpreter which is hosting that WSGI
application being destroyed. A new Python sub interpreter will then be
created and the WSGI application reloaded including any changes made to
normal Python modules.

For many WSGI applications this mechanism will generally work fine, however
there are a few limitations on what is reloaded, plus some Python C extension
modules can be incompatible with this feature.

The first issue is that although Python code modules will be destroyed and
reloaded, because a C extension module is only loaded once and used across
all Python sub interpreters for the life of the process, any changes to a C
extension module will not be picked up.

The second issue is that some C extension modules may cache references to
the Python interpreter object itself. Because there is no notification
mechanism for letting a C extension module know when a sub interpreter is
destroyed, it is possible that later on the C extension module may attempt
to access the now destroyed Python interpreter. By this time the pointer
reference is likely a dangling reference to unused memory or some
completely different data and attempting to access or use it will likely
cause the process to crash at some point.

A third issue is that the C extension module may cache references to Python
objects in static variables but not actually increment the reference count
on the objects in respect of its own reference to the objects. When the
last Python sub interpreter to hold a reference to that Python object is
destroyed, the object itself would be destroyed but the static variable left
with a dangling pointer. If a new Python sub interpreter is then created
and the C extension module attempts to use that cached Python object,
accessing it or using it will likely cause the process to crash at some
point.

A few examples of Python modules which exhibit one or more of these problems
are psycopg2, PyProtocols and lxml. In the case of !PyProtocols, because this
module is used by TurboGears and sometimes used indirectly by Pylons
applications, it means that the interpreter reloading mechanism can not be
used with either of these packages. The reason for the problems with
!PyProtocols appear to stem from its use of Pyrex generated code. The lxml
package similarly uses Pyrex and is thus afflicted.

In general it is probably inadvisable to use the interpreter reload
mechanism with any WSGI application which uses large or complicated C
extension modules. It would be recommended for example that the interpreter
reload mechanism not be used with Trac because of its use of the Python
Subversion bindings. One would also need to be cautious if using any Python
database client, although some success has been seen when using simple
database adapters such as pysqlite.

Multiple Python Sub Interpreters
--------------------------------

In addition to the requirements imposed by the Python GIL, other issues can
also arise with C extension modules when multiple Python sub interpreters
are being used. Typically these problems arise where an extension module
caches a Python object from the sub interpreter which is initially used to
load the module and then passes that object to code executing within
secondary sub interpreters.

The prime example of where this would be a problem is where the code within
the second sub interpreter attempts to execute a method of the Python
object. When this occurs the result will be an attempt to execute Python
code which doesn't belong to the current sub interpreter.

One result of this will be that if the code being executed attempts to
import additional modules it will obtain those modules from the current sub
interpreter rather than the interpreter the code belonged to. The result of
this can be a unholy mixing of code and data owned by multiple sub
interpreters leading to potential chaos at some point.

A more concrete outcome of such a mixing of code and data from multiple
sub interpreters is where a file object from one sub interpreter is used
within a different sub interpreter. In this sort of situation a Python
exception will occur as Python will detect in certain cases that the object
didn't belong to that interpreter::

    exceptions.IOError: file() constructor not accessible in restricted mode

Problems with code being executed in restricted mode can also occur when
the Python code and data marshalling features are used::

    exceptions.RuntimeError: cannot unmarshal code objects in restricted execution mode

A further case is where the cached object is a class object and that object
is used to create instances of that type of object for different sub
interpreters. As above this can result in an unholy mixing of code and data
from multiple sub interpreters, but at a more mundane level may become
evident through the 'isinstance()' function failing when used to check the
object instances against the local type object for that sub interpreter.

An example of a Python module which fails in this way is psycopg2, which
caches an instance of the 'decimal.Decimal' type and uses it to create
object instances for all sub interpreters. This particular problem in
psycopg2 has been reported in psycopg2 ticket:

  * http://www.initd.org/tracker/psycopg/ticket/192
    
and has been fixed in pyscopg2 source code. It isn't known however which
version of psycopg2 this fix may have been released with. Another package
believed to have this problem in certain use cases is lxml.

Because of the possibilty that extension module writers have not written
their code to take into consideration it being used from multiple sub
interpreters, the safest approach is to force all WSGI applications to run
within the same application group, with that preferably being the
first interpreter instance created by Python.

To force a specific WSGI application to be run within the very first Python
sub interpreter created when Python is initialised, the WSGIApplicationGroup
directive should be used and the group set to '%{GLOBAL}'::

    WSGIApplicationGroup %{GLOBAL}

If it is not feasible to force all WSGI applications to run in the same
interpreter, then daemon mode of mod_wsgi should be used to assign
different WSGI applications to their own daemon processes. Each would
then be made to run in the first Python sub interpreter instance within
their respective processes.

Memory Constrained VPS Systems
------------------------------

Virtual Private Server (VPS) systems typically always have constraints
imposed on them in regard to the amount of memory or resources they are
able to use. Various limits and related counts are described below:

*Memory Limit*
    Maximum virtual memory size a VPS/context can allocate.

*Used Memory*
    Virtual memory size used by a running VPS/context.

*Max Total Memory*
    Maximum virtual memory usage by VPS/context.

*Context RSS Limit*
    Maximum resident memory size a VPS/context can allocate. If limit is exceeded, VPS starts to use the host's SWAP.

*Context RSS*
    Resident memory size used by a running VPS/context.

*Max RSS Memory*
    Maximum resident memory usage by VPS/context.

*Disk Limit*
    Maximum disk space that can be used by VPS (calculated for the entire VPS file tree).

*Used Disk Memory*
    Disk space used by a VPS file tree.

*Files Limit*
    Maximum number of files that can be switched to a VPS/context.

*Used Files*
    Number of files used in a VPS/context.

*TCP Sockets Limit*
    Limit on the number of established connections in a virtual server.

*Established Sockets*
    Number of established connections in a virtual server.

In respect of the limits, when summary virtual memory size used by the
VPS exceeds Memory Limit, processes can't allocate the required memory and
will fail in unexpected ways. The general recommendation is that Context
RSS Limit be set to be one third of Memory Limit.

Some VPS providers however appear to ignore such guidance, not perhaps
understanding how virtual memory systems work, and set too restrictive a
value on the Memory Limit of the VPS, to the extent that virtual memory use
will exceed the Memory Limit even before actual memory use reaches Max RSS
Memory or even perhaps before reaching Context RSS Limit.

This is especially a problem where the hosted operating system is Linux, as
Linux uses a default per thread stack size which is excessive. When using
Apache worker MPM with multiple threads, or mod_wsgi daemon mode and
multiple worker threads, the amount of virtual memory quickly adds up
causing the artificial Memory Limit to be exceeded.

Under Linux the default process stack size is 8MB. Where as other UNIX
system typically use a much smaller per thread stack size in the order of
512KB, Linux inherits the process stack size and also uses it as the per
thread stack size.

If running a VPS system and are having problems with Memory Limit being
exceeded by the amount of virtual memory set aside by all applications
running in the VPS, it will be necessary to override the default per thread
stack size as used by Linux.

If you are using the Apache worker MPM, you will need to upgrade to Apache
2.2 if you are not already running it. Having done that you should then use
the Apache directive !ThreadStackSize to lower the per thread stack size
for threads created by Apache for the Apache child processes::

    ThreadStackSize 524288

This should drop the amount of virtual memory being set aside by Apache for
its child process and thus any WSGI application running under embedded
mode.

If a WSGI application creates its own threads for performing background
activities, it is also preferable that they also override the stack size
set aside for that thread. For that you will need to be using at least
Python 2.5. The WSGI application should be ammended to execute::

    import thread 
    thread.stack_size(524288) 

If using mod_wsgi daemon mode, you will need to use mod_wsgi 2.0 and
override the per thread stack size using the 'stack-size' option to the
WSGIDaemonProcess directive::

    WSGIDaemonProcess example stack-size=524288

If you are unable to upgrade to Apache 2.2 and/or mod_wsgi 2.0, the only
other option you have for affecting the amount of virtual memory set aside
for the stack of each thread is to override the process stack size. If you are
using a standard Apache distribution, this can be done by adding to the
'envvars' file for the Apache installation::

    ulimit -s 512

If using a customised Apache installation, such as on RedHat, the 'envvars'
file may not exist. In this case you would need to add this into the actual
startup script for Apache. For RedHat this is '/etc/sysconfig/httpd'.

Note that although 512KB is given here as an example, you may in practice
need to adjust this higher if you are using third party C extension modules
for Python which allocate significant amounts of memory on the stack.

OpenBSD And Thread Stack Size
-----------------------------

When using Linux the excessive amount of virtual memory set aside for the
stack of each thread can cause problems in memory constrained VPS systems.
Under OpenBSD the opposite problem can occur in that the default per thread
stack size can be too small. In this situation the same mechanisms as used
above for adjusting the amount of virtual memory set aside can be used, but
in this case to increase the amount of memory to be greater than the
default value.

Although it has been reported that the default per thread stack size on
OpenBSD can be a problem, it isn't known what it defaults too and thus
whether it is too low, or whether it was just the users specific
application which was attempting to allocate too much memory from the
stack.

Python Oracle Wrappers
----------------------

When using WSGIDaemonProcess directive, it is possible to use the
'display-name' option to set what the name of the process is that will be
displayed in output from BSD derived 'ps' programs and some other monitoring
programs. This allows one to distinguish the WSGI daemon processes in a
process group from the normal Apache 'httpd' processes.

The mod_wsgi package accepts the magic string '%{GROUP}' as value to the
WSGIDaemonProcess directive to indicate that mod_wsgi should construct the
name of the processes based on the name of the process group. Specifically,
if you have::

    WSGIDaemonprocess mygroup display-name=%{GROUP}

then the name of the processes in that process group would be set to the
value::

    (wsgi:mygroup)

This generally works fine, however causes a problem when the WSGI
application makes use of the 'cx_Oracle' module for wrapping Oracle client
libraries in Python. Specifically, Oracle client libraries can produce the
error::

    ORA-06413: Connection not open.

This appears to be caused by the use of brackets, ie., '()' in the name of
the process. It is therefore recommended that you explicitly provide the
name to use for the process and avoid these characters and potentially any
non alphanumeric characters to be extra safe.

This issue is briefly mentioned in:

  * http://www.dba-oracle.com/t_ora_06413_connection_not_open.htm

Non Blocking Module Imports
---------------------------

In Python 2.6 non blocking module imports were added as part of the Python
C API in the form of the function PyImport_ImportModuleNoBlock(). This
function was introduced to prevent deadlocks with module imports in certain
circumstances. Unfortunately, for valid reasons or not, use of this
function has been sprinkled through Python standard library modules as well
as third party modules.

Although the function may have been created to fix some underlying issue,
its usage has caused a new set of problems for multithreaded programs which
defer module importing until after threads have been created. With mod_wsgi
this is actually the norm as the default mode of operation is that code is
lazily loaded only when the first request arrives which requires it.

A classic example of the sorts of problems use of this function causes is the
error::

    ImportError: Failed to import _strptime because the import lock is held by another thread.

This particular error occurs when 'time.strptime()' is called for the first
time and it so happens that another thread is in the process of doing a
module import and holds the global module import lock.

It is believed that the fact this can happen indicates that Python is
flawed in using the PyImport_ImportModuleNoBlock(). Unfortunately, when
this issue has been highlighted in the past, people seemed to think it was
acceptable and the only solution, rather than fixing the Python standard
library, was to ensure that all module imports are done before any threads
are created.

This response is frankly crazy and you can expect all manner of random
problems related to this to crop up as more and more people start using the
PyImport_ImportModuleNoBlock() function without realising that it is a
really bad idea in the context of a multithreaded system.

Although no hope is held out for the issue being fixed in Python, a problem
report has still been lodged and can be found at::

  * http://bugs.python.org/issue8098

The only work around for the problem is to ensure that all module imports
related to modules on which the PyImport_ImportModuleNoBlock() function is
used be done explicitly or indirectly when the WSGI script file is loaded.
Thus, to get around the specific case above, add the following into the
WSGI script file::

    import _strptime

There is nothing that can be done in mod_wsgi to fix this properly as the
set of modules that might have to be forceably imported is unknown. Having
a hack to import them just to avoid the problem is also going to result in
unnecessary memory usage if the application didn't actually need them.
