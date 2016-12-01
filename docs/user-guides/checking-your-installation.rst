==========================
Checking Your Installation
==========================

When debugging mod_wsgi or a WSGI application, it is import to be able to
understand how mod_wsgi has been installed, what Apache and/or Python it
uses and how those systems have been configured, plus under what
configuration the WSGI application is running.

This document details various such checks that can be made. The primary
purpose of providing this information is so that when people ask questions
on the mod_wsgi mailing list, they can be directed here to perform certain
checks as a way of collecting additional information needed to help debug
their problem.

If you are reading this document because you have been directed here from
the mailing list, then ensure that you actually provide the full amount of
detail obtained from the checks and not leave out information. When you
leave out information then it means guesses have to be made about your
setup which makes it harder to debug your problems.

Apache Build Information
------------------------

Information related to what version of Apache is being used and how it is
built is obtained in a number of ways. The primary means is from the
Apache 'httpd' executable itself using command line options. The main such
option is the ``-V`` option.

On most systems the standard Apache executable supplied with the operating
system is located at '/usr/sbin/httpd'. On MacOS X, for the operating system
supplied Apache the output from this is::

    $ /usr/sbin/httpd -V
    Server version: Apache/2.2.14 (Unix)
    Server built:   Feb 10 2010 22:22:39
    Server's Module Magic Number: 20051115:23
    Server loaded:  APR 1.3.8, APR-Util 1.3.9
    Compiled using: APR 1.3.8, APR-Util 1.3.9
    Architecture:   64-bit
    Server MPM:     Prefork
      threaded:     no
        forked:     yes (variable process count)
    Server compiled with....
     -D APACHE_MPM_DIR="server/mpm/prefork"
     -D APR_HAS_SENDFILE
     -D APR_HAS_MMAP
     -D APR_HAVE_IPV6 (IPv4-mapped addresses enabled)
     -D APR_USE_FLOCK_SERIALIZE
     -D APR_USE_PTHREAD_SERIALIZE
     -D SINGLE_LISTEN_UNSERIALIZED_ACCEPT
     -D APR_HAS_OTHER_CHILD
     -D AP_HAVE_RELIABLE_PIPED_LOGS
     -D DYNAMIC_MODULE_LIMIT=128
     -D HTTPD_ROOT="/usr"
     -D SUEXEC_BIN="/usr/bin/suexec"
     -D DEFAULT_PIDLOG="/private/var/run/httpd.pid"
     -D DEFAULT_SCOREBOARD="logs/apache_runtime_status"
     -D DEFAULT_LOCKFILE="/private/var/run/accept.lock"
     -D DEFAULT_ERRORLOG="logs/error_log"
     -D AP_TYPES_CONFIG_FILE="/private/etc/apache2/mime.types"
     -D SERVER_CONFIG_FILE="/private/etc/apache2/httpd.conf"

The most important details here are:

  * The version of Apache from the 'Server version' entry.
  * The MPM which Apache has been compiled to use from the 'Server MPM' entry.

Although this has a section which appears to indicate what preprocessor
options the server was compiled with, it is a massaged list. What is often
more useful is the actual arguments which were supplied to the 'configure'
command when Apache was built.

To determine this information you need to do the following.

  * Work out where 'apxs2' or 'apxs' is installed.
  * Open this file and find setting for '$installbuilddir'.
  * Open the 'config.nice' file in the directory specified for build directory.

On MacOS X, for the operating system supplied Apache this file is located at
'/usr/share/httpd/build/config.nice'. The contents of the file is::

    #! /bin/sh
    #
    # Created by configure

    "/SourceCache/apache/apache-747.1/httpd/configure" \
    "--prefix=/usr" \
    "--enable-layout=Darwin" \
    "--with-apr=/usr" \
    "--with-apr-util=/usr" \
    "--with-pcre=/usr/local/bin/pcre-config" \
    "--enable-mods-shared=all" \
    "--enable-ssl" \
    "--enable-cache" \
    "--enable-mem-cache" \
    "--enable-proxy-balancer" \
    "--enable-proxy" \
    "--enable-proxy-http" \
    "--enable-disk-cache" \
    "$@"

Not only does this indicate what features of Apache have been compiled in,
it also indicates by way of the ``--enable-layout`` option what custom Apache
installation layout has been used.

Apache Modules Loaded
---------------------

Modules can be loaded into Apache statically, or can be loaded dynamically
at run time based on Apache configuration files.

If modules have been statically compiled into Apache, usually it would be
evident by what 'configure' arguments have been used when Apache was built.
To verify what exactly what is compiled in statically, you can use the ``-l``
option to the Apache executable.

On MacOS X, for the operating system supplied Apache the output from
running ``-l`` option is::

    $ /usr/sbin/httpd -l
    Compiled in modules:
      core.c
      prefork.c
      http_core.c
      mod_so.c

This indicates that the only module that is loaded statically is 'mod_so'.
This is actually the Apache module that handles the task of dynamically
loading other Apache modules.

For a specific Apache configuration, you can determine what Apache modules
will be loaded dynamically by using the ``-M`` option for the Apache executable.

On MacOS X, for the operating system supplied Apache the output from
running ``-M`` option, where the only additional module added is mod_wsgi,
is::

    $ /usr/sbin/httpd -M
    Loaded Modules:
     core_module (static)
     mpm_prefork_module (static)
     http_module (static)
     so_module (static)
     authn_file_module (shared)
     authn_dbm_module (shared)
     authn_anon_module (shared)
     authn_dbd_module (shared)
     authn_default_module (shared)
     authz_host_module (shared)
     authz_groupfile_module (shared)
     authz_user_module (shared)
     authz_dbm_module (shared)
     authz_owner_module (shared)
     authz_default_module (shared)
     auth_basic_module (shared)
     auth_digest_module (shared)
     cache_module (shared)
     disk_cache_module (shared)
     mem_cache_module (shared)
     dbd_module (shared)
     dumpio_module (shared)
     ext_filter_module (shared)
     include_module (shared)
     filter_module (shared)
     substitute_module (shared)
     deflate_module (shared)
     log_config_module (shared)
     log_forensic_module (shared)
     logio_module (shared)
     env_module (shared)
     mime_magic_module (shared)
     cern_meta_module (shared)
     expires_module (shared)
     headers_module (shared)
     ident_module (shared)
     usertrack_module (shared)
     setenvif_module (shared)
     version_module (shared)
     proxy_module (shared)
     proxy_connect_module (shared)
     proxy_ftp_module (shared)
     proxy_http_module (shared)
     proxy_ajp_module (shared)
     proxy_balancer_module (shared)
     ssl_module (shared)
     mime_module (shared)
     dav_module (shared)
     status_module (shared)
     autoindex_module (shared)
     asis_module (shared)
     info_module (shared)
     cgi_module (shared)
     dav_fs_module (shared)
     vhost_alias_module (shared)
     negotiation_module (shared)
     dir_module (shared)
     imagemap_module (shared)
     actions_module (shared)
     speling_module (shared)
     userdir_module (shared)
     alias_module (shared)
     rewrite_module (shared)
     bonjour_module (shared)
     wsgi_module (shared)
    Syntax OK

The names reflect that which would have been used with the LoadModule line
in the Apache configuration and not the name of the module file itself.

The order in which modules are listed can be important in some cases where
a module doesn't explicitly designate in what order a handler should be
applied relative to other Apache modules.

Global Accept Mutex
-------------------

Because Apache is a multi process server, it needs to use a global cross
process mutex to control which of the Apache child processes get the next
chance to accept a connection from a HTTP client.

This cross process mutex can be implemented using a variety of different
mechanisms and exactly which is used can vary based on the operating system.
Which mechanism is used can also be overridden in the Apache configuration
if absolutely required.

A simlar instance of a cross process mutex is also used for each mod_wsgi
daemon process group to mediate which process in the daemon process group
gets to accept the next request proxied to that daemon process group via the
Apache child processes.

The list of mechanisms which might be used to implement the cross process
mutex are as follows:

  * flock
  * fcntl
  * sysvsem
  * posixsem
  * pthread

In the event that there are issues which communicating between the Apache
child processes and the mod_wsgi daemon process in particular, it can be
useful to know what mechanism is used to implement the cross process mutex.

By default, the Apache configuration files would not specify a specific
mechanism, and instead which is used would be automatically selected by the
underlying Apache runtime libraries based on various build time and system
checks about what is the prefered mechanism for a particular operating
system.

Which mechanism is used by default can be determined from the build
information displayed by the ``-V`` option to the Apache executable described
previously. The particular entries of interest are those with 'SERIALIZE'
in the name of the macro.

On MacOS X, using operating system supplied Apache, the entries of interest
are::

    -D APR_USE_FLOCK_SERIALIZE
    -D APR_USE_PTHREAD_SERIALIZE

As the entries are used in order, what this indicates is that Apache will by
default use the 'flock' mechanism to implement the cross process mutex.

In comparison, on a Linux system, the entries of interest may be::

    -D APR_USE_SYSVSEM_SERIALIZE
    -D APR_USE_PTHREAD_SERIALIZE

which indicates that 'sysvsem' mechanism is instead used.

This mechanism is also what would be used by mod_wsgi by default as well for
the cross process mutex for daemon process groups.

This mechanism will be different where the AcceptMutex and WSGIAcceptMutex
directives are used.

If the AcceptMutex directive is defined in the Apache configuration file,
then what ever mechanism is specified will be used instead for Apache child
processes. Provided that Apache 2.2 or older is used, and WSGIAcceptMutex
is not specified, then when AcceptMutex is used, that will also then be used
by mod_wsgi daemon processes as well.

In the case of Apache 2.4 and later, AcceptMutex will no longer override the
default for mod_wsgi daemon process groups, and instead WSGIAcceptMutex must
be specified seperately if it needs to be overridden for both.

Either way, you should check the Apache configuration files as to whether
either AcceptMutex or WSGIAcceptMutex directives are used as they will
override the defaults calculated above. Under normal circumstances neither
should be set as default would always be used.

If wanting to look at overriding the default mechanism, what options exist
for what mechanism can be used will be dependent on the operating system
being used. There are a couple of ways this can be determined.

The first is to find the 'apr.h' header file from the Apache runtime library
installation that Apache was compiled against. In that you will find entries
similar to the 'USE' macros above. You will also find 'HAS' entries. In this
case we are interested in the 'HAS' entries.

On MacOS X, with the operating system supplied APR library, the entries in
'apr.h' are::

    #define APR_HAS_FLOCK_SERIALIZE           1
    #define APR_HAS_SYSVSEM_SERIALIZE         1
    #define APR_HAS_POSIXSEM_SERIALIZE        1
    #define APR_HAS_FCNTL_SERIALIZE           1
    #define APR_HAS_PROC_PTHREAD_SERIALIZE    0

The available mechanisms are those defined to be '1'.

Finding where the right 'apr.h' is located may be tricky, so an easier way
is to trick Apache into generating an error message to list what the available
mechanisms are. To do this, in turn, add entries into the Apache configuration
files, at global scope of::

    AcceptMutex xxx

and::

    WSGIAcceptMutex xxx

For each run the ``-t`` option on the Apache program executable.

On MacOS X, with the operating system supplied APR library, this yields::

    $ /usr/sbin/httpd -t
    Syntax error on line 501 of /private/etc/apache2/httpd.conf:
    xxx is an invalid mutex mechanism; Valid accept mutexes for this platform \
     and MPM are: default, flock, fcntl, sysvsem, posixsem.

for AcceptMutex and for WSGIAcceptMutex::

    $ /usr/sbin/httpd -t
    Syntax error on line 501 of /private/etc/apache2/httpd.conf:
    Accept mutex lock mechanism 'xxx' is invalid. Valid accept mutex mechanisms \
     for this platform are: default, flock, fcntl, sysvsem, posixsem.

The list of available mechanisms should normally be the same in both cases.

Using the value of 'default' indicates that which mechanism is used is left
up to the APR library.

Python Shared Library
---------------------

When mod_wsgi is built, the 'mod_wsgi.so' file should be linked against
Python via a shared library. If it isn't and it is linked against a static
library, various issues can arise. These include additional memory usage,
plus conflicts with mod_python if it is also loaded in same Apache.

To validate that 'mod_wsgi.so' is using a shared library for Python, on most
UNIX systems the 'ldd' command is used. For example::

    $ ldd mod_wsgi.so
     linux-vdso.so.1 =>  (0x00007fffeb3fe000)
     libpython2.5.so.1.0 => /usr/local/lib/libpython2.5.so.1.0 (0x00002adebf94d000)
     libpthread.so.0 => /lib/libpthread.so.0 (0x00002adebfcba000)
     libdl.so.2 => /lib/libdl.so.2 (0x00002adebfed6000)
     libutil.so.1 => /lib/libutil.so.1 (0x00002adec00da000)
     libc.so.6 => /lib/libc.so.6 (0x00002adec02dd000)
     libm.so.6 => /lib/libm.so.6 (0x00002adec0635000)
     /lib64/ld-linux-x86-64.so.2 (0x0000555555554000)

What you want to see is a reference to an instance of 'libpythonX.Y.so'.
Normally the operating system shared library version suffix would always be
'1.0'. What it is shouldn't really matter though.

This reference should refer to the actual Python shared library for your
Python installation.

Do note though, that 'ldd' will take into consideration any local user
setting of the 'LD_LIBRARY_PATH' environment variable. That is, 'ldd' will
also search any directories listed in that environment variable for shared
libraries.

Although that environment variable may be defined in your user account, it
will not normally be defined in the environment of the account that Apache
starts up as. Thus, it is important that you unset the 'LD_LIBRARY_PATH'
environment variable when running 'ldd'.

If you run the check with and without 'LD_LIBRARY_PATH' set and find that
without it that a different, or no Python shared library is found, then you
will likely have a problem. For the case of it not being found, Apache will
fail to start. For where it is found but it is a different installation to
that which you want used, subtle problems could occur due to C extension
modules for Python being used which were compiled against that installation.

For example, if 'LD_LIBRARY_PATH' contained the directory '/usr/local/lib'
and you obtained the results above, but when you unset it, it picked up
shared library from '/usr/lib' instead, then you may end up with problems
if for a different installation. In this case you would see::

    $ unset LD_LIBRARY_PATH
    $ ldd mod_wsgi.so
     linux-vdso.so.1 =>  (0x00007fffeb3fe000)
     libpython2.5.so.1.0 => /usr/lib/libpython2.5.so.1.0 (0x00002adebf94d000)
     libpthread.so.0 => /lib/libpthread.so.0 (0x00002adebfcba000)
     libdl.so.2 => /lib/libdl.so.2 (0x00002adebfed6000)
     libutil.so.1 => /lib/libutil.so.1 (0x00002adec00da000)
     libc.so.6 => /lib/libc.so.6 (0x00002adec02dd000)
     libm.so.6 => /lib/libm.so.6 (0x00002adec0635000)
     /lib64/ld-linux-x86-64.so.2 (0x0000555555554000)

Similarly, if not found at all, you would see::

    $ unset LD_LIBRARY_PATH
    $ ldd mod_wsgi.so
     linux-vdso.so.1 =>  (0x00007fffeb3fe000)
     libpython2.5.so.1.0 => not found
     libpthread.so.0 => /lib/libpthread.so.0 (0x00002adebfcba000)
     libdl.so.2 => /lib/libdl.so.2 (0x00002adebfed6000)
     libutil.so.1 => /lib/libutil.so.1 (0x00002adec00da000)
     libc.so.6 => /lib/libc.so.6 (0x00002adec02dd000)
     libm.so.6 => /lib/libm.so.6 (0x00002adec0635000)
     /lib64/ld-linux-x86-64.so.2 (0x0000555555554000)

If you have this problem, then it would be necessary to set 'LD_RUN_PATH'
environment variable to include directory containing where Python library
resides when building mod_wsgi, or set 'LD_LIBRARY_PATH' in startup file
for Apache such that it is also set for Apache when run. For standard
Apache installation the latter would be done in 'envvars' file in same
directory as Apache program executable. For some Linux installations would
need to be done in init scripts for Apache.

Note that MacOS X doesn't use 'LD_LIBRARY_PATH' nor have 'ldd'. On MacOS X,
instead of 'ldd' you can use 'otool -L'::

    $ otool -L mod_wsgi.so 
    mod_wsgi.so:
      /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 125.2.0)
      /System/Library/Frameworks/Python.framework/Versions/2.6/Python (compatibility version 2.6.0, current version 2.6.1)

If using standard MacOS X compilers and not using Fink or !MacPorts, there
generally should not ever be any issues with whether it is a shared library
or not as everything should just work.

The only issue with MacOS X is that for whatever reason, the location
dependency for the shared library (framework) isn't always encoded into
'mod_wsgi.so' correctly. This seems to vary between what Python installation
was used and what MacOS X operating system version. In this case, if
multiple installations of same version of Python in different locations,
may find the system installation rather than your custom installation.

In that situation you may need to use the ``--disable-framework`` option to
'configure' script for mod_wsgi. This doesn't actually disable use of the
framework, but does change how it links to use a more traditional library
style linking rather than framework linking. This seems to resolve the
problems in most cases.

Python Installation In Use
--------------------------

Although the 'mod_wsgi.so' file may be finding a specific Python shared
library and that may be from the correct installation, the Python library
when initialised doesn't actually know from where it came. As such, it uses
a series of checks to try and determine where the Python installation is
actually located.

This check has various subtleties and how it works varies depending on the
platform used. At its simplest though, on most UNIX systems it will check
all directories listed in the 'PATH' environment variable of the process.
In each of those directories it will look for the 'python' program. When it
finds such a file, it will then look for a corresponding 'lib' directory
containing a valid Python installation for the same version of Python as is
being run.

When it finds such a directory, the home for the Python installation will
be taken as being the parent directory of the directory containing the
'python' program file found.

Because this search is dependent on the 'PATH' environment variable, which
is likely set to a minimal set of directories for the Apache user, then if
you are using a Python installation in a non standard location, then it may
not properly find the location of that installation.

The easiest way to validate which Python installation is being used is to
use a test WSGI script to output the value of 'sys.prefix'::

    import sys 

    def application(environ, start_response):
        status = '200 OK'

        output = ''
        output += 'sys.version = %s\n' % repr(sys.version)
        output += 'sys.prefix = %s\n' % repr(sys.prefix)

        response_headers = [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        return [output]

For standard Python installation on a Linux system, this would produce
something like::

    sys.version = "'2.6.1 (r261:67515, Feb 11 2010, 00:51:29) \\n[GCC 4.2.1 (Apple Inc. build 5646)]'"
    sys.prefix = '/usr'

Thus, if you were expecting to pick up a separate Python installation
located under '/usr/local' or elsewhere, this would be indicative of a
problem.

It can also be worthwhile to check that the Python module search path also
looks correct. This can be done by using a test WSGI script to output the
value of 'sys.path'::

    import sys

    def application(environ, start_response):
        status = '200 OK'
        output = 'sys.path = %s' % repr(sys.path)

        response_headers = [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        return [output]

In both cases, even if incorrect location is being used for Python
installation and even if there is no actual Python installation of the
correct version under that root directory, then these test scripts should
still run as 'sys' module is a builtin module which can be satisified via
just the Python library.

If debugging, whether there is a Python installation underneath that root
directory, the subdirectory which you would want to look for is
'lib/pythonX.Y' corresponding to version of Python being used.

If the calculated directory is wrong, then you will need to use the
WSGIPythonHome directory to set the location to the correct value. The value
to use is what 'sys.prefix' is set to when the correct Python is run from
the command line and 'sys.prefix' output::

    >>> import sys
    >>> print sys.prefix
    /usr/local

Thus for case where installed under '/usr/local', would use::

    WSGIPythonHome /usr/local

Embedded Or Daemon Mode
-----------------------

WSGI applications can run in either embedded mode or daemon mode. In the
case of embedded mode, the WSGI application runs within the Apache child
processes themselves. In the case of daemon mode, they run within a
separate set of processes managed by mod_wsgi.

To determine what mode a WSGI application is running under, replace its
WSGI script with the test WSGI script as follows::

    import sys

    def application(environ, start_response):
        status = '200 OK'
        output = 'mod_wsgi.process_group = %s' % repr(environ['mod_wsgi.process_group']) 
        response_headers = [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        return [output]

If the configuration is such that the WSGI application is running in embedded
mode, then you will see::

    mod_wsgi.process_group = ''

This actually corresponds to the directive::

    WSGIProcessGroup %{GLOBAL}

having being used, or the same value being used to the 'process-group'
directive of WSGIScriptAlias. Do note though that these are also actually
the defaults for these if not explicitly defined.

If the WSGI application is actually running in daemon mode, then a non
empty string will instead be shown corresponding to the name of the daemon
process group used.

Sub Interpreter Being Used
--------------------------

As well as WSGI application being able to be delegated to run in either
embedded mode or daemon mode, within the process it ends up running in, it
can be delegated to a specific Python sub interpreter.

To determine which Python sub interpreter is being used within the process
the WSGI application is being run use the test WSGI script of::

    import sys

    def application(environ, start_response):
        status = '200 OK'
        output = 'mod_wsgi.application_group = %s' % repr(environ['mod_wsgi.application_group'])

        response_headers = [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        return [output]

If being run in the main interpreter, ie., the first interpreter created by
Python, this will output::

    mod_wsgi.application_group = ''

This actually corresponds to the directive::

    WSGIApplicationGroup %{GLOBAL}

having being used, or the same value being used to the 'application-group'
directive of WSGIScriptAlias.

The default for these if not defined is actually '%{RESOURCE}'. This will
be a value made up from the name of the virtual host or server, the port
on which connection was accepted and the mount point of the WSGI application.
The port however is actually dropped where port is 80 or 443.

An example of what you would expect to see is::

    mod_wsgi.application_group = 'tests.example.com|/interpreter.wsgi'

This corresponds to server name of 'tests.example.com' with connection
received on either port 80 or 443 and where WSGI application was mounted at
the URL of '/interpreter.wsgi'.

Single Or Multi Threaded
------------------------

Apache supports differing Multiprocessing Modules (MPMs) having different
attributes. One such difference is whether a specific Apache child process
uses multiple threads for handling requests or whether a single thread is
instead used.

Depending on how you configure a daemon process group when using daemon
mode will also dictate whether single or multithreaded. By default, if
number of threads is not explicitly specified for a daemon process group,
it will be multithreaded.

Whether a WSGI application is executing within a multithreaded environment
is important to know. If it is, then you need to ensure that your own code
and any framework you are using is also thread safe.

A test WSGI script for validating whether WSGI application running in
multithread configuration is as follows::

    import sys

    def application(environ, start_response):
        status = '200 OK'
        output = 'wsgi.multithread = %s' % repr(environ['wsgi.multithread'])

        response_headers = [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        return [output]

If multithreaded, this will yield::

    wsgi.multithread = True

Multithreaded would usually be true on Windows, on UNIX if running in embedded
mode and worker MPM is used by Apache, or if using daemon mode and number of
threads not explicitly set, or number of threads explicitly set to value other
than '1'.
