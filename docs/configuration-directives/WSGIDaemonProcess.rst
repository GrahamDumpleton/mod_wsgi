=================
WSGIDaemonProcess
=================

:Description: Configure a distinct daemon process for running applications.
:Syntax: ``WSGIDaemonProcess`` *name* ``[`` *options* ``]``
:Context: server config, virtual host

The WSGIDaemonProcess directive can be used to specify that distinct daemon
processes should be created to which the running of WSGI applications can
be delegated. Where Apache has been started as the ``root`` user, the
daemon processes can be run as a user different to that which the Apache
child processes would normally be run as.

When distinct daemon processes are enabled and used, the process is
dedicated to mod_wsgi and the only thing that the processes do is run the
WSGI applications assigned to that process group. Any other Apache modules
such as PHP or activities such as serving up static files continue to be
run in the standard Apache child processes.

Note that having denoted that daemon processes should be created by using
the WSGIDaemonProcess directive, the WSGIProcessGroup directive still needs
to be used to delegate specific WSGI applications to execute within those
daemon processes.

Also note that the name of the daemon process group must be unique for the
whole server. That is, it is not possible to use the same daemon process
group name in different virtual hosts.

Options which can be supplied to the WSGIDaemonProcess directive are:

**user=name | user=#uid**.rst
    Defines the UNIX user *name* or numeric user *uid* of the user that
    the daemon processes should be run as. If this option is not supplied
    the daemon processes will be run as the same user that Apache would
    run child processes and as defined by the `User`_ directive.

    Note that this option is ignored if Apache wasn't started as the root
    user, in which case no matter what the settings, the daemon processes
    will be run as the user that Apache was started as.

	Also be aware that mod_wsgi will not allow you to run a daemon
	process group as the root user due to the security risk of running
	a web application as root.

**group=name | group=#gid**
    Defines the UNIX group *name* or numeric group *gid* of the primary
    group that the daemon processes should be run as. If this option is not
    supplied the daemon processes will be run as the same group that Apache
    would run child processes and as defined by the `Group`_ directive.

    Note that this option is ignored if Apache wasn't started as the root
    user, in which case no matter what the settings, the daemon processes
    will be run as the group that Apache was started as.

**processes=num**
    Defines the number of daemon processes that should be started in this
    process group. If not defined then only one process will be run in this
    process group.

    Note that if this option is defined as 'processes=1', then the WSGI
    environment attribute called 'wsgi.multiprocess' will be set to be True
    whereas not providing the option at all will result in the attribute
    being set to be False. This distinction is to allow for where some form
    of mapping mechanism might be used to distribute requests across
    multiple process groups and thus in effect it is still a multiprocess
    application. If you need to ensure that 'wsgi.multiprocess' is False so
    that interactive debuggers will work, simply do not specify the
    'processes' option and allow the default single daemon process to be
    created in the process group.

**threads=num**
    Defines the number of threads to be created to handle requests in each
    daemon process within the process group.
    
    If this option is not defined then the default will be to create 15
    threads in each daemon process within the process group.

**umask=0nnn**
    Defines a value to be used for the umask of the daemon processes within
    the process group. The value must be provided as an octal number.
    
    If this option is not defined then the umask of the user that Apache is
    initially started as will be inherited by the process. Typically the
    inherited umask would be '0022'.

**home=directory**
    Defines an absolute path of a directory which should be used as the
    initial current working directory of the daemon processes within the
    process group.
    
    If this option is not defined, in mod_wsgi 1.X the current working
    directory of the Apache parent process will be inherited by the daemon
    processes within the process group. Normally the current working directory
    of the Apache parent process would be the root directory. In mod_wsgi 2.0+
    the initial current working directory will be set to be the home
    directory of the user that the daemon process runs as.

**python-path=directory | python-path=directory:directory**
    List of colon separated directories to add to the Python module search
    path, ie., ``sys.path``.

    Note that this is not strictly the same as having set ``PYTHONPATH``
    environment variable when running normal command line Python. When this
    option is used, the directories are added by calling
    ``site.addsitedir()``. As well as adding the directory to
    ``sys.path`` this function has the effect of opening and interpreting
    any '.pth' files located in the specified directories. The option
    therefore can be used to point at the ``site-packages`` directory
    corresponding to a Python virtual environment created by a tool such as
    ``virtualenv``, with any additional directories corresponding to
    Python eggs within that directory also being automatically added to
    ``sys.path``.

**python-eggs=directory**
    Directory to be used as the Python egg cache directory. This is
    equivalent to having set the ``PYTHON_EGG_CACHE`` environment
    variable.

    Note that the directory specified must exist and be writable by the
    user that the daemon process run as.

**stack-size=nnn**
    The amount of virtual memory in bytes to be allocated for the stack
    corresponding to each thread created by mod_wsgi in a daemon process.

    This option would be used when running Linux in a VPS system which has
    been configured with a quite low 'Memory Limit' in relation to the
    'Context RSS' and 'Max RSS Memory' limits. In particular, the default
    stack size for threads under Linux is 8MB is quite excessive and could
    for such a VPS result in the 'Memory Limit' being exceeded before the
    RSS limits were exceeded. In this situation, the stack size should be
    dropped down to be in the region of 512KB (524288 bytes).

**maximum-requests=nnn**
    Defines a limit on the number of requests a daemon process should
    process before it is shutdown and restarted. Setting this to a non zero
    value has the benefit of limiting the amount of memory that a process
    can consume by (accidental) memory leakage.

    If this option is not defined, or is defined to be 0, then the daemon
    process will be persistent and will continue to service requests until
    Apache itself is restarted or shutdown.

**inactivity-timeout=sss**
    Defines the maximum number of seconds allowed to pass before the
    daemon process is shutdown and restarted when the daemon process has
    entered an idle state. For the purposes of this option, being idle
    means no new requests being received, or no attempts by current
    requests to read request content or generate response content for the
    defined period.

    This option exists to allow infrequently used applications running in
    a daemon process to be restarted, thus allowing memory being used to
    be reclaimed, with process size dropping back to the initial startup
    size before any application had been loaded or requests processed.

**deadlock-timeout=sss**
    Defines the maximum number of seconds allowed to pass before the
    daemon process is shutdown and restarted after a potential deadlock on
    the Python GIL has been detected. The default is 300 seconds.

    This option exists to combat the problem of a daemon process freezing
    as the result of a rouge Python C extension module which doesn't
    properly release the Python GIL when entering into a blocking or long
    running operation.

**shutdown-timeout=sss**
    Defines the maximum number of seconds allowed to pass when waiting
    for a daemon process to gracefully shutdown as a result of the maximum
    number of requests or inactivity timeout being reached, or when a user
    initiated SIGINT signal is sent to a daemon process. When this timeout
    has been reached the daemon process will be forced to exited even if
    there are still active requests or it is still running Python exit
    functions.

    If this option is not defined, then the shutdown timeout will be set
    to 5 seconds. Note that this option does not change the shutdown
    timeout applied to daemon processes when Apache itself is being stopped
    or restarted. That timeout value is defined internally to Apache as 3
    seconds and cannot be overridden.

**display-name=value**
    Defines a different name to show for the daemon process when using the
    'ps' command to list processes. If the value is '%{GROUP}' then the
    name will be '(wsgi:group)' where 'group' is replaced with the name
    of the daemon process group.

    Note that only as many characters of the supplied value can be displayed
    as were originally taken up by 'argv0' of the executing process. Anything
    in excess of this will be truncated.

    This feature may not work as described on all platforms. Typically it
    also requires a 'ps' program with BSD heritage. Thus on Solaris UNIX
    the '/usr/bin/ps' program doesn't work, but '/usr/ucb/ps' does.

**receive-buffer-size=nnn**
    Defines the UNIX socket buffer size for data being received by the
    daemon process from the Apache child process.

    This option may need to be used to override small default values set by
    certain operating systems and would help avoid possibility of deadlock
    between Apache child process and daemon process when WSGI application
    generates large responses but doesn't consume request content. In
    general such deadlock problems would not arise with well behaved WSGI
    applications, but some spam bots attempting to post data to web sites
    are known to trigger the problem.

    The maximum possible value that can be set for the buffer size is
    operating system dependent and will need to be calculated through trial
    and error.

**send-buffer-size=nnn**
    Defines the UNIX socket buffer size for data being sent in the
    direction daemon process back to Apache child process.

    This option may need to be used to override small default values set by
    certain operating systems and would help avoid possibility of deadlock
    between Apache child process and daemon process when WSGI application
    generates large responses but doesn't consume request content. In
    general such deadlock problems would not arise with well behaved WSGI
    applications, but some spam bots attempting to post data to web sites
    are known to trigger the problem.

    The maximum possible value that can be set for the buffer size is
    operating system dependent and will need to be calculated through trial
    and error.

To delegate a particular WSGI application to run in a named set of daemon
processes, the WSGIProcessGroup directive should be specified in
appropriate context for that application. If WSGIProcessGroup is not used,
the application will be run within the standard Apache child processes.

If the WSGIDaemonProcess directive is specified outside of all virtual
host containers, any WSGI application can be delegated to be run within
that daemon process group. If the WSGIDaemonProcess directive is specified
within a virtual host container, only WSGI applications associated with
virtual hosts with the same server name as that virtual host can be
delegated to that set of daemon processes.

When WSGIDaemonProcess is associated with a virtual host, the error log
associated with that virtual host will be used for all Apache error log
output from mod_wsgi rather than it appear in the main Apache error log.

For example, if a server is hosting two virtual hosts and it is desired
that the WSGI applications related to each virtual host run in distinct
processes of their own and as a user which is the owner of that virtual
host, the following could be used::

  <VirtualHost *:80>
  ServerName www.site1.com
  CustomLog logs/www.site1.com-access_log common
  ErrorLog logs/ww.site1.com-error_log

  WSGIDaemonProcess www.site1.com user=joe group=joe processes=2 threads=25
  WSGIProcessGroup www.site1.com

  ...
  </VirtualHost>

  <VirtualHost *:80>
  ServerName www.site2.com
  CustomLog logs/www.site2.com-access_log common
  ErrorLog logs/www.site2.com-error_log

  WSGIDaemonProcess www.site2.com user=bob group=bob processes=2 threads=25
  WSGIProcessGroup www.site2.com

  ...
  </VirtualHost>

Note that the WSGIDaemonProcess directive and corresponding features are
not available on Windows or when running Apache 1.3.

.. _User: http://httpd.apache.org/docs/2.2/mod/mpm_common.html#user
.. _Group: http://httpd.apache.org/docs/2.2/mod/mpm_common.html#group
