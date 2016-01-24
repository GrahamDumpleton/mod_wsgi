=====================
Reloading Source Code
=====================

This document contains information about mechanisms available in mod_wsgi
for automatic reloading of source code when an application is changed and
any issues related to those mechanisms.

Embedded Mode Vs Daemon Mode
----------------------------

What is achievable in the way of automatic source code reloading depends on
which mode your WSGI application is running.

If your WSGI application is running in embedded mode then what happens when
you make code changes is largely dictated by how Apache works, as it
controls the processes handling requests. In general, if using embedded
mode you will have no choice but to manually restart Apache in order for code
changes to be used.

If using daemon mode, because mod_wsgi manages directly the processes
handling requests and in which your WSGI application runs, there is more
avenue for performing automatic source code reloading.

As a consequence, it is important to understand what mode your WSGI
application is running in.

If you are running on Windows, are using Apache 1.3, or have not used
WSGIDaemonProcess/WSGIProcessGroup directives to delegate your WSGI
application to a mod_wsgi daemon mode process, then you will be using
embedded mode.

If you are not sure whether you are using embedded mode or daemon mode,
then substitute your WSGI application entry point with::

    def application(environ, start_response):
        status = '200 OK'

        if not environ['mod_wsgi.process_group']:
          output = 'EMBEDDED MODE'
        else:
          output = 'DAEMON MODE'

        response_headers = [('Content-Type', 'text/plain'),
                            ('Content-Length', str(len(output)))]

        start_response(status, response_headers)

        return [output]

If your WSGI application is running in embedded mode, this will output to
the browser 'EMBEDDED MODE'. If your WSGI application is running in daemon
mode, this will output to the browser 'DAEMON MODE'.

Reloading In Embedded Mode
--------------------------

However you have configured Apache to mount your WSGI application, you will
have a script file which contains the entry point for the WSGI application.
This script file is not treated exactly like a normal Python module and
need not even use a '.py' extension. It is even preferred that a '.py'
extension not be used for reasons described below.

For embedded mode, one of the properties of the script file is that by
default it will be reloaded whenever the file is changed. The primary
intent with the file being reloaded is to provide a second chance at
getting any configuration in it and the mapping to the application correct.
If the script weren't reloaded in this way, you would need to restart
Apache even for a trivial change to the script file.

Do note though that this script reloading mechanism is not intended as a
general purpose code reloading mechanism. Only the script file itself is
reloaded, no other Python modules are reloaded. This means that if modifying
normal Python code files which are used by your WSGI application, you will
need to trigger a restart of Apache. For example, if you are using Django
in embedded mode and needed to change your 'settings.py' file, you would
still need to restart Apache.

That only the script file and not the whole process is reloaded also has a
number of implications and imposes certain restrictions on what code in the
script file can do or how it should be implemented.

The first issue is that when the script file is imported, if the code makes
modifications to ``sys.path`` or other global data structures and the
changes are additive, checks should first be made to ensure that the change
has not already been made, else duplicate data will be added every time the
script file is reloaded.

This means that when updating ``sys.path``, instead of using::

    import sys
    sys.path.append('/usr/local/wsgi/modules')

the more correct way would be to use::

    import sys
    path = '/usr/local/wsgi/modules'
    if path not in sys.path:
        sys.path.append(path)

This will ensure that the path doesn't get added multiple times.

Even where the script file is named so as to have a '.py' extension, that
the script file is not treated like a normal module means that you should
never try to import the file from another code file using the 'import'
statement or any other import mechanism. The easiest way to avoid this is
not use the '.py' extension on script files or never place script files in
a directory which is located on the standard module search path, nor add
the directory containing the script into ``sys.path`` explicitly.

If an attempt is made to import the script file as a module the result will
be that it will be loaded a second time as an independent module. This is
because script files are loaded under a module name which is keyed to the
full absolute path for the script file and not just the basename of the
file. Importing the script file directly and accessing it will therefore
not result in the same data being accessed as exists in the script file
when loaded.

Because the script file is not treated like a normal Python module also has
implications when it comes to using the "pickle" module in conjunction
with objects contained within the script file.

In practice what this means is that neither function objects, class objects
or instances of classes which are defined in the script file should be
stored using the "pickle" module.

The technical reasons for the limitations on the use of the "pickle" module
in conjunction with objects defined in the script file are further
discussed in the document :doc:`../user-guides/issues-with-pickle-module`.

The act of reloading script files also means that any data previously held
by the module corresponding to the script file will be deleted. If such
data constituted handles to database connections, and the connections are
not able to clean up themselves when deleted, it may result in resource
leakage.

One should therefore be cautious of what data is kept in a script file.
Preferably the script file should only act as a bridge to code and data
residing in a normal Python module imported from an entirely different
directory.

Restarting Apache Processes
---------------------------

As explained above, the only facility that mod_wsgi provides for reloading
source code files in embedded mode, is the reloading of just the script
file providing the entry point for your WSGI application.

If you don't have a choice but to use embedded mode and still desire some
measure of automatic source code reloading, one option available which
works for both Windows and UNIX systems is to force Apache to recycle the
Apache server child process that handles the request automatically after
the request has completed.

To enable this, you need to modify the value of the MaxRequestsPerChild
directive in the Apache configuration. Normally this would be set to a
value of '0', indicating that the process should never be restarted as a
result of the number of requests processed. To have it restart a process
after every request, set it to the value '1' instead::

    MaxRequestsPerChild 1

Do note however that this will cause the process to be restarted after any
request. That is, the process will even be restarted if the request was for
a static file or a PHP application and wasn't even handled by your WSGI
application. The restart will also occur even if you have made no changes
to your code.

Because a restart happens regardless of the request type, using this method
is not recommended.

Because of how the Apache server child processes are monitored and restarts
handled, it is technically possible that this method will yield performance
which is worse than CGI scripts. For that reason you may even be better off
using a CGI/WSGI bridge to host your WSGI application. At least that way
the handling of other types of requests, such as for static files and PHP
applications will not be affected.

Reloading In Daemon Mode
------------------------

If using mod_wsgi daemon mode, what happens when the script file is changed
is different to what happens in embedded mode. In daemon mode, if the
script file changed, rather than just the script file being reloaded, the
daemon process which contains the application will be shutdown and
restarted automatically.

Detection of the change in the script file will occur at the time of the
first request to arrive after the change has been made. The way that the
restart is performed does not affect the handling of the request, with it
still being processed once the daemon process has been restarted.

In the case of there being multiple daemon processes in the process group,
then a cascade effect will occur, with successive processes being restarted
until the request is again routed to one of the newly restarted processes.

In this way, restarting of a WSGI application when a change has been made
to the code is a simple matter of touching the script file if daemon mode
is being used. Any daemon processes will then automatically restart without
the need to restart the whole of Apache.

So, if you are using Django in daemon mode and needed to change your
'settings.py' file, once you have made the required change, also touch the
script file containing the WSGI application entry point. Having done that,
on the next request the process will be restarted and your Django
application reloaded.

Restarting Daemon Processes
---------------------------

If you are using daemon mode of mod_wsgi, restarting of processes can to a
degree also be controlled by a user, or by the WSGI application itself,
without restarting the whole of Apache.

To force a daemon process to be restarted, if you are using a single daemon
process with many threads for the application, then you can embed a page in
your application (password protected hopefully), that sends an appropriate
signal to itself.

This should only be done for daemon processes and not within the Apache
child processes, as sending such a signal within a child process may
interfere with the operation of Apache. That the code is executing within a
daemon process can be determined by checking the 'mod_wsgi.process_group'
variable in the WSGI environment passed to the application. The value will
be non empty if a daemon process::

    if environ['mod_wsgi.process_group'] != '':
        import signal, os
        os.kill(os.getpid(), signal.SIGINT)

This will cause the daemon process your application is in to shutdown. The
Apache process supervisor will then automatically restart your process
ready for subsequent requests. On the restart it will pick up your new
code. This way you can control a reload from your application through some
special web page specifically for that purpose.

You can also send this signal from an external application, but a problem
there may be identifying which process to send the signal to. If you are
running the daemon process(es) as a distinct user/group to Apache and each
application is running as a different user then you could just look for the
Apache (httpd) processes owned by the user the application is running as,
as opposed to the Apache user, and send them all signals.

If the daemon process is running as the same user as Apache or there are
distinct applications running in different daemon processes but as the same
user, knowing which daemon processes to send the signal may be harder to
determine.

Either way, to make it easier to identify which processes belong to a
daemon process group, you can use the 'display-name' option to the
WSGIDaemonProcess to name the process. On many platforms, when this option
is used, that name will then appear in the output from the 'ps' command
and not the name of the actual Apache server binary.

Monitoring For Code Changes
---------------------------

The use of signals to restart a daemon process could also be employed in a
mechanism which automatically detects changes to any Python modules or
dependent files. This could be achieved by creating a thread at startup
which periodically looks to see if file timestamps have changed and trigger
a restart if they have.

Example code for such an automatic restart mechanism which is compatible
with how mod_wsgi works is shown below::

    import os
    import sys
    import time
    import signal
    import threading
    import atexit
    import Queue

    _interval = 1.0
    _times = {}
    _files = []

    _running = False
    _queue = Queue.Queue()
    _lock = threading.Lock()

    def _restart(path):
        _queue.put(True)
        prefix = 'monitor (pid=%d):' % os.getpid()
        print >> sys.stderr, '%s Change detected to \'%s\'.' % (prefix, path)
        print >> sys.stderr, '%s Triggering process restart.' % prefix
        os.kill(os.getpid(), signal.SIGINT)

    def _modified(path):
        try:
            # If path doesn't denote a file and were previously
            # tracking it, then it has been removed or the file type
            # has changed so force a restart. If not previously
            # tracking the file then we can ignore it as probably
            # pseudo reference such as when file extracted from a
            # collection of modules contained in a zip file.

            if not os.path.isfile(path):
                return path in _times

            # Check for when file last modified.

            mtime = os.stat(path).st_mtime
            if path not in _times:
                _times[path] = mtime

            # Force restart when modification time has changed, even
            # if time now older, as that could indicate older file
            # has been restored.

            if mtime != _times[path]:
                return True
        except:
            # If any exception occured, likely that file has been
            # been removed just before stat(), so force a restart.

            return True

        return False

    def _monitor():
        while 1:
            # Check modification times on all files in sys.modules.

            for module in sys.modules.values():
                if not hasattr(module, '__file__'):
                    continue
                path = getattr(module, '__file__')
                if not path:
                    continue
                if os.path.splitext(path)[1] in ['.pyc', '.pyo', '.pyd']:
                    path = path[:-1]
                if _modified(path):
                    return _restart(path)

            # Check modification times on files which have
            # specifically been registered for monitoring.

            for path in _files:
                if _modified(path):
                    return _restart(path)

            # Go to sleep for specified interval.

            try:
                return _queue.get(timeout=_interval)
            except:
                pass

    _thread = threading.Thread(target=_monitor)
    _thread.setDaemon(True)

    def _exiting():
        try:
            _queue.put(True)
        except:
            pass
        _thread.join()

    atexit.register(_exiting)

    def track(path):
        if not path in _files:
            _files.append(path)

    def start(interval=1.0):
        global _interval
        if interval < _interval:
            _interval = interval

        global _running
        _lock.acquire()
        if not _running:
            prefix = 'monitor (pid=%d):' % os.getpid()
            print >> sys.stderr, '%s Starting change monitor.' % prefix
            _running = True
            _thread.start()
        _lock.release()

This would be used by importing into the script file the Python module
containing the above code, starting the monitoring system and adding any
additional non Python files which should be tracked::

    import os

    import monitor
    monitor.start(interval=1.0)
    monitor.track(os.path.join(os.path.dirname(__file__), 'site.cf'))

    def application(environ, start_response):
        ...

Where needing to add many non Python files in a directory hierarchy, such
as template files which would otherwise be cached within the running
process, the ``os.path.walk()`` function could be used to traverse
all files and add required files based on extension or other criteria
using the 'track()' function.

This mechanism would generally work adequately where a single daemon
process is used within a process group. You would need to be careful
however when multiple daemon processes are used. This is because it may not
be possible to synchronise the checks exactly across all of the daemon
processes. As a result you may end up with the daemon processes running a
mixture of old and new code until they all synchronise with the new code
base. This problem can be minimised by defining a short interval time
between scans, however that will increase the overhead of the checks.

Using such an approach may in some cases be useful if using mod_wsgi as a
development platform. It certainly would not be recommended you use this
mechanism for a production system.

The reasons for not using it on a production system is due to the
additional overhead and chance that daemon processes are restarted when you
are not expecting them to be. For example, in a production environment
where requests are coming in all the time, you do not want a restart
triggered when you are part way through making a set of changes which cover
multiple files as likely then that an inconsistent set of code will be
loaded and the application will fail.

Note that you should also not use this mechanism on a system where you have
configured mod_wsgi to preload your WSGI application as soon as the daemon
process has started. If you do that, then the monitor thread will be recreated
immediately and so for every single code change on a preloaded file you
make, the daemon process will be restarted, even if there is no intervening
request.

If preloading was really required, the example code would need to be
modified so as to not use signals to restart the daemon process, but reset
to zero the variable saved away in the WSGI script file that records the
modification time of the script file. This will have the affect of delaying
the restart until the next request has arrived. Because that variable holding
the modification time is an internal implementation detail of mod_wsgi and
not strictly part of its published API or behaviour, you should only use
that approach if it is warranted.

Restarting Windows Apache
-------------------------

On the Windows platform there is no daemon mode only embedded mode. The MPM
used on Apache is the 'winnt' MPM. This MPM is like the worker MPM on UNIX
systems except that there is only one process.

Being embedded mode, modifying the WSGI script file only results in the WSGI
script file itself being reloaded, the process as a whole is not reloaded.
Thus there is no way normally through modifying the WSGI script file or any
other Python code file used by the application, of having the whole
application reloaded automatically.

The recipe in the previous section can be used with daemon mode on UNIX
systems to implement an automated scheme for restarting the daemon
processes when any code change is made, but because Windows lacks the
'fork()' system call daemon mode isn't supported in the first place.

Thus, the only way one can have code changes picked up on Windows is to
restart Apache as a whole. Although a full restart is required, Apache on
Windows only uses a single child server process and so the impact isn't as
significant as on UNIX platforms, where many processes may need to be
shutdown and restarted.

With that in mind, it is actually possible to modify the prior recipe for
restarting a daemon process to restart Apache itself. To achieve this slight
of hand, it is necessary to use the Python 'ctypes' module to get access to
a special internal Apache function which is available in the Windows version
of Apache called 'ap_signal_parent()'.

The required change to get this to work is to replace the restart
function in the previous code with the following::

    def _restart(path):
        _queue.put(True)
        prefix = 'monitor (pid=%d):' % os.getpid()
        print >> sys.stderr, '%s Change detected to \'%s\'.' % (prefix, path)
        print >> sys.stderr, '%s Triggering Apache restart.' % prefix
        import ctypes
        ctypes.windll.libhttpd.ap_signal_parent(1)

Other than that, the prior code would be used exactly as before. Now when
any change is made to Python code used by the application or any other
monitored files, Apache will be restarted automatically for you.

As before, probably recommended that this only be used during development
and not on a production system.
