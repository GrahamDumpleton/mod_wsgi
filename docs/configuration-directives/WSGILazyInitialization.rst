======================
WSGILazyInitialization
======================

:Description: Enable/disable lazy initialisation of Python.
:Syntax: ``WSGILazyInitialization On|Off``
:Default: ``WSGILazyInitialization On``
:Context: server config

The WSGILazyInitialization directives sets whether or not the Python
interpreter is preinitialised within the Apache parent process or whether
lazy initialisation is performed, and the Python interpreter only
initialised in the Apache server processes or mod_wsgi daemon processes
after they have forked from the Apache parent process.

In versions of mod_wsgi prior to version 3.0 the Python interpreter was
always preinitialised in the Apache parent process. This did mean that
theoretically some benefit in memory usage could be derived from delayed
copy on write semantics of memory inherited by child processes that was
initialised in the parent. This memory wasn't significant however and was
tempered by the fact that the Python interpreter when destroyed and then
reinitialised in the Apache parent process on an Apache restart, would with
some Python versions leak memory. This meant that if a server had many
restarts performed, the Apache parent process and thus all forked child
processes could grow in memory usage over time, eventually necessitating
Apache be completely stopped and then restarted.

This issue of memory leaks with the Python interpreter reached an extreme
with Python 3.0, where by design, various data structures would not be
destroyed on the basis that it would be reused when Python interpreter was
reinitialised within the same process. The problem is that when an Apache
restart is performed, mod_wsgi and the Python library are unloaded from
memory, with the result that the references to that memory would be lost
and so a real memory leak, of significant size and much worse that older
versions of Python, would result.

As a consequence, with mod_wsgi 3.0 and onwards, the Python interpreter is
not initialised by default in the Apache parent process for any version of
Python. This avoids completely the risk of cummulative memory leaks by the
Python interpreter on a restart into the Apache parent process, albeit with
potential for a slight increase in child process memory sizes. If need be,
the existing behaviour can be restored by setting the directive with the
value 'Off'.

A further upside of using lazy initialisation is that if you are using
daemon mode only, ie., not using embedded mode, you can completely turn off
initialisation of the Python interpreter within the main Apache server
child process. Unfortunately, because it isn't possible in the general case
to know whether embedded mode will be needed or not, you will need to
manually set the configuration to do this. This can be done by setting::

    WSGIRestrictEmbedded On

With restrictions on embedded mode enabled, any attempt to run a WSGI
application in embedded mode will fail, so it will be necessary to ensure
all WSGI applications are delegated to run in daemon mode. Although WSGI
applications will be restricted from being run in embedded mode and the
Python interpreter therefore not initialised, it will fallback to being
initialised if you use any of the Python hooks for access control,
authentication or authorisation providers, or WSGI application dispatch
overrides.

Note that if mod_python is being used in the same Apache installation,
because mod_python takes precedence over mod_wsgi in initialising the
Python interpreter, lazy initialisation cannot be done and so Python
interpreter will continue to be preinitialised in the Apache parent process
regardless of the setting of WSGILazyInitialization. Use of mod_python will
thus perpetuate the risk of memory leaks and growing memory use of Apache
process. This is especially the case since mod_python doesn't even properly
destroy the Python interpreter in the Apache parent process on a restart
and so all memory associated with the Python interpreter is leaked and not
just that caused by the Python interpreter when it is destroyed and doesn't
clean up after itself.
