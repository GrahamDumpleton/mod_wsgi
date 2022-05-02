=============
Version 4.9.1
=============

Version 4.9.1 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.9.1

Bugs Fixed
----------

* When using ``--enable-debugger`` of mod_wsgi-express to enable Pdb, it was
  failing due to prior changes to run Apache in a sub processes to avoid Apache
  being shutdown when the window size changed. This was because standard input
  was being detached from Apache and so it was not possible to interact with
  Pdb. Now when ``--enable-debugger`` is used, or any feature which uses
  ``--debug-mode``, Apache will not be run in a sub process so that you can
  still use standard input to interact with the process if needed. This does
  mean that a window size change event will again cause Apache to shutdown in
  these cases though.

* Update code so compiles on Python 3.11. Python 3.11 makes structures for
  Python frame objects opaque and requires functions to access struct members.

Features Changed
----------------

* Historically when a process was being shutdown, mod_wsgi would do its best to
  destroy any Python sub interpreters as well as the main Python interpreter.
  This was done in case applications attempted to run any actions on process
  shutdown via ``atexit`` registered callbacks or other means.

  Because of changes in Python 3.9, and possibly because mod_wsgi makes use of
  externally created C threads to handle requests, and not Python native
  threads, there is now a suspiscion that attempting to delete Python sub
  interpreters can hang. It is believed this may relate to Python core now
  expecting all Python thread state objects to have been deleted before the
  Python sub interpreter can be destroyed. If they aren't then Python core
  code can block indefinitely. If the issue isn't the externally created C
  threads that mod_wsgi uses, it might instead be arising as a problem when a
  hosted WSGI application creates its own background threads but they are
  still running when the attempt is made to destroy the sub interpreter.

  In the case of using daemon mode the result is that processes can hang on
  shutdown, but will still at least be deleted after 5 seconds due to how
  Apache process management will forcibly kill managed processes after 5
  seconds if they do not exit cleanly themselves. In other words the issue
  may not be noticed.

  For embedded mode however, the Apache child process can hang around
  indefinitely, possibly only being deleted if some higher level system
  application manager such as systemd is able to detect the problem and
  forcibly deleted the hung process.

  Although mod_wsgi always attempts to ensure that the externally created C
  threads are not still handling HTTP requests and thus not active prior to
  destroying the Python interpreter, it is impossible to guarantee this.
  Similarly, there is no way to guarantee that background threads created by a
  WSGI application aren't still running. As such, it isn't possible to safely
  attempt to delete the Python thread state objects before deleting the Python
  sub interpreter.

  Because of this uncertainty mod_wsgi now provides a way to disable the attempt
  to destroy the Python sub interpreters or the main Python interpreter when the
  process is being shutdown. This will though mean that ``atexit`` registered
  callbacks will not be called if this option is enabled. It is therefore
  important that you use mod_wsgi's own mechanism of being notified when a
  process is being shutdown to perform any special actions.

  ::

    import mod_wsgi

    def shutdown_handler(event, **kwargs):
      print('SHUTDOWN-HANDLER', event, kwargs)

    mod_wsgi.subscribe_shutdown(shutdown_handler)
  
  Use of this shutdown notification was necessary anyway to reliably attempt
  to stop background threads created by the WSGI application since ``atexit``
  registered callbacks are not called by Python core until after it thinks all
  threads have been stopped. In other words, ``atexit`` register callbacks
  couldn't be used to reliably stop background threads. Thus use of the
  mod_wsgi mechanism for performing actions on process shutdown is the
  preferred way.

  Overall it is expected that the majority of users will not notice this
  change as it is very rare to see WSGI applications want to perform special
  actions on process shutdown. If you are affected, you should use mod_wsgi's
  mechanism to perform special actions on process shutdown.

  If you need to enable this mode whereby no attempt is made to destroy the
  Python interpreter (including sub interpreters) on process shutdown, you can
  add at global scope in the Apache configuration::

    WSGIDestroyInterpreter Off

  If you are using mod_wsgi-express, you can instead supply the command line
  option ``--orphan-interpreter``.
