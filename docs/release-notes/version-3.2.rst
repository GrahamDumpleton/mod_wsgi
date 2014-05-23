===========
Version 3.2
===========

Version 3.2 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-3.2.tar.gz

Bug Fixes
---------

1. The path of the handler script was reported wrongly when
WSGIHandlerScript was being used and an error occurred when loading the
file. Rather than the handler script file being listed, the file to which
the URL mapped was reported instead.

2. Fix problem with use of condition variables/thread mutexes that was
causing all requests in daemon mode on a FreeBSD system to hang immediately
upon Apache being started.

  http://code.google.com/p/modwsgi/issues/detail?id=176

Also use a distinct flag with condition variable in case condition variable
is triggered even though condition not satisfied. This latter issue hasn't
presented as a known problem, but technically a condition variable can by
definition return even though not satisified. If this were to occur,
undefined behaviour could result as multiple threads could listen on socket
and/or accept connections on that socket at the same time.

3. Wrong check of APR_HAS_THREADS by preprocessor conditional resulting in code
not compiling where APR_HAS_THREADS was defined but 0.

4. When Apache error logging redirected to syslog there is no error log
associated with Apache server data structure to close. Code should always
check that there is an error log to avoid crashing mod_wsgi daemon process
on startup by operating on null pointer. See:

  http://code.google.com/p/modwsgi/issues/detail?id=178

5. Code was not compiling with Apache 2.3. This is because ap_accept_lock_mech
variable was removed. See:

  http://code.google.com/p/modwsgi/issues/detail?id=186
