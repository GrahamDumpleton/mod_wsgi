===========
Version 3.3
===========

Version 3.3 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-3.3.tar.gz

Bug Fixes
---------

1. Inactivity timeout not triggered at correct time when occurs for first
request after process is started. See

  http://code.google.com/p/modwsgi/issues/detail?id=182

2. Back off timer for failed connections to daemon process group wasn't
working correctly and no delay on reconnect attempts was being applied. See:

  http://code.google.com/p/modwsgi/issues/detail?id=195

3. Logging not appearing in Apache error log files when using daemon mode
and have multiple virtual hosts against same server name. See:

  http://code.google.com/p/modwsgi/issues/detail?id=204

4. Eliminate logging of !KeyError exception in threading module when processes
are shutdown when using Python 2.6.5 or 3.1.2 or later. This wasn't indicating
any real problem but was annoying all the same. See:

  http://code.google.com/p/modwsgi/issues/detail?id=197

5. Fix potential for crash when logging error message resulting from failed
group authorisation.

6. Fix compilation problems with Apache 2.3.6.

Features Changed
----------------

1. When compiled against ITK MPM for Apache, if using daemon mode, the
listener socket for daemon process will be marked as being owned by the
same user that daemon process runs. This will at least allow a request
handled under ITK MPM to be directed to daemon process owned by same user
as script. See issue:

  http://code.google.com/p/modwsgi/issues/detail?id=187

2. Add isatty() to log objects used for sys.stdout/sys.stderr and
wsgi.errors. The Python documentation says 'If a file-like object is not
associated with a real file, this method should not be implemented'. That
however is ambiguous as to whether one can omit it, or whether one should
raise an NotImplementedError exception. Either way, various code doesn't
cope with isatty() not existing or failing, so implement it and have it
return False to be safe.
