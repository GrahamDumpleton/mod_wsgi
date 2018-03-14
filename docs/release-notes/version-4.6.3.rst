=============
Version 4.6.3
=============

Version 4.6.3 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.6.3

Bugs Fixed
----------

* When compiled for Python 2.6, when run mod_wsgi would fail to load into
  Apache due to misisng symbol ``PyFrame_GetLineNumber``. This was only
  introduced in Python 2.7. Use alternate way to get line number which
  still yields correct answer. This issue was introduced in mod_wsgi
  version 4.6.0 in fix to have correct line numbers generated for stack
  traces on shutdown due to request timeout.

* Installing mod_wsgi on Windows would fail as hadn't exclude mod_wsgi
  daemon mode specific code from Windows build. This would result in compile
  time error about ``wsgi_daemon_process`` being undefined. This problem
  was introduced to Windows in version 4.6.0.
