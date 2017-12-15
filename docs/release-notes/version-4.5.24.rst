==============
Version 4.5.24
==============

Version 4.5.24 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.24

Bugs Fixed
----------

* Using mod_wsgi in daemon mode on Solaris would cause a process hang or
  max out CPU usage. Caused by change of variable type to unsigned to get
  rid of compiler warnings, without fixing how condition check using
  variable was done.

  Problem could also affect non Solaris systems if total number of HTTP
  headers and other variables passed in WSGI environ was greater than 1024.
  Affected Solaris all the time due to it having a limit of only 16 in
  operating system for same code, meaning hit problem immediately.
