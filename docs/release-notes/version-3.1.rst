===========
Version 3.1
===========

Version 3.1 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-3.1.tar.gz

As this version follows on quickly from mod_wsgi 3.0, ensure you read:

* :doc:`version-3.0`

Bug Fixes
---------

1. Ensure that any compiler flags supplied via the CFLAGS environment variable
when running 'configure' script are prefixed by '-Wc,' before being passed to
'apxs' to build module. Without this 'apxs' will incorrectly interpret the
compiler options. For more details see:

  http://code.google.com/p/modwsgi/issues/detail?id=166

Features Changed
----------------

1. Now give more explicit error message when compilation fails due to the
Apache or Python developer header files not being installed. See:

  http://code.google.com/p/modwsgi/issues/detail?id=169
