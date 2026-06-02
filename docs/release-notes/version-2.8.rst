:orphan:

===========
Version 2.8
===========

Bug Fixes
---------

1. Ensure that any compiler flags supplied via the CFLAGS environment variable
when running 'configure' script are prefixed by '-Wc,' before being passed to
'apxs' to build module. Without this 'apxs' will incorrectly interpret the
compiler options. For more details see:

  https://code.google.com/archive/p/modwsgi/issues/166
