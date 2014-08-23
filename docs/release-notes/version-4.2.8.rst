=============
Version 4.2.8
=============

Version 4.2.8 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.2.8.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. Disable feature for dumping stack traces on daemon process shutdown when
a timeout occurs when using Python prior to 2.5. This is because the C API
functions are not available in older Python versions.

2. If using Python 3.4 the minimum MacOS X version you can use is 10.8.
This needs to be inforced as Apache Runtime library has a definition in
header files which changes sizes from 10.7 to 10.8 and trying to compile
for compatability back to 10.6 as Python 3.4 tries to enforce, will cause
mod_wsgi daemon mode processes to crash at runtime.
