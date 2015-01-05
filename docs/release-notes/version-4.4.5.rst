=============
Version 4.4.5
=============

Version 4.4.5 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.5

Known Issues
------------

1. Although the makefiles for building mod_wsgi on Windows have now been
updated for the new source code layout, some issues are being seen with
mod_wsgi on Apache 2.4. These issues are still being investigated. As
most new changes in 4.X relate to mod_wsgi daemon mode, which is not
supported under Windows, you should keep using the last available binary
for version 3.X on Windows instead. Binaries compiled by a third party
can be obtained from:

* http://www.lfd.uci.edu/~gohlke/pythonlibs/#mod_wsgi

Bugs Fixed
----------

1. When installing ``mod_wsgi-express`` from PyPi on OpenShift as a
dependency of an application ``setup.py`` file, the precompiled Apache
binaries would not be installed.
