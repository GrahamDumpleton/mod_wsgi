===========
Version 2.5
===========

Version 2.5 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-2.5.tar.gz

For Windows binaries see:

  http://code.google.com/p/modwsgi/wiki/InstallationOnWindows

Note that this release does not support Python 3.0. Python 3.0 will only be
supported in mod_wsgi 3.0.

Bug Fixes
---------

1. Change to workaround problem where correct version of Python framework
isn't being found at run time and instead uses the standard system one,
which may be the wrong version. Change is for those Python versions on
MacOS X which include a .a in Python config directory, which should be
symlinked to framework, link against the .a instead. For some reason, doing
this results in framework then being picked up from the correct location.

This problem may well have only started cropping up at some point due to a
MacOS X Leopard patch update as has been noticed that Python frameworks
installed previously stopped being found properly when mod_wsgi was
subsequently recompiled against them. Something may therefore have changed
in compiler tools suite.

For more details see:

  http://code.google.com/p/modwsgi/issues/detail?id=28

2. Remove isatty from Log object used for stdout/stderr. It should have
been a function and not an attribute. Even so, isatty() is not meant to be
supplied by a file like object if it is associated with a file descriptor.
Thus, packages which want to use isatty() are supposed to check for its
existance before calling it. Thus wasn't ever mod_wsgi that was wrong in
not supply this, but the packages which were trying to use it.

For more details see:

  http://code.google.com/p/modwsgi/issues/detail?id=146
