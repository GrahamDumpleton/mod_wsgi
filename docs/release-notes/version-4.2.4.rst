=============
Version 4.2.4
=============

Version 4.2.4 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.2.4.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. Fixed one off error in applying limit to the number of supplementary
groups allowed for a daemon process group. The result could be that if
more groups than the operating system allowed were specified to the option
``supplementary-groups``, then memory corruption or a process crash could
occur.

2. Improved error handling in setting up the current working directory and
group access rights for a process when creating a daemon process group. The
change means that if any error occurs that the daemon process group will be
restarted rather than allow it to keep running with an incorrect working
directory or group access rights.

New Features
------------

1. Added the ``--setup-only`` option to mod_wsgi express so that it is
possible to create the configuration when using the Django management command
``runmodwsgi`` without actually starting the server.
