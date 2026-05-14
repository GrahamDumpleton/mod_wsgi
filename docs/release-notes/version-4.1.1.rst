:orphan:

=============
Version 4.1.1
=============

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. Compilation would fail on Apache 2.4 due to a change in the Apache API to
determine the name of the MPM being used.
