:orphan:

=============
Version 4.2.1
=============

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. The auto generated configuration would not work with an Apache
installation where core Apache modules were statically compiled into Apache
rather than being dynamically loaded.
