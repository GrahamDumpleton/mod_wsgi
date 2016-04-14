=============
Version 4.5.2
=============

Version 4.5.2 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.2

Bugs Fixed
----------

1. When using ``--debug-mode`` with ``mod_wsgi-express`` any additional
   directories to search for Python modules, which were supplied by the
   ``--python-path`` option, were not being added to ``sys.path``.
