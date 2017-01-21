==============
Version 4.5.14
==============

Version 4.5.14 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.14

New Features
------------

* Added a ``name`` attribute to the log object used in place of
  ``sys.stdout`` and ``sys.stderr``, and which is also used for
  ``wsgi.errors`` in the per request ``environ`` dictionary. This is
  because although the ``name`` attribute is not required to exist, one can
  find code out there that assumes it always does exist for file like
  objects. Adding the attribute ensures that such code doesn't fail.
