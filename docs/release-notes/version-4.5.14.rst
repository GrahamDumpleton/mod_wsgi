==============
Version 4.5.14
==============

Version 4.5.14 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.14

Bugs Fixed
----------

* Using the ``--url-alias`` option to the ``runmodwsgi`` management
  command when integrating ``mod_wsgi-express`` with Django could fail
  with Python 3. This is because the type of the items passed in an
  option list could be tuple or list depending on Python version. It
  was necessary to add items with same type else sorting would break.

New Features
------------

* Added a ``name`` attribute to the log object used in place of
  ``sys.stdout`` and ``sys.stderr``, and which is also used for
  ``wsgi.errors`` in the per request ``environ`` dictionary. This is
  because although the ``name`` attribute is not required to exist, one can
  find code out there that assumes it always does exist for file like
  objects. Adding the attribute ensures that such code doesn't fail.
