=============
Version 6.1.0
=============

Features Changed
----------------

* ``mod_wsgi-standalone`` package has been updated to use
  ``mod_wsgi-httpd-2.4.68.2``. This provides the same Apache 2.4.68
  version as before, but it is now built with APR-util 1.6.5 in place of
  1.6.3, and against the PCRE2 library (version 10.48) in place of the
  original PCRE library (version 8.45). The original PCRE library reached
  end of life with version 8.45 and no longer receives fixes.

* Python 3.15 has been added to the Python versions listed in the package
  classifiers for the ``mod_wsgi`` and ``mod_wsgi-standalone`` packages
  on PyPi.
