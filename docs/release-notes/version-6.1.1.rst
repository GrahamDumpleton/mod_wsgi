=============
Version 6.1.1
=============

Features Changed
----------------

* ``mod_wsgi-standalone`` package has been updated to use
  ``mod_wsgi-httpd-2.4.69.1``. This moves from Apache 2.4.68 to Apache
  2.4.69, which includes a range of CVE fixes as detailed in the
  `Apache HTTP Server 2.4.69 changelog <https://dlcdn.apache.org/httpd/CHANGES_2.4.69>`_,
  and from PCRE2 10.48 to PCRE2 10.49, which fixes an out of bounds
  write in the PCRE2 JIT. The APR and APR-util versions are unchanged
  at 1.7.6 and 1.6.5.

Bugs Fixed
----------

* The ``configure`` script used by the classic ``make`` based build now
  tests whether the linker can find ``libpython`` on its own, and adds
  the Python library directory to the linker search path only when it
  cannot. The directory was only ever added when it differed from the
  Apache library directory, on the assumption that a directory shared
  with Apache is one the linker searches by default. That is not so on
  FreeBSD, where both are ``/usr/local/lib``, so linking the module
  failed against a Python built without gettext support. A Python built
  with gettext support linked only because its own library flags named
  the directory. Where the plain link succeeds nothing is added, so the
  module does not record an RPATH naming a standard directory on
  platforms where that is rejected.
