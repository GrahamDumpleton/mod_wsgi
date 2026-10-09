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
