=============
Version 5.0.1
=============

Version 5.0.1 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/5.0.1

Bugs Fixed
----------

* Fix issue which could result in process crashing when values were supplied
  for user/password/realm of HTTP basic authentication which weren't compliant
  with UTF-8 encoding format.

* Fix memory leak in `check_password()` authentication hook handler.
