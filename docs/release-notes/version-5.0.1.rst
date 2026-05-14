=============
Version 5.0.1
=============

Features Changed
----------------

* Internally, when using Python 3.8 or newer, the PyConfig API will now be used
  due to deprecation and future removal of older C API alternatives. This was
  required to support Python 3.13.

Bugs Fixed
----------

* Fix issue which could result in process crashing when values were supplied
  for user/password/realm of HTTP basic authentication which weren't compliant
  with UTF-8 encoding format.

* Fix memory leak in `check_password()` authentication hook handler.

* Change use of deprecated `thread.setDaemon` to `thread.daemon`.
