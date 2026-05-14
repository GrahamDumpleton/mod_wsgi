:orphan:

==============
Version 4.5.15
==============

Bugs Fixed
----------

* Incorrect version for mod_wsgi was being reported in server token.

* On 32 bit platforms, when reading from request content, all input would
  be returned and the chunk size would be ignored.
