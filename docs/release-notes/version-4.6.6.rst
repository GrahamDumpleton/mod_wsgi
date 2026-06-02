:orphan:

=============
Version 4.6.6
=============

Bugs Fixed
----------

* Fix compilation failures when using Python 3.8.

Features Changed
----------------

* When running ``mod_wsgi-express`` it will do a search for the location of
  ``bash`` and ``sh`` when defining the shell to use for the generated
  ``apachectl``. The shell used can be overridden using ``--shell-executable``
  option. This is to get around issue with FreeBSD not having ``/bin/bash``.

New Features
------------

* The Apache request ID is accessible in request events as ``request_id``.

* The per request data dictionary accessible using ``mod_wsgi.request_data()``
  is now also accessible in events as ``request_data``.
