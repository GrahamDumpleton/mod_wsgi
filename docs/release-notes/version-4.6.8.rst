=============
Version 4.6.8
=============

Version 4.6.8 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.6.8

Bugs Fixed
----------

* When the queue timeout was triggered for requests sent to daemon mode
  processes, the error response wasn't being flushed out correctly resulting
  in the connection still being held up to the time of the socket timeout.

New Features
------------

* Add ``--enable-sendfile`` option to ``mod_wsgi-express``. Should only be
  used where the operating system kernel supports ``sendfile()`` for the
  file system type where files are hosted.
