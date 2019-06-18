=============
Version 4.6.8
=============

Version 4.6.8 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.6.8

New Features
------------

* Add ``--enable-sendfile`` option to ``mod_wsgi-express``. Should only be
  used where the operating system kernel supports ``sendfile()`` for the
  file system type where files are hosted.
