==============
Version 4.5.21
==============

Version 4.5.21 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.21

Bugs Fixed
----------

* Installation using ``pip`` or ``setup.py`` install was failing on
  MacOS X High Sierra with latest Xcode as Apple doesn't even include
  the ``apxs`` program at all.

  Note you still cannot use the configure/make/make install method of
  deploying mod_wsgi to MacOS X. You need to use the ``pip install``
  method.

* Speculated that crashes on daemon process shutdown were being caused
  by a race condition around accessing Python C API when interpreter
  was being destroyed. There was a check in place to avoid this but may
  not have been robust enough depending on how memory cache worked
  for threads running across multi core machine. Now use a dedicated
  thread mutex to avoid race condition between main process thread and
  Python interpreter deadlock detection thread.

Features Changed
----------------

* Set ``wsgi.input_terminated`` to ``True`` in WSGI environment. This is a
  unofficial extension to WSGI specification proposed by Armin Ronacher
  for a WSGI server/middleware to flag that it is safe to read to the
  end of input and that ``CONTENT_LENGTH`` can be ignored. This is to be
  able to support chunked request content, but also anything which
  mutates the request content length but which can't easily change the
  ``CONTENT_LENGTH``, such as occurs when request content is compressed
  and is decompressed by the Apache web server.

  The ability to safely read until end of input was always present in
  mod_wsgi, but there was no way in the WSGI specification for a WSGI
  server to tell a WSGI application this was the case. Prior attempts to
  include something to deal with this in the WSGI specification when it
  was updated in PEP 3333 were ignored. This is why now an unofficial way
  of doing it is being adopted by WSGI servers separate to the WSGI
  specification.
