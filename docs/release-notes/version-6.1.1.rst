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

* Two threads of the same process could be handed the same per-thread
  record when they started, or took their first request, at the same
  moment. The records were allocated from an Apache memory pool shared
  by every thread, without a lock, and APR pools are not thread safe.
  Two threads sharing a record shared the ``mod_wsgi.thread_id`` value
  and, for a named application group, the same Python thread state.
  Concurrent requests on those threads then shared ``contextvars``
  state, so a request could see and change the request context of
  another, such as a web framework's current request and session, and
  on Python 3.14 and later the process crashed. In daemon mode every
  worker thread creates its record as the process starts, which made
  the race likely on every process start since 6.0.0; in embedded mode
  the first requests on a fresh Apache child could do the same. The
  same lack of locking affected the table of Python thread states kept
  for each sub interpreter, the creation of worker threads at daemon
  process start, the lazily allocated metrics state, and messages
  logged on error paths. Everything allocated once threads are running
  now comes from a pool used under one lock or belonging to one
  thread. Reported by hinohi as GHSA-q67r-wxfm-97hj.

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
