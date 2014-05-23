===========
Version 1.1
===========

Version 1.1 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-1.1.tar.gz

Bug Fixes
---------

1. Fix bug which could result in processes crashing when multiple threads
attempt to write to sys.stderr or sys.stdout at the same time. See:

  http://code.google.com/p/modwsgi/issues/detail?id=30

Chance of this occuring was small, as was contingent on code writing out
strings which contained an embedded newline but no terminating new line,
thereby triggering the internal line caching code.

2. In error case when not able to release interpreter, was wrongly trying
to release Python GIL around code to unlock module mutex when didn't
actually have the GIL acquired in the first place. Didn't strictly need to
be releasing GIL when releasing lock as it shouldn't block anyway, so don't
do this even in case where had the Python GIL.

This problem would only have been encountered in situation where Python had
failed in a major way to begin with.

3. Incorrectly trying to output Python exception details when Python GIL
would not have been held.

This problem would only have been encountered in situation where Python had
failed in a major way to begin with.

4. Fix location of Python object reference count decrements to avoid
decrement reference count on null pointer.

Would only have caused a problem if Python was in some sort of corrupted
state to begin with as the object which the reference count was being
performed on should always exist.

5. Replace normal Apache connection setup in daemon processes with
equivalent code that avoids possibility that other Apache modules will
insert their own connection level input/output filters. This is needed as
running WSGI applications in daemon processes where requests were arriving
to Apache as HTTPS requests could cause daemon processes to crash. See:

  http://code.google.com/p/modwsgi/issues/detail?id=33

This was only occuring for some HTTPS configurations, but not known what
exactly was different about those configurations to cause the problem.
Actually possible that the real problem was mod_logio as described below.

6. Substitute optional ap_logio_add_bytes_out() function provided by the
mod_logio module when loaded and when handling request in daemon process.
This is needed to prevent core output filters calling this function and
triggering a crash due to configuration for mod_logio not being setup. See:

  http://code.google.com/p/modwsgi/issues/detail?id=34
