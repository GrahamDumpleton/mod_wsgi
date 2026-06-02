=============
Version 6.0.2
=============

Bugs Fixed
----------

* Setting ``WSGIRestrictEmbedded Off`` after it had previously been set
  to ``On`` could crash the Apache child process when an embedded mode
  request was subsequently received. ``WSGIRestrictEmbedded On`` not only
  blocks embedded mode requests but, as an optimisation, also suppresses
  initialisation of Python in the Apache child processes when nothing
  else requires it. Switching it back ``Off`` re-enabled embedded mode
  request handling but did not undo that suppression, so the request
  reached the embedded mode code path in a child where Python, and the
  per-thread state it depends on, had never been initialised, causing a
  crash. ``WSGIRestrictEmbedded Off`` now marks Python as required in the
  Apache child processes, consistent with the other directives that need
  it, so embedded mode works as expected. As an additional safeguard, an
  embedded mode request that reaches a child with no initialised Python
  interpreter is now rejected with a ``500 Internal Server Error`` and
  logged as :ref:`WSGI0210` rather than crashing the process.
