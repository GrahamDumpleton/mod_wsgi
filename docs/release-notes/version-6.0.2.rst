=============
Version 6.0.2
=============

Features Changed
----------------

* The way mod_wsgi proxies a response body back from a daemon process to
  the HTTP client has been reworked so that it no longer interferes with
  downstream output filters that pace or batch data, most notably
  ``mod_ratelimit``. Previously mod_wsgi forced a flush both every time the
  daemon socket momentarily ran dry and after each ``response-buffer-size``
  worth of data had been passed on. Both kinds of flush forced the
  ``mod_ratelimit`` ``RATE_LIMIT`` filter to emit a short write and so
  throttled daemon mode responses far below the configured rate. As
  mod_wsgi requires Apache 2.4, whose core output filter already bounds how
  much response data is buffered in the Apache child processes, these
  forced flushes are no longer needed to limit memory use and have been
  removed. mod_wsgi now passes response data straight on, so a pacing
  filter receives full-size writes and works correctly, while a genuinely
  idle application still has its partial output flushed promptly so
  streaming responses remain responsive.

  The visible effect of the previous behaviour varied with the version of
  Apache in use. With some versions of mod_ratelimit the forced flushes
  effectively let the response through at close to full speed, so a
  configured rate limit had little effect; with others they caused the
  rate limit to be applied far too aggressively, throttling the response
  well below the configured rate. In neither case could the rate limit be
  honoured accurately for a daemon mode response, which it now is.

  Two options on the :doc:`../configuration-directives/WSGIDaemonProcess`
  directive control this behaviour:

  - The new ``response-flush-delay`` option (default 5 milliseconds) sets
    how long mod_wsgi waits for more response data before flushing when the
    daemon socket runs dry, so a transient stall during an active transfer
    does not trigger a flush while a genuinely paused application still has
    its output flushed within that delay. Setting it to 0 flushes on any
    stall and is not recommended when a pacing filter such as
    ``mod_ratelimit`` is in use, as it can throttle responses far below the
    configured rate.

  - The ``response-buffer-size`` option has changed meaning. It is now a
    coarse runaway guard that forces a flush only once this many bytes have
    been passed downstream without one, in order to bound a downstream
    filter that buffers without draining. Its default has been raised from
    65536 bytes to 8388608 bytes (8 MB) accordingly; normal bounding of
    response memory use is handled by the Apache core output filter.

Bugs Fixed
----------

* Building the Windows ``mod_wsgi`` extension failed at the link stage with
  a ``LNK2005`` multiply defined symbol error for ``PyInit_mod_wsgi``, and a
  fatal ``LNK1169``. When the single ``mod_wsgi.c`` source file was split
  into the separate ``wsgi_*.c`` files in version 6.0.0, the real
  ``PyInit_mod_wsgi`` module init function moved into ``wsgi_module.c`` as
  an unconditional definition, but an older Windows-only stub of the same
  function was left behind in ``mod_wsgi.c``. On non-Windows builds the stub
  was excluded by ``#if defined(_WIN32)`` so only one definition was
  compiled, but on Windows both were compiled and the linker rejected the
  duplicate. The obsolete stub has been removed so ``wsgi_module.c`` is the
  sole provider of ``PyInit_mod_wsgi`` on all platforms.

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
