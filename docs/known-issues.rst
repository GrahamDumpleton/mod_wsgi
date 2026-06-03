============
Known Issues
============

This page lists known issues in mod_wsgi itself: confirmed defects and
accepted limitations in the module, as opposed to problems in your
Apache configuration or your WSGI application. If you are still working
out *where* a problem lives, start with :doc:`troubleshooting`; the
guides it links to cover installation, configuration, and application
problems, which are far more common than bugs in mod_wsgi.

An issue is listed here when the behaviour is understood, there is
nothing a user can do to make mod_wsgi behave differently beyond the
noted workaround, and a full fix is either not yet available or not
considered worthwhile. Each entry records the symptom, which mode of
operation is affected, the underlying cause, any workaround, and the
current status with a link to the tracking issue.

If you are hitting something that is not listed here and not explained
by :doc:`troubleshooting`, see :doc:`reporting-bugs`.

.. _known-issue-chunked-truncation:

Truncated chunked responses are not signalled to the client in daemon mode
--------------------------------------------------------------------------

**Symptom**

A WSGI application streams a response with no ``Content-Length`` header,
so it is sent to the client using ``Transfer-Encoding: chunked``. If the
response is then cut short partway through, the client still receives a
syntactically complete chunked response, terminated with the final
``0`` chunk, and cannot tell that the body was truncated. The response
is cut short when either:

* the application raises an unhandled exception while iterating the
  response, or
* the daemon process handling the request dies mid-response (for
  example, it is killed, crashes, or hits a resource limit).

**Affected mode**

Daemon mode only. In embedded mode this was addressed in version 4.4.0:
when a chunked response is interrupted by an application exception,
mod_wsgi suppresses the terminating ``0`` chunk so the client sees an
unterminated response and can detect the truncation. Responses that do
carry a ``Content-Length`` are not affected in either mode, because a
client can already detect a short read against the declared length.

**Cause**

In daemon mode the response is produced in the daemon process and
proxied back to the Apache child process over a socket, with the chunked
framing toward the client applied by the Apache child. The response leg
between daemon and child is an unframed byte stream whose end is
signalled only by the socket closing, so a clean completion, an
application exception, and an outright crash all look identical to the
Apache child. The child then terminates the chunked response toward the
client normally. The embedded-mode fix does not carry over because it
acts in the daemon process, on a different request, from where the
client-facing chunked framing is applied.

**Workaround**

Where it matters that a client can detect a truncated response, have the
application set a ``Content-Length`` header so the response is not sent
chunked; a client can then detect a short read against the declared
length. This is only possible when the response length is known in
advance.

**Status**

Open. A fix would require framing the daemon-to-child response leg so the
Apache child can distinguish a truncated response from a clean one and
withhold the terminating ``0`` chunk. The value of such a fix is limited
in any case: chunked transfer encoding is hop by hop, so an intermediary
proxy may dechunk and re-chunk the response and append its own
terminating chunk, which would erase the truncation signal before it
reaches the client. Tracked as
`issue #42 <https://github.com/GrahamDumpleton/mod_wsgi/issues/42>`__.
