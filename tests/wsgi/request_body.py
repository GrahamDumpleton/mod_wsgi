"""Test that request bodies proxied to a daemon process are read back
byte-for-byte via wsgi.input, with the deferred-content handshake both
enabled and disabled.

In daemon mode the Apache child re-frames the request body as chunked
transfer encoding and proxies it to the daemon, where the HTTP_IN
filter de-chunks it. When the deferred-content "200 Continue" handshake
is disabled (WSGIScriptReloading Off and the serving daemon group's
queue-timeout is 0) the child sends the environment frame and the body
back to back in a single write, so the daemon frame reader must not
over-read the environment frame into the following body. This test
drives both configurations against the same app:

  /test/wsgi/request-body
      Normal case, handshake enabled: routed to the shared daemon
      group (reloading on, queue-timeout 45).

  /test/wsgi/request-body/no-handshake
      Handshake disabled: routed to a dedicated daemon group whose
      queue-timeout is 0, with WSGIScriptReloading Off. See
      request_body.conf for the group/mount and dispatch.py for the
      routing.

The response reports the serving daemon process group, the number of
body bytes read, and the SHA-256 of the body, so the test can verify
both that routing reached the intended group and that the body arrived
intact for any size.
"""

import hashlib


def application(environ, start_response):
    stream = environ["wsgi.input"]

    digest = hashlib.sha256()
    total = 0

    # Read in bounded blocks so the body is consumed across multiple
    # de-chunk reads rather than a single call.
    while True:
        chunk = stream.read(8192)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)

    group = environ.get("mod_wsgi.process_group", "")

    payload = (
        b"group=" + group.encode()
        + b" len=" + str(total).encode()
        + b" sha256=" + digest.hexdigest().encode()
    )

    start_response(
        "200 OK",
        [
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(payload))),
        ],
    )
    return [payload]
