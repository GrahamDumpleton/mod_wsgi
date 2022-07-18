=============
Version 4.9.3
=============

Version 4.9.3 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.9.3

Bugs Fixed
----------

* When using ``WSGITrustedProxies`` and ``WSGITrustedProxyHeaders`` in the
  Apache configuration, or ``--trust-proxy`` and ``--trust-proxy-header``
  options with ``mod_wsgi-express``, if you trusted the ``X-Client-IP``
  header and a request was received from an untrusted client, the header
  was not being correctly removed from the set of headers passed through to
  the WSGI application.

  This only occurred with the ``X-Client-IP`` header and the same problem was
  not present if trusting the ``X-Real-IP`` or ``X-Forwarded-For`` headers.

  The purpose of this feature for trusting a front end proxy was in this
  case for the headers:

    * ``X-Client-IP``
    * ``X-Real-IP``
    * ``X-Forwarded-For``

  and was designed to allow the value of ``REMOTE_ADDR`` passed to the WSGI
  application to be rewritten to the IP address that a trusted proxy said
  was the real remote address of the client.

  In other words, if a request was received from a proxy the IP address
  of which was trusted, ``REMOTE_ADDR`` would be set to the value of the
  single designated header out of those listed above which was to be
  trusted.

  In the case where the proxy was trusted, in addition to ``REMOTE_ADDR``
  being rewritten, only the trusted header would be passed through. That is,
  if ``X-Real-IP`` was the trusted header, then ``HTTP_X_REAL_IP`` would
  be passed to the WSGI application, but ``HTTP_X_CLIENT_IP`` and
  ``HTTP_X_FORWARDED_FOR`` would be dropped if corresponding headers had
  also been supplied. That the header used to rewrite ``REMOTE_ADDR`` was
  passed through still was only intended for the purpose of documenting
  where the value of ``REMOTE_ADDR`` came from. A WSGI application when
  relying on this feature should only ever use the value of ``REMOTE_ADDR``
  and should ignore the header passed through.

  The behaviour as described was therefore based on a WSGI application
  not at the same time enabling any WSGI or web framework middleware to
  try and process any proxy headers a second time and ``REMOTE_ADDR``
  should be the single source of truth. Albeit the headers which were
  passed through should have resulted in the same result for ``REMOTE_ADDR``
  if the proxy headers were processed a second time.

  Now in the case of the client a request was received from not being a
  trusted proxy, then ``REMOTE_ADDR`` would not be rewritten, and would
  be left as the IP of the client, and none of the headers listed above
  were supposed to be passed through.

  That ``REMOTE_ADDR`` is not rewritten is implemented correctly when the
  client is not a trusted proxy, but of the three headers listed above,
  ``HTTP_X_CLIENT_ID`` was not being dropped if the corresponding header
  was supplied.

  If the WSGI application followed best practice and only relied on the
  value of ``REMOTE_ADDR`` as the source of truth for the remote client
  address, then that ``HTTP_X_CLIENT_ID`` was not being dropped should
  pose no security risk. There would however be a problem if a WSGI
  application was still enabling a WSGI or web framework specific middleware
  to process the proxy headers a second time even though not required. In this
  case, the middleware used by the WSGI application may still trust the
  ``X-Client-IP`` header and rewrite ``REMOTE_ADDR`` allowing a malicious
  client to pretend to have a different IP address.

  In addition to the WSGI application having redundant checks for the proxy
  headers, to take advantage of this, a client would also need direct access
  to the Apache/mod_wsgi server instance.

  In the case that only clients on your private network behind your proxy
  could access the Apache/mod_wsgi server instance, that would imply any
  malicious actor already had access to your private network and had access
  to hosts in that private network or could attach their own device to that
  private network.

  In the case where your Apache/mod_wsgi server instance could be accessed
  from the same external networks as a proxy forwarding requests to it, such
  as may occur if making use of a CDN proxy cache, a client would still need
  to know the direct address used by the Apache/mod_wsgi server instance.

  Note that only one proxy header for designating the IP of a client should
  ever be trusted. If you trust more than one, then which will be used if
  both are present is undefined as it is dependent on the order that Apache
  processes headers. This hasn't changed and as before to avoid ambiguity you
  should only trust one of the proxy headers recognised for this purpose.
