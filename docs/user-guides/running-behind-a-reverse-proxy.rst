================================
Running Behind A Reverse Proxy
================================

This page covers what to configure when mod_wsgi sits behind a
reverse proxy: a separate front-end server that accepts the
client connection, then forwards the request to the Apache and
mod_wsgi instance running underneath it. Common front-ends are
another Apache, nginx, HAProxy, a cloud load balancer (AWS ALB,
GCP HTTPS load balancer), or a Kubernetes ingress controller.

The same configuration applies whether mod_wsgi is configured
manually inside a system Apache or run via
``mod_wsgi-express``; only the spelling of the trust knobs
differs. Both forms are shown side by side throughout this
page.

HTTPS termination at the front-end proxy is the typical reason
for this deployment shape, but the proxy and trust mechanics
covered here apply equally to plain-HTTP proxying. For
configuring TLS at the mod_wsgi instance itself (the other
deployment shape), see :doc:`enabling-https`.

What goes wrong without proxy configuration
-------------------------------------------

When a request reaches mod_wsgi by way of a reverse proxy, the
TCP connection mod_wsgi sees is the connection from the proxy,
not from the client. By default mod_wsgi populates the WSGI
environment from that connection, so the application sees the
proxy's view of the world rather than the client's:

* ``REMOTE_ADDR`` is the proxy's IP address, not the client's.
* ``HTTP_HOST`` is the host name the proxy used when connecting
  to the back-end (often an internal hostname or
  ``localhost``), not the host the client originally typed.
* ``wsgi.url_scheme`` is ``http`` even when the original client
  request was ``https`` and TLS was terminated at the proxy.
* ``SERVER_PORT`` is the back-end port, not the public port.

The visible consequences for a typical application:

* Generated URLs (``url_for(...)``, ``request.build_absolute_uri()``,
  framework redirects) embed the back-end's internal hostname
  and port.
* Apache-emitted directory redirects (the 301 issued when a URL
  refers to a directory without a trailing slash) put the
  back-end's hostname in the ``Location`` response header, so
  the client follows it to the wrong URL.
* Access controls or audit logs that key off ``REMOTE_ADDR`` see
  every request as coming from the proxy.
* Frameworks that conditionally enforce HTTPS based on
  ``wsgi.url_scheme`` will see all requests as plain HTTP.

The fix has two halves: have the proxy attach headers carrying
the original client information, and have mod_wsgi trust those
headers and rewrite the WSGI environment accordingly.

The forwarded-headers convention
--------------------------------

The proxy adds HTTP headers carrying the original client
information that the back-end would otherwise be unable to see.
The de-facto headers and what they convey:

* ``X-Forwarded-For`` carries the original client IP address.
* ``X-Forwarded-Proto`` carries the original protocol scheme
  (``http`` or ``https``).
* ``X-Forwarded-Host`` carries the host name from the original
  client request.
* ``X-Forwarded-Port`` carries the public port the client
  connected to.

There is no single standard for these headers. Multiple
conventions exist for the same purpose: the protocol scheme has
been carried in ``X-Forwarded-Proto``, ``X-Forwarded-Scheme``,
``X-Forwarded-SSL``, ``X-Forwarded-HTTPS``, ``X-HTTPS``, and
``X-Scheme`` by different proxies; the client IP has been
carried in ``X-Forwarded-For``, ``X-Real-IP``, and
``X-Client-IP``. mod_wsgi knows about all of the equivalents
within each group; you tell it which header your proxy actually
sends, and mod_wsgi rewrites the WSGI environment from that one.

For the full enumeration of equivalent headers in each group
and which WSGI environment variable each group rewrites, see
:doc:`../configuration-directives/WSGITrustedProxyHeaders`.

Why proxy IPs must be designated as trusted
-------------------------------------------

The forwarded headers are just regular HTTP headers, so any
client can send them. If mod_wsgi blindly trusted
``X-Forwarded-For``, an external client could send::

    X-Forwarded-For: 127.0.0.1

and the application would see ``REMOTE_ADDR == '127.0.0.1'``,
which is an authentication bypass for any application that
gates behaviour on the source IP.

mod_wsgi avoids this by requiring the operator to declare which
IP addresses the forwarded headers are allowed to come from.
Headers received from any other source are stripped before the
WSGI environment is built. The default is to trust no proxies,
so until the trust list is configured the forwarded headers are
ignored regardless of their values.

For a similar reason, only one header per equivalence group
should be trusted. If you trust both ``X-Forwarded-For`` and
``X-Real-IP``, a request that arrives from the trusted proxy
with both set has an indeterminate result.

Telling mod_wsgi to trust the proxy
-----------------------------------

For a manually-configured Apache, two directives do the work:

* :doc:`../configuration-directives/WSGITrustedProxies` lists
  the IP addresses or CIDR ranges that mod_wsgi will accept the
  forwarded headers from.
* :doc:`../configuration-directives/WSGITrustedProxyHeaders`
  lists which forwarded headers (one per equivalence group) to
  honour.

A typical configuration for a single trusted front-end at
``192.0.2.10``::

    WSGITrustedProxies 192.0.2.10
    WSGITrustedProxyHeaders X-Forwarded-For X-Forwarded-Proto \
        X-Forwarded-Host X-Forwarded-Port

CIDR ranges are accepted, so a whole proxy subnet can be
trusted in one line::

    WSGITrustedProxies 10.0.0.0/24

For ``mod_wsgi-express``, the equivalent options on the
``start-server`` (or ``setup-server``) command line are
``--trust-proxy`` and ``--trust-proxy-header``::

    mod_wsgi-express start-server wsgi.py \
        --trust-proxy 192.0.2.10 \
        --trust-proxy-header X-Forwarded-For \
        --trust-proxy-header X-Forwarded-Proto \
        --trust-proxy-header X-Forwarded-Host \
        --trust-proxy-header X-Forwarded-Port

Each option can be supplied multiple times to list multiple
proxies or multiple headers; ``mod_wsgi-express`` translates
the options into the directive pair shown above when it
generates the Apache configuration.

Trust only the proxies you actually operate. Do not list a
public CIDR range; do not list ``0.0.0.0/0``. If you do not
control the IP that requests reach mod_wsgi from, the
forwarded headers cannot be authenticated and the trust
mechanism does not protect anything.

Configuring the front-end proxy
-------------------------------

The other half of the configuration belongs on the proxy: it
must add the forwarded headers, and (depending on the front-end)
it may need to be told to rewrite ``Location`` headers in
back-end responses so back-end-emitted redirects appear to come
from the public URL.

Apache as the front-end proxy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Front-end Apache uses ``mod_proxy``. ``ProxyPass`` adds the
``X-Forwarded-For``, ``X-Forwarded-Host``, and
``X-Forwarded-Server`` headers automatically. The
``X-Forwarded-Proto`` and ``X-Forwarded-Port`` headers must be
added explicitly with ``RequestHeader``::

    <VirtualHost *:80>
        ServerName www.example.com
        ProxyPass        / http://backend.internal:8000/
        ProxyPassReverse / http://backend.internal:8000/
        RequestHeader set X-Forwarded-Port 80
    </VirtualHost>

``ProxyPassReverse`` rewrites the ``Location``,
``Content-Location``, and ``URI`` response headers so that any
``Location`` value the back-end emitted using its internal
hostname is rewritten to the public hostname before reaching
the client. This is what makes Apache-emitted directory
redirects work correctly under proxying; see "Redirect and
Location-header issues" below.

If the back-end should construct URLs (including
``Location`` headers) using the original client's view of the
``Host``, add ``ProxyPreserveHost On``::

    ProxyPreserveHost On

With this set, the back-end Apache receives the original
``Host`` header as supplied by the client, so its
``HTTP_HOST`` and ``SERVER_NAME`` already reflect the public
hostname even before ``WSGITrustedProxies`` is consulted.
Pairing ``ProxyPreserveHost On`` with the trust directives is
the most reliable configuration: ``ProxyPreserveHost`` covers
URLs Apache itself constructs (for example for directory
redirects), and the trust directives cover URLs the WSGI
application constructs.

nginx as the front-end proxy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

nginx does not add forwarded headers automatically; every
header to be forwarded must be set explicitly with
``proxy_set_header``. A typical configuration::

    server {
        listen 80;
        server_name www.example.com;

        location / {
            proxy_pass         http://backend.internal:8000;
            proxy_set_header   Host              $host;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Host  $host;
            proxy_set_header   X-Forwarded-Port  $server_port;
            proxy_set_header   X-Forwarded-Proto $scheme;
        }
    }

``$proxy_add_x_forwarded_for`` is the nginx variable that
appends the current client IP to any incoming
``X-Forwarded-For`` value, producing the comma-separated
chain expected when there are multiple proxies in front of the
back-end.

Setting ``Host $host`` on the proxied request is the nginx
equivalent of Apache's ``ProxyPreserveHost On``: the back-end
sees the original ``Host`` header rather than
``backend.internal:8000``.

The equivalent of Apache's ``ProxyPassReverse`` is
``proxy_redirect``. By default nginx rewrites ``Location``
response headers from ``proxy_pass`` URLs to the requested URL,
which is the desired behaviour for most setups; the directive
needs only to be touched if the back-end emits redirects that
go outside the proxied URL space.

Cloud load balancers and Kubernetes ingress
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Managed cloud load balancers (AWS ALB, GCP HTTPS load balancer,
Azure Application Gateway) and Kubernetes ingress controllers
(nginx-ingress, Traefik, Kong) typically add the
``X-Forwarded-For``, ``X-Forwarded-Proto``, and
``X-Forwarded-Host`` headers automatically and configurably.
The ingress provider's documentation is the authoritative
source for which headers it sends.

What you provide on the mod_wsgi side is the ``WSGITrustedProxies``
list. This is the IP range that requests enter the back-end
from after the load balancer or ingress, which depending on the
platform may be:

* The load-balancer's own internal IP range (AWS ALB, when the
  back-end is reachable over the same VPC).
* The ingress controller's pod CIDR (Kubernetes).
* The host's loopback interface (when the LB and back-end run
  on the same host).

If the back-end is reachable only through the proxy by virtue
of network policy (private subnet, ingress-only Service), the
trust list can sometimes be a broad range without weakening
security; if the back-end is also reachable directly, the trust
list must be tight.

End-to-end example
------------------

A complete example pairing an Apache front-end on port 80 with
a back-end ``mod_wsgi-express`` instance on port 8000.

Front-end Apache (``/etc/apache2/sites-enabled/example.conf``)::

    <VirtualHost *:80>
        ServerName www.example.com
        ProxyPass        / http://127.0.0.1:8000/
        ProxyPassReverse / http://127.0.0.1:8000/
        ProxyPreserveHost On
        RequestHeader set X-Forwarded-Port 80
    </VirtualHost>

Back-end ``mod_wsgi-express``::

    mod_wsgi-express start-server wsgi.py \
        --host 127.0.0.1 --port 8000 \
        --trust-proxy 127.0.0.1 \
        --trust-proxy-header X-Forwarded-For \
        --trust-proxy-header X-Forwarded-Proto \
        --trust-proxy-header X-Forwarded-Host \
        --trust-proxy-header X-Forwarded-Port

Equivalent back-end configuration in a manually-managed
Apache::

    Listen 127.0.0.1:8000

    <VirtualHost 127.0.0.1:8000>
        WSGIDaemonProcess example processes=2 threads=15
        WSGIProcessGroup example
        WSGIApplicationGroup %{GLOBAL}
        WSGIScriptAlias / /var/www/example/wsgi.py

        WSGITrustedProxies 127.0.0.1
        WSGITrustedProxyHeaders X-Forwarded-For X-Forwarded-Proto \
            X-Forwarded-Host X-Forwarded-Port

        <Directory /var/www/example>
            Require all granted
        </Directory>
    </VirtualHost>

In all three forms above, a request to
``http://www.example.com/somepath`` arrives at the WSGI
application with ``REMOTE_ADDR`` set to the original client's
IP, ``HTTP_HOST`` set to ``www.example.com``,
``wsgi.url_scheme`` set to ``http``, and ``SERVER_PORT`` set
to ``80``. URLs the application constructs through standard
WSGI URL-reconstruction reflect the public address.

Redirect and Location-header issues
-----------------------------------

Apache emits a 301 redirect with a ``Location`` header when a
request URL refers to a directory but does not include the
trailing slash. The redirect's purpose is to point the client at
the canonical URL with the slash appended. Without proxy
configuration, the back-end Apache builds the ``Location``
header using *its own* hostname and port: a request for
``http://www.example.com/static`` proxied to
``http://backend.internal:8000/static`` produces a ``Location``
header pointing at ``http://backend.internal:8000/static/``,
which is at best ugly and at worst unreachable from the client.

There are two complementary fixes:

* **Front-end rewriting** of the ``Location`` header.
  Apache's ``ProxyPassReverse`` and nginx's default
  ``proxy_redirect`` behaviour both rewrite the ``Location``
  header on the way back through the proxy: any URL matching
  the back-end's proxied prefix is rewritten to the
  front-end's prefix. This works for any ``Location`` header
  that the back-end emits, whether from Apache or from the
  WSGI application.
* **Back-end construction** of the right ``Location`` in the
  first place. Apache's ``ProxyPreserveHost On`` (or nginx's
  ``proxy_set_header Host $host;``) makes the back-end see
  the original ``Host`` header, so the back-end Apache
  constructs its directory redirects with the public
  hostname and the rewriting on the way out is redundant.

Both can be in place at once and they do not conflict. The
front-end rewriting also covers the case where the WSGI
application explicitly emits a ``Location`` referring to the
back-end (rare but possible if the application is doing its own
URL construction without consulting the WSGI environment
variables).

HTML body URL leakage
---------------------

A separate failure mode: even with the headers and ``Location``
rewriting in place, the HTML body of error responses can still
embed the back-end's internal URL. Apache's stock error
documents include the request URL in the HTML body of 301
responses, so a directory redirect served as
``http://backend.internal:8000/static/`` shows that internal
URL in the response body even though the ``Location`` header is
correct.

Two ways to address this:

* **Apache mod_proxy_html** on the front-end, which rewrites
  URLs inside HTML response bodies::

      ProxyHTMLEnable On
      ProxyHTMLURLMap http://backend.internal:8000 http://www.example.com

  This rewrites every URL in the response, not just
  ``Location``-style headers. The cost is that every HTML
  response body is parsed and rewritten on the way back through
  the proxy.

* **Custom error documents** that do not include the back-end
  URL. For ``mod_wsgi-express``, the ``--error-document``
  option supplies a static file in place of Apache's default
  for a given status code::

      mod_wsgi-express start-server wsgi.py \
          ... \
          --error-document 301 /errors/301.html

  For a manually-configured Apache, the equivalent is the
  standard ``ErrorDocument`` directive::

      ErrorDocument 301 /errors/301.html

  This is cheaper than ``mod_proxy_html`` but only addresses
  the specific status codes for which substitute documents are
  supplied.

If the back-end is configured with ``ProxyPreserveHost`` or its
nginx equivalent, the body-leakage problem largely disappears
because the back-end builds the body using the public hostname
in the first place. ``mod_proxy_html`` and custom error
documents are mostly relevant when the back-end cannot be
configured to see the original ``Host``.

mod_wsgi-express specifics
--------------------------

A few ``mod_wsgi-express`` options interact with the
reverse-proxy story:

* ``--server-name HOSTNAME`` sets the public host name that
  ``mod_wsgi-express`` uses when generating its Apache
  ``ServerName`` directive. Without it the server name is the
  host the express instance binds to (often ``localhost`` or
  the container hostname). Set this to the public hostname when
  ``mod_wsgi-express`` is the back-end of a proxy::

      mod_wsgi-express start-server wsgi.py \
          --server-name www.example.com \
          ...

  This affects URLs Apache itself constructs in the absence of
  ``X-Forwarded-Host`` (for example when ``ProxyPreserveHost``
  is not in effect on the front-end).

* ``--allow-localhost`` allows requests to ``localhost`` to
  bypass the ``ServerName`` virtual-host gate when a public
  ``ServerName`` has been set. This is useful when a health
  check or sidecar in the same host or pod connects to the
  back-end on ``localhost`` directly while regular traffic
  comes through the proxy.

* ``--trust-proxy`` and ``--trust-proxy-header`` are the
  options described in "Telling mod_wsgi to trust the proxy"
  above.

Static files served from the back-end
-------------------------------------

``mod_wsgi-express`` can host static files alongside the WSGI
application using ``--document-root`` and ``--url-alias``. Any
static-file request is then served by Apache directly, without
calling the WSGI application. The redirect and Location issues
described above apply equally to those static-file responses
(the same Apache-emitted directory redirect is the typical
trigger), so the same front-end ``ProxyPassReverse`` /
``proxy_redirect`` and ``ProxyPreserveHost`` configuration is
needed.

For new deployments where the front-end proxy is itself an
Apache or nginx, serving static files directly from the
front-end (without proxying to the back-end at all) avoids the
issue entirely and is faster. The back-end ``mod_wsgi-express``
instance only handles requests that the front-end could not
satisfy from disk.

mod_wsgi-express as a front-end proxy
-------------------------------------

The rest of this page covers ``mod_wsgi-express`` as the
*back-end* of a proxy, with the front-end terminating TLS
and adding forwarded headers. ``mod_wsgi-express`` can also
play the *front-end* role: serve a WSGI application on its
primary hostname while proxying selected sub-URLs or other
hostnames out to upstream backends. Two options drive this:

``--proxy-mount-point URL-PATH URL``
    Mounts an upstream URL at a sub-URL of the express
    server. Requests under the prefix are forwarded to the
    upstream; everything else is still handled by the WSGI
    application or static files. Repeatable.

``--proxy-virtual-host HOSTNAME URL``
    Proxies every request for the named hostname out to the
    upstream URL. The express instance's primary hostname
    continues to serve the WSGI application; the listed
    hostnames are proxied wholesale. Repeatable.

A small example combining the two::

    mod_wsgi-express start-server wsgi.py \
        --server-name www.example.com \
        --proxy-mount-point /api/ http://api-backend.internal:9000/ \
        --proxy-virtual-host static.example.com http://cdn.internal/

In the generated Apache configuration,
``--proxy-mount-point`` emits ``ProxyPass`` and
``ProxyPassReverse`` directives wrapped in a ``<Location>``
block, and ``--proxy-virtual-host`` emits a sibling
``<VirtualHost *:port>`` block (where ``port`` is the port
express is listening on) with ``ProxyPass /`` and
``ProxyPassReverse /`` proxying the entire hostname.

Both forms additionally inject ``X-Forwarded-Port`` and
``X-Forwarded-Scheme`` headers on the outbound request, so
the upstream sees the public-facing port and scheme without
``RequestHeader`` lines added by hand. Apache's
``ProxyPass`` and ``ProxyPassReverse`` also add
``X-Forwarded-For``, ``X-Forwarded-Host`` and
``X-Forwarded-Server`` automatically; combined, the upstream
receives the full forwarded-header set that the rest of this
page describes mod_wsgi consuming.

Trust on the upstream side remains the upstream's
responsibility. If the upstream is itself a mod_wsgi
instance, it needs ``WSGITrustedProxies`` listing the IP
that requests reach it from (the express front-end's IP),
in exactly the way described in `Telling mod_wsgi to trust
the proxy`_ above.

When ``--proxy-mount-point`` is given a URL-PATH without a
trailing slash (``/api`` rather than ``/api/``),
``mod_wsgi-express`` also adds a 302 redirect from the bare
prefix to the slash form. Specifying the trailing-slash form
directly avoids that hop.

Both ``--proxy-mount-point`` and ``--proxy-virtual-host``
generate ``ProxyPass`` directives with the
``upgrade=websocket`` parameter set, so clients that initiate
the WebSocket handshake (``Upgrade: websocket``,
``Connection: Upgrade``) are tunnelled through to the upstream
without further configuration. ``mod_proxy_wstunnel`` is not
required; ``mod_proxy_http`` handles the upgrade in place.
This requires Apache 2.4.47 or newer.

Idle WebSocket connections (no traffic for longer than
``--socket-timeout``, default 60 seconds) are otherwise
dropped by Apache. The ``--proxy-timeout SECONDS`` option
overrides ``ProxyTimeout`` for proxied connections only,
leaving the regular request-handling timeout untouched, and is
the knob to raise when WebSocket clients do not heartbeat
often enough::

    mod_wsgi-express start-server wsgi.py \
        --proxy-mount-point /ws/ http://api.internal:9000/ \
        --proxy-timeout 300

The upstream URL accepted by ``--proxy-mount-point`` and
``--proxy-virtual-host`` may be either a regular HTTP URL or
Apache's unix-socket form
``unix:/path/to/socket|http://host/``. ``mod_wsgi-express``
does not parse the URL: it is passed through to ``mod_proxy``
as written, and ``mod_proxy`` understands the unix-socket form
natively::

    mod_wsgi-express start-server wsgi.py \
        --proxy-mount-point /api/ \
            'unix:/var/run/api.sock|http://localhost/'

The host name after ``|`` is a syntactic placeholder required
by Apache, not used for routing; the actual connection goes to
the unix-domain socket path. Quote the whole URL, since ``|``
is special in most shells.

When ``--proxy-mount-point`` is in use, Apache strips the
prefix before forwarding the request to the upstream: a
request for ``/api/users`` mounted at ``/api/`` reaches the
backend as ``/users``. The backend cannot infer its public
mount point from the path it sees, and must be told the prefix
explicitly anywhere it constructs URLs the client is expected
to follow (``Location`` headers, HTML links, JSON-embedded
URLs, OpenAPI specs, WebSocket addresses).

To make the prefix discoverable, ``mod_wsgi-express``
automatically emits ``X-Forwarded-Prefix`` on every request
forwarded by ``--proxy-mount-point``. The header value is the
mount point with any trailing slash removed, so both
``/api`` and ``/api/`` send ``X-Forwarded-Prefix: /api``. This
is the de-facto convention used by Traefik, Spring, and
Werkzeug-derived stacks. ``--proxy-virtual-host`` does not set
the header, since hostname-based proxying does not strip a
path prefix and the backend already sees the same URL space
as the client.

Whether the upstream uses the header is up to the framework
on the upstream side. Werkzeug's ``ProxyFix`` (used by Flask)
honours ``X-Forwarded-Prefix`` directly. ASGI servers and
frameworks (uvicorn, Hypercorn, FastAPI, Starlette) instead
take the prefix as a ``root_path`` setting passed at startup
(``uvicorn --root-path /api``,
``Starlette(..., root_path="/api")``). WSGI servers and
frameworks read ``SCRIPT_NAME`` from the environment, set
either by the server (``gunicorn --mount-point /api``) or by
the framework (Django's ``FORCE_SCRIPT_NAME``, Werkzeug
``ProxyFix``). Frameworks that do not consume
``X-Forwarded-Prefix`` simply ignore it; the header is
harmless when unused.

Where to go next
----------------

* :doc:`../configuration-directives/WSGITrustedProxies` and
  :doc:`../configuration-directives/WSGITrustedProxyHeaders`
  for the directive-level reference, including the full
  enumeration of equivalent headers in each group.
* :doc:`enabling-https` for the other deployment shape,
  where TLS is terminated at the mod_wsgi instance itself
  rather than at a separate proxy.
* :doc:`mod-wsgi-express-quickstart` for ``mod_wsgi-express``
  options in general.
* :doc:`installing-with-docker` for the related case of
  ``mod_wsgi-express`` running inside a container behind an
  ingress.
* :doc:`../how-mod-wsgi-works` for where the reverse-proxy
  pattern fits among the other deployment shapes.
* :doc:`configuration-guidelines` for richer configuration
  examples covering other aspects of mod_wsgi deployment.
