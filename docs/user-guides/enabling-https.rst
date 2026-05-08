================
Enabling HTTPS
================

This page covers terminating TLS at the mod_wsgi instance
itself: the Apache and mod_wsgi process accepts HTTPS
connections directly from the client and serves the WSGI
application over them. The same configuration material applies
whether mod_wsgi is configured manually inside a system Apache
or run via ``mod_wsgi-express``; only the spelling of the SSL
knobs differs. Both forms are shown side by side.

The other deployment pattern, where TLS is terminated at a
separate front-end reverse proxy and mod_wsgi sees plain HTTP,
is covered in :doc:`running-behind-a-reverse-proxy`. In
production deployments TLS is more often handled at the proxy
or load-balancer layer (managed certificate rotation, central
TLS policy, offload of crypto work) than inside mod_wsgi-instance
Apache. Use this page when the mod_wsgi instance is itself the
TLS endpoint.

Apache mod_ssl prerequisites
----------------------------

Whether you are configuring a system Apache or running
``mod_wsgi-express``, the underlying TLS implementation is
Apache's ``mod_ssl``. It must be installed and loadable.

* Debian/Ubuntu: ``mod_ssl`` is part of the ``apache2`` package
  but is not enabled by default. Run ``a2enmod ssl`` to enable
  it. Distributions also ship a ``ssl-cert`` package containing
  a default self-signed certificate at
  ``/etc/ssl/certs/ssl-cert-snakeoil.pem``; do not use that
  certificate for anything beyond verifying the install works.
* RHEL/Fedora/AlmaLinux/Rocky: install the ``mod_ssl`` package
  (``dnf install mod_ssl``). The default configuration in
  ``/etc/httpd/conf.d/ssl.conf`` listens on port 443 and uses
  ``/etc/pki/tls/certs/localhost.crt``, again a self-signed
  default that should not be used for real traffic.
* macOS (Homebrew Apache): ``mod_ssl`` is included in the
  ``httpd`` formula. Enable it by uncommenting the
  ``LoadModule ssl_module`` line in
  ``$(brew --prefix)/etc/httpd/httpd.conf``.

For ``mod_wsgi-express``, ``mod_ssl`` only needs to be present
on disk; the generated Apache configuration does its own
``LoadModule`` and listener setup. Distribution packages of
Apache that ship ``mod_ssl`` as a separate package satisfy this.

HTTPS with mod_wsgi-express
---------------------------

``mod_wsgi-express`` exposes a small set of options that map
directly onto the underlying ``SSLEngine`` /
``SSLCertificateFile`` / ``SSLCertificateKeyFile`` Apache
directives.

The two options always required to enable HTTPS:

``--https-port NUMBER``
    The port to listen on for HTTPS. There is no default; if
    this is not set, the express instance only accepts plain
    HTTP. Conventionally this is ``443`` for production and
    ``8443`` for local development.

``--ssl-certificate-file FILE-PATH``
    Path to the PEM-encoded server certificate.

``--ssl-certificate-key-file FILE-PATH``
    Path to the PEM-encoded private key.

The ``--ssl-certificate`` option is a shorthand for the pair
above: it takes a path prefix and infers ``.crt`` and ``.key``
extensions, so ``--ssl-certificate /etc/pki/example`` is
equivalent to
``--ssl-certificate-file /etc/pki/example.crt --ssl-certificate-key-file /etc/pki/example.key``.

Optional supporting options:

``--ssl-certificate-chain-file FILE-PATH``
    Path to a PEM-encoded chain file containing the
    intermediate CA certificates between the server cert and a
    publicly-trusted root. Required for any cert issued by a
    real CA, including Let's Encrypt.

``--ssl-environment``
    Enable the standard ``mod_ssl`` request environment
    variables (``HTTPS``, ``SSL_PROTOCOL``, ``SSL_CIPHER``,
    ``SSL_CLIENT_*``, etc.) so the WSGI application receives
    them in ``environ``. Off by default.

A typical local-development invocation, listening on plain HTTP
at 8080 and HTTPS at 8443::

    mod_wsgi-express start-server wsgi.py \
        --port 8080 --https-port 8443 \
        --ssl-certificate-file ./server.crt \
        --ssl-certificate-key-file ./server.key

The ports 8080 and 8443 mirror the conventional 80 and 443 in
production: keeping the same 80/443 relationship between the
plain and TLS ports makes it less ambiguous which port is
which when reading logs or debugging redirects.

For a production-style setup where the express instance binds
the privileged ports, see
:doc:`mod-wsgi-express-quickstart` for the ``--user`` /
``--group`` pattern that pairs with starting as root.

Manual Apache HTTPS configuration
---------------------------------

For a manually-configured Apache the TLS material lives in a
``<VirtualHost *:443>`` block alongside the regular mod_wsgi
directives. When the same site is served over both plain HTTP
and HTTPS (for example during a migration to HTTPS, or for an
internal site where strict HTTPS-only enforcement is not
required), the canonical form pairs a ``<VirtualHost *:80>``
and a ``<VirtualHost *:443>`` block::

    Listen 80
    Listen 443

    <VirtualHost *:80>
        ServerName www.example.com

        WSGIDaemonProcess example processes=2 threads=15
        WSGIProcessGroup example
        WSGIApplicationGroup %{GLOBAL}
        WSGIScriptAlias / /var/www/example/wsgi.py

        <Directory /var/www/example>
            Require all granted
        </Directory>
    </VirtualHost>

    <VirtualHost *:443>
        ServerName www.example.com

        SSLEngine on
        SSLCertificateFile      /etc/pki/example/example.crt
        SSLCertificateKeyFile   /etc/pki/example/example.key
        SSLCertificateChainFile /etc/pki/example/chain.crt

        WSGIProcessGroup example
        WSGIApplicationGroup %{GLOBAL}
        WSGIScriptAlias / /var/www/example/wsgi.py

        <Directory /var/www/example>
            Require all granted
        </Directory>
    </VirtualHost>

The ``WSGIDaemonProcess`` directive appears in only one of the
two virtual hosts (the ``*:80`` block above); the ``*:443``
block references the same daemon-process pool through
``WSGIProcessGroup``. This works because both blocks share the
same ``ServerName``: ``WSGIProcessGroup`` resolves a
process-group name to a ``WSGIDaemonProcess`` declared in any
virtual host with a matching ``ServerName``. The result is one
shared pool of daemon processes serving requests for both
ports, with a single in-memory copy of the application.

If ``WSGIDaemonProcess`` were declared in both virtual hosts,
the result would be two unrelated process pools and two copies
of the loaded application, with HTTP and HTTPS requests routed
into different pools. Define ``WSGIDaemonProcess`` in exactly
one of the paired blocks; conventionally, in whichever appears
first in the configuration file.

For an HTTPS-only site with no plain-HTTP listener, the
``*:443`` block stands alone and carries the
``WSGIDaemonProcess`` directive itself.

When the plain-HTTP listener is purely a redirect to the HTTPS
site (the recommended pattern for most production deployments,
covered in "Forcing HTTP traffic to HTTPS" below), the
``*:80`` block has no WSGI directives at all and the
``*:443`` block carries ``WSGIDaemonProcess``.

Generating a self-signed certificate for local testing
------------------------------------------------------

For local development the simplest approach is to generate a
self-signed certificate with ``openssl``. A working one-line
invocation, valid for 365 days and including a ``subjectAltName``
covering ``localhost`` and the loopback address::

    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout server.key -out server.crt \
        -subj '/CN=localhost' \
        -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'

The output is two files in the current directory,
``server.crt`` (the certificate) and ``server.key`` (the
private key), ready to be passed to ``mod_wsgi-express`` as
``--ssl-certificate-file ./server.crt
--ssl-certificate-key-file ./server.key``.

The ``subjectAltName`` extension is required: modern browsers
no longer honour the certificate's ``Common Name`` field for
hostname verification and will reject a cert that has no SAN,
even when the URL host matches the CN. Add every hostname or
IP address you want the cert to cover to the SAN list.

The certificate is self-signed, so browsers and any HTTP
client doing certificate verification will refuse to trust it.
You will see "your connection is not private" / "self-signed
certificate" warnings until you click through them.

mkcert as an alternative
~~~~~~~~~~~~~~~~~~~~~~~~

A friendlier option for local development is
`mkcert <https://github.com/FiloSottile/mkcert>`_, a small
command-line tool that creates a local certificate authority,
installs that CA into the system trust store, and then issues
certificates that are signed by it. Browsers and tools that
read the system trust store treat those certs as fully valid
without any warnings.

Install with the system package manager (``brew install mkcert``,
``apt install mkcert``, ``dnf install mkcert``), then::

    mkcert -install
    mkcert localhost 127.0.0.1 ::1

This produces ``localhost+2.pem`` (the certificate) and
``localhost+2-key.pem`` (the private key) which can be passed
to ``mod_wsgi-express`` in place of the self-signed pair from
the ``openssl`` recipe above. The ``mkcert -install`` step
only needs to be run once per machine; subsequent ``mkcert``
invocations reuse the same local CA.

mkcert is for local development only. The local CA exists only
on machines where ``mkcert -install`` has been run, so a cert
issued by it will not be trusted by anyone else.

Forcing HTTP traffic to HTTPS
-----------------------------

Once the HTTPS endpoint is up, plain-HTTP requests should be
redirected to it. Both ``mod_wsgi-express`` and manually-managed
Apache support this.

For ``mod_wsgi-express`` the ``--https-only`` flag enables the
redirect from the HTTP listener to the HTTPS listener
automatically::

    mod_wsgi-express start-server wsgi.py \
        --port 8080 --https-port 8443 \
        --ssl-certificate-file ./server.crt \
        --ssl-certificate-key-file ./server.key \
        --https-only

With this flag set, requests arriving on the HTTP port receive
a permanent redirect to the same path on the HTTPS port. The
WSGI application is not invoked for the redirected request.

For a manually-configured Apache the equivalent is a separate
HTTP virtual host that redirects everything to the HTTPS site::

    <VirtualHost *:80>
        ServerName www.example.com
        Redirect permanent / https://www.example.com/
    </VirtualHost>

A redirect-only HTTP virtual host is preferred over a
``RewriteRule`` inside a multi-purpose virtual host: the
configuration is clearer, log output for redirected requests
is easier to filter, and there is no ``mod_rewrite`` overhead
on every request.

HSTS
----

Once HTTPS is the only intended way to reach the site, HSTS
(HTTP Strict Transport Security, defined in RFC 6797)
instructs compliant clients to refuse plain-HTTP requests for
the host for a configured period. A subsequent ``http://``
URL typed into the address bar is upgraded to ``https://``
locally without ever sending the plain-HTTP request.

For ``mod_wsgi-express``::

    mod_wsgi-express start-server wsgi.py \
        --port 8080 --https-port 8443 \
        --ssl-certificate-file ./server.crt \
        --ssl-certificate-key-file ./server.key \
        --https-only \
        --hsts-policy "max-age=63072000; includeSubDomains; preload"

For a manually-configured Apache::

    <VirtualHost *:443>
        ...
        Header always set Strict-Transport-Security \
            "max-age=63072000; includeSubDomains; preload"
    </VirtualHost>

Parameter notes:

* ``max-age`` is the number of seconds the policy is valid for.
  ``63072000`` is two years, which is the value the HSTS
  preload list requires for inclusion. Start with a much
  smaller value (a few minutes) when first enabling HSTS so a
  configuration mistake can be backed out without leaving
  clients locked out for years.
* ``includeSubDomains`` extends the policy to every subdomain
  of the host. Be sure every subdomain has working HTTPS
  before setting this.
* ``preload`` is a marker requesting inclusion in the browser
  vendors' hard-coded HSTS preload list maintained at
  https://hstspreload.org/. Inclusion is permanent in
  practice; do not set this unless you are certain about the
  rest of the policy.

When mod_wsgi sits behind a front-end reverse proxy, HSTS
should be set at the public-facing layer (the proxy or load
balancer), not inside the back-end mod_wsgi instance. The
back-end's view of the request scheme is plain HTTP regardless
of what the client used.

Production certificates
-----------------------

For any internet-facing site, use a certificate issued by a
real CA rather than a self-signed certificate. The free option
that has displaced commercial CAs for almost all use cases is
`Let's Encrypt <https://letsencrypt.org/>`_. The standard
client is `certbot <https://certbot.eff.org/>`_, which handles
the ACME exchange, places the issued cert and key in a known
location on disk, and arranges automatic renewal via cron or
systemd. The certbot site has installation instructions for
each supported platform and Apache, so this page does not
duplicate them.

Two operational notes that matter for mod_wsgi specifically:

* Cert rotation requires Apache to re-read the certificate
  files. For a system Apache running mod_wsgi, an
  ``apachectl graceful`` (or ``systemctl reload apache2`` /
  ``systemctl reload httpd``) on cert renewal is sufficient;
  certbot's renewal hooks can be configured to run this
  automatically. For ``mod_wsgi-express`` the equivalent is
  restarting the express instance.
* When using ``--ssl-certificate-chain-file`` (or
  ``SSLCertificateChainFile``) with a Let's Encrypt cert, the
  chain file is the ``chain.pem`` file that certbot writes to
  ``/etc/letsencrypt/live/<domain>/`` alongside the cert
  itself.

Cipher and protocol configuration
---------------------------------

The set of TLS protocol versions and cipher suites a server
should accept changes over time as cryptographic primitives
weaken or are deprecated. Rather than baking a recommended
cipher list into this page (which would go stale), use
`Mozilla's SSL Configuration Generator
<https://ssl-config.mozilla.org/>`_, which produces an Apache
``mod_ssl`` configuration block tuned to a chosen profile
(modern, intermediate, or old) and current best practice. Drop
the generated ``SSLProtocol`` / ``SSLCipherSuite`` /
``SSLHonorCipherOrder`` lines into the ``<VirtualHost *:443>``
block (or, for ``mod_wsgi-express``, into a configuration
fragment loaded via ``--include-file``).

A reasonable baseline as of writing is::

    SSLProtocol -all +TLSv1.2 +TLSv1.3

which disables every older protocol version. SSLv3, TLS 1.0,
and TLS 1.1 are no longer considered secure.

HTTPS when there is a reverse proxy in front
--------------------------------------------

In the common production deployment where mod_wsgi sits behind
a separate reverse proxy (nginx, HAProxy, AWS ALB, Kubernetes
ingress), TLS is terminated at the proxy and the connection
between the proxy and mod_wsgi is plain HTTP. In this
configuration:

* The mod_wsgi instance does not need ``--https-port``,
  ``--ssl-certificate-file``, ``SSLEngine``, or any of the
  other TLS options on this page. The proxy holds the
  certificate.
* For the WSGI application to know the original request was
  HTTPS rather than the plain-HTTP connection from the proxy,
  the proxy must send ``X-Forwarded-Proto: https`` and
  mod_wsgi must be configured to trust that header. This is
  covered in :doc:`running-behind-a-reverse-proxy`.
* HSTS belongs on the proxy, not the back-end. The back-end's
  view of the request scheme is plain HTTP regardless of what
  the client used.
* ``--https-only`` should not be set on the back-end. With
  ``X-Forwarded-Proto`` trust configured, mod_wsgi already
  knows whether the original was HTTPS; with the flag set,
  redirect logic on the back-end can interact badly with the
  proxy's view.

Client certificates (mutual TLS)
--------------------------------

In the standard HTTPS handshake the server presents a
certificate to the client and the client (typically a browser)
verifies it. *Mutual* TLS, often abbreviated mTLS, additionally
requires the client to present a certificate that the server
verifies. Where regular HTTPS authenticates the server to the
client, mTLS authenticates the client to the server.

mTLS is mostly seen in non-browser contexts: server-to-server
API calls between trusted services, IoT or embedded devices
talking to a backend, internal-only admin endpoints, and
enterprise integrations where the consuming party is a known
organisation rather than a member of the public. The client
certificate becomes the authentication credential, replacing
or supplementing username/password or API tokens.

The mod_wsgi-instance configuration adds two pieces:

* A CA bundle that lists which Certificate Authorities are
  allowed to issue valid client certificates. Typically this
  is a small private CA that you operate, not a public CA.
* A directive saying that client cert verification is required
  (or optional) for some or all URLs.

For ``mod_wsgi-express``::

    mod_wsgi-express start-server wsgi.py \
        --port 8080 --https-port 8443 \
        --ssl-certificate-file ./server.crt \
        --ssl-certificate-key-file ./server.key \
        --ssl-ca-certificate-file ./client-ca.crt \
        --ssl-verify-client /api/

Without ``--ssl-verify-client`` the cert is requested but not
required; with the option, requests under the supplied URL
prefix that do not present a valid client cert are rejected
at the TLS layer with a 403-style failure.

For a manually-configured Apache the equivalent uses
``SSLCACertificateFile`` plus ``SSLVerifyClient`` scoped to a
``<Location>``::

    <VirtualHost *:443>
        ...
        SSLEngine on
        SSLCertificateFile      /etc/pki/example/example.crt
        SSLCertificateKeyFile   /etc/pki/example/example.key
        SSLCACertificateFile    /etc/pki/example/client-ca.crt

        <Location /api/>
            SSLVerifyClient require
            SSLVerifyDepth 1
        </Location>
    </VirtualHost>

The application then sees information about the verified
client certificate in the WSGI environment when
``--ssl-environment`` is set (or ``SSLOptions +StdEnvVars``
for manual Apache); the standard ``mod_ssl`` variables include
``SSL_CLIENT_S_DN``, ``SSL_CLIENT_VERIFY``, and others. See
the `Apache mod_ssl documentation
<https://httpd.apache.org/docs/2.4/mod/mod_ssl.html>`_ for
the full list and for the directives controlling chain depth,
revocation checking, and certificate-issuer constraints.

Generating client certificates and operating the private CA
that signs them is the same workflow as for any small CA. The
`Apache SSL/TLS How-To
<https://httpd.apache.org/docs/2.4/ssl/ssl_howto.html>`_
covers the basics; for a production rollout, dedicated CA
tools such as smallstep's ``step-ca`` or HashiCorp Vault's PKI
secrets engine are typically more appropriate than ad-hoc
``openssl`` invocations.

Where to go next
----------------

* :doc:`running-behind-a-reverse-proxy` for the common
  production case where TLS is terminated at the proxy and
  mod_wsgi sees plain HTTP.
* :doc:`mod-wsgi-express-quickstart` for ``mod_wsgi-express``
  options unrelated to TLS, including the privileged-port
  story for binding 443 directly.
* :doc:`installing-with-docker` for running ``mod_wsgi-express``
  in a container; TLS in containerised deployments is almost
  always handled by the ingress, not by the container itself.
* :doc:`debugging-techniques` and :doc:`application-issues`
  for diagnosing TLS handshake errors, certificate-chain
  problems, and similar.
