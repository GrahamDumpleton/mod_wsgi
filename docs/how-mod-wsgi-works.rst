==================
How mod_wsgi Works
==================

This page sketches the bigger picture of where mod_wsgi sits in a
deployment: how it relates to Apache, what its hosting model looks
like, how ``mod_wsgi-express`` differs from a traditional Apache plus
mod_wsgi setup, and the common shapes of production deployments. It
is intended as orientation reading for someone who wants to understand
the model before getting into specific install or configuration
steps.

For step-by-step setup instructions see :doc:`installation` and the
:doc:`user-guides/quick-configuration-guide`.

Apache HTTP Server
------------------

mod_wsgi is a module for the Apache HTTP Server (also known as
``httpd``). Apache is one of the longest-running open source web
servers, with active development and security maintenance going back
to the mid-1990s. It is a mature, conservatively-engineered platform
with a long track record of stable production use, regular security
fixes, and a substantial body of operational knowledge in the wider
community.

Apache is built around a small core that handles the basics of
listening on sockets, parsing HTTP requests, and dispatching responses.
Almost everything else — HTTPS termination, URL rewriting,
authentication, content compression, language-specific application
hosting — is implemented as a *loadable module*. Modules are compiled
as shared libraries and pulled into the server at startup with the
``LoadModule`` directive::

    LoadModule ssl_module       modules/mod_ssl.so
    LoadModule rewrite_module   modules/mod_rewrite.so
    LoadModule wsgi_module      modules/mod_wsgi.so

::

                    Apache HTTP Server (httpd)
                    ┌────────────────────────────────────┐
                    │  Core: sockets, HTTP, dispatch     │
                    │                                    │
                    │  ┌────────┐ ┌────────┐ ┌────────┐  │
                    │  │ mod_ssl│ │mod_rewr│ │mod_wsgi│  │
                    │  └────────┘ └────────┘ └────────┘  │
                    │        loaded shared modules       │
                    └────────────────────────────────────┘

This module architecture is the reason mod_wsgi exists and the reason
it works the way it does. Hosting Python under Apache via mod_wsgi is
not a matter of running a separate, independently-managed Python web
server alongside Apache and shuttling requests between them. mod_wsgi
loads the Python interpreter into processes that are spawned and
managed by Apache itself, and runs your WSGI application as part of
Apache's request-handling pipeline.

How mod_wsgi hosts your application
-----------------------------------

A WSGI application is a Python callable that follows the interface
specified in `PEP 3333`_: it accepts an environment dictionary and a
``start_response`` callable, and returns an iterable of response body
chunks. mod_wsgi's job is to take an incoming HTTP request that
matches one of its handler URLs, convert it into a WSGI environment,
invoke your Python callable, and turn the response back into an HTTP
response.

Mapping URLs to a WSGI application is done with
:doc:`configuration-directives/WSGIScriptAlias`::

    WSGIScriptAlias /myapp /path/to/myapp.wsgi

The script file at the end of that path is a Python module that
exposes an ``application`` callable — your WSGI entry point. mod_wsgi
imports the module, finds the callable, and routes matching requests
to it.

Embedded mode and daemon mode
-----------------------------

mod_wsgi can run your WSGI application in one of two execution modes.
The choice has significant operational consequences.

In **embedded mode** the Python interpreter and your application are
loaded inside the Apache worker processes themselves. Every Apache
worker process that handles a request also has the Python interpreter
embedded in it. ::

    HTTP request
         │
         ▼
    ┌────────────────────────────────┐
    │ Apache worker process          │
    │                                │
    │  ┌──────────────────────────┐  │
    │  │ Embedded Python          │  │
    │  │ interpreter + WSGI app   │  │
    │  └──────────────────────────┘  │
    └────────────────────────────────┘
         │
         ▼
    HTTP response

Embedded mode is simple to set up but couples the lifetime of your
application to the lifetime of Apache worker processes, and means
Apache and your Python application share the same address space and
the same operating system user. The user is typically a low-privilege
account, but it is the same one used by every other module loaded
into Apache and by every other site or application the same Apache
instance might be hosting.

In **daemon mode** mod_wsgi runs your application in one or more
*daemon process groups* — separate processes forked and managed by
Apache's parent process, but isolated from the worker processes that
handle inbound HTTP traffic. Apache workers act as proxies that hand
the request over a Unix domain socket to the daemon process, which
runs the Python interpreter and your application. ::

    HTTP request
         │
         ▼
    ┌─────────────────────┐    Unix socket    ┌──────────────────────────┐
    │ Apache worker       │ ───────────────►  │ mod_wsgi daemon process  │
    │ (mod_wsgi as proxy) │                   │  Python interpreter      │
    │                     │ ◄───────────────  │  WSGI application        │
    └─────────────────────┘                   └──────────────────────────┘
         │
         ▼
    HTTP response

Daemon mode gives you process-level isolation between your application
and the rest of Apache. It also lets you run the application as a
different operating system user from the one Apache itself runs as,
restart the application without restarting Apache, control its
process count and threading model independently, and constrain its
resource usage. Daemon mode is configured with
:doc:`configuration-directives/WSGIDaemonProcess` and
:doc:`configuration-directives/WSGIProcessGroup`.

Daemon mode is the recommended mode for production use on UNIX-like
systems and is what ``mod_wsgi-express`` uses by default. Embedded
mode remains supported but its operational characteristics make it
a poor fit for most modern deployments.

mod_wsgi-express
----------------

``mod_wsgi-express`` is a Python command-line program installed when
you ``pip install mod_wsgi``. It is *not* a different web server: it
is a packaging and configuration layer over the same Apache plus
mod_wsgi components used in a traditional install.

When you run ``mod_wsgi-express start-server myapp.wsgi``, the
following happens:

1. The package locates a working ``httpd`` binary on the system —
   the same Apache binary that the host's package manager or
   manual install provides.
2. It generates a fresh Apache configuration in a private directory,
   tuned specifically for hosting a single WSGI application: daemon
   mode, sensible default process and thread counts, an isolated log
   directory, no extraneous modules.
3. It starts a new ``httpd`` process using that configuration, owned
   by the invoking user, listening on a chosen port.

The result is a complete, self-contained Apache plus mod_wsgi
instance that exists alongside (rather than instead of) any Apache
that the system has installed. ::

    System Apache (root-owned)            mod_wsgi-express (your user)
    ┌───────────────────────────┐         ┌───────────────────────────┐
    │  /etc/apache2/...         │         │  /tmp/mod_wsgi-.../       │
    │  /etc/httpd/...           │         │   httpd.conf  (generated) │
    │  port 80, port 443        │         │   error_log, access_log   │
    │  managed by package mgr   │         │   port 8000 (default)     │
    │  may serve other sites    │         │   one WSGI application    │
    └───────────────────────────┘         └───────────────────────────┘

The two instances are independent. They do not share configuration,
log directories, ports, or process trees. The system Apache is
typically managed by your operating system's service manager and
runs under its package-default user; the ``mod_wsgi-express``
instance is started from the command line, runs entirely as the user
who invoked it, and exits when that user stops it.

Because ``mod_wsgi-express`` runs as an unprivileged user by default,
it cannot bind to privileged ports (anything below 1024) without
help. By default it uses port 8000.

Deployment patterns
-------------------

Several deployment shapes are common. Each is suitable for production;
they trade off integration with the rest of the system against
isolation, ease of setup, and ease of operation.

System Apache hosting WSGI directly
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The traditional pattern: install mod_wsgi into the system's Apache
(from source or a distribution package), edit Apache's configuration
files to add ``WSGIScriptAlias`` and ``WSGIDaemonProcess`` directives,
and let Apache serve your WSGI application alongside any static
content or other modules already loaded. ::

    ┌──────────────────────────────────────┐
    │  System Apache (root)                │
    │  port 80, port 443                   │
    │                                      │
    │   ├── mod_ssl                        │
    │   ├── mod_rewrite                    │
    │   ├── mod_wsgi                       │
    │   │   └── daemon process group       │
    │   │       └── your WSGI app          │
    │   └── static content, other vhosts   │
    └──────────────────────────────────────┘

This pattern is appropriate when you administer the host yourself,
the WSGI application is one of several things the host serves, and
you want a single Apache instance handling everything.

mod_wsgi-express as the front-line server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A ``mod_wsgi-express`` instance can replace the system Apache as the
host's main web server. In this pattern there is no separate system
Apache running; ``mod_wsgi-express`` listens on ports 80 and 443
itself. ::

    ┌──────────────────────────────────────┐
    │  mod_wsgi-express                    │
    │  port 80, port 443                   │
    │                                      │
    │  one WSGI application                │
    └──────────────────────────────────────┘

This requires running ``mod_wsgi-express`` with sufficient privilege
to bind to the privileged ports, which on a typical Linux deployment
means running it under a service manager (systemd, supervisord, etc.)
that handles the privilege drop, or under a process supervisor that
can grant the necessary capability.

This pattern is appropriate when a host is dedicated to a single
WSGI application and the operational simplicity of a single
self-contained runtime outweighs the convenience of the system's
package-managed Apache.

mod_wsgi-express behind a reverse proxy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A common production pattern is to run ``mod_wsgi-express`` listening
on an unprivileged port and put a separate front-end web server in
front of it acting as a reverse proxy. The front-end can be the
system Apache, nginx, HAProxy, or anything else that can proxy HTTP. ::

                       ┌──────────────────────┐
                       │  Public internet     │
                       └──────────┬───────────┘
                                  │
                       ┌──────────▼───────────┐
                       │  Front-end           │
                       │  (system Apache,     │
                       │   nginx, HAProxy)    │
                       │  port 80, port 443   │
                       │  TLS termination     │
                       │  static assets       │
                       └──────────┬───────────┘
                                  │  reverse proxy
                  ┌───────────────┼───────────────┐
                  │               │               │
           ┌──────▼─────┐  ┌──────▼─────┐  ┌──────▼─────┐
           │ mod_wsgi-  │  │ mod_wsgi-  │  │ mod_wsgi-  │
           │ express    │  │ express    │  │ express    │
           │ (user A)   │  │ (user B)   │  │ (user C)   │
           │ port 8001  │  │ port 8002  │  │ port 8003  │
           │ app1       │  │ app2       │  │ app3       │
           └────────────┘  └────────────┘  └────────────┘

The front end handles TLS termination, static asset serving, virtual
host routing, and any cross-cutting concerns; each
``mod_wsgi-express`` instance focuses solely on hosting one WSGI
application. The instances can be owned by different users, started
and stopped independently, and run different versions of Python or
different framework dependencies in their respective virtual
environments without interfering with each other.

This pattern is appropriate when multiple applications share a host,
when applications belong to different users or teams, or when you
want application restarts to be isolated from the front-end
TLS-handling server.

mod_wsgi-express in a container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A container is in many ways the natural home for a
``mod_wsgi-express`` instance. The container model — one main
foreground process, one user, one filesystem, one or two predictable
ports — maps directly onto how ``mod_wsgi-express`` is structured. ::

    ┌──────────────────────────────────────┐
    │  Container                           │
    │                                      │
    │  ┌────────────────────────────────┐  │
    │  │ mod_wsgi-express               │  │
    │  │  Apache (httpd)                │  │
    │  │  mod_wsgi                      │  │
    │  │  Python interpreter + app      │  │
    │  └────────────────────────────────┘  │
    │  EXPOSE 8000                         │
    └──────────────────────────────────────┘

Inside the container there is no system Apache to integrate with and
no other services contending for ports or filesystem locations.
``mod_wsgi-express`` starts in the foreground, logs to stdout and
stderr (suitable for the container runtime to collect), and exits
cleanly when the container is stopped.

Containers running ``mod_wsgi-express`` are typically deployed behind
the same kind of reverse-proxy layer as native instances —
Kubernetes ingress controllers, cloud load balancers, or a separate
front-end Apache or nginx — so the architectural pattern is the same
as the reverse-proxy deployment above, with container boundaries
replacing process boundaries.

Choosing between deployment patterns
------------------------------------

The patterns above are not mutually exclusive and the right choice
depends on what else lives on the host:

* If the host already has a system Apache serving content and you
  want to add a WSGI application to it, integrate with the system
  Apache directly.
* If the host is dedicated to a single WSGI application and you do
  not want to manage a separately-installed Apache, use
  ``mod_wsgi-express`` as the front-line server.
* If the host serves multiple WSGI applications, especially under
  different users, put ``mod_wsgi-express`` instances behind a
  reverse proxy.
* If you are deploying into containers or onto a container-based
  platform, use ``mod_wsgi-express`` inside the container and let
  the platform's existing ingress layer handle TLS and routing.

In every case the actual runtime — Apache plus mod_wsgi plus your
Python application — is the same. The deployment pattern only
determines how that runtime is started, who owns it, and what sits
in front of it.

.. _PEP 3333: https://peps.python.org/pep-3333/
