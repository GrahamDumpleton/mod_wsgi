========================
Installing With Docker
========================

This page covers running ``mod_wsgi-express`` inside a Docker
container. The companion pages cover related material:

* :doc:`installation-from-pypi` for the ``pip install mod_wsgi``
  step that the Dockerfile examples here perform inside the
  image.
* :doc:`mod-wsgi-express-quickstart` for the broader operational
  shape of ``mod_wsgi-express``, including ``--log-to-terminal``
  and the foreground process model that this page assumes.
* :doc:`../how-mod-wsgi-works` for the conceptual picture of how
  ``mod_wsgi-express`` fits into a container.

The examples below use Docker syntax. Other OCI-compatible
runtimes (Podman, containerd) accept the same Dockerfiles
unchanged.

Why mod_wsgi-express works well in a container
----------------------------------------------

A container expects a single foreground process that owns
process ID 1, handles ``SIGTERM`` for orderly shutdown, and
reaps any child processes it forks. ``mod_wsgi-express`` fits
that shape directly because it runs Apache HTTP Server in the
foreground, and Apache's parent process is already a real
process supervisor:

* Apache forks daemon-mode worker processes as its children and
  installs a ``SIGCHLD`` handler that reaps them when they exit.
  Zombies do not accumulate when running as PID 1.
* Apache handles ``SIGTERM`` and exits cleanly. The container
  runtime's stop signal is honoured without a wrapper.
* With ``--log-to-terminal``, Apache writes access and error
  logs to standard output and standard error, so the container
  runtime collects them through its normal log pipeline.

This is in contrast to several other Python WSGI / ASGI servers
where running the application directly as PID 1 is unsafe
(child processes orphan, signals are not forwarded) and a
separate init wrapper such as ``tini`` or ``dumb-init`` is
typically inserted. With ``mod_wsgi-express`` no such wrapper is
needed.

Base image requirements
-----------------------

``pip install mod_wsgi`` compiles the Apache module against the
Apache and Python in the image, so the build environment has
the same prerequisites as a native install:

* Python 3.10 or later, with development headers.
* Apache HTTP Server 2.4 with development headers and the
  ``apxs`` build tool.
* A C compiler.

The standard ``python`` base images on Docker Hub include Python
and a C compiler but do not pre-install Apache. The Apache
runtime and development packages need to be added before
``pip install mod_wsgi`` can succeed:

* On Debian-derived images (the default ``python:3.X`` and
  ``python:3.X-slim`` tags): ``apt-get install -y apache2 apache2-dev``.
* On RHEL-derived images (``python:3.X-fedora``, or a Fedora /
  Rocky / AlmaLinux base with Python added separately):
  ``dnf install -y httpd httpd-devel gcc``.
* On Alpine images (``python:3.X-alpine``):
  ``apk add --no-cache apache2 apache2-dev gcc musl-dev``.

A minimal Dockerfile
--------------------

The following Dockerfile takes a Debian-based ``python:3.X-slim``
image, installs Apache and the build toolchain, installs
mod_wsgi from PyPI, switches to a dedicated non-root user, copies
a WSGI application into the image, and runs it under
``mod_wsgi-express``::

    FROM python:3.12-slim

    RUN apt-get update \
     && apt-get install -y --no-install-recommends \
            apache2 apache2-dev gcc \
     && rm -rf /var/lib/apt/lists/*

    RUN pip install --no-cache-dir mod_wsgi

    RUN useradd --create-home --shell /usr/sbin/nologin app
    USER app
    WORKDIR /home/app

    COPY --chown=app:app hello.py /home/app/hello.py

    EXPOSE 8000

    CMD ["mod_wsgi-express", "start-server", "/home/app/hello.py", \
         "--port=8000", \
         "--log-to-terminal"]

The ``USER app`` directive switches the container's main
process to an unprivileged account before ``mod_wsgi-express``
runs. This is required for the example as written: Docker's
default user is root, and Apache refuses to serve requests as
root unless explicitly told which non-root user to switch to via
``mod_wsgi-express``'s ``--user`` and ``--group`` options. Using
``USER app`` avoids that whole mechanism, and is also good
container hygiene independently.

The ``CMD`` is in Docker's exec form (a JSON array), so the
container runtime invokes ``mod_wsgi-express`` directly as
PID 1 rather than going through a shell. This is the form to
use when you want the PID 1 reaping and signal-handling
behaviour described above.

The ``hello.py`` next to the Dockerfile is the standard minimal
WSGI application::

    def application(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return [b'Hello world!\n']

Build and run::

    docker build -t mod-wsgi-hello .
    docker run --rm -p 8000:8000 mod-wsgi-hello

Then::

    curl http://localhost:8000/

should return ``Hello world!``.

Alternative: install mod_wsgi-standalone
----------------------------------------

The Dockerfile above relies on the base image's package manager
to install Apache and its development headers before
``pip install mod_wsgi`` can compile the module against them.
For base images that ship Python but where adding a system
Apache is undesirable (or where the distro Apache is too old or
unavailable), the ``mod_wsgi-standalone`` package on PyPI
bundles a private Apache install of its own. mod_wsgi-express
then runs against that bundled Apache instead of one supplied by
the OS.

The same Dockerfile shape, with no system Apache::

    FROM python:3.12-slim

    RUN apt-get update \
     && apt-get install -y --no-install-recommends \
            build-essential libexpat1-dev \
     && rm -rf /var/lib/apt/lists/*

    RUN pip install --no-cache-dir mod_wsgi-standalone

    RUN useradd --create-home --shell /usr/sbin/nologin app
    USER app
    WORKDIR /home/app

    COPY --chown=app:app hello.py /home/app/hello.py

    EXPOSE 8000

    CMD ["mod_wsgi-express", "start-server", "/home/app/hello.py", \
         "--port=8000", \
         "--log-to-terminal"]

``mod_wsgi-standalone`` pulls in the companion ``mod_wsgi-httpd``
package, which downloads and compiles Apache, APR, APR-util and
PCRE from source inside the Python environment. The system
packages installed here are the build toolchain
(``build-essential``) and ``libexpat1-dev`` (needed by APR-util);
``apache2`` and ``apache2-dev`` are no longer needed.

Trade-off versus the system-Apache example: building
``mod_wsgi-httpd`` from source takes several minutes the first
time, so ``docker build`` is noticeably slower than the
system-package variant. The resulting image is self-contained
(no reliance on the distro's Apache version), at the cost of
that one-time build. For repeated builds the ``mod_wsgi-httpd``
layer caches like any other, so only the first build pays the
full compilation cost.

Only ``mod_wsgi-express`` is usable from a
``mod_wsgi-standalone`` install; the bundled Apache cannot host
non-mod_wsgi workloads. For all other purposes the resulting
container behaves identically to the system-Apache variant
above, including the PID 1 reaping and signal handling described
earlier.

See :doc:`installation-from-pypi` for the broader context on
``mod_wsgi-standalone`` and when to reach for it outside the
container case.

Exposing a privileged port
--------------------------

The example above publishes on container port 8000, which any
user can bind to, and the container itself runs as a non-root
user. That combination is the recommended shape for a container
running ``mod_wsgi-express``: containers should not run as root,
and there is no need for ``mod_wsgi-express`` to bind a
privileged port directly when the container runtime can map one
for you.

If the host needs to publish on a privileged port such as 80 or
443, do that mapping at the runtime layer rather than inside
the container::

    docker run -p 80:8000 mod-wsgi-hello

The container's ``mod_wsgi-express`` is still bound to 8000
internally, the ``USER app`` Dockerfile is unchanged, and the
container's main process is still non-root.

In Kubernetes, the same idea applies: the ``Pod`` exposes
container port 8000, and a ``Service`` and ``Ingress`` (or
``LoadBalancer``) in front of it terminate TLS and publish on
80 / 443 externally.

Development with bind-mounted source
------------------------------------

For development, the application source can be bind-mounted
into the container instead of copied in at build time, and
``--reload-on-changes`` set so the daemon restarts whenever any
imported Python file is modified::

    docker run --rm \
        -v "$(pwd)":/app -w /app \
        -p 8000:8000 mod-wsgi-hello \
        mod_wsgi-express start-server hello.py \
            --port=8000 \
            --log-to-terminal \
            --reload-on-changes

This pattern is convenient during development but unsuitable
for production. See the ``--reload-on-changes`` description in
:doc:`mod-wsgi-express-quickstart` for why.

Behind a reverse proxy or ingress
---------------------------------

A container running ``mod_wsgi-express`` is normally deployed
behind a reverse-proxy layer that handles TLS, routing across
multiple services, and any cross-cutting concerns. Common
arrangements:

* A Kubernetes ``Ingress`` controller in front of a ``Service``
  pointing at the pod's ``mod_wsgi-express`` port.
* A cloud load balancer (AWS ALB, GCP HTTPS load balancer, etc.)
  pointing at the container's exposed port.
* A separate Apache or nginx container in the same network
  acting as the front-line server.

The container itself does not need to be aware of TLS in any of
these cases; ``EXPOSE 8000`` and a plain HTTP listener are
enough. The container does need to trust the proxy's forwarded
headers if the application is to see the original client IP,
hostname, and protocol scheme rather than the connection from
the proxy: see :doc:`running-behind-a-reverse-proxy` for the
matching ``--trust-proxy`` / ``--trust-proxy-header`` options
and the front-end proxy configuration that pairs with them.

Where to go next
----------------

* :doc:`mod-wsgi-express-quickstart` for the broader
  ``mod_wsgi-express`` option surface beyond what is shown
  here.
* :doc:`../how-mod-wsgi-works` for where the container pattern
  fits among the other deployment shapes.
* :doc:`configuration-guidelines` for richer configuration
  examples once the container's hosted application grows beyond
  Hello world.
* :doc:`debugging-techniques` and :doc:`application-issues`
  when things go wrong.
