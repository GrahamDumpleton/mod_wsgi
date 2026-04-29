===================
Installation Issues
===================

mod_wsgi is a small package but its build depends on both Apache and
Python, and various install problems can arise as a result. Common
causes include an incomplete Python installation, multiple Python
versions on the host, or platform-specific build-toolchain quirks.
This page lists known problems and workarounds.

If your problem is not covered here, also see
:doc:`configuration-issues` and :doc:`application-issues`.

Missing Python Header Files
---------------------------

Compiling mod_wsgi from source requires Python's development headers.
On Linux distributions where Python is split into a runtime package
and a separate developer package, the developer package is often not
installed by default and the build will fail with errors like::

    mod_wsgi.c:113:20: error: Python.h: No such file or directory
    mod_wsgi.c:114:21: error: compile.h: No such file or directory
    mod_wsgi.c:115:18: error: node.h: No such file or directory
    mod_wsgi.c:116:20: error: osdefs.h: No such file or directory
    mod_wsgi.c:119:2: error: #error Sorry, mod_wsgi requires at least Python 3.10.0.

Install the developer package for the Python you are using. The name
varies by distribution but is typically the runtime package name with
``-dev`` appended (``python3-dev`` on Debian/Ubuntu) or ``-devel``
(``python3-devel`` on RHEL/Fedora).

Lack Of Python Shared Library
-----------------------------

A normally-built ``mod_wsgi.so`` is under 250KB. If your build comes
out over 1MB, the Python installation it was built against does not
provide a shared library — only a static one — and ``libtool`` has
embedded the static Python objects directly into ``mod_wsgi.so``
instead of linking against ``libpython3.X.so`` dynamically.

This has two practical consequences:

* When Apache loads ``mod_wsgi.so``, the dynamic linker performs
  address relocations on the embedded Python objects. Because
  relocations modify memory, the Python library becomes private to
  each Apache process rather than shared, adding 1-2MB per Apache
  child process on Linux.

* Subsequent Python patch-level upgrades will not be picked up
  automatically. The static Python is baked into ``mod_wsgi.so`` and
  any changes in the upgraded Python library will not be reflected in
  the embedded copy. See "Python Patch Level Mismatch" below.

To check whether ``mod_wsgi.so`` is using a shared Python library,
run ``ldd`` against it::

    $ ldd mod_wsgi.so
     linux-vdso.so.1 =>  (0x00007fffeb3fe000)
     libpython3.12.so.1.0 => /usr/local/lib/libpython3.12.so.1.0 (0x00002adebf94d000)
     libpthread.so.0 => /lib/libpthread.so.0 (0x00002adebfcba000)
     libdl.so.2 => /lib/libdl.so.2 (0x00002adebfed6000)
     libutil.so.1 => /lib/libutil.so.1 (0x00002adec00da000)
     libc.so.6 => /lib/libc.so.6 (0x00002adec02dd000)
     libm.so.6 => /lib/libm.so.6 (0x00002adec0635000)
     /lib64/ld-linux-x86-64.so.2 (0x0000555555554000)

The presence of a ``libpython3.X.so`` line indicates a shared Python
library is being used. If there is no such line, mod_wsgi is using
the static library.

To get a shared library, build Python with ``--enable-shared``. Most
distribution Python packages, Homebrew Python, and python.org
installers already do so.

Multiple Python Versions
------------------------

If multiple Python installations are present on the host — for
example a system Python plus a ``pyenv``- or ``uv``-managed Python,
or a python.org installer alongside a Homebrew Python — and you need
mod_wsgi to use a specific one, pass ``--with-python`` to
``configure`` when building::

    ./configure --with-python=/usr/local/bin/python3.12

This is enough when the Pythons live under the same top-level
directory. If the version you want to use is in a different location
(for example ``/usr/local`` while another Python is at ``/usr``),
Apache may fail to find the Python library files at startup.

The Python interpreter determines its installation prefix at startup
by looking up its own executable on ``PATH`` and taking the parent
of that location. The ``PATH`` Apache inherits at startup is
typically only the system default, so if Python's ``bin`` directory
is not on Apache's ``PATH`` the Python embedded in mod_wsgi will
find ``/usr/bin/python3`` rather than the intended
``/usr/local/bin/python3``, and use ``/usr`` as its installation
prefix instead of ``/usr/local``.

If there is no Python installation under ``/usr`` matching the
version mod_wsgi was built against, Apache's error log will show::

    'import site' failed; use -v for traceback

and any request to a WSGI application will fail because nothing
beyond the built-in modules is importable.

If there *is* a Python installation under ``/usr`` of the same
major and minor version (but not the one mod_wsgi was built
against), startup may succeed but at runtime imports may resolve to
a different installation than expected. Imports may fail entirely
or — worse — silently pick up incompatible third-party modules.

To direct mod_wsgi to the right Python installation explicitly, use
the ``WSGIPythonHome`` directive::

    WSGIPythonHome /usr/local

The value should be a normalised path corresponding to the
``sys.prefix`` of the Python you built mod_wsgi against::

    >>> import sys
    >>> sys.prefix
    '/usr/local'

A less-preferred alternative is to extend Apache's ``PATH`` so the
intended Python is found first. For a standard Apache installation,
edit the ``envvars`` file in the same directory as the Apache
executable::

    PATH=/usr/local/bin:$PATH
    export PATH

To verify which Python installation is actually being used at
runtime, deploy a small WSGI script that prints ``sys.prefix`` and
``sys.path`` to ``stderr``::

    import sys

    def application(environ, start_response):
        status = '200 OK'
        output = b'Hello World!'

        response_headers = [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        print('sys.prefix = %s' % repr(sys.prefix), file=sys.stderr)
        print('sys.path = %s' % repr(sys.path), file=sys.stderr)

        return [output]

Anaconda Python Conflicting With System Shared Libraries
--------------------------------------------------------

Anaconda Python ships its own copies of various third-party shared
libraries inside the Anaconda installation — including SSL,
image manipulation, cryptography, and others. When mod_wsgi is
built against Anaconda Python and loaded into an Apache instance
that also has another module loaded which links against the
corresponding *system* shared library, the two modules can end up
disagreeing about which copy of that library is in use within the
same Apache process address space.

Two examples that have been seen in practice:

* **mod_ssl plus Anaconda Python's ssl module.** mod_ssl is built
  against the host's system SSL libraries. Anaconda Python's
  ``ssl`` module is built against Anaconda's own SSL libraries.
  When both are loaded into the same Apache process — for example
  when an HTTPS-serving Apache also hosts a WSGI application that
  imports Python's ``ssl`` module — this has been observed to
  cause crashes of the Apache worker process.

* **PHP plus Anaconda Python.** mod_php (and other Apache modules)
  link against system libraries for image manipulation and
  similar. Loading both mod_php and an Anaconda-built mod_wsgi
  into the same Apache instance can result in disagreements over
  which copy of those libraries is in use.

The symptoms vary widely depending on which library the conflict
is over. They range from runtime errors out of either Python or
the conflicting module's code through to outright crashes of the
Apache worker process.

The conflict is fundamental: there is no way for mod_wsgi to
mediate the disagreement between Anaconda's shipped libraries and
the system libraries the rest of Apache is using.

If you must use Anaconda Python for your WSGI application, do not
load mod_wsgi into the same Apache instance as mod_ssl, mod_php,
or other modules that overlap with Anaconda's bundled native
dependencies. Run the WSGI application in a separate Apache
instance — for example via ``mod_wsgi-express`` on an
unprivileged port behind a front-end Apache or nginx that
terminates HTTPS — so the two sets of libraries are not loaded
into the same process. Otherwise, use a system Python or a
python.org installer for the mod_wsgi build instead of Anaconda.

Python Patch Level Mismatch
---------------------------

If the Python installation is upgraded to a newer patch-level revision
without rebuilding mod_wsgi, you will likely see a warning of the
following form (logged with the WSGI0099 error code; see
:doc:`../error-reference`) in the Apache error log when Python is being
initialised::

    [Sat Jan 01 12:34:56.789012 2026] [wsgi:warn] [pid 12345] WSGI0099: Compiled for Python/3.12.0 but runtime using Python/3.12.1.

The warning indicates that a newer Python version is now being used
than the one mod_wsgi was originally compiled against.

If both Pythons were installed with ``--enable-shared``, this is
generally harmless: the Python library is linked dynamically at
runtime, so the upgrade is picked up automatically.

If ``--enable-shared`` was not used and the static Python library is
embedded into ``mod_wsgi.so``, the embedded library code will be
older than the Python modules and extension modules now present in
the Python installation. Behaviour in this case is undefined and you
should rebuild mod_wsgi against the upgraded Python.

.. _mixing-32-bit-and-64-bit-packages:

Linker Relocation Errors Against The Python Static Library
----------------------------------------------------------

When building mod_wsgi on a 64-bit Linux system against a Python
installation that provides only a static library
(``libpython3.X.a``), the link step can fail with an error of the
following shape::

    /usr/bin/ld: /path/to/libpython3.X.a(abstract.o): \
        relocation R_X86_64_32S against symbol `_Py_NoneStruct' \
        can not be used when making a shared object; \
        recompile with -fPIC
    /usr/bin/ld: failed to set dynamic section sizes: bad value
    collect2: error: ld returned 1 exit status

The exact relocation type cited can be ``R_X86_64_32``,
``R_X86_64_32S``, or ``R_X86_64_PC32`` depending on the linker
version and which Python symbols are involved. The defining
feature of the error is the trailing message "can not be used
when making a shared object; recompile with -fPIC".

The root cause is that the static Python library being linked
into ``mod_wsgi.so`` was not compiled with position-independent
code. The mod_wsgi module is itself a shared object, so every
object linked into it must be position-independent. Object files
inside ``libpython3.X.a`` were not, and the link fails.

Historically this error appeared when a 32-bit Python static
library was being linked into a 64-bit mod_wsgi build, which is
where the older form of this section's title comes from. On
modern systems the more common cause is simply that Python was
built without ``--enable-shared``: the resulting ``libpython.a``
is not position-independent and the same relocation error appears
even on a fully 64-bit system.

The fix is to use a Python build that provides a *shared* library
(``libpython3.X.so``) rather than only a static one. Most
distribution Python packages, Homebrew Python, and python.org
installers ship Python with ``--enable-shared`` and so already
provide a shared library. If you are using a hand-built Python
that does not, rebuild it with::

    ./configure --enable-shared
    make
    make install

See also the "Lack Of Python Shared Library" section above.

Unable To Find Python Shared Library
------------------------------------

When mod_wsgi is built against a Python that provides a shared
library, that shared library must be in a directory the dynamic
linker searches at runtime. If it is not, Apache will fail to load
``mod_wsgi.so`` with::

    error while loading shared libraries: libpython3.12.so.1.0: \
     cannot open shared object file: No such file or directory

The simplest fix is to ensure the Python shared library is on the
system-wide library search path. ``/lib`` and ``/usr/lib`` are
typically always searched. ``/usr/local/lib`` is also searched on
many systems, but only if it has been added to the loader's
configuration — on Linux this is typically ``/etc/ld.so.conf`` or a
file under ``/etc/ld.so.conf.d/``, with ``ldconfig`` rerun
afterwards.

Alternatively, set ``LD_LIBRARY_PATH`` in Apache's startup
environment to include the directory containing the Python shared
library. For an unmodified Apache distribution this goes in the
``envvars`` file in the same directory as the Apache executable. On
RHEL-derived distributions the package may not ship an ``envvars``
file; use ``/etc/sysconfig/httpd`` instead.

A third option is to have Apache itself preload the Python shared
library before loading mod_wsgi, using the ``LoadFile`` directive
placed before the ``LoadModule wsgi_module`` line in the Apache
configuration::

    LoadFile /usr/local/lib/libpython3.12.so.1.0
    LoadModule wsgi_module modules/mod_wsgi.so

By the time Apache reaches ``LoadModule wsgi_module``, the Python
shared library is already mapped into the Apache process and the
linker resolves mod_wsgi's references to it directly, without
consulting the system library search path. This avoids needing root
access to update ``ld.so.conf``, avoids polluting the system
loader's configuration with a path that is only relevant to Apache,
and makes the dependency explicit and local to the Apache
configuration. ``mod_wsgi-express module-config`` already emits a
``LoadFile`` directive automatically on macOS and Windows; on Linux
it is not emitted by default but can be added manually if needed.

The same ``LoadFile`` trick is also useful when the Python shared
library *is* findable but the dynamic linker resolves to the wrong
copy — for example on hosts that have multiple installations of the
same Python major version, when ``rpath`` settings baked into a
relocated Python installation no longer point at the right place,
or when the Python shared library exists at an unusual location
(such as inside a virtual environment) that is not on any system
search path. Pointing ``LoadFile`` at the exact path of the Python
shared library that mod_wsgi was built against forces that specific
copy to be the one used.

