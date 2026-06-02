==============
Project Status
==============

mod_wsgi is a mature project. It has been used in production by Python
web applications for over 15 years and is functionally complete for
typical Apache + Python WSGI deployments. Active work today is focused
on polish, internal cleanup, and rounding out auxiliary capabilities
rather than on changing the core hosting model.

Active development
------------------

The project is maintained by its original author, Graham Dumpleton.
The 6.x release line is the current focus of development. Recent and
ongoing themes include:

* Surfacing and documenting mod_wsgi's internal metrics, including a
  monitoring UI and paths for integration with external monitoring
  systems.
* Opt-in support for Python's evolving concurrency models: the
  per-interpreter GIL (PEP 684) and free-threaded Python (PEP 703).
* Reliability improvements, such as the v6 request-timeout machinery.
* Worked examples of using AI tooling to help tune Apache and mod_wsgi
  configuration for a particular workload.

Version support
---------------

* **6.x** — current development line. New features and fixes go here.
* **5.x** — stable. Once 6.x has stabilised, 5.x will receive backports
  of essential fixes only; new features will not be backported.
* **Older versions (4.x and earlier)** — no longer maintained. Linux
  distributions sometimes ship older versions of mod_wsgi as part of
  long-term-support releases; those older versions are not supported
  by this project even when shipped by an LTS distribution.

Python and Apache support
-------------------------

The current release requires Python 3.10 or later and Apache 2.4.

Earlier mod_wsgi releases held compatibility with end-of-life Python
versions for a long time, largely because the code base was not seeing
active updates. With 6.x, support for end-of-life Python versions is
dropped more proactively, in line with upstream Python's own support
timeline.

Windows support
---------------

mod_wsgi has historically built and run on Windows, but Windows is not
a platform that the project's author actively uses or tests on. In
earlier release lines, Windows confirmation amounted to verifying that
``pip install mod_wsgi`` produced a working build; some features were
known not to work on Windows, including ``mod_wsgi-express
start-server``.

With the substantial changes in 6.x, it is currently unknown whether
mod_wsgi still builds and runs cleanly on Windows. Continued Windows
support will depend on users running mod_wsgi on Windows reporting
issues, and helping to investigate them, via the GitHub issue tracker.

Where to get help
-----------------

For bug reports and questions, use the GitHub issue tracker at
https://github.com/GrahamDumpleton/mod_wsgi/issues.

The historical mod_wsgi mailing list still exists as a read-only
archive of past discussions but is no longer active and should not be
used for new questions.

See also :doc:`finding-help` and :doc:`reporting-bugs`.
