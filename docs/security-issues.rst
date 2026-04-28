===============
Security Issues
===============

Reporting a security issue
--------------------------

If you believe you have found a security issue in mod_wsgi, please
report it privately so that a fix can be coordinated before any public
disclosure. Do not open a public GitHub issue for vulnerabilities.

The preferred channel is GitHub's private security advisory feature
for the mod_wsgi repository. Submit a new draft advisory at:

  https://github.com/GrahamDumpleton/mod_wsgi/security/advisories/new

Reports submitted there are visible only to the repository's
maintainer. A CVE can be requested through GitHub once the issue has
been triaged.

If your operating system or Linux distribution ships mod_wsgi as a
system package, you can additionally report the issue through that
distribution's own security process. Red Hat in particular have
historically coordinated CVEs for mod_wsgi via their bug reporting
channel and contacted the upstream maintainer from there.

Supported versions
------------------

Security fixes target the active 6.x release line. The 5.x release
line will receive backports of essential fixes only, including
security fixes where applicable. Older release lines (4.x and
earlier) are not maintained and should not be relied on for new
fixes. See :doc:`project-status` for the project's overall version
support policy.

Known advisories
----------------

The following CVEs have been issued against past versions of
mod_wsgi. All of them have been fixed; running a current release of
mod_wsgi means none of them apply.

* **CVE-2022-2255** — Trusted proxy header bypass. The
  ``X-Client-IP`` request header was not stripped from requests
  received from untrusted proxies, allowing a remote attacker to
  spoof the header value to the hosted WSGI application. Affected
  versions prior to 4.9.3; fixed in 4.9.3.

* **CVE-2014-8583** — Daemon process group privilege drop. When
  creating a daemon process group, mod_wsgi did not correctly check
  the result of dropping supplementary group privileges in some
  configurations. Affected versions prior to 4.2.4; fixed in 4.2.4.
  Reaching the affected code path required local root in order to
  set up the misconfigured daemon process group in the first place.

* **CVE-2014-0240** — setuid error code handling. On certain Linux
  kernels, mod_wsgi did not correctly handle non-POSIX error codes
  returned by ``setuid()`` when dropping privileges in daemon mode.
  In a configuration that allowed unprivileged users to run their
  own WSGI applications, a local user could potentially use this to
  escalate privileges. Affected versions up to and including 3.4;
  fixed in 3.5.

* **CVE-2014-0242** — Content-Type response header memory reuse. In
  embedded mode, the response Content-Type header could be corrupted
  by a concurrent thread reusing memory that had been freed,
  potentially exposing data from other requests. Affected versions
  prior to 3.4; fixed in 3.4.

Linux distribution packages
---------------------------

The version of mod_wsgi shipped by your Linux distribution may lag
the current upstream release. The age and currency of the packaged
version varies by distribution and release; long-term-support
releases in particular can lag upstream by some time. Check what
version your distribution provides and, if security currency matters
for your deployment, weigh that against installing a more recent
version yourself either from source or via ``pip install mod_wsgi``.
