===============
Troubleshooting
===============

If mod_wsgi is not behaving as expected, start with the relevant
"issues" guide based on where the problem is:

* :doc:`user-guides/installation-issues` — building and loading
  the mod_wsgi module.
* :doc:`user-guides/configuration-issues` — Apache configuration
  for mod_wsgi.
* :doc:`user-guides/application-issues` — running the WSGI
  application once mod_wsgi is loaded.

If you have a specific ``WSGI####`` error code in the Apache error
log, look it up in :doc:`error-reference` for the cause and any
recommended action.

Additional pages that may help:

* :doc:`user-guides/checking-your-installation` — sanity checks
  for an Apache plus mod_wsgi setup.
* :doc:`user-guides/debugging-techniques` — running Apache in the
  foreground, inspecting daemon processes, and other diagnostic
  approaches.
* :doc:`user-guides/frequently-asked-questions` — common questions
  and gotchas.
* :doc:`known-issues` — confirmed defects and accepted limitations
  in mod_wsgi itself, where the problem is not in your install,
  configuration, or application.

If none of these resolve the issue, see :doc:`finding-help` for
where to ask.
