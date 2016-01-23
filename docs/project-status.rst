==============
Project Status
==============

The mod_wsgi project is still being developed and maintained. The available
time of the sole developer is however limited. As a result, progress may
appear to be slow.

In general, the documentation is in a bit of a mess right now and somewhat
outdated, so if you can't find something then ask on the mod_wsgi mailing
list for help. Also check out the :doc:`release-notes` as they at least are
being updated.

A lot of the more recent changes are being made with the aim of making it a
lot easier to deploy Apache with mod_wsgi in Docker based environments.
Changes included the ability to install mod_wsgi using ``pip``, along with
an admin command called ``mod_wsgi-express`` which provides a really simple
way of starting up Apache and mod_wsgi from the command line with an
automatically generated configuration.
