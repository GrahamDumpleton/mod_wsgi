==============
Project Status
==============

No mod_wsgi is not dead, it was just resting.

Development work on mod_wsgi did effectively stop there for a few years
due to developer burnout and the fact that the project has a bus factor
of one. Renewed development did however restart early 2014, with a
considerable amount of new development work and fixes being performed
since then.

A lot of the changes being made were with the aim of making it a lot easier
to deploy Apache with mod_wsgi in Docker based environments. Changes
included the ability to install mod_wsgi using ``pip``, along with an
admin command called ``mod_wsgi-express`` which provides a really simple
way of starting up Apache and mod_wsgi from the command line with an
automatically generated configuration.

Completely revised documentation will eventually be incorporated here. To
date though it has been seen as being a bit pointless spending huge amounts
of time documenting all the new features given that Linux distributions
have historically tended to supply quite old versions of mod_wsgi anyway.
Most users tend to outright refuse to build mod_wsgi from source code
themselves and so are stuck with the much older versions their Linux
distribution provides.

In the mean time keep referring to the older documentation located on
the Google Code site at:

    https://code.google.com/p/modwsgi/wiki/WhereToGetHelp

The full documentation index on the Google Code site can be found at:

    http://code.google.com/p/modwsgi/w/list

Documentation for the new ``mod_wsgi-express`` feature will not be found
on the Google Code site, but is documented in the PyPi entry for mod_wsgi
at:

   https://pypi.python.org/pypi/mod_wsgi
