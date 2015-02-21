.. image:: dead-parrot.jpg
   :width: 250 px
   :align: right

.. toctree::
   :maxdepth: 1
   :hidden:

   release-notes/index

mod_wsgi
========

The mod_wsgi package implements a simple to use Apache module which can
host any Python application which supports the Python WSGI_ interface.

.. _WSGI: http://www.python.org/dev/peps/pep-0333/

Status
======

No mod_wsgi is not dead, it was just resting.

Renewed development on mod_wsgi began early 2014, with a considerable
amount of new development work and fixes being performed. This included the
ability to install mod_wsgi using 'pip', along with an admin command
called ``mod_wsgi-express`` which provides a really simple way of starting
up Apache/mod_wsgi with an automatically generated configuration.

Completely revised documentation will eventually be incorporated here.
Right now though I am having too much fun working on all the new features.

In the mean time keep referring to the older documentation at:

    http://www.modwsgi.org/

The new ``mod_wsgi-express`` feature is also documented in the PyPi
entry for mod_wsgi at:

   http://pypi.python.org/pypi/mod_wsgi 

Due to security issues in versions of mod_wsgi up to and including
version 3.4, it is recommended that version 3.5 or later be used.

If you need help in using mod_wsgi, then use the mod_wsgi mailing list to
ask your questions:

    http://groups.google.com/group/modwsgi
