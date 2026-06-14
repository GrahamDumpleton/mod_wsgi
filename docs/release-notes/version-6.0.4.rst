=============
Version 6.0.4
=============

Bugs Fixed
----------

* The Django ``runmodwsgi`` management command was broken and would fail
  immediately with ``AttributeError: module 'mod_wsgi.express' has no
  attribute 'options'``. The command referenced the ``mod_wsgi.express.options``
  and ``mod_wsgi.express.server`` submodules without importing them. As Django
  builds the argument parser on every invocation, this affected all uses of the
  command and not just ``runmodwsgi --help``.

* The Django ``runmodwsgi`` management command failed with ``ValueError:
  unsupported format character`` when displaying help. The optparse option
  help text is now escaped and translated correctly when it is converted to
  the argparse form Django requires, so literal ``%`` characters such as the
  ``%{GLOBAL}`` token and the ``%default`` token are handled properly.

* The Django ``runmodwsgi`` management command raised ``NameError: name
  'value' is not defined`` when validating percentage style options such as
  ``--initial-workers``. The value is now parsed and range checked correctly.
