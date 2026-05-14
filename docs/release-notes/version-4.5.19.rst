:orphan:

==============
Version 4.5.19
==============

Features Changed
----------------

* When using the Django management command integration of
  ``mod_wsgi-express``, allow the ``--working-directory`` option to
  override the calculated directory. This is necessary to cope with
  where the meaning of ``BASE_DIR`` in the Django settings file has been
  changed from the accepted convention of it being the parent directory
  of the Django project.
