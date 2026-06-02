=====================
WSGIDontWriteBytecode
=====================

:Description: Disable writing of Python bytecode files.
:Syntax: ``WSGIDontWriteBytecode On|Off``
:Default: ``WSGIDontWriteBytecode Off``
:Context: server config

Controls whether Python writes ``.pyc`` bytecode files to disk when
modules are imported. This is the embedded equivalent of the ``-B``
command-line option to the ``python`` executable, or the
``PYTHONDONTWRITEBYTECODE`` environment variable.

By default Python writes bytecode files for any module imported
from a source file that doesn't already have a current cached
bytecode file. Setting this directive to ``On`` suppresses that
behaviour::

  WSGIDontWriteBytecode On

This is most often useful when the application directories are owned
by a user other than the one Apache runs as, and you want to avoid
``__pycache__`` directories being created with permissions tied to
the Apache user. It can also be used when application files live on
a read-only filesystem.

Note that disabling bytecode writes means each fresh process pays
the cost of recompiling Python source on first import, rather than
loading from cache.
