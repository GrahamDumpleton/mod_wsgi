==================
WSGIPythonWarnings
==================

:Description: Add an entry to the Python warnings filter.
:Syntax: ``WSGIPythonWarnings`` *spec*
:Context: server config

Adds an entry to the Python warnings filter. This is the embedded
equivalent of the ``-W`` command-line option to the ``python``
executable, or one entry of the ``PYTHONWARNINGS`` environment
variable.

The argument is a single warning filter specification using the
standard Python ``-W`` syntax::

  action:message:category:module:lineno

Each field is optional. The most common form supplies only the
action, which is one of ``default``, ``error``, ``always``,
``module``, ``once`` or ``ignore``.

For example, to turn all warnings into errors::

  WSGIPythonWarnings error

Or to silence ``DeprecationWarning`` from a specific module::

  WSGIPythonWarnings ignore::DeprecationWarning:somepackage.legacy

The directive may be specified multiple times. Each occurrence
appends a further entry to the warnings filter. Filters are applied
in the order they appear in the configuration.

When configuring via ``mod_wsgi-express``, the ``--python-warnings``
option emits one ``WSGIPythonWarnings`` directive per occurrence in
the generated configuration. It may be repeated to install multiple
filter entries, mirroring the directive's append semantics.

See the Python documentation on the warnings module and the ``-W``
option for details on filter precedence and matching.
