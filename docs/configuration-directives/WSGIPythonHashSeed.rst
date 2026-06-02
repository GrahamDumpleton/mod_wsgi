==================
WSGIPythonHashSeed
==================

:Description: Set the seed used for Python hash randomisation.
:Syntax: ``WSGIPythonHashSeed`` *random|0..4294967295*
:Default: ``WSGIPythonHashSeed random``
:Context: server config

Sets the seed value used by Python for hash randomisation. This is
the embedded equivalent of the ``-R`` command-line option to the
``python`` executable, or the ``PYTHONHASHSEED`` environment variable.

The argument must be either ``random``, in which case Python chooses
a random seed value at startup, or an unsigned integer in the range
0 to 4294967295 (i.e. ``2**32 - 1``).

For example, to make hash output deterministic::

  WSGIPythonHashSeed 0

Or to explicitly request randomised hashing (the modern Python
default)::

  WSGIPythonHashSeed random

Hash randomisation affects the iteration order of objects such as
``dict``, ``set`` and ``frozenset`` when they are keyed by strings
or bytes. Setting a fixed seed can be useful for reproducing
ordering-dependent test failures, but is generally not needed for
production deployments.
