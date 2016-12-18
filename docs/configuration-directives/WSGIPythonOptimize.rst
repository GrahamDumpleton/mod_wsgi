==================
WSGIPythonOptimize
==================

:Description: Enables basic Python optimisation features.
:Syntax: ``WSGIPythonOptimize [0|1|2]``
:Default: ``WSGIPythonOptimize 0``
:Context: server config

Sets the level of Python compiler optimisations. The default is '0' which
means no optimisations are applied.

Setting the optimisation level to '1' or above will have the effect of
enabling basic Python optimisations and changes the filename extension for
compiled (bytecode) files from ``.pyc`` to ``.pyo``.

On the Windows platform, optimisation level of '0' apparently results in
the same outcome as if the optimisation level had been set to '1'.

When the optimisation level is set to '2', doc strings will not be
generated and thus not retained. This may techically result in a smaller
memory footprint if all ``.pyo`` files were compiled at this optimisation
level, but may cause some Python packages which interrogate doc strings in
some way to fail.

Since all the installed ``.pyo`` files in your Python installation are
not likely to be installed with level '2' optimisation, the gain from using
this level of optimisation will probably be negligible if any. This is
because potentially only the Python code for your own application code will
be compiled with this level of optimisation. This will be the case as the
``.pyo`` files will aready exist for modules in the standard Python
library and they will be used as is, rather than them being regenerated
with a higher level of optimisation than they might be. Use of level '2'
optimisation is therefore discouraged.

This directive will have no affect if mod_python is being loaded into Apache
at the same time as mod_wsgi as mod_python will in that case be responsible
for initialising Python.

Overall, if you do not understand what the normal 'python' executable ``-O``
option does, how the Python runtime changes it behaviour as a result, and
you don't know exactly how your application would be affected by enabling
this option, then do not use this option. In other words, stop trying to
prematurely optimise the performance of your application through shortcuts.
You will get much better performance gains by looking at the design of your
application and eliminating bottlenecks within it and how it uses any
database. So, put the gun down and back away, it will be better for all
concerned.

