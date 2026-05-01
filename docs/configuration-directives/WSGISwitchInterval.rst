==================
WSGISwitchInterval
==================

:Description: Override the Python GIL switch interval (``sys.setswitchinterval``).
:Syntax: ``WSGISwitchInterval`` *seconds*
:Default: *Python's built-in default* (``0.005`` = 5 ms in CPython 3.2+)
:Context: server config

Sets the Python interpreter's GIL switch interval at process start by
calling ``sys.setswitchinterval()`` once after the interpreter has been
initialised. The argument is the same form ``sys.setswitchinterval()``
accepts — a positive number of seconds expressed as a float. The
interval controls how often the thread holding the GIL checks whether
to release it for another waiting thread.

For example, to set the interval to 2 ms::

  WSGISwitchInterval 0.002

When the directive applies the value, mod_wsgi emits an INFO entry to
the Apache error log naming the value that was set.

This directive only affects the embedded interpreter created in Apache
child processes when embedded mode is used. To set the switch interval
for interpreters running in daemon processes, use the
:ref:`switch-interval <switch-interval>` option to the
:doc:`WSGIDaemonProcess` directive instead. Different daemon groups
can run with different intervals by setting the option differently on
each ``WSGIDaemonProcess`` directive.

For most modern deployments, daemon mode is the preferred deployment
method, in which case configure the switch interval via
``WSGIDaemonProcess`` rather than this directive.
