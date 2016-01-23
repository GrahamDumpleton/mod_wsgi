===================
WSGIAuthGroupScript
===================

:Description: Specify script implementing group authorisation.
:Syntax: ``WSGIAuthGroupScript`` *path* [ *options* ]
:Context: directory, .htaccess
:Override: AuthConfig

The ``WSGIAuthGroupScript`` directive provides a mechanism for implementing
group authorisation using the Apache ``Require`` directive.

More detailed information on using the ``WSGIAuthGroupScript`` directive
can be found in :doc:`../user-guides/access-control-mechanisms`.

The options which can be supplied to the ``WSGIAuthGroupScript`` directive are:

**application-group=name**

    Specifies the name of the application group within the specified
    process for which the script file will be loaded.

    If the ``application-group`` option is not supplied, the special value
    ``%{GLOBAL}`` which denotes that the script file be loaded within the
    context of the first interpreter created by Python when it is
    initialised will be used. Otherwise, will be loaded into the
    interpreter for the specified application group.

Note that the script always runs in processes associated with embedded
mode. It is not possible to delegate the script such that it is run within
context of a daemon process.
