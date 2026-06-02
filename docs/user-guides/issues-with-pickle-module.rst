=========================
Issues With Pickle Module
=========================

This article describes various limitations on what data can be stored using
the "pickle" module from a WSGI application script file. This arises due
to the fact that a WSGI application script file is not treated exactly the
same as a standard Python module.

Note that these limitations only apply to the WSGI application script file
which is the target of the WSGIScriptAlias, AddHandler or Action
directives. Any standard Python modules or packages which make up an
application and which are being imported from directories located in
``sys.path`` using the 'import' statement are not affected.

Pickling And Script Reloading
-----------------------------

The first source of problems and limitations is how the operation of the
"pickle" serialisation routine is affected by the ability of mod_wsgi to
automatically reload WSGI application script files. The particular types
of data which are known to be affected are function objects, class
objects, and instances of classes.

To illustrate the problems and where they arise, consider the following
output from an interactive Python session::

    >>> import pickle
    >>> def a(): pass
    ...
    >>> pickle.dumps(a)
    b'...'
    >>> z = a
    >>> pickle.dumps(z)
    b'...'

As can be seen, it is possible to pickle a function object. This can be
done even through a copy of the function object by reference, although in
that case the pickled object still refers to the original function object.

If now the original function object is deleted however, and the copy of
the function object is pickled, a failure will occur::

    >>> del a
    >>> pickle.dumps(z)
    Traceback (most recent call last):
    ...
    _pickle.PicklingError: Can't pickle <function a at 0x...>: it's not found as __main__.a

The exception has been raised because the original function object was
deleted from where it was created. It occurs because the copy of the
original function object is still internally identified by the name which
it was assigned at the point of creation. The "pickle" serialisation
routine will check that the original object as identified by the name
still exists. If it doesn't exist, it will refuse to serialise the object.

Creating a new function object in place of the original function object
does not eliminate the problem, although it does result in a different
sort of exception::

    >>> def a(): pass
    ...
    >>> pickle.dumps(z)
    Traceback (most recent call last):
    ...
    _pickle.PicklingError: Can't pickle <function a at 0x...>: it's not the same object as __main__.a

In this case, the "pickle" serialisation routine recognises that "a"
exists but realises that it is actually a different function object from
which the "z" copy was originally made.

Where the problems start occurring with mod_wsgi is if the function
object being saved was itself a copy of some function object which is
held outside of the module the function object was defined in. If the
module holding the original function object was actually the WSGI
application script file and it was reloaded because of the automatic
script reloading mechanism, an attempt to pickle the object will fail.
This is because the original function object which had been copied from
will have been replaced by a new one when the script was reloaded.

The same problem occurs for class objects::

    >>> class B: pass
    ...
    >>> pickle.dumps(B)
    b'...'
    >>> C = B
    >>> pickle.dumps(C)
    b'...'
    >>> del B
    >>> pickle.dumps(C)
    Traceback (most recent call last):
    ...
    _pickle.PicklingError: Can't pickle <class '__main__.B'>: it's not found as __main__.B

It also occurs for instances of a class — pickling an instance validates
the class against the current value of its qualified name::

    >>> class B: pass
    ...
    >>> b = B()
    >>> pickle.dumps(b)
    b'...'
    >>> del B
    >>> pickle.dumps(b)
    Traceback (most recent call last):
    ...
    _pickle.PicklingError: Can't pickle <class '__main__.B'>: it's not found as __main__.B

Unpickling And Module Names
---------------------------

The second problem derives from how the mod_wsgi script loading
mechanism does not make use of the standard Python module importing
mechanism. This is necessary as the standard Python module importing
mechanism requires every loaded module to have a unique name, with each
module residing in ``sys.modules`` under that name. Further, that name
must be able to be used to import the module.

The mod_wsgi script loading mechanism does not place modules in
``sys.modules`` under their original name so as to allow multiple
modules with the same name in different directories and also to avoid
having to use the ".py" extension for script files.

The consequence is that function objects and class objects defined in
such a module may not be able to be converted back into objects from
their serialised form. When ``pickle`` encounters a name from a module
that is not already in ``sys.modules``, it will try to import it; for a
WSGI application script file there is no importable module to find.

The problem can be seen in the following output from an interactive
Python session::

    >>> import sys, types, pickle
    >>> m = types.ModuleType('m')
    >>> sys.modules['m'] = m
    >>> exec("class C: pass", m.__dict__)
    >>> c = m.C()
    >>> data = pickle.dumps(c)
    >>> pickle.loads(data)
    <m.C object at 0x...>
    >>> del sys.modules['m']
    >>> pickle.loads(data)
    Traceback (most recent call last):
    ...
    ModuleNotFoundError: No module named 'm'

Summary Of Limitations
----------------------

Although the first problem described above could be avoided by disabling
script reloading, there is no way to work around the second problem
resulting from how mod_wsgi names modules when stored in ``sys.modules``.

In practice, what this means is that neither function objects, class
objects or instances of classes which are defined in a WSGI application
script file should be stored using the "pickle" module.

In order to ensure that no strange problems at all are likely to occur,
it is suggested that only basic builtin Python types, ie., scalars,
tuples, lists and dictionaries, be stored using the "pickle" module from
a WSGI application script file. That is, avoid any type of object which
has user defined code associated with it.

Note that this limitation only applies to the WSGI application script
file, it doesn't apply to normal Python modules imported using the
Python "import" statement.
