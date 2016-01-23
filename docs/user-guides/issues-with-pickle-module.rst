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

Packing And Script Reloading
----------------------------

The first source of problems and limitations is how the operation of the
"pickle" serialisation routine is affected by the ability of mod_wsgi to
automatically reload WSGI application script files. The particular types of
data which are known to be affected are function objects and class objects.

To illustrate the problems and where they arise, consider the following
output from an interactive Python session::

    >>> import pickle
    >>> def a(): pass
    ... 
    >>> pickle.dumps(a)
    'c__main__\na\np0\n.'
    >>> z = a
    >>> pickle.dumps(z)
    'c__main__\na\np0\n.'

As can be seen, it is possible to pickle a function object. This can be
done even through a copy of the function object by reference, although in
that case the pickled object still refers to the original function object.

If now the original function object is deleted however, and the copy of the
function object is pickled, a failure will occur::

    >>> del a
    >>> pickle.dumps(z)
    Traceback (most recent call last):
    ... <deleted>
    pickle.PicklingError: Can't pickle <function a at 0x612b0>: it's not found as __main__.a

The exception has been raised because the original function object was
deleted from where it was created. It occurs because the copy of the
original function object is still internally identified by the name which
it was assigned at the point of creation. The "pickle" serialisation
routine will check that the original object as identified by the name still
exists. If it doesn't exist, it will refuse to serialise the object.

Creating a new function object in place of the original function object
does not eliminate the problem, although it does result in a different sort
of exception::

    >>> def a(): pass
    ... 
    >>> pickle.dumps(z)
    Traceback (most recent call last):
    ... <deleted>
    pickle.PicklingError: Can't pickle <function a at 0x612b0>: it's not the same object as __main__.a

In this case, the "pickle" serialisation routine recognises that "a" exists
but realises that it is actually a different function object from which the
"z" copy was originally made.

Where the problems start occuring with mod_wsgi is if the function object
being saved was itself a copy of some function object which is held outside
of the module the function object was defined in. If the module holding the
original function object was actually the WSGI application script file and
it was reloaded because of the automatic script reloading mechanism, an
attempt to pickle the object will fail. This is because the original
function object which had been copied from will have been replaced by a new
one when the script was reloaded.

This sort of problem, although it will not occur for an instance of a
class, will occur for the class object itself::

    >>> class B: pass
    ... 
    >>> b=B()
    >>> pickle.dumps(b)
    '(i__main__\nB\np0\n(dp1\nb.'
    >>> del B
    >>> pickle.dumps(b)
    '(i__main__\nB\np0\n(dp1\nb.'
    >>> class B: pass
    ... 
    >>> pickle.dumps(B)
    'c__main__\nB\np0\n.'
    >>> C = B
    >>> pickle.dumps(C)
    'c__main__\nB\np0\n.'
    >>> del B
    >>> pickle.dumps(C)
    Traceback (most recent call last):
    ... <deleted>
    pickle.PicklingError: Can't pickle <class __main__.B at 0x53ab0>: it's not found as __main__.B

Note though that for the case of a class instance, an appropriate class
object must exist at the same location when the serialised object is being
restored::

    >>> class B: pass
    ... 
    >>> b = B()
    >>> pickle.loads(pickle.dumps(b))
    <__main__.B instance at 0x41e40>
    >>> del B
    >>> pickle.loads(pickle.dumps(b))
    Traceback (most recent call last):
    ... <delete>
    AttributeError: 'module' object has no attribute 'B'

Unpacking And Module Names
--------------------------

The second problem derives from how the mod_wsgi script loading mechanism
does not make use of the standard Python module importing mechanism. This
is necessary as the standard Python module importing mechanism requires
every loaded module to have a unique name, with each module residing in
``sys.modules`` under that name. Further, that name must be able to be
used to import the module.

The mod_wsgi script loading mechanism does not place modules in
``sys.modules`` under their original name so as to allow multiple modules
with the same name in different directories and also to avoid having to use
the ".py" extension for script files.

The consequence though of modules not residing in ``sys.modules`` under
their original name is that function objects and class objects within such
a module may not be able to converted back into objects from their
serialised form. This is because "pickle" when attempting to import a
module automatically if the module isn't already loaded will not be
able to load the WSGI application script file.

The problem can be seen in the following output from an interactive Python
session::

    >>> exec "class C: pass" in m.__dict__
    >>> c = m.C()
    >>> pickle.dumps(c)
    '(im\nC\np0\n(dp1\nb.'
    >>> pickle.loads(pickle.dumps(c))
    <m.C instance at 0x9a0d0>
    >>> del sys.modules["m"]
    >>> pickle.loads(pickle.dumps(c))
    Traceback (most recent call last):
    ... <deleted>
    ImportError: No module named m

Summary Of Limitations
----------------------

Although the first problem described above could be avoided by disabling
script reloading, there is no way to work around the second problem
resulting from how mod_wsgi names modules when stored in ``sys.modules``.

In practice, what this means is that neither function objects, class
objects or instances of classes which are defined in a WSGI application
script file should be stored using the "pickle" module.

In order to ensure that no strange problems at all are likely to occur, it
is suggested that only basic builtin Python types, ie., scalars, tuples,
lists and dictionaries, be stored using the "pickle" module from a WSGI
application script file. That is, avoid any type of object which has user
defined code associated with it.

Note that this limitation only applies to the WSGI application script file,
it doesn't apply to normal Python modules imported using the Python "import"
statement.
