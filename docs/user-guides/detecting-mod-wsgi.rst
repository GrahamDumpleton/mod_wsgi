=============================
Detecting mod_wsgi at Runtime
=============================

As a WSGI application developer you should always be striving to write
portable WSGI applications. That is, you should not write your code so as
to be dependent on the specific features of a specific WSGI hosting
mechanism.

This unfortunately is not always possible especially when it comes to
deployment due to there being no one blessed way for exposing a WSGI
application for hooking into WSGI hosting mechanisms. There may also be
times when you might want to rely on a feature of a specific WSGI hosting
mechanism, which although not part of the WSGI specification, allows you
to do something you wouldn't otherwise.

That said, there are a few ways in which you can detect that your code is
running under mod_wsgi. These fall under two categories. The first being
a general mechanism for how to detect if mod_wsgi is being used. The
second being additional ways to detect that mod_wsgi is being used when a
request is being handled.

When mod_wsgi loads a WSGI application under Apache, it inserts a built-in
``mod_wsgi`` module into ``sys.modules`` which exposes mod_wsgi-specific
attributes such as ``version``.

A bare ``import mod_wsgi`` is not a reliable test on its own, because the
mod_wsgi project is also distributed as a Python package on PyPI (which
provides the ``mod_wsgi-express`` tooling). With that package installed,
``import mod_wsgi`` succeeds in any Python process even outside of Apache.

A reliable check is to import an attribute that is only set when running
under Apache::

    try:
        from mod_wsgi import version
        # Put code here which should only run when mod_wsgi is being used.
    except ImportError:
        pass

The ``version`` attribute is supplied by the built-in module that
Apache/mod_wsgi inserts into ``sys.modules`` and reports the version of
``mod_wsgi.so`` loaded into Apache.

The above import check can be used anywhere, be that in the WSGI script file,
or in your application code at either global scope or within the context of
a specific function.

In the specific case of the WSGI script file, although the above can be
used there is an alternate check that can be made. That is to check the
value of the '__name__' attribute given to the WSGI script file when the
code is loaded into the Python interpreter.

The normal situation where one would check the value of '__name__' is where
wanting to do something different when a Python code file is executed
directly against the Python interpreter as opposed to being imported. For
example::

    if __name__ == '__main__':
        ...

In contrast, where a Python code file is imported, the '__name__' attribute
would be the dotted path which would be used to import the code file.

In the case of mod_wsgi, although WSGI script files are imported as if they
are a module, because they could exist anywhere and not in locations on
the Python module search path, they don't have a conventional dotted path
name. Instead they have a magic name built from a md5 hash of the path to the
WSGI script file.

So as to at least identify this as being related to mod_wsgi, it has the
prefix '_mod_wsgi_'. This means a WSGI script file could use::

    if __name__.startswith('_mod_wsgi_'):
        ...

if it needed to execute different code based on whether the WSGI script
file was actually being loaded by the Apache/mod_wsgi module as opposed to
be executed directly as a script by the command line Python interpreter.

This latter technique obviously only works in the WSGI script file and not
elsewhere.

A final method that can be used within the context of the WSGI application
handling the request is to interrogate the WSGI environ dictionary passed
to the WSGI application. In this case code can look for the presence of
the 'mod_wsgi.version' key within the WSGI environ dictionary::

    def application(environ, start_response):
        status = '200 OK'
        if 'mod_wsgi.version' in environ:
            output = b'Hello mod_wsgi!'
        else:
            output = b'Hello other WSGI hosting mechanism!'

        response_headers = [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        return [output]
