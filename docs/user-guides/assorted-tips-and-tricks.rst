========================
Assorted Tips And Tricks
========================

This document contains various tips and tricks related to using mod_wsgi
which don't deserve a document of their own or which don't fit within other
documentation.

Determining If Running Under mod_wsgi
-------------------------------------

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

That said, there a few ways in which you can detect that your code is
running under mod_wsgi. These fall under two categories. The first being
a general mechanism for how to detect if mod_wsgi is being used. The
second being additional ways to detect that mod_wsgi is being used when a
request is being handled.

The simplest way of detecting if mod_wsgi is being used is to import the
'mod_wsgi' module. This is a special embedded mode which is installed
automatically by the Apache/mod_wsgi module into set of imported modules,
ie., sys.modules. You can thus do::

    try:
        import mod_wsgi
        # Put code here which should only run when mod_wsgi is being used.
    except:
        pass

Do note however that although this is an embedded mode added automatically,
the way mod_wsgi has been implemented allows in the future for there to be
a separate Python package/module distinct from the mod_wsgi.so file called
'mod_wsgi' which might contain additional Python code to support use of
mod_wsgi.

What would happen if such a separate Python package/module is available is
that it will be automatically imported and additional information setup by
the Apache/mod_wsgi module then inserted into the global namespace of that
Python package/module.

The potential existance of this distinct Python package/module means that
importing 'mod_wsgi' could one day actually succeed outside of code being
run under the Apache/mod_wsgi module.

A more correct test therefore is::

    try:
        from mod_wsgi import version
        # Put code here which should only run when mod_wsgi is being used.
    except:
        pass

This is different because the 'version' attribute will only be present when
running under the Apache/mod_wsgi module as that version relates to the
version of mod_wsgi.so.

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

In contrast, were a Python code file is imported, the '__name__' attribute
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
        if environ.has_key('mod_wsgi.version'):
            output = b'Hello mod_wsgi!'
        else:
            output = b'Hello other WSGI hosting mechanism!'

        response_headers = [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        return [output]
