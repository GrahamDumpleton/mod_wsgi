===========
Version 3.4
===========

Version 3.4 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-3.4.tar.gz

Security Issues
---------------

1. Information disclosure via Content-Type response header. (CVE-2014-0242)

The issue was identified and fixed in version 3.4 (August 2012) of mod_wsgi
and is listed below at item 7 under 'Bugs Fixed'.

  Response Content-Type header could be corrupted when being sent in
  multithreaded configuration and embedded mode being used. Problem thus
  affected Windows and worker MPM on UNIX.

At the time it was believed to be relatively benign, only ever having been
seen with one specific web application (Trac - http://trac.edgewall.org),
with the corrupted value always appearing to be replaced with a small set
of known values which themselves did not raise concerns.

A new example of this problem was identified May 2014 which opens this
issue up as being able to cause arbitrary corruption of the web server HTTP
response Content-Type value, resulting in possible exposure of data from
the hosted web application to a HTTP client.

The new example also opens the possibility that the issue can occur with
any Apache MPM and not just multithreaded MPMs as previously identified.
Albeit that it still requires some form of background application threads
to be in use, when a single threaded Apache MPM is being used.

In either case, it is still however restricted to the case where embedded
mode of mod_wsgi is being used.

The specific scenario which can trigger the issue is where the value for
the Content-Type response header is dynamically generated, and where the
stack frame where the calculation was done went out of use between the time
that the WSGI start_response() function was called and the first non empty
byte string was yielded from the WSGI application for the response,
resulting in the Python object being destroyed and memory returned to the
free list.

At the same time, it would have been necessary for a parallel request
thread or an application background thread to execute during that window of
time and perform sufficient object allocations so as to reuse the memory
previously used by the value of the Content-Type response header.

Example code which can be used to trigger the specific scenario can be
found at:

  https://gist.github.com/GrahamDumpleton/14b31ebe18166a89b090

That example code also provides a workaround if you find yourself affected
by the issue but cannot upgrade straight away. It consists of the
@intern_content_type decorator/wrapper. This can be applied to the WSGI
application entry point and will use a cache to store the value of the
Content-Type response header to ensure it is persistent for the life of the
request.

Bugs Fixed
----------

1. If using write() function returned by start_response() and a non string
value is passed to it, then process can crash due to errors in Python object
reference counting in error path of code.

2. If using write() function returned by start_response() under Python 3.X
and a Unicode string is passed to it rather than a byte string, then a
memory leak will occur because of errors in Python object reference
counting.

3. Debug level log message about mismatch in content length generated was
generated when content returned less than that specified by Content-Length
response header even when exception occurring during response generation
from an iterator. In the case of an exception occuring, was only meant to
generate the log message if more content returned than defined by the
Content-Length response header.

4. Using writelines() on wsgi.errors was failing.

5. If a UNIX signal received by daemon mode process while still being
initialised to signal that it should be shutdown, the process could crash
rather than shutdown properly due to not registering the signal pipe
prior to registering signal handler.

6. Python doesn't initialise codecs in sub interpreters automatically which
in some cases could cause code running in WSGI script to fail due to lack
of encoding for Unicode strings when converting them. The error message
in this case was::

    LookupError: no codec search functions registered: can't find encoding

The 'ascii' encoding is now forcibly loaded when initialising sub interpreters
to get Python to initialise codecs.

7. Response Content-Type header could be corrupted when being sent in
multithreaded configuration and embedded mode being used. Problem thus
affected Windows and worker MPM on UNIX.

Features Changed
----------------

1. The HTTPS variable is no longer set within the WSGI environment. The
authoritative indicator of whether a SSL connection is used is
wsgi.url_scheme and a WSGI compliant application should check for
wsgi.url_scheme. The only reason that HTTPS was supplied at all was because
early Django versions supporting WSGI interface weren't correctly using
wsgi.url_scheme. Instead they were expecting to see HTTPS to exist.

This change will cause non conformant WSGI applications to finally break.
This possibly includes some Django versions prior to Django version 1.0.

Note that you can still set HTTPS in Apache configuration using the !SetEnv
or !SetEnvIf directive, or via a rewrite rule. In that case, that will
override what wsgi.url_scheme is set to and once wsgi.url_scheme is set
appropriately, the HTTPS variable will be removed from the set of variables
passed through to the WSGI environment.

2. The wsgi.version variable has been reverted to 1.0 to conform to the
WSGI PEP 3333 specification. It was originally set to 1.1 on expectation
that revised specification would use 1.1 but that didn't come to be.

3. Use of kernel sendfile() function by wsgi.file_wrapper is now off by
default. This was originally always on for embedded mode and completely
disabled for daemon mode. Use of this feature can be enabled for either
mode using WSGIEnableSendfile directive, setting it to On to enable it.

The default is now off because kernel sendfile() is not always able to work
on all file objects. Some instances where it will not work are described
for the Apache !EnableSendfile directive.

  http://httpd.apache.org/docs/2.2/mod/core.html#enablesendfile

Although Apache has use of sendfile() enabled by default for static files,
they are moving to having it off by default in future version of Apache.
This change is being made because of the problems which arise and users not
knowing how to debug it and solve it.

Thus also erring on side of caution and having it off by default but
allowing more knowledgeable users to enable it where they know always using
file objects which will work with sendfile().

New Features
------------

1. Support use of Python 3.2.

2. Support use of Apache 2.4.

3. Is now guaranteed that mod_ssl access handler is run before that for
mod_wsgi so that any per request variables setup by mod_ssl are available
in the mod_wsgi access handler as implemented by WSGIAccessScript
directive.

4. Added 'python-home' option to WSGIDaemonProcess allowing a Python virtual
environment to be used directly in conjunction with daemon process. Note that
this option does not do anything if setting WSGILazyInitialization to 'Off'.

5. Added 'lang' and 'locale' options to WSGIDaemonProcess to perform same
tasks as setting 'LANG' and 'LC_ALL environment' variables. Note that if
needing to do the same for embedded mode you still need to set the
environment variables in the Apache envvars file or init.d startup scripts.

6. Split combined WWW-Authenticate header returned from daemon process back
into separate headers. This is work around for some browsers which require
separate headers when multiple authentication providers exist.

7. For Python 2.6 and above, the WSGIDontWriteBytecode directive can be used
at global scope in Apache configuration to disable writing of all byte code
files, ie., .pyc, by the Python interpreter when it imports Python code files.
To disable writing of byte code files, set directive to 'On'.

Note that this doesn't prevent existing byte code files on disk being used
in preference to the corresponding Python code files. Thus you should first
remove .pyc files from web application directories if relying on this
option to ensure that .py file is always used.

8. Add supplementary-groups option to WSGIDaemonProcess to allow group
membership to be overridden and specified comma separated list of groups
to be used instead.

9. Add 'memory-limit' option to WSGIDaemonProcess to allow memory usage of
daemon processes to be restricted. This will have no affect on some
platforms as RLIMIT_AS/RLIMIT_DATA with setrlimit() isn't always
implemented. For example MacOS X and older Linux kernel versions do not
implement this feature. You will need to test whether this feature works
or not before depending on it.

10. Add 'virtual-memory-limit' option to WSGIDaemonProcess to allow virtual
memory usage of daemon processes to be restricted. This will have no affect
on some platforms as RLIMIT_VMEM with setrlimit() isn't always implemented.
You will need to test whether this feature works or not before depending on
it.

11. Access, authentication and authorisation hooks now have additional keys
in the environ dictionary for 'mod_ssl.is_https' and 'mod_ssl.var_lookup'.
These equate to callable functions provided by mod_ssl for determining if
the client connection to Apache used SSL and what the values of variables
specified in the SSL certifcates, server or client, are. These are only
available if Apache 2.0 or later is being used.

12. Add 'mod_wsgi.queue_start' attribute to WSGI environ so tools like
New Relic can use it to track request queueing time. This is the time between
when request accepted by Apache and when handled by WSGI application.

