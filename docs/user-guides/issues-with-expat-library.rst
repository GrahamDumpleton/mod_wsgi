=========================
Issues With Expat Library
=========================

This article describes problems caused due to mismatches in the version of
the "expat" library embedded into Python and that linked into Apache. Where
incompatible versions are used, Apache can crash as soon as any Python code
module imports the "pyexpat" module.

Note that this only applies to Python versions prior to Python 2.5. From
Python 2.5 onwards, the copy of the "expat" library bundled in with Python
is name space prefixed, thereby avoid name clashes with an "expat" library
which has previously been loaded.

The Dreaded Segmentation Fault
------------------------------

When moving beyond creating simple WSGI applications to more complicated
tasks, one can unexpectedly be confronted with Apache crashing. This
generally manifests in no response being returned to the browser when a
request is made. Upon further investigation of the Apache error log file, a
message similar to the following message is found::

    [notice] child pid 3238 exit signal Segmentation fault (11)

The change which causes this is the explicit addition of code to import the
Python module "pyexpat", or the importing of any Python module which
indirectly makes use of the "pyexpat" module. Examples of other modules
which make use of the "pyexpat" module are "xmlrpclib" and modules from the
"PyXML" package. Nearly always, any module which in some way performs
processing of XML data will be affected as most such modules rely on using
the "pyexpat" module in some way.

Verifying Expat Is The Problem
------------------------------

To verify that the "pyexpat" module is the trigger for the problem,
construct a simple WSGI application script file containing::

    def application(environ, start_response):
        status = '200 OK'
        output = 'without expat\n' 

        response_headers = [('Content-type', 'text/plain'), 
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        return [output]

Verify that this handler works and the browser receives the response
"without pyepxat". Now modify the handler such that the "pyexpat" module is
being imported. Also change the response so that it is clear that the
modified handler is being used::

    import pyexpat

    def application(environ, start_response):
        status = '200 OK'
        output = 'with expat\n' 

        response_headers = [('Content-type', 'text/plain'), 
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        return [output]

Presuming that script reloading is enabled, if now upon a request being
received by the WSGI application a succesful response of "with pyexpat" is
received by the browser, it would generally indicate that the "pyexpat"
module is not the problem after all. If however no response is received and
the Apache error log records a "Segmentation fault" then the "pyexpat"
module is the trigger.

Mismatch In Versions Of Expat
-----------------------------

Segmentation faults can occur with any application where different
components of the application were compiled against different versions of a
common library such as the "expat" library. The actual cause of the problem
is generally a change in the API of the library, such as changed function
prototypes, changed data types, or changes in structure layouts. In the
case where mod_wsgi is being used, the different components are Apache
and the "pyexpat" module from Python.

Normally when different components of an application are built, they would
be built against the same version of the library and such problems would
not occur. In the case of the "pyexpat" module however, it is compiled
against a distinct version of the "expat" library which is then embedded
within the "pyexpat" module. At the same time, Apache will be built against
the version of the "expat" library included with the operating system, or
if not a standard part of the operating system, a version which is supplied
with Apache.

Thus if the version of the "expat" library embedded into the "pyexpat"
module is different to that which Apache was compiled against, the
potential for this problem will exist. Note though that there may not
always be a problem. Whether there is or not will ultimately depend on what
changes were made in the "expat" library between the releases of the
different versions used. It is also possible how each library version was
compiled could be a factor.

Expat Version Used By Apache
----------------------------

To determine the version of the the "expat" library which is used by
Apache, on Linux the "ldd" command can be used. Other operating systems
also provide this program or will generally have some form of equivalent
program. For example, on Mac OS X the command which is run is "otool -L".

The purpose of these programs is to generate a list of all shared libraries
that an application is linked against. To determine where the "expat"
library being used by Apache is located, it is necessary to run the "ldd"
program on the "httpd" program. On a Linux system, the "httpd" program is
normally located in "/usr/sbin". Because we are only interested in the
"expat" library, we can ignore anything but the reference to that library::

    [grahamd@dscpl grahamd]$ ldd /usr/sbin/httpd | grep expat
            libexpat.so.0 => /usr/lib/libexpat.so.0 (0xb7e8c000)

From this output it can be seen that the "httpd" program appears to be
using "/usr/lib/libexpat.so.0". Although some operating systems embed in
the name of the shared library versioning information, it does not
generally indicate the true version of the code base which made up the
library. To obtain this, it is necessary to extract the version information
out of the library. For the "expat" library this can be determined by
searching within the strings contained in the library for a version string
starting with ``expat_``::

    [grahamd@dscpl grahamd]$ strings /usr/lib/libexpat.so.0 | grep expat_
    expat_1.95.8

The version of the "expat" library would therefore appear to be "1.95.8".
Unfortunately though, many operating systems allow the library search path
to be overridden at the point that a program is run using an environment
variable such as "LD_LIBRARY_PATH" and it is quite possible that when
Apache is run, the context in which it is run could result in it finding
the "expat" library in a different location.

To be absolutely sure, it is necessary to determine which "expat" library
the running copy of Apache used. On Linux and many other operating systems,
this can be determined using the "lsof" command. If this program doesn't
exist, an alternate program which may be available is "ofiles". Either of
these should be run against one of the active Apache processes. If Apache
was originally started as root, the command will also need to be run as
root::

    [grahamd@dscpl grahamd]$ ps aux | grep http | head -3
    root      3625  0.0  0.6 31068 12836 ?       SN   Sep25   0:08 /usr/sbin/httpd
    apache   24814  0.0  0.7 34196 15604 ?       SN   04:11   0:00 /usr/sbin/httpd
    apache   24815  0.0  0.7 33924 15916 ?       SN   04:11   0:00 /usr/sbin/httpd

    [grahamd@dscpl grahamd]$ sudo /usr/sbin/lsof -p 3625 | grep expat
    httpd   3625 root  mem    REG     253,0   123552    6409040
    /usr/lib/libexpat.so.0.5.0

    [grahamd@dscpl grahamd]$ strings /usr/lib/libexpat.so.0.5.0 | grep expat_
    expat_1.95.8

Expat Version Used By Python
----------------------------

To determine the version of the "expat" library which is embedded in the
Python "pyexpat" module, the module should be imported and the version
information extracted from the module. This can be done by executing
"python" on the command line and entering the necessary code directly::

    [grahamd@dscpl grahamd]$ python
    Python 2.3.3 (#1, May  7 2004, 10:31:40) 
    [GCC 3.3.3 20040412 (Red Hat Linux 3.3.3-7)] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import pyexpat 
    >>> pyexpat.version_info
    (1, 95, 7)

Combining Python And Apache
---------------------------

When mod_wsgi is used from within Apache, although there is a version of
the "expat" library embedded in the "pyexpat" module, it will effectively
be ignored. This is because Apache has already loaded into memory at
startup the version of the "expat" library which it is linked against. That
this occurs can be seen by using the ability of Linux to forcibly preload a
shared library into a program when run, even though that program wasn't
linked against the library orginally. This is achieved using the
"LD_PRELOAD" environment variable::

    [grahamd@dscpl grahamd]$ LD_PRELOAD=/usr/lib/libexpat.so.0.5.0 python
    Python 2.3.3 (#1, May  7 2004, 10:31:40) 
    [GCC 3.3.3 20040412 (Red Hat Linux 3.3.3-7)] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import pyexpat
    >>> pyexpat.version_info
    (1, 95, 8)

As can be seen, although the "pyexpat" module for this version of Python
embedded version 1.95.7 of the "expat" library, when the same version of
the "expat" library as was being used by Apache is forcibly loaded into the
program at startup, the version information obtained from the "pyexpat"
module now shows that version 1.95.8 of the "expat" library is being used.

Luckily in this case, the patch level difference between the two versions
of the "expat" library as used by Python and Apache doesn't cause a
problem. If however the two versions of the "expat" library were
incompatible, one would expect to see the "python" program crash with a
segmentation fault at this point. This therefore can be used as an
alternate way of verifying that it is the "pyexpat" module and more
specifically the version of the "expat" library used, that is causing the
problem.

Updating System Expat Version
-----------------------------

Because the version of the "expat" library embedded within the "pyexpat"
module is shipped as source code within the Python distribution, it can be
hard to replace it. The preferred approach to resolving the mismatch is
therefore to replace/update the version of the "expat" library that is used
by Apache.

Generally the problem occurs where that used by Apache is older than that
which is being used by Python. In that case, the version of the "expat"
library used by Apache should be updated to be the same version as that
embedded within the "pyexpat" module. By using the same version, one would
expect any problems to disappear. If problems still persist, it is possible
that Apache may also need to be recompiled against the same version of the
"expat" library as used in Python.
