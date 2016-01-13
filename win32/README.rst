===========================
Running mod_wsgi on Windows
===========================

Overview
--------

Running Apache/mod_wsgi on Windows can be a bit tricky.

There are four requirements that should strictly be satisified.

1. You need to ensure that you are using either 32 bit (Win32) versions of
everything or 64 bit (Win64) versions of everything. You cannot mix 32 bit
and 64 bit binaries.

2. That the Python version you are using was installed for all users
and not just the user that installed Python.

3. That you are using a precompiled Apache binary built with the same
version of the Microsoft C/C++ compiler as the version of Python you are
using.

4. That you are using a mod_wsgi binary built with the same version of
the Microsoft C/C++ compiler as the version of Python you are using.

The Microsoft C/C++ compiler versions which were used for various Python
versions are:

* Python 2.6 - VC9
* Python 2.7 - VC9
* Python 3.3 - VC10
* Python 3.4 - VC10

This means that if using Python 2.6 or 2.7, you should use a version of
Apache compiled with the Microsoft VC9 C/C++ compiler. If instead using
Python 3.3 or 3.4, you should use a version of Apache compiled with the
Microsoft VC10 C/C++ compiler.

If you ignore these requirements and use a version of Apache compiled with
the Microsoft VC11 C/C++ compiler, then nothing can be guaranteed to work
and Apache may fail to startup or crash when handling requests.

You may also have problems with using Python 2.6 or Python 2.7 binaries,
which were compiled with the Microsoft VC9 C/C++ compiler, with a version
of Apache 2.4 compiled with the Microsoft VC10 C/C++ compiler.

The problem is that Apache Lounge, whose Apache binaries have been used
up until this point, has stopped making available versions of Apache
compiled with a VC9 compiler. This means that if you hadn't managed to
download a Win32 VC9 version of Apache at some time in the past, you
technically can't use mod_wsgi on Windows with Python 2.6 or Python 2.7
any more as you can't get the right version of an Apache binary.

See further comments below though about a possible way of running Python
2.6 and Python 2.7 using a Win64 VC10 version of Apache. This is not
gauranteed to work though as explained below.

Using the pre-compiled binaries
-------------------------------

Occassionally precompiled binaries will be made available for mod_wsgi.
These may not be updated on every release because more often than not code
changes are being made which relate only to mod_wsgi daemon mode, or
``mod_wsgi-express``, neither of which are available for Windows.

When pre-compiled mod_wsgi binaries are made available they will be
downloadable from the github release page for the mod_wsgi project at:

* https://github.com/GrahamDumpleton/mod_wsgi/releases

Look back at older releases if the most current version doesn't have them
associated with it.

These mod_wsgi binaries will have been compiled with Python binaries
available from the Python Software Foundation (PSF) site at:

* https://www.python.org/downloads/

The mod_wsgi binaries would generally not be usable with other binary
Python distributions unless they specify that they are entirely ABI
compatible with the binary Python distributions from the PSF.

For Apache, mod_wsgi is compiled against Apache binaries available from the
Apache Lounge web site at:

* http://www.apachelounge.com

The mod_wsgi binaries would generally only be usable with Apache Lounge
binaries and should not be used with any other Apache binary distribution.

The actual mod_wsgi binaries that are made available are:

* Apache22-win32-VC9/modules/mod_wsgi-py26-VC9.so
* Apache22-win32-VC9/modules/mod_wsgi-py27-VC9.so

* Apache24-win32-VC9/modules/mod_wsgi-py26-VC9.so
* Apache24-win32-VC9/modules/mod_wsgi-py27-VC9.so

* Apache24-win32-VC10/modules/mod_wsgi-py33-VC10.so
* Apache24-win32-VC10/modules/mod_wsgi-py34-VC10.so

* Apache24-win64-VC10/modules/mod_wsgi-py33-VC10.so
* Apache24-win64-VC10/modules/mod_wsgi-py34-VC10.so

Those labelled with ``Apache22-win32-VC9`` should be used with an Apache
2.2 Win32 VC9 version of Apache. Alas Apache Lounge no longer makes such
binaries available any more. If you don't already have an older version of
Apache which has been compiled with the Win32 VC9 compiler you are out
of luck.

Those labelled with ``Apache24-win32-VC10`` should be used with the Apache
2.4 Win32 VC10 version of Apache available from:

* https://www.apachelounge.com/download/VC10/

Those labelled with ``Apache24-win64-VC10`` should be used with the Apache
2.4 Win64 VC10 version of Apache available from:

* https://www.apachelounge.com/download/VC10/

Note that Apache Lounge never made available any Win64 VC9 binaries for
Apache 2.4. This means that technically there is no combination
available for correctly running mod_wsgi with a Win64 VC9 version of
Python 2.6 or 2.7.

History shows that users simply don't want to accept this and don't want to
understand that mixing VC9 and VC10 binaries are not guaranteed to work.

The specific issue is that if certain data structures are passed between
VC9 and VC10 code, then the application could crash as the data structure
layouts for each variant may not be compatible.

As it happens the interface between Apache and Python via mod_wsgi is very
minimal and so it is possible that there are no instances of incompatible
data structures being passed across the ABI boundary, but that cannot be
guaranteed.

So because Apache Lounge is no longer making available any VC9 versions of
Apache, the following binaries are still provided. Because they are mixing
binaries using different ABIs, they may or may not work for your particular
cirumstances. You are still welcome to try, but there is no support for
using this combination.

* Apache24-win64-VC10/modules/mod_wsgi-py26-VC9.so
* Apache24-win64-VC10/modules/mod_wsgi-py27-VC9.so

Note that no binaries for Python 3.2 are provided due to it being an older
version in the 3.X line, but also because a Win64 VC9 version of it does
crash a Win64 VC10 version of Apache 2.4 on startup. This shows how
arbitrary compatibility is when you start mixing binaries built against
different ABIs. You have been warned.

Compiling from source code
--------------------------

If you need to compile from source code because you are using a different
Apache distribution or a different Python distribution, you will need to
have installed the appropriate Microsoft C/C++ compiler. You cannot simply
use any Microsoft C/C++ compiler you might have.

The details on where the Microsoft C/C++ compilers are available from are
given below.

Python 2.6, 2.7 (32 Bit Only)
+++++++++++++++++++++++++++++

Use the latest Python 2.6 or 2.7 binary available from the PSF:

* https://www.python.org/downloads/release/python-279/

You must use the 32 bit version which is labelled as:

* Windows x86 MSI installer

Python 2.6 and 2.7 are compiled with the Microsoft C/C++ compiler from
Visual Studio 2008. This is referred to as being compiled for VC9.

You must therefore use a version of Apache compiled for VC9.

For the Microsoft C/C++ compiler, you need to download it from Microsoft.

* http://www.microsoft.com/en-us/download/details.aspx?id=44266

This can compile both 32 bit and 64 bit binaries.

Python 2.6, 2.7 (64 Bit Only)
+++++++++++++++++++++++++++++

Use the latest Python 2.6 or 2.7 binary available from the PSF:

* https://www.python.org/downloads/

You must use the 64 bit version which is labelled as:

* Windows x86-64 MSI installer

Python 2.6 and 2.7 are compiled with the Microsoft C/C++ compiler from
Visual Studio 2008. This is referred to as being compiled for VC9.

You must therefore use a version of Apache compiled for VC9.

For the Microsoft C/C++ compiler, you need to download it from Microsoft.

* http://www.microsoft.com/en-us/download/details.aspx?id=44266

This can compile both 32 bit and 64 bit binaries.

Python 3.3, 3.4 (32 Bit)
++++++++++++++++++++++++

Use the latest Python 3.3 or 3.4 binary available from the PSF:

* https://www.python.org/downloads/

You must use the 32 bit version which is labelled as:

* Windows x86 MSI installer

Python 3.3 and 3.4 are compiled with the Microsoft C/C++ compiler from
Visual Studio 2010. This is referred to as being compiled for VC10.

You must therefore use a version of Apache compiled for VC10.

For the Microsoft C/C++ compiler, you need to download it from Microsoft.

* http://www.visualstudio.com/downloads/download-visual-studio-vs#DownloadFamilies_4

Use the one labelled as:

* Visual C++ 2010 Express

This version of the Microsoft C/C++ compiler can only compile 32 bit binaries.

Python 3.3, 3.4 (64 Bit)
++++++++++++++++++++++++

Use the latest Python 3.3 or 3.4 binary available from the PSF:

* https://www.python.org/downloads/

You must use the 64 bit version which is labelled as:

* Windows x86-64 MSI installer

Python 3.3 and 3.4 are compiled with the Microsoft C/C++ compiler from
Visual Studio 2010. This is referred to as being compiled for VC10.

You must therefore use a version of Apache compiled for VC10.

For the Microsoft C/C++ compiler, you need to download it from Microsoft.

* http://www.microsoft.com/en-us/download/details.aspx?id=8279

This is different to the Visual C++ 2010 Express above which could only
compile 32 bit binaries. This version can instead compile 64 bit binaries.

Triggering the build
+++++++++++++++++++++

Once Python, Apache and the appropriate Microsoft C/C++ is installed, start
up the Visual Studio 2008/2010 or Windows 7.1 SDK Command Prompt window
corresponding to the version of the Microsoft C/C++ compiler required for
your Python version. Make your way to this directory. You then need to do:

1. Find the appropriate makefile in the directory for your combination
   of Apache and Python.
2. Edit the makefile and set the path to where you installed both Apache
   and Python.
3. Run ``nmake -f apXYpyXY-winNN-VC?.mk clean``. Substitute 'XY' in each
   case for the version of Apache and Python being used. Substitute 'NN'
   with either '32' or '64' and substitute '?' with '9' or '10'.
4. Run ``nmake -f apXYpyXY-winNN-VC?.mk``. This will build mod_wsgi.
5. Run ``nmake -f apXYpyXY-winNN-VC?.mk install``. This will install the
   mod_wsgi module into the modules directory of your Apache installation.
6. Add the ``LoadModule`` line to the Apache configuration which was
   displayed when the ``install`` target was run.
7. Edit the Apache configuration as covered in mod_wsgi documentation or
   otherwise to have mod_wsgi host your WSGI application.

Other build scripts do exist in this directory but they are to allow bulk
compilation of all combinations in one go and wouldn't generally be of
interest. They require all possible Apache and Python versions to be
available as well as all required Microsoft C/C++ compiler. You should
therefore stick to just the makefile you need.
