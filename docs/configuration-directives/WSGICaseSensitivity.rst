===================
WSGICaseSensitivity
===================

:Description: Define whether file system is case sensitive.
:Syntax: ``WSGICaseSensitivity On|Off``
:Context: server config

When mod_wsgi is used on the Windows and MacOS X platforms, it will assume
that the filesystem in use is case insensitive. This is necessary to ensure
that the module caching system works correctly and only one module is
retained in memory where paths with different case are used to identify the
same script file. On other platforms it will always be assumed that a case
sensitive file system is used.

The WSGICaseSensitivity directive can be used explicitly to specify for a
particular WSGI application whether the file system the script file is
stored in is case sensitive or not, thus overriding the default for any
platform. A value of On indicates that the filesystem is case sensitive.

Because it is set in the main server config it will apply to the whole
site. All paths therefore would need to be located in a filesystem with the
same case convention.
