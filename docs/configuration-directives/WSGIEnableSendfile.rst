==================
WSGIEnableSendfile
==================

:Description: Enable use of sendfile() for response file objects.
:Syntax: ``WSGIEnableSendfile On|Off``
:Default: ``WSGIEnableSendfile Off``
:Context: server config, virtual host, directory, .htaccess
:Override: ``FileInfo``

Controls whether mod_wsgi will use the operating system's
``sendfile()`` system call when a WSGI application returns a
response that wraps an open file (via the ``wsgi.file_wrapper``
extension). When enabled and the underlying object exposes a real
file descriptor, the file contents are sent to the network without
copying through user space first.

For example::

  WSGIEnableSendfile On

This option is most useful for applications that serve large file
payloads (downloads, media) directly from a WSGI handler. For
small responses, the saving is negligible.

Note that on some platforms, ``sendfile()`` does not work over
UNIX domain sockets, which is the transport mod_wsgi uses for
daemon mode. As a result, this option is most often relevant for
applications running in embedded mode. In daemon mode the option
may have no effect.

Note also that ``sendfile()`` is not safe to use on some
filesystems — notably network mounts (NFS, SMB/CIFS), many
FUSE-backed filesystems, and some encrypted or overlay filesystems.
On those, the call may fail, return wrong content, or block
unexpectedly. If files served via ``wsgi.file_wrapper`` may live
on such a filesystem, leave this option ``Off``. This is also why
the directive defaults to ``Off`` and why Apache's own
``EnableSendfile`` directive defaults to ``Off`` in 2.4.

See also the :doc:`../user-guides/file-wrapper-extension` user
guide for how to return file objects from a WSGI application.
