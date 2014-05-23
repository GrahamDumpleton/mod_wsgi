===========
Version 1.6
===========

Version 1.6 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-1.6.tar.gz

**Note that this is a quick followup to version 1.5 of mod_wsgi to rectify
significant problem introduced by that release. You should therefore also
refer to:**

* :doc:`version-1.5`.

Bug Fixes
---------

1. Fixed problem introduced in version 1.5 of mod_wsgi whereby use of
daemon mode would cause CGI scripts to fail.

It is quite possible that the bug could also have caused failures with other
Apache modules that relied on registering of cleanup functions against
Apache configuration memory pool.

For details see:

  http://groups.google.com/group/modwsgi/browse_frm/thread/79a86f8faffe7dcf
