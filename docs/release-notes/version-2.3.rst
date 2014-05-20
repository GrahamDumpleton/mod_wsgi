===========
Version 2.3
===========

Version 2.3 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-2.3.tar.gz

**Note that this is a quick followup to version 2.2 of mod_wsgi to rectify
significant problem introduced by that release. You should therefore also
refer to:**

* :doc:`version-2.2`

Bug Fixes
---------

1. Fixed problem introduced in version 2.2 of mod_wsgi whereby use of
daemon mode would cause CGI scripts to fail.

It is quite possible that the bug could also have caused failures with other
Apache modules that relied on registering of cleanup functions against
Apache configuration memory pool.

For details see:

  http://groups.google.com/group/modwsgi/browse_frm/thread/79a86f8faffe7dcf

2. When using setproctitle() on BSD systems, first argument should be a
printf style format string with values to fill out per format as additional
arguments. Code was supplying value to be displayed as format string which
meant that if it contained any printf type format sequences, could cause
process to crash as corresponding arguments wouldn't have ben provided.

For details see:

  http://code.google.com/p/modwsgi/issues/detail?id=90
