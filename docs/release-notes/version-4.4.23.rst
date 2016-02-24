==============
Version 4.4.23
==============

Version 4.4.23 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.23

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

New Features
------------

1. Added the ``--ssl-certificate-chain-file`` option to
``mod_wsgi-express``, for specifying the path to a file containing the
certificates of Certification Authorities (CA) which form the certificate
chain of the server certificate. This is equivalent to having used the
Apache ``SSLCertificateChainFile`` directive.
