=============
Configuration
=============

This page lists the Apache configuration directives provided by
mod_wsgi, grouped by purpose. An alphabetical index of all
directives is at the bottom of the page.

Application loading
-------------------

.. toctree::
   :maxdepth: 1

   configuration-directives/WSGIScriptAlias
   configuration-directives/WSGIScriptAliasMatch
   configuration-directives/WSGICallableObject
   configuration-directives/WSGIImportScript
   configuration-directives/WSGIScriptReloading
   configuration-directives/WSGICaseSensitivity

Process model and daemon mode
-----------------------------

.. toctree::
   :maxdepth: 1

   configuration-directives/WSGIDaemonProcess
   configuration-directives/WSGIProcessGroup
   configuration-directives/WSGIApplicationGroup
   configuration-directives/WSGISocketPrefix
   configuration-directives/WSGIAcceptMutex
   configuration-directives/WSGIDestroyInterpreter
   configuration-directives/WSGIRestrictProcess

Python environment
------------------

.. toctree::
   :maxdepth: 1

   configuration-directives/WSGIPythonHome
   configuration-directives/WSGIPythonPath
   configuration-directives/WSGIPythonOptimize
   configuration-directives/WSGIPythonEggs

Authentication and access control
---------------------------------

.. toctree::
   :maxdepth: 1

   configuration-directives/WSGIAuthUserScript
   configuration-directives/WSGIAuthGroupScript
   configuration-directives/WSGIAccessScript
   configuration-directives/WSGIPassAuthorization

Request handling
----------------

.. toctree::
   :maxdepth: 1

   configuration-directives/WSGIChunkedRequest
   configuration-directives/WSGIMapHEADToGET
   configuration-directives/WSGIErrorOverride

Reverse proxy
-------------

.. toctree::
   :maxdepth: 1

   configuration-directives/WSGITrustedProxies
   configuration-directives/WSGITrustedProxyHeaders

Sandboxing and safety
---------------------

.. toctree::
   :maxdepth: 1

   configuration-directives/WSGIRestrictEmbedded
   configuration-directives/WSGIRestrictSignal
   configuration-directives/WSGIRestrictStdin
   configuration-directives/WSGIRestrictStdout

Alphabetical index
------------------

* :doc:`configuration-directives/WSGIAcceptMutex`
* :doc:`configuration-directives/WSGIAccessScript`
* :doc:`configuration-directives/WSGIApplicationGroup`
* :doc:`configuration-directives/WSGIAuthGroupScript`
* :doc:`configuration-directives/WSGIAuthUserScript`
* :doc:`configuration-directives/WSGICallableObject`
* :doc:`configuration-directives/WSGICaseSensitivity`
* :doc:`configuration-directives/WSGIChunkedRequest`
* :doc:`configuration-directives/WSGIDaemonProcess`
* :doc:`configuration-directives/WSGIDestroyInterpreter`
* :doc:`configuration-directives/WSGIErrorOverride`
* :doc:`configuration-directives/WSGIImportScript`
* :doc:`configuration-directives/WSGIMapHEADToGET`
* :doc:`configuration-directives/WSGIPassAuthorization`
* :doc:`configuration-directives/WSGIProcessGroup`
* :doc:`configuration-directives/WSGIPythonEggs`
* :doc:`configuration-directives/WSGIPythonHome`
* :doc:`configuration-directives/WSGIPythonOptimize`
* :doc:`configuration-directives/WSGIPythonPath`
* :doc:`configuration-directives/WSGIRestrictEmbedded`
* :doc:`configuration-directives/WSGIRestrictProcess`
* :doc:`configuration-directives/WSGIRestrictSignal`
* :doc:`configuration-directives/WSGIRestrictStdin`
* :doc:`configuration-directives/WSGIRestrictStdout`
* :doc:`configuration-directives/WSGIScriptAlias`
* :doc:`configuration-directives/WSGIScriptAliasMatch`
* :doc:`configuration-directives/WSGIScriptReloading`
* :doc:`configuration-directives/WSGISocketPrefix`
* :doc:`configuration-directives/WSGITrustedProxies`
* :doc:`configuration-directives/WSGITrustedProxyHeaders`
