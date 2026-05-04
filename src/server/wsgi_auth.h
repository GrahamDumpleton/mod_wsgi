#ifndef WSGI_AUTH_H
#define WSGI_AUTH_H

/* ------------------------------------------------------------------------- */

/*
 * Copyright 2007-2026 GRAHAM DUMPLETON
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* ------------------------------------------------------------------------- */

#include "wsgi_python.h"
#include "wsgi_apache.h"
#include "wsgi_server.h"

#include "mod_auth.h"
#include "ap_provider.h"

/* ------------------------------------------------------------------------- */

/*
 * Auth: an internal per-request scratch object used by the
 * mod_wsgi authentication and access control hooks
 * (WSGIAuthUserScript, WSGIAuthGroupScript, WSGIAccessScript) to
 * build the environ dict passed to the user-provided
 * check_password / get_realm_hash / groups_for_user /
 * allow_access callables. It carries the Apache request_rec, the
 * resolved WSGIRequestConfig, and a Log object that gets
 * installed into the environ dict as environ["wsgi.errors"].
 * The Auth instance itself is not exposed to the script: only
 * the environ dict it produces is passed to the callable. Built
 * fresh per auth-hook invocation and discarded once the callable
 * has returned.
 *
 * The type is internal; instances are never constructed from
 * Python and the type is not exposed as a module attribute. It
 * exists as a Python type purely so reference counting can
 * govern the lifetime of the wrapped per-request resources, and
 * to host the ssl_is_https / ssl_var_lookup helper methods that
 * the auth-environ builder exposes via callable bindings on the
 * environ dict.
 *
 * The Python type backing this object is heap-allocated, created
 * via PyType_FromModuleAndSpec, so each Python sub-interpreter
 * has its own type instance. The type pointer lives in
 * WSGIModuleState and is looked up via
 * PyImport_ImportModule("mod_wsgi") + PyModule_GetState by
 * newAuthObject.
 */

/*
 * Create the heap-allocated Auth PyTypeObject for `module`'s
 * interpreter and store it in WSGIModuleState. Called from the
 * embedded mod_wsgi module's exec slot. Returns 0 on success,
 * -1 on failure with Python exception set.
 */

extern int wsgi_auth_init(PyObject *module);

extern const authn_provider wsgi_authn_provider;
extern const authz_provider wsgi_authz_provider;

extern int wsgi_hook_access_checker(request_rec *r);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
