#ifndef WSGI_DISPATCH_H
#define WSGI_DISPATCH_H

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

/* ------------------------------------------------------------------------- */

/*
 * Dispatch: an internal per-request scratch object used by
 * wsgi_execute_dispatch to build the environ dict passed to the
 * dispatch script callables (process_group, application_group,
 * callable_object) installed by WSGIDispatchScript. It carries
 * the Apache request_rec, the resolved WSGIRequestConfig, and a
 * Log object that gets installed into the environ dict as
 * environ["wsgi.errors"]. The Dispatch instance itself is not
 * exposed to the script: only the environ dict it produces is
 * passed to the callables. Built fresh per request and
 * discarded once the script's callables have returned.
 *
 * The type is internal; instances are never constructed from
 * Python and the type is not exposed as a module attribute. It
 * exists as a Python type purely so reference counting can
 * govern the lifetime of the wrapped per-request resources.
 *
 * The Python type backing this object is heap-allocated, created
 * via PyType_FromModuleAndSpec, so each Python sub-interpreter
 * has its own type instance. The type pointer lives in
 * WSGIModuleState and is looked up via
 * PyImport_ImportModule("mod_wsgi") + PyModule_GetState by
 * newDispatchObject.
 */

typedef struct
{
    PyObject_HEAD
    request_rec *r;
    WSGIRequestConfig *config;
    PyObject *log;
} DispatchObject;

/*
 * Create the heap-allocated Dispatch PyTypeObject for `module`'s
 * interpreter and store it in WSGIModuleState. Called from the
 * embedded mod_wsgi module's exec slot. Returns 0 on success,
 * -1 on failure with Python exception set.
 */

extern int wsgi_dispatch_init(PyObject *module);

/*
 * Run the configured WSGIDispatchScript callables (process_group,
 * application_group, callable_object) for the current request,
 * applying any returned overrides to the request config. Returns
 * an Apache HTTP status (OK on success, HTTP_INTERNAL_SERVER_ERROR
 * on failure to load or execute the script).
 */

extern int wsgi_execute_dispatch(request_rec *r);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
