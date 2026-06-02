#ifndef WSGI_ADAPTER_H
#define WSGI_ADAPTER_H

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

#include "wsgi_input.h"

/* ------------------------------------------------------------------------- */

/*
 * Adapter: the per-request WSGI adapter. Built once per request
 * by the request handler, owns all per-request Python state for
 * the lifetime of the request: the wsgi.input reader, the
 * wsgi.errors log buffer/wrapper, the captured response status
 * line and headers, and the response body iterable returned by
 * the WSGI callable. Adapter_run drives the WSGI protocol
 * end-to-end: it builds the environ, invokes the application,
 * processes the start_response callback, streams the response
 * body through Apache's bucket brigades, and updates the metrics
 * counters.
 *
 * The type exposes start_response and write to the WSGI
 * application via bound methods on the environ dict; ssl_is_https
 * and ssl_var_lookup are also exposed as environ entries (under
 * mod_ssl.is_https / mod_ssl.var_lookup) so applications can
 * query mod_ssl from the request context.
 *
 * The type is internal: instances are never constructed from
 * Python and the type is not exposed as a module attribute.
 *
 * The Python type backing this object is heap-allocated, created
 * via PyType_FromModuleAndSpec, so each Python sub-interpreter
 * has its own type instance. The type pointer lives in
 * WSGIModuleState and is looked up via
 * PyImport_ImportModule("mod_wsgi") + PyModule_GetState by
 * newAdapterObject.
 */

typedef struct
{
    PyObject_HEAD int result;
    request_rec *r;
    apr_bucket_brigade *bb;
    WSGIRequestConfig *config;
    InputObject *input;
    PyObject *log_buffer;
    PyObject *log;
    int status;
    const char *status_line;
    PyObject *headers;
    PyObject *sequence;
    int content_length_set;
    apr_off_t content_length;
    apr_off_t output_length;
    apr_off_t output_writes;
    apr_time_t output_time;
    apr_time_t start_time;
} AdapterObject;

/*
 * Construct an Adapter for `r`. Initialises the per-request
 * Python state (Input, log buffer, log wrapper) and returns the
 * adapter ready for Adapter_run. Returns NULL with a Python
 * exception set on failure; the most likely failure mode is the
 * embedded mod_wsgi module not yet being in sys.modules for the
 * current interpreter, which indicates an init order bug.
 */

extern AdapterObject *newAdapterObject(request_rec *r);

/*
 * Drive the WSGI application end-to-end for `self`'s request,
 * calling `object` (the WSGI callable resolved from the script)
 * with environ + start_response, streaming the returned iterable
 * back through Apache's bucket brigades, and updating per-request
 * metrics. Returns OK on success or an Apache HTTP status on
 * failure.
 */

extern int Adapter_run(AdapterObject *self, PyObject *object);

/*
 * Create the heap-allocated Adapter PyTypeObject for `module`'s
 * interpreter and store it in WSGIModuleState. Called from the
 * embedded mod_wsgi module's exec slot. Returns 0 on success,
 * -1 on failure with Python exception set.
 */

extern int wsgi_adapter_init(PyObject *module);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
