#ifndef WSGI_INPUT_H
#define WSGI_INPUT_H

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

/* ------------------------------------------------------------------------- */

/*
 * Input: the WSGI request body reader, exposed to applications
 * as environ["wsgi.input"]. Constructed once per request by the
 * Adapter, owned by the AdapterObject for the duration of the
 * request, and explicitly torn down via Input_finish once the
 * response has completed so that the Apache bucket brigade
 * lifetime is bounded by the request rather than by Python GC
 * timing of any environ references the application stashed.
 *
 * Implements read / readline / readlines / close plus the
 * iteration protocol so that user code can iterate the input
 * stream line by line. Reads pull data from the request input
 * filter chain via apr_brigade_*; the GIL is released around the
 * blocking read so other Python threads can run while the
 * request body is being received.
 *
 * The Python type backing this object is heap-allocated, created
 * via PyType_FromModuleAndSpec, so each Python sub-interpreter
 * has its own type instance. The type pointer lives in
 * WSGIModuleState and is looked up via
 * PyImport_ImportModule("mod_wsgi") + PyModule_GetState by
 * newInputObject.
 */

typedef struct
{
    PyObject_HEAD request_rec *r;
    int init;
    int done;
    char *buffer;
    apr_off_t size;
    apr_off_t offset;
    apr_off_t length;
    apr_bucket_brigade *bb;
    int seen_eos;
    int seen_error;
    apr_off_t bytes;
    apr_off_t reads;
    apr_time_t time;
    int ignore_activity;
} InputObject;

/*
 * Construct an Input instance for `r`, with `ignore_activity`
 * controlling whether read() resets the daemon idle-shutdown
 * timer. Returns NULL with a Python exception set on failure;
 * the most likely failure mode is the embedded mod_wsgi module
 * not yet being in sys.modules for the current interpreter,
 * which indicates an init order bug.
 */

extern InputObject *newInputObject(request_rec *r, int ignore_activity);

/*
 * Tear down request-scoped resources (the bucket brigade, the
 * back-pointer to request_rec) so the underlying Apache
 * structures can be released without waiting on Python GC. After
 * this call, any subsequent read / readline / close call from
 * Python raises RuntimeError("request object has expired").
 */

extern void Input_finish(InputObject *self);

/*
 * Create the heap-allocated Input PyTypeObject for `module`'s
 * interpreter and store it in WSGIModuleState. Called from the
 * embedded mod_wsgi module's exec slot. Returns 0 on success,
 * -1 on failure with Python exception set.
 */

extern int wsgi_input_init(PyObject *module);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
