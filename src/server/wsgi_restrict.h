#ifndef WSGI_RESTRICT_H
#define WSGI_RESTRICT_H

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

/* ------------------------------------------------------------------------- */

/*
 * Restricted: a sentinel Python object that raises OSError on any
 * attribute access. Used by mod_wsgi to substitute for sys.stdin
 * and sys.stdout in the embedded interpreter when the
 * WSGIRestrictStdin / WSGIRestrictStdout directives are set. WSGI
 * applications should never read from or write to the standard
 * streams (those are tied to the Apache worker process, not to
 * any specific HTTP request), and a Restricted instance gives a
 * clear OSError if they try, instead of a silent read/write that
 * goes nowhere or pollutes the Apache error log.
 *
 * The instance carries a single C string identifier (e.g.
 * "sys.stdin") that is included in the OSError message so the
 * operator can tell which stream was misused. The string is
 * borrowed and must outlive the object; process-static literals
 * are the typical usage.
 *
 * The Python type backing this object is heap-allocated, created
 * via PyType_FromModuleAndSpec, so each Python sub-interpreter
 * has its own type instance. The type pointer lives in
 * WSGIModuleState and is looked up via
 * PyImport_ImportModule("mod_wsgi") + PyModule_GetState.
 */

typedef struct
{
    PyObject_HEAD const char *s;
} RestrictedObject;

/*
 * Construct a Restricted instance whose error message names `s`
 * as the affected stream (e.g. "sys.stdin"). Returns NULL with a
 * Python exception set on failure; the most likely failure mode
 * is the embedded mod_wsgi module not yet being in sys.modules
 * for the current interpreter, which indicates an init order
 * bug.
 */

extern RestrictedObject *newRestrictedObject(const char *s);

/*
 * Create the heap-allocated Restricted PyTypeObject for `module`'s
 * interpreter and store it in WSGIModuleState. Called from the
 * embedded mod_wsgi module's exec slot. Returns 0 on success, -1
 * on failure with Python exception set.
 */

extern int wsgi_restricted_init(PyObject *module);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
