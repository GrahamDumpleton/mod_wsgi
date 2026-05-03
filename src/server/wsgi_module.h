#ifndef WSGI_MODULE_H
#define WSGI_MODULE_H

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
 * Per-interpreter state for the embedded 'mod_wsgi' Python module.
 * Each Python sub-interpreter created by mod_wsgi has its own
 * instance of this struct, addressable via PyModule_GetState() on
 * the module returned by PyImport_ImportModule("mod_wsgi"). The
 * Restricted_Type field is populated by wsgi_restricted_init,
 * called from the module's exec slot.
 *
 * Lookup from anywhere in the embedded code goes through
 * sys.modules:
 *
 *     PyObject *m = PyImport_ImportModule("mod_wsgi");
 *     WSGIModuleState *s = PyModule_GetState(m);
 *     ... use s->Restricted_Type ...
 *     Py_DECREF(m);
 */

typedef struct
{
    PyTypeObject *Restricted_Type;
    PyTypeObject *SignalIntercept_Type;
} WSGIModuleState;

/* ------------------------------------------------------------------------- */

extern struct PyModuleDef wsgi_module_def;

extern PyMODINIT_FUNC PyInit_mod_wsgi(void);

/*
 * Helper to add an object to a module. Properly handles the case
 * where the value is NULL (i.e. the allocator that produced it
 * failed) and where PyModule_AddObject() itself fails. The latter
 * does not steal the reference on failure, so the value must be
 * decremented in that case. Returns 0 on success, -1 on failure.
 */

extern int wsgi_module_add_object(PyObject *module, const char *name,
                                  PyObject *value);

/*
 * Build the embedded mod_wsgi module for the current Python
 * sub-interpreter and install it as sys.modules['mod_wsgi']. The
 * module is built via PEP 489 multi-phase init; its exec slot
 * populates WSGIModuleState with the heap-allocated PyTypeObjects
 * needed by the rest of interp setup. If the upstream mod_wsgi
 * PyPi companion package is on the import path, its __path__ is
 * copied across first so subpackage imports continue to resolve.
 *
 * Called early in interpreter setup, before any code that
 * constructs an instance of one of the heap types (Restricted,
 * SignalIntercept, etc.) so the type pointers are reachable via
 * PyImport_ImportModule + PyModule_GetState.
 *
 * `name` is the application group of the interpreter being set
 * up (the empty string for the main interpreter). It is used
 * only for log header context if the import of the upstream
 * Python companion package raises an exception other than
 * ModuleNotFoundError.
 *
 * Returns 0 on success, -1 on failure with Python exception set.
 */

extern int wsgi_module_init_state(const char *name);

/*
 * Populate the embedded mod_wsgi module with all its attributes:
 * the common ones (version, FileWrapper, RequestTimeout,
 * methods, empty containers) and the per-interpreter runtime
 * ones (process_group, application_group, maximum_processes,
 * threads_per_process). Looks the module up from sys.modules;
 * wsgi_module_init_state must have been called earlier in the
 * same interpreter.
 *
 * Returns an owned reference to the module, or NULL on failure
 * with Python exception set.
 */

extern PyObject *wsgi_module_populate(const char *name);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
