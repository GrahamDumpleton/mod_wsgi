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
 * Install the interpreter-stable attributes onto the embedded
 * mod_wsgi module: version, FileWrapper type, RequestTimeout
 * exception, module-level methods, and the empty
 * event_callbacks/shutdown_callbacks lists and active_requests
 * dict. Returns 0 on success, -1 on failure with Python exception
 * set.
 */

extern int wsgi_module_install_stable(PyObject *module);

/*
 * Install the per-application-group attributes: process_group,
 * application_group, maximum_processes, threads_per_process.
 * Called after module construction because the application group
 * context is not visible to the exec slot.
 */

extern int wsgi_module_install_group_attrs(PyObject *module,
                                           const char *name);

/*
 * Construct the embedded mod_wsgi module for the current Python
 * sub-interpreter. Builds a state-bearing module via PEP 489
 * multi-phase init, copies __path__ from the upstream
 * mod_wsgi-express companion package if installed (so subpackage
 * imports still resolve), installs it as sys.modules['mod_wsgi'],
 * and populates its user-facing attributes plus the per-application-
 * group attributes for `name`. Returns an owned reference, or NULL
 * on failure with Python exception set.
 */

extern PyObject *wsgi_module_create_for_interp(const char *name);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
