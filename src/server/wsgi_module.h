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
 * Currently a placeholder; future phases will move heap-type
 * pointers and other per-interpreter PyObject references out of
 * process-level C globals into here, accessed via
 * PyModule_GetState() against wsgi_module_def.
 */

typedef struct
{
    int initialized;
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
 * Install the interpreter-stable attributes onto an existing
 * 'mod_wsgi' module instance: version, FileWrapper type,
 * RequestTimeout exception, module-level methods, and the empty
 * event_callbacks/shutdown_callbacks lists and active_requests
 * dict. Used by both the C-built fallback path (via the exec slot)
 * and the user-import augmentation path so that either form of
 * the module presents the same surface area. Returns 0 on
 * success, -1 on failure with Python exception set.
 */

extern int wsgi_module_install_stable(PyObject *module);

/*
 * Install the per-application-group attributes: process_group,
 * application_group, maximum_processes, threads_per_process. The
 * exec slot cannot install these itself because the application
 * group context is not visible to it; the caller invokes this
 * after module creation in either path.
 */

extern int wsgi_module_install_group_attrs(PyObject *module,
                                           const char *name);

/*
 * Top-level entry point invoked from interpreter setup. First
 * tries to import a user-supplied 'mod_wsgi' Python package; if
 * not present, builds the C-defined module via PEP 489 multi-phase
 * init (PyModule_FromDefAndSpec + PyModule_ExecDef) and registers
 * it in sys.modules. Either way installs the per-group attributes
 * and returns an owned reference. Returns NULL on failure with
 * Python exception set.
 */

extern PyObject *wsgi_module_create_for_interp(const char *name);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
