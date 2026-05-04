#ifndef WSGI_SHUTDOWN_H
#define WSGI_SHUTDOWN_H

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
 * ShutdownInterpreter: a callable Python object that wraps the
 * real threading._shutdown so that, when CPython tears a sub
 * interpreter down, atexit callbacks registered in that sub
 * interpreter still get a chance to run. CPython invokes
 * threading._shutdown automatically as part of finalising any
 * interpreter; it does not invoke atexit._run_exitfuncs in sub
 * interpreters (only in the main one), so without this wrapper
 * atexit callbacks registered by code running in a mod_wsgi sub
 * interpreter would silently never fire.
 *
 * When called, the wrapper first defers to the wrapped
 * threading._shutdown so non-daemon threads get joined as usual.
 * If that returned cleanly it then drives atexit._run_exitfuncs
 * directly, logging any exception (including SystemExit, which
 * is converted to a log line rather than allowed to terminate
 * the process) via the Apache error log. Finally it walks the
 * interpreter's thread state list and clears any thread states
 * left behind by application code so the interpreter can be
 * destroyed cleanly.
 *
 * The Python type backing this object is heap-allocated, created
 * via PyType_FromModuleAndSpec, so each Python sub-interpreter
 * has its own type instance. The type pointer lives in
 * WSGIModuleState and is looked up via
 * PyImport_ImportModule("mod_wsgi") + PyModule_GetState.
 */

typedef struct
{
    PyObject_HEAD PyObject *wrapped;
} ShutdownInterpreterObject;

/*
 * Construct a ShutdownInterpreter instance wrapping `wrapped`
 * (the real threading._shutdown function). The wrapper takes a
 * strong reference to `wrapped`. Returns NULL with a Python
 * exception set on failure; the most likely failure mode is the
 * embedded mod_wsgi module not yet being in sys.modules for the
 * current interpreter, which indicates an init order bug.
 */

extern ShutdownInterpreterObject *newShutdownInterpreterObject(
    PyObject *wrapped);

/*
 * Create the heap-allocated ShutdownInterpreter PyTypeObject for
 * `module`'s interpreter and store it in WSGIModuleState. Called
 * from the embedded mod_wsgi module's exec slot. Returns 0 on
 * success, -1 on failure with Python exception set.
 */

extern int wsgi_shutdown_init(PyObject *module);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
