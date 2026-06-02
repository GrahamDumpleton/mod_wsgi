#ifndef WSGI_SIGNAL_H
#define WSGI_SIGNAL_H

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
 * SignalIntercept: a callable Python object that wraps the real
 * signal.signal so calls to it from inside an mod_wsgi-managed
 * process can be detected and refused. mod_wsgi installs an
 * instance of this in place of signal.signal in the embedded
 * interpreter when WSGIRestrictSignal is set, because a WSGI
 * application installing its own signal handlers would interfere
 * with the signal handling that mod_wsgi and Apache rely on for
 * worker management.
 *
 * When called, the wrapper logs a warning that names the signal
 * being registered and dumps a Python stack trace identifying the
 * caller, then returns the existing handler unchanged so the
 * caller observes a no-op replacement. The original signal.signal
 * function is held as `wrapped` for the (uncommon) case where the
 * call originated from a process the wrapper considers external
 * (different daemon or worker pid), in which case the wrapped
 * function is called through to install the handler normally.
 *
 * The Python type backing this object is heap-allocated, created
 * via PyType_FromModuleAndSpec, so each Python sub-interpreter
 * has its own type instance. The type pointer lives in
 * WSGIModuleState and is looked up via
 * PyImport_ImportModule("mod_wsgi") + PyModule_GetState.
 */

typedef struct
{
    PyObject_HEAD
    PyObject *wrapped;
} SignalInterceptObject;

/*
 * Construct a SignalIntercept instance wrapping `wrapped` (the
 * real signal.signal function). The wrapper takes a strong
 * reference to `wrapped`. Returns NULL with a Python exception
 * set on failure; the most likely failure mode is the embedded
 * mod_wsgi module not yet being in sys.modules for the current
 * interpreter, which indicates an init order bug.
 */

extern SignalInterceptObject *newSignalInterceptObject(PyObject *wrapped);

/*
 * Create the heap-allocated SignalIntercept PyTypeObject for
 * `module`'s interpreter and store it in WSGIModuleState. Called
 * from the embedded mod_wsgi module's exec slot. Returns 0 on
 * success, -1 on failure with Python exception set.
 */

extern int wsgi_signal_init(PyObject *module);

/*
 * PyMethodDef array exposing wsgi_system_exit() as a callable
 * suitable for installing as a signal handler via signal.signal.
 * mod_wsgi registers it for SIGTERM in the embedded interpreter
 * so a SIGTERM raises SystemExit in Python code, giving atexit
 * handlers a chance to run during shutdown.
 */

extern PyMethodDef wsgi_system_exit_method[];

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
