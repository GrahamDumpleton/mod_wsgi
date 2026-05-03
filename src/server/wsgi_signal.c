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

#include "wsgi_signal.h"

#include "wsgi_apache.h"
#include "wsgi_server.h"
#include "wsgi_logger.h"
#include "wsgi_daemon.h"
#include "wsgi_module.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* ------------------------------------------------------------------------- */

/*
 * Heap-type destructor. Releases the wrapped signal.signal
 * reference held by the instance, then frees the instance memory
 * and decrements the type's refcount (every heap-type instance
 * owns a reference to its type).
 */

static void SignalIntercept_dealloc(SignalInterceptObject *self)
{
    PyTypeObject *tp = Py_TYPE(self);

    Py_DECREF(self->wrapped);

    tp->tp_free(self);
    Py_DECREF(tp);
}

/*
 * tp_call hook. Invoked when Python code calls the wrapper as
 * if it were signal.signal. The pid checks pass through to the
 * real signal.signal when running inside a process forked from
 * the mod_wsgi daemon or the Apache worker child: the wrapper
 * is inherited across fork, but the forked child is no longer
 * subject to mod_wsgi's signal management and code running
 * there must be free to install its own handlers. When the call
 * comes from the mod_wsgi-managed process itself, log a
 * warning, print a stack trace identifying the caller, and
 * return the existing handler unchanged so the caller observes
 * a no-op replacement.
 */

static PyObject *SignalIntercept_call(
    SignalInterceptObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *h = NULL;
    int n = 0;

    PyObject *m = NULL;

    if (wsgi_daemon_pid != 0 && wsgi_daemon_pid != getpid())
        return PyObject_Call(self->wrapped, args, kwds);

    if (wsgi_worker_pid != 0 && wsgi_worker_pid != getpid())
        return PyObject_Call(self->wrapped, args, kwds);

    if (!PyArg_ParseTuple(args, "iO:signal", &n, &h))
        return NULL;

    wsgi_log_error_locked(APLOG_INFO, 0, wsgi_server,
                          "Ignoring Python signal handler registration for "
                          "signal %d in WSGI process; mod_wsgi manages "
                          "signals.",
                          n);

    m = PyImport_ImportModule("traceback");

    if (m)
    {
        PyObject *d = NULL;
        PyObject *o = NULL;
        d = PyModule_GetDict(m);
        o = PyDict_GetItemString(d, "print_stack");
        if (o)
        {
            PyObject *log = NULL;
            PyObject *call_args = NULL;
            PyObject *result = NULL;
            Py_INCREF(o);
            log = newLogObject(NULL, APLOG_INFO, NULL, 0);
            if (log)
                call_args = Py_BuildValue("(OOO)", Py_None, Py_None, log);
            if (call_args)
                result = PyObject_CallObject(o, call_args);
            Py_XDECREF(result);
            Py_XDECREF(call_args);
            Py_XDECREF(log);
            Py_DECREF(o);
        }
    }

    Py_XDECREF(m);

    /* The traceback print above is a best-effort debug aid. Any step
     * along the way (import, attribute lookup, log object allocation,
     * tuple build, call) can leave an exception set; clear it so we
     * never return a non-NULL handler with a pending exception, which
     * would violate the C API contract and surface as a confusing
     * unrelated error at the next Python C API call. */

    if (PyErr_Occurred())
        PyErr_Clear();

    Py_INCREF(h);

    return h;
}

/* ------------------------------------------------------------------------- */

/*
 * PyType_Spec for the SignalIntercept heap type. The two slots
 * with non-default behaviour are tp_dealloc (releases the
 * wrapped reference) and tp_call (the intercept hook); everything
 * else falls back to the framework defaults.
 *
 * tp_name is "mod_wsgi.SignalIntercept" so error messages and
 * repr() output identify where the type comes from. The type is
 * not exposed as a module attribute; instances are installed
 * directly into the signal module's signal slot from C.
 */

static PyType_Slot SignalIntercept_slots[] = {
    {Py_tp_dealloc, SignalIntercept_dealloc},
    {Py_tp_call,    SignalIntercept_call},
    {0, NULL},
};

static PyType_Spec SignalIntercept_spec = {
    .name      = "mod_wsgi.SignalIntercept",
    .basicsize = sizeof(SignalInterceptObject),
    .itemsize  = 0,
    .flags     = Py_TPFLAGS_DEFAULT,
    .slots     = SignalIntercept_slots,
};

/* ------------------------------------------------------------------------- */

int wsgi_signal_init(PyObject *module)
{
    WSGIModuleState *state = NULL;
    PyObject *type = NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state)
        return -1;

    type = PyType_FromModuleAndSpec(module, &SignalIntercept_spec, NULL);
    if (!type)
        return -1;

    state->SignalIntercept_Type = (PyTypeObject *)type;

    return 0;
}

/* ------------------------------------------------------------------------- */

SignalInterceptObject *newSignalInterceptObject(PyObject *wrapped)
{
    PyObject *module = NULL;
    WSGIModuleState *state = NULL;
    PyTypeObject *type = NULL;
    SignalInterceptObject *self = NULL;

    /*
     * Find the embedded mod_wsgi module for the current
     * interpreter and pull the SignalIntercept heap type out of
     * its state. Returns NULL with a clear error if the module
     * is not in sys.modules or its state has not been
     * initialised; either indicates an init ordering bug.
     */

    module = PyImport_ImportModule("mod_wsgi");
    if (!module)
        return NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state || !state->SignalIntercept_Type)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "SignalIntercept type not initialised for the "
                        "current interpreter; newSignalInterceptObject() "
                        "called before the embedded mod_wsgi module's "
                        "exec slot ran");
        Py_DECREF(module);
        return NULL;
    }

    type = state->SignalIntercept_Type;

    self = (SignalInterceptObject *)type->tp_alloc(type, 0);
    Py_DECREF(module);

    if (!self)
        return NULL;

    Py_INCREF(wrapped);
    self->wrapped = wrapped;

    return self;
}

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_system_exit(PyObject *Py_UNUSED(self),
                                  PyObject *Py_UNUSED(args))
{
    PyErr_SetObject(PyExc_SystemExit, 0);

    return NULL;
}

/* ------------------------------------------------------------------------- */

PyMethodDef wsgi_system_exit_method[] = {
    {"system_exit", (PyCFunction)wsgi_system_exit, METH_VARARGS, 0},
    {NULL},
};

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
