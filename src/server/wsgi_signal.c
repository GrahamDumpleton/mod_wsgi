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

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* ------------------------------------------------------------------------- */

/* Function to restrict access to use of signal(). */

static void SignalIntercept_dealloc(SignalInterceptObject *self)
{
    Py_DECREF(self->wrapped);
}

SignalInterceptObject *newSignalInterceptObject(PyObject *wrapped)
{
    SignalInterceptObject *self = NULL;

    self = PyObject_New(SignalInterceptObject, &SignalIntercept_Type);
    if (self == NULL)
        return NULL;

    Py_INCREF(wrapped);
    self->wrapped = wrapped;

    return self;
}

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

    Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Callback registration for "
                     "signal %d ignored.",
                     getpid(), n);
    Py_END_ALLOW_THREADS

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
            log = newLogObject(NULL, APLOG_WARNING, NULL, 0);
            call_args = Py_BuildValue("(OOO)", Py_None, Py_None, log);
            result = PyObject_CallObject(o, call_args);
            Py_XDECREF(result);
            Py_DECREF(call_args);
            Py_DECREF(log);
            Py_DECREF(o);
        }
    }

    Py_XDECREF(m);

    Py_INCREF(h);

    return h;
}

PyTypeObject SignalIntercept_Type = {
    PyVarObject_HEAD_INIT(NULL, 0) "mod_wsgi.SignalIntercept", /*tp_name*/
    sizeof(SignalInterceptObject),                             /*tp_basicsize*/
    0,                                                         /*tp_itemsize*/
    /* methods */
    (destructor)SignalIntercept_dealloc, /*tp_dealloc*/
    0,                                   /*tp_print*/
    0,                                   /*tp_getattr*/
    0,                                   /*tp_setattr*/
    0,                                   /*tp_compare*/
    0,                                   /*tp_repr*/
    0,                                   /*tp_as_number*/
    0,                                   /*tp_as_sequence*/
    0,                                   /*tp_as_mapping*/
    0,                                   /*tp_hash*/
    (ternaryfunc)SignalIntercept_call,   /*tp_call*/
    0,                                   /*tp_str*/
    0,                                   /*tp_getattro*/
    0,                                   /*tp_setattro*/
    0,                                   /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,                  /*tp_flags*/
    0,                                   /*tp_doc*/
    0,                                   /*tp_traverse*/
    0,                                   /*tp_clear*/
    0,                                   /*tp_richcompare*/
    0,                                   /*tp_weaklistoffset*/
    0,                                   /*tp_iter*/
    0,                                   /*tp_iternext*/
    0,                                   /*tp_methods*/
    0,                                   /*tp_members*/
    0,                                   /*tp_getset*/
    0,                                   /*tp_base*/
    0,                                   /*tp_dict*/
    0,                                   /*tp_descr_get*/
    0,                                   /*tp_descr_set*/
    0,                                   /*tp_dictoffset*/
    0,                                   /*tp_init*/
    0,                                   /*tp_alloc*/
    0,                                   /*tp_new*/
    0,                                   /*tp_free*/
    0,                                   /*tp_is_gc*/
};

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
