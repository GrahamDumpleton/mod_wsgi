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

#include "wsgi_shutdown.h"

#include "wsgi_apache.h"
#include "wsgi_server.h"
#include "wsgi_logger.h"
#include "wsgi_module.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* ------------------------------------------------------------------------- */

/*
 * Heap-type destructor. Releases the wrapped threading._shutdown
 * reference held by the instance, then frees the instance memory
 * and decrements the type's refcount (every heap-type instance
 * owns a reference to its type).
 */

static void ShutdownInterpreter_dealloc(ShutdownInterpreterObject *self)
{
    PyTypeObject *tp = Py_TYPE(self);

    Py_DECREF(self->wrapped);

    tp->tp_free(self);
    Py_DECREF(tp);
}

/*
 * tp_call hook. Invoked when CPython interpreter shutdown calls
 * threading._shutdown to join non-daemon threads. The wrapped
 * function is delegated to first; if it returned cleanly, the
 * wrapper drives atexit._run_exitfuncs so atexit callbacks
 * registered in the sub interpreter run before the interpreter
 * is destroyed (CPython does this automatically only for the
 * main interpreter). Any exception raised by the atexit
 * callbacks is logged via the Apache error log; SystemExit in
 * particular is swallowed so it cannot terminate the process
 * during shutdown. Finally any thread states left behind by
 * application code are cleared so the interpreter can be
 * destroyed cleanly.
 */

static PyObject *ShutdownInterpreter_call(
    ShutdownInterpreterObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *result = NULL;

    result = PyObject_Call(self->wrapped, args, kwds);

    if (result)
    {
        PyObject *module = NULL;
        PyObject *exitfunc = NULL;

        PyThreadState *tstate = PyThreadState_Get();

        PyThreadState *tstate_save = tstate;
        PyThreadState *tstate_next = NULL;

        module = PyImport_ImportModule("atexit");

        if (module)
        {
            PyObject *dict = NULL;

            dict = PyModule_GetDict(module);
            exitfunc = PyDict_GetItemString(dict, "_run_exitfuncs");
        }
        else
            PyErr_Clear();

        if (exitfunc)
        {
            PyObject *res = NULL;
            Py_INCREF(exitfunc);
            res = PyObject_CallObject(exitfunc, (PyObject *)NULL);

            if (res == NULL)
            {
                PyObject *m = NULL;
                PyObject *tb_result = NULL;

                PyObject *type = NULL;
                PyObject *value = NULL;
                PyObject *traceback = NULL;

                if (PyErr_ExceptionMatches(PyExc_SystemExit))
                    wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server, WSGI_APLOGNO(0130) "SystemExit exception raised "
                                                                                        "by Python atexit/sys.exitfunc; "
                                                                                        "ignored.");
                else
                    wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server, WSGI_APLOGNO(0131) "Exception occurred within "
                                                                                        "Python atexit/sys.exitfunc "
                                                                                        "during shutdown.");

                PyErr_Fetch(&type, &value, &traceback);
                PyErr_NormalizeException(&type, &value, &traceback);

                if (!value)
                {
                    value = Py_None;
                    Py_INCREF(value);
                }

                m = PyImport_ImportModule("traceback");

                if (m)
                {
                    PyObject *d = NULL;
                    PyObject *o = NULL;
                    d = PyModule_GetDict(m);
                    o = PyDict_GetItemString(d, "print_exception");
                    if (o)
                    {
                        PyObject *log = NULL;
                        PyObject *tb_args = NULL;
                        PyObject *tb_kwargs = NULL;
                        Py_INCREF(o);
                        log = newLogObject(NULL, APLOG_ERR, NULL, 0);
                        if (log)
                        {
                            tb_args = Py_BuildValue("(O)", value);
                            tb_kwargs = Py_BuildValue("{s:O}", "file", log);
                        }
                        if (tb_args && tb_kwargs)
                            tb_result = PyObject_Call(o, tb_args, tb_kwargs);
                        Py_XDECREF(tb_kwargs);
                        Py_XDECREF(tb_args);
                        Py_XDECREF(log);
                        Py_DECREF(o);
                    }
                }

                if (!tb_result)
                {
                    /*
                     * If can't output exception and traceback then
                     * use PyErr_Print to dump out details of the
                     * exception. For SystemExit though if we do
                     * that the process will actually be terminated
                     * so can only clear the exception information
                     * and keep going.
                     */

                    PyErr_Restore(type, value, traceback);

                    if (!PyErr_ExceptionMatches(PyExc_SystemExit))
                    {
                        PyErr_Print();
                        PyErr_Clear();
                    }
                    else
                    {
                        PyErr_Clear();
                    }
                }
                else
                {
                    Py_XDECREF(type);
                    Py_XDECREF(value);
                    Py_XDECREF(traceback);
                }

                Py_XDECREF(tb_result);

                Py_XDECREF(m);
            }

            Py_XDECREF(res);
            Py_DECREF(exitfunc);
        }

        Py_XDECREF(module);

        /* Delete remaining thread states. */

        PyThreadState_Swap(NULL);

        tstate = PyInterpreterState_ThreadHead(tstate->interp);

        while (tstate)
        {
            tstate_next = PyThreadState_Next(tstate);
            if (tstate != tstate_save)
            {
                PyThreadState_Swap(tstate);
                PyThreadState_Clear(tstate);
                PyThreadState_Swap(NULL);
                PyThreadState_Delete(tstate);
            }
            tstate = tstate_next;
        }
        tstate = tstate_save;

        PyThreadState_Swap(tstate);
    }

    return result;
}

/* ------------------------------------------------------------------------- */

/*
 * PyType_Spec for the ShutdownInterpreter heap type. The two
 * slots with non-default behaviour are tp_dealloc (releases the
 * wrapped reference) and tp_call (the shutdown driver);
 * everything else falls back to the framework defaults.
 *
 * tp_name is "mod_wsgi.ShutdownInterpreter" so error messages
 * and repr() output identify where the type comes from. The
 * type is not exposed as a module attribute; instances are
 * installed directly into the threading module's _shutdown slot
 * from C.
 */

static PyType_Slot ShutdownInterpreter_slots[] = {
    {Py_tp_dealloc, ShutdownInterpreter_dealloc},
    {Py_tp_call, ShutdownInterpreter_call},
    {0, NULL},
};

static PyType_Spec ShutdownInterpreter_spec = {
    .name = "mod_wsgi.ShutdownInterpreter",
    .basicsize = sizeof(ShutdownInterpreterObject),
    .itemsize = 0,
    .flags = Py_TPFLAGS_DEFAULT,
    .slots = ShutdownInterpreter_slots,
};

/* ------------------------------------------------------------------------- */

int wsgi_shutdown_init(PyObject *module)
{
    WSGIModuleState *state = NULL;
    PyObject *type = NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state)
        return -1;

    type = PyType_FromModuleAndSpec(module, &ShutdownInterpreter_spec, NULL);
    if (!type)
        return -1;

    state->ShutdownInterpreter_Type = (PyTypeObject *)type;

    return 0;
}

/* ------------------------------------------------------------------------- */

ShutdownInterpreterObject *newShutdownInterpreterObject(PyObject *wrapped)
{
    PyObject *module = NULL;
    WSGIModuleState *state = NULL;
    PyTypeObject *type = NULL;
    ShutdownInterpreterObject *self = NULL;

    /*
     * Find the embedded mod_wsgi module for the current
     * interpreter and pull the ShutdownInterpreter heap type
     * out of its state. Returns NULL with a clear error if the
     * module is not in sys.modules or its state has not been
     * initialised; either indicates an init ordering bug.
     */

    module = PyImport_ImportModule("mod_wsgi");
    if (!module)
        return NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state || !state->ShutdownInterpreter_Type)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "ShutdownInterpreter type not initialised for the "
                        "current interpreter; newShutdownInterpreterObject() "
                        "called before the embedded mod_wsgi module's "
                        "exec slot ran");
        Py_DECREF(module);
        return NULL;
    }

    type = state->ShutdownInterpreter_Type;

    self = (ShutdownInterpreterObject *)type->tp_alloc(type, 0);
    Py_DECREF(module);

    if (!self)
        return NULL;

    Py_INCREF(wrapped);
    self->wrapped = wrapped;

    return self;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
