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

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* ------------------------------------------------------------------------- */

static void ShutdownInterpreter_dealloc(ShutdownInterpreterObject *self)
{
    Py_DECREF(self->wrapped);
}

ShutdownInterpreterObject *newShutdownInterpreterObject(
    PyObject *wrapped)
{
    ShutdownInterpreterObject *self = NULL;

    self = PyObject_New(ShutdownInterpreterObject, &ShutdownInterpreter_Type);
    if (self == NULL)
        return NULL;

    Py_INCREF(wrapped);
    self->wrapped = wrapped;

    return self;
}

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
            PySys_SetObject("exitfunc", (PyObject *)NULL);
            res = PyObject_CallObject(exitfunc, (PyObject *)NULL);

            if (res == NULL)
            {
                PyObject *m = NULL;
                PyObject *tb_result = NULL;

                PyObject *type = NULL;
                PyObject *value = NULL;
                PyObject *traceback = NULL;

                if (PyErr_ExceptionMatches(PyExc_SystemExit))
                {
                    Py_BEGIN_ALLOW_THREADS
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                                     "mod_wsgi (pid=%d): SystemExit exception "
                                     "raised by exit functions ignored.",
                                     getpid());
                    Py_END_ALLOW_THREADS
                }
                else
                {
                    Py_BEGIN_ALLOW_THREADS
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                                     "mod_wsgi (pid=%d): Exception occurred within "
                                     "exit functions.",
                                     getpid());
                    Py_END_ALLOW_THREADS
                }

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
                        tb_args = Py_BuildValue("(O)", value);
                        tb_kwargs = Py_BuildValue("{s:O}", "file", log);
                        tb_result = PyObject_Call(o, tb_args, tb_kwargs);
                        Py_DECREF(tb_kwargs);
                        Py_DECREF(tb_args);
                        Py_DECREF(log);
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

PyTypeObject ShutdownInterpreter_Type = {
    PyVarObject_HEAD_INIT(NULL, 0) "mod_wsgi.ShutdownInterpreter", /*tp_name*/
    sizeof(ShutdownInterpreterObject),                             /*tp_basicsize*/
    0,                                                             /*tp_itemsize*/
    /* methods */
    (destructor)ShutdownInterpreter_dealloc, /*tp_dealloc*/
    0,                                       /*tp_print*/
    0,                                       /*tp_getattr*/
    0,                                       /*tp_setattr*/
    0,                                       /*tp_compare*/
    0,                                       /*tp_repr*/
    0,                                       /*tp_as_number*/
    0,                                       /*tp_as_sequence*/
    0,                                       /*tp_as_mapping*/
    0,                                       /*tp_hash*/
    (ternaryfunc)ShutdownInterpreter_call,   /*tp_call*/
    0,                                       /*tp_str*/
    0,                                       /*tp_getattro*/
    0,                                       /*tp_setattro*/
    0,                                       /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,                      /*tp_flags*/
    0,                                       /*tp_doc*/
    0,                                       /*tp_traverse*/
    0,                                       /*tp_clear*/
    0,                                       /*tp_richcompare*/
    0,                                       /*tp_weaklistoffset*/
    0,                                       /*tp_iter*/
    0,                                       /*tp_iternext*/
    0,                                       /*tp_methods*/
    0,                                       /*tp_members*/
    0,                                       /*tp_getset*/
    0,                                       /*tp_base*/
    0,                                       /*tp_dict*/
    0,                                       /*tp_descr_get*/
    0,                                       /*tp_descr_set*/
    0,                                       /*tp_dictoffset*/
    0,                                       /*tp_init*/
    0,                                       /*tp_alloc*/
    0,                                       /*tp_new*/
    0,                                       /*tp_free*/
    0,                                       /*tp_is_gc*/
};

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
