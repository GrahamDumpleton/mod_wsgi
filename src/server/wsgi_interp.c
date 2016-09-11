/* ------------------------------------------------------------------------- */

/*
 * Copyright 2007-2016 GRAHAM DUMPLETON
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

#include "wsgi_interp.h"

#include "wsgi_version.h"

#include "wsgi_apache.h"
#include "wsgi_server.h"
#include "wsgi_logger.h"
#include "wsgi_restrict.h"
#include "wsgi_stream.h"
#include "wsgi_metrics.h"
#include "wsgi_daemon.h"
#include "wsgi_metrics.h"
#include "wsgi_thread.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef WIN32
#include <pwd.h>
#endif

/* ------------------------------------------------------------------------- */

/* Function to restrict access to use of signal(). */

static void SignalIntercept_dealloc(SignalInterceptObject *self)
{
    Py_DECREF(self->wrapped);
}

static SignalInterceptObject *newSignalInterceptObject(PyObject *wrapped)
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
                 "signal %d ignored.", getpid(), n);
    Py_END_ALLOW_THREADS

    m = PyImport_ImportModule("traceback");

    if (m) {
        PyObject *d = NULL;
        PyObject *o = NULL;
        d = PyModule_GetDict(m);
        o = PyDict_GetItemString(d, "print_stack");
        if (o) {
            PyObject *log = NULL;
            PyObject *args = NULL;
            PyObject *result = NULL;
            Py_INCREF(o);
            log = newLogObject(NULL, APLOG_WARNING, NULL, 0);
            args = Py_BuildValue("(OOO)", Py_None, Py_None, log);
            result = PyEval_CallObject(o, args);
            Py_XDECREF(result);
            Py_DECREF(args);
            Py_DECREF(log);
            Py_DECREF(o);
        }
    }

    Py_XDECREF(m);

    Py_INCREF(h);

    return h;
}

PyTypeObject SignalIntercept_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "mod_wsgi.SignalIntercept",  /*tp_name*/
    sizeof(SignalInterceptObject), /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)SignalIntercept_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    (ternaryfunc)SignalIntercept_call, /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    0,                      /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

/* Wrapper around Python interpreter instances. */

const char *wsgi_python_path = NULL;
const char *wsgi_python_eggs = NULL;

#if PY_MAJOR_VERSION > 3 || (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 4)
static void ShutdownInterpreter_dealloc(ShutdownInterpreterObject *self)
{
    Py_DECREF(self->wrapped);
}

static ShutdownInterpreterObject *newShutdownInterpreterObject(
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

    if (result) {
        PyObject *module = NULL;
        PyObject *exitfunc = NULL;

        PyThreadState *tstate = PyThreadState_Get();

        PyThreadState *tstate_save = tstate;
        PyThreadState *tstate_next = NULL;

#if PY_MAJOR_VERSION >= 3
        module = PyImport_ImportModule("atexit");

        if (module) {
            PyObject *dict = NULL;

            dict = PyModule_GetDict(module);
            exitfunc = PyDict_GetItemString(dict, "_run_exitfuncs");
        }
        else
            PyErr_Clear();
#else
        exitfunc = PySys_GetObject("exitfunc");
#endif

        if (exitfunc) {
            PyObject *res = NULL;
            Py_INCREF(exitfunc);
            PySys_SetObject("exitfunc", (PyObject *)NULL);
            res = PyEval_CallObject(exitfunc, (PyObject *)NULL);

            if (res == NULL) {
                PyObject *m = NULL;
                PyObject *result = NULL;

                PyObject *type = NULL;
                PyObject *value = NULL;
                PyObject *traceback = NULL;

                if (PyErr_ExceptionMatches(PyExc_SystemExit)) {
                    Py_BEGIN_ALLOW_THREADS
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): SystemExit exception "
                                 "raised by exit functions ignored.", getpid());
                    Py_END_ALLOW_THREADS
                }
                else {
                    Py_BEGIN_ALLOW_THREADS
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Exception occurred within "
                                 "exit functions.", getpid());
                    Py_END_ALLOW_THREADS
                }

                PyErr_Fetch(&type, &value, &traceback);
                PyErr_NormalizeException(&type, &value, &traceback);

                if (!value) {
                    value = Py_None;
                    Py_INCREF(value);
                }

                if (!traceback) {
                    traceback = Py_None;
                    Py_INCREF(traceback);
                }

                m = PyImport_ImportModule("traceback");

                if (m) {
                    PyObject *d = NULL;
                    PyObject *o = NULL;
                    d = PyModule_GetDict(m);
                    o = PyDict_GetItemString(d, "print_exception");
                    if (o) {
                        PyObject *log = NULL;
                        PyObject *args = NULL;
                        Py_INCREF(o);
                        log = newLogObject(NULL, APLOG_ERR, NULL, 0);
                        args = Py_BuildValue("(OOOOO)", type, value,
                                             traceback, Py_None, log);
                        result = PyEval_CallObject(o, args);
                        Py_DECREF(args);
                        Py_DECREF(log);
                        Py_DECREF(o);
                    }
                }

                if (!result) {
                    /*
                     * If can't output exception and traceback then
                     * use PyErr_Print to dump out details of the
                     * exception. For SystemExit though if we do
                     * that the process will actually be terminated
                     * so can only clear the exception information
                     * and keep going.
                     */

                    PyErr_Restore(type, value, traceback);

                    if (!PyErr_ExceptionMatches(PyExc_SystemExit)) {
                        PyErr_Print();
                        PyErr_Clear();
                    }
                    else {
                        PyErr_Clear();
                    }
                }
                else {
                    Py_XDECREF(type);
                    Py_XDECREF(value);
                    Py_XDECREF(traceback);
                }

                Py_XDECREF(result);

                Py_XDECREF(m);
            }

            Py_XDECREF(res);
            Py_DECREF(exitfunc);
        }

        Py_XDECREF(module);

        /* Delete remaining thread states. */

        PyThreadState_Swap(NULL);

        tstate = tstate->interp->tstate_head;
        while (tstate) {
            tstate_next = tstate->next;
            if (tstate != tstate_save) {
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
    PyVarObject_HEAD_INIT(NULL, 0)
    "mod_wsgi.ShutdownInterpreter",  /*tp_name*/
    sizeof(ShutdownInterpreterObject), /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)ShutdownInterpreter_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    (ternaryfunc)ShutdownInterpreter_call, /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    0,                      /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};
#endif

PyTypeObject Interpreter_Type;

InterpreterObject *newInterpreterObject(const char *name)
{
    PyInterpreterState *interp = NULL;
    InterpreterObject *self = NULL;
    PyThreadState *tstate = NULL;
    PyThreadState *save_tstate = NULL;
    PyObject *module = NULL;
    PyObject *object = NULL;
    PyObject *item = NULL;

    int max_threads = 0;
    int max_processes = 0;
    int is_threaded = 0;
    int is_forked = 0;

    const char *str = NULL;

    /* Create handle for interpreter and local data. */

    self = PyObject_New(InterpreterObject, &Interpreter_Type);
    if (self == NULL)
        return NULL;

    /*
     * If interpreter not named, then we want to bind
     * to the first Python interpreter instance created.
     * Give this interpreter an empty string as name.
     */

    if (!name) {
        interp = PyInterpreterState_Head();
        while (interp->next)
            interp = interp->next;

        name = "";
    }

    /* Save away the interpreter name. */

    self->name = strdup(name);

    if (interp) {
        /*
         * Interpreter provided to us so will not be
         * responsible for deleting it later. This will
         * be the case for the main Python interpreter.
         */

        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Attach interpreter '%s'.",
                     getpid(), name);

        self->interp = interp;
        self->owner = 0;
    }
    else {
        /*
         * Remember active thread state so can restore
         * it. This is actually the thread state
         * associated with simplified GIL state API.
         */

        save_tstate = PyThreadState_Swap(NULL);

        /*
         * Create the interpreter. If creation of the
         * interpreter fails it will restore the
         * existing active thread state for us so don't
         * need to worry about it in that case.
         */

        tstate = Py_NewInterpreter();

        if (!tstate) {
            PyErr_SetString(PyExc_RuntimeError, "Py_NewInterpreter() failed");

            Py_DECREF(self);

            return NULL;
        }

        Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Create interpreter '%s'.",
                     getpid(), name);
        Py_END_ALLOW_THREADS

        self->interp = tstate->interp;
        self->owner = 1;

        /*
         * We need to replace threading._shutdown() with our own
         * function which will also call atexit callbacks after
         * threads are shutdown to cope with fact that Python
         * itself doesn't call the atexit callbacks in sub
         * interpreters.
         */

#if PY_MAJOR_VERSION > 3 || (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 4)
        module = PyImport_ImportModule("threading");

        if (module) {
            PyObject *dict = NULL;
            PyObject *func = NULL;

            dict = PyModule_GetDict(module);
            func = PyDict_GetItemString(dict, "_shutdown");

            if (func) {
                PyObject *wrapper = NULL;

                wrapper = (PyObject *)newShutdownInterpreterObject(func);
                PyDict_SetItemString(dict, "_shutdown", wrapper);
                Py_DECREF(wrapper);
            }
        }

        Py_XDECREF(module);
#endif
    }

    /*
     * Install restricted objects for STDIN and STDOUT,
     * or log object for STDOUT as appropriate. Don't do
     * this if not running on Win32 and we believe we
     * are running in single process mode, otherwise
     * it prevents use of interactive debuggers such as
     * the 'pdb' module.
     */

    object = newLogObject(NULL, APLOG_ERR, "stderr", 1);
    PySys_SetObject("stderr", object);
    Py_DECREF(object);

#ifndef WIN32
    if (wsgi_parent_pid != getpid()) {
#endif
        if (wsgi_server_config->restrict_stdout == 1) {
            object = (PyObject *)newRestrictedObject("sys.stdout");
            PySys_SetObject("stdout", object);
            Py_DECREF(object);
        }
        else {
            object = newLogObject(NULL, APLOG_ERR, "stdout", 1);
            PySys_SetObject("stdout", object);
            Py_DECREF(object);
        }

        if (wsgi_server_config->restrict_stdin == 1) {
            object = (PyObject *)newRestrictedObject("sys.stdin");
            PySys_SetObject("stdin", object);
            Py_DECREF(object);
        }
#ifndef WIN32
    }
#endif

    /*
     * Set sys.argv to one element list to fake out
     * modules that look there for Python command
     * line arguments as appropriate.
     */

    object = PyList_New(0);
#if PY_MAJOR_VERSION >= 3
    item = PyUnicode_FromString("mod_wsgi");
#else
    item = PyString_FromString("mod_wsgi");
#endif
    PyList_Append(object, item);
    PySys_SetObject("argv", object);
    Py_DECREF(item);
    Py_DECREF(object);

    /*
     * Install intercept for signal handler registration
     * if appropriate.
     */

    if (wsgi_server_config->restrict_signal != 0) {

        module = PyImport_ImportModule("signal");

        if (module) {
            PyObject *dict = NULL;
            PyObject *func = NULL;

            dict = PyModule_GetDict(module);
            func = PyDict_GetItemString(dict, "signal");

            if (func) {
                PyObject *wrapper = NULL;

                wrapper = (PyObject *)newSignalInterceptObject(func);
                PyDict_SetItemString(dict, "signal", wrapper);
                Py_DECREF(wrapper);
            }
        }

        Py_XDECREF(module);
    }

    /*
     * Force loading of codecs into interpreter. This has to be
     * done as not otherwise done in sub interpreters and if not
     * done, code running in sub interpreters can fail on some
     * platforms if a unicode string is added in sys.path and an
     * import then done.
     */

    item = PyCodec_Encoder("ascii");
    Py_XDECREF(item);

    /*
     * If running in daemon process, override as appropriate
     * the USER, USERNAME or LOGNAME environment  variables
     * so that they match the user that the process is running
     * as. Need to do this else we inherit the value from the
     * Apache parent process which is likely wrong as will be
     * root or the user than ran sudo when Apache started.
     * Can't update these for normal Apache child processes
     * as that would change the expected environment of other
     * Apache modules.
     */

#ifndef WIN32
    if (wsgi_daemon_pool) {
        module = PyImport_ImportModule("os");

        if (module) {
            PyObject *dict = NULL;
            PyObject *key = NULL;
            PyObject *value = NULL;

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "environ");

            if (object) {
                struct passwd *pwent;

                pwent = getpwuid(geteuid());

                if (pwent && getenv("USER")) {
#if PY_MAJOR_VERSION >= 3
                    key = PyUnicode_FromString("USER");
                    value = PyUnicode_Decode(pwent->pw_name,
                                             strlen(pwent->pw_name),
                                             Py_FileSystemDefaultEncoding,
                                             "surrogateescape");
#else
                    key = PyString_FromString("USER");
                    value = PyString_FromString(pwent->pw_name);
#endif

                    PyObject_SetItem(object, key, value);

                    Py_DECREF(key);
                    Py_DECREF(value);
                }

                if (pwent && getenv("USERNAME")) {
#if PY_MAJOR_VERSION >= 3
                    key = PyUnicode_FromString("USERNAME");
                    value = PyUnicode_Decode(pwent->pw_name,
                                             strlen(pwent->pw_name),
                                             Py_FileSystemDefaultEncoding,
                                             "surrogateescape");
#else
                    key = PyString_FromString("USERNAME");
                    value = PyString_FromString(pwent->pw_name);
#endif

                    PyObject_SetItem(object, key, value);

                    Py_DECREF(key);
                    Py_DECREF(value);
                }

                if (pwent && getenv("LOGNAME")) {
#if PY_MAJOR_VERSION >= 3
                    key = PyUnicode_FromString("LOGNAME");
                    value = PyUnicode_Decode(pwent->pw_name,
                                             strlen(pwent->pw_name),
                                             Py_FileSystemDefaultEncoding,
                                             "surrogateescape");
#else
                    key = PyString_FromString("LOGNAME");
                    value = PyString_FromString(pwent->pw_name);
#endif

                    PyObject_SetItem(object, key, value);

                    Py_DECREF(key);
                    Py_DECREF(value);
                }
            }

            Py_DECREF(module);
        }
    }
#endif

    /*
     * If running in daemon process, override HOME environment
     * variable so that is matches the home directory of the
     * user that the process is running as. Need to do this as
     * Apache will inherit HOME from root user or user that ran
     * sudo and started Apache and this would be wrong. Can't
     * update HOME for normal Apache child processes as that
     * would change the expected environment of other Apache
     * modules.
     */

#ifndef WIN32
    if (wsgi_daemon_pool) {
        module = PyImport_ImportModule("os");

        if (module) {
            PyObject *dict = NULL;
            PyObject *key = NULL;
            PyObject *value = NULL;

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "environ");

            if (object) {
                struct passwd *pwent;

                pwent = getpwuid(geteuid());

                if (pwent) {
#if PY_MAJOR_VERSION >= 3
                    key = PyUnicode_FromString("HOME");
                    value = PyUnicode_Decode(pwent->pw_dir,
                                             strlen(pwent->pw_dir),
                                             Py_FileSystemDefaultEncoding,
                                             "surrogateescape");
#else
                    key = PyString_FromString("HOME");
                    value = PyString_FromString(pwent->pw_dir);
#endif

                    PyObject_SetItem(object, key, value);

                    Py_DECREF(key);
                    Py_DECREF(value);
                }
            }

            Py_DECREF(module);
        }
    }
#endif

    /*
     * Explicitly override the PYTHON_EGG_CACHE variable if it
     * was defined by Apache configuration. For embedded processes
     * this would have been done by using WSGIPythonEggs directive.
     * For daemon processes the 'python-eggs' option to the
     * WSGIDaemonProcess directive would have needed to be used.
     */

    if (!wsgi_daemon_pool)
        wsgi_python_eggs = wsgi_server_config->python_eggs;

    if (wsgi_python_eggs) {
        module = PyImport_ImportModule("os");

        if (module) {
            PyObject *dict = NULL;
            PyObject *key = NULL;
            PyObject *value = NULL;

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "environ");

            if (object) {
#if PY_MAJOR_VERSION >= 3
                key = PyUnicode_FromString("PYTHON_EGG_CACHE");
                value = PyUnicode_Decode(wsgi_python_eggs,
                                         strlen(wsgi_python_eggs),
                                         Py_FileSystemDefaultEncoding,
                                         "surrogateescape");
#else
                key = PyString_FromString("PYTHON_EGG_CACHE");
                value = PyString_FromString(wsgi_python_eggs);
#endif

                PyObject_SetItem(object, key, value);

                Py_DECREF(key);
                Py_DECREF(value);
            }

            Py_DECREF(module);
        }
    }

    /*
     * Install user defined Python module search path. This is
     * added using site.addsitedir() so that any Python .pth
     * files are opened and additional directories so defined
     * are added to default Python search path as well. This
     * allows virtual Python environments to work. Note that
     * site.addsitedir() adds new directories at the end of
     * sys.path when they really need to be added in order at
     * the start. We therefore need to do a fiddle and shift
     * any newly added directories to the start of sys.path.
     */

    if (!wsgi_daemon_pool)
        wsgi_python_path = wsgi_server_config->python_path;

    module = PyImport_ImportModule("site");

    if (wsgi_python_path && *wsgi_python_path) {
        PyObject *path = NULL;

        path = PySys_GetObject("path");

        if (module && path) {
            PyObject *dict = NULL;

            PyObject *old = NULL;
            PyObject *new = NULL;
            PyObject *tmp = NULL;

            PyObject *item = NULL;

            int i = 0;

            old = PyList_New(0);
            new = PyList_New(0);
            tmp = PyList_New(0);

            for (i=0; i<PyList_Size(path); i++)
                PyList_Append(old, PyList_GetItem(path, i));

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "addsitedir");

            if (object) {
                const char *start;
                const char *end;
                const char *value;

                PyObject *item;
                PyObject *args;

                PyObject *result = NULL;

                Py_INCREF(object);

                start = wsgi_python_path;
                end = strchr(start, DELIM);

                if (end) {
#if PY_MAJOR_VERSION >= 3
                    item = PyUnicode_DecodeFSDefaultAndSize(start, end-start);
                    value = PyUnicode_AsUTF8(item);
#else
                    item = PyString_FromStringAndSize(start, end-start);
                    value = PyString_AsString(item);
#endif
                    start = end+1;

                    Py_BEGIN_ALLOW_THREADS
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Adding '%s' to "
                                 "path.", getpid(), value);
                    Py_END_ALLOW_THREADS

                    args = Py_BuildValue("(O)", item);
                    result = PyEval_CallObject(object, args);

                    if (!result) {
                        Py_BEGIN_ALLOW_THREADS
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                                     "mod_wsgi (pid=%d): Call to "
                                     "'site.addsitedir()' failed for '%s', "
                                     "stopping.", getpid(), value);
                        Py_END_ALLOW_THREADS
                    }

                    Py_XDECREF(result);
                    Py_DECREF(item);
                    Py_DECREF(args);

                    end = strchr(start, DELIM);

                    while (result && end) {
#if PY_MAJOR_VERSION >= 3
                        item = PyUnicode_DecodeFSDefaultAndSize(start,
                                end-start);
                        value = PyUnicode_AsUTF8(item);
#else
                        item = PyString_FromStringAndSize(start, end-start);
                        value = PyString_AsString(item);
#endif
                        start = end+1;

                        Py_BEGIN_ALLOW_THREADS
                        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                     "mod_wsgi (pid=%d): Adding '%s' to "
                                     "path.", getpid(), value);
                        Py_END_ALLOW_THREADS

                        args = Py_BuildValue("(O)", item);
                        result = PyEval_CallObject(object, args);

                        if (!result) {
                            Py_BEGIN_ALLOW_THREADS
                            ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                                         wsgi_server, "mod_wsgi (pid=%d): "
                                         "Call to 'site.addsitedir()' failed "
                                         "for '%s', stopping.",
                                         getpid(), value);
                            Py_END_ALLOW_THREADS
                        }

                        Py_XDECREF(result);
                        Py_DECREF(item);
                        Py_DECREF(args);

                        end = strchr(start, DELIM);
                    }
                }

#if PY_MAJOR_VERSION >= 3
                item = PyUnicode_DecodeFSDefault(start);
                value = PyUnicode_AsUTF8(item);
#else
                item = PyString_FromString(start);
                value = PyString_AsString(item);
#endif

                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Adding '%s' to "
                             "path.", getpid(), value);
                Py_END_ALLOW_THREADS

                args = Py_BuildValue("(O)", item);
                result = PyEval_CallObject(object, args);

                if (!result) {
                    Py_BEGIN_ALLOW_THREADS
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Call to "
                                 "'site.addsitedir()' failed for '%s'.",
                                 getpid(), start);
                    Py_END_ALLOW_THREADS
                }

                Py_XDECREF(result);
                Py_XDECREF(item);
                Py_DECREF(args);

                Py_DECREF(object);
            }
            else {
                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Unable to locate "
                             "'site.addsitedir()'.", getpid());
                Py_END_ALLOW_THREADS
            }

            for (i=0; i<PyList_Size(path); i++)
                PyList_Append(tmp, PyList_GetItem(path, i));

            for (i=0; i<PyList_Size(tmp); i++) {
                item = PyList_GetItem(tmp, i);
                if (!PySequence_Contains(old, item)) {
                    long index = PySequence_Index(path, item);
                    PyList_Append(new, item);
                    if (index != -1)
                        PySequence_DelItem(path, index); 
                }
            }

            PyList_SetSlice(path, 0, 0, new);

            Py_DECREF(old);
            Py_DECREF(new);
            Py_DECREF(tmp);
        }
        else {
            if (!module) {
                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Unable to import 'site' "
                             "module.", getpid());
                Py_END_ALLOW_THREADS
            }

            if (!path) {
                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Lookup for 'sys.path' "
                             "failed.", getpid());
                Py_END_ALLOW_THREADS
            }
        }
    }

    /*
     * If running in daemon mode and a home directory was set then
     * insert the home directory at the start of the Python module
     * search path. This makes things similar to when using the Python
     * interpreter on the command line with a script.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process && wsgi_daemon_process->group->home) {
        PyObject *path = NULL;
        const char *home = wsgi_daemon_process->group->home;

        path = PySys_GetObject("path");

        if (module && path) {
            PyObject *item;

#if PY_MAJOR_VERSION >= 3
            item = PyUnicode_Decode(home, strlen(home),
                                    Py_FileSystemDefaultEncoding,
                                    "surrogateescape");
#else
            item = PyString_FromString(home);
#endif
            PyList_Insert(path, 0, item);
            Py_DECREF(item);
        }
    }
#endif

    Py_XDECREF(module);

    /*
     * Create 'mod_wsgi' Python module. We first try and import an
     * external Python module of the same name. The intent is
     * that this external module would provide optional features
     * implementable using pure Python code. Don't want to
     * include them in the main Apache mod_wsgi package as that
     * complicates that package and also wouldn't allow them to
     * be released to a separate schedule. It is easier for
     * people to replace Python modules package with a new
     * version than it is to replace Apache module package.
     */

    module = PyImport_ImportModule("mod_wsgi");

    if (!module) {
        PyObject *modules = NULL;

        modules = PyImport_GetModuleDict();
        module = PyDict_GetItemString(modules, "mod_wsgi");

        if (module) {
            PyErr_Print();

            PyDict_DelItemString(modules, "mod_wsgi");
        }

        PyErr_Clear();

        module = PyImport_AddModule("mod_wsgi");

        Py_INCREF(module);
    }
    else if (!*name) {
        Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Imported 'mod_wsgi'.",
                     getpid());
        Py_END_ALLOW_THREADS
    }

    /*
     * Add Apache module version information to the Python
     * 'mod_wsgi' module.
     */

    PyModule_AddObject(module, "version", Py_BuildValue("(iii)",
                       MOD_WSGI_MAJORVERSION_NUMBER,
                       MOD_WSGI_MINORVERSION_NUMBER,
                       MOD_WSGI_MICROVERSION_NUMBER));

    /* Add type object for file wrapper. */

    Py_INCREF(&Stream_Type);
    PyModule_AddObject(module, "FileWrapper", (PyObject *)&Stream_Type);

    /*
     * Add information about process group and application
     * group to the Python 'mod_wsgi' module.
     */

#if PY_MAJOR_VERSION >= 3
    PyModule_AddObject(module, "process_group",
                       PyUnicode_DecodeLatin1(wsgi_daemon_group,
                       strlen(wsgi_daemon_group), NULL));
    PyModule_AddObject(module, "application_group",
                       PyUnicode_DecodeLatin1(name, strlen(name), NULL));
#else
    PyModule_AddObject(module, "process_group",
                       PyString_FromString(wsgi_daemon_group));
    PyModule_AddObject(module, "application_group",
                       PyString_FromString(name));
#endif

    /*
     * Add information about number of processes and threads
     * available to the WSGI application to the 'mod_wsgi' module.
     * When running in embedded mode, this will be the same as
     * what the 'apache' module records for Apache itself.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process) {
        object = PyLong_FromLong(wsgi_daemon_process->group->processes);
        PyModule_AddObject(module, "maximum_processes", object);

        object = PyLong_FromLong(wsgi_daemon_process->group->threads);
        PyModule_AddObject(module, "threads_per_process", object);
    }
    else {
        ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded);
        if (is_threaded != AP_MPMQ_NOT_SUPPORTED) {
            ap_mpm_query(AP_MPMQ_MAX_THREADS, &max_threads);
        }
        ap_mpm_query(AP_MPMQ_IS_FORKED, &is_forked);
        if (is_forked != AP_MPMQ_NOT_SUPPORTED) {
            ap_mpm_query(AP_MPMQ_MAX_DAEMON_USED, &max_processes);
            if (max_processes == -1) {
                ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &max_processes);
            }
        }

        max_threads = (max_threads <= 0) ? 1 : max_threads;
        max_processes = (max_processes <= 0) ? 1 : max_processes;

        object = PyLong_FromLong(max_processes);
        PyModule_AddObject(module, "maximum_processes", object);

        object = PyLong_FromLong(max_threads);
        PyModule_AddObject(module, "threads_per_process", object);
    }
#else
    ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded);
    if (is_threaded != AP_MPMQ_NOT_SUPPORTED) {
        ap_mpm_query(AP_MPMQ_MAX_THREADS, &max_threads);
    }
    ap_mpm_query(AP_MPMQ_IS_FORKED, &is_forked);
    if (is_forked != AP_MPMQ_NOT_SUPPORTED) {
        ap_mpm_query(AP_MPMQ_MAX_DAEMON_USED, &max_processes);
        if (max_processes == -1) {
            ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &max_processes);
        }
    }

    max_threads = (max_threads <= 0) ? 1 : max_threads;
    max_processes = (max_processes <= 0) ? 1 : max_processes;

    object = PyLong_FromLong(max_processes);
    PyModule_AddObject(module, "maximum_processes", object);

    object = PyLong_FromLong(max_threads);
    PyModule_AddObject(module, "threads_per_process", object);
#endif

    PyModule_AddObject(module, "server_metrics", PyCFunction_New(
                       &wsgi_server_metrics_method[0], NULL));

    PyModule_AddObject(module, "process_metrics", PyCFunction_New(
                       &wsgi_process_metrics_method[0], NULL));

    PyModule_AddObject(module, "subscribe_events", PyCFunction_New(
                       &wsgi_process_events_method[0], NULL));

    PyModule_AddObject(module, "event_callbacks", PyList_New(0));

    PyModule_AddObject(module, "request_data", PyCFunction_New(
                       &wsgi_request_data_method[0], NULL));

    /* Done with the 'mod_wsgi' module. */

    Py_DECREF(module);

    /*
     * Create 'apache' Python module. If this is not a daemon
     * process and it is the first interpreter created by
     * Python, we first try and import an external Python module
     * of the same name. The intent is that this external module
     * would provide the SWIG bindings for the internal Apache
     * APIs. Only support use of such bindings in the first
     * interpreter created due to threading issues in SWIG
     * generated.
     */

    module = NULL;

    if (!wsgi_daemon_pool) {
        module = PyImport_ImportModule("apache");

        if (!module) {
            PyObject *modules = NULL;

            modules = PyImport_GetModuleDict();
            module = PyDict_GetItemString(modules, "apache");

            if (module) {
                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Unable to import "
                             "'apache' extension module.", getpid());
                Py_END_ALLOW_THREADS

                PyErr_Print();

                PyDict_DelItemString(modules, "apache");

                module = NULL;
            }

            PyErr_Clear();
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Imported 'apache'.",
                         getpid());
            Py_END_ALLOW_THREADS
        }
    }

    if (!module) {
        module = PyImport_AddModule("apache");

        Py_INCREF(module);
    }

    /*
     * Add Apache version information to the Python 'apache'
     * module.
     */

    PyModule_AddObject(module, "version", Py_BuildValue("(iii)",
                       AP_SERVER_MAJORVERSION_NUMBER,
                       AP_SERVER_MINORVERSION_NUMBER,
                       AP_SERVER_PATCHLEVEL_NUMBER));

    /*
     * Add information about the Apache MPM configuration and
     * the number of processes and threads available.
     */

    ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded);
    if (is_threaded != AP_MPMQ_NOT_SUPPORTED) {
        ap_mpm_query(AP_MPMQ_MAX_THREADS, &max_threads);
    }
    ap_mpm_query(AP_MPMQ_IS_FORKED, &is_forked);
    if (is_forked != AP_MPMQ_NOT_SUPPORTED) {
        ap_mpm_query(AP_MPMQ_MAX_DAEMON_USED, &max_processes);
        if (max_processes == -1) {
            ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &max_processes);
        }
    }

    max_threads = (max_threads <= 0) ? 1 : max_threads;
    max_processes = (max_processes <= 0) ? 1 : max_processes;

    object = PyLong_FromLong(max_processes);
    PyModule_AddObject(module, "maximum_processes", object);

    object = PyLong_FromLong(max_threads);
    PyModule_AddObject(module, "threads_per_process", object);

#if AP_MODULE_MAGIC_AT_LEAST(20051115,4)
    str = ap_get_server_description();
#else
    str = ap_get_server_version();
#endif
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(str, strlen(str), NULL);
#else
    object = PyString_FromString(str);
#endif
    PyModule_AddObject(module, "description", object);

    str = MPM_NAME;
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(str, strlen(str), NULL);
#else
    object = PyString_FromString(str);
#endif
    PyModule_AddObject(module, "mpm_name", object);

    str = ap_get_server_built();
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(str, strlen(str), NULL);
#else
    object = PyString_FromString(str);
#endif
    PyModule_AddObject(module, "build_date", object);

    /* Done with the 'apache' module. */

    Py_DECREF(module);

    /*
     * If support for New Relic monitoring is enabled then
     * import New Relic agent module and initialise it.
     */

    if (!wsgi_daemon_pool) {
        wsgi_newrelic_config_file = wsgi_server_config->newrelic_config_file;
        wsgi_newrelic_environment = wsgi_server_config->newrelic_environment;
    }

    if (wsgi_newrelic_config_file) {
        PyObject *dict = NULL;

        module = PyImport_ImportModule("newrelic.agent");

        if (module) {
            Py_BEGIN_ALLOW_THREADS
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                         "mod_wsgi (pid=%d, process='%s', application='%s'): "
                         "Imported 'newrelic.agent'.", getpid(),
                         wsgi_daemon_group , name);
            Py_END_ALLOW_THREADS

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "initialize");

            if (object) {
                PyObject *config_file = NULL;
                PyObject *environment = NULL;
                PyObject *result = NULL;

#if PY_MAJOR_VERSION >= 3
                config_file = PyUnicode_Decode(wsgi_newrelic_config_file,
                         strlen(wsgi_newrelic_config_file),
                         Py_FileSystemDefaultEncoding,
                         "surrogateescape");
#else
                config_file = PyString_FromString(wsgi_newrelic_config_file);
#endif

                if (wsgi_newrelic_environment) {
#if PY_MAJOR_VERSION >= 3
                    environment = PyUnicode_Decode(wsgi_newrelic_environment,
                            strlen(wsgi_newrelic_environment),
                            Py_FileSystemDefaultEncoding,
                            "surrogateescape");
#else
                    environment = PyString_FromString(
                            wsgi_newrelic_environment);
#endif
                }
                else {
                    Py_INCREF(Py_None);
                    environment = Py_None;
                }

                result = PyObject_CallFunctionObjArgs(object, config_file,
                        environment, NULL);

                if (!result) {
                    Py_BEGIN_ALLOW_THREADS
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Unable to initialise "
                                 "New Relic agent with config '%s'.", getpid(),
                                 wsgi_newrelic_config_file);
                    Py_END_ALLOW_THREADS
                }

                Py_DECREF(config_file);
                Py_DECREF(environment);

                Py_XDECREF(result);

                Py_DECREF(object);
            }

            Py_XDECREF(module);
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Unable to import "
                         "'newrelic.agent' module.", getpid());
            Py_END_ALLOW_THREADS

            PyErr_Print();
            PyErr_Clear();
        }
    }

    /*
     * Restore previous thread state. Only need to do
     * this where had to create a new interpreter. This
     * is basically anything except the first Python
     * interpreter instance. We need to restore it in
     * these cases as came into the function holding the
     * simplified GIL state for this thread but creating
     * the interpreter has resulted in a new thread
     * state object being created bound to the newly
     * created interpreter. In doing this though we want
     * to cache the thread state object which has been
     * created when interpreter is created. This is so
     * it can be reused later ensuring that thread local
     * data persists between requests.
     */

    if (self->owner) {
#if APR_HAS_THREADS
        WSGIThreadInfo *thread_handle = NULL;

        self->tstate_table = apr_hash_make(wsgi_server->process->pool);

        thread_handle = wsgi_thread_info(1, 0);

        if (wsgi_server_config->verbose_debugging) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Bind thread state for "
                         "thread %d against interpreter '%s'.", getpid(),
                         thread_handle->thread_id, self->name);
        }

        apr_hash_set(self->tstate_table, &thread_handle->thread_id,
                     sizeof(thread_handle->thread_id), tstate);

        PyThreadState_Swap(save_tstate);
#else
        self->tstate = tstate;
        PyThreadState_Swap(save_tstate);
#endif
    }

    return self;
}

static void Interpreter_dealloc(InterpreterObject *self)
{
    PyThreadState *tstate = NULL;
    PyObject *module = NULL;

    PyThreadState *tstate_enter = NULL;

#if PY_MAJOR_VERSION < 3 || (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION < 4)
    PyObject *exitfunc = NULL;
#endif

    PyObject *event = NULL;

    /*
     * We should always enter here with the Python GIL
     * held and an active thread state. This should only
     * now occur when shutting down interpreter and not
     * when releasing interpreter as don't support
     * recyling of interpreters within the process. Thus
     * the thread state should be that for the main
     * Python interpreter. Where dealing with a named
     * sub interpreter, we need to change the thread
     * state to that which was originally used to create
     * that sub interpreter before doing anything.
     */

    tstate_enter = PyThreadState_Get();

    if (*self->name) {
#if APR_HAS_THREADS
        WSGIThreadInfo *thread_handle = NULL;

        thread_handle = wsgi_thread_info(1, 0);

        tstate = apr_hash_get(self->tstate_table, &thread_handle->thread_id,
                              sizeof(thread_handle->thread_id));

        if (!tstate) {
            tstate = PyThreadState_New(self->interp);

            if (wsgi_server_config->verbose_debugging) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Create thread state for "
                             "thread %d against interpreter '%s'.", getpid(),
                             thread_handle->thread_id, self->name);
            }

            apr_hash_set(self->tstate_table, &thread_handle->thread_id,
                         sizeof(thread_handle->thread_id), tstate);
        }
#else
        tstate = self->tstate;
#endif

        /*
         * Swap to interpreter thread state that was used when
         * the sub interpreter was created.
         */

        PyThreadState_Swap(tstate);
    }

    /* Now destroy the sub interpreter. */

    if (self->owner) {
        Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Destroy interpreter '%s'.",
                     getpid(), self->name);
        Py_END_ALLOW_THREADS
    }
    else {
        Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Cleanup interpreter '%s'.",
                     getpid(), self->name);
        Py_END_ALLOW_THREADS
    }

    /* Publish event that process is being stopped. */

    event = PyDict_New();

    wsgi_publish_event("process_stopping", event);

    Py_DECREF(event);

    /*
     * Because the thread state we are using was created outside
     * of any Python code and is not the same as the Python main
     * thread, there is no record of it within the 'threading'
     * module. We thus need to access current thread function of
     * the 'threading' module to force it to create a thread
     * handle for the thread. If we do not do this, then the
     * 'threading' modules exit function will always fail
     * because it will not be able to find a handle for this
     * thread.
     */

    module = PyImport_ImportModule("threading");

    if (!module)
        PyErr_Clear();

    if (module) {
        PyObject *dict = NULL;
        PyObject *func = NULL;

        dict = PyModule_GetDict(module);
#if PY_MAJOR_VERSION >= 3
        func = PyDict_GetItemString(dict, "current_thread");
#else
        func = PyDict_GetItemString(dict, "currentThread");
#endif
        if (func) {
            PyObject *res = NULL;
            Py_INCREF(func);
            res = PyEval_CallObject(func, (PyObject *)NULL);
            if (!res) {
                PyErr_Clear();
            }
            Py_XDECREF(res);
            Py_DECREF(func);
        }
    }

    /*
     * In Python 2.5.1 an exit function is no longer used to
     * shutdown and wait on non daemon threads which were created
     * from Python code. Instead, in Py_Main() it explicitly
     * calls 'threading._shutdown()'. Thus need to emulate this
     * behaviour for those versions.
     */

#if PY_MAJOR_VERSION < 3 || (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION < 4)
    if (module) {
        PyObject *dict = NULL;
        PyObject *func = NULL;

        dict = PyModule_GetDict(module);
        func = PyDict_GetItemString(dict, "_shutdown");
        if (func) {
            PyObject *res = NULL;
            Py_INCREF(func);
            res = PyEval_CallObject(func, (PyObject *)NULL);

            if (res == NULL) {
                PyObject *m = NULL;
                PyObject *result = NULL;

                PyObject *type = NULL;
                PyObject *value = NULL;
                PyObject *traceback = NULL;

                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Exception occurred within "
                             "threading._shutdown().", getpid());
                Py_END_ALLOW_THREADS

                PyErr_Fetch(&type, &value, &traceback);
                PyErr_NormalizeException(&type, &value, &traceback);

                if (!value) {
                    value = Py_None;
                    Py_INCREF(value);
                }

                if (!traceback) {
                    traceback = Py_None;
                    Py_INCREF(traceback);
                }

                m = PyImport_ImportModule("traceback");

                if (m) {
                    PyObject *d = NULL;
                    PyObject *o = NULL;
                    d = PyModule_GetDict(m);
                    o = PyDict_GetItemString(d, "print_exception");
                    if (o) {
                        PyObject *log = NULL;
                        PyObject *args = NULL;
                        Py_INCREF(o);
                        log = newLogObject(NULL, APLOG_ERR, NULL, 0);
                        args = Py_BuildValue("(OOOOO)", type, value,
                                             traceback, Py_None, log);
                        result = PyEval_CallObject(o, args);
                        Py_DECREF(args);
                        Py_DECREF(log);
                        Py_DECREF(o);
                    }
                }

                if (!result) {
                    /*
                     * If can't output exception and traceback then
                     * use PyErr_Print to dump out details of the
                     * exception. For SystemExit though if we do
                     * that the process will actually be terminated
                     * so can only clear the exception information
                     * and keep going.
                     */

                    PyErr_Restore(type, value, traceback);

                    if (!PyErr_ExceptionMatches(PyExc_SystemExit)) {
                        PyErr_Print();
                        PyErr_Clear();
                    }
                    else {
                        PyErr_Clear();
                    }
                }
                else {
                    Py_XDECREF(type);
                    Py_XDECREF(value);
                    Py_XDECREF(traceback);
                }

                Py_XDECREF(result);

                Py_XDECREF(m);
            }

            Py_XDECREF(res);
            Py_DECREF(func);
        }
    }

    /* Finally done with 'threading' module. */

    Py_XDECREF(module);

    /*
     * Invoke exit functions by calling sys.exitfunc() for
     * Python 2.X and atexit._run_exitfuncs() for Python 3.X.
     * Note that in Python 3.X we can't call this on main Python
     * interpreter as for Python 3.X it doesn't deregister
     * functions as called, so have no choice but to rely on
     * Py_Finalize() to do it for the main interpreter. Now
     * that simplified GIL state API usage sorted out, this
     * should be okay.
     */

    module = NULL;

#if PY_MAJOR_VERSION >= 3
    if (self->owner) {
        module = PyImport_ImportModule("atexit");

        if (module) {
            PyObject *dict = NULL;

            dict = PyModule_GetDict(module);
            exitfunc = PyDict_GetItemString(dict, "_run_exitfuncs");
        }
        else
            PyErr_Clear();
    }
#else
    exitfunc = PySys_GetObject("exitfunc");
#endif

    if (exitfunc) {
        PyObject *res = NULL;
        Py_INCREF(exitfunc);
        PySys_SetObject("exitfunc", (PyObject *)NULL);
        res = PyEval_CallObject(exitfunc, (PyObject *)NULL);

        if (res == NULL) {
            PyObject *m = NULL;
            PyObject *result = NULL;

            PyObject *type = NULL;
            PyObject *value = NULL;
            PyObject *traceback = NULL;

            if (PyErr_ExceptionMatches(PyExc_SystemExit)) {
                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                             "mod_wsgi (pid=%d): SystemExit exception "
                             "raised by exit functions ignored.", getpid());
                Py_END_ALLOW_THREADS
            }
            else {
                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Exception occurred within "
                             "exit functions.", getpid());
                Py_END_ALLOW_THREADS
            }

            PyErr_Fetch(&type, &value, &traceback);
            PyErr_NormalizeException(&type, &value, &traceback);

            if (!value) {
                value = Py_None;
                Py_INCREF(value);
            }

            if (!traceback) {
                traceback = Py_None;
                Py_INCREF(traceback);
            }

            m = PyImport_ImportModule("traceback");

            if (m) {
                PyObject *d = NULL;
                PyObject *o = NULL;
                d = PyModule_GetDict(m);
                o = PyDict_GetItemString(d, "print_exception");
                if (o) {
                    PyObject *log = NULL;
                    PyObject *args = NULL;
                    Py_INCREF(o);
                    log = newLogObject(NULL, APLOG_ERR, NULL, 0);
                    args = Py_BuildValue("(OOOOO)", type, value,
                                         traceback, Py_None, log);
                    result = PyEval_CallObject(o, args);
                    Py_DECREF(args);
                    Py_DECREF(log);
                    Py_DECREF(o);
                }
            }

            if (!result) {
                /*
                 * If can't output exception and traceback then
                 * use PyErr_Print to dump out details of the
                 * exception. For SystemExit though if we do
                 * that the process will actually be terminated
                 * so can only clear the exception information
                 * and keep going.
                 */

                PyErr_Restore(type, value, traceback);

                if (!PyErr_ExceptionMatches(PyExc_SystemExit)) {
                    PyErr_Print();
                    PyErr_Clear();
                }
                else {
                    PyErr_Clear();
                }
            }
            else {
                Py_XDECREF(type);
                Py_XDECREF(value);
                Py_XDECREF(traceback);
            }

            Py_XDECREF(result);

            Py_XDECREF(m);
        }

        Py_XDECREF(res);
        Py_DECREF(exitfunc);
    }

    Py_XDECREF(module);
#endif

    /* If we own it, we destroy it. */

    if (self->owner) {
        /*
         * We need to destroy all the thread state objects
         * associated with the interpreter. If there are
         * background threads that were created then this
         * may well cause them to crash the next time they
         * try to run. Only saving grace is that we are
         * trying to shutdown the process.
         */

#if PY_MAJOR_VERSION < 3 || (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION < 4)
        PyThreadState *tstate_save = tstate;
        PyThreadState *tstate_next = NULL;

        PyThreadState_Swap(NULL);

        tstate = tstate->interp->tstate_head;
        while (tstate) {
            tstate_next = tstate->next;
            if (tstate != tstate_save) {
                PyThreadState_Swap(tstate);
                PyThreadState_Clear(tstate);
                PyThreadState_Swap(NULL);
                PyThreadState_Delete(tstate);
            }
            tstate = tstate_next;
        }

        tstate = tstate_save;

        PyThreadState_Swap(tstate);
#endif

        /* Can now destroy the interpreter. */

        Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                     "mod_wsgi (pid=%d): End interpreter '%s'.",
                     getpid(), self->name);
        Py_END_ALLOW_THREADS

        Py_EndInterpreter(tstate);

        PyThreadState_Swap(tstate_enter);
    }

    free(self->name);

    PyObject_Del(self);
}

PyTypeObject Interpreter_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "mod_wsgi.Interpreter",  /*tp_name*/
    sizeof(InterpreterObject), /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Interpreter_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    0,                      /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

/*
 * Startup and shutdown of Python interpreter. In mod_wsgi if
 * the Python interpreter hasn't been initialised by another
 * Apache module such as mod_python, we will take control and
 * initialise it. Need to remember that we initialised Python
 * and whether done in parent or child process as when done in
 * the parent we also take responsibility for performing special
 * Python fixups after Apache is forked and child process has
 * run.
 *
 * Note that by default we now defer initialisation of Python
 * until after the fork of processes as Python 3.X by design
 * doesn't clean up properly when it is destroyed causing
 * significant memory leaks into Apache parent process on an
 * Apache restart. Some Python 2.X versions also have real
 * memory leaks but not near as much. The result of deferring
 * initialisation is that can't benefit from copy on write
 * semantics for loaded data across a fork. Each process will
 * therefore have higher memory requirement where Python needs
 * to be used.
 */

int wsgi_python_initialized = 0;

#if defined(MOD_WSGI_DISABLE_EMBEDDED)
int wsgi_python_required = 0;
#else
int wsgi_python_required = -1;
#endif

int wsgi_python_after_fork = 1;

void wsgi_python_version(void)
{
    const char *compile = PY_VERSION;
    const char *dynamic = 0;

    dynamic = strtok((char *)Py_GetVersion(), " ");

    if (strcmp(compile, dynamic) != 0) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, wsgi_server,
                     "mod_wsgi: Compiled for Python/%s.", compile);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, wsgi_server,
                     "mod_wsgi: Runtime using Python/%s.", dynamic);
    }
}

apr_status_t wsgi_python_term(void)
{
    PyObject *module = NULL;

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                 "mod_wsgi (pid=%d): Terminating Python.", getpid());

    /*
     * We should be executing in the main thread again at this
     * point but without the GIL, so simply restore the original
     * thread state for that thread that we remembered when we
     * initialised the interpreter.
     */

    PyEval_AcquireThread(wsgi_main_tstate);

    /*
     * Work around bug in Python 3.X whereby it will crash if
     * atexit imported into sub interpreter, but never imported
     * into main interpreter before calling Py_Finalize(). We
     * perform an import of atexit module and it as side effect
     * must be performing required initialisation.
     */

    module = PyImport_ImportModule("atexit");
    Py_XDECREF(module);

    /*
     * In Python 2.6.5 and Python 3.1.2 the shutdown of
     * threading was moved back into Py_Finalize() for the main
     * Python interpreter. Because we shutting down threading
     * ourselves, the second call results in errors being logged
     * when Py_Finalize() is called and the shutdown function
     * called a second time. The errors don't indicate any real
     * problem and the threading module ignores them anyway.
     * Whether we are using Python with this changed behaviour
     * can only be checked by looking at run time version.
     * Rather than try and add a dynamic check, create a fake
     * 'dummy_threading' module as the presence of that shuts up
     * the messages. It doesn't matter that the rest of the
     * shutdown function still runs as everything is already
     * stopped so doesn't do anything.
     */

    if (!PyImport_AddModule("dummy_threading"))
        PyErr_Clear();

    /* Shutdown Python interpreter completely. */

    Py_Finalize();

    wsgi_python_initialized = 0;

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                 "mod_wsgi (pid=%d): Python has shutdown.", getpid());

    return APR_SUCCESS;
}

static apr_status_t wsgi_python_parent_cleanup(void *data)
{
    if (wsgi_parent_pid == getpid()) {
        /*
         * Destroy Python itself including the main
         * interpreter. If mod_python is being loaded it
         * is left to mod_python to destroy Python,
         * although it currently doesn't do so.
         */

        if (wsgi_python_initialized)
            wsgi_python_term();
    }

    return APR_SUCCESS;
}


void wsgi_python_init(apr_pool_t *p)
{
    const char *python_home = 0;

    int is_pyvenv = 0;

    /* Perform initialisation if required. */

    if (!Py_IsInitialized()) {

        /* Enable Python 3.0 migration warnings. */

#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 6
        if (wsgi_server_config->py3k_warning_flag == 1)
            Py_Py3kWarningFlag++;
#endif

        /* Disable writing of byte code files. */

#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 6
        if (wsgi_server_config->dont_write_bytecode == 1)
            Py_DontWriteBytecodeFlag++;
#endif

        /* Check for Python paths and optimisation flag. */

        if (wsgi_server_config->python_optimize > 0)
            Py_OptimizeFlag = wsgi_server_config->python_optimize;
        else
            Py_OptimizeFlag = 0;

        /* Check for control options for Python warnings. */

        if (wsgi_server_config->python_warnings) {
            apr_array_header_t *options = NULL;
            char **entries;

            int i;

            options = wsgi_server_config->python_warnings;
            entries = (char **)options->elts;

            for (i = 0; i < options->nelts; ++i) {
#if PY_MAJOR_VERSION >= 3
                wchar_t *s = NULL;
                int len = strlen(entries[i])+1;

                s = (wchar_t *)apr_palloc(p, len*sizeof(wchar_t));

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
                wsgi_utf8_to_unicode_path(s, len, entries[i]);
#else
                mbstowcs(s, entries[i], len);
#endif
                PySys_AddWarnOption(s);
#else
                PySys_AddWarnOption(entries[i]);
#endif
            }
        }

#if defined(WIN32)
        /*
         * Check for Python HOME being overridden. This is only being
         * used on Windows for now. For UNIX systems we actually do
         * a fiddle and work out where the Python executable would be
         * and set its location instead. This is to get around some
         * brokeness in pyvenv in Python 3.X. We don't know if that
         * workaround works for Windows yet, but since not supporting
         * Windows for mod_wsgi 4.X as yet, doesn't matter.
         */

        python_home = wsgi_server_config->python_home;

        if (python_home) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Python home %s.", getpid(),
                         python_home);
        }

        if (python_home) {
#if PY_MAJOR_VERSION >= 3
            wchar_t *s = NULL;
            int len = strlen(python_home)+1;

            s = (wchar_t *)apr_palloc(p, len*sizeof(wchar_t));

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
            wsgi_utf8_to_unicode_path(s, len, python_home);
#else
            mbstowcs(s, python_home, len);
#endif
            Py_SetPythonHome(s);
#else
            Py_SetPythonHome((char *)python_home);
#endif
        }

#else
        /*
         * Now for the UNIX version of the code to set the Python HOME.
         * For this things are a mess. If using pyvenv with Python 3.3+
         * then setting Python HOME doesn't work. For it we need to use
         * Python executable location. Everything else seems to be cool
         * with setting Python HOME. We therefore need to detect when we
         * have a pyvenv by looking for the presence of pyvenv.cfg file.
         * We can simply just set Python executable everywhere as that
         * doesn't work with brew Python on MacOS X.
         */

        python_home = wsgi_server_config->python_home;

#if defined(MOD_WSGI_WITH_DAEMONS)
        if (wsgi_daemon_process && wsgi_daemon_process->group->python_home)
            python_home = wsgi_daemon_process->group->python_home;
#endif

        if (python_home) {
            apr_status_t rv;
            apr_finfo_t finfo; 

            char *pyvenv_cfg;

            const char *python_exe = 0;

#if PY_MAJOR_VERSION >= 3
            wchar_t *s = NULL;
            int len = 0;
#endif

            /*
             * Is common to see people set the directory to an incorrect
             * location, including to a location within an inaccessible
             * user home directory, or to the 'python' executable itself.
             * Try and validate that the location is accessible and is a
             * directory.
             */

            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Python home %s.", getpid(),
                         python_home);

            rv = apr_stat(&finfo, python_home, APR_FINFO_NORM, p);

            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv, wsgi_server,
                             "mod_wsgi (pid=%d): Unable to stat Python home "
                             "%s. Python interpreter may not be able to be "
                             "initialized correctly. Verify the supplied path "
                             "and access permissions for whole of the path.",
                             getpid(), python_home);
            }
            else {
                if (finfo.filetype != APR_DIR) {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, rv, wsgi_server,
                                 "mod_wsgi (pid=%d): Python home %s is not "
                                 "a directory. Python interpreter may not "
                                 "be able to be initialized correctly. "
                                 "Verify the supplied path.", getpid(),
                                 python_home);
                }
                else if (access(python_home, X_OK) == -1) {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, rv, wsgi_server,
                                 "mod_wsgi (pid=%d): Python home %s is not "
                                 "accessible. Python interpreter may not "
                                 "be able to be initialized correctly. "
                                 "Verify the supplied path and access "
                                 "permissions on the directory.", getpid(),
                                 python_home);
                }
            }

            /* Now detect whether have a pyvenv with Python 3.3+. */

            pyvenv_cfg = apr_pstrcat(p, python_home, "/pyvenv.cfg", NULL);

            if (access(pyvenv_cfg, R_OK) == 0)
                is_pyvenv = 1;

            if (is_pyvenv) {
                /*
                 * Embedded support for pyvenv is broken so need to
                 * set Python executable location and cannot set the
                 * Python HOME as is more desirable.
                 */

                python_exe = apr_pstrcat(p, python_home, "/bin/python", NULL);
#if PY_MAJOR_VERSION >= 3
                len = strlen(python_exe)+1;
                s = (wchar_t *)apr_palloc(p, len*sizeof(wchar_t));
                mbstowcs(s, python_exe, len);

                Py_SetProgramName(s);
#else
                Py_SetProgramName((char *)python_exe);
#endif
            }
            else {
#if PY_MAJOR_VERSION >= 3
                len = strlen(python_home)+1;
                s = (wchar_t *)apr_palloc(p, len*sizeof(wchar_t));
                mbstowcs(s, python_home, len);

                Py_SetPythonHome(s);
#else
                Py_SetPythonHome((char *)python_home);
#endif
            }
        }
#endif

        /*
         * Set environment variable PYTHONHASHSEED. We need to
         * make sure we remove the environment variable later
         * so that it doesn't remain in the process environment
         * and be inherited by execd sub processes.
         */

        if (wsgi_server_config->python_hash_seed != NULL) {
            char *envvar = apr_pstrcat(p, "PYTHONHASHSEED=",
                    wsgi_server_config->python_hash_seed, NULL);
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Setting hash seed to %s.",
                         getpid(), wsgi_server_config->python_hash_seed);
            putenv(envvar);
        }

        /*
         * Work around bug in Python 3.1 where it will crash
         * when used in non console application on Windows if
         * stdin/stdout have been initialised and aren't null.
         * Supposed to be fixed in Python 3.3.
         */

#if defined(WIN32) && PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION < 3
        _wputenv(L"PYTHONIOENCODING=cp1252:backslashreplace");
#endif

        /* Initialise Python. */

        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Initializing Python.", getpid());

        Py_Initialize();

        /* Initialise threading. */

        PyEval_InitThreads();

        /*
         * Remove the environment variable we set for the hash
         * seed. This has to be done in os.environ, which will
         * in turn remove it from process environ. This should
         * only be necessary for the main interpreter. We need
         * to do this before we release the GIL.
         */

        if (wsgi_server_config->python_hash_seed != NULL) {
            PyObject *module = NULL;

            module = PyImport_ImportModule("os");

            if (module) {
                PyObject *dict = NULL;
                PyObject *object = NULL;
                PyObject *key = NULL;

                dict = PyModule_GetDict(module);
                object = PyDict_GetItemString(dict, "environ");

                if (object) {
#if PY_MAJOR_VERSION >= 3
                    key = PyUnicode_FromString("PYTHONHASHSEED");
#else
                    key = PyString_FromString("PYTHONHASHSEED");
#endif

                    PyObject_DelItem(object, key);

                    Py_DECREF(key);
                }

                Py_DECREF(module);
            }
        }
      
        /*
         * We now want to release the GIL. Before we do that
         * though we remember what the current thread state is.
         * We will use that later to restore the main thread
         * state when we want to cleanup interpreters on
         * shutdown.
         */

        wsgi_main_tstate = PyThreadState_Get();
        PyEval_ReleaseThread(wsgi_main_tstate);

        wsgi_python_initialized = 1;

        /*
         * Register cleanups to be performed on parent restart
         * or shutdown. This will destroy Python itself.
         */

        apr_pool_cleanup_register(p, NULL, wsgi_python_parent_cleanup,
                                  apr_pool_cleanup_null);
    }
}

/*
 * Functions for acquiring and subsequently releasing desired
 * Python interpreter instance. When acquiring the interpreter
 * a new interpreter instance will be created on demand if it
 * is required. The Python GIL will be held on return when the
 * interpreter is acquired.
 */

#if APR_HAS_THREADS
apr_thread_mutex_t* wsgi_interp_lock = NULL;
#endif

PyObject *wsgi_interpreters = NULL;

InterpreterObject *wsgi_acquire_interpreter(const char *name)
{
    PyThreadState *tstate = NULL;
    PyInterpreterState *interp = NULL;
    InterpreterObject *handle = NULL;

    PyGILState_STATE state;

    /*
     * In a multithreaded MPM must protect the
     * interpreters table. This lock is only needed to
     * avoid a secondary thread coming in and creating
     * the same interpreter if Python releases the GIL
     * when an interpreter is being created.
     */

#if APR_HAS_THREADS
    apr_thread_mutex_lock(wsgi_interp_lock);
#endif

    /*
     * This function should never be called when the
     * Python GIL is held, so need to acquire it. Even
     * though we may need to work with a sub
     * interpreter, we need to acquire GIL against main
     * interpreter first to work with interpreter
     * dictionary.
     */

    state = PyGILState_Ensure();

    /*
     * Check if already have interpreter instance and
     * if not need to create one.
     */

    handle = (InterpreterObject *)PyDict_GetItemString(wsgi_interpreters,
                                                       name);

    if (!handle) {
        handle = newInterpreterObject(name);

        if (!handle) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Cannot create interpreter '%s'.",
                         getpid(), name);

            PyErr_Print();
            PyErr_Clear();

            PyGILState_Release(state);

#if APR_HAS_THREADS
            apr_thread_mutex_unlock(wsgi_interp_lock);
#endif
            return NULL;
        }

        PyDict_SetItemString(wsgi_interpreters, name, (PyObject *)handle);
    }
    else
        Py_INCREF(handle);

    interp = handle->interp;

    /*
     * Create new thread state object. We should only be
     * getting called where no current active thread
     * state, so no need to remember the old one. When
     * working with the main Python interpreter always
     * use the simplified API for GIL locking so any
     * extension modules which use that will still work.
     */

    PyGILState_Release(state);

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_interp_lock);
#endif

    if (*name) {
#if APR_HAS_THREADS
        WSGIThreadInfo *thread_handle = NULL;

        thread_handle = wsgi_thread_info(1, 0);

        tstate = apr_hash_get(handle->tstate_table, &thread_handle->thread_id,
                              sizeof(thread_handle->thread_id));

        if (!tstate) {
            tstate = PyThreadState_New(interp);

            if (wsgi_server_config->verbose_debugging) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Create thread state for "
                             "thread %d against interpreter '%s'.", getpid(),
                             thread_handle->thread_id, handle->name);
            }

            apr_hash_set(handle->tstate_table, &thread_handle->thread_id,
                         sizeof(thread_handle->thread_id), tstate);
        }
#else
        tstate = handle->tstate;
#endif

        PyEval_AcquireThread(tstate);
    }
    else {
        PyGILState_Ensure();

        /*
         * When simplified GIL state API is used, the thread
         * local data only persists for the extent of the top
         * level matching ensure/release calls. We want to
         * extend lifetime of the thread local data beyond
         * that, retaining it for all requests within the one
         * thread for the life of the process. To do that we
         * need to artificially increment the reference count
         * for the associated thread state object.
         */

        tstate = PyThreadState_Get();
        if (tstate && tstate->gilstate_counter == 1)
            tstate->gilstate_counter++;
    }

    return handle;
}

void wsgi_release_interpreter(InterpreterObject *handle)
{
    PyThreadState *tstate = NULL;

    PyGILState_STATE state;

    /*
     * Need to release and destroy the thread state that
     * was created against the interpreter. This will
     * release the GIL. Note that it should be safe to
     * always assume that the simplified GIL state API
     * lock was originally unlocked as always calling in
     * from an Apache thread when we acquire the
     * interpreter in the first place.
     */

    if (*handle->name) {
        tstate = PyThreadState_Get();
        PyEval_ReleaseThread(tstate);
    }
    else
        PyGILState_Release(PyGILState_UNLOCKED);

    /*
     * Need to reacquire the Python GIL just so we can
     * decrement our reference count to the interpreter
     * itself. If the interpreter has since been removed
     * from the table of interpreters this will result
     * in its destruction if its the last reference.
     */

    state = PyGILState_Ensure();

    Py_DECREF(handle);

    PyGILState_Release(state);
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
