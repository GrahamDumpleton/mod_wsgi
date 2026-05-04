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

#include "wsgi_interp.h"

#include "wsgi_version.h"

#include "wsgi_apache.h"
#include "wsgi_server.h"
#include "wsgi_config.h"
#include "wsgi_logger.h"
#include "wsgi_module.h"
#include "wsgi_restrict.h"
#include "wsgi_stream.h"
#include "wsgi_metrics.h"
#include "wsgi_daemon.h"
#include "wsgi_thread.h"
#include "wsgi_signal.h"
#include "wsgi_shutdown.h"
#include "wsgi_adapter.h"
#include "wsgi_dispatch.h"
#include "wsgi_auth.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef WIN32
#include <pwd.h>
#endif

/* ------------------------------------------------------------------------- */

/* Wrapper around Python interpreter instances. */

const char *wsgi_python_path = NULL;
const char *wsgi_python_eggs = NULL;

PyTypeObject Interpreter_Type;

/*
 * Helper to set an environment variable in the os.environ dict.
 * Allocates the key as a Python unicode object and decodes the
 * value using the filesystem default encoding. Returns 0 on
 * success, -1 on failure with Python exception set.
 */

static int wsgi_set_environ_item(PyObject *environ, const char *key,
                                 const char *value)
{
    PyObject *py_key = NULL;
    PyObject *py_value = NULL;
    int result = -1;

    py_key = PyUnicode_FromString(key);
    if (!py_key)
        goto done;

    py_value = PyUnicode_DecodeFSDefault(value);
    if (!py_value)
        goto done;

    if (PyObject_SetItem(environ, py_key, py_value) < 0)
        goto done;

    result = 0;

done:
    if (result < 0)
        wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                             "Setting os.environ['%s'] failed", key);
    Py_XDECREF(py_key);
    Py_XDECREF(py_value);
    return result;
}

/*
 * Helper to invoke site.addsitedir() for one delim-separated entry
 * of WSGIPythonPath / python-path. Decodes the byte range using
 * the filesystem default encoding, logs the addition at INFO, then
 * dispatches the call. Returns 0 on success, -1 on failure with a
 * Python exception set; the caller is responsible for logging the
 * failure detail.
 */

static int wsgi_addsitedir_entry(PyObject *addsitedir, const char *start,
                                 Py_ssize_t len)
{
    PyObject *path_entry = NULL;
    PyObject *args = NULL;
    PyObject *result = NULL;
    const char *value = NULL;
    int rv = -1;

    path_entry = PyUnicode_DecodeFSDefaultAndSize(start, len);
    if (!path_entry)
        goto done;

    value = PyUnicode_AsUTF8(path_entry);
    if (!value)
        goto done;

    wsgi_log_error_locked(APLOG_INFO, 0, wsgi_server,
                          "Adding '%s' to Python module search "
                          "path for %s.",
                          value,
                          wsgi_format_process_context(
                              wsgi_server->process->pool));

    args = Py_BuildValue("(O)", path_entry);
    if (!args)
        goto done;

    result = PyObject_CallObject(addsitedir, args);
    if (!result)
        goto done;

    rv = 0;

done:
    Py_XDECREF(result);
    Py_XDECREF(args);
    Py_XDECREF(path_entry);
    return rv;
}

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

    int is_service_script = 0;

    const char *str = NULL;

#if defined(WIN32)
    const char *python_home = 0;
#endif

    /*
     * If interpreter not named, then we want to bind
     * to the first Python interpreter instance created.
     * Give this interpreter an empty string as name.
     */

    if (!name)
    {
        interp = PyInterpreterState_Main();

        name = "";
    }

    /* Create handle for interpreter and local data. */

    self = PyObject_New(InterpreterObject, &Interpreter_Type);
    if (self == NULL)
    {
        wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                             "PyObject_New() for InterpreterObject failed");
        goto failure;
    }

    /*
     * Initialize fields immediately so the failure label can run
     * safely from any later point without tripping on uninitialized
     * self->owner. Set name from a strdup of the (now finalized)
     * local 'name' parameter.
     */

    self->owner = 0;
    self->name = strdup(name);
#if APR_HAS_THREADS
    self->tstate_table = NULL;
#else
    self->tstate = NULL;
#endif

    if (interp)
    {
        /*
         * Interpreter provided to us so will not be
         * responsible for deleting it later. This will
         * be the case for the main Python interpreter.
         */

        wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                       "Attaching to Python main interpreter in %s.",
                       wsgi_format_process_context(
                           wsgi_server->process->pool));

        self->interp = interp;

        /* Force import of threading module so that main
         * thread attribute of module is correctly set to
         * the main thread and not a secondary request
         * thread.
         */

        module = PyImport_ImportModule("threading");

        Py_XDECREF(module);
        module = NULL;
    }
    else
    {
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

        if (!tstate)
        {
            wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                                 "Py_NewInterpreter() failed");
            goto failure;
        }

        wsgi_log_error_locked(APLOG_INFO, 0, wsgi_server,
                              "Creating %s in %s.",
                              wsgi_format_interp_name(
                                  wsgi_server->process->pool, name),
                              wsgi_format_process_context(
                                  wsgi_server->process->pool));

        self->interp = tstate->interp;
        self->owner = 1;
    }

    /*
     * Build the embedded mod_wsgi module and install it as
     * sys.modules['mod_wsgi']. Done early so the heap-allocated
     * PyTypeObjects in WSGIModuleState are reachable by code in
     * the rest of interpreter setup that builds instances of
     * those types (sys.stdin/sys.stdout substitution,
     * signal.signal interception, etc.). The module's user-
     * facing and per-interpreter runtime attributes are
     * installed later by wsgi_module_populate once the rest of
     * interpreter setup has populated the surrounding
     * environment.
     */

    if (wsgi_module_init_state(name) < 0)
        goto failure;

    /*
     * Replace threading._shutdown() with a wrapper that also
     * drives atexit._run_exitfuncs after the join, so atexit
     * callbacks registered in this sub interpreter still get to
     * run when the interpreter is torn down. CPython invokes
     * atexit only for the main interpreter; without this wrapper
     * sub-interpreter atexit callbacks would silently never fire.
     * Skipped for the main interpreter, which CPython already
     * handles itself.
     *
     * Disabled for now via #if 0: Python 3.7 changed CPython to
     * run atexit callbacks in sub interpreters as well, which
     * may make the wrapper unnecessary on supported Python
     * versions. Left in place so the behaviour can be re-enabled
     * if testing on newer Python versions shows otherwise.
     */

#if 0
    if (self->owner)
    {
        module = PyImport_ImportModule("threading");

        if (module)
        {
            PyObject *dict = NULL;
            PyObject *func = NULL;

            dict = PyModule_GetDict(module);
            func = PyDict_GetItemString(dict, "_shutdown");

            if (func)
            {
                PyObject *wrapper = NULL;

                wrapper = (PyObject *)newShutdownInterpreterObject(func);

                if (wrapper)
                {
                    if (PyDict_SetItemString(dict, "_shutdown",
                                             wrapper) < 0)
                    {
                        wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                              WSGI_APLOGNO(0181) "Unable to "
                                                                 "install "
                                                                 "'threading."
                                                                 "_shutdown' "
                                                                 "wrapper for "
                                                                 "%s in %s; "
                                                                 "continuing "
                                                                 "without "
                                                                 "atexit "
                                                                 "callback "
                                                                 "support in "
                                                                 "sub "
                                                                 "interpreters.",
                                              wsgi_format_interp_name(
                                                  wsgi_server->process->pool,
                                                  name),
                                              wsgi_format_process_context(
                                                  wsgi_server->process->pool));
                        PyErr_Clear();
                    }
                    Py_DECREF(wrapper);
                }
                else
                {
                    wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                          WSGI_APLOGNO(0182) "Unable to create "
                                                             "'threading."
                                                             "_shutdown' "
                                                             "wrapper for %s "
                                                             "in %s; "
                                                             "continuing "
                                                             "without atexit "
                                                             "callback support "
                                                             "in sub "
                                                             "interpreters.",
                                          wsgi_format_interp_name(
                                              wsgi_server->process->pool,
                                              name),
                                          wsgi_format_process_context(
                                              wsgi_server->process->pool));
                    PyErr_Clear();
                }
            }
        }

        Py_XDECREF(module);
        module = NULL;
    }
#endif

    /*
     * Replace sys.stderr with a Log object so writes from Python
     * code are routed into the Apache error log. Always done; the
     * stdin/stdout substitution that follows is gated by
     * configuration and platform.
     */

    object = newLogObject(NULL, APLOG_ERR, "<stderr>", 1);
    if (!object || PySys_SetObject("stderr", object) < 0)
    {
        wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                              WSGI_APLOGNO(0185) "Unable to replace "
                                                 "'sys.stderr' with log "
                                                 "object for %s in %s; "
                                                 "continuing with default "
                                                 "stream object.",
                              wsgi_format_interp_name(
                                  wsgi_server->process->pool, name),
                              wsgi_format_process_context(
                                  wsgi_server->process->pool));
        PyErr_Clear();
    }
    Py_XDECREF(object);

    /*
     * Override sys.stdout (always) and sys.stdin (when
     * configured) for the embedded interpreter so WSGI
     * applications cannot accidentally interact with the
     * standard streams of the Apache worker process.
     *
     * sys.stdout is always replaced. With WSGIRestrictStdout set
     * it becomes a Restricted sentinel that raises OSError on
     * any access; otherwise it becomes a Log object that routes
     * writes into the Apache error log, the same routing
     * applied to sys.stderr above.
     *
     * sys.stdin is replaced with a Restricted sentinel only
     * when WSGIRestrictStdin is set. Otherwise sys.stdin is
     * left as the stream the embedded interpreter inherited.
     *
     * The block is skipped on non-Win32 when wsgi_parent_pid
     * equals the current pid, indicating Apache is running in
     * single-process mode (httpd -X) where interactive
     * debuggers like pdb need the controlling terminal's
     * standard streams intact.
     */

#ifndef WIN32
    if (wsgi_parent_pid != getpid())
    {
#endif
        if (wsgi_server_config->restrict_stdout == 1)
            object = (PyObject *)newRestrictedObject("sys.stdout");
        else
            object = newLogObject(NULL, APLOG_ERR, "<stdout>", 1);

        if (!object || PySys_SetObject("stdout", object) < 0)
        {
            wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                  WSGI_APLOGNO(0186) "Unable to replace "
                                                     "'sys.stdout' for %s "
                                                     "in %s; continuing "
                                                     "with default stream "
                                                     "object.",
                                  wsgi_format_interp_name(
                                      wsgi_server->process->pool, name),
                                  wsgi_format_process_context(
                                      wsgi_server->process->pool));
            PyErr_Clear();
        }
        Py_XDECREF(object);

        if (wsgi_server_config->restrict_stdin == 1)
        {
            object = (PyObject *)newRestrictedObject("sys.stdin");
            if (!object || PySys_SetObject("stdin", object) < 0)
            {
                wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                      WSGI_APLOGNO(0187) "Unable to "
                                                         "replace "
                                                         "'sys.stdin' "
                                                         "with restricted "
                                                         "object for %s "
                                                         "in %s; "
                                                         "continuing with "
                                                         "default stream "
                                                         "object.",
                                      wsgi_format_interp_name(
                                          wsgi_server->process->pool,
                                          name),
                                      wsgi_format_process_context(
                                          wsgi_server->process->pool));
                PyErr_Clear();
            }
            Py_XDECREF(object);
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
    if (!object)
    {
        wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                             "PyList_New() for sys.argv failed");
        goto failure;
    }

    item = PyUnicode_FromString("mod_wsgi");
    if (!item)
    {
        wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                             "PyUnicode_FromString() for sys.argv[0] failed");
        Py_DECREF(object);
        goto failure;
    }

    if (PyList_Append(object, item) < 0)
    {
        wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                             "PyList_Append() for sys.argv[0] failed");
        Py_DECREF(item);
        Py_DECREF(object);
        goto failure;
    }

    if (PySys_SetObject("argv", object) < 0)
    {
        wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                             "PySys_SetObject() for sys.argv failed");
        Py_DECREF(item);
        Py_DECREF(object);
        goto failure;
    }

    Py_DECREF(item);
    Py_DECREF(object);

    /*
     * Install signal-handler intercept for the new interpreter. The
     * intercept replaces signal.signal so that application code
     * cannot register handlers that would interfere with Apache or
     * the daemon.
     *
     * Daemon processes configured with threads=0 are running a
     * service script (no request handling); for those we instead
     * register a default SIGTERM handler that raises SystemExit, so
     * the script can shut down cleanly.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process && wsgi_daemon_process->group->threads == 0)
    {
        is_service_script = 1;

        module = PyImport_ImportModule("signal");

        if (module)
        {
            PyObject *dict = NULL;
            PyObject *func = NULL;

            dict = PyModule_GetDict(module);
            func = PyDict_GetItemString(dict, "signal");

            if (func)
            {
                PyObject *res = NULL;
                PyObject *args = NULL;
                PyObject *callback = NULL;

                Py_INCREF(func);

                callback = PyCFunction_New(&wsgi_system_exit_method[0], NULL);

                if (callback)
                    args = Py_BuildValue("(iO)", SIGTERM, callback);

                if (args)
                    res = PyObject_CallObject(func, args);

                if (!res)
                {
                    wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                          WSGI_APLOGNO(0090) "Call to "
                                                             "'signal.signal()' "
                                                             "to register "
                                                             "exit-function "
                                                             "callback failed "
                                                             "for %s in %s; "
                                                             "continuing "
                                                             "without "
                                                             "callback.",
                                          wsgi_format_interp_name(
                                              wsgi_server->process->pool,
                                              name),
                                          wsgi_format_process_context(
                                              wsgi_server->process->pool));
                    PyErr_Clear();
                }

                Py_XDECREF(res);
                Py_XDECREF(args);

                Py_XDECREF(callback);

                Py_DECREF(func);
            }
        }

        Py_XDECREF(module);
        module = NULL;
    }
#endif

    if (!is_service_script && wsgi_server_config->restrict_signal != 0)
    {
        module = PyImport_ImportModule("signal");

        if (module)
        {
            PyObject *dict = NULL;
            PyObject *func = NULL;

            dict = PyModule_GetDict(module);
            func = PyDict_GetItemString(dict, "signal");

            if (func)
            {
                PyObject *wrapper = NULL;

                wrapper = (PyObject *)newSignalInterceptObject(func);

                if (wrapper)
                {
                    if (PyDict_SetItemString(dict, "signal", wrapper) < 0)
                    {
                        wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                              WSGI_APLOGNO(0183) "Unable to "
                                                                 "install "
                                                                 "'signal."
                                                                 "signal' "
                                                                 "intercept "
                                                                 "for %s in "
                                                                 "%s; "
                                                                 "continuing "
                                                                 "without "
                                                                 "signal "
                                                                 "handler "
                                                                 "restrictions.",
                                              wsgi_format_interp_name(
                                                  wsgi_server->process->pool,
                                                  name),
                                              wsgi_format_process_context(
                                                  wsgi_server->process->pool));
                        PyErr_Clear();
                    }
                    Py_DECREF(wrapper);
                }
                else
                {
                    wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                          WSGI_APLOGNO(0184) "Unable to create "
                                                             "'signal.signal' "
                                                             "intercept for %s "
                                                             "in %s; "
                                                             "continuing "
                                                             "without signal "
                                                             "handler "
                                                             "restrictions.",
                                          wsgi_format_interp_name(
                                              wsgi_server->process->pool,
                                              name),
                                          wsgi_format_process_context(
                                              wsgi_server->process->pool));
                    PyErr_Clear();
                }
            }
        }

        Py_XDECREF(module);
        module = NULL;
    }

    /*
     * Force loading of codecs into interpreter. This has to be
     * done as not otherwise done in sub interpreters and if not
     * done, code running in sub interpreters can fail on some
     * platforms if a unicode string is added in sys.path and an
     * import then done.
     */

    item = PyCodec_Encoder("ascii");
    if (!item)
        PyErr_Clear();
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
    if (wsgi_daemon_pool)
    {
        module = PyImport_ImportModule("os");

        if (module)
        {
            PyObject *dict = NULL;

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "environ");

            if (object)
            {
                struct passwd *pwent;

                pwent = getpwuid(geteuid());

                if (pwent && getenv("USER"))
                {
                    if (wsgi_set_environ_item(object, "USER",
                                              pwent->pw_name) < 0)
                    {
                        Py_DECREF(module);
                        module = NULL;
                        goto failure;
                    }
                }

                if (pwent && getenv("USERNAME"))
                {
                    if (wsgi_set_environ_item(object, "USERNAME",
                                              pwent->pw_name) < 0)
                    {
                        Py_DECREF(module);
                        module = NULL;
                        goto failure;
                    }
                }

                if (pwent && getenv("LOGNAME"))
                {
                    if (wsgi_set_environ_item(object, "LOGNAME",
                                              pwent->pw_name) < 0)
                    {
                        Py_DECREF(module);
                        module = NULL;
                        goto failure;
                    }
                }
            }

            Py_DECREF(module);
            module = NULL;
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
    if (wsgi_daemon_pool)
    {
        module = PyImport_ImportModule("os");

        if (module)
        {
            PyObject *dict = NULL;

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "environ");

            if (object)
            {
                struct passwd *pwent;

                pwent = getpwuid(geteuid());

                if (pwent)
                {
                    if (wsgi_set_environ_item(object, "HOME",
                                              pwent->pw_dir) < 0)
                    {
                        Py_DECREF(module);
                        module = NULL;
                        goto failure;
                    }
                }
            }

            Py_DECREF(module);
            module = NULL;
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

    if (wsgi_python_eggs)
    {
        module = PyImport_ImportModule("os");

        if (module)
        {
            PyObject *dict = NULL;

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "environ");

            if (object)
            {
                if (wsgi_set_environ_item(object, "PYTHON_EGG_CACHE",
                                          wsgi_python_eggs) < 0)
                {
                    Py_DECREF(module);
                    module = NULL;
                    goto failure;
                }
            }

            Py_DECREF(module);
            module = NULL;
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

    /*
     * We use a hack here on Windows to add the site-packages
     * directory into the Python module search path as well
     * as use of Python virtual environments doesn't work
     * otherwise if using 'python -m venv' or any released of
     * 'virtualenv' from 20.x onwards.
     */

#if defined(WIN32)
    python_home = wsgi_server_config->python_home;

    if (python_home && *python_home)
    {
        if (wsgi_python_path && *wsgi_python_path)
        {
            char delim[2];
            delim[0] = DELIM;
            delim[1] = '\0';

            wsgi_python_path = apr_pstrcat(wsgi_server->process->pool,
                                           python_home, "/Lib/site-packages", delim,
                                           wsgi_python_path, NULL);
        }
        else
        {
            wsgi_python_path = apr_pstrcat(wsgi_server->process->pool,
                                           python_home, "/Lib/site-packages", NULL);
        }
    }
#endif

    if (wsgi_python_path && *wsgi_python_path)
    {
        PyObject *path = NULL;

        module = PyImport_ImportModule("site");
        path = PySys_GetObject("path");

        if (module && path)
        {
            PyObject *dict = NULL;

            PyObject *old = NULL;
            PyObject *new = NULL;
            PyObject *tmp = NULL;

            Py_ssize_t i = 0;

            old = PyList_New(0);
            new = PyList_New(0);
            tmp = PyList_New(0);

            if (!old || !new || !tmp)
            {
                wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                                     "PyList_New() for sys.path reorder buffers failed");
                Py_XDECREF(old);
                Py_XDECREF(new);
                Py_XDECREF(tmp);
                Py_DECREF(module);
                module = NULL;
                goto failure;
            }

            /* Snapshot pre-addsitedir sys.path into 'old'. */

            for (i = 0; i < PyList_Size(path); i++)
            {
                if (PyList_Append(old, PyList_GetItem(path, i)) < 0)
                {
                    PyErr_Clear();
                    break;
                }
            }

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "addsitedir");

            if (object)
            {
                const char *start;
                const char *end_ptr;

                Py_INCREF(object);

                start = wsgi_python_path;

                for (;;)
                {
                    Py_ssize_t entry_len;

                    end_ptr = strchr(start, DELIM);
                    entry_len = end_ptr ? (Py_ssize_t)(end_ptr - start)
                                        : (Py_ssize_t)strlen(start);

                    if (wsgi_addsitedir_entry(object, start, entry_len) < 0)
                    {
                        wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                              WSGI_APLOGNO(0091) "Call to "
                                                                 "'site."
                                                                 "addsitedir()' "
                                                                 "failed for "
                                                                 "'%.*s' in "
                                                                 "%s; "
                                                                 "remaining "
                                                                 "python-path "
                                                                 "entries "
                                                                 "will not be "
                                                                 "added.",
                                              (int)entry_len, start,
                                              wsgi_format_process_context(
                                                  wsgi_server->process->pool));
                        wsgi_log_python_interp_init_error(name);
                        break;
                    }

                    if (!end_ptr)
                        break;
                    start = end_ptr + 1;
                }

                Py_DECREF(object);
            }
            else
            {
                wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                      WSGI_APLOGNO(0094) "Unable to locate "
                                                         "'site.addsitedir()' in %s.",
                                      wsgi_format_process_context(
                                          wsgi_server->process->pool));
            }

            /*
             * Reorder sys.path so entries added by site.addsitedir
             * land at the front. Snapshot post-addsitedir state into
             * 'tmp', diff against pre-state in 'old', accumulate the
             * new entries in 'new', then prepend. List operations
             * here are best-effort: any failure clears the exception
             * and continues with whatever ordering we end up with.
             * The interpreter remains usable in any case.
             */

            for (i = 0; i < PyList_Size(path); i++)
            {
                if (PyList_Append(tmp, PyList_GetItem(path, i)) < 0)
                {
                    PyErr_Clear();
                    break;
                }
            }

            for (i = 0; i < PyList_Size(tmp); i++)
            {
                PyObject *path_item;
                int contains;

                path_item = PyList_GetItem(tmp, i);
                if (!path_item)
                {
                    PyErr_Clear();
                    continue;
                }

                contains = PySequence_Contains(old, path_item);

                if (contains == -1)
                {
                    PyErr_Clear();
                    contains = 0;
                }

                if (!contains)
                {
                    Py_ssize_t index = PySequence_Index(path, path_item);

                    if (index == -1)
                    {
                        PyErr_Clear();
                        continue;
                    }

                    if (PyList_Append(new, path_item) < 0)
                    {
                        PyErr_Clear();
                        continue;
                    }

                    if (PySequence_DelItem(path, index) < 0)
                        PyErr_Clear();
                }
            }

            if (PyList_SetSlice(path, 0, 0, new) < 0)
                PyErr_Clear();

            Py_DECREF(old);
            Py_DECREF(new);
            Py_DECREF(tmp);
        }
        else
        {
            if (!module)
            {
                wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                      WSGI_APLOGNO(0095) "Unable to import 'site' module "
                                                         "in %s.",
                                      wsgi_format_process_context(
                                          wsgi_server->process->pool));
            }

            if (!path)
            {
                wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                      WSGI_APLOGNO(0096) "Unable to look up 'sys.path' "
                                                         "attribute on 'sys' module in %s.",
                                      wsgi_format_process_context(
                                          wsgi_server->process->pool));
            }
        }

        Py_XDECREF(module);
        module = NULL;
    }

    /*
     * If running in daemon mode and a home directory was set then
     * insert the home directory at the start of the Python module
     * search path. This makes things similar to when using the Python
     * interpreter on the command line with a script.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process && wsgi_daemon_process->group->home)
    {
        PyObject *path = NULL;
        const char *home = wsgi_daemon_process->group->home;

        path = PySys_GetObject("path");

        if (path)
        {
            PyObject *item;

            item = PyUnicode_DecodeFSDefault(home);
            if (!item)
            {
                wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                                     "PyUnicode_DecodeFSDefault() for daemon home "
                                                     "directory failed");
                goto failure;
            }
            if (PyList_Insert(path, 0, item) < 0)
            {
                wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                                     "PyList_Insert() of daemon home directory into "
                                                     "sys.path failed");
                Py_DECREF(item);
                goto failure;
            }
            Py_DECREF(item);
        }
    }
#endif

    /*
     * Populate the embedded 'mod_wsgi' module (built earlier by
     * wsgi_module_init_state) with its user-facing attributes
     * and the per-interpreter runtime attributes for this
     * interpreter.
     */

    module = wsgi_module_populate(name);
    if (!module)
        goto failure;

    Py_DECREF(module);
    module = NULL;

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

    if (!wsgi_daemon_pool)
    {
        module = PyImport_ImportModule("apache");

        if (!module)
        {
            PyObject *modules = NULL;

            /*
             * If the import failed because no user-supplied
             * 'apache' Python module exists on the search path
             * (the common case), silently fall back to creating an
             * empty module ourselves. For any other failure (a
             * real bug in the user's module) surface the traceback
             * so the operator sees what actually went wrong
             * instead of a silent fallback masking the bug.
             */

            if (!PyErr_ExceptionMatches(PyExc_ModuleNotFoundError))
                wsgi_log_python_interp_init_error(name);

            PyErr_Clear();

            /*
             * Defensive cleanup of any orphan entry in sys.modules.
             * Modern CPython removes the entry itself on import
             * failure, but historically this was not always
             * reliable.
             */

            modules = PyImport_GetModuleDict();
            if (PyDict_GetItemString(modules, "apache"))
            {
                if (PyDict_DelItemString(modules, "apache") < 0)
                    PyErr_Clear();
            }
        }
        else
        {
            wsgi_log_error_locked(APLOG_INFO, 0, wsgi_server,
                                  "Imported 'apache' extension module.");
        }
    }

    if (!module)
    {
        module = PyImport_AddModule("apache");

        if (!module)
        {
            wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                                 "PyImport_AddModule(\"apache\") failed");
            goto failure;
        }

        Py_INCREF(module);
    }

    /*
     * Add Apache version information to the Python 'apache'
     * module.
     */

    if (wsgi_module_add_object(module, "version",
                               Py_BuildValue("(iii)", AP_SERVER_MAJORVERSION_NUMBER,
                                             AP_SERVER_MINORVERSION_NUMBER,
                                             AP_SERVER_PATCHLEVEL_NUMBER)) < 0)
        goto failure;

    /*
     * Add information about the Apache MPM configuration and
     * the number of processes and threads available.
     */

    ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded);
    if (is_threaded != AP_MPMQ_NOT_SUPPORTED)
    {
        ap_mpm_query(AP_MPMQ_MAX_THREADS, &max_threads);
    }
    ap_mpm_query(AP_MPMQ_IS_FORKED, &is_forked);
    if (is_forked != AP_MPMQ_NOT_SUPPORTED)
    {
        ap_mpm_query(AP_MPMQ_MAX_DAEMON_USED, &max_processes);
        if (max_processes == -1)
        {
            ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &max_processes);
        }
    }

    max_threads = (max_threads <= 0) ? 1 : max_threads;
    max_processes = (max_processes <= 0) ? 1 : max_processes;

    if (wsgi_module_add_object(module, "maximum_processes",
                               PyLong_FromLong(max_processes)) < 0)
        goto failure;

    if (wsgi_module_add_object(module, "threads_per_process",
                               PyLong_FromLong(max_threads)) < 0)
        goto failure;

    str = ap_get_server_description();
    if (wsgi_module_add_object(module, "description",
                               PyUnicode_DecodeLatin1(str, strlen(str), NULL)) < 0)
        goto failure;

    str = ap_show_mpm();
    if (wsgi_module_add_object(module, "mpm_name",
                               PyUnicode_DecodeLatin1(str, strlen(str), NULL)) < 0)
        goto failure;

    str = ap_get_server_built();
    if (wsgi_module_add_object(module, "build_date",
                               PyUnicode_DecodeLatin1(str, strlen(str), NULL)) < 0)
        goto failure;

    /* Done with the 'apache' module. */

    Py_DECREF(module);

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

    if (self->owner)
    {
#if APR_HAS_THREADS
        WSGIThreadInfo *thread_handle = NULL;

        self->tstate_table = apr_hash_make(wsgi_server->process->pool);

        thread_handle = wsgi_thread_info(1, 0);

        wsgi_log_error_locked(APLOG_TRACE1, 0, wsgi_server,
                              "Binding thread state for thread %d against "
                              "interpreter '%s'.",
                              thread_handle->thread_id, self->name);

        apr_hash_set(self->tstate_table, &thread_handle->thread_id,
                     sizeof(thread_handle->thread_id), tstate);

        PyThreadState_Swap(save_tstate);
#else
        self->tstate = tstate;
        PyThreadState_Swap(save_tstate);
#endif
    }

    return self;

failure:
    /*
     * Cleanup partially constructed interpreter on allocation
     * failure. self may be NULL if PyObject_New itself failed, so
     * fall back to the local name parameter for the log; everything
     * else is conditional on what was reached. If we still hold a
     * reference to a Python module being populated, decrement it.
     * If we own the sub interpreter we created, end it which also
     * cleans up all Python objects created within it. Then restore
     * the original thread state, free the heap allocated name and
     * decrement reference count on self.
     */

    {
        const char *log_name = (self && self->name) ? self->name : name;

        wsgi_log_error_locked(APLOG_CRIT, 0, wsgi_server, WSGI_APLOGNO(0035) "Unable to setup %s in %s.",
                              wsgi_format_interp_name(
                                  wsgi_server->process->pool, log_name),
                              wsgi_format_process_context(
                                  wsgi_server->process->pool));

        /*
         * Surface any pending Python exception (the actual cause of
         * the failure) before we tear down the sub-interpreter. The
         * header logged above has no detail; once Py_EndInterpreter
         * runs the exception is destroyed with the tstate, so
         * callers would otherwise never see what actually went
         * wrong.
         */

        if (PyErr_Occurred())
            wsgi_log_python_interp_init_error(log_name);
    }

    Py_XDECREF(module);

    if (self && self->owner)
    {
        Py_EndInterpreter(tstate);
        PyThreadState_Swap(save_tstate);
    }

    if (self)
    {
        /*
         * Sub-interpreter teardown (if any) is already done above; null
         * out name and clear owner so Interpreter_dealloc skips both the
         * tstate-management block and a second Py_EndInterpreter, and
         * does not read freed memory at *self->name.
         */

        free(self->name);
        self->name = NULL;
        self->owner = 0;
        Py_DECREF(self);
    }

    return NULL;
}

static void Interpreter_dealloc(InterpreterObject *self)
{
    PyThreadState *tstate = NULL;
    PyObject *module = NULL;
    PyObject *exitfunc = NULL;

    PyThreadState *tstate_enter = NULL;

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

    if (self->name && *self->name)
    {
#if APR_HAS_THREADS
        WSGIThreadInfo *thread_handle = NULL;

        thread_handle = wsgi_thread_info(1, 0);

        tstate = apr_hash_get(self->tstate_table, &thread_handle->thread_id,
                              sizeof(thread_handle->thread_id));

        if (!tstate)
        {
            tstate = PyThreadState_New(self->interp);

            if (!tstate)
            {
                wsgi_log_error(APLOG_ERR, 0, wsgi_server,
                               WSGI_APLOGNO(0192) "Unable to create "
                                                  "thread state to "
                                                  "destroy %s in %s; "
                                                  "sub interpreter "
                                                  "will not be shut "
                                                  "down cleanly.",
                               wsgi_format_interp_name(
                                   wsgi_server->process->pool, self->name),
                               wsgi_format_process_context(
                                   wsgi_server->process->pool));

                free(self->name);
                PyObject_Del(self);
                return;
            }

            wsgi_log_error_locked(APLOG_TRACE1, 0, wsgi_server,
                                  "Creating thread state for thread %d "
                                  "against interpreter '%s'.",
                                  thread_handle->thread_id, self->name);

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

    if (self->owner)
    {
        wsgi_log_error_locked(APLOG_INFO, 0, wsgi_server,
                              "Destroying %s in %s.",
                              wsgi_format_interp_name(
                                  wsgi_server->process->pool, self->name),
                              wsgi_format_process_context(
                                  wsgi_server->process->pool));
    }
    else
    {
        wsgi_log_error_locked(APLOG_INFO, 0, wsgi_server,
                              "Releasing Python main interpreter wrapper "
                              "in %s.",
                              wsgi_format_process_context(
                                  wsgi_server->process->pool));
    }

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

    if (module)
    {
        PyObject *dict = NULL;
        PyObject *func = NULL;

        dict = PyModule_GetDict(module);
        func = PyDict_GetItemString(dict, "current_thread");
        if (func)
        {
            PyObject *res = NULL;
            Py_INCREF(func);
            res = PyObject_CallObject(func, (PyObject *)NULL);
            if (!res)
            {
                PyErr_Clear();
            }
            Py_XDECREF(res);
            Py_DECREF(func);
        }
    }

    /* Finally done with 'threading' module. */

    Py_XDECREF(module);

    /*
     * Invoke registered atexit handlers via atexit._run_exitfuncs()
     * for sub interpreters we own. Python does not call atexit
     * handlers itself when a sub interpreter is destroyed by
     * Py_EndInterpreter, so we have to drive them here. Skip this
     * for the main interpreter: atexit doesn't deregister handlers
     * as it calls them, so calling here would also call them again
     * from Py_Finalize() during process shutdown. Rely on
     * Py_Finalize() to handle the main interpreter's atexit chain.
     */

    module = NULL;

    if (self->owner)
    {
        module = PyImport_ImportModule("atexit");

        if (module)
        {
            PyObject *dict = NULL;

            dict = PyModule_GetDict(module);
            exitfunc = PyDict_GetItemString(dict, "_run_exitfuncs");
        }
        else
            PyErr_Clear();
    }

    if (exitfunc)
    {
        PyObject *res = NULL;
        Py_INCREF(exitfunc);
        res = PyObject_CallObject(exitfunc, (PyObject *)NULL);

        if (res == NULL)
            wsgi_log_python_interp_atexit_error(self->name);

        Py_XDECREF(res);
        Py_DECREF(exitfunc);
    }

    Py_XDECREF(module);

    /* If we own it, we destroy it. */

    if (self->owner)
    {
        /*
         * Clear and delete every thread state still attached to the
         * sub interpreter other than the one we will use to drive
         * Py_EndInterpreter. Py_EndInterpreter requires the tstate
         * passed to it to be the only thread state remaining in the
         * interpreter; without this cleanup CPython aborts the
         * process with "Py_EndInterpreter: not the last thread"
         * whenever more than one Apache worker thread bound a
         * tstate against the sub interpreter via PyThreadState_New.
         *
         * The interpreter's full thread chain is walked rather than
         * just our own tstate_table so any tstate that ended up on
         * the chain by some path other than Interpreter_New /
         * wsgi_acquire_interpreter is still released. Each tstate
         * is swapped in before being cleared so finalizers triggered
         * by the clear see that tstate as current, then current is
         * restored before delete because PyThreadState_Delete
         * requires its argument not to be the current tstate.
         * tstate_next is captured before the clear so the iteration
         * stays valid across the unlinking that delete performs.
         */

        {
            PyThreadState *iter = PyInterpreterState_ThreadHead(self->interp);
            PyThreadState *next = NULL;

            while (iter)
            {
                next = PyThreadState_Next(iter);

                if (iter != tstate)
                {
                    PyThreadState_Swap(iter);
                    PyThreadState_Clear(iter);
                    PyThreadState_Swap(tstate);
                    PyThreadState_Delete(iter);
                }

                iter = next;
            }
        }

        /* Can now destroy the interpreter. */

        Py_EndInterpreter(tstate);

        PyThreadState_Swap(tstate_enter);
    }

    free(self->name);

    PyObject_Del(self);
}

PyTypeObject Interpreter_Type = {
    PyVarObject_HEAD_INIT(NULL, 0) "mod_wsgi.Interpreter", /*tp_name*/
    sizeof(InterpreterObject),                             /*tp_basicsize*/
    0,                                                     /*tp_itemsize*/
    /* methods */
    (destructor)Interpreter_dealloc, /*tp_dealloc*/
    0,                               /*tp_print*/
    0,                               /*tp_getattr*/
    0,                               /*tp_setattr*/
    0,                               /*tp_compare*/
    0,                               /*tp_repr*/
    0,                               /*tp_as_number*/
    0,                               /*tp_as_sequence*/
    0,                               /*tp_as_mapping*/
    0,                               /*tp_hash*/
    0,                               /*tp_call*/
    0,                               /*tp_str*/
    0,                               /*tp_getattro*/
    0,                               /*tp_setattro*/
    0,                               /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,              /*tp_flags*/
    0,                               /*tp_doc*/
    0,                               /*tp_traverse*/
    0,                               /*tp_clear*/
    0,                               /*tp_richcompare*/
    0,                               /*tp_weaklistoffset*/
    0,                               /*tp_iter*/
    0,                               /*tp_iternext*/
    0,                               /*tp_methods*/
    0,                               /*tp_members*/
    0,                               /*tp_getset*/
    0,                               /*tp_base*/
    0,                               /*tp_dict*/
    0,                               /*tp_descr_get*/
    0,                               /*tp_descr_set*/
    0,                               /*tp_dictoffset*/
    0,                               /*tp_init*/
    0,                               /*tp_alloc*/
    0,                               /*tp_new*/
    0,                               /*tp_free*/
    0,                               /*tp_is_gc*/
};

/*
 * Startup and shutdown of Python interpreter.
 */

int wsgi_python_initialized = 0;

#if defined(MOD_WSGI_DISABLE_EMBEDDED)
int wsgi_python_required = 0;
#else
int wsgi_python_required = -1;
#endif

void wsgi_python_version(void)
{
    const char *compile = PY_VERSION;
    const char *dynamic = 0;

    dynamic = strtok((char *)Py_GetVersion(), " ");

    if (strcmp(compile, dynamic) != 0)
    {
        wsgi_log_error(APLOG_WARNING, 0, wsgi_server, WSGI_APLOGNO(0099) "Compiled for Python/%s but runtime using "
                                                                         "Python/%s in %s.",
                       compile, dynamic,
                       wsgi_format_process_context(
                           wsgi_server->process->pool));
    }
}

apr_status_t wsgi_python_term(void)
{
    PyObject *module = NULL;

    /* Skip destruction of Python interpreter. */

    if (wsgi_server_config->destroy_interpreter == 0)
        return APR_SUCCESS;

    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                   "Terminating Python runtime in %s.",
                   wsgi_format_process_context(
                       wsgi_server->process->pool));

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

    /*
     * Shutdown Python interpreter completely. Just to be safe
     * flag daemon shutdown here again and do it within a lock
     * which is then shared with deadlock thread used for the
     * daemon. This is just to avoid any risk there is a race
     * condition.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
        apr_thread_mutex_lock(wsgi_shutdown_lock);

    wsgi_daemon_shutdown++;
#endif

    Py_Finalize();

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
        apr_thread_mutex_unlock(wsgi_shutdown_lock);
#endif

    wsgi_python_initialized = 0;

    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                   "Python runtime has shut down in %s.",
                   wsgi_format_process_context(
                       wsgi_server->process->pool));

    return APR_SUCCESS;
}

static apr_status_t wsgi_python_parent_cleanup(void *data)
{
    if (wsgi_parent_pid == getpid())
    {
        /*
         * Destroy Python itself including the main
         * interpreter.
         */

        if (wsgi_python_initialized)
            wsgi_python_term();
    }

    return APR_SUCCESS;
}

static int wsgi_python_init_failed(PyStatus status)
{
    /*
     * On a PyConfig API failure, usually a memory allocation failure,
     * log a critical error. Returns non-zero so callers can track
     * that a failure has occurred and bail out before continuing on
     * to call Py_InitializeFromConfig() with a broken config.
     */
    wsgi_log_error(APLOG_CRIT, 0, wsgi_server, WSGI_APLOGNO(0036) "Python interpreter configuration failed in %s: %s",
                   wsgi_format_process_context(wsgi_server->process->pool),
                   status.err_msg);

    return 1;
}

void wsgi_python_set_switch_interval(double seconds)
{
    PyGILState_STATE gstate;
    PyObject *sys = NULL;
    PyObject *result = NULL;

    gstate = PyGILState_Ensure();

    sys = PyImport_ImportModule("sys");
    if (sys)
    {
        result = PyObject_CallMethod(sys, "setswitchinterval",
                                     "d", seconds);
        Py_DECREF(sys);
    }

    if (!result)
    {
        PyErr_Clear();
        PyGILState_Release(gstate);
        wsgi_log_error(APLOG_WARNING, 0, wsgi_server,
                       "mod_wsgi: failed to apply Python GIL switch "
                       "interval %.6fs in %s.",
                       seconds,
                       wsgi_format_process_context(
                           wsgi_server->process->pool));
        return;
    }

    Py_DECREF(result);
    PyGILState_Release(gstate);

    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                   "mod_wsgi: Python GIL switch interval set to "
                   "%.6fs in %s.",
                   seconds,
                   wsgi_format_process_context(
                       wsgi_server->process->pool));
}

apr_status_t wsgi_python_init(apr_pool_t *p)
{
    const char *python_home = 0;

    int is_pyvenv = 0;
    int init_failed = 0;

    PyConfig config;
    PyStatus status;
    PyConfig_InitPythonConfig(&config);

    /* Perform initialisation if required. */

    if (!Py_IsInitialized())
    {

        /* Disable writing of byte code files. */

        if (wsgi_server_config->dont_write_bytecode == 1)
        {
            config.write_bytecode = 0;
        }

        /* Check for Python paths and optimisation flag. */

        if (wsgi_server_config->python_optimize > 0)
        {
            config.optimization_level = wsgi_server_config->python_optimize;
        }
        else
        {
            config.optimization_level = 0;
        }

        /* Check for control options for Python warnings. */

        if (wsgi_server_config->python_warnings)
        {
            apr_array_header_t *options = NULL;
            char **entries;

            int i;

            options = wsgi_server_config->python_warnings;
            entries = (char **)options->elts;

            for (i = 0; i < options->nelts; ++i)
            {
                wchar_t *s = NULL;
                int len = strlen(entries[i]) + 1;

                s = (wchar_t *)apr_palloc(p, len * sizeof(wchar_t));

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
                wsgi_utf8_to_unicode_path(s, len, entries[i]);
#else
                mbstowcs(s, entries[i], len);
#endif
                status = PyWideStringList_Append(&config.warnoptions, s);
                if (PyStatus_Exception(status))
                    init_failed = wsgi_python_init_failed(status);
            }
        }

#if defined(WIN32)
#if defined(WIN32_PYTHON_VENV_IS_BROKEN)
        /*
         * XXX Python new style virtual environments break Python embedding
         * API for Python initialisation on Windows. So disable this code as
         * any attempt to call Py_SetPythonHome() with location of the
         * virtual environment will not work and will break initialization
         * of the Python interpreter. Instead manually add the directory
         * Lib/site-packages to the Python module search path later if
         * WSGIPythonHome has been set.
         */

        /*
         * Check for Python home being overridden. This is only being
         * used on Windows. For UNIX systems we actually do a fiddle
         * and work out where the Python executable would be and set
         * its location instead. This is to get around some brokeness
         * in pyvenv in Python 3.X. That fiddle doesn't work on Windows
         * so for Windows with pyvenv, and also virtualenv 20.X and
         * later, we do a later fiddle where add the virtual environment
         * site-packages directory to the Python module search path.
         */

        python_home = wsgi_server_config->python_home;

        if (python_home)
        {
            wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                           "Python home set to '%s' for %s.",
                           python_home,
                           wsgi_format_process_context(
                               wsgi_server->process->pool));
        }

        if (python_home)
        {
            wchar_t *s = NULL;
            int len = strlen(python_home) + 1;

            s = (wchar_t *)apr_palloc(p, len * sizeof(wchar_t));

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
            wsgi_utf8_to_unicode_path(s, len, python_home);
#else
            mbstowcs(s, python_home, len);
#endif
            status = PyConfig_SetString(&config, &config.home, s);
            if (PyStatus_Exception(status))
                init_failed = wsgi_python_init_failed(status);
        }
#endif
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

        if (python_home)
        {
            apr_status_t rv;
            apr_finfo_t finfo;

            char *pyvenv_cfg;

            const char *python_exe = 0;

            wchar_t *s = NULL;
            int len = 0;

            /*
             * Is common to see people set the directory to an incorrect
             * location, including to a location within an inaccessible
             * user home directory, or to the 'python' executable itself.
             * Try and validate that the location is accessible and is a
             * directory.
             */

            wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                           "Python home set to '%s' for %s.",
                           python_home,
                           wsgi_format_process_context(
                               wsgi_server->process->pool));

#if !defined(WIN32)
            rv = apr_stat(&finfo, python_home, APR_FINFO_NORM, p);

            if (rv != APR_SUCCESS)
            {
                wsgi_log_error(APLOG_WARNING, rv, wsgi_server,
                               WSGI_APLOGNO(0100) "Unable to stat Python home '%s' for %s; "
                                                  "Python interpreter may not initialise "
                                                  "correctly. Verify the path and the "
                                                  "access permissions on every component "
                                                  "of it.",
                               python_home,
                               wsgi_format_process_context(
                                   wsgi_server->process->pool));
            }
            else
            {
                if (finfo.filetype != APR_DIR)
                {
                    wsgi_log_error(APLOG_WARNING, rv, wsgi_server,
                                   WSGI_APLOGNO(0101) "Python home '%s' for %s is not a "
                                                      "directory; Python interpreter may "
                                                      "not initialise correctly. Verify "
                                                      "the supplied path.",
                                   python_home,
                                   wsgi_format_process_context(
                                       wsgi_server->process->pool));
                }
                else if (access(python_home, X_OK) == -1)
                {
                    wsgi_log_error(APLOG_WARNING, rv, wsgi_server,
                                   WSGI_APLOGNO(0102) "Python home '%s' for %s is not "
                                                      "accessible; Python interpreter may "
                                                      "not initialise correctly. Verify "
                                                      "the access permissions on the "
                                                      "directory.",
                                   python_home,
                                   wsgi_format_process_context(
                                       wsgi_server->process->pool));
                }
            }
#endif

            /* Now detect whether have a pyvenv with Python 3.3+. */

            pyvenv_cfg = apr_pstrcat(p, python_home, "/pyvenv.cfg", NULL);

#if defined(WIN32)
            if (access(pyvenv_cfg, 0) == 0)
                is_pyvenv = 1;
#else
            if (access(pyvenv_cfg, R_OK) == 0)
                is_pyvenv = 1;
#endif

            if (is_pyvenv)
            {
                /*
                 * Embedded support for pyvenv is broken so need to
                 * set Python executable location and cannot set the
                 * Python HOME as is more desirable.
                 */

                python_exe = apr_pstrcat(p, python_home, "/bin/python", NULL);
                len = strlen(python_exe) + 1;
                s = (wchar_t *)apr_palloc(p, len * sizeof(wchar_t));
#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
                wsgi_utf8_to_unicode_path(s, len, python_exe);
#else
                mbstowcs(s, python_exe, len);
#endif

                status = PyConfig_SetString(&config, &config.program_name, s);
                if (PyStatus_Exception(status))
                    init_failed = wsgi_python_init_failed(status);
            }
            else
            {
                len = strlen(python_home) + 1;
                s = (wchar_t *)apr_palloc(p, len * sizeof(wchar_t));
#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
                wsgi_utf8_to_unicode_path(s, len, python_home);
#else
                mbstowcs(s, python_home, len);
#endif

                status = PyConfig_SetString(&config, &config.home, s);
                if (PyStatus_Exception(status))
                    init_failed = wsgi_python_init_failed(status);
            }
        }
#endif

        /*
         * Set environment variable PYTHONHASHSEED. We need to
         * make sure we remove the environment variable later
         * so that it doesn't remain in the process environment
         * and be inherited by execd sub processes.
         */

        if (wsgi_server_config->python_hash_seed != NULL)
        {
            wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                           "Setting Python hash seed (PYTHONHASHSEED) to "
                           "'%s'.",
                           wsgi_server_config->python_hash_seed);
            long seed = atol(wsgi_server_config->python_hash_seed);
            config.use_hash_seed = 1;
            config.hash_seed = (unsigned long)seed;
        }

        /*
         * If any earlier PyConfig setup failed, don't proceed to
         * initialize Python as the config is likely incomplete or
         * broken and Py_InitializeFromConfig() may either fail or
         * worse, succeed with an unexpected configuration.
         */

        if (init_failed)
        {
            PyConfig_Clear(&config);
            return APR_EGENERAL;
        }

        /* Initialise Python. */

        wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                       "Initializing Python runtime in %s.",
                       wsgi_format_process_context(
                           wsgi_server->process->pool));

        status = Py_InitializeFromConfig(&config);
        if (PyStatus_Exception(status))
        {
            wsgi_python_init_failed(status);
            PyConfig_Clear(&config);
            return APR_EGENERAL;
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

        /* Apply WSGISwitchInterval to the embedded interpreter only.
         * In daemon mode wsgi_python_init also runs inside the daemon
         * child after fork, but daemon processes pick up their value
         * from daemon->group->switch_interval after wsgi_python_child_init
         * (see wsgi_daemon.c) — applying the server-config value here
         * would shadow that and emit a redundant INFO log line. */
        if (wsgi_daemon_process == NULL && wsgi_server_config->switch_interval > 0.0)
            wsgi_python_set_switch_interval(
                wsgi_server_config->switch_interval);

        /*
         * Register cleanups to be performed on parent restart
         * or shutdown. This will destroy Python itself.
         */

        apr_pool_cleanup_register(p, NULL, wsgi_python_parent_cleanup,
                                  apr_pool_cleanup_null);
    }

    PyConfig_Clear(&config);

    return APR_SUCCESS;
}

/*
 * Functions for acquiring and subsequently releasing desired
 * Python interpreter instance. When acquiring the interpreter
 * a new interpreter instance will be created on demand if it
 * is required. The Python GIL will be held on return when the
 * interpreter is acquired.
 */

#if APR_HAS_THREADS
apr_thread_mutex_t *wsgi_interp_lock = NULL;
apr_thread_mutex_t *wsgi_shutdown_lock = NULL;
#endif

PyObject *wsgi_interpreters = NULL;

PyObject *wsgi_request_timeout_exc = NULL;

apr_hash_t *wsgi_interpreters_index = NULL;

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

    if (!handle)
    {
        handle = newInterpreterObject(name);

        if (!handle)
        {
            wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                  WSGI_APLOGNO(0103) "Python based handlers "
                                                     "will not be available "
                                                     "for %s in %s.",
                                  wsgi_format_interp_name(
                                      wsgi_server->process->pool, name),
                                  wsgi_format_process_context(
                                      wsgi_server->process->pool));

            PyGILState_Release(state);

#if APR_HAS_THREADS
            apr_thread_mutex_unlock(wsgi_interp_lock);
#endif
            return NULL;
        }

        if (PyDict_SetItemString(wsgi_interpreters, name,
                                 (PyObject *)handle) < 0)
        {
            wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                  WSGI_APLOGNO(0180) "Unable to register %s in "
                                                     "interpreters dictionary "
                                                     "for %s.",
                                  wsgi_format_interp_name(
                                      wsgi_server->process->pool, name),
                                  wsgi_format_process_context(
                                      wsgi_server->process->pool));

            PyErr_Clear();

            Py_DECREF(handle);

            PyGILState_Release(state);

#if APR_HAS_THREADS
            apr_thread_mutex_unlock(wsgi_interp_lock);
#endif
            return NULL;
        }

        /*
         * Add interpreter name to index kept in Apache data
         * strcuture as well. Make a copy of the name just in
         * case we have been given temporary value.
         */

        apr_hash_set(wsgi_interpreters_index, apr_pstrdup(apr_hash_pool_get(wsgi_interpreters_index), name),
                     APR_HASH_KEY_STRING, "");
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

    if (*name)
    {
        apr_time_t _gil_t1;
#if APR_HAS_THREADS
        WSGIThreadInfo *thread_handle = NULL;

        thread_handle = wsgi_thread_info(1, 0);

        tstate = apr_hash_get(handle->tstate_table, &thread_handle->thread_id,
                              sizeof(thread_handle->thread_id));

        if (!tstate)
        {
            tstate = PyThreadState_New(interp);

            if (!tstate)
            {
                PyGILState_STATE retry_state;

                wsgi_log_error(APLOG_ERR, 0, wsgi_server,
                               WSGI_APLOGNO(0191) "Unable to create "
                                                  "thread state for "
                                                  "thread %d against "
                                                  "%s in %s.",
                               thread_handle->thread_id,
                               wsgi_format_interp_name(
                                   wsgi_server->process->pool, name),
                               wsgi_format_process_context(
                                   wsgi_server->process->pool));

                retry_state = PyGILState_Ensure();
                Py_DECREF(handle);
                PyGILState_Release(retry_state);

                return NULL;
            }

            wsgi_log_error_locked(APLOG_TRACE1, 0, wsgi_server,
                                  "Creating thread state for thread %d "
                                  "against interpreter '%s'.",
                                  thread_handle->thread_id, handle->name);

            apr_hash_set(handle->tstate_table, &thread_handle->thread_id,
                         sizeof(thread_handle->thread_id), tstate);
        }
#else
        tstate = handle->tstate;
#endif

        /* Time the narrow GIL acquire only — interpreter creation and
         * threadstate creation above are cold-path costs that belong on
         * the lifecycle datagram, not the per-request indicator. */
        _gil_t1 = apr_time_now();
        PyEval_AcquireThread(tstate);
        wsgi_gil_wait_record((apr_uint64_t)(apr_time_now() - _gil_t1));
    }
    else
    {
        apr_time_t _gil_t1 = apr_time_now();
        PyGILState_Ensure();
        wsgi_gil_wait_record((apr_uint64_t)(apr_time_now() - _gil_t1));

        /*
         * For the main interpreter we deliberately route through
         * the simplified GIL state API (PyGILState_Ensure /
         * PyGILState_Release) rather than driving the thread
         * state ourselves. This is required so that any third
         * party C extension which itself uses the simplified API
         * can find the current thread state via the auto-TSS
         * slot that PyGILState_Ensure populates. If we instead
         * managed the thread state explicitly via
         * PyThreadState_New / PyEval_AcquireThread, the auto-TSS
         * slot would be empty and a nested PyGILState_Ensure
         * inside an extension would create a second, parallel
         * thread state for the same OS thread, which is
         * undefined behaviour.
         *
         * The catch is that the simplified API is designed for
         * scoped use: the matching pair Ensure/Release tears the
         * thread state down again at the end of the outer
         * Release. We do not want that — we want the thread
         * state, and therefore any thread local data Python or
         * extensions have attached to it (threading.local,
         * contextvars defaults, extension-side TLS via
         * PyThread_tss_*, etc.), to persist across distinct
         * requests for the entire life of the Apache worker
         * thread. Recreating the thread state per request would
         * silently reset any such state at request boundaries.
         *
         * To extend the thread state's lifetime across requests
         * we lean on the documented behaviour of
         * PyGILState_Release: it decrements
         * tstate->gilstate_counter and only destroys the thread
         * state when the counter reaches zero. Immediately after
         * the very first PyGILState_Ensure on this thread the
         * counter is 1 (the sentinel CPython uses to mean
         * "registered in the auto-TSS table; do not destroy on
         * Release"). By bumping it to 2 here the matching
         * Release in wsgi_release_interpreter brings it back
         * down to 1, which is non-zero, so Release just drops
         * the GIL via PyEval_SaveThread() and leaves the thread
         * state — and its TSS registration — in place for the
         * next request on this thread. We only do the bump on
         * the first Ensure (counter == 1); any nested Ensure
         * from inside the request leaves the counter alone so
         * pairing inside the request still balances normally.
         *
         * gilstate_counter is exposed via Include/cpython/
         * pystate.h, which is the unstable CPython tier — the
         * field is not part of the stable ABI and could in
         * principle be renamed or removed in a future release.
         * There is no public API equivalent for "extend the
         * lifetime of an auto-TSS thread state beyond
         * Ensure/Release"; if CPython ever removes this field
         * we will need a CPython-side replacement, since neither
         * dropping the simplified API (breaks third party
         * extensions, see above) nor letting the thread state
         * be torn down each request (loses thread local data,
         * see above) is acceptable.
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
     * Drop the GIL for the duration of the request. For named
     * sub interpreters we manage the thread state explicitly
     * and PyEval_ReleaseThread does the obvious thing.
     *
     * For the main interpreter we mirror the simplified GIL
     * state API path used in wsgi_acquire_interpreter (see the
     * long comment there for the full rationale, including why
     * the simplified API must be used at all and why we keep
     * the thread state alive across requests). The matching
     * call here is PyGILState_Release with PyGILState_UNLOCKED
     * passed in directly rather than the value originally
     * returned by PyGILState_Ensure. We can do that safely
     * because:
     *
     *  - mod_wsgi only ever enters acquire from a fresh Apache
     *    worker thread, which by construction does not already
     *    hold the GIL on its first call. PyGILState_Ensure
     *    therefore returns PyGILState_UNLOCKED and that is the
     *    correct value to feed back into Release on the way
     *    out, regardless of how many requests this worker
     *    thread has already processed (the gilstate_counter
     *    bump in acquire keeps the thread state alive between
     *    requests, so there is no nested Ensure scope to
     *    unwind).
     *  - We do not capture the return value of Ensure in
     *    acquire; threading it back here as a parameter would
     *    require plumbing it through the InterpreterObject
     *    handle for no behavioural gain, since the value is
     *    invariant for our call pattern.
     *
     * Combined with the counter bump in acquire, this Release
     * decrements gilstate_counter from 2 to 1 (not 0), so the
     * thread state is preserved for the next request and the
     * GIL is released via PyEval_SaveThread() inside Release.
     */

    if (*handle->name)
    {
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

void wsgi_publish_process_stopping(char *reason)
{
    InterpreterObject *interp = NULL;
    apr_hash_index_t *hi;

    hi = apr_hash_first(NULL, wsgi_interpreters_index);

    while (hi)
    {
        PyObject *event = NULL;
        PyObject *object = NULL;

        const void *key;

        apr_hash_this(hi, &key, NULL, NULL);

        interp = wsgi_acquire_interpreter((char *)key);

        if (!interp)
        {
            hi = apr_hash_next(hi);
            continue;
        }

        event = PyDict_New();
        object = PyUnicode_DecodeLatin1(reason, strlen(reason), NULL);

        if (event && object &&
            PyDict_SetItemString(event, "shutdown_reason", object) == 0)
        {
            wsgi_publish_event("process_stopping", event);
        }
        else
        {
            wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                                  WSGI_APLOGNO(0104) "Unable to publish 'process_stopping' "
                                                     "event for %s.",
                                  wsgi_format_interp_context(
                                      wsgi_server->process->pool, NULL,
                                      (const char *)key));
            PyErr_Clear();
        }

        Py_XDECREF(object);
        Py_XDECREF(event);

        wsgi_release_interpreter(interp);

        hi = apr_hash_next(hi);
    }
}

/* ------------------------------------------------------------------------- */

/*
 * Code for importing a module from source by absolute path.
 */

PyObject *wsgi_load_source(apr_pool_t *pool, request_rec *r,
                           const char *name, int exists,
                           const char *filename,
                           const char *process_group,
                           const char *application_group,
                           int ignore_system_exit)
{
    PyObject *m = NULL;
    PyObject *co = NULL;
    PyObject *io_module = NULL;
    PyObject *fileobject = NULL;
    PyObject *source_bytes_object = NULL;
    PyObject *result = NULL;
    char *source_buf = NULL;

    if (exists)
    {
        wsgi_log_error_locked(APLOG_INFO, 0, r ? r->server : wsgi_server,
                              "Reloading WSGI script '%s' into %s.",
                              filename,
                              wsgi_format_interp_context(pool,
                                                         process_group,
                                                         application_group));
    }
    else
    {
        wsgi_log_error_locked(APLOG_INFO, 0, r ? r->server : wsgi_server,
                              "Loading WSGI script '%s' into %s.",
                              filename,
                              wsgi_format_interp_context(pool,
                                                         process_group,
                                                         application_group));
    }

    io_module = PyImport_ImportModule("io");

    if (!io_module)
        goto load_source_finally;

    fileobject = PyObject_CallMethod(io_module, "open", "ss", filename, "rb");

    if (!fileobject)
        goto load_source_finally;

    source_bytes_object = PyObject_CallMethod(fileobject, "read", "");

    if (!source_bytes_object)
        goto load_source_finally;

    result = PyObject_CallMethod(fileobject, "close", "");

    if (!result)
    {
        /* read() already returned the source bytes, so a close()
         * failure cannot retroactively invalidate the data we have.
         * Surface the failure as a warning with the Python traceback
         * so operators have evidence, then clear the exception and
         * proceed with the compile rather than discarding a
         * successfully read source. */

        if (r)
            wsgi_log_rerror_locked(APLOG_WARNING, 0, r,
                                   WSGI_APLOGNO(0195) "Failed to close "
                                                      "source file after "
                                                      "reading WSGI "
                                                      "script '%s' for "
                                                      "%s; continuing "
                                                      "with the data "
                                                      "already read.",
                                   filename,
                                   wsgi_format_interp_context(
                                       pool, process_group,
                                       application_group));
        else
            wsgi_log_error_locked(APLOG_WARNING, 0, wsgi_server,
                                  WSGI_APLOGNO(0196) "Failed to close "
                                                     "source file after "
                                                     "reading WSGI "
                                                     "script '%s' for "
                                                     "%s; continuing "
                                                     "with the data "
                                                     "already read.",
                                  filename,
                                  wsgi_format_interp_context(
                                      pool, process_group,
                                      application_group));

        wsgi_log_python_error(r, filename, application_group, 0);
    }

    source_buf = PyBytes_AsString(source_bytes_object);

    if (!source_buf)
        goto load_source_finally;

    co = Py_CompileString(source_buf, filename, Py_file_input);

load_source_finally:
    if (!co)
    {
        if (r)
            wsgi_log_rerror_locked(APLOG_ERR, errno, r, WSGI_APLOGNO(0105) "Could not read or compile WSGI "
                                                                           "script '%s' for %s.",
                                   filename,
                                   wsgi_format_interp_context(
                                       pool, process_group,
                                       application_group));
        else
            wsgi_log_error_locked(APLOG_ERR, errno, wsgi_server,
                                  WSGI_APLOGNO(0106) "Could not read or compile WSGI "
                                                     "script '%s' for %s.",
                                  filename,
                                  wsgi_format_interp_context(
                                      pool, process_group,
                                      application_group));

        wsgi_log_python_error(r, filename, application_group, 0);

        Py_XDECREF(io_module);
        Py_XDECREF(fileobject);
        Py_XDECREF(source_bytes_object);
        Py_XDECREF(result);

        return NULL;
    }

    Py_XDECREF(io_module);
    Py_XDECREF(fileobject);
    Py_XDECREF(source_bytes_object);
    Py_XDECREF(result);

    m = PyImport_ExecCodeModuleEx(name, co, filename);

    if (m)
    {
        PyObject *object = NULL;

        if (!r || strcmp(r->filename, filename))
        {
            apr_finfo_t finfo;
            apr_status_t status;

            Py_BEGIN_ALLOW_THREADS
                status = apr_stat(&finfo, filename, APR_FINFO_NORM, pool);
            Py_END_ALLOW_THREADS

                if (status != APR_SUCCESS)
                    object = PyLong_FromLongLong(0);
            else object = PyLong_FromLongLong(finfo.mtime);
        }
        else
        {
            object = PyLong_FromLongLong(r->finfo.mtime);
        }
        if (wsgi_module_add_object(m, "__mtime__", object) < 0)
            PyErr_Clear();
    }
    else
    {
        if (PyErr_ExceptionMatches(PyExc_SystemExit))
        {
            if (!ignore_system_exit)
            {
                if (r)
                    wsgi_log_rerror_locked(APLOG_ERR, 0, r, WSGI_APLOGNO(0107) "SystemExit exception raised "
                                                                               "when doing exec of Python "
                                                                               "script file '%s'.",
                                           filename);
                else
                    wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server, WSGI_APLOGNO(0108) "SystemExit exception raised "
                                                                                        "when doing exec of Python "
                                                                                        "script file '%s'.",
                                          filename);
            }
        }
        else
        {
            if (r)
                wsgi_log_rerror_locked(APLOG_ERR, 0, r, WSGI_APLOGNO(0109) "Unable to execute Python script "
                                                                           "file '%s'.",
                                       filename);
            else
                wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server, WSGI_APLOGNO(0110) "Unable to execute Python script "
                                                                                    "file '%s'.",
                                      filename);

            wsgi_log_python_error(r, filename, application_group, 0);
        }
    }

    Py_XDECREF(co);

    return m;
}

int wsgi_reload_required(apr_pool_t *pool, request_rec *r,
                         const char *filename, PyObject *module,
                         const char *resource,
                         const char *application_group)
{
    PyObject *dict = NULL;
    PyObject *object = NULL;
    apr_time_t mtime = 0;

    dict = PyModule_GetDict(module);
    object = PyDict_GetItemString(dict, "__mtime__");

    if (object)
    {
        mtime = PyLong_AsLongLong(object);
        if (PyErr_Occurred())
        {
            PyErr_Clear();
            return 1;
        }

        if (!r || strcmp(r->filename, filename))
        {
            apr_finfo_t finfo;
            apr_status_t status;

            Py_BEGIN_ALLOW_THREADS
                status = apr_stat(&finfo, filename, APR_FINFO_NORM, pool);
            Py_END_ALLOW_THREADS

                if (status != APR_SUCCESS) return 1;
            else if (mtime != finfo.mtime) return 1;
        }
        else
        {
            if (mtime != r->finfo.mtime)
                return 1;
        }
    }
    else
        return 1;

    if (resource)
    {
        object = PyDict_GetItemString(dict, "reload_required");

        if (object)
        {
            PyObject *args = NULL;
            PyObject *result = NULL;
            PyObject *path = NULL;

            Py_INCREF(object);
            path = PyUnicode_DecodeFSDefault(resource);
            if (path)
                args = Py_BuildValue("(O)", path);
            Py_XDECREF(path);
            if (args)
                result = PyObject_CallObject(object, args);
            Py_XDECREF(args);
            Py_DECREF(object);

            if (result)
            {
                int istrue = PyObject_IsTrue(result);

                if (istrue == 1)
                {
                    Py_DECREF(result);

                    return 1;
                }
            }

            /*
             * A raising callback (or __bool__ raising) is logged but
             * does NOT force a reload. In daemon mode a forced reload
             * on every call means a full daemon restart per request,
             * which for a systematically-failing callback degenerates
             * into a restart loop. Keeping the cached module is the
             * safer behaviour; operators see the traceback in the
             * error log and can fix the callback.
             */

            if (PyErr_Occurred())
                wsgi_log_python_error(r, filename, application_group, 0);

            Py_XDECREF(result);
        }
    }

    return 0;
}

char *wsgi_module_name(apr_pool_t *pool, const char *filename)
{
    char *hash = NULL;
    char *file = NULL;

    /*
     * Calculate a name for the module using the MD5 of its full
     * pathname. This is so that different code files with the
     * same basename are still considered unique. Note that where
     * we believe a case insensitive file system is being used,
     * we always change the file name to lower case so that use
     * of different case in name doesn't result in duplicate
     * modules being loaded for the same file.
     */

    file = (char *)filename;

    if (!wsgi_server_config->case_sensitivity)
    {
        file = apr_pstrdup(pool, file);
        ap_str_tolower(file);
    }

    hash = ap_md5(pool, (const unsigned char *)file);
    return apr_pstrcat(pool, "_mod_wsgi_", hash, NULL);
}

const char *wsgi_format_interp_name(apr_pool_t *p,
                                    const char *application_group)
{
    if (application_group && *application_group)
        return apr_psprintf(p, "sub-interpreter '%s'", application_group);

    return "main interpreter";
}

const char *wsgi_format_interp_context(apr_pool_t *p,
                                       const char *process_group,
                                       const char *application_group)
{
    const char *interp = wsgi_format_interp_name(p, application_group);

    if (process_group && *process_group)
        return apr_psprintf(p, "%s of daemon process '%s'",
                            interp, process_group);

#if defined(MOD_WSGI_WITH_DAEMONS)
    /*
     * No explicit process group supplied. Fall back to the runtime
     * process context: when invoked from a daemon process,
     * wsgi_daemon_process is non-NULL and identifies the daemon group;
     * when invoked from the Apache child, it is NULL and the message
     * is rendered as "in embedded mode".
     */

    if (wsgi_daemon_process)
        return apr_psprintf(p, "%s of daemon process '%s'",
                            interp, wsgi_daemon_process->group->name);
#endif

    return apr_psprintf(p, "%s in embedded mode", interp);
}

const char *wsgi_format_process_context(apr_pool_t *p)
{
#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
        return apr_psprintf(p, "daemon process '%s'",
                            wsgi_daemon_process->group->name);
#endif

    return "embedded mode";
}

#if APR_HAS_THREADS
apr_thread_mutex_t *wsgi_module_lock = NULL;
#endif

/*
 * Apache child process initialisation and cleanup. Initialise
 * global table containing Python interpreter instances and
 * cache reference to main interpreter. Also register cleanup
 * function to delete interpreter on process shutdown.
 */

static apr_status_t wsgi_python_child_cleanup(void *data)
{
    PyObject *interp = NULL;

    /*
     * If not a daemon process need to publish that process
     * is shutting down here. For daemon we did it earlier
     * before trying to wait on request threads. The telemetry
     * lifecycle datagrams (STOPPING and the final-tick + STOPPED
     * sequence) follow the same split — daemon mode emits them in
     * wsgi_daemon_main; embedded mode emits both here back-to-back
     * since Apache has already drained worker requests by the time
     * this cleanup hook runs.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (!wsgi_daemon_process)
    {
        wsgi_publish_process_stopping(wsgi_shutdown_reason);
        wsgi_telemetry_emit_process_stopping(wsgi_shutdown_reason);
        wsgi_telemetry_pause_reporter();
        wsgi_telemetry_emit_final_tick(wsgi_shutdown_reason);
    }
#else
    wsgi_publish_process_stopping(wsgi_shutdown_reason);
    wsgi_telemetry_emit_process_stopping(wsgi_shutdown_reason);
    wsgi_telemetry_pause_reporter();
    wsgi_telemetry_emit_final_tick(wsgi_shutdown_reason);
#endif

    /* Skip destruction of Python interpreter. */

    if (wsgi_server_config->destroy_interpreter == 0)
        return APR_SUCCESS;

    /* In a multithreaded MPM must protect table. */

#if APR_HAS_THREADS
    apr_thread_mutex_lock(wsgi_interp_lock);
#endif

    /*
     * We should be executing in the main thread again at this
     * point but without the GIL, so simply restore the original
     * thread state for that thread that we remembered when we
     * initialised the interpreter.
     */

    PyEval_AcquireThread(wsgi_main_tstate);

    /*
     * Extract a handle to the main Python interpreter from
     * interpreters dictionary as want to process that one last.
     * The entry for the main interpreter is seeded by
     * wsgi_python_child_init and should always be present; if it
     * is not, something has gone seriously wrong. Log and skip
     * the special-case hold so the rest of the cleanup (clearing
     * the dict, releasing the interp lock, tearing down Python
     * itself) still runs.
     */

    interp = PyDict_GetItemString(wsgi_interpreters, "");

    if (interp)
    {
        Py_INCREF(interp);
    }
    else
    {
        wsgi_log_error(APLOG_WARNING, 0, wsgi_server, WSGI_APLOGNO(0111) "Main interpreter reference is missing from "
                                                                         "interpreters dictionary during cleanup in %s.",
                       wsgi_format_process_context(
                           wsgi_server->process->pool));
    }

    /*
     * Remove all items from interpreters dictionary. This will
     * have side affect of calling any exit functions and
     * destroying interpreters we own.
     */

    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                   "Destroying Python sub-interpreters in %s.",
                   wsgi_format_process_context(
                       wsgi_server->process->pool));

    PyDict_Clear(wsgi_interpreters);

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_interp_lock);
#endif

    /*
     * Now we decrement reference on handle for main Python
     * interpreter. This only causes exit functions to be called
     * and doesn't result in interpreter being destroyed as we
     * we didn't previously mark ourselves as the owner of the
     * interpreter. Note that when Python as a whole is later
     * being destroyed it will also call exit functions, but by
     * then the exit function registrations have been removed
     * and so they will not actually be run a second time.
     */

    if (interp)
        Py_DECREF(interp);

    /*
     * The code which performs actual shutdown of the main
     * interpreter expects to be called without the GIL, so
     * we release it here again.
     */

    PyEval_ReleaseThread(wsgi_main_tstate);

    /*
     * Destroy Python itself including the main interpreter.
     */

    if (wsgi_python_initialized)
        wsgi_python_term();

    return APR_SUCCESS;
}

apr_status_t wsgi_python_child_init(apr_pool_t *p)
{
    PyGILState_STATE state;
    PyObject *object = NULL;

    int ignore_system_exit = 0;

    /* Working with Python, so must acquire GIL. */

    state = PyGILState_Ensure();

    /* Finalise any Python objects required by child process. */

    if (PyType_Ready(&Adapter_Type) < 0 || PyType_Ready(&Interpreter_Type) < 0)
    {
        wsgi_log_error_locked(APLOG_CRIT, 0, wsgi_server, WSGI_APLOGNO(0037) "Unable to initialise Python types in %s; "
                                                                             "Python based handlers will not be "
                                                                             "available.",
                              wsgi_format_process_context(
                                  wsgi_server->process->pool));
        PyErr_Clear();
        PyGILState_Release(state);
        wsgi_python_initialized = 0;
        return APR_EGENERAL;
    }

    /* Initialise Python interpreter instance table and lock. */

    wsgi_interpreters = PyDict_New();

    if (!wsgi_interpreters)
    {
        wsgi_log_error_locked(APLOG_CRIT, 0, wsgi_server,
                              WSGI_APLOGNO(0193) "Unable to allocate "
                                                 "interpreters dictionary "
                                                 "for %s; Python based "
                                                 "handlers will not be "
                                                 "available.",
                              wsgi_format_process_context(
                                  wsgi_server->process->pool));
        PyErr_Clear();
        PyGILState_Release(state);
        wsgi_python_initialized = 0;
        return APR_EGENERAL;
    }

#if APR_HAS_THREADS
    apr_thread_mutex_create(&wsgi_interp_lock, APR_THREAD_MUTEX_UNNESTED, p);
    apr_thread_mutex_create(&wsgi_module_lock, APR_THREAD_MUTEX_UNNESTED, p);
    apr_thread_mutex_create(&wsgi_shutdown_lock, APR_THREAD_MUTEX_UNNESTED, p);
#endif

    /*
     * Create an interpreters index using Apache data structure so
     * can iterate over interpreter names without needing Python GIL.
     */

    wsgi_interpreters_index = apr_hash_make(p);

    /*
     * Initialise the key for data related to a thread and force
     * creation of thread info.
     */

    apr_threadkey_private_create(&wsgi_thread_key, NULL, p);

    wsgi_thread_info(1, 0);

    /*
     * Cache a reference to the first Python interpreter
     * instance. This interpreter is special as some third party
     * Python modules will only work when used from within this
     * interpreter. This is generally when they use the Python
     * simplified GIL API or otherwise don't use threading API
     * properly. An empty string for name is used to identify
     * the first Python interpreter instance.
     */

    object = (PyObject *)newInterpreterObject(NULL);

    if (!object)
    {
        wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server,
                              WSGI_APLOGNO(0038) "Python based handlers "
                                                 "will not be available in "
                                                 "%s.",
                              wsgi_format_process_context(
                                  wsgi_server->process->pool));
        PyGILState_Release(state);
        wsgi_python_initialized = 0;
        return APR_EGENERAL;
    }

    if (PyDict_SetItemString(wsgi_interpreters, "", object) < 0)
    {
        wsgi_log_error_locked(APLOG_CRIT, 0, wsgi_server, WSGI_APLOGNO(0039) "Unable to register wrapper for main "
                                                                             "Python interpreter in interpreter cache "
                                                                             "in %s; Python based handlers will not "
                                                                             "be available.",
                              wsgi_format_process_context(
                                  wsgi_server->process->pool));
        Py_DECREF(object);
        PyErr_Clear();
        PyGILState_Release(state);
        wsgi_python_initialized = 0;
        return APR_EGENERAL;
    }

    Py_DECREF(object);

    apr_hash_set(wsgi_interpreters_index, "", APR_HASH_KEY_STRING, "");

    /* Restore the prior thread state and release the GIL. */

    PyGILState_Release(state);

    /* Register cleanups to performed on process shutdown. */

    apr_pool_cleanup_register(p, NULL, wsgi_python_child_cleanup,
                              apr_pool_cleanup_null);

    /* Loop through import scripts for this process and load them. */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process && wsgi_daemon_process->group->threads == 0)
        ignore_system_exit = 1;
#endif

    if (wsgi_import_list)
    {
        apr_array_header_t *scripts = NULL;

        WSGIScriptFile *entries;
        WSGIScriptFile *entry;

        int i;

        scripts = wsgi_import_list;
        entries = (WSGIScriptFile *)scripts->elts;

        for (i = 0; i < scripts->nelts; ++i)
        {
            entry = &entries[i];

            /*
             * Stop loading scripts if this is a daemon process and
             * we have already been flagged to be shutdown.
             */

            if (wsgi_daemon_shutdown)
                break;

            if (!strcmp(wsgi_daemon_group, entry->process_group))
            {
                InterpreterObject *interp = NULL;
                PyObject *modules = NULL;
                PyObject *module = NULL;
                char *name = NULL;
                int exists = 0;

                interp = wsgi_acquire_interpreter(entry->application_group);

                if (!interp)
                {
                    wsgi_log_error(APLOG_CRIT, 0, wsgi_server,
                                   WSGI_APLOGNO(0040) "Unable to acquire %s during daemon "
                                                      "startup script preload; skipping "
                                                      "import.",
                                   wsgi_format_interp_context(
                                       wsgi_server->process->pool, NULL,
                                       entry->application_group));

                    /*
                     * Cannot proceed without a valid interpreter handle;
                     * the module-import code below would operate without
                     * a thread state and wsgi_release_interpreter would
                     * dereference a NULL handle.
                     */

                    continue;
                }

                /* Calculate the Python module name to be used for script. */

                name = wsgi_module_name(p, entry->handler_script);

                /*
                 * Use a lock around the check to see if the module is
                 * already loaded and the import of the module. Strictly
                 * speaking shouldn't be required at this point.
                 */

#if APR_HAS_THREADS
                Py_BEGIN_ALLOW_THREADS
                    apr_thread_mutex_lock(wsgi_module_lock);
                Py_END_ALLOW_THREADS
#endif

                    modules = PyImport_GetModuleDict();
                module = PyDict_GetItemString(modules, name);

                Py_XINCREF(module);

                if (module)
                    exists = 1;

                /*
                 * If script reloading is enabled and the module for it has
                 * previously been loaded, see if it has been modified since
                 * the last time it was accessed.
                 */

                if (module && wsgi_server_config->script_reloading)
                {
                    if (wsgi_reload_required(p, NULL, entry->handler_script,
                                             module, NULL,
                                             entry->application_group))
                    {
                        /*
                         * Script file has changed. Only support module
                         * reloading for dispatch scripts. Remove the
                         * module from the modules dictionary before
                         * reloading it again. If code is executing within
                         * the module at the time, the callers reference
                         * count on the module should ensure it isn't
                         * actually destroyed until it is finished.
                         */

                        Py_DECREF(module);
                        module = NULL;

                        if (PyDict_DelItemString(modules, name) < 0)
                            PyErr_Clear();
                    }
                }

                if (!module)
                {
                    module = wsgi_load_source(p, NULL, name, exists,
                                              entry->handler_script,
                                              entry->process_group,
                                              entry->application_group,
                                              ignore_system_exit);

                    if (PyErr_Occurred())
                        PyErr_Clear();
                }

                /* Safe now to release the module lock. */

#if APR_HAS_THREADS
                apr_thread_mutex_unlock(wsgi_module_lock);
#endif

                /* Cleanup and release interpreter, */

                Py_XDECREF(module);

                wsgi_release_interpreter(interp);
            }
        }
    }

    return APR_SUCCESS;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
