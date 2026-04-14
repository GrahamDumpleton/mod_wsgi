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
#include "wsgi_logger.h"
#include "wsgi_restrict.h"
#include "wsgi_stream.h"
#include "wsgi_metrics.h"
#include "wsgi_daemon.h"
#include "wsgi_thread.h"
#include "wsgi_signal.h"
#include "wsgi_shutdown.h"

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
 * Helper to add an object to a module. Properly handles the case
 * where the value is NULL (i.e. the allocator that produced it
 * failed) and where PyModule_AddObject() itself fails. The latter
 * does not steal the reference on failure, so the value must be
 * decremented in that case. Returns 0 on success, -1 on failure.
 */

static int wsgi_module_add_object(PyObject *module, const char *name,
                                  PyObject *value)
{
    if (!value)
        return -1;

    if (PyModule_AddObject(module, name, value) < 0)
    {
        Py_DECREF(value);
        return -1;
    }

    return 0;
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

    /* Create handle for interpreter and local data. */

    self = PyObject_New(InterpreterObject, &Interpreter_Type);
    if (self == NULL)
        return NULL;

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

    /* Save away the interpreter name. */

    self->name = strdup(name);

    if (interp)
    {
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

        /* Force import of threading module so that main
         * thread attribute of module is correctly set to
         * the main thread and not a secondary request
         * thread.
         */

        module = PyImport_ImportModule("threading");

        Py_XDECREF(module);
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
                PyDict_SetItemString(dict, "_shutdown", wrapper);
                Py_DECREF(wrapper);
            }
        }

        Py_XDECREF(module);
    }

    /*
     * Install restricted objects for STDIN and STDOUT,
     * or log object for STDOUT as appropriate. Don't do
     * this if not running on Win32 and we believe we
     * are running in single process mode, otherwise
     * it prevents use of interactive debuggers such as
     * the 'pdb' module.
     */

    object = newLogObject(NULL, APLOG_ERR, "<stderr>", 1);
    PySys_SetObject("stderr", object);
    Py_DECREF(object);

#ifndef WIN32
    if (wsgi_parent_pid != getpid())
    {
#endif
        if (wsgi_server_config->restrict_stdout == 1)
        {
            object = (PyObject *)newRestrictedObject("sys.stdout");
            PySys_SetObject("stdout", object);
            Py_DECREF(object);
        }
        else
        {
            object = newLogObject(NULL, APLOG_ERR, "<stdout>", 1);
            PySys_SetObject("stdout", object);
            Py_DECREF(object);
        }

        if (wsgi_server_config->restrict_stdin == 1)
        {
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
    if (!object)
        goto failure;

    item = PyUnicode_FromString("mod_wsgi");
    if (!item)
    {
        Py_DECREF(object);
        goto failure;
    }

    if (PyList_Append(object, item) < 0)
    {
        Py_DECREF(item);
        Py_DECREF(object);
        goto failure;
    }

    PySys_SetObject("argv", object);
    Py_DECREF(item);
    Py_DECREF(object);

    /*
     * Install intercept for signal handler registration
     * if appropriate. Don't do this though if number of
     * threads for daemon process was set as 0, indicating
     * a potential daemon process which is running a
     * service script.
     */

    /*
     * If running in daemon mode and there are no threads
     * specified, must be running with service script, in
     * which case we register default signal handler for
     * SIGINT which throws a SystemExit exception. If
     * instead restricting signals, replace function for
     * registering signal handlers so they are ignored.
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

                args = Py_BuildValue("(iO)", SIGTERM, callback);
                res = PyObject_CallObject(func, args);

                if (!res)
                {
                    Py_BEGIN_ALLOW_THREADS
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                                     "mod_wsgi (pid=%d): Call to "
                                     "'signal.signal()' to register exit "
                                     "function failed, ignoring.",
                                     getpid());
                    Py_END_ALLOW_THREADS
                }

                Py_XDECREF(res);
                Py_XDECREF(args);

                Py_XDECREF(callback);

                Py_DECREF(func);
            }
        }

        Py_XDECREF(module);
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
    if (wsgi_daemon_pool)
    {
        module = PyImport_ImportModule("os");

        if (module)
        {
            PyObject *dict = NULL;
            PyObject *key = NULL;
            PyObject *value = NULL;

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "environ");

            if (object)
            {
                struct passwd *pwent;

                pwent = getpwuid(geteuid());

                if (pwent && getenv("USER"))
                {
                    key = PyUnicode_FromString("USER");
                    value = PyUnicode_DecodeFSDefault(pwent->pw_name);

                    PyObject_SetItem(object, key, value);

                    Py_DECREF(key);
                    Py_DECREF(value);
                }

                if (pwent && getenv("USERNAME"))
                {
                    key = PyUnicode_FromString("USERNAME");
                    value = PyUnicode_DecodeFSDefault(pwent->pw_name);

                    PyObject_SetItem(object, key, value);

                    Py_DECREF(key);
                    Py_DECREF(value);
                }

                if (pwent && getenv("LOGNAME"))
                {
                    key = PyUnicode_FromString("LOGNAME");
                    value = PyUnicode_DecodeFSDefault(pwent->pw_name);

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
    if (wsgi_daemon_pool)
    {
        module = PyImport_ImportModule("os");

        if (module)
        {
            PyObject *dict = NULL;
            PyObject *key = NULL;
            PyObject *value = NULL;

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "environ");

            if (object)
            {
                struct passwd *pwent;

                pwent = getpwuid(geteuid());

                if (pwent)
                {
                    key = PyUnicode_FromString("HOME");
                    value = PyUnicode_DecodeFSDefault(pwent->pw_dir);

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

    if (wsgi_python_eggs)
    {
        module = PyImport_ImportModule("os");

        if (module)
        {
            PyObject *dict = NULL;
            PyObject *key = NULL;
            PyObject *value = NULL;

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "environ");

            if (object)
            {
                key = PyUnicode_FromString("PYTHON_EGG_CACHE");
                value = PyUnicode_DecodeFSDefault(wsgi_python_eggs);

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

    module = PyImport_ImportModule("site");

    if (wsgi_python_path && *wsgi_python_path)
    {
        PyObject *path = NULL;

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

            for (i = 0; i < PyList_Size(path); i++)
                PyList_Append(old, PyList_GetItem(path, i));

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "addsitedir");

            if (object)
            {
                const char *start;
                const char *end;
                const char *value;

                PyObject *path_entry;
                PyObject *args;

                PyObject *result = NULL;

                Py_INCREF(object);

                start = wsgi_python_path;
                end = strchr(start, DELIM);

                if (end)
                {
                    path_entry = PyUnicode_DecodeFSDefaultAndSize(start, end - start);
                    value = PyUnicode_AsUTF8(path_entry);
                    start = end + 1;

                    Py_BEGIN_ALLOW_THREADS
                        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                     "mod_wsgi (pid=%d): Adding '%s' to "
                                     "path.",
                                     getpid(), value);
                    Py_END_ALLOW_THREADS

                        args = Py_BuildValue("(O)", path_entry);
                    result = PyObject_CallObject(object, args);

                    if (!result)
                    {
                        Py_BEGIN_ALLOW_THREADS
                            ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                                         "mod_wsgi (pid=%d): Call to "
                                         "'site.addsitedir()' failed for '%s', "
                                         "stopping.",
                                         getpid(), value);
                        Py_END_ALLOW_THREADS
                    }

                    Py_XDECREF(result);
                    Py_DECREF(path_entry);
                    Py_DECREF(args);

                    end = strchr(start, DELIM);

                    while (result && end)
                    {
                        path_entry = PyUnicode_DecodeFSDefaultAndSize(start,
                                                                end - start);
                        value = PyUnicode_AsUTF8(path_entry);
                        start = end + 1;

                        Py_BEGIN_ALLOW_THREADS
                            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                         "mod_wsgi (pid=%d): Adding '%s' to "
                                         "path.",
                                         getpid(), value);
                        Py_END_ALLOW_THREADS

                            args = Py_BuildValue("(O)", path_entry);
                        result = PyObject_CallObject(object, args);

                        if (!result)
                        {
                            Py_BEGIN_ALLOW_THREADS
                                ap_log_error(APLOG_MARK, APLOG_ERR, 0,
                                             wsgi_server, "mod_wsgi (pid=%d): "
                                                          "Call to 'site.addsitedir()' failed "
                                                          "for '%s', stopping.",
                                             getpid(), value);
                            Py_END_ALLOW_THREADS
                        }

                        Py_XDECREF(result);
                        Py_DECREF(path_entry);
                        Py_DECREF(args);

                        end = strchr(start, DELIM);
                    }
                }

                path_entry = PyUnicode_DecodeFSDefault(start);
                value = PyUnicode_AsUTF8(path_entry);

                Py_BEGIN_ALLOW_THREADS
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Adding '%s' to "
                                 "path.",
                                 getpid(), value);
                Py_END_ALLOW_THREADS

                    args = Py_BuildValue("(O)", path_entry);
                result = PyObject_CallObject(object, args);

                if (!result)
                {
                    Py_BEGIN_ALLOW_THREADS
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                                     "mod_wsgi (pid=%d): Call to "
                                     "'site.addsitedir()' failed for '%s'.",
                                     getpid(), start);
                    Py_END_ALLOW_THREADS
                }

                Py_XDECREF(result);
                Py_XDECREF(path_entry);
                Py_DECREF(args);

                Py_DECREF(object);
            }
            else
            {
                Py_BEGIN_ALLOW_THREADS
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Unable to locate "
                                 "'site.addsitedir()'.",
                                 getpid());
                Py_END_ALLOW_THREADS
            }

            for (i = 0; i < PyList_Size(path); i++)
                PyList_Append(tmp, PyList_GetItem(path, i));

            for (i = 0; i < PyList_Size(tmp); i++)
            {
                PyObject *path_item;
                int contains;

                path_item = PyList_GetItem(tmp, i);

                contains = PySequence_Contains(old, path_item);

                if (contains == -1)
                {
                    PyErr_Clear();
                    contains = 0;
                }

                if (!contains)
                {
                    Py_ssize_t index = PySequence_Index(path, path_item);
                    PyList_Append(new, path_item);
                    if (index != -1)
                        PySequence_DelItem(path, index);
                }
            }

            PyList_SetSlice(path, 0, 0, new);

            Py_DECREF(old);
            Py_DECREF(new);
            Py_DECREF(tmp);
        }
        else
        {
            if (!module)
            {
                Py_BEGIN_ALLOW_THREADS
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Unable to import 'site' "
                                 "module.",
                                 getpid());
                Py_END_ALLOW_THREADS
            }

            if (!path)
            {
                Py_BEGIN_ALLOW_THREADS
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Lookup for 'sys.path' "
                                 "failed.",
                                 getpid());
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
    if (wsgi_daemon_process && wsgi_daemon_process->group->home)
    {
        PyObject *path = NULL;
        const char *home = wsgi_daemon_process->group->home;

        path = PySys_GetObject("path");

        if (module && path)
        {
            PyObject *item;

            item = PyUnicode_DecodeFSDefault(home);
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

    if (!module)
    {
        PyObject *modules = NULL;

        modules = PyImport_GetModuleDict();
        module = PyDict_GetItemString(modules, "mod_wsgi");

        if (module)
        {
            PyErr_Print();

            PyDict_DelItemString(modules, "mod_wsgi");
        }

        PyErr_Clear();

        module = PyImport_AddModule("mod_wsgi");

        Py_INCREF(module);
    }
    else if (!*name)
    {
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

    if (wsgi_module_add_object(module, "version",
            Py_BuildValue("(iii)", MOD_WSGI_MAJORVERSION_NUMBER,
                          MOD_WSGI_MINORVERSION_NUMBER,
                          MOD_WSGI_MICROVERSION_NUMBER)) < 0)
        goto failure;

    /* Add type object for file wrapper. */

    Py_INCREF(&Stream_Type);
    if (wsgi_module_add_object(module, "FileWrapper",
                               (PyObject *)&Stream_Type) < 0)
        goto failure;

    /*
     * Add information about process group and application
     * group to the Python 'mod_wsgi' module.
     */

    if (wsgi_module_add_object(module, "process_group",
            PyUnicode_DecodeLatin1(wsgi_daemon_group,
                                   strlen(wsgi_daemon_group), NULL)) < 0)
        goto failure;
    if (wsgi_module_add_object(module, "application_group",
            PyUnicode_DecodeLatin1(name, strlen(name), NULL)) < 0)
        goto failure;

    /*
     * Add information about number of processes and threads
     * available to the WSGI application to the 'mod_wsgi' module.
     * When running in embedded mode, this will be the same as
     * what the 'apache' module records for Apache itself.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
    {
        if (wsgi_module_add_object(module, "maximum_processes",
                PyLong_FromLong(wsgi_daemon_process->group->processes)) < 0)
            goto failure;

        if (wsgi_module_add_object(module, "threads_per_process",
                PyLong_FromLong(wsgi_daemon_process->group->threads)) < 0)
            goto failure;
    }
    else
    {
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
    }
#else
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
#endif

    if (wsgi_module_add_object(module, "server_metrics",
            PyCFunction_New(&wsgi_server_metrics_method[0], NULL)) < 0)
        goto failure;

    if (wsgi_module_add_object(module, "process_metrics",
            PyCFunction_New(&wsgi_process_metrics_method[0], NULL)) < 0)
        goto failure;

    if (wsgi_module_add_object(module, "request_metrics",
            PyCFunction_New(&wsgi_request_metrics_method[0], NULL)) < 0)
        goto failure;

    if (wsgi_module_add_object(module, "subscribe_events",
            PyCFunction_New(&wsgi_subscribe_events_method[0], NULL)) < 0)
        goto failure;

    if (wsgi_module_add_object(module, "subscribe_shutdown",
            PyCFunction_New(&wsgi_subscribe_shutdown_method[0], NULL)) < 0)
        goto failure;

    if (wsgi_module_add_object(module, "event_callbacks",
                               PyList_New(0)) < 0)
        goto failure;

    if (wsgi_module_add_object(module, "shutdown_callbacks",
                               PyList_New(0)) < 0)
        goto failure;

    if (wsgi_module_add_object(module, "active_requests",
                               PyDict_New()) < 0)
        goto failure;

    if (wsgi_module_add_object(module, "request_data",
            PyCFunction_New(&wsgi_request_data_method[0], NULL)) < 0)
        goto failure;

    /* Done with the 'mod_wsgi' module. */

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

            modules = PyImport_GetModuleDict();
            module = PyDict_GetItemString(modules, "apache");

            if (module)
            {
                Py_BEGIN_ALLOW_THREADS
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Unable to import "
                                 "'apache' extension module.",
                                 getpid());
                Py_END_ALLOW_THREADS

                PyErr_Print();

                PyDict_DelItemString(modules, "apache");

                module = NULL;
            }

            PyErr_Clear();
        }
        else
        {
            Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Imported 'apache'.",
                             getpid());
            Py_END_ALLOW_THREADS
        }
    }

    if (!module)
    {
        module = PyImport_AddModule("apache");

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

        if (wsgi_server_config->verbose_debugging)
        {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Bind thread state for "
                         "thread %d against interpreter '%s'.",
                         getpid(),
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

failure:
    /*
     * Cleanup partially constructed interpreter on allocation
     * failure. If we still hold a reference to a Python module
     * being populated, decrement it. If we own the sub interpreter
     * we created, end it which also cleans up all Python objects
     * created within it. Then restore the original thread state,
     * free the heap allocated name and decrement reference count
     * on self.
     */

    Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Failed to create interpreter '%s'.",
                     getpid(), self->name);
    Py_END_ALLOW_THREADS

    Py_XDECREF(module);

    if (self->owner)
    {
        Py_EndInterpreter(tstate);
        PyThreadState_Swap(save_tstate);
    }

    free(self->name);
    Py_DECREF(self);

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

    if (*self->name)
    {
#if APR_HAS_THREADS
        WSGIThreadInfo *thread_handle = NULL;

        thread_handle = wsgi_thread_info(1, 0);

        tstate = apr_hash_get(self->tstate_table, &thread_handle->thread_id,
                              sizeof(thread_handle->thread_id));

        if (!tstate)
        {
            tstate = PyThreadState_New(self->interp);

            if (wsgi_server_config->verbose_debugging)
            {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Create thread state for "
                             "thread %d against interpreter '%s'.",
                             getpid(),
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

    if (self->owner)
    {
        Py_BEGIN_ALLOW_THREADS
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Destroy interpreter '%s'.",
                         getpid(), self->name);
        Py_END_ALLOW_THREADS
    }
    else
    {
        Py_BEGIN_ALLOW_THREADS
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Cleanup interpreter '%s'.",
                         getpid(), self->name);
        Py_END_ALLOW_THREADS
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

    /*
     * In Python 2.5.1 an exit function is no longer used to
     * shutdown and wait on non daemon threads which were created
     * from Python code. Instead, in Py_Main() it explicitly
     * calls 'threading._shutdown()'. Thus need to emulate this
     * behaviour for those versions.
     */

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

    /* If we own it, we destroy it. */

    if (self->owner)
    {
        /*
         * We need to destroy all the thread state objects
         * associated with the interpreter. If there are
         * background threads that were created then this
         * may well cause them to crash the next time they
         * try to run. Only saving grace is that we are
         * trying to shutdown the process.
         */

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
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, wsgi_server,
                     "mod_wsgi: Compiled for Python/%s.", compile);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, wsgi_server,
                     "mod_wsgi: Runtime using Python/%s.", dynamic);
    }
}

apr_status_t wsgi_python_term(void)
{
    PyObject *module = NULL;

    /* Skip destruction of Python interpreter. */

    if (wsgi_server_config->destroy_interpreter == 0)
        return APR_SUCCESS;

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

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                 "mod_wsgi (pid=%d): Python has shutdown.", getpid());

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
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, wsgi_server,
                 "mod_wsgi (pid=%d): Initializing Python failed: %s",
                 getpid(), status.err_msg);

    return 1;
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
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Python home %s.", getpid(),
                         python_home);
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

            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Python home %s.", getpid(),
                         python_home);

#if !defined(WIN32)
            rv = apr_stat(&finfo, python_home, APR_FINFO_NORM, p);

            if (rv != APR_SUCCESS)
            {
                ap_log_error(APLOG_MARK, APLOG_WARNING, rv, wsgi_server,
                             "mod_wsgi (pid=%d): Unable to stat Python home "
                             "%s. Python interpreter may not be able to be "
                             "initialized correctly. Verify the supplied path "
                             "and access permissions for whole of the path.",
                             getpid(), python_home);
            }
            else
            {
                if (finfo.filetype != APR_DIR)
                {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, rv, wsgi_server,
                                 "mod_wsgi (pid=%d): Python home %s is not "
                                 "a directory. Python interpreter may not "
                                 "be able to be initialized correctly. "
                                 "Verify the supplied path.",
                                 getpid(),
                                 python_home);
                }
                else if (access(python_home, X_OK) == -1)
                {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, rv, wsgi_server,
                                 "mod_wsgi (pid=%d): Python home %s is not "
                                 "accessible. Python interpreter may not "
                                 "be able to be initialized correctly. "
                                 "Verify the supplied path and access "
                                 "permissions on the directory.",
                                 getpid(),
                                 python_home);
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
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Setting hash seed to %s.",
                         getpid(), wsgi_server_config->python_hash_seed);
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

        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Initializing Python.", getpid());

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
#if APR_HAS_THREADS
        WSGIThreadInfo *thread_handle = NULL;

        thread_handle = wsgi_thread_info(1, 0);

        tstate = apr_hash_get(handle->tstate_table, &thread_handle->thread_id,
                              sizeof(thread_handle->thread_id));

        if (!tstate)
        {
            tstate = PyThreadState_New(interp);

            if (wsgi_server_config->verbose_debugging)
            {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Create thread state for "
                             "thread %d against interpreter '%s'.",
                             getpid(),
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
    else
    {
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

        event = PyDict_New();

        object = PyUnicode_DecodeLatin1(reason, strlen(reason), NULL);
        PyDict_SetItemString(event, "shutdown_reason", object);
        Py_DECREF(object);

        wsgi_publish_event("process_stopping", event);

        Py_DECREF(event);

        wsgi_release_interpreter(interp);

        hi = apr_hash_next(hi);
    }
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
