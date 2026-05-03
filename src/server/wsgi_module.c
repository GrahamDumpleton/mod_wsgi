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

#include "wsgi_module.h"

#include "wsgi_version.h"

#include "wsgi_apache.h"
#include "wsgi_server.h"
#include "wsgi_logger.h"
#include "wsgi_stream.h"
#include "wsgi_metrics.h"
#include "wsgi_interp.h"
#include "wsgi_daemon.h"
#include "wsgi_restrict.h"

/* ------------------------------------------------------------------------- */

int wsgi_module_add_object(PyObject *module, const char *name,
                           PyObject *value)
{
    if (!value)
    {
        PyErr_Format(PyExc_RuntimeError,
                     "Allocation of value for module attribute '%s' failed",
                     name);
        return -1;
    }

    if (PyModule_AddObject(module, name, value) < 0)
    {
        wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                             "PyModule_AddObject() failed for attribute '%s'",
                                             name);
        Py_DECREF(value);
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------------- */

int wsgi_module_install_stable(PyObject *module)
{
    /* Apache mod_wsgi version tuple. */

    if (wsgi_module_add_object(module, "version",
                               Py_BuildValue("(iii)",
                                             MOD_WSGI_MAJORVERSION_NUMBER,
                                             MOD_WSGI_MINORVERSION_NUMBER,
                                             MOD_WSGI_MICROVERSION_NUMBER)) < 0)
        return -1;

    /* File wrapper type. */

    Py_INCREF(&Stream_Type);
    if (wsgi_module_add_object(module, "FileWrapper",
                               (PyObject *)&Stream_Type) < 0)
        return -1;

    /*
     * RequestTimeout exception class. Created once at process scope
     * and shared across every interpreter that imports the module.
     * Derives directly from BaseException so that well-written code
     * does not catch it via 'except Exception:'. Used by the daemon
     * monitor thread when injecting a timeout exception into a
     * worker via PyThreadState_SetAsyncExc().
     */

    if (!wsgi_request_timeout_exc)
    {
        wsgi_request_timeout_exc = PyErr_NewExceptionWithDoc(
            "mod_wsgi.RequestTimeout",
            "Raised by mod_wsgi when a daemon request exceeds the "
            "configured request-timeout and exception injection is "
            "enabled. Derives directly from BaseException so well-written "
            "code does not catch it via 'except Exception:'. May be "
            "caught for cleanup but should be re-raised so the WSGI "
            "adapter can return 504.",
            PyExc_BaseException, NULL);

        if (!wsgi_request_timeout_exc)
            return -1;
    }

    Py_INCREF(wsgi_request_timeout_exc);
    if (wsgi_module_add_object(module, "RequestTimeout",
                               wsgi_request_timeout_exc) < 0)
        return -1;

    /* Module-level methods. */

    if (wsgi_module_add_object(module, "server_metrics",
                               PyCFunction_New(&wsgi_server_metrics_method[0],
                                               NULL)) < 0)
        return -1;

    if (wsgi_module_add_object(module, "process_metrics",
                               PyCFunction_New(&wsgi_process_metrics_method[0],
                                               NULL)) < 0)
        return -1;

    if (wsgi_module_add_object(module, "request_metrics",
                               PyCFunction_New(&wsgi_request_metrics_method[0],
                                               NULL)) < 0)
        return -1;

    if (wsgi_module_add_object(module, "subscribe_events",
                               PyCFunction_New(&wsgi_subscribe_events_method[0],
                                               NULL)) < 0)
        return -1;

    if (wsgi_module_add_object(module, "subscribe_shutdown",
                               PyCFunction_New(&wsgi_subscribe_shutdown_method[0],
                                               NULL)) < 0)
        return -1;

    if (wsgi_module_add_object(module, "request_data",
                               PyCFunction_New(&wsgi_request_data_method[0],
                                               NULL)) < 0)
        return -1;

    /* Empty per-interp containers. */

    if (wsgi_module_add_object(module, "event_callbacks",
                               PyList_New(0)) < 0)
        return -1;

    if (wsgi_module_add_object(module, "shutdown_callbacks",
                               PyList_New(0)) < 0)
        return -1;

    if (wsgi_module_add_object(module, "active_requests",
                               PyDict_New()) < 0)
        return -1;

    return 0;
}

/* ------------------------------------------------------------------------- */

int wsgi_module_install_group_attrs(PyObject *module, const char *name)
{
    int max_threads = 0;
    int max_processes = 0;
    int is_threaded = 0;
    int is_forked = 0;

    if (wsgi_module_add_object(module, "process_group",
                               PyUnicode_DecodeLatin1(wsgi_daemon_group,
                                                      strlen(wsgi_daemon_group),
                                                      NULL)) < 0)
        return -1;

    if (wsgi_module_add_object(module, "application_group",
                               PyUnicode_DecodeLatin1(name, strlen(name),
                                                      NULL)) < 0)
        return -1;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
    {
        if (wsgi_module_add_object(module, "maximum_processes",
                                   PyLong_FromLong(
                                       wsgi_daemon_process->group->processes)) < 0)
            return -1;

        if (wsgi_module_add_object(module, "threads_per_process",
                                   PyLong_FromLong(
                                       wsgi_daemon_process->group->threads)) < 0)
            return -1;

        return 0;
    }
#endif

    ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded);
    if (is_threaded != AP_MPMQ_NOT_SUPPORTED)
        ap_mpm_query(AP_MPMQ_MAX_THREADS, &max_threads);

    ap_mpm_query(AP_MPMQ_IS_FORKED, &is_forked);
    if (is_forked != AP_MPMQ_NOT_SUPPORTED)
    {
        ap_mpm_query(AP_MPMQ_MAX_DAEMON_USED, &max_processes);
        if (max_processes == -1)
            ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &max_processes);
    }

    max_threads = (max_threads <= 0) ? 1 : max_threads;
    max_processes = (max_processes <= 0) ? 1 : max_processes;

    if (wsgi_module_add_object(module, "maximum_processes",
                               PyLong_FromLong(max_processes)) < 0)
        return -1;

    if (wsgi_module_add_object(module, "threads_per_process",
                               PyLong_FromLong(max_threads)) < 0)
        return -1;

    return 0;
}

/* ------------------------------------------------------------------------- */

/*
 * PEP 489 multi-phase init plumbing. The exec slot runs
 * wsgi_restricted_init to create the Restricted heap type and
 * store it in WSGIModuleState. User-facing attribute installation
 * (FileWrapper, RequestTimeout, methods, lists, dict) and per-
 * application-group attribute installation are handled by
 * wsgi_module_create_for_interp.
 *
 * The Py_mod_multiple_interpreters slot is not declared: static
 * PyTypeObject definitions and the process-shared RequestTimeout
 * exception preclude per-interpreter isolation.
 */

static int wsgi_module_exec(PyObject *module)
{
    if (wsgi_restricted_init(module) < 0)
        return -1;

    return 0;
}

static PyModuleDef_Slot wsgi_module_slots[] = {
    {Py_mod_exec, (void *)wsgi_module_exec},
    {0, NULL},
};

struct PyModuleDef wsgi_module_def = {
    PyModuleDef_HEAD_INIT,
    .m_name = "mod_wsgi",
    .m_doc = NULL,
    .m_size = sizeof(WSGIModuleState),
    .m_methods = NULL,
    .m_slots = wsgi_module_slots,
    .m_traverse = NULL,
    .m_clear = NULL,
    .m_free = NULL,
};

PyMODINIT_FUNC PyInit_mod_wsgi(void)
{
    return PyModuleDef_Init(&wsgi_module_def);
}

/* ------------------------------------------------------------------------- */

/*
 * Construct a minimal importlib.machinery.ModuleSpec for the
 * 'mod_wsgi' module. PyModule_FromDefAndSpec requires a real
 * spec object whose 'name' attribute is "mod_wsgi"; loader=None
 * and origin=None match what a no-op import would produce and
 * get copied onto the resulting module as __spec__, __loader__,
 * __file__.
 */

static PyObject *wsgi_module_make_spec(void)
{
    PyObject *machinery = NULL;
    PyObject *spec_class = NULL;
    PyObject *spec = NULL;

    machinery = PyImport_ImportModule("importlib.machinery");
    if (!machinery)
    {
        wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                             "Failed to import importlib.machinery");
        return NULL;
    }

    spec_class = PyObject_GetAttrString(machinery, "ModuleSpec");
    Py_DECREF(machinery);
    if (!spec_class)
    {
        wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                             "Failed to get importlib.machinery.ModuleSpec");
        return NULL;
    }

    spec = PyObject_CallFunction(spec_class, "sO", "mod_wsgi", Py_None);
    Py_DECREF(spec_class);
    if (!spec)
    {
        wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                             "Failed to construct ModuleSpec for 'mod_wsgi'");
        return NULL;
    }

    return spec;
}

/*
 * Build the embedded 'mod_wsgi' module via PEP 489 multi-phase
 * init: create a ModuleSpec, instantiate the module against
 * wsgi_module_def, then run the exec slot. Returns an owned
 * reference, or NULL on failure with Python exception set. The
 * caller is responsible for installing the result in sys.modules.
 */

static PyObject *wsgi_module_build(void)
{
    PyObject *spec = NULL;
    PyObject *module = NULL;

    spec = wsgi_module_make_spec();
    if (!spec)
        return NULL;

    module = PyModule_FromDefAndSpec(&wsgi_module_def, spec);
    Py_DECREF(spec);
    if (!module)
    {
        wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                             "PyModule_FromDefAndSpec() for 'mod_wsgi' failed");
        return NULL;
    }

    if (PyModule_ExecDef(module, &wsgi_module_def) < 0)
    {
        Py_DECREF(module);
        return NULL;
    }

    return module;
}

/* ------------------------------------------------------------------------- */

PyObject *wsgi_module_create_for_interp(const char *name)
{
    PyObject *state_module = NULL;
    PyObject *user_module = NULL;
    PyObject *modules = NULL;

    /*
     * Step 1: build the state-bearing module via PEP 489 multi-
     * phase init. Its exec slot populates WSGIModuleState with the
     * Restricted heap type, which the embedded code looks up via
     * PyImport_ImportModule + PyModule_GetState.
     */

    state_module = wsgi_module_build();
    if (!state_module)
        return NULL;

    /*
     * Step 2: try to import a 'mod_wsgi' Python package from the
     * normal import path. This is the companion package shipped
     * alongside the C module by the mod_wsgi PyPi distribution
     * (mod_wsgi-express); its __init__.py extends __path__ via
     * pkgutil.extend_path so the in-tree subpackages
     * (mod_wsgi.server, mod_wsgi.images, etc.) are importable. It
     * is not a third-party extension point. Only the upstream-
     * provided package is expected here.
     *
     * If the package is present, copy its __path__ across to the
     * state module so subpackage imports continue to resolve once
     * the state module takes its place in sys.modules.
     *
     * If the import fails with ModuleNotFoundError, the package
     * is simply not installed. Typical when the Apache module
     * came from a distro that bundles only the .so.
     */

    user_module = PyImport_ImportModule("mod_wsgi");

    if (user_module)
    {
        PyObject *user_path = NULL;

        if (!*name)
            wsgi_log_error_locked(APLOG_INFO, 0, wsgi_server,
                                  "Imported existing 'mod_wsgi' Python "
                                  "extension module.");

        user_path = PyObject_GetAttrString(user_module, "__path__");
        if (user_path)
        {
            if (PyObject_SetAttrString(state_module, "__path__",
                                       user_path) < 0)
            {
                wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                                     "Failed to copy __path__ from user-supplied "
                                                     "'mod_wsgi' package onto embedded module");
                Py_DECREF(user_path);
                Py_DECREF(user_module);
                Py_DECREF(state_module);
                return NULL;
            }
            Py_DECREF(user_path);
        }
        else
        {
            /* No __path__ on the user module is unusual but not
             * fatal: subpackage imports will simply not work. */
            PyErr_Clear();
        }

        Py_DECREF(user_module);
    }
    else
    {
        /*
         * If the import failed for any reason other than
         * ModuleNotFoundError (a real bug in the user's module:
         * syntax error, exception during module body execution,
         * etc.) surface the traceback so the operator sees what
         * actually went wrong instead of a silent fallback masking
         * the bug.
         */

        if (!PyErr_ExceptionMatches(PyExc_ModuleNotFoundError))
            wsgi_log_python_interp_init_error(name);

        PyErr_Clear();
    }

    /*
     * Step 3: install the state module as sys.modules['mod_wsgi'].
     * PyDict_SetItemString decrefs any prior entry and increfs
     * the new one.
     */

    modules = PyImport_GetModuleDict();
    if (PyDict_SetItemString(modules, "mod_wsgi", state_module) < 0)
    {
        wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                             "Failed to register 'mod_wsgi' in sys.modules");
        Py_DECREF(state_module);
        return NULL;
    }

    /*
     * Step 4: install user-facing attributes (FileWrapper,
     * RequestTimeout, methods, lists, dict) and per-application-
     * group attributes onto the state module.
     */

    if (wsgi_module_install_stable(state_module) < 0)
    {
        Py_DECREF(state_module);
        return NULL;
    }

    if (wsgi_module_install_group_attrs(state_module, name) < 0)
    {
        Py_DECREF(state_module);
        return NULL;
    }

    return state_module;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
