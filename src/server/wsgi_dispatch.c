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

#include "wsgi_dispatch.h"

#include "wsgi_daemon.h"
#include "wsgi_interp.h"
#include "wsgi_logger.h"
#include "wsgi_module.h"

/* ------------------------------------------------------------------------- */

static DispatchObject *newDispatchObject(request_rec *r,
                                         WSGIRequestConfig *config)
{
    PyObject *module = NULL;
    WSGIModuleState *state = NULL;
    PyTypeObject *type = NULL;
    DispatchObject *self = NULL;

    /*
     * Find the embedded mod_wsgi module for the current
     * interpreter and pull the Dispatch heap type out of its
     * state. Returns NULL with a clear error if the module is
     * not in sys.modules or its state has not been initialised;
     * either indicates an init ordering bug.
     */

    module = PyImport_ImportModule("mod_wsgi");
    if (!module)
        return NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state || !state->Dispatch_Type)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "Dispatch type not initialised for the current "
                        "interpreter; newDispatchObject() called before "
                        "the embedded mod_wsgi module's exec slot ran");
        Py_DECREF(module);
        return NULL;
    }

    type = state->Dispatch_Type;

    self = (DispatchObject *)type->tp_alloc(type, 0);
    Py_DECREF(module);

    if (!self)
        return NULL;

    self->config = config;

    self->r = r;

    self->log = newLogObject(r, APLOG_ERR, NULL, 0);

    if (!self->log)
    {
        Py_DECREF(self);
        return NULL;
    }

    return self;
}

/*
 * Heap-type destructor. Releases the per-request log reference,
 * frees the instance memory via the type's tp_free, and decrements
 * the type's refcount (every heap-type instance owns a reference
 * to its type).
 */

static void Dispatch_dealloc(DispatchObject *self)
{
    PyTypeObject *tp = Py_TYPE(self);

    Py_XDECREF(self->log);

    tp->tp_free(self);
    Py_DECREF(tp);
}

static PyObject *Dispatch_environ(DispatchObject *self, const char *group)
{
    request_rec *r = NULL;

    PyObject *vars = NULL;
    PyObject *object = NULL;

    const apr_array_header_t *head = NULL;
    const apr_table_entry_t *elts = NULL;

    int i = 0;

    /* Create the WSGI environment dictionary. */

    vars = PyDict_New();

    if (!vars)
        return NULL;

    /* Merge the CGI environment into the WSGI environment. */

    r = self->r;

    head = apr_table_elts(r->subprocess_env);
    elts = (apr_table_entry_t *)head->elts;

    for (i = 0; i < head->nelts; ++i)
    {
        if (elts[i].key)
        {
            if (elts[i].val)
            {
                if (!strcmp(elts[i].key, "DOCUMENT_ROOT") ||
                    !strcmp(elts[i].key, "SCRIPT_FILENAME"))
                {
                    object = PyUnicode_DecodeFSDefault(elts[i].val);
                    if (!object)
                    {
                        PyErr_Clear();
                        object = PyUnicode_DecodeLatin1(elts[i].val,
                                                        strlen(elts[i].val), NULL);
                    }
                }
                else
                {
                    object = PyUnicode_DecodeLatin1(elts[i].val,
                                                    strlen(elts[i].val), NULL);
                }
                if (!object)
                    goto error;
                if (PyDict_SetItemString(vars, elts[i].key, object) < 0)
                    goto error;
                Py_CLEAR(object);
            }
            else
            {
                if (PyDict_SetItemString(vars, elts[i].key, Py_None) < 0)
                    goto error;
            }
        }
    }

    /*
     * Need to override process and application group as they
     * are set to the default target, where as we need to set
     * them to context dispatch script is run in. Also need
     * to remove callable object reference.
     */

    object = PyUnicode_FromString("");
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.process_group", object) < 0)
        goto error;
    Py_CLEAR(object);

    object = PyUnicode_DecodeLatin1(group, strlen(group), NULL);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.application_group", object) < 0)
        goto error;
    Py_CLEAR(object);

    if (PyDict_DelItemString(vars, "mod_wsgi.callable_object") < 0)
    {
        if (PyErr_ExceptionMatches(PyExc_KeyError))
            PyErr_Clear();
        else
            goto error;
    }

    /*
     * Setup log object for WSGI errors. Don't decrement
     * reference to log object as keep reference to it.
     */

    if (PyDict_SetItemString(vars, "wsgi.errors",
                             (PyObject *)self->log) < 0)
        goto error;

    /*
     * If Apache extensions are enabled add a CObject reference
     * to the Apache request_rec structure instance.
     */

    if (!wsgi_daemon_pool && self->config->pass_apache_request)
    {
        object = PyCapsule_New(self->r, 0, 0);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "apache.request_rec", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    return vars;

error:
    Py_XDECREF(object);
    Py_DECREF(vars);
    return NULL;
}

/*
 * PyType_Spec for the Dispatch heap type. The only slot with
 * non-default behaviour is tp_dealloc (releases the per-request
 * log); everything else falls back to the framework defaults.
 *
 * tp_name is "mod_wsgi.Dispatch" so error messages and repr()
 * output identify where the type comes from. The type is not
 * exposed as a module attribute; instances are produced by
 * newDispatchObject from C and consumed by the dispatch script
 * machinery in the same request.
 */

static PyType_Slot Dispatch_slots[] = {
    {Py_tp_dealloc, Dispatch_dealloc},
    {0, NULL},
};

static PyType_Spec Dispatch_spec = {
    .name      = "mod_wsgi.Dispatch",
    .basicsize = sizeof(DispatchObject),
    .itemsize  = 0,
    .flags     = Py_TPFLAGS_DEFAULT,
    .slots     = Dispatch_slots,
};

/* ------------------------------------------------------------------------- */

int wsgi_dispatch_init(PyObject *module)
{
    WSGIModuleState *state = NULL;
    PyObject *type = NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state)
        return -1;

    type = PyType_FromModuleAndSpec(module, &Dispatch_spec, NULL);
    if (!type)
        return -1;

    state->Dispatch_Type = (PyTypeObject *)type;

    return 0;
}

int wsgi_execute_dispatch(request_rec *r)
{
    WSGIRequestConfig *config;

    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    char *name = NULL;
    int exists = 0;

    const char *script = NULL;
    const char *group = NULL;

    int status;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    if (!config->dispatch_script)
    {
        wsgi_log_error(APLOG_ERR, 0, wsgi_server, WSGI_APLOGNO(0085) "Location of WSGI dispatch script not provided.");

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    script = config->dispatch_script->handler_script;
    group = wsgi_server_group(r, config->dispatch_script->application_group);

    interp = wsgi_acquire_interpreter(group);

    if (!interp)
    {
        wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0086) "Unable to acquire %s for dispatch hook.",
                        wsgi_format_interp_name(r->pool, group));

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Calculate the Python module name to be used for script. */

    name = wsgi_module_name(r->pool, script);

    /*
     * Use a lock around the check to see if the module is
     * already loaded and the import of the module to prevent
     * two request handlers trying to import the module at the
     * same time.
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

    if (module && config->script_reloading)
    {
        if (wsgi_reload_required(r->pool, r, script, module, NULL, group))
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
        module = wsgi_load_source(r->pool, r, name, exists, script,
                                  "", group, 0);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Log any details of exceptions if import failed. */

    if (PyErr_Occurred())
        wsgi_log_python_error(r, script, NULL, 0);

    /* Assume everything will be okay for now. */

    status = OK;

    /* Determine if script exists and execute it. */

    if (module)
    {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;
        DispatchObject *adapter = NULL;

        module_dict = PyModule_GetDict(module);

        adapter = newDispatchObject(r, config);

        if (adapter)
        {
            PyObject *vars = NULL;
            PyObject *args = NULL;
            PyObject *method = NULL;

            vars = Dispatch_environ(adapter, group);

            if (!vars)
            {
                status = HTTP_INTERNAL_SERVER_ERROR;

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, script, NULL, 0);
            }

            /* First check process_group(). */

#if defined(MOD_WSGI_WITH_DAEMONS)
            if (status == OK)
                object = PyDict_GetItemString(module_dict, "process_group");

            if (object)
            {
                PyObject *result = NULL;

                Py_INCREF(object);
                args = Py_BuildValue("(O)", vars);

                if (args)
                {
                    result = PyObject_CallObject(object, args);
                    Py_DECREF(args);
                }

                Py_DECREF(object);

                if (result)
                {
                    if (result != Py_None)
                    {
                        if (PyBytes_Check(result))
                        {
                            const char *s;

                            s = PyBytes_AsString(result);
                            s = apr_pstrdup(r->pool, s);
                            s = wsgi_process_group(r, s);
                            config->process_group = s;

                            apr_table_setn(r->subprocess_env,
                                           "mod_wsgi.process_group",
                                           config->process_group);
                        }
                        else if (PyUnicode_Check(result))
                        {
                            PyObject *latin_item;
                            latin_item = PyUnicode_AsLatin1String(result);
                            if (!latin_item)
                            {
                                wsgi_set_python_exception_from_cause(
                                        PyExc_TypeError,
                                        "Process group must be a byte "
                                        "string, value containing non "
                                        "'latin-1' characters found");

                                status = HTTP_INTERNAL_SERVER_ERROR;
                            }
                            else
                            {
                                const char *s;

                                Py_DECREF(result);
                                result = latin_item;

                                s = PyBytes_AsString(result);
                                s = apr_pstrdup(r->pool, s);
                                s = wsgi_process_group(r, s);
                                config->process_group = s;

                                apr_table_setn(r->subprocess_env,
                                               "mod_wsgi.process_group",
                                               config->process_group);
                            }
                        }
                        else
                        {
                            PyErr_SetString(PyExc_TypeError, "Process "
                                                             "group must be a byte string");

                            status = HTTP_INTERNAL_SERVER_ERROR;
                        }
                    }

                    Py_DECREF(result);
                }
                else
                    status = HTTP_INTERNAL_SERVER_ERROR;

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, script, NULL, 0);

                object = NULL;
            }
#endif

            /* Now check application_group(). */

            if (status == OK)
                object = PyDict_GetItemString(module_dict, "application_group");

            if (object)
            {
                PyObject *result = NULL;

                Py_INCREF(object);
                args = Py_BuildValue("(O)", vars);

                if (args)
                {
                    result = PyObject_CallObject(object, args);
                    Py_DECREF(args);
                }

                Py_DECREF(object);

                if (result)
                {
                    if (result != Py_None)
                    {
                        if (PyBytes_Check(result))
                        {
                            const char *s;

                            s = PyBytes_AsString(result);
                            s = apr_pstrdup(r->pool, s);
                            s = wsgi_application_group(r, s);
                            config->application_group = s;

                            apr_table_setn(r->subprocess_env,
                                           "mod_wsgi.application_group",
                                           config->application_group);
                        }
                        else if (PyUnicode_Check(result))
                        {
                            PyObject *latin_item;
                            latin_item = PyUnicode_AsLatin1String(result);
                            if (!latin_item)
                            {
                                wsgi_set_python_exception_from_cause(
                                        PyExc_TypeError,
                                        "Application group must be a "
                                        "byte string, value containing "
                                        "non 'latin-1' characters found");

                                status = HTTP_INTERNAL_SERVER_ERROR;
                            }
                            else
                            {
                                const char *s;

                                Py_DECREF(result);
                                result = latin_item;

                                s = PyBytes_AsString(result);
                                s = apr_pstrdup(r->pool, s);
                                s = wsgi_application_group(r, s);
                                config->application_group = s;

                                apr_table_setn(r->subprocess_env,
                                               "mod_wsgi.application_group",
                                               config->application_group);
                            }
                        }
                        else
                        {
                            PyErr_SetString(PyExc_TypeError, "Application "
                                                             "group must be a string "
                                                             "object");

                            status = HTTP_INTERNAL_SERVER_ERROR;
                        }
                    }

                    Py_DECREF(result);
                }
                else
                    status = HTTP_INTERNAL_SERVER_ERROR;

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, script, NULL, 0);

                object = NULL;
            }

            /* Now check callable_object(). */

            if (status == OK)
                object = PyDict_GetItemString(module_dict, "callable_object");

            if (object)
            {
                PyObject *result = NULL;

                Py_INCREF(object);
                args = Py_BuildValue("(O)", vars);

                if (args)
                {
                    result = PyObject_CallObject(object, args);
                    Py_DECREF(args);
                }

                Py_DECREF(object);

                if (result)
                {
                    if (result != Py_None)
                    {
                        if (PyBytes_Check(result))
                        {
                            const char *s;

                            s = PyBytes_AsString(result);
                            s = apr_pstrdup(r->pool, s);
                            s = wsgi_callable_object(r, s);
                            config->callable_object = s;

                            apr_table_setn(r->subprocess_env,
                                           "mod_wsgi.callable_object",
                                           config->callable_object);
                        }
                        else if (PyUnicode_Check(result))
                        {
                            PyObject *latin_item;
                            latin_item = PyUnicode_AsLatin1String(result);
                            if (!latin_item)
                            {
                                wsgi_set_python_exception_from_cause(
                                        PyExc_TypeError,
                                        "Callable object must be a "
                                        "byte string, value containing "
                                        "non 'latin-1' characters found");

                                status = HTTP_INTERNAL_SERVER_ERROR;
                            }
                            else
                            {
                                const char *s;

                                Py_DECREF(result);
                                result = latin_item;

                                s = PyBytes_AsString(result);
                                s = apr_pstrdup(r->pool, s);
                                s = wsgi_callable_object(r, s);
                                config->callable_object = s;

                                apr_table_setn(r->subprocess_env,
                                               "mod_wsgi.callable_object",
                                               config->callable_object);
                            }
                        }
                        else
                        {
                            PyErr_SetString(PyExc_TypeError, "Callable "
                                                             "object must be a string "
                                                             "object");

                            status = HTTP_INTERNAL_SERVER_ERROR;
                        }
                    }

                    Py_DECREF(result);
                }
                else
                    status = HTTP_INTERNAL_SERVER_ERROR;

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, script, NULL, 0);

                object = NULL;
            }

            /*
             * Wipe out references to Apache request object
             * held by Python objects, so can detect when an
             * application holds on to the transient Python
             * objects beyond the life of the request and
             * thus raise an exception if they are used.
             */

            adapter->r = NULL;

            /* Close the log object so data is flushed. */

            method = PyObject_GetAttrString(adapter->log, "close");

            if (!method)
            {
                wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                        "Failed to look up close() method on log object "
                        "during request teardown");
            }
            else
            {
                object = PyObject_CallObject(method, NULL);
            }

            Py_XDECREF(object);
            Py_XDECREF(method);

            /* No longer need adapter object. */

            Py_DECREF((PyObject *)adapter);

            /* Log any details of exceptions if execution failed. */

            if (PyErr_Occurred())
                wsgi_log_python_error(r, script, NULL, 0);

            Py_XDECREF(vars);
        }
    }

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    return status;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
