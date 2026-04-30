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

#include "wsgi_execute.h"

#include "wsgi_server.h"
#include "wsgi_interp.h"
#include "wsgi_adapter.h"
#include "wsgi_logger.h"
#include "wsgi_metrics.h"
#include "wsgi_daemon.h"

int wsgi_execute_script(request_rec *r)
{
    WSGIRequestConfig *config = NULL;

    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    const char *script = NULL;
    const char *name = NULL;
    int exists = 0;

    int status = HTTP_INTERNAL_SERVER_ERROR;

    WSGIThreadInfo *thread_info = NULL;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    interp = wsgi_acquire_interpreter(config->application_group);

    if (!interp)
    {
        wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0087)
                        "Unable to acquire %s for WSGI request handler "
                        "in %s.",
                        wsgi_format_interp_name(r->pool,
                                                config->application_group),
                        wsgi_format_process_context(r->pool));

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Setup startup timeout if first request and specified. */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
    {
        if (wsgi_startup_shutdown_time == 0)
        {
            if (wsgi_startup_timeout > 0)
            {
                wsgi_log_error_locked(APLOG_INFO, 0, wsgi_server,
                                      "Application startup timer started "
                                      "for daemon process '%s'.",
                                      config->process_group);

                apr_thread_mutex_lock(wsgi_monitor_lock);
                wsgi_startup_shutdown_time = apr_time_now();
                wsgi_startup_shutdown_time += wsgi_startup_timeout;
                apr_thread_mutex_unlock(wsgi_monitor_lock);
            }
        }
    }
#endif

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

        /* Determine the script path to be loaded. */

        if (config->handler_script && *config->handler_script)
    {
        script = config->handler_script;

#if 0
        /*
         * Check for whether a module reference is provided
         * as opposed to a filesystem path.
         */

        if (strlen(script) > 2 && script[0] == '(' &&
            script[strlen(script)-1] == ')') {
            name = apr_pstrndup(r->pool, script+1, strlen(script)-2);

            module = PyImport_ImportModule(name);

            if (!module) {
                wsgi_log_rerror_locked(APLOG_ERR, 0, r, WSGI_APLOGNO(0088)
                                       "Unable to import handler via "
                                       "Python module reference '%s'.",
                                       script);

                wsgi_log_python_error(r, r->filename, NULL, 0);
            }
        }
#endif
    }
    else
    {
        script = r->filename;
    }

    if (!module)
    {
        /* Calculate the Python module name to be used for script. */

        name = wsgi_module_name(r->pool, script);

        modules = PyImport_GetModuleDict();
        module = PyDict_GetItemString(modules, name);

        Py_XINCREF(module);

        if (module)
            exists = 1;

        /*
         * If script reloading is enabled and the module for it has
         * previously been loaded, see if it has been modified since
         * the last time it was accessed. For a handler script will
         * also see if it contains a custom function for determining
         * if a reload should be performed.
         */

        if (module && config->script_reloading)
        {
            if (wsgi_reload_required(r->pool, r, script, module, r->filename,
                                     config->application_group))
            {
                /*
                 * Script file has changed. Discard reference to
                 * loaded module and work out what action we are
                 * supposed to take. Choices are process reloading
                 * and module reloading. Process reloading cannot be
                 * performed unless a daemon process is being used.
                 */

                Py_DECREF(module);
                module = NULL;

#if defined(MOD_WSGI_WITH_DAEMONS)
                if (*config->process_group)
                {
                    /*
                     * Need to restart the daemon process. We bail
                     * out on the request process here, sending back
                     * a special response header indicating that
                     * process is being restarted and that remote
                     * end should abandon connection and attempt to
                     * reconnect again. We also need to signal this
                     * process so it will actually shutdown. The
                     * process supervisor code will ensure that it
                     * is restarted.
                     */

                    wsgi_log_error_locked(APLOG_INFO, 0, r->server,
                                          "Forcing restart of daemon "
                                          "process '%s' due to "
                                          "modification of script '%s'.",
                                          config->process_group, script);

#if APR_HAS_THREADS
                    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

                    wsgi_release_interpreter(interp);

                    r->status = HTTP_INTERNAL_SERVER_ERROR;
                    r->status_line = "200 Rejected";

                    wsgi_shutdown_reason = "script_reload";

                    wsgi_daemon_shutdown++;
                    kill(getpid(), SIGINT);

                    return OK;
                }
#endif

                /*
                 * Need to reload just the script module. Remove
                 * the module from the modules dictionary before
                 * reloading it again. If code is executing
                 * within the module at the time, the callers
                 * reference count on the module should ensure
                 * it isn't actually destroyed until it is
                 * finished.
                 */

                PyDict_DelItemString(modules, name);
            }
        }
    }

    /*
     * When process reloading is in use, or a queue timeout is
     * set, need to indicate that request content should now be
     * sent through. This is done by writing a special response
     * header directly out onto the appropriate network output
     * filter. The special response is picked up by remote end
     * and data will then be sent.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (*config->process_group && (config->script_reloading ||
                                   wsgi_daemon_process->group->queue_timeout != 0))
    {

        ap_filter_t *filters;
        apr_bucket_brigade *bb;
        apr_bucket *b;

        const char *data = "Status: 200 Continue\r\n\r\n";
        long length = strlen(data);

        Py_BEGIN_ALLOW_THREADS

            filters = r->output_filters;
        while (filters && filters->frec->ftype != AP_FTYPE_NETWORK)
        {
            filters = filters->next;
        }

        bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

        b = apr_bucket_transient_create(data, length,
                                        r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);

        b = apr_bucket_flush_create(r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);

        /*
         * This should always work, so ignore any errors
         * from passing the brigade to the network
         * output filter. If there are are problems they
         * will be picked up further down in processing
         * anyway.
         */

        ap_pass_brigade(filters, bb);

        Py_END_ALLOW_THREADS
    }
#endif

    /* Setup metrics for start of request. */

    thread_info = wsgi_start_request(r);

    /* Load module if not already loaded. */

    if (!module)
    {
        module = wsgi_load_source(r->pool, r, name, exists, script,
                                  config->process_group,
                                  config->application_group, 0);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /*
     * Clear startup timeout and prevent from running again if the
     * module was successfully loaded.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (module && wsgi_startup_shutdown_time > 0)
    {
        wsgi_startup_shutdown_time = -1;

        wsgi_log_error_locked(APLOG_INFO, 0, wsgi_server,
                              "Application startup timer cancelled for "
                              "daemon process '%s'.",
                              config->process_group);
    }
#endif

    /* Determine if script exists and execute it. */

    if (module)
    {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;

        module_dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(module_dict, config->callable_object);

        if (object)
        {
            AdapterObject *adapter = NULL;
            adapter = newAdapterObject(r);

            if (adapter)
            {
                PyObject *method = NULL;
                PyObject *args = NULL;
                PyObject *close_result = NULL;

                Py_INCREF(adapter->log_buffer);
                thread_info->log_buffer = adapter->log_buffer;

                Py_INCREF(object);
                status = Adapter_run(adapter, object);
                Py_DECREF(object);

                /*
                 * Wipe out references to Apache request object
                 * held by Python objects, so can detect when an
                 * application holds on to the transient Python
                 * objects beyond the life of the request and
                 * thus raise an exception if they are used.
                 */

                adapter->r = NULL;

                Input_finish(adapter->input);

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method)
                {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 Py_TYPE(adapter->log)->tp_name);
                }
                else
                {
                    args = PyTuple_New(0);
                    close_result = PyObject_CallObject(method, args);
                    Py_DECREF(args);
                }

                Py_XDECREF(close_result);
                Py_XDECREF(method);

                Py_CLEAR(thread_info->log_buffer);

                adapter->bb = NULL;
            }

            Py_XDECREF((PyObject *)adapter);
        }
        else
        {
            wsgi_log_rerror_locked(APLOG_ERR, 0, r, WSGI_APLOGNO(0089) "Target WSGI script '%s' does not "
                                                                       "contain WSGI application '%s'.",
                                   script, config->callable_object);

            status = HTTP_NOT_FOUND;
        }
    }

    /* Log any details of exceptions if execution failed. */

    if (PyErr_Occurred())
        wsgi_log_python_error(r, r->filename, NULL, 0);

    Py_XDECREF(module);

    /* Finalise any metrics at end of the request. */

    wsgi_end_request();

    /* Cleanup and release interpreter. */

    wsgi_release_interpreter(interp);

    return status;
}

/* vi: set sw=4 expandtab : */
