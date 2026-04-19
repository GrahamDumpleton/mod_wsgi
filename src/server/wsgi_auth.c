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

#include "wsgi_auth.h"

#include "wsgi_daemon.h"
#include "wsgi_interp.h"
#include "wsgi_logger.h"
#include "wsgi_version.h"

/* Forward declaration for helper defined in mod_wsgi.c. */

extern char *wsgi_original_uri(request_rec *r);

/* ------------------------------------------------------------------------- */

typedef struct
{
    PyObject_HEAD request_rec *r;
    WSGIRequestConfig *config;
    PyObject *log;
} AuthObject;

static AuthObject *newAuthObject(request_rec *r, WSGIRequestConfig *config)
{
    AuthObject *self;

    self = PyObject_New(AuthObject, &Auth_Type);
    if (self == NULL)
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

static void Auth_dealloc(AuthObject *self)
{
    Py_XDECREF(self->log);

    PyObject_Del(self);
}

static PyObject *Auth_environ(AuthObject *self, const char *group)
{
    PyObject *vars = NULL;
    PyObject *object = NULL;

    request_rec *r = self->r;
    server_rec *s = r->server;
    conn_rec *c = r->connection;
    apr_port_t rport;

    const apr_array_header_t *hdrs_arr;
    const apr_table_entry_t *hdrs;

    const char *value = NULL;

    int i;

    vars = PyDict_New();
    if (!vars)
        return NULL;

    hdrs_arr = apr_table_elts(r->headers_in);
    hdrs = (const apr_table_entry_t *)hdrs_arr->elts;

    for (i = 0; i < hdrs_arr->nelts; ++i)
    {
        if (!hdrs[i].key)
        {
            continue;
        }

        if (!strcasecmp(hdrs[i].key, "Content-type"))
        {
            object = PyUnicode_DecodeLatin1(hdrs[i].val,
                                            strlen(hdrs[i].val), NULL);
            if (!object)
                goto error;
            if (PyDict_SetItemString(vars, "CONTENT_TYPE", object) < 0)
                goto error;
            Py_CLEAR(object);
        }
        else if (!strcasecmp(hdrs[i].key, "Content-length"))
        {
            object = PyUnicode_DecodeLatin1(hdrs[i].val,
                                            strlen(hdrs[i].val), NULL);
            if (!object)
                goto error;
            if (PyDict_SetItemString(vars, "CONTENT_LENGTH", object) < 0)
                goto error;
            Py_CLEAR(object);
        }
        else if (!strcasecmp(hdrs[i].key, "Authorization") || !strcasecmp(hdrs[i].key, "Proxy-Authorization"))
        {
            continue;
        }
        else
        {
            if (hdrs[i].val)
            {
                char *header = wsgi_http2env(r->pool, hdrs[i].key);

                if (header)
                {
                    object = PyUnicode_DecodeLatin1(hdrs[i].val,
                                                    strlen(hdrs[i].val), NULL);
                    if (!object)
                        goto error;
                    if (PyDict_SetItemString(vars, header, object) < 0)
                        goto error;
                    Py_CLEAR(object);
                }
            }
        }
    }

    value = ap_psignature("", r);
    if (value)
    {
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "SERVER_SIGNATURE", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    value = ap_get_server_banner();
    if (value)
    {
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "SERVER_SOFTWARE", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    value = ap_escape_html(r->pool, ap_get_server_name(r));
    if (value)
    {
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "SERVER_NAME", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    if (r->connection->local_ip)
    {
        value = r->connection->local_ip;
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "SERVER_ADDR", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    value = apr_psprintf(r->pool, "%u", ap_get_server_port(r));
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "SERVER_PORT", object) < 0)
        goto error;
    Py_CLEAR(object);

    value = ap_get_remote_host(c, r->per_dir_config, REMOTE_HOST, NULL);
    if (value)
    {
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "REMOTE_HOST", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    if (r->useragent_ip)
    {
        value = r->useragent_ip;
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "REMOTE_ADDR", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    value = ap_document_root(r);
    if (value)
    {
        object = PyUnicode_DecodeFSDefault(value);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "DOCUMENT_ROOT", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    if (s->server_admin)
    {
        value = s->server_admin;
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "SERVER_ADMIN", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    rport = c->client_addr->port;
    value = apr_itoa(r->pool, rport);
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "REMOTE_PORT", object) < 0)
        goto error;
    Py_CLEAR(object);

    value = r->protocol;
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "SERVER_PROTOCOL", object) < 0)
        goto error;
    Py_CLEAR(object);

    value = r->method;
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "REQUEST_METHOD", object) < 0)
        goto error;
    Py_CLEAR(object);

    value = r->args ? r->args : "";
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "QUERY_STRING", object) < 0)
        goto error;
    Py_CLEAR(object);

    value = wsgi_original_uri(r);
    if (value)
    {
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "REQUEST_URI", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    /*
     * XXX Apparently webdav does actually do modifications to
     * the uri and path_info attributes of request and they
     * could be used as part of authorisation.
     */

    if (!strcmp(r->protocol, "INCLUDED"))
    {
        value = r->uri;
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "SCRIPT_NAME", object) < 0)
            goto error;
        Py_CLEAR(object);

        value = r->path_info ? r->path_info : "";
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "PATH_INFO", object) < 0)
            goto error;
        Py_CLEAR(object);
    }
    else if (!r->path_info || !*r->path_info)
    {
        value = r->uri;
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "SCRIPT_NAME", object) < 0)
            goto error;
        Py_CLEAR(object);

        value = "";
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "PATH_INFO", object) < 0)
            goto error;
        Py_CLEAR(object);
    }
    else
    {
        int path_info_start = ap_find_path_info(r->uri, r->path_info);
        value = apr_pstrndup(r->pool, r->uri, path_info_start);
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "SCRIPT_NAME", object) < 0)
            goto error;
        Py_CLEAR(object);

        value = r->path_info ? r->path_info : "";
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "PATH_INFO", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    object = Py_BuildValue("(iii)", AP_SERVER_MAJORVERSION_NUMBER,
                           AP_SERVER_MINORVERSION_NUMBER,
                           AP_SERVER_PATCHLEVEL_NUMBER);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "apache.version", object) < 0)
        goto error;
    Py_CLEAR(object);

    object = Py_BuildValue("(iii)", MOD_WSGI_MAJORVERSION_NUMBER,
                           MOD_WSGI_MINORVERSION_NUMBER,
                           MOD_WSGI_MICROVERSION_NUMBER);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.version", object) < 0)
        goto error;
    Py_CLEAR(object);

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

    object = PyLong_FromLong(self->config->script_reloading);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.script_reloading", object) < 0)
        goto error;
    Py_CLEAR(object);

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

    /*
     * Extensions for accessing SSL certificate information from
     * mod_ssl when in use.
     */

    object = PyObject_GetAttrString((PyObject *)self, "ssl_is_https");
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "mod_ssl.is_https", object) < 0)
        goto error;
    Py_CLEAR(object);

    object = PyObject_GetAttrString((PyObject *)self, "ssl_var_lookup");
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "mod_ssl.var_lookup", object) < 0)
        goto error;
    Py_CLEAR(object);

    return vars;

error:
    Py_XDECREF(object);
    Py_DECREF(vars);
    return NULL;
}

static PyObject *Auth_ssl_is_https(AuthObject *self, PyObject *args)
{
    APR_OPTIONAL_FN_TYPE(ssl_is_https) *ssl_is_https = 0;

    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, ":ssl_is_https"))
        return NULL;

    ssl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

    if (ssl_is_https == 0)
        return Py_BuildValue("i", 0);

    return Py_BuildValue("i", ssl_is_https(self->r->connection));
}

static PyObject *Auth_ssl_var_lookup(AuthObject *self, PyObject *args)
{
    APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *ssl_var_lookup = 0;

    PyObject *item = NULL;
    PyObject *latin_item = NULL;

    char *name = 0;
    char *value = 0;

    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:ssl_var_lookup", &item))
        return NULL;

    if (PyUnicode_Check(item))
    {
        latin_item = PyUnicode_AsLatin1String(item);
        if (!latin_item)
        {
            PyErr_Format(PyExc_TypeError, "byte string value expected, "
                                          "value containing non 'latin-1' characters found");

            return NULL;
        }

        item = latin_item;
    }

    if (!PyBytes_Check(item))
    {
        PyErr_Format(PyExc_TypeError, "byte string value expected, value "
                                      "of type %.200s found",
                     item->ob_type->tp_name);

        Py_XDECREF(latin_item);

        return NULL;
    }

    name = PyBytes_AsString(item);

    ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);

    if (ssl_var_lookup == 0)
    {
        Py_XDECREF(latin_item);

        Py_INCREF(Py_None);

        return Py_None;
    }

    value = ssl_var_lookup(self->r->pool, self->r->server,
                           self->r->connection, self->r, name);

    Py_XDECREF(latin_item);

    if (!value)
    {
        Py_INCREF(Py_None);

        return Py_None;
    }

    return PyUnicode_DecodeLatin1(value, strlen(value), NULL);
}

static PyMethodDef Auth_methods[] = {
    {"ssl_is_https", (PyCFunction)Auth_ssl_is_https, METH_VARARGS, 0},
    {"ssl_var_lookup", (PyCFunction)Auth_ssl_var_lookup, METH_VARARGS, 0},
    {NULL, NULL}};

PyTypeObject Auth_Type = {
    PyVarObject_HEAD_INIT(NULL, 0) "mod_wsgi.Auth", /*tp_name*/
    sizeof(AuthObject),                             /*tp_basicsize*/
    0,                                              /*tp_itemsize*/
    /* methods */
    (destructor)Auth_dealloc, /*tp_dealloc*/
    0,                        /*tp_print*/
    0,                        /*tp_getattr*/
    0,                        /*tp_setattr*/
    0,                        /*tp_compare*/
    0,                        /*tp_repr*/
    0,                        /*tp_as_number*/
    0,                        /*tp_as_sequence*/
    0,                        /*tp_as_mapping*/
    0,                        /*tp_hash*/
    0,                        /*tp_call*/
    0,                        /*tp_str*/
    0,                        /*tp_getattro*/
    0,                        /*tp_setattro*/
    0,                        /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,       /*tp_flags*/
    0,                        /*tp_doc*/
    0,                        /*tp_traverse*/
    0,                        /*tp_clear*/
    0,                        /*tp_richcompare*/
    0,                        /*tp_weaklistoffset*/
    0,                        /*tp_iter*/
    0,                        /*tp_iternext*/
    Auth_methods,             /*tp_methods*/
    0,                        /*tp_members*/
    0,                        /*tp_getset*/
    0,                        /*tp_base*/
    0,                        /*tp_dict*/
    0,                        /*tp_descr_get*/
    0,                        /*tp_descr_set*/
    0,                        /*tp_dictoffset*/
    0,                        /*tp_init*/
    0,                        /*tp_alloc*/
    0,                        /*tp_new*/
    0,                        /*tp_free*/
    0,                        /*tp_is_gc*/
};

static authn_status wsgi_check_password(request_rec *r, const char *user,
                                        const char *password)
{
    WSGIRequestConfig *config;

    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    char *name = NULL;
    int exists = 0;

    const char *script;
    const char *group;

    authn_status status;

    config = wsgi_create_req_config(r->pool, r);

    if (!config->auth_user_script)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Location of WSGI user "
                     "authentication script not provided.",
                     getpid());

        return AUTH_GENERAL_ERROR;
    }

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    script = config->auth_user_script->handler_script;
    group = wsgi_server_group(r, config->auth_user_script->application_group);

    interp = wsgi_acquire_interpreter(group);

    if (!interp)
    {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                      "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                      getpid(), group);

        return AUTH_GENERAL_ERROR;
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
        if (wsgi_reload_required(r->pool, r, script, module, NULL))
        {
            /*
             * Script file has changed. Only support module
             * reloading for authentication scripts. Remove the
             * module from the modules dictionary before
             * reloading it again. If code is executing within
             * the module at the time, the callers reference
             * count on the module should ensure it isn't
             * actually destroyed until it is finished.
             */

            Py_DECREF(module);
            module = NULL;

            PyDict_DelItemString(modules, name);
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
        wsgi_log_python_error(r, NULL, script, 0);

    /* Assume an internal server error unless everything okay. */

    status = AUTH_GENERAL_ERROR;

    /* Determine if script exists and execute it. */

    if (module)
    {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;

        module_dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(module_dict, "check_password");

        if (object)
        {
            PyObject *vars = NULL;
            PyObject *args = NULL;
            PyObject *result = NULL;
            PyObject *method = NULL;

            AuthObject *adapter = NULL;

            adapter = newAuthObject(r, config);

            if (adapter)
            {
                PyObject *user_string = NULL;
                PyObject *password_string = NULL;

                user_string = PyUnicode_DecodeLatin1(user, strlen(user), NULL);
                password_string = PyUnicode_DecodeLatin1(password, strlen(password), NULL);

                if (user_string && password_string)
                    vars = Auth_environ(adapter, group);

                if (vars)
                    args = Py_BuildValue("(OOO)", vars, user_string,
                                         password_string);

                if (args)
                {
                    Py_INCREF(object);
                    result = PyObject_CallObject(object, args);
                    Py_DECREF(object);
                }

                Py_XDECREF(args);
                Py_XDECREF(vars);
                Py_XDECREF(user_string);
                Py_XDECREF(password_string);

                if (result)
                {
                    if (result == Py_None)
                    {
                        status = AUTH_USER_NOT_FOUND;
                    }
                    else if (result == Py_True)
                    {
                        status = AUTH_GRANTED;
                    }
                    else if (result == Py_False)
                    {
                        status = AUTH_DENIED;
                    }
                    else if (PyUnicode_Check(result))
                    {
                        PyObject *str = NULL;

                        str = PyUnicode_AsUTF8String(result);

                        if (str)
                        {
                            adapter->r->user = apr_pstrdup(adapter->r->pool,
                                                           PyBytes_AsString(str));
                            Py_DECREF(str);

                            status = AUTH_GRANTED;
                        }
                    }
                    else
                    {
                        PyErr_SetString(PyExc_TypeError, "Basic auth "
                                                         "provider must return True, False "
                                                         "None or user name as string");
                    }

                    Py_DECREF(result);
                }

                /*
                 * Wipe out references to Apache request object
                 * held by Python objects, so can detect when an
                 * application holds on to the transient Python
                 * objects beyond the life of the request and
                 * thus raise an exception if they are used.
                 */

                adapter->r = NULL;

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method)
                {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else
                {
                    result = PyObject_CallObject(method, NULL);
                    Py_XDECREF(result);
                }

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
        }
        else
        {
            Py_BEGIN_ALLOW_THREADS
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "mod_wsgi (pid=%d): Target WSGI user "
                              "authentication script '%s' does not provide "
                              "'Basic' auth provider.",
                              getpid(), script);
            Py_END_ALLOW_THREADS
        }
    }

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    return status;
}

static authn_status wsgi_get_realm_hash(request_rec *r, const char *user,
                                        const char *realm, char **rethash)
{
    WSGIRequestConfig *config;

    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    char *name = NULL;
    int exists = 0;

    const char *script;
    const char *group;

    authn_status status;

    config = wsgi_create_req_config(r->pool, r);

    if (!config->auth_user_script)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Location of WSGI user "
                     "authentication script not provided.",
                     getpid());

        return AUTH_GENERAL_ERROR;
    }

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    script = config->auth_user_script->handler_script;
    group = wsgi_server_group(r, config->auth_user_script->application_group);

    interp = wsgi_acquire_interpreter(group);

    if (!interp)
    {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                      "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                      getpid(), group);

        return AUTH_GENERAL_ERROR;
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
        if (wsgi_reload_required(r->pool, r, script, module, NULL))
        {
            /*
             * Script file has changed. Only support module
             * reloading for authentication scripts. Remove the
             * module from the modules dictionary before
             * reloading it again. If code is executing within
             * the module at the time, the callers reference
             * count on the module should ensure it isn't
             * actually destroyed until it is finished.
             */

            Py_DECREF(module);
            module = NULL;

            PyDict_DelItemString(modules, name);
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
        wsgi_log_python_error(r, NULL, script, 0);

    /* Assume an internal server error unless everything okay. */

    status = AUTH_GENERAL_ERROR;

    /* Determine if script exists and execute it. */

    if (module)
    {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;

        module_dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(module_dict, "get_realm_hash");

        if (object)
        {
            PyObject *vars = NULL;
            PyObject *args = NULL;
            PyObject *result = NULL;
            PyObject *method = NULL;

            AuthObject *adapter = NULL;

            adapter = newAuthObject(r, config);

            if (adapter)
            {
                PyObject *user_string = NULL;
                PyObject *realm_string = NULL;

                user_string = PyUnicode_DecodeLatin1(user, strlen(user), NULL);
                realm_string = PyUnicode_DecodeLatin1(realm, strlen(realm), NULL);

                if (user_string && realm_string)
                    vars = Auth_environ(adapter, group);

                if (vars)
                    args = Py_BuildValue("(OOO)", vars, user_string,
                                         realm_string);

                if (args)
                {
                    Py_INCREF(object);
                    result = PyObject_CallObject(object, args);
                    Py_DECREF(object);
                }

                Py_XDECREF(args);
                Py_XDECREF(vars);
                Py_XDECREF(user_string);
                Py_XDECREF(realm_string);

                if (result)
                {
                    if (result == Py_None)
                    {
                        status = AUTH_USER_NOT_FOUND;
                    }
                    else if (PyBytes_Check(result))
                    {
                        *rethash = PyBytes_AsString(result);
                        *rethash = apr_pstrdup(r->pool, *rethash);

                        status = AUTH_USER_FOUND;
                    }
                    else if (PyUnicode_Check(result))
                    {
                        PyObject *latin_item;
                        latin_item = PyUnicode_AsLatin1String(result);
                        if (!latin_item)
                        {
                            PyErr_SetString(PyExc_TypeError, "Digest auth "
                                                             "provider must return None "
                                                             "or string object, value "
                                                             "containing non 'latin-1' "
                                                             "characters found");
                        }
                        else
                        {
                            Py_DECREF(result);
                            result = latin_item;

                            *rethash = PyBytes_AsString(result);
                            *rethash = apr_pstrdup(r->pool, *rethash);

                            status = AUTH_USER_FOUND;
                        }
                    }
                    else
                    {
                        PyErr_SetString(PyExc_TypeError, "Digest auth "
                                                         "provider must return None "
                                                         "or string object");
                    }

                    Py_DECREF(result);
                }

                /*
                 * Wipe out references to Apache request object
                 * held by Python objects, so can detect when an
                 * application holds on to the transient Python
                 * objects beyond the life of the request and
                 * thus raise an exception if they are used.
                 */

                adapter->r = NULL;

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method)
                {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else
                {
                    args = PyTuple_New(0);
                    result = PyObject_CallObject(method, args);
                    Py_XDECREF(result);
                    Py_DECREF(args);
                }

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
        }
        else
        {
            Py_BEGIN_ALLOW_THREADS
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "mod_wsgi (pid=%d): Target WSGI user "
                              "authentication script '%s' does not provide "
                              "'Digest' auth provider.",
                              getpid(), script);
            Py_END_ALLOW_THREADS
        }
    }

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    return status;
}

const authn_provider wsgi_authn_provider =
    {
        &wsgi_check_password,
        &wsgi_get_realm_hash};

static int wsgi_groups_for_user(request_rec *r, WSGIRequestConfig *config,
                                apr_table_t **grpstatus)
{
    apr_table_t *grps = apr_table_make(r->pool, 15);

    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    char *name = NULL;
    int exists = 0;

    const char *script;
    const char *group;

    int status = HTTP_INTERNAL_SERVER_ERROR;

    if (!config->auth_group_script)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Location of WSGI group "
                     "authentication script not provided.",
                     getpid());

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    script = config->auth_group_script->handler_script;
    group = wsgi_server_group(r, config->auth_group_script->application_group);

    interp = wsgi_acquire_interpreter(group);

    if (!interp)
    {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                      "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                      getpid(), group);

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
        if (wsgi_reload_required(r->pool, r, script, module, NULL))
        {
            /*
             * Script file has changed. Only support module
             * reloading for authentication scripts. Remove the
             * module from the modules dictionary before
             * reloading it again. If code is executing within
             * the module at the time, the callers reference
             * count on the module should ensure it isn't
             * actually destroyed until it is finished.
             */

            Py_DECREF(module);
            module = NULL;

            PyDict_DelItemString(modules, name);
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
        wsgi_log_python_error(r, NULL, script, 0);

    /* Assume an internal server error unless everything okay. */

    status = HTTP_INTERNAL_SERVER_ERROR;

    /* Determine if script exists and execute it. */

    if (module)
    {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;

        module_dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(module_dict, "groups_for_user");

        if (object)
        {
            PyObject *vars = NULL;
            PyObject *args = NULL;
            PyObject *result = NULL;
            PyObject *method = NULL;

            AuthObject *adapter = NULL;

            adapter = newAuthObject(r, config);

            if (adapter)
            {
                PyObject *user_string = NULL;

                user_string = PyUnicode_DecodeLatin1(r->user, strlen(r->user), NULL);

                if (user_string)
                    vars = Auth_environ(adapter, group);

                if (vars)
                    args = Py_BuildValue("(OO)", vars, user_string);

                if (args)
                {
                    Py_INCREF(object);
                    result = PyObject_CallObject(object, args);
                    Py_DECREF(object);
                }

                Py_XDECREF(args);
                Py_XDECREF(vars);
                Py_XDECREF(user_string);

                if (result)
                {
                    PyObject *iterator;

                    iterator = PyObject_GetIter(result);

                    if (iterator)
                    {
                        PyObject *item;
                        const char *name;

                        status = OK;

                        while ((item = PyIter_Next(iterator)))
                        {
                            if (PyUnicode_Check(item))
                            {
                                PyObject *latin_item;
                                latin_item = PyUnicode_AsLatin1String(item);
                                if (!latin_item)
                                {
                                    Py_BEGIN_ALLOW_THREADS
                                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0,
                                                      r, "mod_wsgi (pid=%d): "
                                                         "Groups for user returned "
                                                         "from '%s' must be an "
                                                         "iterable sequence of "
                                                         "byte strings, value "
                                                         "containing non 'latin-1' "
                                                         "characters found",
                                                      getpid(), script);
                                    Py_END_ALLOW_THREADS

                                        Py_DECREF(item);

                                    status = HTTP_INTERNAL_SERVER_ERROR;

                                    break;
                                }
                                else
                                {
                                    Py_DECREF(item);
                                    item = latin_item;
                                }
                            }

                            if (!PyBytes_Check(item))
                            {
                                Py_BEGIN_ALLOW_THREADS
                                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                                  "mod_wsgi (pid=%d): Groups for "
                                                  "user returned from '%s' must "
                                                  "be an iterable sequence of "
                                                  "byte strings.",
                                                  getpid(),
                                                  script);
                                Py_END_ALLOW_THREADS

                                    Py_DECREF(item);

                                status = HTTP_INTERNAL_SERVER_ERROR;

                                break;
                            }

                            name = PyBytes_AsString(item);

                            apr_table_setn(grps, apr_pstrdup(r->pool, name),
                                           "1");

                            Py_DECREF(item);
                        }

                        Py_DECREF(iterator);
                    }
                    else
                    {
                        Py_BEGIN_ALLOW_THREADS
                            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                          "mod_wsgi (pid=%d): Groups for user "
                                          "returned from '%s' must be an iterable "
                                          "sequence of byte strings.",
                                          getpid(),
                                          script);
                        Py_END_ALLOW_THREADS
                    }

                    Py_DECREF(result);
                }

                /*
                 * Wipe out references to Apache request object
                 * held by Python objects, so can detect when an
                 * application holds on to the transient Python
                 * objects beyond the life of the request and
                 * thus raise an exception if they are used.
                 */

                adapter->r = NULL;

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method)
                {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else
                {
                    args = PyTuple_New(0);
                    result = PyObject_CallObject(method, args);
                    Py_XDECREF(result);
                    Py_DECREF(args);
                }

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
        }
        else
        {
            Py_BEGIN_ALLOW_THREADS
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "mod_wsgi (pid=%d): Target WSGI group "
                              "authentication script '%s' does not provide "
                              "group provider.",
                              getpid(), script);
            Py_END_ALLOW_THREADS
        }
    }

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    if (status == OK)
        *grpstatus = grps;

    return status;
}

static int wsgi_allow_access(request_rec *r, WSGIRequestConfig *config,
                             const char *host)
{
    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    char *name = NULL;
    int exists = 0;

    const char *script;
    const char *group;

    int allow = 0;

    if (!config->access_script)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Location of WSGI host "
                     "access script not provided.",
                     getpid());

        return 0;
    }

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    script = config->access_script->handler_script;
    group = wsgi_server_group(r, config->access_script->application_group);

    interp = wsgi_acquire_interpreter(group);

    if (!interp)
    {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                      "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                      getpid(), group);

        return 0;
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
        if (wsgi_reload_required(r->pool, r, script, module, NULL))
        {
            /*
             * Script file has changed. Only support module
             * reloading for authentication scripts. Remove the
             * module from the modules dictionary before
             * reloading it again. If code is executing within
             * the module at the time, the callers reference
             * count on the module should ensure it isn't
             * actually destroyed until it is finished.
             */

            Py_DECREF(module);
            module = NULL;

            PyDict_DelItemString(modules, name);
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
        wsgi_log_python_error(r, NULL, script, 0);

    /* Assume not allowed unless everything okay. */

    allow = 0;

    /* Determine if script exists and execute it. */

    if (module)
    {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;

        module_dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(module_dict, "allow_access");

        if (object)
        {
            PyObject *vars = NULL;
            PyObject *args = NULL;
            PyObject *result = NULL;
            PyObject *method = NULL;

            AuthObject *adapter = NULL;

            adapter = newAuthObject(r, config);

            if (adapter)
            {
                vars = Auth_environ(adapter, group);

                if (vars)
                    args = Py_BuildValue("(Oz)", vars, host);

                if (args)
                {
                    Py_INCREF(object);
                    result = PyObject_CallObject(object, args);
                    Py_DECREF(object);
                }

                Py_XDECREF(args);
                Py_XDECREF(vars);

                if (result)
                {
                    if (result == Py_None)
                    {
                        allow = -1;
                    }
                    else if (PyBool_Check(result))
                    {
                        if (result == Py_True)
                            allow = 1;
                    }
                    else
                    {
                        Py_BEGIN_ALLOW_THREADS
                            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                          "mod_wsgi (pid=%d): Indicator of "
                                          "host accessibility returned from '%s' "
                                          "must a boolean or None.",
                                          getpid(),
                                          script);
                        Py_END_ALLOW_THREADS
                    }

                    Py_DECREF(result);
                }

                /*
                 * Wipe out references to Apache request object
                 * held by Python objects, so can detect when an
                 * application holds on to the transient Python
                 * objects beyond the life of the request and
                 * thus raise an exception if they are used.
                 */

                adapter->r = NULL;

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method)
                {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else
                {
                    args = PyTuple_New(0);
                    result = PyObject_CallObject(method, args);
                    Py_XDECREF(result);
                    Py_DECREF(args);
                }

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
        }
        else
        {
            Py_BEGIN_ALLOW_THREADS
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "mod_wsgi (pid=%d): Target WSGI host "
                              "access script '%s' does not provide "
                              "host validator.",
                              getpid(), script);
            Py_END_ALLOW_THREADS
        }
    }

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    return allow;
}

int wsgi_hook_access_checker(request_rec *r)
{
    WSGIRequestConfig *config;

    int allow = 0;
    const char *host = NULL;

    config = wsgi_create_req_config(r->pool, r);

    if (!config->access_script)
        return DECLINED;

    host = ap_get_remote_host(r->connection, r->per_dir_config,
                              REMOTE_HOST, NULL);

    if (!host)
        host = r->useragent_ip;

    allow = wsgi_allow_access(r, config, host);

    if (allow < 0)
        return DECLINED;
    else if (allow)
        return OK;

    if (ap_satisfies(r) != SATISFY_ANY || !ap_some_auth_required(r))
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_wsgi (pid=%d): "
                                                   "Client denied by server configuration: '%s'.",
                      getpid(), r->filename);
    }

    return HTTP_FORBIDDEN;
}

static authz_status wsgi_check_authorization(request_rec *r,
                                             const char *require_args,
                                             const void *parsed_require_line)
{
    WSGIRequestConfig *config;

    apr_table_t *grpstatus = NULL;
    const char *t, *w;
    int status;

    if (!r->user)
        return AUTHZ_DENIED_NO_USER;

    config = wsgi_create_req_config(r->pool, r);

    if (!config->auth_group_script)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Location of WSGI group "
                     "authorization script not provided.",
                     getpid());

        return AUTHZ_DENIED;
    }

    status = wsgi_groups_for_user(r, config, &grpstatus);

    if (status != OK)
        return AUTHZ_DENIED;

    if (apr_table_elts(grpstatus)->nelts == 0)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_wsgi (pid=%d): "
                                                   "Authorization of user '%s' to access '%s' failed. "
                                                   "User is not a member of any groups.",
                      getpid(),
                      r->user, r->uri);
        return AUTHZ_DENIED;
    }

    t = require_args;
    while ((w = ap_getword_conf(r->pool, &t)) && w[0])
    {
        if (apr_table_get(grpstatus, w))
        {
            return AUTHZ_GRANTED;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_wsgi (pid=%d): "
                                               "Authorization of user '%s' to access '%s' failed. "
                                               "User is not a member of designated groups.",
                  getpid(),
                  r->user, r->uri);

    return AUTHZ_DENIED;
}

const authz_provider wsgi_authz_provider =
    {
        &wsgi_check_authorization,
        NULL,
};

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
