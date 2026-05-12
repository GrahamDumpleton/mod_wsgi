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

#include "wsgi_adapter.h"

#include "wsgi_buckets.h"
#include "wsgi_convert.h"
#include "wsgi_daemon.h"
#include "wsgi_interp.h"
#include "wsgi_logger.h"
#include "wsgi_metrics.h"
#include "wsgi_module.h"
#include "wsgi_stream.h"
#include "wsgi_thread.h"
#include "wsgi_validate.h"
#include "wsgi_version.h"

/* ------------------------------------------------------------------------- */

AdapterObject *newAdapterObject(request_rec *r)
{
    PyObject *module = NULL;
    WSGIModuleState *state = NULL;
    PyTypeObject *type = NULL;
    AdapterObject *self = NULL;

    /*
     * Find the embedded mod_wsgi module for the current
     * interpreter and pull the Adapter heap type out of its
     * state. Returns NULL with a clear error if the module is
     * not in sys.modules or its state has not been initialised;
     * either indicates an init ordering bug.
     */

    module = PyImport_ImportModule("mod_wsgi");
    if (!module)
        return NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state || !state->Adapter_Type)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "Adapter type not initialised for the current "
                        "interpreter; newAdapterObject() called before "
                        "the embedded mod_wsgi module's exec slot ran");
        Py_DECREF(module);
        return NULL;
    }

    type = state->Adapter_Type;

    self = (AdapterObject *)type->tp_alloc(type, 0);
    Py_DECREF(module);

    if (!self)
        return NULL;

    self->result = HTTP_INTERNAL_SERVER_ERROR;

    self->r = r;

    self->bb = NULL;

    self->config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                             &wsgi_module);

    self->status = HTTP_INTERNAL_SERVER_ERROR;
    self->status_line = NULL;
    self->headers = NULL;
    self->sequence = NULL;

    self->content_length_set = 0;
    self->content_length = 0;
    self->output_length = 0;
    self->output_writes = 0;

    self->output_time = 0;

    self->input = NULL;
    self->log_buffer = NULL;
    self->log = NULL;

    self->input = newInputObject(r, self->config->ignore_activity);

    if (!self->input)
    {
        Py_DECREF(self);
        return NULL;
    }

    self->log_buffer = newLogBufferObject(r, APLOG_ERR, "<wsgi.errors>", 0);

    if (!self->log_buffer)
    {
        Py_DECREF(self);
        return NULL;
    }

    self->log = newLogWrapperObject(self->log_buffer);

    if (!self->log)
    {
        Py_DECREF(self);
        return NULL;
    }

    return self;
}

/*
 * Heap-type destructor. Releases all per-request Python state
 * (headers, response sequence, Input reader, log buffer/wrapper),
 * frees the instance memory via the type's tp_free, and decrements
 * the type's refcount (every heap-type instance owns a reference
 * to its type).
 */

static void Adapter_dealloc(AdapterObject *self)
{
    PyTypeObject *tp = Py_TYPE(self);

    Py_XDECREF(self->headers);
    Py_XDECREF(self->sequence);

    Py_XDECREF(self->input);

    Py_XDECREF(self->log_buffer);
    Py_XDECREF(self->log);

    tp->tp_free(self);
    Py_DECREF(tp);
}

static PyObject *Adapter_start_response(AdapterObject *self, PyObject *args)
{
    PyObject *result = NULL;

    PyObject *status_line = NULL;
    PyObject *headers = NULL;
    PyObject *exc_info = Py_None;

    PyObject *status_line_as_bytes = NULL;
    PyObject *headers_as_bytes = NULL;

    PyObject *event = NULL;
    PyObject *item = NULL;

    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "OO!|O:start_response",
                          &status_line, &PyList_Type, &headers, &exc_info))
    {
        return NULL;
    }

    if (exc_info != Py_None && !PyTuple_Check(exc_info))
    {
        PyErr_SetString(PyExc_RuntimeError, "exception info must be a tuple");
        return NULL;
    }

    if (exc_info != Py_None)
    {
        if (self->status_line && !self->headers)
        {
            PyObject *type = NULL;
            PyObject *value = NULL;
            PyObject *traceback = NULL;

            if (!PyArg_ParseTuple(exc_info, "OOO", &type,
                                  &value, &traceback))
            {
                return NULL;
            }

            Py_INCREF(type);
            Py_INCREF(value);
            Py_INCREF(traceback);

            PyErr_Restore(type, value, traceback);

            return NULL;
        }
    }
    else if (self->status_line && !self->headers)
    {
        PyErr_SetString(PyExc_RuntimeError, "headers have already been sent");
        return NULL;
    }

    /* Publish event for the start of the response. */

    if (wsgi_event_subscribers())
    {
        WSGIThreadInfo *thread_info;

        thread_info = wsgi_thread_info(0, 0);

        event = PyDict_New();

        if (!event)
            goto finally;

        if (self->r->log_id)
        {
            item = PyUnicode_DecodeLatin1(self->r->log_id,
                                          strlen(self->r->log_id), NULL);
            if (!item)
                goto finally;
            if (PyDict_SetItemString(event, "request_id", item) < 0)
                goto finally;
            Py_CLEAR(item);
        }

        if (PyDict_SetItemString(event, "response_status", status_line) < 0 ||
            PyDict_SetItemString(event, "response_headers", headers) < 0 ||
            PyDict_SetItemString(event, "exception_info", exc_info) < 0 ||
            PyDict_SetItemString(event, "request_data",
                                 thread_info->request_data) < 0)
            goto finally;

        wsgi_publish_event("response_started", event);

        Py_CLEAR(event);
    }

    status_line_as_bytes = wsgi_convert_status_line_to_bytes(status_line);

    if (!status_line_as_bytes)
        goto finally;

    headers_as_bytes = wsgi_convert_headers_to_bytes(headers);

    if (!headers_as_bytes)
        goto finally;

    self->status_line = apr_pstrdup(self->r->pool, PyBytes_AsString(
                                                       status_line_as_bytes));
    self->status = (int)strtol(self->status_line, NULL, 10);

    /* Transfer ownership of headers_as_bytes to self->headers and
     * disclaim the local so the finally XDECREF below is a no-op
     * for this object — avoids the +1/-1 refcount round-trip the
     * older INCREF-then-XDECREF pattern incurred. */

    Py_XDECREF(self->headers);
    self->headers = headers_as_bytes;
    headers_as_bytes = NULL;

    result = PyObject_GetAttrString((PyObject *)self, "write");

finally:
    Py_XDECREF(event);
    Py_XDECREF(item);
    Py_XDECREF(status_line_as_bytes);
    Py_XDECREF(headers_as_bytes);

    return result;
}

static int Adapter_output(AdapterObject *self, const char *data,
                          apr_off_t length, PyObject *string_object,
                          int exception_when_aborted)
{
    Py_ssize_t i;
    Py_ssize_t headers_count;
    apr_status_t rv;
    request_rec *r;

    /* output_start / output_finish bracket the GIL-released regions
     * around ap_pass_brigade and apr_brigade_cleanup. They are
     * captured *inside* each WSGI_BEGIN_ALLOW_THREADS block, so the
     * accumulated self->output_time measures only the time the WSGI
     * app spent waiting for Apache to take its data — header
     * processing, bucket construction and the GIL re-acquire wait
     * (which WSGI_END_ALLOW_THREADS attributes to gil_wait_time)
     * are deliberately excluded. Same pattern as Input_read_from_input
     * uses for self->time. */
    apr_time_t output_start = 0;
    apr_time_t output_finish = 0;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_idle_timeout && !self->config->ignore_activity)
    {
        apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);

        if (wsgi_idle_timeout)
        {
            wsgi_idle_shutdown_time = apr_time_now();
            wsgi_idle_shutdown_time += wsgi_idle_timeout;
        }

        apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);
    }
#endif

    if (!self->status_line)
    {
        PyErr_SetString(PyExc_RuntimeError, "response has not been started");
        return 0;
    }

    r = self->r;

    /* Count how many separate blocks have been output. */

    if (string_object)
        self->output_writes++;

    /* Have response headers yet been sent. */

    if (self->headers)
    {
        /*
         * Now setup the response headers in request object. We
         * have already converted any native strings in the
         * headers to byte strings and validated the format of
         * the header names and values so can skip all the error
         * checking.
         */

        r->status = self->status;
        r->status_line = self->status_line;

        headers_count = PyList_Size(self->headers);

        for (i = 0; i < headers_count; i++)
        {
            PyObject *tuple = NULL;

            PyObject *object1 = NULL;
            PyObject *object2 = NULL;

            char *name = NULL;
            char *value = NULL;

            tuple = PyList_GetItem(self->headers, i);

            object1 = PyTuple_GetItem(tuple, 0);
            object2 = PyTuple_GetItem(tuple, 1);

            name = PyBytes_AsString(object1);
            value = PyBytes_AsString(object2);

            if (!strcasecmp(name, "Content-Type"))
            {
                /*
                 * In a daemon child process we cannot call the
                 * function ap_set_content_type() as want to
                 * avoid adding any output filters based on the
                 * type of file being served as this will be
                 * done in the main Apache child process which
                 * proxied the request to the daemon process.
                 */

                if (*self->config->process_group)
                    r->content_type = apr_pstrdup(r->pool, value);
                else
                    ap_set_content_type(r, apr_pstrdup(r->pool, value));
            }
            else if (!strcasecmp(name, "Content-Length"))
            {
                char *endstr;
                apr_off_t length;

                if (wsgi_strtoff(&length, value, &endstr, 10) || *endstr || length < 0)
                {

                    PyErr_SetString(PyExc_ValueError,
                                    "invalid content length");

                    /* No I/O has happened yet on this code path, so
                     * nothing to fold into output_time. */

                    return 0;
                }

                ap_set_content_length(r, length);

                self->content_length_set = 1;
                self->content_length = length;
            }
            else if (!strcasecmp(name, "WWW-Authenticate"))
            {
                apr_table_add(r->err_headers_out, name, value);
            }
            else
            {
                apr_table_add(r->headers_out, name, value);
            }
        }

        /*
         * Reset flag indicating whether '100 Continue' response
         * expected. If we don't do this then if an attempt to read
         * input for the first time is after headers have been
         * sent, then Apache is wrongly generate the '100 Continue'
         * response into the response content. Not sure if this is
         * a bug in Apache, or that it truly believes that input
         * will never be read after the response headers have been
         * sent.
         */

        r->expecting_100 = 0;

        /* No longer need headers now that they have been sent. */

        Py_DECREF(self->headers);
        self->headers = NULL;
    }

    /*
     * If content length was specified, ensure that we don't
     * actually output more data than was specified as being
     * sent as otherwise technically in violation of HTTP RFC.
     */

    if (length)
    {
        apr_off_t output_length = length;

        if (self->content_length_set)
        {
            if (self->output_length < self->content_length)
            {
                if (self->output_length + length > self->content_length)
                {
                    length = self->content_length - self->output_length;
                }
            }
            else
                length = 0;
        }

        self->output_length += output_length;
    }

    /* Now output any data. */

    if (length)
    {
        apr_bucket *b;

        /*
         * When using Apache 2.X can use lower level
         * bucket brigade APIs. This is preferred as
         * ap_rwrite()/ap_rflush() will grow memory in
         * the request pool on each call, which will
         * result in an increase in memory use over time
         * when streaming of data is being performed.
         * The memory is still reclaimed, but only at
         * the end of the request. Using bucket brigade
         * API avoids this, and also avoids any copying
         * of response data due to buffering performed
         * by ap_rwrite().
         */

        if (r->connection->aborted)
        {
            if (!exception_when_aborted)
            {
                wsgi_log_rerror_locked(APLOG_TRACE1, 0, self->r,
                                       "Client closed connection.");
            }
            else
                PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi client "
                                               "connection closed.");

            /* No I/O has happened yet on this code path, so nothing
             * to fold into output_time. */

            return 0;
        }

        if (!self->bb)
        {
            self->bb = apr_brigade_create(r->pool,
                                          r->connection->bucket_alloc);
        }

#if 0
        if (string_object) {
            b = wsgi_apr_bucket_python_create(data, length,
                    self->config->application_group, string_object,
                    r->connection->bucket_alloc);
        }
        else {
#endif
        b = apr_bucket_transient_create(data, (apr_size_t)length,
                                        r->connection->bucket_alloc);
#if 0
        }
#endif

        APR_BRIGADE_INSERT_TAIL(self->bb, b);

        b = apr_bucket_flush_create(r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(self->bb, b);

        WSGI_BEGIN_ALLOW_THREADS
        output_start = apr_time_now();
        rv = ap_pass_brigade(r->output_filters, self->bb);
        output_finish = apr_time_now();
        if (output_finish > output_start)
            self->output_time += (output_finish - output_start);
        WSGI_END_ALLOW_THREADS

        if (rv != APR_SUCCESS)
        {
            char status_buffer[512];
            const char *error_message;

            if (!exception_when_aborted)
            {
                error_message = apr_psprintf(r->pool, "Unable to write "
                                                      "response data: %s",
                                             apr_strerror(rv, status_buffer,
                                                          sizeof(status_buffer) - 1));

                wsgi_log_rerror_locked(APLOG_TRACE1, 0, self->r,
                                       "%s.", error_message);
            }
            else
            {
                error_message = apr_psprintf(r->pool, "Apache/mod_wsgi "
                                                      "failed to write response data: %s",
                                             apr_strerror(rv, status_buffer,
                                                          sizeof(status_buffer) - 1));

                PyErr_SetString(PyExc_IOError, error_message);
            }

            /* output_time already folded above. */

            return 0;
        }

        WSGI_BEGIN_ALLOW_THREADS
        output_start = apr_time_now();
        apr_brigade_cleanup(self->bb);
        output_finish = apr_time_now();
        if (output_finish > output_start)
            self->output_time += (output_finish - output_start);
        WSGI_END_ALLOW_THREADS
    }

    /*
     * Check whether aborted connection was found when data
     * being written, otherwise will not be flagged until next
     * time that data is being written. Early detection is
     * better as it may have been the last data block being
     * written and application may think that data has all
     * been written. In a streaming application, we also want
     * to avoid any additional data processing to generate any
     * successive data.
     */

    if (r->connection->aborted)
    {
        if (!exception_when_aborted)
        {
            wsgi_log_rerror_locked(APLOG_TRACE1, 0, self->r,
                                   "Client closed connection.");
        }
        else
            PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi client "
                                           "connection closed.");

        return 0;
    }

    return 1;
}

/* Split buckets at 1GB when sending large files. */

#define MAX_BUCKET_SIZE (0x40000000)

static int Adapter_output_file(AdapterObject *self, apr_file_t *tmpfile,
                               apr_off_t offset, apr_off_t len)
{
    request_rec *r;
    apr_bucket *b;
    apr_status_t rv;
    apr_bucket_brigade *bb;

    apr_file_t *dupfile = NULL;

    /* Same in-block timing pattern as Adapter_output: bracket the
     * GIL-released ap_pass_brigade region (and its companion
     * apr_brigade_destroy calls) so the accumulated time excludes
     * the GIL re-acquire wait that WSGI_END_ALLOW_THREADS attributes
     * to gil_wait_time instead. */
    apr_time_t output_start = 0;
    apr_time_t output_finish = 0;

    r = self->r;

    if (r->connection->aborted)
    {
        PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi client "
                                       "connection closed.");
        return 0;
    }

    if (len == 0)
        return 1;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    rv = apr_file_dup(&dupfile, tmpfile, r->pool);

    if (rv != APR_SUCCESS)
    {
        char status_buffer[512];
        const char *error_message;

        error_message = apr_psprintf(r->pool, "Apache/mod_wsgi failed "
                                              "to duplicate file handle: %s.",
                                     apr_strerror(rv, status_buffer,
                                                  sizeof(status_buffer) - 1));

        PyErr_SetString(PyExc_IOError, error_message);

        WSGI_BEGIN_ALLOW_THREADS
        output_start = apr_time_now();
        apr_brigade_destroy(bb);
        output_finish = apr_time_now();
        if (output_finish > output_start)
            self->output_time += (output_finish - output_start);
        WSGI_END_ALLOW_THREADS

        return 0;
    }

    if (sizeof(apr_off_t) == sizeof(apr_size_t) || len < MAX_BUCKET_SIZE)
    {
        /* Can use a single bucket to send file. */

#if 0
        b = apr_bucket_file_create(tmpfile, offset, (apr_size_t)len, r->pool,
                                   r->connection->bucket_alloc);
#endif
        b = apr_bucket_file_create(dupfile, offset, (apr_size_t)len, r->pool,
                                   r->connection->bucket_alloc);
    }
    else
    {
        /* Need to create multiple buckets to send file. */

#if 0
        b = apr_bucket_file_create(tmpfile, offset, MAX_BUCKET_SIZE, r->pool,
                                   r->connection->bucket_alloc);
#endif
        b = apr_bucket_file_create(dupfile, offset, MAX_BUCKET_SIZE, r->pool,
                                   r->connection->bucket_alloc);

        while (len > MAX_BUCKET_SIZE)
        {
            apr_bucket *cb;
            apr_bucket_copy(b, &cb);
            APR_BRIGADE_INSERT_TAIL(bb, cb);
            b->start += MAX_BUCKET_SIZE;
            len -= MAX_BUCKET_SIZE;
        }

        /* Resize just the last bucket */

        b->length = (apr_size_t)len;
    }

    APR_BRIGADE_INSERT_TAIL(bb, b);

    b = apr_bucket_flush_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    WSGI_BEGIN_ALLOW_THREADS
    output_start = apr_time_now();
    rv = ap_pass_brigade(r->output_filters, bb);
    output_finish = apr_time_now();
    if (output_finish > output_start)
        self->output_time += (output_finish - output_start);
    WSGI_END_ALLOW_THREADS

    if (rv != APR_SUCCESS)
    {
        char status_buffer[512];
        const char *error_message;

        error_message = apr_psprintf(r->pool, "Apache/mod_wsgi failed "
                                              "to write response data: %s.",
                                     apr_strerror(rv,
                                                  status_buffer, sizeof(status_buffer) - 1));

        PyErr_SetString(PyExc_IOError, error_message);
        return 0;
    }

    WSGI_BEGIN_ALLOW_THREADS
    output_start = apr_time_now();
    apr_brigade_destroy(bb);
    output_finish = apr_time_now();
    if (output_finish > output_start)
        self->output_time += (output_finish - output_start);
    WSGI_END_ALLOW_THREADS

    if (r->connection->aborted)
    {
        PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi client connection "
                                       "closed.");
        return 0;
    }

    return 1;
}

static PyObject *Adapter_environ(AdapterObject *self)
{
    request_rec *r = NULL;

    PyObject *vars = NULL;
    PyObject *object = NULL;

    const apr_array_header_t *head = NULL;
    const apr_table_entry_t *elts = NULL;

    int i = 0;

    const char *scheme = NULL;

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
            /*
             * Hide internal microsecond-string carriers from the
             * WSGI environ. The canonical mod_wsgi timing keys
             * are inserted below as Python floats in seconds.
             */

            size_t key_len = strlen(elts[i].key);

            if (key_len > 12 &&
                memcmp(elts[i].key, "mod_wsgi.", 9) == 0 &&
                memcmp(elts[i].key + key_len - 3, "_us", 3) == 0)
            {
                continue;
            }

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

    if (PyDict_DelItemString(vars, "PATH") < 0)
    {
        if (PyErr_ExceptionMatches(PyExc_KeyError))
            PyErr_Clear();
        else
            goto error;
    }

    /* Now setup all the WSGI specific environment values. */

    object = Py_BuildValue("(ii)", 1, 0);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "wsgi.version", object) < 0)
        goto error;
    Py_CLEAR(object);

    object = PyBool_FromLong(wsgi_multithread);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "wsgi.multithread", object) < 0)
        goto error;
    Py_CLEAR(object);

    object = PyBool_FromLong(wsgi_multiprocess);
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "wsgi.multiprocess", object) < 0)
        goto error;
    Py_CLEAR(object);

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
    {
        if (wsgi_daemon_process->group->threads == 1 &&
            wsgi_daemon_process->group->maximum_requests == 1)
        {
            if (PyDict_SetItemString(vars, "wsgi.run_once", Py_True) < 0)
                goto error;
        }
        else
        {
            if (PyDict_SetItemString(vars, "wsgi.run_once", Py_False) < 0)
                goto error;
        }
    }
    else
    {
        if (PyDict_SetItemString(vars, "wsgi.run_once", Py_False) < 0)
            goto error;
    }
#else
    if (PyDict_SetItemString(vars, "wsgi.run_once", Py_False) < 0)
        goto error;
#endif

    scheme = apr_table_get(r->subprocess_env, "HTTPS");

    if (scheme && (!strcasecmp(scheme, "On") || !strcmp(scheme, "1")))
    {
        object = PyUnicode_FromString("https");
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "wsgi.url_scheme", object) < 0)
            goto error;
        Py_CLEAR(object);
    }
    else
    {
        object = PyUnicode_FromString("http");
        if (!object)
            goto error;
        if (PyDict_SetItemString(vars, "wsgi.url_scheme", object) < 0)
            goto error;
        Py_CLEAR(object);
    }

    /*
     * We remove the HTTPS variable because WSGI compliant
     * applications shouldn't rely on it. Instead they should
     * use wsgi.url_scheme. We do this even if SetEnv was
     * used to set HTTPS from Apache configuration. That is
     * we convert it into the correct variable and remove the
     * original.
     */

    if (scheme)
    {
        if (PyDict_DelItemString(vars, "HTTPS") < 0)
        {
            if (PyErr_ExceptionMatches(PyExc_KeyError))
                PyErr_Clear();
            else
                goto error;
        }
    }

    /*
     * Setup log object for WSGI errors. Don't decrement
     * reference to log object as keep reference to it.
     */

    if (PyDict_SetItemString(vars, "wsgi.errors",
                             (PyObject *)self->log) < 0)
        goto error;

    /* Setup input object for request content. */

    if (PyDict_SetItemString(vars, "wsgi.input",
                             (PyObject *)self->input) < 0)
        goto error;

    if (PyDict_SetItemString(vars, "wsgi.input_terminated", Py_True) < 0)
        goto error;

    /* Setup file wrapper object for efficient file responses. */

    {
        PyTypeObject *file_wrapper = wsgi_stream_type();
        if (!file_wrapper)
            goto error;
        if (PyDict_SetItemString(vars, "wsgi.file_wrapper",
                                 (PyObject *)file_wrapper) < 0)
            goto error;
    }

    /* Add Apache and mod_wsgi version information. */

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

    /*
     * Publish request timing instants in seconds since the
     * epoch, matching the corresponding fields on the
     * request_started and request_finished event payloads.
     * queue_start and daemon_start are 0.0 in embedded mode.
     */

    object = PyFloat_FromDouble(apr_time_sec(
        (double)self->config->request_start));
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.request_start", object) < 0)
        goto error;
    Py_CLEAR(object);

    object = PyFloat_FromDouble(apr_time_sec(
        (double)self->config->queue_start));
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.queue_start", object) < 0)
        goto error;
    Py_CLEAR(object);

    object = PyFloat_FromDouble(apr_time_sec(
        (double)self->config->daemon_start));
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.daemon_start", object) < 0)
        goto error;
    Py_CLEAR(object);

    object = PyFloat_FromDouble(apr_time_sec((double)self->start_time));
    if (!object)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.application_start", object) < 0)
        goto error;
    Py_CLEAR(object);

    /*
     * If Apache extensions are enabled and running in embedded
     * mode add a CObject reference to the Apache request_rec
     * structure instance.
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

static int Adapter_process_file_wrapper(AdapterObject *self)
{
    int done = 0;

#ifndef WIN32
    PyObject *filelike = NULL;
    PyObject *method = NULL;
    PyObject *object = NULL;

    apr_status_t rv = 0;

    apr_os_file_t fd = -1;
    apr_file_t *tmpfile = NULL;
    apr_finfo_t finfo;

    apr_off_t fd_offset = 0;
    apr_off_t fo_offset = 0;

    apr_off_t length = 0;

    /* Perform file wrapper optimisations where possible. */

    {
        int is_instance;
        PyTypeObject *file_wrapper = wsgi_stream_type();

        if (!file_wrapper)
        {
            PyErr_Clear();
            return 0;
        }

        is_instance = PyObject_IsInstance(self->sequence,
                                          (PyObject *)file_wrapper);

        if (is_instance == -1)
        {
            PyErr_Clear();
            return 0;
        }

        if (!is_instance)
            return 0;
    }

    /*
     * Only attempt to perform optimisations if the
     * write() function returned by start_response()
     * function has not been called with non zero length
     * data. In other words if no prior response content
     * generated. Technically it could be done, but want
     * to have a consistent rule about how specifying a
     * content length affects how much of a file is
     * sent. Don't want to have to take into
     * consideration whether write() function has been
     * called or not as just complicates things.
     */

    if (self->output_length != 0)
        return 0;

    /*
     * Work out if file wrapper is associated with a
     * file like object, where that file object is
     * associated with a regular file. If it does then
     * we can optimise how the contents of the file are
     * sent out. If no such associated file descriptor
     * then it needs to be processed like any other
     * iterable value.
     */

    filelike = PyObject_GetAttrString((PyObject *)self->sequence, "filelike");

    if (!filelike)
    {
        PyErr_Clear();
        return 0;
    }

    fd = PyObject_AsFileDescriptor(filelike);
    if (fd == -1)
    {
        PyErr_Clear();
        Py_DECREF(filelike);
        return 0;
    }

    /*
     * On some platforms, such as Linux, sendfile() system call
     * will not work on UNIX sockets. Thus when using daemon mode
     * cannot enable that feature.
     */

    if (self->config->enable_sendfile)
        apr_os_file_put(&tmpfile, &fd, APR_SENDFILE_ENABLED, self->r->pool);
    else
        apr_os_file_put(&tmpfile, &fd, 0, self->r->pool);

    rv = apr_file_info_get(&finfo, APR_FINFO_SIZE | APR_FINFO_TYPE, tmpfile);
    if (rv != APR_SUCCESS || finfo.filetype != APR_REG)
    {
        Py_DECREF(filelike);
        return 0;
    }

    /*
     * Because Python file like objects potentially have
     * their own buffering layering, or use an operating
     * system FILE object which also has a buffering
     * layer on top of a normal file descriptor, need to
     * determine from the file like object its position
     * within the file and use that as starting position.
     * Note that it is assumed that user had flushed any
     * modifications to the file as necessary. Also, we
     * need to make sure we remember the original file
     * descriptor position as will need to restore that
     * position so it matches the upper buffering layers
     * when done. This is done to avoid any potential
     * problems if file like object does anything strange
     * in its close() method which relies on file position
     * being what it thought it should be.
     */

    rv = apr_file_seek(tmpfile, APR_CUR, &fd_offset);
    if (rv != APR_SUCCESS)
    {
        Py_DECREF(filelike);
        return 0;
    }

    method = PyObject_GetAttrString(filelike, "tell");
    Py_DECREF(filelike);
    if (!method)
    {
        PyErr_Clear();
        return 0;
    }

    object = PyObject_CallObject(method, NULL);
    Py_DECREF(method);

    if (!object)
    {
        PyErr_Clear();
        return 0;
    }

    if (PyLong_Check(object))
    {
        fo_offset = PyLong_AsLongLong(object);
    }
    else
    {
        Py_DECREF(object);
        return 0;
    }

    if (PyErr_Occurred())
    {
        Py_DECREF(object);
        PyErr_Clear();
        return 0;
    }

    Py_DECREF(object);

    /*
     * For a file wrapper object need to always ensure
     * that response headers are parsed. This is done so
     * that if the content length header has been
     * defined we can get its value and use it to limit
     * how much of a file is being sent. The WSGI 1.0
     * specification says that we are meant to send all
     * available bytes from the file, however this is
     * questionable as sending more than content length
     * would violate HTTP RFC. Note that this doesn't
     * actually flush the headers out when using Apache
     * 2.X. This is good, as we want to still be able to
     * set the content length header if none set and file
     * is seekable. If processing response headers fails,
     * then need to return as if done, with error being
     * logged later.
     */

    if (!Adapter_output(self, "", 0, NULL, 0))
        return 1;

    /*
     * If content length wasn't defined then determine
     * the amount of data which is available to send and
     * set the content length response header. Either
     * way, if can work out length then send data
     * otherwise fall through and treat it as normal
     * iterable.
     */

    if (!self->content_length_set)
    {
        length = finfo.size - fo_offset;
        self->output_length += length;

        ap_set_content_length(self->r, length);

        self->content_length_set = 1;
        self->content_length = length;

        if (Adapter_output_file(self, tmpfile, fo_offset, length))
            self->result = OK;

        done = 1;
    }
    else
    {
        length = finfo.size - fo_offset;
        self->output_length += length;

        /* Use user specified content length instead. */

        length = self->content_length;

        if (Adapter_output_file(self, tmpfile, fo_offset, length))
            self->result = OK;

        done = 1;
    }

    /*
     * Restore position of underlying file descriptor.
     * If this fails, then not much we can do about it.
     */

    apr_file_seek(tmpfile, APR_SET, &fd_offset);

#endif

    return done;
}

int Adapter_run(AdapterObject *self, PyObject *object)
{
    PyObject *module = NULL;
    WSGIModuleState *state = NULL;

    PyObject *vars = NULL;
    PyObject *start = NULL;
    PyObject *args = NULL;
    PyObject *iterator = NULL;
    PyObject *close = NULL;

    PyObject *evwrapper = NULL;

    PyObject *value = NULL;
    PyObject *event = NULL;

    const char *msg = NULL;
    apr_off_t length = 0;

    WSGIThreadInfo *thread_handle = NULL;

    apr_time_t finish_time;

    WSGIThreadCPUUsage start_usage;
    WSGIThreadCPUUsage end_usage;

    int aborted = 0;

    /*
     * The per-interpreter mod_wsgi.RequestTimeout exception class is
     * read from WSGIModuleState by the PyErr_ExceptionMatches checks
     * in the request-completion path below. Fetched once up front so
     * every consumer site can reach it without redoing the import.
     */

    module = PyImport_ImportModule("mod_wsgi");
    if (!module)
        goto error;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state)
        goto error;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_idle_timeout && !self->config->ignore_activity)
    {
        apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);

        if (wsgi_idle_timeout)
        {
            wsgi_idle_shutdown_time = apr_time_now();
            wsgi_idle_shutdown_time += wsgi_idle_timeout;
        }

        apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);
    }
#endif

    self->start_time = apr_time_now();

    /* Make application_start visible to the slow-record active-snapshot
     * path; without this an in-flight slow request would fall back to
     * slot->start_us (the slot-claim instant, before module load) and
     * conflate framework-load time with application time. */
    wsgi_record_application_start(self->start_time);

    apr_table_setn(self->r->subprocess_env, "mod_wsgi.application_start_us",
                   apr_psprintf(self->r->pool, "%" APR_TIME_T_FMT,
                                self->start_time));

    vars = Adapter_environ(self);

    if (!vars)
        goto error;

    value = PyLong_FromLongLong(wsgi_process_metrics->total_requests);
    if (!value)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.total_requests", value) < 0)
        goto error;
    Py_CLEAR(value);

    thread_handle = wsgi_thread_info(1, 1);

    value = PyLong_FromLong(thread_handle->thread_id);
    if (!value)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.thread_id", value) < 0)
        goto error;
    Py_CLEAR(value);

    value = PyLong_FromLongLong(thread_handle->request_count);
    if (!value)
        goto error;
    if (PyDict_SetItemString(vars, "mod_wsgi.thread_requests", value) < 0)
        goto error;
    Py_CLEAR(value);

    /* Publish event for the start of the request. */

    start_usage.user_time = 0.0;
    start_usage.system_time = 0.0;

    if (wsgi_event_subscribers())
    {
        wsgi_thread_cpu_usage(&start_usage);

        event = PyDict_New();

        if (!event)
            goto error;

        if (self->r->log_id)
        {
            value = PyUnicode_DecodeLatin1(self->r->log_id,
                                           strlen(self->r->log_id), NULL);
            if (!value)
                goto error;
            if (PyDict_SetItemString(event, "request_id", value) < 0)
                goto error;
            Py_CLEAR(value);
        }

        value = PyLong_FromLong(thread_handle->thread_id);
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "thread_id", value) < 0)
            goto error;
        Py_CLEAR(value);

        value = PyLong_FromLong(self->config->daemon_connects);
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "daemon_connects", value) < 0)
            goto error;
        Py_CLEAR(value);

        value = PyLong_FromLong(self->config->daemon_restarts);
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "daemon_restarts", value) < 0)
            goto error;
        Py_CLEAR(value);

        value = PyLong_FromLong((long)self->config->server_pid);
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "server_pid", value) < 0)
            goto error;
        Py_CLEAR(value);

        value = PyFloat_FromDouble(apr_time_sec(
            (double)self->config->request_start));
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "request_start", value) < 0)
            goto error;
        Py_CLEAR(value);

        value = PyFloat_FromDouble(apr_time_sec(
            (double)self->config->queue_start));
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "queue_start", value) < 0)
            goto error;
        Py_CLEAR(value);

        value = PyFloat_FromDouble(apr_time_sec(
            (double)self->config->daemon_start));
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "daemon_start", value) < 0)
            goto error;
        Py_CLEAR(value);

        if (PyDict_SetItemString(event, "application_object", object) < 0)
            goto error;

        if (PyDict_SetItemString(event, "request_environ", vars) < 0)
            goto error;

        value = PyFloat_FromDouble(apr_time_sec((double)self->start_time));
        if (!value)
            goto error;
        if (PyDict_SetItemString(event, "application_start", value) < 0)
            goto error;
        Py_CLEAR(value);

        if (PyDict_SetItemString(event, "request_data",
                                 thread_handle->request_data) < 0)
            goto error;

        wsgi_publish_event("request_started", event);

        evwrapper = PyDict_GetItemString(event, "application_object");

        if (evwrapper)
        {
            if (evwrapper != object)
            {
                Py_INCREF(evwrapper);
                object = evwrapper;
            }
            else
                evwrapper = NULL;
        }

        Py_CLEAR(event);
    }

    /* Pass the request through to the WSGI application. */

    thread_handle->request_count++;

    start = PyObject_GetAttrString((PyObject *)self, "start_response");

    if (start)
        args = Py_BuildValue("(OO)", vars, start);

    if (args)
        self->sequence = PyObject_CallObject(object, args);

    if (self->sequence != NULL)
    {
        if (!Adapter_process_file_wrapper(self))
        {
            iterator = PyObject_GetIter(self->sequence);

            if (iterator != NULL)
            {
                PyObject *item = NULL;

                while ((item = PyIter_Next(iterator)))
                {
                    if (!PyBytes_Check(item))
                    {
                        PyErr_Format(PyExc_TypeError, "sequence of byte "
                                                      "string values expected, value of "
                                                      "type %.200s found",
                                     item->ob_type->tp_name);
                        Py_DECREF(item);
                        break;
                    }

                    msg = PyBytes_AsString(item);
                    length = PyBytes_Size(item);

                    if (!msg)
                    {
                        Py_DECREF(item);
                        break;
                    }

                    if (length && !Adapter_output(self, msg, length,
                                                  item, 0))
                    {
                        if (!PyErr_Occurred())
                            aborted = 1;
                        Py_DECREF(item);
                        break;
                    }

                    Py_DECREF(item);
                }
            }

            if (!PyErr_Occurred())
            {
                if (!aborted)
                {
                    /*
                     * In the case where the response was empty we
                     * need to ensure we explicitly flush out the
                     * headers. This is done by calling the output
                     * routine but with an empty string as content.
                     * This could be gated on whether any content
                     * had already been sent, but easier to just call
                     * it all the time.
                     */

                    if (Adapter_output(self, "", 0, NULL, 0))
                        self->result = OK;
                }
                else
                {
                    /*
                     * If the client connection was already marked
                     * as aborted, then it indicates the client has
                     * closed the connection. In this case mark the
                     * final result as okay rather than an error so
                     * that the access log still records the original
                     * HTTP response code for the request rather than
                     * overriding it. If don't do this then access
                     * log will show 500 when the WSGI application
                     * itself had run fine.
                     */

                    self->result = OK;
                }
            }

            Py_XDECREF(iterator);
        }

        /*
         * Log warning if more response content generated than was
         * indicated, or less, if there was no errors generated by
         * the application and connection wasn't aborted.
         */

        if (self->content_length_set && ((!PyErr_Occurred() && !aborted &&
                                          self->output_length != self->content_length) ||
                                         (self->output_length > self->content_length)))
        {
            wsgi_log_rerror_locked(APLOG_TRACE1, 0, self->r,
                                   "Content length mismatch, expected %s, "
                                   "response generated %s: %s",
                                   apr_off_t_toa(self->r->pool,
                                                 self->content_length),
                                   apr_off_t_toa(self->r->pool,
                                                 self->output_length),
                                   self->r->filename);
        }

        if (PyErr_Occurred())
        {
            int is_request_timeout = 0;

            if (state->RequestTimeout &&
                PyErr_ExceptionMatches(state->RequestTimeout))
                is_request_timeout = 1;

            if (is_request_timeout && !(self->status_line && !self->headers))
            {
                /*
                 * RequestTimeout was injected and reached the adapter
                 * before the response headers were flushed. Produce a
                 * 504 Gateway Timeout response. The worker thread
                 * returns to the pool; the process is not shut down.
                 */

                self->r->status = HTTP_GATEWAY_TIME_OUT;
                self->r->status_line = "504 Gateway Timeout";
                self->status = HTTP_GATEWAY_TIME_OUT;
                self->result = OK;

                PyErr_Clear();

                wsgi_log_rerror_locked(APLOG_INFO, 0, self->r,
                                       "Request interrupted by "
                                       "RequestTimeout; thread "
                                       "recovered.");
            }
            else
            {
                /*
                 * Response content has already been sent, so cannot
                 * return an internal server error as Apache will
                 * append its own error page. Thus need to return OK
                 * and just truncate the response.
                 */

                if (self->status_line && !self->headers)
                    self->result = OK;

                if (is_request_timeout)
                {
                    /*
                     * RequestTimeout but the headers were already
                     * flushed; the wire status is committed and we
                     * can only truncate. Clear the exception so it
                     * isn't logged as an unhandled error.
                     */

                    PyErr_Clear();

                    wsgi_log_rerror_locked(APLOG_INFO, 0, self->r,
                                           "Request interrupted by "
                                           "RequestTimeout after headers "
                                           "sent; response truncated.");
                }
                else
                    wsgi_log_python_error(self->r, self->r->filename,
                                          NULL, 1);

                /*
                 * If response content is being chunked and an error
                 * occurred, we need to prevent the sending of the EOS
                 * bucket so a client is able to detect that the the
                 * response was incomplete.
                 */

                if (self->r->chunked)
                    self->r->eos_sent = 1;
            }
        }

        /* PyObject_HasAttrString swallows all exceptions raised by
         * the lookup, so a custom __getattribute__ that raises would
         * be silently treated as "no close method". Use
         * GetAttrString and only treat AttributeError as benign — any
         * other exception gets a context preamble logged here, then
         * is left set so the PyErr_Occurred() block below prints the
         * traceback after our preamble. */

        close = PyObject_GetAttrString(self->sequence, "close");

        if (close)
        {
            PyObject *args = NULL;
            PyObject *data = NULL;

            args = Py_BuildValue("()");

            if (args)
            {
                data = PyObject_CallObject(close, args);
                Py_XDECREF(data);
                Py_DECREF(args);
            }

            Py_DECREF(close);
        }
        else if (PyErr_ExceptionMatches(PyExc_AttributeError))
        {
            PyErr_Clear();
        }
        else
        {
            wsgi_log_rerror_locked(APLOG_ERR, 0, self->r,
                                   WSGI_APLOGNO(0194) "Lookup of "
                                                      "'close' attribute "
                                                      "on WSGI response "
                                                      "iterable raised an "
                                                      "exception.");
        }

        if (PyErr_Occurred())
        {
            if (state->RequestTimeout &&
                PyErr_ExceptionMatches(state->RequestTimeout))
            {
                PyErr_Clear();
            }
            else
                wsgi_log_python_error(self->r, self->r->filename, NULL, 1);
        }
    }
    else
    {
        /*
         * The WSGI application call itself raised (no sequence
         * returned). If RequestTimeout was injected before
         * start_response was called, produce a 504 directly and
         * return the worker to the pool. Otherwise log the error
         * normally and let the default 500 result apply.
         */

        if (state->RequestTimeout &&
            PyErr_ExceptionMatches(state->RequestTimeout))
        {
            self->r->status = HTTP_GATEWAY_TIME_OUT;
            self->r->status_line = "504 Gateway Timeout";
            self->status = HTTP_GATEWAY_TIME_OUT;
            self->result = OK;

            PyErr_Clear();

            wsgi_log_rerror_locked(APLOG_INFO, 0, self->r,
                                   "Request interrupted by "
                                   "RequestTimeout; thread "
                                   "recovered.");
        }
        else
            wsgi_log_python_error(self->r, self->r->filename, NULL, 1);
    }

    /* Publish event for the end of the request. */

    finish_time = apr_time_now();

    if (wsgi_event_subscribers())
    {
        double application_time = 0.0;
        double output_time = 0.0;
        apr_uint64_t gil_wait_us = 0;
        apr_uint64_t gil_wait_count = 0;

        wsgi_gil_wait_current(&gil_wait_us, &gil_wait_count);

        event = PyDict_New();

        if (event)
        {
            if (self->r->log_id)
            {
                value = PyUnicode_DecodeLatin1(self->r->log_id,
                                               strlen(self->r->log_id), NULL);
                if (value)
                {
                    if (PyDict_SetItemString(event, "request_id", value) < 0)
                        goto event_error;
                    Py_CLEAR(value);
                }
                else
                    goto event_error;
            }

            value = PyLong_FromLong(thread_handle->thread_id);
            if (value)
            {
                if (PyDict_SetItemString(event, "thread_id", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyLong_FromLong((long)self->config->server_pid);
            if (value)
            {
                if (PyDict_SetItemString(event, "server_pid", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyFloat_FromDouble(apr_time_sec(
                (double)self->config->request_start));
            if (value)
            {
                if (PyDict_SetItemString(event, "request_start", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyFloat_FromDouble(apr_time_sec(
                (double)self->config->queue_start));
            if (value)
            {
                if (PyDict_SetItemString(event, "queue_start", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyFloat_FromDouble(apr_time_sec(
                (double)self->config->daemon_start));
            if (value)
            {
                if (PyDict_SetItemString(event, "daemon_start", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyLong_FromLongLong(self->input->reads);
            if (value)
            {
                if (PyDict_SetItemString(event, "input_reads", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyLong_FromLongLong(self->input->bytes);
            if (value)
            {
                if (PyDict_SetItemString(event, "input_length", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyFloat_FromDouble(apr_time_sec((double)self->input->time));
            if (value)
            {
                if (PyDict_SetItemString(event, "input_time", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyLong_FromLongLong(self->output_length);
            if (value)
            {
                if (PyDict_SetItemString(event, "output_length", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyLong_FromLongLong(self->output_writes);
            if (value)
            {
                if (PyDict_SetItemString(event, "output_writes", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            output_time = apr_time_sec((double)self->output_time);

            if (output_time < 0.0)
                output_time = 0.0;

            application_time = apr_time_sec((double)finish_time - self->start_time);

            if (application_time < 0.0)
                application_time = 0.0;

            if (start_usage.user_time != 0.0)
            {
                if (wsgi_thread_cpu_usage(&end_usage))
                {
                    double user_seconds;
                    double system_seconds;
                    double total_seconds;

                    user_seconds = end_usage.user_time;
                    user_seconds -= start_usage.user_time;

                    if (user_seconds < 0.0)
                        user_seconds = 0.0;

                    system_seconds = end_usage.system_time;
                    system_seconds -= start_usage.system_time;

                    if (system_seconds < 0.0)
                        system_seconds = 0.0;

                    total_seconds = user_seconds + system_seconds;

                    if (total_seconds && total_seconds > application_time)
                    {
                        user_seconds = (user_seconds / total_seconds) * application_time;
                        system_seconds = application_time - user_seconds;
                    }

                    value = PyFloat_FromDouble(user_seconds);
                    if (value)
                    {
                        if (PyDict_SetItemString(event, "cpu_user_time", value) < 0)
                            goto event_error;
                        Py_CLEAR(value);
                    }
                    else
                        goto event_error;

                    value = PyFloat_FromDouble(system_seconds);
                    if (value)
                    {
                        if (PyDict_SetItemString(event, "cpu_system_time", value) < 0)
                            goto event_error;
                        Py_CLEAR(value);
                    }
                    else
                        goto event_error;

                    value = PyFloat_FromDouble(user_seconds + system_seconds);
                    if (value)
                    {
                        if (PyDict_SetItemString(event, "cpu_time", value) < 0)
                            goto event_error;
                        Py_CLEAR(value);
                    }
                    else
                        goto event_error;
                }
            }

            value = PyFloat_FromDouble(output_time);
            if (value)
            {
                if (PyDict_SetItemString(event, "output_time", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyFloat_FromDouble(apr_time_sec((double)finish_time));
            if (value)
            {
                if (PyDict_SetItemString(event, "application_finish", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyFloat_FromDouble(application_time);
            if (value)
            {
                if (PyDict_SetItemString(event, "application_time", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyLong_FromLong(self->status);
            if (value)
            {
                if (PyDict_SetItemString(event, "status", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyFloat_FromDouble((double)gil_wait_us / 1.0e6);
            if (value)
            {
                if (PyDict_SetItemString(event, "gil_wait_time", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            value = PyLong_FromUnsignedLongLong(gil_wait_count);
            if (value)
            {
                if (PyDict_SetItemString(event, "gil_wait_count", value) < 0)
                    goto event_error;
                Py_CLEAR(value);
            }
            else
                goto event_error;

            if (PyDict_SetItemString(event, "request_data",
                                     thread_handle->request_data) < 0)
                goto event_error;

            /*
             * If any allocation while building the event failed,
             * discard the partial event rather than publishing
             * misleading data to subscribers. wsgi_log_python_error
             * also clears the exception so the subscriber callbacks
             * aren't invoked with an error pending.
             */

        event_error:
            if (PyErr_Occurred())
                wsgi_log_python_error(self->r, self->r->filename, NULL, 1);
            else
                wsgi_publish_event("request_finished", event);

            Py_XDECREF(value);
            Py_CLEAR(event);
        }
        else
            wsgi_log_python_error(self->r, self->r->filename, NULL, 1);
    }

    /*
     * Record server and application time for metrics. Values
     * are the time request first accepted by child workers,
     * the time that the WSGI application started processing
     * the request, and when the WSGI application finished the
     * request.
     */

    wsgi_record_request_times(self->config->request_start,
                              self->config->queue_start, self->config->daemon_start,
                              self->start_time, finish_time,
                              self->input ? self->input->bytes : 0,
                              self->input ? self->input->reads : 0,
                              self->output_length, self->output_writes,
                              self->input ? self->input->time : 0,
                              self->output_time,
                              self->status);

    /*
     * If result indicates an internal server error, then
     * replace the status line in the request object else
     * that provided by the application will be what is used
     * in any error page automatically generated by Apache.
     */

error:
    if (PyErr_Occurred())
        wsgi_log_python_error(self->r, self->r->filename, NULL, 1);

    if (self->result == HTTP_INTERNAL_SERVER_ERROR)
        self->r->status_line = "500 Internal Server Error";

    Py_XDECREF(args);
    Py_XDECREF(start);
    Py_XDECREF(vars);

    Py_XDECREF(event);
    Py_XDECREF(value);

    Py_XDECREF(evwrapper);

    Py_CLEAR(self->sequence);

    Py_XDECREF(module);

    return self->result;
}

static PyObject *Adapter_write(AdapterObject *self, PyObject *args)
{
    PyObject *item = NULL;
    const char *data = NULL;
    Py_ssize_t length = 0;

    if (!self->r)
    {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:write", &item))
        return NULL;

    if (!PyBytes_Check(item))
    {
        PyErr_Format(PyExc_TypeError, "byte string value expected, value "
                                      "of type %.200s found",
                     item->ob_type->tp_name);
        return NULL;
    }

    data = PyBytes_AsString(item);
    length = PyBytes_Size(item);

    if (!Adapter_output(self, data, length, item, 1))
    {
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *Adapter_ssl_is_https(AdapterObject *self, PyObject *args)
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

static PyObject *Adapter_ssl_var_lookup(AdapterObject *self, PyObject *args)
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
            wsgi_set_python_exception_from_cause(PyExc_TypeError,
                                                 "byte string value expected, value containing non "
                                                 "'latin-1' characters found");

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

        Py_RETURN_NONE;
    }

    value = ssl_var_lookup(self->r->pool, self->r->server,
                           self->r->connection, self->r, name);

    Py_XDECREF(latin_item);

    if (!value)
    {
        Py_RETURN_NONE;
    }

    return PyUnicode_DecodeLatin1(value, strlen(value), NULL);
}

static PyMethodDef Adapter_methods[] = {
    {"start_response", (PyCFunction)Adapter_start_response, METH_VARARGS, 0},
    {"write", (PyCFunction)Adapter_write, METH_VARARGS, 0},
    {"ssl_is_https", (PyCFunction)Adapter_ssl_is_https, METH_VARARGS, 0},
    {"ssl_var_lookup", (PyCFunction)Adapter_ssl_var_lookup, METH_VARARGS, 0},
    {NULL, NULL}};

/*
 * PyType_Spec for the Adapter heap type. The slots with non-default
 * behaviour are tp_dealloc (releases per-request Python state) and
 * tp_methods (start_response / write / ssl_is_https /
 * ssl_var_lookup); everything else falls back to the framework
 * defaults.
 *
 * tp_name is "mod_wsgi.Adapter" so error messages and repr() output
 * identify where the type comes from. The type is not exposed as a
 * module attribute; instances are produced by newAdapterObject from
 * C and consumed by Adapter_run in the same request.
 */

static PyType_Slot Adapter_slots[] = {
    {Py_tp_dealloc, Adapter_dealloc},
    {Py_tp_methods, Adapter_methods},
    {0, NULL},
};

static PyType_Spec Adapter_spec = {
    .name = "mod_wsgi.Adapter",
    .basicsize = sizeof(AdapterObject),
    .itemsize = 0,
    .flags = Py_TPFLAGS_DEFAULT,
    .slots = Adapter_slots,
};

/* ------------------------------------------------------------------------- */

int wsgi_adapter_init(PyObject *module)
{
    WSGIModuleState *state = NULL;
    PyObject *type = NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state)
        return -1;

    type = PyType_FromModuleAndSpec(module, &Adapter_spec, NULL);
    if (!type)
        return -1;

    state->Adapter_Type = (PyTypeObject *)type;

    return 0;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
