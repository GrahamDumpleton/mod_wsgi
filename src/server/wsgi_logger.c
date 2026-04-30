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

#include "wsgi_logger.h"

#include "wsgi_server.h"
#include "wsgi_metrics.h"
#include "wsgi_thread.h"
#include "wsgi_interp.h"
#include "wsgi_daemon.h"

/* ------------------------------------------------------------------------- */

/*
 * Buffer size for pre-formatting log messages. Mirrors Apache's own
 * internal log line length cap; messages longer than this are silently
 * truncated, matching ap_log_error()'s behaviour for an oversized
 * formatted message.
 */

#define WSGI_LOG_BUFFER_SIZE 8192

void wsgi_log_error_ex(const char *file, int line, int module_index,
                       int level, apr_status_t rv, server_rec *s,
                       const char *fmt, ...)
{
    char buf[WSGI_LOG_BUFFER_SIZE];
    va_list ap;

    va_start(ap, fmt);
    apr_vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    ap_log_error(file, line, module_index, level, rv, s, "%s", buf);
}

void wsgi_log_error_locked_ex(const char *file, int line, int module_index,
                              int level, apr_status_t rv, server_rec *s,
                              const char *fmt, ...)
{
    char buf[WSGI_LOG_BUFFER_SIZE];
    va_list ap;

    va_start(ap, fmt);
    apr_vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    Py_BEGIN_ALLOW_THREADS
        ap_log_error(file, line, module_index, level, rv, s, "%s", buf);
    Py_END_ALLOW_THREADS
}

void wsgi_log_rerror_ex(const char *file, int line, int module_index,
                        int level, apr_status_t rv, request_rec *r,
                        const char *fmt, ...)
{
    char buf[WSGI_LOG_BUFFER_SIZE];
    va_list ap;

    va_start(ap, fmt);
    apr_vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (r->filename)
    {
        ap_log_rerror(file, line, module_index, level, rv, r,
                      "[script %s] %s", r->filename, buf);
    }
    else
    {
        ap_log_rerror(file, line, module_index, level, rv, r, "%s", buf);
    }
}

void wsgi_log_rerror_locked_ex(const char *file, int line, int module_index,
                               int level, apr_status_t rv, request_rec *r,
                               const char *fmt, ...)
{
    char buf[WSGI_LOG_BUFFER_SIZE];
    va_list ap;

    va_start(ap, fmt);
    apr_vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    Py_BEGIN_ALLOW_THREADS if (r->filename)
    {
        ap_log_rerror(file, line, module_index, level, rv, r,
                      "[script %s] %s", r->filename, buf);
    }
    else
    {
        ap_log_rerror(file, line, module_index, level, rv, r, "%s", buf);
    }
    Py_END_ALLOW_THREADS
}

/* ------------------------------------------------------------------------- */

typedef struct
{
    PyObject_HEAD const char *name;
    int proxy;
    request_rec *r;
    int level;
    char *s;
    long l;
    int expired;
} LogObject;

PyTypeObject Log_Type;

PyObject *newLogBufferObject(request_rec *r, int level, const char *name,
                             int proxy)
{
    LogObject *self;

    self = PyObject_New(LogObject, &Log_Type);
    if (self == NULL)
        return NULL;

    if (!name)
        name = "<log>";

    self->name = name;
    self->proxy = proxy;
    self->r = r;
    self->level = APLOG_NOERRNO | level;
    self->s = NULL;
    self->l = 0;
    self->expired = 0;

    return (PyObject *)self;
}

PyObject *newLogWrapperObject(PyObject *buffer)
{
    PyObject *module = NULL;
    PyObject *dict = NULL;
    PyObject *object = NULL;
    PyObject *args = NULL;
    PyObject *wrapper = NULL;

    module = PyImport_ImportModule("io");

    if (!module)
        return NULL;

    dict = PyModule_GetDict(module);
    object = PyDict_GetItemString(dict, "TextIOWrapper");

    if (!object)
    {
        Py_DECREF(module);
        PyErr_SetString(PyExc_NameError,
                        "name 'TextIOWrapper' is not defined");
        return NULL;
    }

    Py_INCREF(object);

    args = Py_BuildValue("(OssOOO)", buffer, "utf-8", "replace",
                         Py_None, Py_True, Py_True);

    wrapper = PyObject_CallObject(object, args);

    Py_DECREF(args);
    Py_DECREF(object);
    Py_DECREF(module);

    return (PyObject *)wrapper;
}

PyObject *newLogObject(request_rec *r, int level, const char *name,
                       int proxy)
{
    PyObject *buffer = NULL;
    PyObject *wrapper = NULL;

    buffer = newLogBufferObject(r, level, name, proxy);

    if (!buffer)
        return NULL;

    wrapper = newLogWrapperObject(buffer);

    Py_DECREF(buffer);

    return wrapper;
}

static void Log_call(LogObject *self, const char *s, long l)
{
    /*
     * The length of the string to be logged is ignored
     * for now. We just pass the whole string to the
     * Apache error log functions. It will actually
     * truncate it at some value less than 8192
     * characters depending on the length of the prefix
     * to go at the front. If there are embedded NULLs
     * then truncation will occur at that point. That
     * truncation occurs like this is also what happens
     * if using FASTCGI solutions for Apache, so not
     * doing anything different here.
     */

    if (self->r)
        wsgi_log_rerror_locked(self->level, 0, self->r, "%s", s);
    else
        wsgi_log_error_locked(self->level, 0, wsgi_server, "%s", s);
}

static void Log_dealloc(LogObject *self)
{
    if (self->s)
    {
        if (!self->expired)
            Log_call(self, self->s, self->l);

        free(self->s);
    }

    PyObject_Del(self);
}

static PyObject *Log_flush(LogObject *self, PyObject *args)
{
    WSGIThreadInfo *thread_info = NULL;

    if (self->proxy)
        thread_info = wsgi_thread_info(0, 0);

    if (thread_info && thread_info->log_buffer)
        return Log_flush((LogObject *)thread_info->log_buffer, args);

    if (self->expired && self->s)
    {
        PyErr_SetString(PyExc_RuntimeError, "log object has expired");
        return NULL;
    }

    if (self->s)
    {
        Log_call(self, self->s, self->l);

        free(self->s);
        self->s = NULL;
        self->l = 0;
    }

    Py_RETURN_NONE;
}

static PyObject *Log_close(LogObject *self, PyObject *args)
{
    PyObject *result = NULL;

    WSGIThreadInfo *thread_info = NULL;

    if (self->proxy)
        thread_info = wsgi_thread_info(0, 0);

    if (thread_info && thread_info->log_buffer)
        return Log_close((LogObject *)thread_info->log_buffer, args);

    if (!self->expired)
        result = Log_flush(self, args);

    /*
     * Flush should never fail for the log object, but
     * clear any exception to avoid returning a result
     * with an exception set.
     */

    if (!result)
        PyErr_Clear();
    else
        Py_DECREF(result);

    self->r = NULL;
    self->expired = 1;

    Py_RETURN_NONE;
}

static PyObject *Log_isatty(LogObject *self, PyObject *Py_UNUSED(args))
{
    Py_RETURN_FALSE;
}

static int Log_queue(LogObject *self, const char *msg, Py_ssize_t len)
{
    const char *p = NULL;
    const char *q = NULL;
    const char *e = NULL;

    p = msg;
    e = p + len;

    /*
     * Break string on newline. This is on assumption
     * that primarily textual information being logged.
     */

    q = p;
    while (q != e)
    {
        if (*q == '\n')
            break;
        q++;
    }

    while (q != e)
    {
        /* Output each complete line. */

        if (self->s)
        {
            /* Need to join with buffered value. */

            Py_ssize_t m = 0;
            Py_ssize_t n = 0;
            char *s = NULL;

            m = self->l;
            n = m + q - p + 1;

            s = (char *)malloc(n);
            if (!s)
            {
                PyErr_NoMemory();
                return -1;
            }
            memcpy(s, self->s, m);
            memcpy(s + m, p, q - p);
            s[n - 1] = '\0';

            free(self->s);
            self->s = NULL;
            self->l = 0;

            Log_call(self, s, n - 1);

            free(s);
        }
        else
        {
            Py_ssize_t n = 0;
            char *s = NULL;

            n = q - p + 1;

            s = (char *)malloc(n);
            if (!s)
            {
                PyErr_NoMemory();
                return -1;
            }
            memcpy(s, p, q - p);
            s[n - 1] = '\0';

            Log_call(self, s, n - 1);

            free(s);
        }

        p = q + 1;

        /* Break string on newline. */

        q = p;
        while (q != e)
        {
            if (*q == '\n')
                break;
            q++;
        }
    }

    if (p != e)
    {
        /* Save away incomplete line. */

        if (self->s)
        {
            /* Need to join with buffered value. */

            Py_ssize_t m = 0;
            Py_ssize_t n = 0;
            char *tmp = NULL;

            m = self->l;
            n = m + e - p + 1;

            tmp = (char *)realloc(self->s, n);
            if (!tmp)
            {
                PyErr_NoMemory();
                return -1;
            }
            self->s = tmp;
            memcpy(self->s + m, p, e - p);
            self->s[n - 1] = '\0';
            self->l = n - 1;
        }
        else
        {
            Py_ssize_t n = 0;

            n = e - p + 1;

            self->s = (char *)malloc(n);
            if (!self->s)
            {
                PyErr_NoMemory();
                return -1;
            }
            memcpy(self->s, p, n - 1);
            self->s[n - 1] = '\0';
            self->l = n - 1;
        }
    }

    return 0;
}

static PyObject *Log_write(LogObject *self, PyObject *args)
{
    const char *msg = NULL;
    Py_ssize_t len = -1;

    WSGIThreadInfo *thread_info = NULL;

    if (self->proxy)
        thread_info = wsgi_thread_info(0, 0);

    if (thread_info && thread_info->log_buffer)
        return Log_write((LogObject *)thread_info->log_buffer, args);

    if (self->expired)
    {
        PyErr_SetString(PyExc_RuntimeError, "log object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "s#:write", &msg, &len))
        return NULL;

    if (Log_queue(self, msg, len) != 0)
        return NULL;

    Py_RETURN_NONE;
}

static PyObject *Log_writelines(LogObject *self, PyObject *args)
{
    PyObject *sequence = NULL;
    PyObject *iterator = NULL;
    PyObject *item = NULL;

    WSGIThreadInfo *thread_info = NULL;

    if (self->proxy)
        thread_info = wsgi_thread_info(0, 0);

    if (thread_info && thread_info->log_buffer)
        return Log_writelines((LogObject *)thread_info->log_buffer, args);

    if (self->expired)
    {
        PyErr_SetString(PyExc_RuntimeError, "log object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:writelines", &sequence))
        return NULL;

    iterator = PyObject_GetIter(sequence);

    if (iterator == NULL)
    {
        PyErr_SetString(PyExc_TypeError,
                        "argument must be sequence of strings");

        return NULL;
    }

    while ((item = PyIter_Next(iterator)))
    {
        PyObject *result = NULL;
        PyObject *item_args = NULL;

        item_args = PyTuple_Pack(1, item);

        result = Log_write(self, item_args);

        Py_DECREF(item_args);
        Py_DECREF(item);

        if (!result)
        {
            Py_DECREF(iterator);

            return NULL;
        }
    }

    Py_DECREF(iterator);

    Py_RETURN_NONE;
}

static PyObject *Log_readable(LogObject *self, PyObject *Py_UNUSED(args))
{
    Py_RETURN_FALSE;
}

static PyObject *Log_seekable(LogObject *self, PyObject *Py_UNUSED(args))
{
    Py_RETURN_FALSE;
}

static PyObject *Log_writable(LogObject *self, PyObject *Py_UNUSED(args))
{
    Py_RETURN_TRUE;
}

static PyObject *Log_fileno(LogObject *self, PyObject *Py_UNUSED(args))
{
    PyErr_SetString(PyExc_OSError, "Apache/mod_wsgi log object is not "
                                   "associated with a file descriptor.");

    return NULL;
}

static PyObject *Log_name(LogObject *self, void *Py_UNUSED(closure))
{
    return PyUnicode_FromString(self->name);
}

static PyObject *Log_closed(LogObject *self, void *Py_UNUSED(closure))
{
    Py_RETURN_FALSE;
}

static PyObject *Log_get_encoding(LogObject *self, void *Py_UNUSED(closure))
{
    return PyUnicode_FromString("utf-8");
}

static PyObject *Log_get_errors(LogObject *self, void *Py_UNUSED(closure))
{
    return PyUnicode_FromString("replace");
}

static PyMethodDef Log_methods[] = {
    {"flush", (PyCFunction)Log_flush, METH_NOARGS, 0},
    {"close", (PyCFunction)Log_close, METH_NOARGS, 0},
    {"isatty", (PyCFunction)Log_isatty, METH_NOARGS, 0},
    {"write", (PyCFunction)Log_write, METH_VARARGS, 0},
    {"writelines", (PyCFunction)Log_writelines, METH_VARARGS, 0},
    {"readable", (PyCFunction)Log_readable, METH_NOARGS, 0},
    {"seekable", (PyCFunction)Log_seekable, METH_NOARGS, 0},
    {"writable", (PyCFunction)Log_writable, METH_NOARGS, 0},
    {"fileno", (PyCFunction)Log_fileno, METH_NOARGS, 0},
    {NULL, NULL}};

static PyGetSetDef Log_getset[] = {
    {"name", (getter)Log_name, NULL, 0},
    {"closed", (getter)Log_closed, NULL, 0},
    {"encoding", (getter)Log_get_encoding, NULL, 0},
    {"errors", (getter)Log_get_errors, NULL, 0},
    {NULL},
};

PyTypeObject Log_Type = {
    PyVarObject_HEAD_INIT(NULL, 0) "mod_wsgi.Log", /*tp_name*/
    sizeof(LogObject),                             /*tp_basicsize*/
    0,                                             /*tp_itemsize*/
    /* methods */
    (destructor)Log_dealloc, /*tp_dealloc*/
    0,                       /*tp_print*/
    0,                       /*tp_getattr*/
    0,                       /*tp_setattr*/
    0,                       /*tp_compare*/
    0,                       /*tp_repr*/
    0,                       /*tp_as_number*/
    0,                       /*tp_as_sequence*/
    0,                       /*tp_as_mapping*/
    0,                       /*tp_hash*/
    0,                       /*tp_call*/
    0,                       /*tp_str*/
    0,                       /*tp_getattro*/
    0,                       /*tp_setattro*/
    0,                       /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,      /*tp_flags*/
    0,                       /*tp_doc*/
    0,                       /*tp_traverse*/
    0,                       /*tp_clear*/
    0,                       /*tp_richcompare*/
    0,                       /*tp_weaklistoffset*/
    0,                       /*tp_iter*/
    0,                       /*tp_iternext*/
    Log_methods,             /*tp_methods*/
    0,                       /*tp_members*/
    Log_getset,              /*tp_getset*/
    0,                       /*tp_base*/
    0,                       /*tp_dict*/
    0,                       /*tp_descr_get*/
    0,                       /*tp_descr_set*/
    0,                       /*tp_dictoffset*/
    0,                       /*tp_init*/
    0,                       /*tp_alloc*/
    0,                       /*tp_new*/
    0,                       /*tp_free*/
    0,                       /*tp_is_gc*/
};

void wsgi_log_python_error_ex(const char *file, int line, int module_index,
                              request_rec *r, const char *filename,
                              const char *application_group, int publish)
{
    PyObject *m = NULL;
    PyObject *result = NULL;

    PyObject *type = NULL;
    PyObject *value = NULL;
    PyObject *traceback = NULL;

    PyObject *io_module = NULL;
    PyObject *stringio = NULL;
    PyObject *captured = NULL;

    const char *captured_text = NULL;
    Py_ssize_t captured_len = 0;

    apr_pool_t *pool;
    server_rec *s;
    const char *context;
    int is_systemexit;

    if (!PyErr_Occurred())
        return;

    /* Resolve application_group from request config when not supplied. */

    if (!application_group && r)
    {
        WSGIRequestConfig *config = (WSGIRequestConfig *)
            ap_get_module_config(r->request_config, &wsgi_module);

        if (config)
            application_group = config->application_group;
    }

    pool = r ? r->pool : wsgi_server->process->pool;
    s = r ? r->server : wsgi_server;

    context = wsgi_format_interp_context(pool, NULL, application_group);

    /*
     * Capture the formatted traceback into an io.StringIO so that it
     * can be emitted line by line under a single GIL release. Compute
     * everything we need from the Python side (header classification,
     * captured text pointer) before releasing the GIL.
     */

    is_systemexit = PyErr_ExceptionMatches(PyExc_SystemExit) ? 1 : 0;

    PyErr_Fetch(&type, &value, &traceback);
    PyErr_NormalizeException(&type, &value, &traceback);

    if (!value)
    {
        value = Py_None;
        Py_INCREF(value);
    }

    if (!traceback)
    {
        traceback = Py_None;
        Py_INCREF(traceback);
    }

    io_module = PyImport_ImportModule("io");

    if (io_module)
    {
        stringio = PyObject_CallMethod(io_module, "StringIO", NULL);
    }

    if (stringio)
    {
        m = PyImport_ImportModule("traceback");

        if (m)
        {
            PyObject *d = PyModule_GetDict(m);
            PyObject *o = PyDict_GetItemString(d, "print_exception");

            if (o)
            {
                PyObject *args = NULL;
                PyObject *kwargs = NULL;

                Py_INCREF(o);
                args = Py_BuildValue("(O)", value);
                kwargs = Py_BuildValue("{s:O}", "file", stringio);
                result = PyObject_Call(o, args, kwargs);
                Py_DECREF(kwargs);
                Py_DECREF(args);
                Py_DECREF(o);
            }
        }

        if (result)
        {
            captured = PyObject_CallMethod(stringio, "getvalue", NULL);

            if (captured && PyUnicode_Check(captured))
            {
                captured_text = PyUnicode_AsUTF8AndSize(captured,
                                                        &captured_len);
            }
        }
    }

    /*
     * Build the header message body before releasing the GIL. The
     * format strings encode the WSGINNNN code, the optional [script]
     * bracket (only present when r is non-NULL), the script filename,
     * and the interpreter+process context.
     */

    {
        char header[WSGI_LOG_BUFFER_SIZE];

        if (r)
        {
            apr_snprintf(header, sizeof(header),
                         is_systemexit
                             ? WSGI_APLOGNO(0175) "[script %s] SystemExit exception raised "
                                                  "by WSGI script '%s' for %s ignored."
                             : WSGI_APLOGNO(0174) "[script %s] Exception occurred processing "
                                                  "WSGI script '%s' for %s.",
                         r->filename ? r->filename : "(unknown)",
                         filename, context);
        }
        else
        {
            apr_snprintf(header, sizeof(header),
                         is_systemexit
                             ? WSGI_APLOGNO(0175) "SystemExit exception raised by WSGI "
                                                  "script '%s' for %s ignored."
                             : WSGI_APLOGNO(0174) "Exception occurred processing WSGI "
                                                  "script '%s' for %s.",
                         filename, context);
        }

        /*
         * Emit the header plus any captured traceback continuation
         * lines under a single GIL release. Calling ap_log_rerror /
         * ap_log_error directly (rather than via the wsgi_log_* _ex
         * wrappers) avoids the per-call GIL release/reacquire that
         * would otherwise happen for every traceback line. The
         * original caller's file/line/module_index are passed to
         * every emission so %7F reports the call site of
         * wsgi_log_python_error rather than this function.
         */

        Py_BEGIN_ALLOW_THREADS

            if (r)
                ap_log_rerror(file, line, module_index, APLOG_ERR, 0, r,
                              "%s", header);
        else ap_log_error(file, line, module_index, APLOG_ERR, 0, s,
                          "%s", header);

        if (captured_text)
        {
            const char *p = captured_text;
            const char *end = captured_text + captured_len;

            while (p < end)
            {
                const char *q = p;
                size_t n;
                char buf[WSGI_LOG_BUFFER_SIZE];

                while (q < end && *q != '\n')
                    q++;

                n = (size_t)(q - p);

                if (n >= sizeof(buf))
                    n = sizeof(buf) - 1;

                memcpy(buf, p, n);
                buf[n] = '\0';

                if (n > 0)
                {
                    if (r)
                        ap_log_rerror(file, line, module_index, APLOG_ERR,
                                      0, r, "%s", buf);
                    else
                        ap_log_error(file, line, module_index, APLOG_ERR,
                                     0, s, "%s", buf);
                }

                p = (q < end) ? q + 1 : end;
            }
        }

        Py_END_ALLOW_THREADS
    }

    if (!result || !captured_text)
    {
        /*
         * Fallback path: traceback module unavailable, StringIO
         * import failed, or getvalue() did not return a string. Use
         * PyErr_Print to dump details of the exception. For
         * SystemExit, this would terminate the process, so just
         * clear the exception in that case.
         */

        if (!result)
        {
            /* Restore the exception we fetched earlier. */
            PyErr_Restore(type, value, traceback);
            type = NULL;
            value = NULL;
            traceback = NULL;
        }

        if (!is_systemexit)
        {
            if (PyErr_Occurred())
            {
                PyErr_Print();
                PyErr_Clear();
            }
        }
        else
        {
            PyErr_Clear();
        }
    }
    else if (publish)
    {
        PyObject *event = NULL;
        PyObject *object = NULL;

        if (wsgi_event_subscribers())
        {
            WSGIThreadInfo *thread_info;

            thread_info = wsgi_thread_info(0, 0);

            event = PyDict_New();

            if (r && r->log_id)
            {
                object = PyUnicode_DecodeLatin1(r->log_id,
                                                strlen(r->log_id), NULL);
                PyDict_SetItemString(event, "request_id", object);
                Py_DECREF(object);
            }

            object = Py_BuildValue("(OOO)", type, value, traceback);
            PyDict_SetItemString(event, "exception_info", object);
            Py_DECREF(object);

            PyDict_SetItemString(event, "request_data",
                                 thread_info->request_data);

            wsgi_publish_event("request_exception", event);

            Py_DECREF(event);
        }
    }

    Py_XDECREF(type);
    Py_XDECREF(value);
    Py_XDECREF(traceback);
    Py_XDECREF(result);
    Py_XDECREF(m);
    Py_XDECREF(captured);
    Py_XDECREF(stringio);
    Py_XDECREF(io_module);
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
