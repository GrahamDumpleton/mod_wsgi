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
#include "wsgi_module.h"

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

    WSGI_BEGIN_ALLOW_THREADS
    ap_log_error(file, line, module_index, level, rv, s, "%s", buf);
    WSGI_END_ALLOW_THREADS
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

    WSGI_BEGIN_ALLOW_THREADS if (r->filename)
    {
        ap_log_rerror(file, line, module_index, level, rv, r,
                      "[script %s] %s", r->filename, buf);
    }
    else
    {
        ap_log_rerror(file, line, module_index, level, rv, r, "%s", buf);
    }
    WSGI_END_ALLOW_THREADS
}

/* ------------------------------------------------------------------------- */

void wsgi_set_python_exception_from_cause(PyObject *exc_type,
                                          const char *format, ...)
{
    PyObject *cause_type = NULL;
    PyObject *cause_value = NULL;
    PyObject *cause_tb = NULL;

    PyErr_Fetch(&cause_type, &cause_value, &cause_tb);
    PyErr_NormalizeException(&cause_type, &cause_value, &cause_tb);
    if (cause_value != NULL && cause_tb != NULL)
    {
        PyException_SetTraceback(cause_value, cause_tb);
    }

    va_list vargs;
    va_start(vargs, format);
    PyObject *msg = PyUnicode_FromFormatV(format, vargs);
    va_end(vargs);

    if (msg == NULL)
    {
        /* Formatting failed. Restore the original error if one was
         * pending; otherwise leave the formatting error in place so
         * the caller is not silently left with no exception set. */
        if (cause_type != NULL)
        {
            PyErr_Restore(cause_type, cause_value, cause_tb);
        }
        return;
    }

    PyErr_SetObject(exc_type, msg);
    Py_DECREF(msg);

    if (cause_value != NULL)
    {
        PyObject *new_type = NULL;
        PyObject *new_value = NULL;
        PyObject *new_tb = NULL;

        PyErr_Fetch(&new_type, &new_value, &new_tb);
        PyErr_NormalizeException(&new_type, &new_value, &new_tb);

        /* Both PyException_SetCause and PyException_SetContext steal
         * the reference they are given, so create one extra ref to
         * cause_value and hand one to each. SetCause also flips
         * __suppress_context__ = 1, matching "raise X from Y". */
        PyException_SetCause(new_value, Py_NewRef(cause_value));
        PyException_SetContext(new_value, cause_value);

        Py_XDECREF(cause_type);
        Py_XDECREF(cause_tb);
        PyErr_Restore(new_type, new_value, new_tb);
    }
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

PyObject *newLogBufferObject(request_rec *r, int level, const char *name,
                             int proxy)
{
    PyObject *module = NULL;
    WSGIModuleState *state = NULL;
    PyTypeObject *type = NULL;
    LogObject *self = NULL;

    /*
     * Find the embedded mod_wsgi module for the current
     * interpreter and pull the Log heap type out of its state.
     * Returns NULL with a clear error if the module is not in
     * sys.modules or its state has not been initialised; either
     * indicates an init ordering bug.
     */

    module = PyImport_ImportModule("mod_wsgi");
    if (!module)
        return NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state || !state->Log_Type)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "Log type not initialised for the current "
                        "interpreter; newLogBufferObject() called before "
                        "the embedded mod_wsgi module's exec slot ran");
        Py_DECREF(module);
        return NULL;
    }

    type = state->Log_Type;

    self = (LogObject *)type->tp_alloc(type, 0);
    Py_DECREF(module);

    if (!self)
        return NULL;

    if (!name)
        name = "<log>";

    /* Stored by pointer, not copied. Callers must pass a string with
     * static lifetime (e.g. a literal); Log_dealloc does not free name
     * and Log_name reads it directly. */

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
        PyErr_SetString(PyExc_RuntimeError,
                        "mod_wsgi could not obtain io.TextIOWrapper for "
                        "wsgi.errors");
        return NULL;
    }

    Py_INCREF(object);

    args = Py_BuildValue("(OssOOO)", buffer, "utf-8", "replace",
                         Py_None, Py_True, Py_True);

    if (args)
    {
        wrapper = PyObject_CallObject(object, args);
        Py_DECREF(args);
    }

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
    PyTypeObject *tp = Py_TYPE(self);

    if (self->s)
    {
        if (!self->expired)
            Log_call(self, self->s, self->l);

        free(self->s);
    }

    tp->tp_free(self);
    Py_DECREF(tp);
}

static PyObject *Log_flush(LogObject *self, PyObject *args)
{
    WSGIThreadInfo *thread_info = NULL;

    if (self->proxy)
        thread_info = wsgi_thread_info(0, 0);

    if (thread_info && thread_info->log_buffer &&
        (LogObject *)thread_info->log_buffer != self)
        return Log_flush((LogObject *)thread_info->log_buffer, args);

    if (self->expired && self->s)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "flush() called on wsgi.errors after request "
                        "completed");
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

    if (thread_info && thread_info->log_buffer &&
        (LogObject *)thread_info->log_buffer != self)
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

    if (thread_info && thread_info->log_buffer &&
        (LogObject *)thread_info->log_buffer != self)
        return Log_write((LogObject *)thread_info->log_buffer, args);

    if (self->expired)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "write() called on wsgi.errors after request "
                        "completed");
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

    if (thread_info && thread_info->log_buffer &&
        (LogObject *)thread_info->log_buffer != self)
        return Log_writelines((LogObject *)thread_info->log_buffer, args);

    if (self->expired)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "writelines() called on wsgi.errors after request "
                        "completed");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:writelines", &sequence))
        return NULL;

    iterator = PyObject_GetIter(sequence);

    if (iterator == NULL)
    {
        wsgi_set_python_exception_from_cause(PyExc_TypeError,
                                             "writelines() argument must be an iterable of str");

        return NULL;
    }

    while ((item = PyIter_Next(iterator)))
    {
        PyObject *result = NULL;
        PyObject *item_args = NULL;

        item_args = PyTuple_Pack(1, item);

        if (!item_args)
        {
            Py_DECREF(item);
            Py_DECREF(iterator);

            return NULL;
        }

        result = Log_write(self, item_args);

        Py_DECREF(item_args);
        Py_DECREF(item);

        if (!result)
        {
            Py_DECREF(iterator);

            return NULL;
        }
    }

    /*
     * PyIter_Next returns NULL for both "iteration complete" and
     * "error raised during iteration"; surface the latter as a
     * failed writelines() rather than silently returning None.
     */

    if (PyErr_Occurred())
    {
        Py_DECREF(iterator);

        return NULL;
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
    PyErr_SetString(PyExc_OSError, "wsgi.errors log object has no file "
                                   "descriptor");

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

/*
 * PyType_Spec for the Log heap type. Only the slots with non-
 * default behaviour are listed (tp_dealloc, tp_methods,
 * tp_getset); everything else falls back to the framework
 * defaults that PyType_FromModuleAndSpec wires in.
 *
 * tp_name is "mod_wsgi.Log" so error messages and repr() output
 * identify where the type comes from. The type is not exposed
 * as a module attribute; instances are produced by
 * newLogBufferObject and (typically) wrapped in an
 * io.TextIOWrapper before being handed out.
 */

static PyType_Slot Log_slots[] = {
    {Py_tp_dealloc, Log_dealloc},
    {Py_tp_methods, Log_methods},
    {Py_tp_getset, Log_getset},
    {0, NULL},
};

static PyType_Spec Log_spec = {
    .name = "mod_wsgi.Log",
    .basicsize = sizeof(LogObject),
    .itemsize = 0,
    .flags = Py_TPFLAGS_DEFAULT,
    .slots = Log_slots,
};

/* ------------------------------------------------------------------------- */

/*
 * Map a Python logging level (record.levelno) onto an Apache
 * APLOG_* level for emission. Non-standard Python levels (custom
 * levels, NOTSET, anything between the standards) round down to
 * the next-lower APLOG_* level.
 */

static int wsgi_log_handler_apache_level(long python_level)
{
    if (python_level >= 50)
        return APLOG_CRIT; /* CRITICAL */
    if (python_level >= 40)
        return APLOG_ERR; /* ERROR    */
    if (python_level >= 30)
        return APLOG_WARNING; /* WARNING  */
    if (python_level >= 20)
        return APLOG_INFO; /* INFO     */
    return APLOG_DEBUG;    /* DEBUG, NOTSET, custom */
}

/*
 * Return the request_rec the calling thread is currently
 * handling, or NULL if the thread is not bound to a request
 * (module init, background thread, shutdown). Reads the
 * per-thread log_buffer stashed by the adapter at request
 * dispatch time; if the buffer is unset or has been expired, no
 * request is in flight.
 */

static request_rec *wsgi_log_handler_current_request(void)
{
    WSGIThreadInfo *thread_info;
    LogObject *log_buffer;

    thread_info = wsgi_thread_info(0, 0);
    if (!thread_info || !thread_info->log_buffer)
        return NULL;

    log_buffer = (LogObject *)thread_info->log_buffer;
    if (log_buffer->expired)
        return NULL;

    return log_buffer->r;
}

/*
 * mod_wsgi.LogHandler is a Python logging.Handler subclass
 * implemented in C that routes records through Apache's error
 * log while preserving the Python log level. The Python levels
 * CRITICAL / ERROR / WARNING / INFO / DEBUG map to Apache
 * APLOG_CRIT / APLOG_ERR / APLOG_WARNING / APLOG_INFO /
 * APLOG_DEBUG; non-standard Python levels round down to the
 * next-lower APLOG_* level. Per record the handler consults the
 * calling thread's WSGIThreadInfo to pick between ap_log_rerror
 * (request-handling thread) and ap_log_error (module-init /
 * background thread / shutdown), so the request decoration story
 * matches the wsgi.errors stream.
 *
 * Records are filtered against the Apache per-server log level
 * for the wsgi module, so operators control application output
 * via the same `LogLevel wsgi:LEVEL` knob that gates mod_wsgi's
 * own diagnostic messages. The Apache-side level acts as a
 * ceiling on top of whatever Python-side filter the application
 * has configured: records the application chose not to emit at
 * all stay invisible regardless of the LogLevel ceiling.
 *
 * The type is created in wsgi_logger_init alongside the Log
 * type and stored in WSGIModuleState as LogHandler_Type. It is
 * exposed to Python as mod_wsgi.LogHandler.
 *
 * emit(record): apply the level map, fast-path against the
 * Apache per-server level for the wsgi module so format() is
 * skipped when Apache would discard the record, format via the
 * inherited Handler API, then emit one Apache log record per
 * newline-delimited segment of the formatted text. Pass through
 * record.pathname / record.lineno so Apache's %F format
 * directive reports the application call site, not the
 * emit-site in this file. Delegate to self.handleError(record)
 * on a formatting exception, matching the logging.Handler base
 * contract.
 */

static PyObject *wsgi_log_handler_emit(PyObject *self, PyObject *record)
{
    PyObject *levelno_obj = NULL;
    long python_level;
    int apache_level;
    request_rec *r;
    server_rec *s;
    int level_ok;
    PyObject *msg = NULL;
    Py_ssize_t msg_len;
    const char *msg_str;
    const char *p_segment;
    const char *end;
    PyObject *pathname_obj = NULL;
    PyObject *lineno_obj = NULL;
    const char *log_file = __FILE__;
    int log_line = __LINE__;

    levelno_obj = PyObject_GetAttrString(record, "levelno");
    if (!levelno_obj)
        return NULL;

    python_level = PyLong_AsLong(levelno_obj);
    Py_DECREF(levelno_obj);
    if (python_level == -1 && PyErr_Occurred())
        return NULL;

    apache_level = wsgi_log_handler_apache_level(python_level);

    r = wsgi_log_handler_current_request();
    s = r ? r->server : wsgi_server;

    /*
     * Fast-path: skip the format() call entirely when Apache's
     * per-server level for the wsgi module would discard the
     * record. The format call can be expensive (interpolation,
     * traceback rendering) so it is worth checking first.
     * APLOG_MODULE_INDEX is the wsgi_module index resolved from
     * this file's APLOG_USE_MODULE declaration.
     */

    if (r)
        level_ok = APLOG_R_MODULE_IS_LEVEL(r, APLOG_MODULE_INDEX,
                                           apache_level);
    else
        level_ok = APLOG_MODULE_IS_LEVEL(s, APLOG_MODULE_INDEX, apache_level);

    if (!level_ok)
        Py_RETURN_NONE;

    msg = PyObject_CallMethod(self, "format", "O", record);
    if (!msg)
    {
        PyObject *res;

        /*
         * Match logging.Handler's contract: a formatting failure
         * is funnelled through self.handleError, which itself
         * either prints to stderr or is silently swallowed
         * depending on logging.raiseExceptions. Either way emit
         * returns None, not an exception.
         */

        res = PyObject_CallMethod(self, "handleError", "O", record);
        Py_XDECREF(res);
        PyErr_Clear();
        Py_RETURN_NONE;
    }

    msg_str = PyUnicode_AsUTF8AndSize(msg, &msg_len);
    if (!msg_str)
    {
        Py_DECREF(msg);
        return NULL;
    }

    /*
     * Read the application's source location off the LogRecord
     * so Apache's %F log format reports where the logger call
     * was made, not the mod_wsgi emit-site. Logger.findCaller
     * populates these attributes by walking the stack for the
     * first frame outside the logging module. Defensive against
     * a custom LogRecord that lacks them or that supplies the
     * wrong type: fall back to wsgi_logger.c's own location.
     *
     * pathname_obj is kept alive across the emit loop because
     * PyUnicode_AsUTF8 returns a pointer into the str object's
     * internal storage; the pointer is invalidated when the str
     * is freed.
     */

    pathname_obj = PyObject_GetAttrString(record, "pathname");
    if (pathname_obj && PyUnicode_Check(pathname_obj))
    {
        const char *as_utf8 = PyUnicode_AsUTF8(pathname_obj);
        if (as_utf8)
            log_file = as_utf8;
        else
            PyErr_Clear();
    }
    else
    {
        PyErr_Clear();
    }

    lineno_obj = PyObject_GetAttrString(record, "lineno");
    if (lineno_obj && PyLong_Check(lineno_obj))
    {
        long ll = PyLong_AsLong(lineno_obj);
        if (ll != -1 || !PyErr_Occurred())
            log_line = (int)ll;
        else
            PyErr_Clear();
    }
    else
    {
        PyErr_Clear();
    }
    Py_XDECREF(lineno_obj);

    /*
     * Walk newline-delimited segments and emit each as its own
     * Apache log record. This matches the wsgi.errors stream's
     * line-based emission so multi-line tracebacks render the
     * same way regardless of which path they took. Each segment
     * also gets its own 8 KiB Apache log buffer budget.
     */

    p_segment = msg_str;
    end = msg_str + msg_len;
    while (p_segment < end)
    {
        const char *line_end;
        Py_ssize_t line_len;

        line_end = memchr(p_segment, '\n', end - p_segment);
        line_len = line_end ? (line_end - p_segment) : (end - p_segment);

        if (r)
        {
            wsgi_log_rerror_locked_ex(log_file, log_line, APLOG_MODULE_INDEX,
                                      apache_level, 0, r,
                                      "%.*s", (int)line_len, p_segment);
        }
        else
        {
            wsgi_log_error_locked_ex(log_file, log_line, APLOG_MODULE_INDEX,
                                     apache_level, 0, s,
                                     "%.*s", (int)line_len, p_segment);
        }

        p_segment = line_end ? (line_end + 1) : end;
    }

    Py_XDECREF(pathname_obj);
    Py_DECREF(msg);
    Py_RETURN_NONE;
}

static PyMethodDef wsgi_log_handler_methods[] = {
    {"emit", wsgi_log_handler_emit, METH_O,
     "Emit a log record via the Apache error log."},
    {NULL, NULL, 0, NULL}};

/*
 * PyType_Spec for the LogHandler heap type. basicsize=0 means
 * the instance layout is inherited from the base class
 * (logging.Handler), which is the only state the type carries.
 * Py_TPFLAGS_BASETYPE leaves the door open for Python code to
 * subclass mod_wsgi.LogHandler if there's ever a reason to.
 */

static PyType_Slot wsgi_log_handler_slots[] = {
    {Py_tp_methods, wsgi_log_handler_methods},
    {0, NULL},
};

static PyType_Spec wsgi_log_handler_spec = {
    .name = "mod_wsgi.LogHandler",
    .basicsize = 0,
    .itemsize = 0,
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .slots = wsgi_log_handler_slots,
};

/* ------------------------------------------------------------------------- */

int wsgi_logger_init(PyObject *module)
{
    WSGIModuleState *state = NULL;
    PyObject *type = NULL;
    PyObject *logging_module = NULL;
    PyObject *handler_class = NULL;
    PyObject *bases = NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state)
        return -1;

    type = PyType_FromModuleAndSpec(module, &Log_spec, NULL);
    if (!type)
        return -1;

    state->Log_Type = (PyTypeObject *)type;

    /*
     * Create the LogHandler heap type as a subclass of
     * logging.Handler. PyType_FromModuleAndSpec accepts a bases
     * tuple as its third argument; passing logging.Handler there
     * lets us inherit setFormatter, setLevel, addFilter,
     * handleError, and the __init__ that accepts a level. The
     * only method this type overrides is emit().
     */

    logging_module = PyImport_ImportModule("logging");
    if (!logging_module)
        return -1;

    handler_class = PyObject_GetAttrString(logging_module, "Handler");
    Py_DECREF(logging_module);
    if (!handler_class)
        return -1;

    bases = PyTuple_Pack(1, handler_class);
    Py_DECREF(handler_class);
    if (!bases)
        return -1;

    type = PyType_FromModuleAndSpec(module, &wsgi_log_handler_spec, bases);
    Py_DECREF(bases);
    if (!type)
        return -1;

    if (PyModule_AddObjectRef(module, "LogHandler", type) < 0)
    {
        Py_DECREF(type);
        return -1;
    }

    state->LogHandler_Type = (PyTypeObject *)type;

    return 0;
}

void wsgi_log_python_error_ex(const char *file, int line, int module_index,
                              request_rec *r, const char *filename,
                              const char *application_group, int publish,
                              wsgi_log_python_phase phase)
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
    const char *exception_type = "Exception";

    apr_pool_t *pool;
    apr_pool_t *parent_pool;
    apr_pool_t *format_pool = NULL;
    server_rec *s;
    const char *context;
    int is_systemexit;
    int formatted_ok = 0;

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

    parent_pool = r ? r->pool : wsgi_server->process->pool;
    s = r ? r->server : wsgi_server;

    /*
     * Format the interpreter context into a transient sub-pool so
     * that server-scope callers (r == NULL) don't accumulate small
     * allocations in the process pool across repeated invocations.
     * Server-scope callers run during single-threaded init, so the
     * sub-pool create on the process pool is not racing other
     * threads. If the sub-pool can't be created (OOM), fall back
     * to the parent pool — the leak is preferable to crashing
     * while logging an exception. The sub-pool is destroyed once
     * the header has been emitted.
     */

    if (apr_pool_create(&format_pool, parent_pool) == APR_SUCCESS)
        pool = format_pool;
    else
        pool = parent_pool;

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

    if (!type)
    {
        type = Py_None;
        Py_INCREF(type);
    }

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

    /*
     * Capture the exception class name for inclusion in the header
     * so that even under severe OOM (where the traceback formatting
     * path below fails) the Apache error log still names the
     * exception type. tp_name is owned by the type object; type is
     * held alive by our reference for the duration of this function.
     */

    if (type && PyType_Check(type))
        exception_type = ((PyTypeObject *)type)->tp_name;

    io_module = PyImport_ImportModule("io");

    if (io_module)
        stringio = PyObject_CallMethod(io_module, "StringIO", NULL);

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

                if (args && kwargs)
                    result = PyObject_Call(o, args, kwargs);

                Py_XDECREF(kwargs);
                Py_XDECREF(args);
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

    formatted_ok = (result != NULL) && (captured_text != NULL);

    /*
     * Drop any latent exception left in tstate by failed Python C
     * API calls above. The original exception is preserved in our
     * local type/value/traceback refs and will be restored below if
     * the formatting failed and we need to emit it via PyErr_Print.
     */

    PyErr_Clear();

    /*
     * Build the header message body before releasing the GIL. The
     * format strings encode the WSGINNNN code, the optional [script]
     * bracket (only present when r is non-NULL), the exception class
     * name, the script filename, and the interpreter+process context.
     */

    {
        char header[WSGI_LOG_BUFFER_SIZE];

        switch (phase)
        {
        case WSGI_LOG_PYTHON_PHASE_INTERP_INIT:
            apr_snprintf(header, sizeof(header),
                         is_systemexit
                             ? WSGI_APLOGNO(0189) "%s exception raised "
                                                  "during Python "
                                                  "interpreter "
                                                  "initialisation for %s; "
                                                  "ignored."
                             : WSGI_APLOGNO(0188) "%s exception raised "
                                                  "during Python "
                                                  "interpreter "
                                                  "initialisation for %s.",
                         exception_type, context);
            break;

        case WSGI_LOG_PYTHON_PHASE_INTERP_ATEXIT:
            apr_snprintf(header, sizeof(header),
                         is_systemexit
                             ? WSGI_APLOGNO(0097) "%s exception raised by "
                                                  "Python atexit functions "
                                                  "during shutdown of %s; "
                                                  "ignored."
                             : WSGI_APLOGNO(0098) "%s exception raised by "
                                                  "Python atexit functions "
                                                  "during shutdown of %s.",
                         exception_type, context);
            break;

        case WSGI_LOG_PYTHON_PHASE_EVENT_CALLBACK:
            apr_snprintf(header, sizeof(header),
                         is_systemexit
                             ? WSGI_APLOGNO(0190) "%s exception raised by "
                                                  "event callback for "
                                                  "'%s'; ignored."
                             : WSGI_APLOGNO(0112) "%s exception raised by "
                                                  "event callback for "
                                                  "'%s'.",
                         exception_type, filename);
            break;

        case WSGI_LOG_PYTHON_PHASE_RUNNING:
        default:
            if (r)
            {
                apr_snprintf(header, sizeof(header),
                             is_systemexit
                                 ? WSGI_APLOGNO(0175) "[script %s] %s exception raised "
                                                      "by WSGI script '%s' for %s; ignored."
                                 : WSGI_APLOGNO(0174) "[script %s] %s exception raised "
                                                      "processing WSGI script '%s' for %s.",
                             r->filename ? r->filename : "(unknown)",
                             exception_type, filename, context);
            }
            else
            {
                apr_snprintf(header, sizeof(header),
                             is_systemexit
                                 ? WSGI_APLOGNO(0175) "%s exception raised by WSGI "
                                                      "script '%s' for %s; ignored."
                                 : WSGI_APLOGNO(0174) "%s exception raised processing "
                                                      "WSGI script '%s' for %s.",
                             exception_type, filename, context);
            }
            break;
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

        WSGI_BEGIN_ALLOW_THREADS

        if (r)
            ap_log_rerror(file, line, module_index, APLOG_ERR, 0, r,
                          "%s", header);
        else
            ap_log_error(file, line, module_index, APLOG_ERR, 0, s,
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

        WSGI_END_ALLOW_THREADS
    }

    /* context is no longer used past this point. */

    if (format_pool)
        apr_pool_destroy(format_pool);

    if (!formatted_ok)
    {
        /*
         * Fallback path: any failure during traceback formatting
         * lands here (io / traceback module unavailable, allocation
         * failure, getvalue() did not return a string, etc.).
         * Restore the original exception we fetched earlier and
         * emit detail via PyErr_Print, which writes to sys.stderr
         * (wired in mod_wsgi to the Apache error log via the
         * LogObject defined in this file). For SystemExit,
         * PyErr_Print would terminate the process, so just clear
         * the exception instead.
         */

        PyErr_Restore(type, value, traceback);
        type = NULL;
        value = NULL;
        traceback = NULL;

        if (!is_systemexit)
            PyErr_Print();

        PyErr_Clear();
    }
    else if (publish && wsgi_event_subscribers())
    {
        WSGIThreadInfo *thread_info = wsgi_thread_info(0, 0);
        PyObject *event = PyDict_New();

        if (event)
        {
            PyObject *object = NULL;
            int ok = 1;

            /* Optional: request_id (only when r->log_id is set). */

            if (r && r->log_id)
            {
                object = PyUnicode_DecodeLatin1(r->log_id,
                                                strlen(r->log_id), NULL);
                if (object)
                {
                    (void)PyDict_SetItemString(event, "request_id", object);
                    Py_DECREF(object);
                }
            }

            /*
             * Required: exception_info. Without this the event has
             * no payload, so drop it rather than publishing a
             * malformed dict.
             */

            object = Py_BuildValue("(OOO)", type, value, traceback);
            if (object)
            {
                if (PyDict_SetItemString(event, "exception_info",
                                         object) != 0)
                    ok = 0;
                Py_DECREF(object);
            }
            else
            {
                ok = 0;
            }

            /*
             * Optional: request_data. thread_info or request_data
             * NULL means we ran outside the wsgi_start_request /
             * wsgi_end_request bracket, or wsgi_start_request's
             * own PyDict_New failed under OOM; either way, skip
             * the key rather than crash.
             */

            if (ok && thread_info && thread_info->request_data)
            {
                (void)PyDict_SetItemString(event, "request_data",
                                           thread_info->request_data);
            }

            if (ok)
                wsgi_publish_event("request_exception", event);

            Py_DECREF(event);
        }

        /*
         * Drop any latent exception left in tstate by failed dict
         * builds, set-item returns, or subscriber callbacks.
         */

        PyErr_Clear();
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
