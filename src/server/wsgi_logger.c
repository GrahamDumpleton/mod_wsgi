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

#include "wsgi_logger.h"

#include "wsgi_server.h"
#include "wsgi_metrics.h"
#include "wsgi_thread.h"

/* ------------------------------------------------------------------------- */

typedef struct {
        PyObject_HEAD
        const char *name;
        int proxy;
        request_rec *r;
        int level;
        char *s;
        long l;
        int expired;
#if PY_MAJOR_VERSION < 3
        long softspace;
#endif
} LogObject;

PyTypeObject Log_Type;

PyObject *newLogBufferObject(request_rec *r, int level, const char *name,
                             int proxy)
{
    LogObject *self;

    self = PyObject_New(LogObject, &Log_Type);
    if (self == NULL)
        return NULL;

    self->name = name;
    self->proxy = proxy;
    self->r = r;
    self->level = APLOG_NOERRNO|level;
    self->s = NULL;
    self->l = 0;
    self->expired = 0;
#if PY_MAJOR_VERSION < 3
    self->softspace = 0;
#endif

    return (PyObject *)self;
}

PyObject *newLogWrapperObject(PyObject *buffer)
{
#if PY_MAJOR_VERSION >= 3
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

    if (!object) {
        PyErr_SetString(PyExc_NameError,
                        "name 'TextIOWrapper' is not defined");
        return NULL;
    }

    Py_INCREF(object);

    args = Py_BuildValue("(OssOOO)", buffer, "utf-8", "replace",
                         Py_None, Py_True, Py_True);

    wrapper = PyEval_CallObject(object, args);

    Py_DECREF(args);
    Py_DECREF(object);

    return (PyObject *)wrapper;
#else
    Py_INCREF(buffer);

    return (PyObject *)buffer;
#endif
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

#if 0
static void Log_file(LogObject *self, const char *s, int l)
{
    /*
     * XXX This function is not currently being used.
     * The intention was that it be called instead of
     * Log_call() when 'name' is non zero. This would
     * be the case for 'stdout' and 'stderr'. Doing
     * this bypasses normally Apache logging mechanisms
     * though. May reawaken this code in mod_wsgi 4.0
     * by way of a mechanism to divert logging from a
     * daemon process to specfic log file or pipe using
     * an option to WSGIDaemonProcess.
     */

    char errstr[MAX_STRING_LEN];

    int plen = 0;
    int slen = 0;

    apr_file_t *logf = NULL;

    if (self->r)
        logf = self->r->server->error_log;
    else
        logf = wsgi_server->error_log;

    errstr[0] = '[';
    ap_recent_ctime(errstr + 1, apr_time_now());
    errstr[1 + APR_CTIME_LEN - 1] = ']';
    errstr[1 + APR_CTIME_LEN    ] = ' ';
    plen = 1 + APR_CTIME_LEN + 1;

    if (self->name) {
        int len;

        errstr[plen++] = '[';

        len = strlen(self->name);
        memcpy(errstr+plen, self->name, len);

        plen += len;

        errstr[plen++] = ']';
        errstr[plen++] = ' ';
    }

    slen = MAX_STRING_LEN - plen - 1;

    Py_BEGIN_ALLOW_THREADS

    /*
     * We actually break long lines up into segments
     * of around 8192 characters, with the date/time
     * and target information prefixing each line.
     * This is just to avoid having to allocate more
     * memory just to format the line with prefix.
     * We want to avoid writing the prefix separately
     * so at least try and write line in one atomic
     * operation.
     */

    while (1) {
        if (l > slen) {
            memcpy(errstr+plen, s, slen);
            errstr[plen+slen] = '\n';
            apr_file_write_full(logf, errstr, plen+slen+1, NULL);
            apr_file_flush(logf);
            s += slen;
            l -= slen;
        }
        else {
            memcpy(errstr+plen, s, l);
            errstr[plen+l] = '\n';
            apr_file_write_full(logf, errstr, plen+l+1, NULL);
            apr_file_flush(logf);
            break;
        }
    }

    Py_END_ALLOW_THREADS
}
#endif

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

    if (self->r) {
        Py_BEGIN_ALLOW_THREADS
        ap_log_rerror(APLOG_MARK, self->level, 0, self->r, "%s", s);
        Py_END_ALLOW_THREADS
    }
    else {
        Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, self->level, 0, wsgi_server, "%s", s);
        Py_END_ALLOW_THREADS
    }
}

static void Log_dealloc(LogObject *self)
{
    if (self->s) {
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

    if (self->expired) {
        PyErr_SetString(PyExc_RuntimeError, "log object has expired");
        return NULL;
    }

    if (self->s) {
        Log_call(self, self->s, self->l);

        free(self->s);
        self->s = NULL;
        self->l = 0;
    }

    Py_INCREF(Py_None);
    return Py_None;
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

    Py_XDECREF(result);

    self->r = NULL;
    self->expired = 1;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *Log_isatty(LogObject *self, PyObject *args)
{
    Py_INCREF(Py_False);
    return Py_False;
}

static void Log_queue(LogObject *self, const char *msg, int len)
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
    while (q != e) {
        if (*q == '\n')
            break;
        q++;
    }

    while (q != e) {
        /* Output each complete line. */

        if (self->s) {
            /* Need to join with buffered value. */

            long m = 0;
            long n = 0;
            char *s = NULL;

            m = self->l;
            n = m+q-p+1;

            s = (char *)malloc(n);
            memcpy(s, self->s, m);
            memcpy(s+m, p, q-p);
            s[n-1] = '\0';

            free(self->s);
            self->s = NULL;
            self->l = 0;

            Log_call(self, s, n-1);

            free(s);
        }
        else {
            long n = 0;
            char *s = NULL;

            n = q-p+1;

            s = (char *)malloc(n);
            memcpy(s, p, q-p);
            s[n-1] = '\0';

            Log_call(self, s, n-1);

            free(s);
        }

        p = q+1;

        /* Break string on newline. */

        q = p;
        while (q != e) {
            if (*q == '\n')
                break;
            q++;
        }
    }

    if (p != e) {
        /* Save away incomplete line. */

        if (self->s) {
            /* Need to join with buffered value. */

            long m = 0;
            long n = 0;

            m = self->l;
            n = m+e-p+1;

            self->s = (char *)realloc(self->s, n);
            memcpy(self->s+m, p, e-p);
            self->s[n-1] = '\0';
            self->l = n-1;
        }
        else {
            long n = 0;

            n = e-p+1;

            self->s = (char *)malloc(n);
            memcpy(self->s, p, n-1);
            self->s[n-1] = '\0';
            self->l = n-1;
        }
    }
}

static PyObject *Log_write(LogObject *self, PyObject *args)
{
    const char *msg = NULL;
    int len = -1;

    WSGIThreadInfo *thread_info = NULL;

    if (self->proxy)
        thread_info = wsgi_thread_info(0, 0);

    if (thread_info && thread_info->log_buffer)
        return Log_write((LogObject *)thread_info->log_buffer, args);

    if (self->expired) {
        PyErr_SetString(PyExc_RuntimeError, "log object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "s#:write", &msg, &len))
        return NULL;

    Log_queue(self, msg, len);

    Py_INCREF(Py_None);
    return Py_None;
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

    if (self->expired) {
        PyErr_SetString(PyExc_RuntimeError, "log object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:writelines", &sequence))
        return NULL;

    iterator = PyObject_GetIter(sequence);

    if (iterator == NULL) {
        PyErr_SetString(PyExc_TypeError,
                        "argument must be sequence of strings");

        return NULL;
    }

    while ((item = PyIter_Next(iterator))) {
        PyObject *result = NULL;
        PyObject *args = NULL;

        args = PyTuple_Pack(1, item);

        result = Log_write(self, args);

        Py_DECREF(args);
        Py_DECREF(item);

        if (!result) {
            Py_DECREF(iterator);

            PyErr_SetString(PyExc_TypeError,
                            "argument must be sequence of strings");

            return NULL;
        }
    }

    Py_DECREF(iterator);

    Py_INCREF(Py_None);
    return Py_None;
}

#if PY_MAJOR_VERSION >= 3
static PyObject *Log_readable(LogObject *self, PyObject *args)
{
    Py_INCREF(Py_False);
    return Py_False;
}

static PyObject *Log_seekable(LogObject *self, PyObject *args)
{
    Py_INCREF(Py_False);
    return Py_False;
}

static PyObject *Log_writable(LogObject *self, PyObject *args)
{
    Py_INCREF(Py_True);
    return Py_True;
}

static PyObject *Log_fileno(LogObject *self, PyObject *args)
{
    PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi log object is not "
            "associated with a file descriptor.");

    return NULL;
}
#endif

static PyObject *Log_closed(LogObject *self, void *closure)
{
    Py_INCREF(Py_False);
    return Py_False;
}

#if PY_MAJOR_VERSION < 3
static PyObject *Log_get_softspace(LogObject *self, void *closure)
{
    WSGIThreadInfo *thread_info = NULL;

    if (self->proxy)
        thread_info = wsgi_thread_info(0, 0);

    if (thread_info && thread_info->log_buffer)
        return Log_get_softspace((LogObject *)thread_info->log_buffer, closure);

    return PyInt_FromLong(self->softspace);
}

static int Log_set_softspace(LogObject *self, PyObject *value)
{
    long new;

    WSGIThreadInfo *thread_info = NULL;

    if (self->proxy)
        thread_info = wsgi_thread_info(0, 0);

    if (thread_info && thread_info->log_buffer)
        return Log_set_softspace((LogObject *)thread_info->log_buffer, value);

    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "can't delete softspace attribute");
        return -1;
    }

    new = PyInt_AsLong(value);
    if (new == -1 && PyErr_Occurred())
        return -1;

    self->softspace = new;

    return 0;
}

#else

static PyObject *Log_get_encoding(LogObject *self, void *closure)
{
    return PyUnicode_FromString("utf-8");
}

static PyObject *Log_get_errors(LogObject *self, void *closure)
{
    return PyUnicode_FromString("replace");
}
#endif

static PyMethodDef Log_methods[] = {
    { "flush",      (PyCFunction)Log_flush,      METH_NOARGS, 0 },
    { "close",      (PyCFunction)Log_close,      METH_NOARGS, 0 },
    { "isatty",     (PyCFunction)Log_isatty,     METH_NOARGS, 0 },
    { "write",      (PyCFunction)Log_write,      METH_VARARGS, 0 },
    { "writelines", (PyCFunction)Log_writelines, METH_VARARGS, 0 },
#if PY_MAJOR_VERSION >= 3
    { "readable",   (PyCFunction)Log_readable,   METH_NOARGS, 0 },
    { "seekable",   (PyCFunction)Log_seekable,   METH_NOARGS, 0 },
    { "writable",   (PyCFunction)Log_writable,   METH_NOARGS, 0 },
    { "fileno",     (PyCFunction)Log_fileno,   METH_NOARGS, 0 },
#endif
    { NULL, NULL}
};

static PyGetSetDef Log_getset[] = {
    { "closed", (getter)Log_closed, NULL, 0 },
#if PY_MAJOR_VERSION < 3
    { "softspace", (getter)Log_get_softspace, (setter)Log_set_softspace, 0 },
#else
    { "encoding", (getter)Log_get_encoding, NULL, 0 },
    { "errors", (getter)Log_get_errors, NULL, 0 },
#endif
    { NULL },
};

PyTypeObject Log_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "mod_wsgi.Log",         /*tp_name*/
    sizeof(LogObject),      /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Log_dealloc, /*tp_dealloc*/
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
    Log_methods,            /*tp_methods*/
    0,                      /*tp_members*/
    Log_getset,             /*tp_getset*/
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

void wsgi_log_python_error(request_rec *r, PyObject *log,
                           const char *filename, int publish)
{
    PyObject *m = NULL;
    PyObject *result = NULL;

    PyObject *type = NULL;
    PyObject *value = NULL;
    PyObject *traceback = NULL;

    PyObject *xlog = NULL;

    if (!PyErr_Occurred())
        return;

    if (!log) {
        PyErr_Fetch(&type, &value, &traceback);

        xlog = newLogObject(r, APLOG_ERR, NULL, 0);

        log = xlog;

        PyErr_Restore(type, value, traceback);

        type = NULL;
        value = NULL;
        traceback = NULL;
    }

    if (PyErr_ExceptionMatches(PyExc_SystemExit)) {
        Py_BEGIN_ALLOW_THREADS
        if (r) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_wsgi (pid=%d): SystemExit exception raised by "
                          "WSGI script '%s' ignored.", getpid(), filename);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                          "mod_wsgi (pid=%d): SystemExit exception raised by "
                          "WSGI script '%s' ignored.", getpid(), filename);
        }
        Py_END_ALLOW_THREADS
    }
    else {
        Py_BEGIN_ALLOW_THREADS
        if (r) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_wsgi (pid=%d): Exception occurred processing "
                          "WSGI script '%s'.", getpid(), filename);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                          "mod_wsgi (pid=%d): Exception occurred processing "
                          "WSGI script '%s'.", getpid(), filename);
        }
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
            PyObject *args = NULL;
            Py_INCREF(o);
            args = Py_BuildValue("(OOOOO)", type, value, traceback,
                                 Py_None, log);
            result = PyEval_CallObject(o, args);
            Py_DECREF(args);
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
        if (publish) {
            PyObject *event = NULL;
            PyObject *object = NULL;

            if (wsgi_event_subscribers()) {
                event = PyDict_New();

                object = Py_BuildValue("(OOO)", type, value, traceback);
                PyDict_SetItemString(event, "exception_info", object);
                Py_DECREF(object);

                wsgi_publish_event("request_exception", event);

                Py_DECREF(event);
            }
        }

        Py_DECREF(type);
        Py_DECREF(value);
        Py_DECREF(traceback);
    }

    Py_XDECREF(result);

    Py_XDECREF(m);

    Py_XDECREF(xlog);
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
