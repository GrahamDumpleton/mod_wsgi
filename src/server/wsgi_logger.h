#ifndef WSGI_LOGGER_H
#define WSGI_LOGGER_H

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

#include "wsgi_python.h"
#include "wsgi_apache.h"

/* ------------------------------------------------------------------------- */

extern PyTypeObject Log_Type;

extern PyObject *newLogBufferObject(request_rec *r, int level,
                                    const char *name, int proxy);

extern PyObject *newLogWrapperObject(PyObject *buffer);

extern PyObject *newLogObject(request_rec *r, int level, const char *name,
                              int proxy);

/*
 * wsgi_log_python_error logs a Python exception to the Apache error log:
 * a single header line that carries the WSGINNNN code, the script path,
 * and the interpreter+process context, followed by the formatted
 * traceback emitted line by line.
 *
 * The traceback is captured into an io.StringIO under the GIL, then the
 * entire emission (header + traceback continuation) is performed under
 * a single Py_BEGIN_ALLOW_THREADS / Py_END_ALLOW_THREADS pair so that a
 * slow piped ErrorLog stalls the calling thread once rather than once
 * per traceback line.
 *
 * application_group identifies the Python interpreter the exception
 * was raised in. Pass NULL when r is non-NULL; the function will
 * extract config->application_group from the request itself. Server-
 * context callers (r == NULL) must pass it explicitly.
 */
extern void wsgi_log_python_error_ex(const char *file, int line,
                                     int module_index, request_rec *r,
                                     const char *filename,
                                     const char *application_group,
                                     int publish);

#define wsgi_log_python_error(r, filename, application_group, publish) \
    wsgi_log_python_error_ex(APLOG_MARK, (r), (filename), \
                             (application_group), (publish))

/* ------------------------------------------------------------------------- */

/*
 * Logging helpers. These wrap ap_log_error / ap_log_rerror so the same
 * call shape is used everywhere in mod_wsgi. The macros capture
 * APLOG_MARK at the call site and forward to the _ex functions, which
 * preserves the original caller's __FILE__ / __LINE__ in Apache's log
 * metadata.
 *
 * The _locked variants release the Python GIL around the underlying
 * Apache log call, for use from contexts where the calling thread
 * holds the GIL. A slow piped ErrorLog must not stall every Python
 * thread; releasing the GIL during the log call lets other Python
 * threads run while the log write blocks.
 *
 * Each macro begins with a per-module log-level test, so when the
 * configured level is below the message level (e.g. APLOG_DEBUG with
 * the default LogLevel) nothing happens: no argument evaluation, no
 * formatting work, and no GIL release for the _locked variants.
 *
 * Each macro evaluates `level`, `s`, and `r` more than once; do not
 * pass side-effecting expressions (same convention as printf-style
 * macros).
 */

/*
 * WSGI_APLOGNO(n) is mod_wsgi's analogue of httpd's APLOGNO(n). It expands
 * to a string literal of the form "WSGIxxxx: " that prefixes the format
 * string of a log call. The "WSGI" prefix gives mod_wsgi its own error-code
 * namespace, distinct from httpd's "AH" codes. The number is allocated
 * sequentially in source-walking order; each number maps to a docs entry
 * in docs/error-reference.rst with the same anchor (e.g. WSGI0001).
 *
 * Usage:
 *     wsgi_log_error(APLOG_CRIT, 0, wsgi_server, WSGI_APLOGNO(0001)
 *                    "Some message about '%s'.", value);
 */

#define WSGI_APLOGNO(n) "WSGI" #n ": "

extern void wsgi_log_error_ex(const char *file, int line, int module_index,
                              int level, apr_status_t rv, server_rec *s,
                              const char *fmt, ...)
    __attribute__((format(printf, 7, 8)));

extern void wsgi_log_error_locked_ex(const char *file, int line,
                                     int module_index, int level,
                                     apr_status_t rv, server_rec *s,
                                     const char *fmt, ...)
    __attribute__((format(printf, 7, 8)));

extern void wsgi_log_rerror_ex(const char *file, int line, int module_index,
                               int level, apr_status_t rv, request_rec *r,
                               const char *fmt, ...)
    __attribute__((format(printf, 7, 8)));

extern void wsgi_log_rerror_locked_ex(const char *file, int line,
                                      int module_index, int level,
                                      apr_status_t rv, request_rec *r,
                                      const char *fmt, ...)
    __attribute__((format(printf, 7, 8)));

#define wsgi_log_error(level, rv, s, ...) \
    do { \
        if (APLOG_MODULE_IS_LEVEL((s), APLOG_MODULE_INDEX, (level))) \
            wsgi_log_error_ex(APLOG_MARK, (level), (rv), (s), \
                              __VA_ARGS__); \
    } while (0)

#define wsgi_log_error_locked(level, rv, s, ...) \
    do { \
        if (APLOG_MODULE_IS_LEVEL((s), APLOG_MODULE_INDEX, (level))) \
            wsgi_log_error_locked_ex(APLOG_MARK, (level), (rv), (s), \
                                     __VA_ARGS__); \
    } while (0)

#define wsgi_log_rerror(level, rv, r, ...) \
    do { \
        if (APLOG_R_MODULE_IS_LEVEL((r), APLOG_MODULE_INDEX, (level))) \
            wsgi_log_rerror_ex(APLOG_MARK, (level), (rv), (r), \
                               __VA_ARGS__); \
    } while (0)

#define wsgi_log_rerror_locked(level, rv, r, ...) \
    do { \
        if (APLOG_R_MODULE_IS_LEVEL((r), APLOG_MODULE_INDEX, (level))) \
            wsgi_log_rerror_locked_ex(APLOG_MARK, (level), (rv), (r), \
                                      __VA_ARGS__); \
    } while (0)

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
