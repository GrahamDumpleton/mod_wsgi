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

/*
 * Log: a write-only file-like Python object that routes writes
 * into the Apache error log via ap_log_error / ap_log_rerror.
 * mod_wsgi installs Log instances in place of sys.stderr (always)
 * and sys.stdout (when WSGIRestrictStdout is unset) in every
 * embedded interpreter, and exposes per-request instances to
 * Python application code as environ["wsgi.errors"], including
 * the environ dicts passed to authentication and dispatch
 * handlers.
 *
 * The type implements enough of the io.IOBase / io.RawIOBase
 * surface (write, writelines, flush, close, isatty, fileno,
 * readable/writable/seekable, name, closed, encoding, errors)
 * for typical user code that writes text via print() or via the
 * logging module to work without errors. A raw Log buffer is
 * produced by newLogBufferObject; newLogObject wraps that buffer
 * in an io.TextIOWrapper so encoding is handled by the standard
 * library rather than reimplemented here.
 *
 * The Python type backing this object is heap-allocated, created
 * via PyType_FromModuleAndSpec, so each Python sub-interpreter
 * has its own type instance. The type pointer lives in
 * WSGIModuleState and is looked up via
 * PyImport_ImportModule("mod_wsgi") + PyModule_GetState.
 */

/*
 * Construct a raw Log buffer that writes to the Apache error log
 * at `level`. When `r` is non-NULL the writes are tied to that
 * request (ap_log_rerror), otherwise they are server-scope
 * (ap_log_error). `name` is the value reported as the Python
 * `name` attribute (e.g. "<stderr>", "<wsgi.errors>") and must
 * have static lifetime: it is stored by pointer, not copied.
 * `proxy` enables per-thread buffer redirection used by the
 * adapter to interleave wsgi.errors writes with the active
 * request's log.
 */

extern PyObject *newLogBufferObject(request_rec *r, int level,
                                    const char *name, int proxy);

/*
 * Wrap a Log buffer in an io.TextIOWrapper so user code can use
 * Python's standard text-mode write protocol (UTF-8, "replace"
 * error handler, line-buffered) against the buffer. Returns a
 * new reference to the wrapper, or NULL with a Python exception
 * set if io.TextIOWrapper is unavailable or rejects the buffer.
 */

extern PyObject *newLogWrapperObject(PyObject *buffer);

/*
 * Convenience composition of newLogBufferObject and
 * newLogWrapperObject: returns a TextIOWrapper around a fresh
 * Log buffer, suitable for installation as sys.stderr / sys.stdout
 * or for use as wsgi.errors. The intermediate buffer is owned
 * solely by the wrapper.
 */

extern PyObject *newLogObject(request_rec *r, int level, const char *name,
                              int proxy);

/*
 * Create the heap-allocated Log PyTypeObject (and the LogHandler
 * subtype of logging.Handler) for `module`'s interpreter and
 * store both in WSGIModuleState. Called from the embedded
 * mod_wsgi module's exec slot. Returns 0 on success, -1 on
 * failure with Python exception set.
 */

extern int wsgi_logger_init(PyObject *module);

/* ------------------------------------------------------------------------- */

/*
 * wsgi_log_python_error logs a Python exception to the Apache error log:
 * a single header line that carries the WSGINNNN code and identifying
 * context, followed by the formatted traceback emitted line by line.
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
 *
 * The phase argument selects which header message template is used.
 * Each phase corresponds to a distinct lifecycle event with its own
 * operator-facing wording and its own WSGINNNN codes for normal
 * exceptions and SystemExit. The actual codes are an implementation
 * detail and live in the function body.
 */

typedef enum
{
    WSGI_LOG_PYTHON_PHASE_RUNNING = 0,
    WSGI_LOG_PYTHON_PHASE_INTERP_INIT,
    WSGI_LOG_PYTHON_PHASE_INTERP_ATEXIT,
    WSGI_LOG_PYTHON_PHASE_EVENT_CALLBACK
} wsgi_log_python_phase;

extern void wsgi_log_python_error_ex(const char *file, int line,
                                     int module_index, request_rec *r,
                                     const char *filename,
                                     const char *application_group,
                                     int publish,
                                     wsgi_log_python_phase phase);

#define wsgi_log_python_error(r, filename, application_group, publish) \
    wsgi_log_python_error_ex(APLOG_MARK, (r), (filename),              \
                             (application_group), (publish),           \
                             WSGI_LOG_PYTHON_PHASE_RUNNING)

#define wsgi_log_python_interp_init_error(application_group) \
    wsgi_log_python_error_ex(APLOG_MARK, NULL, NULL,         \
                             (application_group), 0,         \
                             WSGI_LOG_PYTHON_PHASE_INTERP_INIT)

#define wsgi_log_python_interp_atexit_error(application_group) \
    wsgi_log_python_error_ex(APLOG_MARK, NULL, NULL,           \
                             (application_group), 0,           \
                             WSGI_LOG_PYTHON_PHASE_INTERP_ATEXIT)

#define wsgi_log_python_event_callback_error(event_name)     \
    wsgi_log_python_error_ex(APLOG_MARK, NULL, (event_name), \
                             NULL, 0,                        \
                             WSGI_LOG_PYTHON_PHASE_EVENT_CALLBACK)

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

#define wsgi_log_error(level, rv, s, ...)                            \
    do                                                               \
    {                                                                \
        if (APLOG_MODULE_IS_LEVEL((s), APLOG_MODULE_INDEX, (level))) \
            wsgi_log_error_ex(APLOG_MARK, (level), (rv), (s),        \
                              __VA_ARGS__);                          \
    } while (0)

#define wsgi_log_error_locked(level, rv, s, ...)                     \
    do                                                               \
    {                                                                \
        if (APLOG_MODULE_IS_LEVEL((s), APLOG_MODULE_INDEX, (level))) \
            wsgi_log_error_locked_ex(APLOG_MARK, (level), (rv), (s), \
                                     __VA_ARGS__);                   \
    } while (0)

#define wsgi_log_rerror(level, rv, r, ...)                             \
    do                                                                 \
    {                                                                  \
        if (APLOG_R_MODULE_IS_LEVEL((r), APLOG_MODULE_INDEX, (level))) \
            wsgi_log_rerror_ex(APLOG_MARK, (level), (rv), (r),         \
                               __VA_ARGS__);                           \
    } while (0)

#define wsgi_log_rerror_locked(level, rv, r, ...)                      \
    do                                                                 \
    {                                                                  \
        if (APLOG_R_MODULE_IS_LEVEL((r), APLOG_MODULE_INDEX, (level))) \
            wsgi_log_rerror_locked_ex(APLOG_MARK, (level), (rv), (r),  \
                                      __VA_ARGS__);                    \
    } while (0)

/* ------------------------------------------------------------------------- */

/*
 * Sets a Python exception of type exc_type with a PyUnicode_FromFormat-
 * style message, chaining any currently set exception as the cause.
 * Equivalent to "raise NewExc from existing" when an exception is
 * already set; equivalent to PyErr_Format when none is. Both
 * __cause__ and __context__ are populated and __suppress_context__ is
 * set, matching "raise X from Y". If formatting itself fails, the
 * original exception (if any) is left in place.
 *
 * The format string uses Python's PyUnicode_FromFormat specifiers
 * (%S, %R, %V, %A, %U, plus the standard %s/%d/etc.), not printf, so
 * the function is intentionally not tagged with the printf format
 * attribute.
 */
extern void wsgi_set_python_exception_from_cause(PyObject *exc_type,
                                                 const char *format, ...);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
