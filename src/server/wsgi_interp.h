#ifndef WSGI_INTERP_H
#define WSGI_INTERP_H

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

typedef struct
{
    PyObject_HEAD char *name;
    PyInterpreterState *interp;
    int owner;
#if APR_HAS_THREADS
    apr_hash_t *tstate_table;
#else
    PyThreadState *tstate;
#endif
} InterpreterObject;

extern PyTypeObject Interpreter_Type;

extern InterpreterObject *newInterpreterObject(const char *name);

extern int wsgi_python_initialized;

extern int wsgi_python_required;

extern const char *wsgi_python_path;
extern const char *wsgi_python_eggs;

extern PyObject *wsgi_interpreters;

extern PyObject *wsgi_request_timeout_exc;

extern apr_hash_t *wsgi_interpreters_index;

#if APR_HAS_THREADS
extern apr_thread_mutex_t *wsgi_interp_lock;
extern apr_thread_mutex_t *wsgi_module_lock;
extern apr_thread_mutex_t *wsgi_shutdown_lock;
#endif

extern char *wsgi_module_name(apr_pool_t *pool, const char *filename);

/*
 * Helpers that format an interpreter or interpreter+process descriptor
 * for inclusion in log messages. The returned strings are allocated
 * from the supplied pool. Empty/NULL group names render as
 * "main interpreter" and "embedded mode" respectively, matching the
 * terminology used throughout the documentation.
 *
 * wsgi_format_process_context() inspects the wsgi_daemon_process
 * global to describe where the calling code is currently running:
 * "daemon process '<group>'" when invoked from a daemon process and
 * "embedded mode" when invoked from the Apache child.
 */

extern const char *wsgi_format_interp_name(apr_pool_t *p,
                                           const char *application_group);

extern const char *wsgi_format_interp_context(apr_pool_t *p,
                                              const char *process_group,
                                              const char *application_group);

extern const char *wsgi_format_process_context(apr_pool_t *p);

extern int wsgi_reload_required(apr_pool_t *pool, request_rec *r,
                                const char *filename, PyObject *module,
                                const char *resource);

extern PyObject *wsgi_load_source(apr_pool_t *pool, request_rec *r,
                                  const char *name, int exists,
                                  const char *filename,
                                  const char *process_group,
                                  const char *application_group,
                                  int ignore_system_exit);

extern void wsgi_python_version(void);

extern apr_status_t wsgi_python_init(apr_pool_t *p);
extern apr_status_t wsgi_python_term(void);

extern InterpreterObject *wsgi_acquire_interpreter(const char *name);
extern void wsgi_release_interpreter(InterpreterObject *handle);

extern void wsgi_publish_process_stopping(char *reason);

extern apr_status_t wsgi_python_child_init(apr_pool_t *p);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
