#ifndef WSGI_INTERP_H
#define WSGI_INTERP_H

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

#include "wsgi_python.h"
#include "wsgi_apache.h"

/* ------------------------------------------------------------------------- */

typedef struct {
    PyObject_HEAD
    PyObject *wrapped;
} SignalInterceptObject;

extern PyTypeObject SignalIntercept_Type;

typedef struct {
    PyObject_HEAD
    PyObject *wrapped;
} ShutdownInterpreterObject;

extern PyTypeObject ShutdownInterpreter_Type;

typedef struct {
    PyObject_HEAD
    char *name;
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
extern int wsgi_python_after_fork;

#ifndef MOD_WSGI_DISABLE_EMBEDDED
extern int wsgi_python_required;
#endif

extern const char *wsgi_python_path;
extern const char *wsgi_python_eggs;

extern PyObject *wsgi_interpreters;

#if APR_HAS_THREADS
extern apr_thread_mutex_t *wsgi_interp_lock;
#endif

extern void wsgi_python_version(void);

extern void wsgi_python_init(apr_pool_t *p);
extern apr_status_t wsgi_python_term(void);

extern InterpreterObject *wsgi_acquire_interpreter(const char *name);
extern void wsgi_release_interpreter(InterpreterObject *handle);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
