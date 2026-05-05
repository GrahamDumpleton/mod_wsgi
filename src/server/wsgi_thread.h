#ifndef WSGI_THREAD_H
#define WSGI_THREAD_H

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
    int thread_id;
    int request_thread;
    apr_int64_t request_count;
    PyObject *request_id;
    PyObject *request_data;
    PyObject *log_buffer;

    /* Application group name of the interpreter this thread is currently
     * servicing a request in. Set by wsgi_execute_script just after
     * wsgi_acquire_interpreter succeeds, cleared just before
     * wsgi_release_interpreter. NULL when the thread is not currently
     * inside a request handler. The string is owned by Apache config
     * memory and lives for process lifetime, so no copy is needed.
     *
     * In daemon mode this is read by the monitor thread (via the
     * back-pointer on WSGIDaemonThread) to discover which sub-interpreter
     * to acquire when injecting a RequestTimeout exception into the
     * worker. */
    const char *current_application_group;

    /* Staging accumulator for GIL wait time observed at instrumented
     * Py_BEGIN/END_ALLOW_THREADS sites that fire before the per-request
     * active slot has been claimed (initial wsgi_acquire_interpreter,
     * module-lock acquire, "200 Continue" brigade send). Drained into
     * the slot in wsgi_start_request and reset at the top of
     * wsgi_execute_script. After slot claim the macros write directly
     * into the slot, so this stays at zero for the rest of the request. */
    apr_uint64_t staged_gil_wait_us;
    apr_uint64_t staged_gil_wait_count;
} WSGIThreadInfo;

extern int wsgi_total_threads;
extern int wsgi_request_threads;
extern apr_threadkey_t *wsgi_thread_key;
extern apr_array_header_t *wsgi_thread_details;

extern WSGIThreadInfo *wsgi_thread_info(int create, int request);

typedef struct
{
    double user_time;
    double system_time;
} WSGIThreadCPUUsage;

extern int wsgi_thread_cpu_usage(WSGIThreadCPUUsage *usage);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
