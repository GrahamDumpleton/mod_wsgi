#ifndef WSGI_THREAD_H
#define WSGI_THREAD_H

/* ------------------------------------------------------------------------- */

/*
 * Copyright 2007-2015 GRAHAM DUMPLETON
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
    int thread_id;
    int request_thread;
    apr_int64_t request_count;
    PyObject *request_data;
    PyObject *log_buffer;
} WSGIThreadInfo;

extern int wsgi_total_threads;
extern int wsgi_request_threads;
extern apr_threadkey_t *wsgi_thread_key;
extern apr_array_header_t *wsgi_thread_details;

extern WSGIThreadInfo *wsgi_thread_info(int create, int request);

typedef struct {
    double user_time;
    double system_time;
} WSGIThreadCPUUsage;

extern int wsgi_thread_cpu_usage(WSGIThreadCPUUsage *usage);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
