#ifndef WSGI_ADAPTER_H
#define WSGI_ADAPTER_H

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
#include "wsgi_server.h"

/* ------------------------------------------------------------------------- */

typedef struct
{
    PyObject_HEAD request_rec *r;
    int init;
    int done;
    char *buffer;
    apr_off_t size;
    apr_off_t offset;
    apr_off_t length;
    apr_bucket_brigade *bb;
    int seen_eos;
    int seen_error;
    apr_off_t bytes;
    apr_off_t reads;
    apr_time_t time;
    int ignore_activity;
} InputObject;

extern PyTypeObject Input_Type;

extern void Input_finish(InputObject *self);

typedef struct
{
    PyObject_HEAD int result;
    request_rec *r;
    apr_bucket_brigade *bb;
    WSGIRequestConfig *config;
    InputObject *input;
    PyObject *log_buffer;
    PyObject *log;
    int status;
    const char *status_line;
    PyObject *headers;
    PyObject *sequence;
    int content_length_set;
    apr_off_t content_length;
    apr_off_t output_length;
    apr_off_t output_writes;
    apr_time_t output_time;
    apr_time_t start_time;
} AdapterObject;

extern PyTypeObject Adapter_Type;

extern AdapterObject *newAdapterObject(request_rec *r);

extern int Adapter_run(AdapterObject *self, PyObject *object);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
