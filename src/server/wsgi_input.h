#ifndef WSGI_INPUT_H
#define WSGI_INPUT_H

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

extern InputObject *newInputObject(request_rec *r, int ignore_activity);

extern void Input_finish(InputObject *self);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
