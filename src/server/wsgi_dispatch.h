#ifndef WSGI_DISPATCH_H
#define WSGI_DISPATCH_H

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
    WSGIRequestConfig *config;
    PyObject *log;
} DispatchObject;

extern PyTypeObject Dispatch_Type;

extern int wsgi_execute_dispatch(request_rec *r);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
