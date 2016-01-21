#ifndef WSGI_CONVERT_H
#define WSGI_CONVERT_H

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

/* ------------------------------------------------------------------------- */

extern PyObject *wsgi_convert_string_to_bytes(PyObject *value);
extern PyObject *wsgi_convert_status_line_to_bytes(PyObject *headers);
extern PyObject *wsgi_convert_headers_to_bytes(PyObject *headers);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
