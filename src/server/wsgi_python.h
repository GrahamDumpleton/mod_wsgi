#ifndef WSGI_PYTHON_H
#define WSGI_PYTHON_H

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

#define PY_SSIZE_T_CLEAN 1

#include <Python.h>

#if !defined(PY_VERSION_HEX)
#error Sorry, Python developer package does not appear to be installed.
#endif

#if PY_VERSION_HEX < 0x030a0000
#error Sorry, mod_wsgi requires at least Python 3.10.0.
#endif

#include "structmember.h"
#include "compile.h"
#include "osdefs.h"
#include "frameobject.h"

/* ------------------------------------------------------------------------- */

#define WSGI_STATIC_INTERNED_STRING(name) \
    static PyObject *wsgi_id_##name

#define WSGI_CREATE_INTERNED_STRING(name, val) \
    if (wsgi_id_##name) ; else wsgi_id_##name = \
    PyUnicode_InternFromString(val)

#define WSGI_CREATE_INTERNED_STRING_ID(name) \
    if (wsgi_id_##name) ; else wsgi_id_##name = \
    PyUnicode_InternFromString(#name)

#define WSGI_INTERNED_STRING(name) \
    wsgi_id_##name

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
