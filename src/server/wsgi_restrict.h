#ifndef WSGI_RESTRICT_H
#define WSGI_RESTRICT_H

/* ------------------------------------------------------------------------- */

/*
 * Copyright 2007-2020 GRAHAM DUMPLETON
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

/* Restricted object to stop access to STDIN/STDOUT. */

typedef struct {
    PyObject_HEAD
    const char *s;
} RestrictedObject;

extern PyTypeObject Restricted_Type;

extern RestrictedObject *newRestrictedObject(const char *s);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
