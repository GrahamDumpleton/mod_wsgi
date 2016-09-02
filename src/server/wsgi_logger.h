#ifndef WSGI_LOGGER_H
#define WSGI_LOGGER_H

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

extern PyTypeObject Log_Type;

extern PyObject *newLogBufferObject(request_rec *r, int level,
                                    const char *name, int proxy);

extern PyObject *newLogWrapperObject(PyObject *buffer);

extern PyObject *newLogObject(request_rec *r, int level, const char *name,
                             int proxy);

extern void wsgi_log_python_error(request_rec *r, PyObject *log,
                                  const char *filename, int publish);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
