#ifndef WSGI_BUCKETS_H
#define WSGI_BUCKETS_H

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

extern const apr_bucket_type_t wsgi_apr_bucket_type_python;

apr_bucket *wsgi_apr_bucket_python_create(const char *buf, apr_size_t length,
                                          const char *application_group,
                                          PyObject *string_object,
                                          apr_bucket_alloc_t *list);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
