#ifndef WSGI_METRICS_H
#define WSGI_METRICS_H

/* ------------------------------------------------------------------------- */

/*
 * Copyright 2007-2014 GRAHAM DUMPLETON
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

extern int wsgi_active_requests;
extern int wsgi_dump_stack_traces;

extern apr_thread_mutex_t* wsgi_monitor_lock;

extern PyMethodDef wsgi_get_utilization_method[];

extern double wsgi_start_request(void);
extern double wsgi_end_request(void);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
