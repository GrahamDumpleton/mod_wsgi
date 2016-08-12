#ifndef WSGI_METRICS_H
#define WSGI_METRICS_H

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

#include "wsgi_thread.h"

/* ------------------------------------------------------------------------- */

extern apr_uint64_t wsgi_total_requests;
extern int wsgi_active_requests;
extern int wsgi_dump_stack_traces;

extern apr_thread_mutex_t* wsgi_monitor_lock;

extern PyMethodDef wsgi_process_metrics_method[];

extern WSGIThreadInfo *wsgi_start_request(void);
extern void wsgi_end_request(void);

extern PyMethodDef wsgi_server_metrics_method[];

extern long wsgi_event_subscribers(void);
extern void wsgi_publish_event(const char *name, PyObject *event);

extern PyMethodDef wsgi_process_events_method[];

extern PyMethodDef wsgi_request_data_method[];

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
