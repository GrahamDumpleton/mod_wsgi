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

#include "wsgi_daemon.h"

/* ------------------------------------------------------------------------- */

int wsgi_daemon_count = 0;
apr_hash_t *wsgi_daemon_index = NULL;
apr_hash_t *wsgi_daemon_listeners = NULL;

WSGIDaemonProcess *wsgi_daemon_process = NULL;

int volatile wsgi_request_count = 0;

WSGIDaemonThread *wsgi_worker_threads = NULL;

WSGIThreadStack *wsgi_worker_stack = NULL;

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
