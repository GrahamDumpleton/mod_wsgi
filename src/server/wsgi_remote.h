#ifndef WSGI_REMOTE_H
#define WSGI_REMOTE_H

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

#include "wsgi_apache.h"
#include "wsgi_daemon.h"

/* ------------------------------------------------------------------------- */

#if defined(MOD_WSGI_WITH_DAEMONS)

extern int wsgi_execute_remote(request_rec *r);

extern apr_status_t wsgi_read_request(apr_socket_t *sock, request_rec *r);

extern ap_filter_rec_t *wsgi_header_filter_handle;

extern apr_status_t wsgi_header_filter(ap_filter_t *f, apr_bucket_brigade *b);

#endif

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
