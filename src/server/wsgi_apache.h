#ifndef WSGI_APACHE_H
#define WSGI_APACHE_H

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

/*
 * Enabled access to Apache private API and data structures. Need to do
 * this to access the following:
 *
 *   In Apache 2.X need access to ap_create_request_config().
 *
 *   In Apache 2.X need access to core_module and core_request_config.
 *
 */

/* ------------------------------------------------------------------------- */

#define CORE_PRIVATE 1

#if defined(_WIN32)
#include <ws2tcpip.h>
#endif

#include "httpd.h"

#if !defined(HTTPD_ROOT)
#error Sorry, Apache developer package does not appear to be installed.
#endif

#if !AP_MODULE_MAGIC_AT_LEAST(20120211, 0)
#error Sorry, mod_wsgi 6.0+ requires Apache 2.4+.
#endif

#include "apr_lib.h"
#include "apr_atomic.h"
#include "ap_mpm.h"
#include "ap_compat.h"
#include "apr_tables.h"
#include "apr_strings.h"
#include "http_config.h"
#include "ap_listen.h"
#include "apr_version.h"
#include "apr_buckets.h"
#include "apr_date.h"
#include "mpm_common.h"

#include "apr_optional.h"

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup, (apr_pool_t *, server_rec *, conn_rec *, request_rec *, char *));

#include "ap_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "util_md5.h"
#include "scoreboard.h"

/* ------------------------------------------------------------------------- */

/*
 * Whether mod_wsgi is built with support for separate daemon processes
 * (WSGIDaemonProcess). This requires fork() and APR other-child support
 * and is never available on Windows.
 *
 * Defined here in the common Apache header, rather than in the daemon
 * specific wsgi_daemon.h, so that every translation unit which
 * conditionally compiles daemon mode code sees a consistent value
 * without having to include the daemon API header. When this is not
 * visible the guarded code is silently compiled out rather than failing
 * to build.
 */

#ifndef WIN32
#if APR_HAS_OTHER_CHILD && APR_HAS_FORK
#define MOD_WSGI_WITH_DAEMONS 1
#endif
#endif

APLOG_USE_MODULE(wsgi);

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
typedef apr_uint16_t apr_wchar_t;
extern apr_status_t wsgi_utf8_to_unicode_path(apr_wchar_t *retstr,
                                              apr_size_t retlen,
                                              const char *srcstr);
#endif

extern apr_status_t wsgi_strtoff(apr_off_t *offset, const char *nptr,
                                 char **endptr, int base);

extern char *wsgi_http2env(apr_pool_t *a, const char *w);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
