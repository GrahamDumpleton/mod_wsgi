#ifndef WSGI_APACHE_H
#define WSGI_APACHE_H

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

#if !defined(AP_SERVER_MAJORVERSION_NUMBER)
#if AP_MODULE_MAGIC_AT_LEAST(20010224,0)
#define AP_SERVER_MAJORVERSION_NUMBER 2
#define AP_SERVER_MINORVERSION_NUMBER 0
#define AP_SERVER_PATCHLEVEL_NUMBER 0
#else
#define AP_SERVER_MAJORVERSION_NUMBER 1
#define AP_SERVER_MINORVERSION_NUMBER 3
#define AP_SERVER_PATCHLEVEL_NUMBER 0
#endif
#endif

#if !defined(AP_SERVER_BASEVERSION)
#define AP_SERVER_BASEVERSION SERVER_BASEVERSION
#endif

#if AP_SERVER_MAJORVERSION_NUMBER < 2
#error Sorry, mod_wsgi 4.0+ requires Apache 2.0+.
#endif

#include "apr_lib.h"
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
APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup, (apr_pool_t *,
      server_rec *, conn_rec *, request_rec *, char *));

#include "ap_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "util_md5.h"
#include "mpm_common.h"
#include "scoreboard.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(wsgi);
#endif

#ifndef APR_FPROT_GWRITE
#define APR_FPROT_GWRITE APR_GWRITE
#endif
#ifndef APR_FPROT_WWRITE
#define APR_FPROT_WWRITE APR_WWRITE
#endif

#ifndef MPM_NAME
#define MPM_NAME ap_show_mpm()
#endif

#if !AP_MODULE_MAGIC_AT_LEAST(20050127,0)
/* Debian backported ap_regex_t to Apache 2.0 and
 * thus made official version checking break. */
#ifndef AP_REG_EXTENDED
typedef regex_t ap_regex_t;
typedef regmatch_t ap_regmatch_t;
#define AP_REG_EXTENDED REG_EXTENDED
#endif
#endif

#if !AP_MODULE_MAGIC_AT_LEAST(20081201,0)
#define ap_unixd_config unixd_config
#endif

#if !AP_MODULE_MAGIC_AT_LEAST(20051115,0)
extern void wsgi_ap_close_listeners(void);
#define ap_close_listeners wsgi_ap_close_listeners
#endif

#if (APR_MAJOR_VERSION == 0) && \
    (APR_MINOR_VERSION == 9) && \
    (APR_PATCH_VERSION < 5)
extern apr_status_t wsgi_apr_unix_file_cleanup(void *);
extern apr_status_t wsgi_apr_os_pipe_put_ex(apr_file_t **, apr_os_file_t *,
                                            int, apr_pool_t *);
#define apr_unix_file_cleanup wsgi_apr_unix_file_cleanup
#define apr_os_pipe_put_ex wsgi_apr_os_pipe_put_ex
#endif

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
typedef apr_uint16_t apr_wchar_t;
extern apr_status_t wsgi_utf8_to_unicode_path(apr_wchar_t* retstr,
                                              apr_size_t retlen, 
                                              const char* srcstr);
#endif

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
