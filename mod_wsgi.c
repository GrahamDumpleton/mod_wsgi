/* vim: set sw=4 expandtab : */

/*
 * Copyright 2007-2010 GRAHAM DUMPLETON
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

/*
 * Enabled access to Apache private API and data structures. Need to do
 * this to access the following:
 *
 *   In Apache 1.3 it is not possible to access ap_check_cmd_context()
 *   where as this was made public in Apache 2.0.
 *
 *   In Apache 2.X need access to ap_create_request_config().
 *
 *   In Apache 2.X need access to core_module and core_request_config.
 *
 */

#define CORE_PRIVATE 1

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
typedef int apr_status_t;
#define APR_SUCCESS 0
typedef pool apr_pool_t;
typedef unsigned int apr_port_t;
#include "ap_ctype.h"
#include "ap_alloc.h"
#define apr_isspace ap_isspace
#define apr_table_make ap_make_table
#define apr_table_get ap_table_get
#define apr_table_set ap_table_set
#define apr_table_setn ap_table_setn
#define apr_table_add ap_table_add
#define apr_table_elts ap_table_elts
#define apr_array_make ap_make_array
#define apr_array_push ap_push_array
#define apr_array_cat ap_array_cat
#define apr_array_append ap_append_arrays
typedef array_header apr_array_header_t;
typedef table apr_table_t;
typedef table_entry apr_table_entry_t;
typedef int apr_size_t;
typedef unsigned long apr_off_t;
#define apr_psprintf ap_psprintf
#define apr_pstrndup ap_pstrndup
#define apr_pstrdup ap_pstrdup
#define apr_pstrcat ap_pstrcat
#define apr_pcalloc ap_pcalloc
#define apr_palloc ap_palloc
#define apr_isalnum isalnum
#define apr_toupper toupper
typedef time_t apr_time_t;
#include "http_config.h"
typedef int apr_lockmech_e;
#else
#include "apr_lib.h"
#include "ap_mpm.h"
#include "ap_compat.h"
#include "apr_tables.h"
#include "apr_strings.h"
#include "http_config.h"
#include "ap_listen.h"
#include "apr_version.h"
#endif

#include "ap_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "util_md5.h"

#ifndef APR_FPROT_GWRITE
#define APR_FPROT_GWRITE APR_GWRITE
#endif
#ifndef APR_FPROT_WWRITE
#define APR_FPROT_WWRITE APR_WWRITE
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

#ifndef WIN32
#include <pwd.h>
#endif

#include "Python.h"

#if !defined(PY_VERSION_HEX)
#error Sorry, Python developer package does not appear to be installed.
#endif

#if PY_VERSION_HEX <= 0x02030000
#error Sorry, mod_wsgi requires at least Python 2.3.0 for Python 2.X.
#endif

#if PY_VERSION_HEX >= 0x03000000 && PY_VERSION_HEX < 0x03010000
#error Sorry, mod_wsgi requires at least Python 3.1.0 for Python 3.X.
#endif

#if !defined(WITH_THREAD)
#error Sorry, mod_wsgi requires that Python supporting thread.
#endif

#include "compile.h"
#include "node.h"
#include "osdefs.h"

#ifndef PyVarObject_HEAD_INIT
#define PyVarObject_HEAD_INIT(type, size)       \
        PyObject_HEAD_INIT(type) size,
#endif

#if PY_MAJOR_VERSION >= 3
#define PyStringObject PyBytesObject
#define PyString_Check PyBytes_Check
#define PyString_Size PyBytes_Size
#define PyString_AsString PyBytes_AsString
#define PyString_FromString PyBytes_FromString
#define PyString_FromStringAndSize PyBytes_FromStringAndSize
#define PyString_AS_STRING PyBytes_AS_STRING
#define PyString_GET_SIZE PyBytes_GET_SIZE
#define _PyString_Resize _PyBytes_Resize
#endif

#ifndef WIN32
#if AP_SERVER_MAJORVERSION_NUMBER >= 2
#if APR_HAS_OTHER_CHILD && APR_HAS_THREADS && APR_HAS_FORK
#define MOD_WSGI_WITH_DAEMONS 1
#endif
#endif
#endif

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
#define MOD_WSGI_WITH_BUCKETS 1
#define MOD_WSGI_WITH_AAA_HANDLERS 1
#endif

#if defined(MOD_WSGI_WITH_AAA_HANDLERS)
static PyTypeObject Auth_Type;
#if AP_SERVER_MAJORVERSION_NUMBER >= 2
#if AP_SERVER_MINORVERSION_NUMBER >= 2
#define MOD_WSGI_WITH_AUTHN_PROVIDER 1
#endif
#endif
#if AP_MODULE_MAGIC_AT_LEAST(20060110,0)
#define MOD_WSGI_WITH_AUTHZ_PROVIDER 1
#endif
#endif

#if defined(MOD_WSGI_WITH_AUTHN_PROVIDER)
#include "mod_auth.h"
#include "ap_provider.h"
#ifndef AUTHN_PROVIDER_VERSION
#define AUTHN_PROVIDER_VERSION "0"
#endif
#endif

#if defined(MOD_WSGI_WITH_DAEMONS)

#if !AP_MODULE_MAGIC_AT_LEAST(20051115,0)
static void ap_close_listeners(void)
{
    ap_listen_rec *lr;

    for (lr = ap_listeners; lr; lr = lr->next) {
        apr_socket_close(lr->sd);
        lr->active = 0;
    }
}
#endif

#if (APR_MAJOR_VERSION == 0) && \
    (APR_MINOR_VERSION == 9) && \
    (APR_PATCH_VERSION < 5)
static apr_status_t apr_unix_file_cleanup(void *thefile)
{
    apr_file_t *file = thefile;

    return apr_file_close(file);
}

static apr_status_t apr_os_pipe_put_ex(apr_file_t **file,
                                       apr_os_file_t *thefile,
                                       int register_cleanup,
                                       apr_pool_t *pool)
{
    apr_status_t rv;

    rv = apr_os_pipe_put(file, thefile, pool);

    if (register_cleanup) {
        apr_pool_cleanup_register(pool, (void *)(*file),
                                  apr_unix_file_cleanup,
                                  apr_pool_cleanup_null);
    }

    return rv;
}
#endif

#endif

#if AP_SERVER_MAJORVERSION_NUMBER < 2

static char *apr_off_t_toa(apr_pool_t *p, apr_off_t n)
{
    const int BUFFER_SIZE = sizeof(apr_off_t) * 3 + 2;
    char *buf = apr_palloc(p, BUFFER_SIZE);
    char *start = buf + BUFFER_SIZE - 1;
    int negative;
    if (n < 0) {
        negative = 1;
        n = -n;
    }
    else {
        negative = 0;
    }
    *start = 0;
    do {
        *--start = '0' + (char)(n % 10);
        n /= 10;
    } while (n);
    if (negative) {
        *--start = '-';
    }
    return start;
}

#endif

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
typedef apr_uint16_t apr_wchar_t;

APR_DECLARE(apr_status_t) apr_conv_utf8_to_ucs2(const char *in,
                                                apr_size_t *inbytes,
                                                apr_wchar_t *out,
                                                apr_size_t *outwords);

static apr_status_t wsgi_utf8_to_unicode_path(apr_wchar_t* retstr,
                                              apr_size_t retlen, 
                                              const char* srcstr)
{
    /* TODO: The computations could preconvert the string to determine
     * the true size of the retstr, but that's a memory over speed
     * tradeoff that isn't appropriate this early in development.
     *
     * Allocate the maximum string length based on leading 4 
     * characters of \\?\ (allowing nearly unlimited path lengths) 
     * plus the trailing null, then transform /'s into \\'s since
     * the \\?\ form doesn't allow '/' path seperators.
     *
     * Note that the \\?\ form only works for local drive paths, and
     * \\?\UNC\ is needed UNC paths.
     */
    apr_size_t srcremains = strlen(srcstr) + 1;
    apr_wchar_t *t = retstr;
    apr_status_t rv;

    /* This is correct, we don't twist the filename if it is will
     * definately be shorter than 248 characters.  It merits some 
     * performance testing to see if this has any effect, but there
     * seem to be applications that get confused by the resulting
     * Unicode \\?\ style file names, especially if they use argv[0]
     * or call the Win32 API functions such as GetModuleName, etc.
     * Not every application is prepared to handle such names.
     * 
     * Note also this is shorter than MAX_PATH, as directory paths 
     * are actually limited to 248 characters. 
     *
     * Note that a utf-8 name can never result in more wide chars
     * than the original number of utf-8 narrow chars.
     */
    if (srcremains > 248) {
        if (srcstr[1] == ':' && (srcstr[2] == '/' || srcstr[2] == '\\')) {
            wcscpy (retstr, L"\\\\?\\");
            retlen -= 4;
            t += 4;
        }
        else if ((srcstr[0] == '/' || srcstr[0] == '\\')
              && (srcstr[1] == '/' || srcstr[1] == '\\')
              && (srcstr[2] != '?')) {
            /* Skip the slashes */
            srcstr += 2;
            srcremains -= 2;
            wcscpy (retstr, L"\\\\?\\UNC\\");
            retlen -= 8;
            t += 8;
        }
    }

    if (rv = apr_conv_utf8_to_ucs2(srcstr, &srcremains, t, &retlen)) {
        return (rv == APR_INCOMPLETE) ? APR_EINVAL : rv;
    }
    if (srcremains) {
        return APR_ENAMETOOLONG;
    }
    for (; *t; ++t)
        if (*t == L'/')
            *t = L'\\';
    return APR_SUCCESS;
}
#endif

/* Compatibility macros for log level and status. */

#if AP_SERVER_MAJORVERSION_NUMBER < 2
#define WSGI_LOG_LEVEL(l) l
#define WSGI_LOG_LEVEL_AND_STATUS(l, e) l | (!e ? APLOG_NOERRNO : 0)
#else
#define WSGI_LOG_LEVEL(l) l, 0
#define WSGI_LOG_LEVEL_AND_STATUS(l, e) l, e
#endif

#define WSGI_LOG_EMERG(e) WSGI_LOG_LEVEL_AND_STATUS(APLOG_EMERG, e)
#define WSGI_LOG_ALERT(e) WSGI_LOG_LEVEL_AND_STATUS(APLOG_ALERT, e)
#define WSGI_LOG_CRIT(e) WSGI_LOG_LEVEL_AND_STATUS(APLOG_CRIT, e)
#define WSGI_LOG_ERR(e) WSGI_LOG_LEVEL_AND_STATUS(APLOG_ERR, e)
#define WSGI_LOG_WARNING(e) WSGI_LOG_LEVEL_AND_STATUS(APLOG_WARNING, e)
#define WSGI_LOG_NOTICE(e) WSGI_LOG_LEVEL_AND_STATUS(APLOG_NOTICE, e)
#define WSGI_LOG_INFO(e) WSGI_LOG_LEVEL_AND_STATUS(APLOG_INFO, e)
#define WSGI_LOG_DEBUG(e) WSGI_LOG_LEVEL_AND_STATUS(APLOG_DEBUG, e)

/* Version and module information. */

#define MOD_WSGI_MAJORVERSION_NUMBER 3
#define MOD_WSGI_MINORVERSION_NUMBER 3
#define MOD_WSGI_VERSION_STRING "3.3"

#if AP_SERVER_MAJORVERSION_NUMBER < 2
module MODULE_VAR_EXPORT wsgi_module;
#else
module AP_MODULE_DECLARE_DATA wsgi_module;
#endif

/* Constants. */

#define WSGI_RELOAD_MODULE 0
#define WSGI_RELOAD_PROCESS 1

/* Base server object. */

static server_rec *wsgi_server = NULL;

/* Process information. */

static pid_t wsgi_parent_pid = 0;
static int wsgi_multiprocess = 1;
static int wsgi_multithread = 1;

/* Daemon information. */

static const char *wsgi_daemon_group = "";

static apr_array_header_t *wsgi_daemon_list = NULL;

static apr_pool_t *wsgi_parent_pool = NULL;
static apr_pool_t *wsgi_daemon_pool = NULL;

static int volatile wsgi_daemon_shutdown = 0;

#if defined(MOD_WSGI_WITH_DAEMONS)
static apr_interval_time_t wsgi_deadlock_timeout = 0;
static apr_interval_time_t wsgi_inactivity_timeout = 0;
static apr_time_t volatile wsgi_deadlock_shutdown_time = 0;
static apr_time_t volatile wsgi_inactivity_shutdown_time = 0;
static apr_thread_mutex_t* wsgi_shutdown_lock = NULL;
#endif

/* Script information. */

static apr_array_header_t *wsgi_import_list = NULL;

/* Configuration objects. */

typedef struct {
    const char *location;
    const char *application;
    ap_regex_t *regexp;
    const char *process_group;
    const char *application_group;
    const char *callable_object;
    int pass_authorization;
} WSGIAliasEntry;

typedef struct {
    const char *handler_script;
    const char *process_group;
    const char *application_group;
    const char *callable_object;
    const char *pass_authorization;
} WSGIScriptFile;

typedef struct {
    apr_pool_t *pool;

    apr_array_header_t *alias_list;

    const char *socket_prefix;
    apr_lockmech_e lock_mechanism;

    int verbose_debugging;

    apr_array_header_t *python_warnings;

    int python_optimize;
    int py3k_warning_flag;

    const char *python_home;
    const char *python_path;
    const char *python_eggs;

    int restrict_embedded;
    int restrict_stdin;
    int restrict_stdout;
    int restrict_signal;

    int case_sensitivity;

    apr_table_t *restrict_process;

    const char *process_group;
    const char *application_group;
    const char *callable_object;

    WSGIScriptFile *dispatch_script;

    int pass_apache_request;
    int pass_authorization;
    int script_reloading;
    int error_override;
    int chunked_request;

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    apr_hash_t *handler_scripts;
#endif
} WSGIServerConfig;

static WSGIServerConfig *wsgi_server_config = NULL;

static WSGIScriptFile *newWSGIScriptFile(apr_pool_t *p)
{
    WSGIScriptFile *object = NULL;

    object = (WSGIScriptFile *)apr_pcalloc(p, sizeof(WSGIScriptFile));

    object->handler_script = NULL;
    object->application_group = NULL;
    object->process_group = NULL;

    return object;
}

static WSGIServerConfig *newWSGIServerConfig(apr_pool_t *p)
{
    WSGIServerConfig *object = NULL;

    object = (WSGIServerConfig *)apr_pcalloc(p, sizeof(WSGIServerConfig));

    object->pool = p;

    object->alias_list = NULL;

    object->socket_prefix = NULL;

#if defined(MOD_WSGI_WITH_DAEMONS)
    object->socket_prefix = DEFAULT_REL_RUNTIMEDIR "/wsgi";
    object->socket_prefix = ap_server_root_relative(p, object->socket_prefix);
#endif

    object->verbose_debugging = 0;

    object->python_warnings = NULL;

    object->py3k_warning_flag = -1;
    object->python_optimize = -1;

    object->python_home = NULL;
    object->python_path = NULL;
    object->python_eggs = NULL;

    object->restrict_embedded = -1;
    object->restrict_stdin = -1;
    object->restrict_stdout = -1;
    object->restrict_signal = -1;

#if defined(WIN32) || defined(DARWIN)
    object->case_sensitivity = 0;
#else
    object->case_sensitivity = 1;
#endif

    object->restrict_process = NULL;

    object->process_group = NULL;
    object->application_group = NULL;
    object->callable_object = NULL;

    object->dispatch_script = NULL;

    object->pass_apache_request = -1;
    object->pass_authorization = -1;
    object->script_reloading = -1;
    object->error_override = -1;
    object->chunked_request = -1;

    return object;
}

static void *wsgi_create_server_config(apr_pool_t *p, server_rec *s)
{
    WSGIServerConfig *config = NULL;

    config = newWSGIServerConfig(p);

    return config;
}

static void *wsgi_merge_server_config(apr_pool_t *p, void *base_conf,
                                      void *new_conf)
{
    WSGIServerConfig *config = NULL;
    WSGIServerConfig *parent = NULL;
    WSGIServerConfig *child = NULL;

    config = newWSGIServerConfig(p);

    parent = (WSGIServerConfig *)base_conf;
    child = (WSGIServerConfig *)new_conf;

    if (child->alias_list && parent->alias_list) {
        config->alias_list = apr_array_append(p, child->alias_list,
                                              parent->alias_list);
    }
    else if (child->alias_list) {
        config->alias_list = apr_array_make(p, 20, sizeof(WSGIAliasEntry));
        apr_array_cat(config->alias_list, child->alias_list);
    }
    else if (parent->alias_list) {
        config->alias_list = apr_array_make(p, 20, sizeof(WSGIAliasEntry));
        apr_array_cat(config->alias_list, parent->alias_list);
    }

    if (child->restrict_process)
        config->restrict_process = child->restrict_process;
    else
        config->restrict_process = parent->restrict_process;

    if (child->process_group)
        config->process_group = child->process_group;
    else
        config->process_group = parent->process_group;

    if (child->application_group)
        config->application_group = child->application_group;
    else
        config->application_group = parent->application_group;

    if (child->callable_object)
        config->callable_object = child->callable_object;
    else
        config->callable_object = parent->callable_object;

    if (child->dispatch_script)
        config->dispatch_script = child->dispatch_script;
    else
        config->dispatch_script = parent->dispatch_script;

    if (child->pass_apache_request != -1)
        config->pass_apache_request = child->pass_apache_request;
    else
        config->pass_apache_request = parent->pass_apache_request;

    if (child->pass_authorization != -1)
        config->pass_authorization = child->pass_authorization;
    else
        config->pass_authorization = parent->pass_authorization;

    if (child->script_reloading != -1)
        config->script_reloading = child->script_reloading;
    else
        config->script_reloading = parent->script_reloading;

    if (child->error_override != -1)
        config->error_override = child->error_override;
    else
        config->error_override = parent->error_override;

    if (child->chunked_request != -1)
        config->chunked_request = child->chunked_request;
    else
        config->chunked_request = parent->chunked_request;

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    if (!child->handler_scripts)
        config->handler_scripts = parent->handler_scripts;
    else if (!parent->handler_scripts)
        config->handler_scripts = child->handler_scripts;
    else {
        config->handler_scripts = apr_hash_overlay(p, child->handler_scripts,
                                                   parent->handler_scripts);
    }
#endif

    return config;
}

typedef struct {
    apr_pool_t *pool;

    apr_table_t *restrict_process;

    const char *process_group;
    const char *application_group;
    const char *callable_object;

    WSGIScriptFile *dispatch_script;

    int pass_apache_request;
    int pass_authorization;
    int script_reloading;
    int error_override;
    int chunked_request;

    WSGIScriptFile *access_script;
    WSGIScriptFile *auth_user_script;
    WSGIScriptFile *auth_group_script;
    int user_authoritative;
    int group_authoritative;

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    apr_hash_t *handler_scripts;
#endif
} WSGIDirectoryConfig;

static WSGIDirectoryConfig *newWSGIDirectoryConfig(apr_pool_t *p)
{
    WSGIDirectoryConfig *object = NULL;

    object = (WSGIDirectoryConfig *)apr_pcalloc(p, sizeof(WSGIDirectoryConfig));

    object->pool = p;

    object->process_group = NULL;
    object->application_group = NULL;
    object->callable_object = NULL;

    object->dispatch_script = NULL;

    object->pass_apache_request = -1;
    object->pass_authorization = -1;
    object->script_reloading = -1;
    object->error_override = -1;
    object->chunked_request = -1;

    object->access_script = NULL;
    object->auth_user_script = NULL;
    object->auth_group_script = NULL;
    object->user_authoritative = -1;
    object->group_authoritative = -1;

    return object;
}

static void *wsgi_create_dir_config(apr_pool_t *p, char *dir)
{
    WSGIDirectoryConfig *config = NULL;

    config = newWSGIDirectoryConfig(p);

    return config;
}

static void *wsgi_merge_dir_config(apr_pool_t *p, void *base_conf,
                                   void *new_conf)
{
    WSGIDirectoryConfig *config = NULL;
    WSGIDirectoryConfig *parent = NULL;
    WSGIDirectoryConfig *child = NULL;

    config = newWSGIDirectoryConfig(p);

    parent = (WSGIDirectoryConfig *)base_conf;
    child = (WSGIDirectoryConfig *)new_conf;

    if (child->restrict_process)
        config->restrict_process = child->restrict_process;
    else
        config->restrict_process = parent->restrict_process;

    if (child->process_group)
        config->process_group = child->process_group;
    else
        config->process_group = parent->process_group;

    if (child->application_group)
        config->application_group = child->application_group;
    else
        config->application_group = parent->application_group;

    if (child->callable_object)
        config->callable_object = child->callable_object;
    else
        config->callable_object = parent->callable_object;

    if (child->dispatch_script)
        config->dispatch_script = child->dispatch_script;
    else
        config->dispatch_script = parent->dispatch_script;

    if (child->pass_apache_request != -1)
        config->pass_apache_request = child->pass_apache_request;
    else
        config->pass_apache_request = parent->pass_apache_request;

    if (child->pass_authorization != -1)
        config->pass_authorization = child->pass_authorization;
    else
        config->pass_authorization = parent->pass_authorization;

    if (child->script_reloading != -1)
        config->script_reloading = child->script_reloading;
    else
        config->script_reloading = parent->script_reloading;

    if (child->error_override != -1)
        config->error_override = child->error_override;
    else
        config->error_override = parent->error_override;

    if (child->chunked_request != -1)
        config->chunked_request = child->chunked_request;
    else
        config->chunked_request = parent->chunked_request;

    if (child->access_script)
        config->access_script = child->access_script;
    else
        config->access_script = parent->access_script;

    if (child->auth_user_script)
        config->auth_user_script = child->auth_user_script;
    else
        config->auth_user_script = parent->auth_user_script;

    if (child->auth_group_script)
        config->auth_group_script = child->auth_group_script;
    else
        config->auth_group_script = parent->auth_group_script;

    if (child->user_authoritative != -1)
        config->user_authoritative = child->user_authoritative;
    else
        config->user_authoritative = parent->user_authoritative;

    if (child->group_authoritative != -1)
        config->group_authoritative = child->group_authoritative;
    else
        config->group_authoritative = parent->group_authoritative;

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    if (!child->handler_scripts)
        config->handler_scripts = parent->handler_scripts;
    else if (!parent->handler_scripts)
        config->handler_scripts = child->handler_scripts;
    else {
        config->handler_scripts = apr_hash_overlay(p, child->handler_scripts,
                                                   parent->handler_scripts);
    }
#endif

    return config;
}

typedef struct {
    apr_pool_t *pool;

    apr_table_t *restrict_process;

    const char *process_group;
    const char *application_group;
    const char *callable_object;

    WSGIScriptFile *dispatch_script;

    int pass_apache_request;
    int pass_authorization;
    int script_reloading;
    int error_override;
    int chunked_request;

    WSGIScriptFile *access_script;
    WSGIScriptFile *auth_user_script;
    WSGIScriptFile *auth_group_script;
    int user_authoritative;
    int group_authoritative;

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    apr_hash_t *handler_scripts;
#endif
    const char *handler_script;
} WSGIRequestConfig;

static int wsgi_find_path_info(const char *uri, const char *path_info)
{
    int lu = strlen(uri);
    int lp = strlen(path_info);

    while (lu-- && lp-- && uri[lu] == path_info[lp]) {
        if (path_info[lp] == '/') {
            while (lu && uri[lu-1] == '/') lu--;
        }
    }

    if (lu == -1) {
        lu = 0;
    }

    while (uri[lu] != '\0' && uri[lu] != '/') {
        lu++;
    }
    return lu;
}

static const char *wsgi_script_name(request_rec *r)
{
    char *script_name = NULL;
    int path_info_start = 0;

    if (!r->path_info || !*r->path_info) {
        script_name = apr_pstrdup(r->pool, r->uri);
    }
    else {
        path_info_start = wsgi_find_path_info(r->uri, r->path_info);

        script_name = apr_pstrndup(r->pool, r->uri, path_info_start);
    }

    if (*script_name) {
        while (*script_name && (*(script_name+1) == '/'))
            script_name++;
        script_name = apr_pstrdup(r->pool, script_name);
        ap_no2slash((char*)script_name);
    }

    ap_str_tolower(script_name);

    return script_name;
}

static const char *wsgi_process_group(request_rec *r, const char *s)
{
    const char *name = NULL;
    const char *value = NULL;

    if (!s)
        return "";

    if (*s != '%')
        return s;

    name = s + 1;

    if (*name) {
        if (!strcmp(name, "{GLOBAL}"))
            return "";

        if (strstr(name, "{ENV:") == name) {
            int len = 0;

            name = name + 5;
            len = strlen(name);

            if (len && name[len-1] == '}') {
                name = apr_pstrndup(r->pool, name, len-1);

                value = apr_table_get(r->notes, name);

                if (!value)
                    value = apr_table_get(r->subprocess_env, name);

                if (!value)
                    value = getenv(name);

                if (value) {
                    if (*value == '%' && strstr(value, "%{ENV:") != value)
                        return wsgi_process_group(r, value);

                    return value;
                }
            }
        }
    }

    return s;
}

static const char *wsgi_server_group(request_rec *r, const char *s)
{
    const char *name = NULL;
    const char *value = NULL;

    const char *h = NULL;
    apr_port_t p = 0;

    if (!s)
        return "";

    if (*s != '%')
        return s;

    name = s + 1;

    if (*name) {
        if (!strcmp(name, "{SERVER}")) {
            h = r->server->server_hostname;
            p = ap_get_server_port(r);

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u", h, p);
            else
                return h;
        }

        if (!strcmp(name, "{GLOBAL}"))
            return "";
    }

    return s;
}

static const char *wsgi_application_group(request_rec *r, const char *s)
{
    const char *name = NULL;
    const char *value = NULL;

    const char *h = NULL;
    apr_port_t p = 0;
    const char *n = NULL;

    if (!s) {
        h = r->server->server_hostname;
        p = ap_get_server_port(r);
        n = wsgi_script_name(r);

        if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
            return apr_psprintf(r->pool, "%s:%u|%s", h, p, n);
        else
            return apr_psprintf(r->pool, "%s|%s", h, n);
    }

    if (*s != '%')
        return s;

    name = s + 1;

    if (*name) {
        if (!strcmp(name, "{RESOURCE}")) {
            h = r->server->server_hostname;
            p = ap_get_server_port(r);
            n = wsgi_script_name(r);

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u|%s", h, p, n);
            else
                return apr_psprintf(r->pool, "%s|%s", h, n);
        }

        if (!strcmp(name, "{SERVER}")) {
            h = r->server->server_hostname;
            p = ap_get_server_port(r);

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u", h, p);
            else
                return h;
        }

        if (!strcmp(name, "{GLOBAL}"))
            return "";

        if (strstr(name, "{ENV:") == name) {
            int len = 0;

            name = name + 5;
            len = strlen(name);

            if (len && name[len-1] == '}') {
                name = apr_pstrndup(r->pool, name, len-1);

                value = apr_table_get(r->notes, name);

                if (!value)
                    value = apr_table_get(r->subprocess_env, name);

                if (!value)
                    value = getenv(name);

                if (value) {
                    if (*value == '%' && strstr(value, "%{ENV:") != value)
                        return wsgi_application_group(r, value);

                    return value;
                }
            }
        }
    }

    return s;
}

static const char *wsgi_callable_object(request_rec *r, const char *s)
{
    const char *name = NULL;
    const char *value = NULL;

    if (!s)
        return "application";

    if (*s != '%')
        return s;

    name = s + 1;

    if (!*name)
        return "application";

    if (strstr(name, "{ENV:") == name) {
        int len = 0;

        name = name + 5;
        len = strlen(name);

        if (len && name[len-1] == '}') {
            name = apr_pstrndup(r->pool, name, len-1);

            value = apr_table_get(r->notes, name);

            if (!value)
                value = apr_table_get(r->subprocess_env, name);

            if (!value)
                value = getenv(name);

            if (value)
                return value;
        }
    }

    return "application";
}

static WSGIRequestConfig *wsgi_create_req_config(apr_pool_t *p, request_rec *r)
{
    WSGIRequestConfig *config = NULL;
    WSGIServerConfig *sconfig = NULL;
    WSGIDirectoryConfig *dconfig = NULL;

    config = (WSGIRequestConfig *)apr_pcalloc(p, sizeof(WSGIRequestConfig));

    dconfig = ap_get_module_config(r->per_dir_config, &wsgi_module);
    sconfig = ap_get_module_config(r->server->module_config, &wsgi_module);

    config->pool = p;

    config->restrict_process = dconfig->restrict_process;

    if (!config->restrict_process)
        config->restrict_process = sconfig->restrict_process;

    config->process_group = dconfig->process_group;

    if (!config->process_group)
        config->process_group = sconfig->process_group;

    config->process_group = wsgi_process_group(r, config->process_group);

    config->application_group = dconfig->application_group;

    if (!config->application_group)
        config->application_group = sconfig->application_group;

    config->application_group = wsgi_application_group(r,
                                    config->application_group);

    config->callable_object = dconfig->callable_object;

    if (!config->callable_object)
        config->callable_object = sconfig->callable_object;

    config->callable_object = wsgi_callable_object(r, config->callable_object);

    config->dispatch_script = dconfig->dispatch_script;

    if (!config->dispatch_script)
        config->dispatch_script = sconfig->dispatch_script;

    config->pass_apache_request = dconfig->pass_apache_request;

    if (config->pass_apache_request < 0) {
        config->pass_apache_request = sconfig->pass_apache_request;
        if (config->pass_apache_request < 0)
            config->pass_apache_request = 0;
    }

    config->pass_authorization = dconfig->pass_authorization;

    if (config->pass_authorization < 0) {
        config->pass_authorization = sconfig->pass_authorization;
        if (config->pass_authorization < 0)
            config->pass_authorization = 0;
    }

    config->script_reloading = dconfig->script_reloading;

    if (config->script_reloading < 0) {
        config->script_reloading = sconfig->script_reloading;
        if (config->script_reloading < 0)
            config->script_reloading = 1;
    }

    config->error_override = dconfig->error_override;

    if (config->error_override < 0) {
        config->error_override = sconfig->error_override;
        if (config->error_override < 0)
            config->error_override = 0;
    }

    config->chunked_request = dconfig->chunked_request;

    if (config->chunked_request < 0) {
        config->chunked_request = sconfig->chunked_request;
        if (config->chunked_request < 0)
            config->chunked_request = 0;
    }

    config->access_script = dconfig->access_script;

    config->auth_user_script = dconfig->auth_user_script;

    config->auth_group_script = dconfig->auth_group_script;

    config->user_authoritative = dconfig->user_authoritative;

    if (config->user_authoritative == -1)
        config->user_authoritative = 1;

    config->group_authoritative = dconfig->group_authoritative;

    if (config->group_authoritative == -1)
        config->group_authoritative = 1;

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    if (!dconfig->handler_scripts)
        config->handler_scripts = sconfig->handler_scripts;
    else if (!sconfig->handler_scripts)
        config->handler_scripts = dconfig->handler_scripts;
    else {
        config->handler_scripts = apr_hash_overlay(p, dconfig->handler_scripts,
                                                   sconfig->handler_scripts);
    }
#endif

    config->handler_script = "";

    return config;
}

/*
 * Apache 2.X and UNIX specific definitions related to
 * distinct daemon processes.
 */

#if defined(MOD_WSGI_WITH_DAEMONS)

#include "unixd.h"
#include "scoreboard.h"
#include "mpm_common.h"
#include "apr_proc_mutex.h"
#include "apr_thread_cond.h"
#include "apr_atomic.h"
#include "http_connection.h"
#include "apr_buckets.h"
#include "apr_poll.h"
#include "apr_signal.h"
#include "http_vhost.h"

#if APR_MAJOR_VERSION < 1
#define apr_atomic_cas32 apr_atomic_cas
#endif

#if APR_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SEM_H
#include <sys/sem.h>
#endif

#include <sys/un.h>

#ifndef WSGI_LISTEN_BACKLOG
#define WSGI_LISTEN_BACKLOG 100
#endif

#ifndef WSGI_CONNECT_ATTEMPTS
#define WSGI_CONNECT_ATTEMPTS 15
#endif

#define WSGI_STACK_HEAD  0xffff
#define WSGI_STACK_LAST  0xffff
#define WSGI_STACK_TERMINATED 0x10000
#define WSGI_STACK_NO_LISTENER 0x20000

typedef struct {
    server_rec *server;
    long random;
    int id;
    const char *name;
    const char *user;
    uid_t uid;
    const char *group;
    gid_t gid;
    int processes;
    int multiprocess;
    int threads;
    int umask;
    const char *root;
    const char *home;
    const char *python_path;
    const char *python_eggs;
    int stack_size;
    int maximum_requests;
    int shutdown_timeout;
    apr_time_t deadlock_timeout;
    apr_time_t inactivity_timeout;
    const char *display_name;
    int send_buffer_size;
    int recv_buffer_size;
    const char *script_user;
    const char *script_group;
    int cpu_time_limit;
    int cpu_priority;
    const char *socket;
    int listener_fd;
    const char* mutex_path;
    apr_proc_mutex_t* mutex;
} WSGIProcessGroup;

typedef struct {
    WSGIProcessGroup *group;
    int instance;
    apr_proc_t process;
    apr_socket_t *listener;
} WSGIDaemonProcess;

typedef struct {
    int id;
    WSGIDaemonProcess *process;
    apr_thread_t *thread;
    int running;
    int next;
    int wakeup;
    apr_thread_cond_t *condition;
    apr_thread_mutex_t *mutex;
} WSGIDaemonThread;

typedef struct {
    apr_uint32_t state;
} WSGIThreadStack;

typedef struct {
    const char *name;
    const char *socket;
    int fd;
} WSGIDaemonSocket;

static int wsgi_daemon_count = 0;
static apr_hash_t *wsgi_daemon_index = NULL;
static apr_hash_t *wsgi_daemon_listeners = NULL;

static WSGIDaemonProcess *wsgi_daemon_process = NULL;

static int volatile wsgi_request_count = 0;

static WSGIDaemonThread *wsgi_worker_threads = NULL;

static WSGIThreadStack *wsgi_worker_stack = NULL;

#endif

/* Class objects used by response handler. */

static PyTypeObject Dispatch_Type;

typedef struct {
        PyObject_HEAD
        const char *target;
        request_rec *r;
        int level;
        char *s;
        int l;
        int expired;
#if PY_MAJOR_VERSION < 3
        int softspace;
#endif
} LogObject;

static PyTypeObject Log_Type;

static PyObject *newLogObject(request_rec *r, int level, const char *target)
{
    LogObject *self;

#if PY_MAJOR_VERSION >= 3
    PyObject *module = NULL;
    PyObject *dict = NULL;
    PyObject *object = NULL;
    PyObject *args = NULL;
    PyObject *result = NULL;

    module = PyImport_ImportModule("io");

    if (!module)
        return NULL;

    dict = PyModule_GetDict(module);
    object = PyDict_GetItemString(dict, "TextIOWrapper");

    if (!object) {
        PyErr_SetString(PyExc_NameError,
                        "name 'TextIOWrapper' is not defined");
        return NULL;
    }
#endif

    self = PyObject_New(LogObject, &Log_Type);
    if (self == NULL)
        return NULL;

    self->target = target;
    self->r = r;
    self->level = APLOG_NOERRNO|level;
    self->s = NULL;
    self->l = 0;
    self->expired = 0;
#if PY_MAJOR_VERSION < 3
    self->softspace = 0;
#endif

#if PY_MAJOR_VERSION >= 3
    Py_INCREF(object);
    args = Py_BuildValue("(OssOO)", self, "utf-8", "replace",
                         Py_None, Py_True);
    Py_DECREF(self);
    result = PyEval_CallObject(object, args);
    Py_DECREF(args);
    Py_DECREF(object);

    return result;
#else
    return (PyObject *)self;
#endif
}

#if 0
static void Log_file(LogObject *self, const char *s, int l)
{
    /*
     * XXX This function is not currently being used.
     * The intention was that it be called instead of
     * Log_call() when 'target' is non zero. This would
     * be the case for 'stdout' and 'stderr'. Doing
     * this bypasses normally Apache logging mechanisms
     * though. May reawaken this code in mod_wsgi 4.0
     * by way of a mechanism to divert logging from a
     * daemon process to specfic log file or pipe using
     * an option to WSGIDaemonProcess.
     */

    char errstr[MAX_STRING_LEN];

    int plen = 0;
    int slen = 0;

#if AP_SERVER_MAJORVERSION_NUMBER < 2
    FILE *logf;
#else
    apr_file_t *logf = NULL;
#endif

    if (self->r)
        logf = self->r->server->error_log;
    else
        logf = wsgi_server->error_log;

#if AP_SERVER_MAJORVERSION_NUMBER < 2
    plen = ap_snprintf(errstr, sizeof(errstr), "[%s] ", ap_get_time());
#else
    errstr[0] = '[';
    ap_recent_ctime(errstr + 1, apr_time_now());
    errstr[1 + APR_CTIME_LEN - 1] = ']';
    errstr[1 + APR_CTIME_LEN    ] = ' ';
    plen = 1 + APR_CTIME_LEN + 1;
#endif

    if (self->target) {
        int len;

        errstr[plen++] = '[';

        len = strlen(self->target);
        memcpy(errstr+plen, self->target, len);

        plen += len;

        errstr[plen++] = ']';
        errstr[plen++] = ' ';
    }

    slen = MAX_STRING_LEN - plen - 1;

    Py_BEGIN_ALLOW_THREADS

    /*
     * We actually break long lines up into segments
     * of around 8192 characters, with the date/time
     * and target information prefixing each line.
     * This is just to avoid having to allocate more
     * memory just to format the line with prefix.
     * We want to avoid writing the prefix separately
     * so at least try and write line in one atomic
     * operation.
     */

    while (1) {
        if (l > slen) {
            memcpy(errstr+plen, s, slen);
            errstr[plen+slen] = '\n';
#if AP_SERVER_MAJORVERSION_NUMBER < 2
            fwrite(errstr, plen+slen+1, 1, logf);
            fflush(logf);
#else
            apr_file_write_full(logf, errstr, plen+slen+1, NULL);
            apr_file_flush(logf);
#endif
            s += slen;
            l -= slen;
        }
        else {
            memcpy(errstr+plen, s, l);
            errstr[plen+l] = '\n';
#if AP_SERVER_MAJORVERSION_NUMBER < 2
            fwrite(errstr, plen+l+1, 1, logf);
            fflush(logf);
#else
            apr_file_write_full(logf, errstr, plen+l+1, NULL);
            apr_file_flush(logf);
#endif
            break;
        }
    }

    Py_END_ALLOW_THREADS
}
#endif

static void Log_call(LogObject *self, const char *s, int l)
{
    /*
     * The length of the string to be logged is ignored
     * for now. We just pass the whole string to the
     * Apache error log functions. It will actually
     * truncate it at some value less than 8192
     * characters depending on the length of the prefix
     * to go at the front. If there are embedded NULLs
     * then truncation will occur at that point. That
     * truncation occurs like this is also what happens
     * if using FASTCGI solutions for Apache, so not
     * doing anything different here.
     */

    if (self->r) {
        Py_BEGIN_ALLOW_THREADS
        ap_log_rerror(APLOG_MARK, WSGI_LOG_LEVEL(self->level),
                      self->r, "%s", s);
        Py_END_ALLOW_THREADS
    }
    else {
        Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, WSGI_LOG_LEVEL(self->level),
                     wsgi_server, "%s", s);
        Py_END_ALLOW_THREADS
    }
}

static void Log_dealloc(LogObject *self)
{
    if (self->s) {
        if (!self->expired)
            Log_call(self, self->s, self->l);

        free(self->s);
    }

    PyObject_Del(self);
}

static PyObject *Log_flush(LogObject *self, PyObject *args)
{
    if (self->expired) {
        PyErr_SetString(PyExc_RuntimeError, "log object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, ":flush"))
        return NULL;

    if (self->s) {
        Log_call(self, self->s, self->l);

        free(self->s);
        self->s = NULL;
        self->l = 0;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *Log_close(LogObject *self, PyObject *args)
{
    PyObject *result = NULL;

    if (!PyArg_ParseTuple(args, ":close"))
        return NULL;

    if (!self->expired)
        result = Log_flush(self, args);

    Py_XDECREF(result);

    self->r = NULL;
    self->expired = 1;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *Log_isatty(LogObject *self, PyObject *args)
{
    PyObject *result = NULL;

    if (!PyArg_ParseTuple(args, ":isatty"))
        return NULL;

    Py_INCREF(Py_False);
    return Py_False;
}

static void Log_queue(LogObject *self, const char *msg, int len)
{
    const char *p = NULL;
    const char *q = NULL;
    const char *e = NULL;

    p = msg;
    e = p + len;

    /*
     * Break string on newline. This is on assumption
     * that primarily textual information being logged.
     */

    q = p;
    while (q != e) {
        if (*q == '\n')
            break;
        q++;
    }

    while (q != e) {
        /* Output each complete line. */

        if (self->s) {
            /* Need to join with buffered value. */

            int m = 0;
            int n = 0;
            char *s = NULL;

            m = self->l;
            n = m+q-p+1;

            s = (char *)malloc(n);
            memcpy(s, self->s, m);
            memcpy(s+m, p, q-p);
            s[n-1] = '\0';

            free(self->s);
            self->s = NULL;
            self->l = 0;

            Log_call(self, s, n-1);

            free(s);
        }
        else {
            int n = 0;
            char *s = NULL;

            n = q-p+1;

            s = (char *)malloc(n);
            memcpy(s, p, q-p);
            s[n-1] = '\0';

            Log_call(self, s, n-1);

            free(s);
        }

        p = q+1;

        /* Break string on newline. */

        q = p;
        while (q != e) {
            if (*q == '\n')
                break;
            q++;
        }
    }

    if (p != e) {
        /* Save away incomplete line. */

        if (self->s) {
            /* Need to join with buffered value. */

            int m = 0;
            int n = 0;

            m = self->l;
            n = m+e-p+1;

            self->s = (char *)realloc(self->s, n);
            memcpy(self->s+m, p, e-p);
            self->s[n-1] = '\0';
            self->l = n-1;
        }
        else {
            int n = 0;

            n = e-p+1;

            self->s = (char *)malloc(n);
            memcpy(self->s, p, n-1);
            self->s[n-1] = '\0';
            self->l = n-1;
        }
    }
}

static PyObject *Log_write(LogObject *self, PyObject *args)
{
    const char *msg = NULL;
    int len = -1;

    if (self->expired) {
        PyErr_SetString(PyExc_RuntimeError, "log object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "s#:write", &msg, &len))
        return NULL;

    Log_queue(self, msg, len);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *Log_writelines(LogObject *self, PyObject *args)
{
    PyObject *sequence = NULL;
    PyObject *iterator = NULL;
    PyObject *item = NULL;
    const char *msg = NULL;

    if (self->expired) {
        PyErr_SetString(PyExc_RuntimeError, "log object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:writelines", &sequence))
        return NULL;

    iterator = PyObject_GetIter(sequence);

    if (iterator == NULL) {
        PyErr_SetString(PyExc_TypeError,
                        "argument must be sequence of strings");

        return NULL;
    }

    while ((item = PyIter_Next(iterator))) {
        PyObject *result = NULL;

        result = Log_write(self, item);

        if (!result) {
            Py_DECREF(iterator);

            PyErr_SetString(PyExc_TypeError,
                            "argument must be sequence of strings");

            return NULL;
        }
    }

    Py_DECREF(iterator);

    Py_INCREF(Py_None);
    return Py_None;
}

#if PY_MAJOR_VERSION >= 3
static PyObject *Log_readable(LogObject *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":readable"))
        return NULL;

    Py_INCREF(Py_False);
    return Py_False;
}

static PyObject *Log_seekable(LogObject *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":seekable"))
        return NULL;

    Py_INCREF(Py_False);
    return Py_False;
}

static PyObject *Log_writable(LogObject *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":writable"))
        return NULL;

    Py_INCREF(Py_True);
    return Py_True;
}
#endif

static PyObject *Log_closed(LogObject *self, void *closure)
{
    Py_INCREF(Py_False);
    return Py_False;
}

#if PY_MAJOR_VERSION < 3
static PyObject *Log_get_softspace(LogObject *self, void *closure)
{
    return PyInt_FromLong(self->softspace);
}

static int Log_set_softspace(LogObject *self, PyObject *value)
{
    int new;

    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "can't delete softspace attribute");
        return -1;
    }

    new = PyInt_AsLong(value);
    if (new == -1 && PyErr_Occurred())
        return -1;

    self->softspace = new;

    return 0;
}

#else

static PyObject *Log_get_encoding(LogObject *self, void *closure)
{
    return PyUnicode_FromString("utf-8");
}

static PyObject *Log_get_errors(LogObject *self, void *closure)
{
    return PyUnicode_FromString("replace");
}
#endif

static PyMethodDef Log_methods[] = {
    { "flush",      (PyCFunction)Log_flush,      METH_VARARGS, 0 },
    { "close",      (PyCFunction)Log_close,      METH_VARARGS, 0 },
    { "isatty",     (PyCFunction)Log_isatty,     METH_VARARGS, 0 },
    { "write",      (PyCFunction)Log_write,      METH_VARARGS, 0 },
    { "writelines", (PyCFunction)Log_writelines, METH_VARARGS, 0 },
#if PY_MAJOR_VERSION >= 3
    { "readable",   (PyCFunction)Log_readable,   METH_VARARGS, 0 },
    { "seekable",   (PyCFunction)Log_seekable,   METH_VARARGS, 0 },
    { "writable",   (PyCFunction)Log_writable,   METH_VARARGS, 0 },
#endif
    { NULL, NULL}
};

static PyGetSetDef Log_getset[] = {
    { "closed", (getter)Log_closed, NULL, 0 },
#if PY_MAJOR_VERSION < 3
    { "softspace", (getter)Log_get_softspace, (setter)Log_set_softspace, 0 },
#else
    { "encoding", (getter)Log_get_encoding, NULL, 0 },
    { "errors", (getter)Log_get_errors, NULL, 0 },
#endif
    { NULL },
};

static PyTypeObject Log_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "mod_wsgi.Log",         /*tp_name*/
    sizeof(LogObject),      /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Log_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    Log_methods,            /*tp_methods*/
    0,                      /*tp_members*/
    Log_getset,             /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

static void wsgi_log_python_error(request_rec *r, PyObject *log,
                                  const char *filename)
{
    PyObject *m = NULL;
    PyObject *result = NULL;

    PyObject *type = NULL;
    PyObject *value = NULL;
    PyObject *traceback = NULL;

    PyObject *xlog = NULL;

    if (!PyErr_Occurred())
        return;

    if (!log) {
        PyErr_Fetch(&type, &value, &traceback);

        xlog = newLogObject(r, APLOG_ERR, NULL);

        log = xlog;

        PyErr_Restore(type, value, traceback);

        type = NULL;
        value = NULL;
        traceback = NULL;
    }

    if (PyErr_ExceptionMatches(PyExc_SystemExit)) {
        Py_BEGIN_ALLOW_THREADS
        if (r) {
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                          "mod_wsgi (pid=%d): SystemExit exception raised by "
                          "WSGI script '%s' ignored.", getpid(), filename);
        }
        else {
            ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                          "mod_wsgi (pid=%d): SystemExit exception raised by "
                          "WSGI script '%s' ignored.", getpid(), filename);
        }
        Py_END_ALLOW_THREADS
    }
    else {
        Py_BEGIN_ALLOW_THREADS
        if (r) {
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                          "mod_wsgi (pid=%d): Exception occurred processing "
                          "WSGI script '%s'.", getpid(), filename);
        }
        else {
            ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                          "mod_wsgi (pid=%d): Exception occurred processing "
                          "WSGI script '%s'.", getpid(), filename);
        }
        Py_END_ALLOW_THREADS
    }

    PyErr_Fetch(&type, &value, &traceback);
    PyErr_NormalizeException(&type, &value, &traceback);

    if (!value) {
        value = Py_None;
        Py_INCREF(value);
    }

    if (!traceback) {
        traceback = Py_None;
        Py_INCREF(traceback);
    }

    m = PyImport_ImportModule("traceback");

    if (m) {
        PyObject *d = NULL;
        PyObject *o = NULL;
        d = PyModule_GetDict(m);
        o = PyDict_GetItemString(d, "print_exception");
        if (o) {
            PyObject *args = NULL;
            Py_INCREF(o);
            args = Py_BuildValue("(OOOOO)", type, value, traceback,
                                 Py_None, log);
            result = PyEval_CallObject(o, args);
            Py_DECREF(args);
            Py_DECREF(o);
        }
    }

    if (!result) {
        /*
         * If can't output exception and traceback then
         * use PyErr_Print to dump out details of the
         * exception. For SystemExit though if we do
         * that the process will actually be terminated
         * so can only clear the exception information
         * and keep going.
         */

        PyErr_Restore(type, value, traceback);

        if (!PyErr_ExceptionMatches(PyExc_SystemExit)) {
            PyErr_Print();
            PyErr_Clear();
        }
        else {
            PyErr_Clear();
        }
    }
    else {
        Py_XDECREF(type);
        Py_XDECREF(value);
        Py_XDECREF(traceback);
    }

    Py_XDECREF(result);

    Py_XDECREF(m);

    Py_XDECREF(xlog);
}

typedef struct {
        PyObject_HEAD
        request_rec *r;
        int init;
        int done;
        char *buffer;
        apr_size_t size;
        apr_size_t offset;
        apr_size_t length;
} InputObject;

static PyTypeObject Input_Type;

static InputObject *newInputObject(request_rec *r)
{
    InputObject *self;

    self = PyObject_New(InputObject, &Input_Type);
    if (self == NULL)
        return NULL;

    self->r = r;
    self->init = 0;
    self->done = 0;

    self->buffer = NULL;
    self->size = 0;
    self->offset = 0;
    self->length = 0;

    return self;
}

static void Input_dealloc(InputObject *self)
{
    if (self->buffer)
        free(self->buffer);

    PyObject_Del(self);
}

static PyObject *Input_close(InputObject *self, PyObject *args)
{
    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, ":close"))
        return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *Input_read(InputObject *self, PyObject *args)
{
    long size = -1;

    PyObject *result = NULL;
    char *buffer = NULL;
    apr_size_t length = 0;
    int init = 0;

    apr_size_t n;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "|l:read", &size))
        return NULL;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_inactivity_timeout) {
        apr_thread_mutex_lock(wsgi_shutdown_lock);
        wsgi_inactivity_shutdown_time = apr_time_now();
        wsgi_inactivity_shutdown_time += wsgi_inactivity_timeout;
        apr_thread_mutex_unlock(wsgi_shutdown_lock);
    }
#endif

    init = self->init;

    if (!self->init) {
        if (!ap_should_client_block(self->r))
            self->done = 1;

        self->init = 1;
    }

    /* No point continuing if no more data to be consumed. */

    if (self->done && self->length == 0)
        return PyString_FromString("");

    /*
     * If requested size is zero bytes, then still need to pass
     * this through to Apache input filters so that any
     * 100-continue response is triggered. Only do this if very
     * first attempt to read data. Note that this will cause an
     * assertion failure in HTTP_IN input filter when Apache
     * maintainer mode is enabled. It is arguable that the
     * assertion check, which prohibits a zero length read,
     * shouldn't exist, as why should a zero length read be not
     * allowed if input filter processing still works when it
     * does occur.
     */

    if (size == 0) {
        if (!init) {
            char dummy[1];

            Py_BEGIN_ALLOW_THREADS
            n = ap_get_client_block(self->r, dummy, 0);
            Py_END_ALLOW_THREADS

            if (n == -1) {
                PyErr_SetString(PyExc_IOError, "request data read error");
                return NULL;
            }
        }

        return PyString_FromString("");
    }

    /*
     * First deal with case where size has been specified. After
     * that deal with case where expected that all remaining
     * data is to be read in and returned as one string.
     */

    if (size > 0) {
        /* Allocate string of the exact size required. */

        result = PyString_FromStringAndSize(NULL, size);

        if (!result)
            return NULL;

        buffer = PyString_AS_STRING((PyStringObject *)result);

        /* Copy any residual data from use of readline(). */

        if (self->buffer && self->length) {
            if (size >= self->length) {
                length = self->length;
                memcpy(buffer, self->buffer + self->offset, length);
                self->offset = 0;
                self->length = 0;
            }
            else {
                length = size;
                memcpy(buffer, self->buffer + self->offset, length);
                self->offset += length;
                self->length -= length;
            }
        }

        /* If all data residual buffer consumed then free it. */

        if (!self->length) {
            free(self->buffer);
            self->buffer = NULL;
        }

        /* Read in remaining data required to achieve size. */

        if (length < size) {
            while (length != size) {
                Py_BEGIN_ALLOW_THREADS
                n = ap_get_client_block(self->r, buffer + length,
                                        size - length);
                Py_END_ALLOW_THREADS

                if (n == -1) {
                    PyErr_SetString(PyExc_IOError, "request data read error");
                    Py_DECREF(result);
                    return NULL;
                }
                else if (n == 0) {
                    /* Have exhausted all the available input data. */

                    self->done = 1;
                    break;
                }

                length += n;
            }

            /*
             * Resize the final string. If the size reduction is
             * by more than 25% of the string size, then Python
             * will allocate a new block of memory and copy the
             * data into it.
             */

            if (length != size) {
                if (_PyString_Resize(&result, length))
                    return NULL;
            }
        }
    }
    else {
        /*
         * Here we are going to try and read in all the
         * remaining data. First we have to allocate a suitably
         * large string, but we can't fully trust the amount
         * that the request structure says is remaining based on
         * the original content length though, as an input
         * filter can insert/remove data from the input stream
         * thereby invalidating the original content length.
         * What we do is allow for an extra 25% above what we
         * have already buffered and what the request structure
         * says is remaining. A value of 25% has been chosen so
         * as to match best how Python handles resizing of
         * strings. Note that even though we do this and allow
         * all available content, strictly speaking the WSGI
         * specification says we should only read up until content
         * length. This though is because the WSGI specification
         * is deficient in dealing with the concept of mutating
         * input filters. Since read() with no argument is also
         * not allowed by WSGI specification implement it in the
         * way which is most logical and ensure that input data
         * is not truncated.
         */

        size = self->length;

        if (!self->r->read_chunked && self->r->remaining > 0)
            size += self->r->remaining;

        size = size + (size >> 2);

        if (size < 256)
            size = self->r->read_chunked ? 8192 : 256;

        /* Allocate string of the estimated size. */

        result = PyString_FromStringAndSize(NULL, size);

        if (!result)
            return NULL;

        buffer = PyString_AS_STRING((PyStringObject *)result);

        /*
         * Copy any residual data from use of readline(). The
         * residual should always be less in size than the
         * string we have allocated to hold it, so can consume
         * all of it.
         */

        if (self->buffer && self->length) {
            length = self->length;
            memcpy(buffer, self->buffer + self->offset, length);
            self->offset = 0;
            self->length = 0;

            free(self->buffer);
            self->buffer = NULL;
        }

        /* Now make first attempt at reading remaining data. */

        Py_BEGIN_ALLOW_THREADS
        n = ap_get_client_block(self->r, buffer + length, size - length);
        Py_END_ALLOW_THREADS

        if (n == -1) {
            PyErr_SetString(PyExc_IOError, "request data read error");
            Py_DECREF(result);
            return NULL;
        }
        else if (n == 0) {
            /* Have exhausted all the available input data. */

            self->done = 1;
        }

        length += n;

        /*
         * Don't just assume that all data has been read if
         * amount read was less than that requested. Still must
         * perform a read which returns that no more data found.
         */

        while (!self->done) {
            if (length == size) {
                /* Increase the size of the string by 25%. */

                size = size + (size >> 2);

                if (_PyString_Resize(&result, size))
                    return NULL;

                buffer = PyString_AS_STRING((PyStringObject *)result);
            }

            /* Now make succesive attempt at reading data. */

            Py_BEGIN_ALLOW_THREADS
            n = ap_get_client_block(self->r, buffer + length, size - length);
            Py_END_ALLOW_THREADS

            if (n == -1) {
                PyErr_SetString(PyExc_IOError, "request data read error");
                Py_DECREF(result);
                return NULL;
            }
            else if (n == 0) {
                /* Have exhausted all the available input data. */

                self->done = 1;
            }

            length += n;
        }

        /*
         * Resize the final string. If the size reduction is by
         * more than 25% of the string size, then Python will
         * allocate a new block of memory and copy the data into
         * it.
         */

        if (length != size) {
            if (_PyString_Resize(&result, length))
                return NULL;
        }
    }

    return result;
}

static PyObject *Input_readline(InputObject *self, PyObject *args)
{
    long size = -1;

    PyObject *result = NULL;
    char *buffer = NULL;
    apr_size_t length = 0;

    apr_size_t n;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "|l:readline", &size))
        return NULL;

    if (!self->init) {
        if (!ap_should_client_block(self->r))
            self->done = 1;

        self->init = 1;
    }

    /*
     * No point continuing if requested size is zero or if no
     * more data to read and no buffered data.
     */

    if ((self->done && self->length == 0) || size == 0)
        return PyString_FromString("");

    /*
     * First deal with case where size has been specified. After
     * that deal with case where expected that a complete line
     * is returned regardless of the size.
     */

    if (size > 0) {
        /* Allocate string of the exact size required. */

        result = PyString_FromStringAndSize(NULL, size);

        if (!result)
            return NULL;

        buffer = PyString_AS_STRING((PyStringObject *)result);

        /* Copy any residual data from use of readline(). */

        if (self->buffer && self->length) {
            char *p = NULL;
            const char *q = NULL;

            p = buffer;
            q = self->buffer + self->offset;

            while (self->length && length < size) {
                self->offset++;
                self->length--;
                length++;
                if ((*p++ = *q++) == '\n')
                    break;
            }

            /* If all data in residual buffer consumed then free it. */

            if (!self->length) {
                free(self->buffer);
                self->buffer = NULL;
            }
        }

        /*
         * Read in remaining data required to achieve size. Note
         * that can't just return whatever the first read might
         * have returned if no EOL encountered as must return
         * exactly the required size if no EOL unless that would
         * have exhausted all input.
         */

        while ((!length || buffer[length-1] != '\n') &&
               !self->done && length < size) {

            char *p = NULL;
            char *q = NULL;

            Py_BEGIN_ALLOW_THREADS
            n = ap_get_client_block(self->r, buffer + length, size - length);
            Py_END_ALLOW_THREADS

            if (n == -1) {
                PyErr_SetString(PyExc_IOError, "request data read error");
                Py_DECREF(result);
                return NULL;
            }
            else if (n == 0) {
                /* Have exhausted all the available input data. */

                self->done = 1;
            }
            else {
                /*
                 * Search for embedded EOL in what was read and if
                 * found copy any residual into a buffer for use
                 * next time the read functions are called.
                 */

                p = buffer + length;
                q = p + n;

                while (p != q) {
                    length++;
                    if (*p++ == '\n')
                        break;
                }

                if (p != q) {
                    self->size = q - p;
                    self->buffer = (char *)malloc(self->size);
                    self->offset = 0;
                    self->length = self->size;

                    memcpy(self->buffer, p, self->size);
                }
            }
        }

        /*
         * Resize the final string. If the size reduction is
         * by more than 25% of the string size, then Python
         * will allocate a new block of memory and copy the
         * data into it.
         */

        if (length != size) {
            if (_PyString_Resize(&result, length))
                return NULL;
        }
    }
    else {
        /*
         * Here we have to read in a line but where we have no
         * idea how long it may be. What we can do first is if
         * we have any residual data from a previous read
         * operation, see if it contains an EOL. This means we
         * have to do a search, but this is likely going to be
         * better than having to resize and copy memory later on.
         */

        if (self->buffer && self->length) {
            const char *p = NULL;
            const char *q = NULL;

            p = self->buffer + self->offset;
            q = memchr(p, '\n', self->length);

            if (q)
                size = q - p;
        }

        /*
         * If residual data buffer didn't contain an EOL, all we
         * can do is allocate a reasonably sized string and if
         * that isn't big enough keep increasing it in size. For
         * this we will start out with a buffer 25% greater in
         * size than what is stored in the residual data buffer
         * or one the same size as Apache string size, whichever
         * is greater.
         */

        if (self->buffer && size < 0) {
            size = self->length;
            size = size + (size >> 2);
        }

        if (size < HUGE_STRING_LEN)
            size = HUGE_STRING_LEN;

        /* Allocate string of the initial size. */

        result = PyString_FromStringAndSize(NULL, size);

        if (!result)
            return NULL;

        buffer = PyString_AS_STRING((PyStringObject *)result);

        /* Copy any residual data from use of readline(). */

        if (self->buffer && self->length) {
            char *p = NULL;
            const char *q = NULL;

            p = buffer;
            q = self->buffer + self->offset;

            while (self->length && length < size) {
                self->offset++;
                self->length--;
                length++;
                if ((*p++ = *q++) == '\n')
                    break;
            }

            /* If all data in residual buffer consumed then free it. */

            if (!self->length) {
                free(self->buffer);
                self->buffer = NULL;
            }
        }

        /*
         * Read in remaining data until find an EOL, or until all
         * data has been consumed.
         */

        while ((!length || buffer[length-1] != '\n') && !self->done) {

            char *p = NULL;
            char *q = NULL;

            Py_BEGIN_ALLOW_THREADS
            n = ap_get_client_block(self->r, buffer + length, size - length);
            Py_END_ALLOW_THREADS

            if (n == -1) {
                PyErr_SetString(PyExc_IOError, "request data read error");
                Py_DECREF(result);
                return NULL;
            }
            else if (n == 0) {
                /* Have exhausted all the available input data. */

                self->done = 1;
            }
            else {
                /*
                 * Search for embedded EOL in what was read and if
                 * found copy any residual into a buffer for use
                 * next time the read functions are called.
                 */

                p = buffer + length;
                q = p + n;

                while (p != q) {
                    length++;
                    if (*p++ == '\n')
                        break;
                }

                if (p != q) {
                    self->size = q - p;
                    self->buffer = (char *)malloc(self->size);
                    self->offset = 0;
                    self->length = self->size;

                    memcpy(self->buffer, p, self->size);
                }

                if (buffer[length-1] != '\n' && length == size) {
                    /* Increase size of string and keep going. */

                    size = size + (size >> 2);

                    if (_PyString_Resize(&result, size))
                        return NULL;

                    buffer = PyString_AS_STRING((PyStringObject *)result);
                }
            }
        }

        /*
         * Resize the final string. If the size reduction is by
         * more than 25% of the string size, then Python will
         * allocate a new block of memory and copy the data into
         * it.
         */

        if (length != size) {
            if (_PyString_Resize(&result, length))
                return NULL;
        }
    }

    return result;
}

static PyObject *Input_readlines(InputObject *self, PyObject *args)
{
    long hint = 0;
    long length = 0;

    PyObject *result = NULL;
    PyObject *line = NULL;
    PyObject *rlargs = NULL;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "|l:readlines", &hint))
        return NULL;

    result = PyList_New(0);
    if (!result)
        return NULL;

    rlargs = PyTuple_New(0);
    if (!rlargs) {
        Py_DECREF(result);
        return NULL;
    }

    while (1) {
        int n;

        if (!(line = Input_readline(self, rlargs))) {
            Py_DECREF(result);
            result = NULL;
            break;
        }

        if ((n = PyString_Size(line)) == 0) {
            Py_DECREF(line);
            break;
        }

        if (PyList_Append(result, line) == -1) {
            Py_DECREF(line);
            Py_DECREF(result);
            result = NULL;
            break;
        }

        Py_DECREF(line);

        length += n;
        if (hint > 0 && length >= hint)
            break;
    }

    Py_DECREF(rlargs);

    return result;
}

static PyMethodDef Input_methods[] = {
    { "close",     (PyCFunction)Input_close,     METH_VARARGS, 0 },
    { "read",      (PyCFunction)Input_read,      METH_VARARGS, 0 },
    { "readline",  (PyCFunction)Input_readline,  METH_VARARGS, 0 },
    { "readlines", (PyCFunction)Input_readlines, METH_VARARGS, 0 },
    { NULL, NULL}
};

static PyObject *Input_iter(InputObject *self)
{
    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    Py_INCREF(self);
    return (PyObject *)self;
}

static PyObject *Input_iternext(InputObject *self)
{
    PyObject *line = NULL;
    PyObject *rlargs = NULL;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    rlargs = PyTuple_New(0);

    if (!rlargs)
      return NULL;

    line = Input_readline(self, rlargs);

    Py_DECREF(rlargs);

    if (!line)
        return NULL;

    if (PyString_GET_SIZE(line) == 0) {
        PyErr_SetObject(PyExc_StopIteration, Py_None);
        Py_DECREF(line);
        return NULL;
    }

    return line;
}

static PyTypeObject Input_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "mod_wsgi.Input",       /*tp_name*/
    sizeof(InputObject),    /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Input_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
#if defined(Py_TPFLAGS_HAVE_ITER)
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER, /*tp_flags*/
#else
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
#endif
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    (getiterfunc)Input_iter, /*tp_iter*/
    (iternextfunc)Input_iternext, /*tp_iternext*/
    Input_methods,          /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

typedef struct {
        PyObject_HEAD
        int result;
        request_rec *r;
#if defined(MOD_WSGI_WITH_BUCKETS)
        apr_bucket_brigade *bb;
#endif
        WSGIRequestConfig *config;
        InputObject *input;
        PyObject *log;
        int status;
        const char *status_line;
        PyObject *headers;
        PyObject *sequence;
        int content_length_set;
        apr_off_t content_length;
        apr_off_t output_length;
} AdapterObject;

static PyTypeObject Adapter_Type;

typedef struct {
        PyObject_HEAD
        AdapterObject *adapter;
        PyObject *filelike;
        apr_size_t blksize;
} StreamObject;

static PyTypeObject Stream_Type;

static AdapterObject *newAdapterObject(request_rec *r)
{
    AdapterObject *self;

    self = PyObject_New(AdapterObject, &Adapter_Type);
    if (self == NULL)
        return NULL;

    self->result = HTTP_INTERNAL_SERVER_ERROR;

    self->r = r;

#if defined(MOD_WSGI_WITH_BUCKETS)
    self->bb = NULL;
#endif

    self->config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                             &wsgi_module);

    self->status = HTTP_INTERNAL_SERVER_ERROR;
    self->status_line = NULL;
    self->headers = NULL;
    self->sequence = NULL;

    self->content_length_set = 0;
    self->content_length = 0;
    self->output_length = 0;

    self->input = newInputObject(r);
    self->log = newLogObject(r, APLOG_ERR, NULL);

    return self;
}

static void Adapter_dealloc(AdapterObject *self)
{
    Py_XDECREF(self->headers);
    Py_XDECREF(self->sequence);

    Py_DECREF(self->input);
    Py_DECREF(self->log);

    PyObject_Del(self);
}

static PyObject *Adapter_start_response(AdapterObject *self, PyObject *args)
{
    const char *status = NULL;
    PyObject *headers = NULL;
    PyObject *exc_info = NULL;

    PyObject *item = NULL;
    PyObject *latin_item = NULL;

    char* value = NULL;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "OO|O:start_response",
        &item, &headers, &exc_info)) {
        return NULL;
    }

#if PY_MAJOR_VERSION >= 3
    if (PyUnicode_Check(item)) {
        latin_item = PyUnicode_AsLatin1String(item);
        if (!latin_item) {
            PyErr_Format(PyExc_TypeError, "expected byte string object for "
                         "status, value containing non 'latin-1' characters "
                         "found");
            return NULL;
        }

        item = latin_item;
    }
#endif

    if (!PyString_Check(item)) {
        PyErr_Format(PyExc_TypeError, "expected byte string object for "
                     "status, value of type %.200s found",
                     item->ob_type->tp_name);
        Py_XDECREF(latin_item);
        return NULL;
    }

    status = PyString_AsString(item);

    if (!PyList_Check(headers)) {
        PyErr_SetString(PyExc_TypeError, "response headers must be a list");
        Py_XDECREF(latin_item);
        return NULL;
    }

    if (exc_info && exc_info != Py_None) {
        if (self->status_line && !self->headers) {
            PyObject *type = NULL;
            PyObject *value = NULL;
            PyObject *traceback = NULL;

            if (!PyArg_ParseTuple(exc_info, "OOO", &type,
                                  &value, &traceback)) {
                Py_XDECREF(latin_item);
                return NULL;
            }

            Py_INCREF(type);
            Py_INCREF(value);
            Py_INCREF(traceback);

            PyErr_Restore(type, value, traceback);

            Py_XDECREF(latin_item);

            return NULL;
        }
    }
    else if (self->status_line && !self->headers) {
        PyErr_SetString(PyExc_RuntimeError, "headers have already been sent");
        Py_XDECREF(latin_item);
        return NULL;
    }

    self->status_line = apr_pstrdup(self->r->pool, status);

    value = ap_getword(self->r->pool, &status, ' ');

    errno = 0;
    self->status = strtol(value, &value, 10);

    if (*value || errno == ERANGE) {
        PyErr_SetString(PyExc_TypeError, "status value is not an integer");
        Py_XDECREF(latin_item);
        return NULL;
    }

    if (!*status) {
        PyErr_SetString(PyExc_ValueError, "status message was not supplied");
        Py_XDECREF(latin_item);
        return NULL;
    }

    Py_XDECREF(self->headers);

    self->headers = headers;

    Py_INCREF(self->headers);

    Py_XDECREF(latin_item);

    return PyObject_GetAttrString((PyObject *)self, "write");
}

static int Adapter_output(AdapterObject *self, const char *data, int length,
                          int exception_when_aborted)
{
    int i = 0;
    int n = 0;
    apr_status_t rv;
    request_rec *r;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_inactivity_timeout) {
        apr_thread_mutex_lock(wsgi_shutdown_lock);
        wsgi_inactivity_shutdown_time = apr_time_now();
        wsgi_inactivity_shutdown_time += wsgi_inactivity_timeout;
        apr_thread_mutex_unlock(wsgi_shutdown_lock);
    }
#endif

    if (!self->status_line) {
        PyErr_SetString(PyExc_RuntimeError, "response has not been started");
        return 0;
    }

    r = self->r;

    /* Have response headers yet been sent. */

    if (self->headers) {
        /*
         * Apache prior to Apache 2.2.8 has a bug in it
         * whereby it doesn't force '100 Continue'
         * response before responding with headers if no
         * read. So, force a zero length read before
         * sending the headers if haven't yet attempted
         * to read anything. This will ensure that if no
         * request content has been read that any '100
         * Continue' response will be flushed and sent
         * back to the client if client was expecting
         * one. Only want to do this for 2xx and 3xx
         * status values. Note that even though Apple
         * supplied version of Apache on MacOS X Leopard
         * is newer than version 2.2.8, the header file
         * has never been patched when they make updates
         * and so anything compiled against it thinks it
         * is older.
         */

#if (AP_SERVER_MAJORVERSION_NUMBER == 1) || \
    (AP_SERVER_MAJORVERSION_NUMBER == 2 && \
     AP_SERVER_MINORVERSION_NUMBER < 2) || \
    (AP_SERVER_MAJORVERSION_NUMBER == 2 && \
     AP_SERVER_MINORVERSION_NUMBER == 2 && \
     AP_SERVER_PATCHLEVEL_NUMBER < 8)

        if (!self->input->init) {
            if (self->status >= 200 && self->status < 400) {
                PyObject *args = NULL;
                PyObject *result = NULL;
                args = Py_BuildValue("(i)", 0);
                result = Input_read(self->input, args);
                if (PyErr_Occurred())
                    PyErr_Clear();
                Py_DECREF(args);
                Py_XDECREF(result);
            }
        }

#endif

        /* Now setup response headers in request object. */

        r->status = self->status;
        r->status_line = self->status_line;

        for (i = 0; i < PyList_Size(self->headers); i++) {
            PyObject *tuple = NULL;

            PyObject *object1 = NULL;
            PyObject *object2 = NULL;

            char *name = NULL;
            char *value = NULL;

            tuple = PyList_GetItem(self->headers, i);

            if (!PyTuple_Check(tuple)) {
                PyErr_Format(PyExc_TypeError, "list of tuple values "
                             "expected, value of type %.200s found",
                             tuple->ob_type->tp_name);
                return 0;
            }

            if (PyTuple_Size(tuple) != 2) {
                PyErr_Format(PyExc_ValueError, "tuple of length 2 "
                             "expected, length is %d",
                             (int)PyTuple_Size(tuple));
                return 0;
            }

            object1 = PyTuple_GetItem(tuple, 0);
            object2 = PyTuple_GetItem(tuple, 1);

            if (PyString_Check(object1)) {
                name = PyString_AsString(object1);
            }
#if PY_MAJOR_VERSION >= 3
            else if (PyUnicode_Check(object1)) {
                PyObject *latin_object;
                latin_object = PyUnicode_AsLatin1String(object1);
                if (!latin_object) {
                    PyErr_Format(PyExc_TypeError, "header name "
                                 "contained non 'latin-1' characters ");
                    return 0;
                }

                name = apr_pstrdup(r->pool, PyString_AsString(latin_object));
                Py_DECREF(latin_object);
            }
#endif
            else {
                PyErr_Format(PyExc_TypeError, "expected byte string object "
                             "for header name, value of type %.200s "
                             "found", object1->ob_type->tp_name);
                return 0;
            }

            if (PyString_Check(object2)) {
                value = PyString_AsString(object2);
            }
#if PY_MAJOR_VERSION >= 3
            else if (PyUnicode_Check(object2)) {
                PyObject *latin_object;
                latin_object = PyUnicode_AsLatin1String(object2);
                if (!latin_object) {
                    PyErr_Format(PyExc_TypeError, "header value "
                                 "contained non 'latin-1' characters ");
                    return 0;
                }

                value = apr_pstrdup(r->pool, PyString_AsString(latin_object));
                Py_DECREF(latin_object);
            }
#endif
            else {
                PyErr_Format(PyExc_TypeError, "expected byte string object "
                             "for header value, value of type %.200s "
                             "found", object2->ob_type->tp_name);
                return 0;
            }

            if (strchr(name, '\n') != 0 || strchr(value, '\n') != 0) {
                PyErr_Format(PyExc_ValueError, "embedded newline in "
                             "response header with name '%s' and value '%s'",
                             name, value);
                return 0;
            }

            if (!strcasecmp(name, "Content-Type")) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
                r->content_type = apr_pstrdup(r->pool, value);
#else
                /*
                 * In a daemon child process we cannot call the
                 * function ap_set_content_type() as want to
                 * avoid adding any output filters based on the
                 * type of file being served as this will be
                 * done in the main Apache child process which
                 * proxied the request to the daemon process.
                 */

                if (*self->config->process_group)
                    r->content_type = apr_pstrdup(r->pool, value);
                else
                    ap_set_content_type(r, value);
#endif
            }
            else if (!strcasecmp(name, "Content-Length")) {
                char *v = value;
                long l = 0;

                errno = 0;
                l = strtol(v, &v, 10);
                if (*v || errno == ERANGE || l < 0) {
                    PyErr_SetString(PyExc_ValueError,
                                    "invalid content length");
                    return 0;
                }

                ap_set_content_length(r, l);

                self->content_length_set = 1;
                self->content_length = l;
            }
            else if (!strcasecmp(name, "WWW-Authenticate")) {
                apr_table_add(r->err_headers_out, name, value);
            }
            else {
                apr_table_add(r->headers_out, name, value);
            }
        }

        /* Need to force output of headers when using Apache 1.3. */

        Py_BEGIN_ALLOW_THREADS
        ap_send_http_header(r);
        Py_END_ALLOW_THREADS

        /*
         * Reset flag indicating whether '100 Continue' response
         * expected. If we don't do this then if an attempt to read
         * input for the first time is after headers have been
         * sent, then Apache is wrongly generate the '100 Continue'
         * response into the response content. Not sure if this is
         * a bug in Apache, or that it truly believes that input
         * will never be read after the response headers have been
         * sent.
         */

        r->expecting_100 = 0;

        /* No longer need headers now that they have been sent. */

        Py_DECREF(self->headers);
        self->headers = NULL;
    }

    /*
     * If content length was specified, ensure that we don't
     * actually output more data than was specified as being
     * sent as otherwise technically in violation of HTTP RFC.
     */

    if (length) {
        int output_length = length;

        if (self->content_length_set) {
            if (self->output_length < self->content_length) {
                if (self->output_length + length > self->content_length) {
                    length = self->content_length - self->output_length;
                }
            }
            else
                length = 0;
        }

        self->output_length += output_length;
    }

    /* Now output any data. */

    if (length) {
#if defined(MOD_WSGI_WITH_BUCKETS)
        apr_bucket *b;

        /*
         * When using Apache 2.X can use lower level
         * bucket brigade APIs. This is preferred as
         * ap_rwrite()/ap_rflush() will grow memory in
         * the request pool on each call, which will
         * result in an increase in memory use over time
         * when streaming of data is being performed.
         * The memory is still reclaimed, but only at
         * the end of the request. Using bucket brigade
         * API avoids this, and also avoids any copying
         * of response data due to buffering performed
         * by ap_rwrite().
         */

        if (r->connection->aborted) {
            if (!exception_when_aborted) {
                ap_log_rerror(APLOG_MARK, WSGI_LOG_DEBUG(0), self->r,
                              "mod_wsgi (pid=%d): Client closed connection.",
                              getpid());
            }
            else
                PyErr_SetString(PyExc_IOError, "client connection closed");

            return 0;
        }

        if (!self->bb) {
            self->bb = apr_brigade_create(r->pool,
                                          r->connection->bucket_alloc);
        }

        b = apr_bucket_transient_create(data, length,
                                        r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(self->bb, b);

        b = apr_bucket_flush_create(r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(self->bb, b);

        Py_BEGIN_ALLOW_THREADS
        rv = ap_pass_brigade(r->output_filters, self->bb);
        Py_END_ALLOW_THREADS

        if (rv != APR_SUCCESS) {
            PyErr_SetString(PyExc_IOError, "failed to write data");
            return 0;
        }

        Py_BEGIN_ALLOW_THREADS
        apr_brigade_cleanup(self->bb);
        Py_END_ALLOW_THREADS
#else
        /*
         * In Apache 1.3, the bucket brigade system doesn't exist,
         * so have no choice but to use ap_rwrite()/ap_rflush().
         * It is not believed that Apache 1.3 suffers the memory
         * accumulation problem when streaming lots of data.
         */

        Py_BEGIN_ALLOW_THREADS
        n = ap_rwrite(data, length, r);
        Py_END_ALLOW_THREADS

        if (n == -1) {
            PyErr_SetString(PyExc_IOError, "failed to write data");
            return 0;
        }

        Py_BEGIN_ALLOW_THREADS
        n = ap_rflush(r);
        Py_END_ALLOW_THREADS

        if (n == -1) {
            PyErr_SetString(PyExc_IOError, "failed to flush data");
            return 0;
        }
#endif
    }

    /*
     * Check whether aborted connection was found when data
     * being written, otherwise will not be flagged until next
     * time that data is being written. Early detection is
     * better as it may have been the last data block being
     * written and application may think that data has all
     * been written. In a streaming application, we also want
     * to avoid any additional data processing to generate any
     * successive data.
     */

    if (r->connection->aborted) {
        if (!exception_when_aborted) {
            ap_log_rerror(APLOG_MARK, WSGI_LOG_DEBUG(0), self->r,
                          "mod_wsgi (pid=%d): Client closed connection.",
                          getpid());
        }
        else
            PyErr_SetString(PyExc_IOError, "client connection closed");

        return 0;
    }

    return 1;
}

#if AP_SERVER_MAJORVERSION_NUMBER >= 2

/* Split buckets at 1GB when sending large files. */

#define MAX_BUCKET_SIZE (0x40000000)

static int Adapter_output_file(AdapterObject *self, apr_file_t* tmpfile,
                               apr_off_t offset, apr_off_t len)
{
    request_rec *r;
    apr_bucket *b;
    apr_status_t rv;
    apr_bucket_brigade *bb;

    r = self->r;

    if (r->connection->aborted) {
        PyErr_SetString(PyExc_IOError, "client connection closed");
        return 0;
    }

    if (len == 0)
        return 1;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    if (sizeof(apr_off_t) == sizeof(apr_size_t) || len < MAX_BUCKET_SIZE) {
        /* Can use a single bucket to send file. */

        b = apr_bucket_file_create(tmpfile, offset, (apr_size_t)len, r->pool,
                                   r->connection->bucket_alloc);
    }
    else {
        /* Need to create multiple buckets to send file. */

        b = apr_bucket_file_create(tmpfile, offset, MAX_BUCKET_SIZE, r->pool,
                                   r->connection->bucket_alloc);

        while (len > MAX_BUCKET_SIZE) {
            apr_bucket *cb;
            apr_bucket_copy(b, &cb);
            APR_BRIGADE_INSERT_TAIL(bb, cb);
            b->start += MAX_BUCKET_SIZE;
            len -= MAX_BUCKET_SIZE;
        }

        /* Resize just the last bucket */

        b->length = (apr_size_t)len;
    }

    APR_BRIGADE_INSERT_TAIL(bb, b);

    b = apr_bucket_flush_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    Py_BEGIN_ALLOW_THREADS
    rv = ap_pass_brigade(r->output_filters, bb);
    Py_END_ALLOW_THREADS

    if (rv != APR_SUCCESS) {
        PyErr_SetString(PyExc_IOError, "failed to write data");
        return 0;
    }

    Py_BEGIN_ALLOW_THREADS
    apr_brigade_destroy(bb);
    Py_END_ALLOW_THREADS

    if (r->connection->aborted) {
        PyErr_SetString(PyExc_IOError, "client connection closed");
        return 0;
    }

    return 1;
}

#endif

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *wsgi_is_https = NULL;
#endif

static PyObject *Adapter_environ(AdapterObject *self)
{
    request_rec *r = NULL;

    PyObject *vars = NULL;
    PyObject *object = NULL;

    const apr_array_header_t *head = NULL;
    const apr_table_entry_t *elts = NULL;

    int i = 0;

    const char *scheme = NULL;

    /* Create the WSGI environment dictionary. */

    vars = PyDict_New();

    /* Merge the CGI environment into the WSGI environment. */

    r = self->r;

    head = apr_table_elts(r->subprocess_env);
    elts = (apr_table_entry_t *)head->elts;

    for (i = 0; i < head->nelts; ++i) {
        if (elts[i].key) {
            if (elts[i].val) {
#if PY_MAJOR_VERSION >= 3
                if (!strcmp(elts[i].val, "DOCUMENT_ROOT")) {
                    object = PyUnicode_Decode(elts[i].val, strlen(elts[i].val),
                                             Py_FileSystemDefaultEncoding,
                                             "surrogateescape");
                }
                else if (!strcmp(elts[i].val, "SCRIPT_FILENAME")) {
                    object = PyUnicode_Decode(elts[i].val, strlen(elts[i].val),
                                             Py_FileSystemDefaultEncoding,
                                             "surrogateescape");
                }
                else {
                    object = PyUnicode_DecodeLatin1(elts[i].val,
                                                    strlen(elts[i].val), NULL);
                }
#else
                object = PyString_FromString(elts[i].val);
#endif
                PyDict_SetItemString(vars, elts[i].key, object);
                Py_DECREF(object);
            }
            else
                PyDict_SetItemString(vars, elts[i].key, Py_None);
        }
    }

    PyDict_DelItemString(vars, "PATH");

    /* Now setup all the WSGI specific environment values. */

    object = Py_BuildValue("(ii)", 1, 1);
    PyDict_SetItemString(vars, "wsgi.version", object);
    Py_DECREF(object);

    object = PyBool_FromLong(wsgi_multithread);
    PyDict_SetItemString(vars, "wsgi.multithread", object);
    Py_DECREF(object);

    object = PyBool_FromLong(wsgi_multiprocess);
    PyDict_SetItemString(vars, "wsgi.multiprocess", object);
    Py_DECREF(object);

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process) {
        if (wsgi_daemon_process->group->threads == 1 &&
            wsgi_daemon_process->group->maximum_requests == 1) {
            PyDict_SetItemString(vars, "wsgi.run_once", Py_True);
        }
        else
            PyDict_SetItemString(vars, "wsgi.run_once", Py_False);
    }
    else
        PyDict_SetItemString(vars, "wsgi.run_once", Py_False);
#else
    PyDict_SetItemString(vars, "wsgi.run_once", Py_False);
#endif

    scheme = apr_table_get(r->subprocess_env, "HTTPS");

    if (scheme && (!strcasecmp(scheme, "On") || !strcmp(scheme, "1"))) {
#if PY_MAJOR_VERSION >= 3
        object = PyUnicode_FromString("https");
#else
        object = PyString_FromString("https");
#endif
        PyDict_SetItemString(vars, "wsgi.url_scheme", object);
        Py_DECREF(object);
    }
    else {
#if PY_MAJOR_VERSION >= 3
        object = PyUnicode_FromString("http");
#else
        object = PyString_FromString("http");
#endif
        PyDict_SetItemString(vars, "wsgi.url_scheme", object);
        Py_DECREF(object);
    }

    /*
     * Setup log object for WSGI errors. Don't decrement
     * reference to log object as keep reference to it.
     */

    object = (PyObject *)self->log;
    PyDict_SetItemString(vars, "wsgi.errors", object);

    /* Setup input object for request content. */

    object = (PyObject *)self->input;
    PyDict_SetItemString(vars, "wsgi.input", object);

    /* Setup file wrapper object for efficient file responses. */

    object = PyObject_GetAttrString((PyObject *)self, "file_wrapper");
    PyDict_SetItemString(vars, "wsgi.file_wrapper", object);
    Py_DECREF(object);

    /* Add mod_wsgi version information. */

    object = Py_BuildValue("(ii)", MOD_WSGI_MAJORVERSION_NUMBER,
                           MOD_WSGI_MINORVERSION_NUMBER);
    PyDict_SetItemString(vars, "mod_wsgi.version", object);
    Py_DECREF(object);

    /*
     * If Apache extensions are enabled and running in embedded
     * mode add a CObject reference to the Apache request_rec
     * structure instance.
     */

    if (!wsgi_daemon_pool && self->config->pass_apache_request) {
        object = PyCObject_FromVoidPtr(self->r, 0);
        PyDict_SetItemString(vars, "apache.request_rec", object);
        Py_DECREF(object);
    }

    return vars;
}

static int Adapter_process_file_wrapper(AdapterObject *self)
{
    int done = 0;

#ifndef WIN32
#if AP_SERVER_MAJORVERSION_NUMBER >= 2

    PyObject *filelike = NULL;
    PyObject *method = NULL;
    PyObject *object = NULL;

    apr_status_t rv = 0;

    apr_os_file_t fd = -1;
    apr_file_t *tmpfile = NULL;
    apr_finfo_t finfo;

    apr_off_t fd_offset = 0;
    apr_off_t fo_offset = 0;

    apr_off_t length = 0;

    /* Perform file wrapper optimisations where possible. */

    if (self->sequence->ob_type != &Stream_Type)
        return 0;

    /*
     * Only attempt to perform optimisations if the
     * write() function returned by start_response()
     * function has not been called with non zero length
     * data. In other words if no prior response content
     * generated. Technically it could be done, but want
     * to have a consistent rule about how specifying a
     * content length affects how much of a file is
     * sent. Don't want to have to take into
     * consideration whether write() function has been
     * called or not as just complicates things.
     */

    if (self->output_length != 0)
        return 0;

    /*
     * Work out if file wrapper is associated with a
     * file like object, where that file object is
     * associated with a regular file. If it does then
     * we can optimise how the contents of the file are
     * sent out. If no such associated file descriptor
     * then it needs to be processed like any other
     * iterable value.
     */

    filelike = ((StreamObject *)self->sequence)->filelike;

    fd = PyObject_AsFileDescriptor(filelike);
    if (fd == -1) {
        PyErr_Clear();
        return 0;
    }

    /*
     * On some platforms, such as Linux, sendfile() system call
     * will not work on UNIX sockets. Thus when using daemon mode
     * cannot enable that feature.
     */

    if (!wsgi_daemon_pool)
        apr_os_file_put(&tmpfile, &fd, APR_SENDFILE_ENABLED, self->r->pool);
    else
        apr_os_file_put(&tmpfile, &fd, 0, self->r->pool);

    rv = apr_file_info_get(&finfo, APR_FINFO_SIZE|APR_FINFO_TYPE, tmpfile);
    if (rv != APR_SUCCESS || finfo.filetype != APR_REG)
        return 0;

    /*
     * Because Python file like objects potentially have
     * their own buffering layering, or use an operating
     * system FILE object which also has a buffering
     * layer on top of a normal file descriptor, need to
     * determine from the file like object its position
     * within the file and use that as starting position.
     * Note that it is assumed that user had flushed any
     * modifications to the file as necessary. Also, we
     * need to make sure we remember the original file
     * descriptor position as will need to restore that
     * position so it matches the upper buffering layers
     * when done. This is done to avoid any potential
     * problems if file like object does anything strange
     * in its close() method which relies on file position
     * being what it thought it should be.
     */

    rv = apr_file_seek(tmpfile, APR_CUR, &fd_offset);
    if (rv != APR_SUCCESS)
        return 0;

    method = PyObject_GetAttrString(filelike, "tell");
    if (!method)
        return 0;

    object = PyEval_CallObject(method, NULL);
    Py_DECREF(method);

    if (!object) {
        PyErr_Clear();
        return 0;
    }

   if (PyLong_Check(object)) {
#if defined(HAVE_LONG_LONG)
       fo_offset = PyLong_AsLongLong(object);
#else
       fo_offset = PyLong_AsLong(object);
#endif
   }
#if PY_MAJOR_VERSION < 3
   else if (PyInt_Check(object)) {
       fo_offset = PyInt_AsLong(object);
   }
#endif
   else {
       Py_DECREF(object);
       return 0;
   }

   if (PyErr_Occurred()){
       Py_DECREF(object);
       PyErr_Clear();
       return 0;
   }

    Py_DECREF(object);

    /*
     * For a file wrapper object need to always ensure
     * that response headers are parsed. This is done so
     * that if the content length header has been
     * defined we can get its value and use it to limit
     * how much of a file is being sent. The WSGI 1.0
     * specification says that we are meant to send all
     * available bytes from the file, however this is
     * questionable as sending more than content length
     * would violate HTTP RFC. Note that this doesn't
     * actually flush the headers out when using Apache
     * 2.X. This is good, as we want to still be able to
     * set the content length header if none set and file
     * is seekable. If processing response headers fails,
     * then need to return as if done, with error being
     * logged later.
     */

    if (!Adapter_output(self, "", 0, 0))
        return 1;

    /*
     * If content length wasn't defined then determine
     * the amount of data which is available to send and
     * set the content length response header. Either
     * way, if can work out length then send data
     * otherwise fall through and treat it as normal
     * iterable.
     */

    if (!self->content_length_set) {
        length = finfo.size - fo_offset;
        self->output_length += length;

        ap_set_content_length(self->r, length);

        self->content_length_set = 1;
        self->content_length = length;

        if (Adapter_output_file(self, tmpfile, fo_offset, length))
            self->result = OK;

        done = 1;
    }
    else {
        length = finfo.size - fo_offset;
        self->output_length += length;

        /* Use user specified content length instead. */

        length = self->content_length;

        if (Adapter_output_file(self, tmpfile, fo_offset, length))
            self->result = OK;

        done = 1;
    }

    /*
     * Restore position of underlying file descriptor.
     * If this fails, then not much we can do about it.
     */

    apr_file_seek(tmpfile, APR_SET, &fd_offset);

#endif
#endif

    return done;
}

static int Adapter_run(AdapterObject *self, PyObject *object)
{
    PyObject *vars = NULL;
    PyObject *start = NULL;
    PyObject *args = NULL;
    PyObject *iterator = NULL;
    PyObject *close = NULL;

    const char *msg = NULL;
    int length = 0;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_inactivity_timeout) {
        apr_thread_mutex_lock(wsgi_shutdown_lock);
        wsgi_inactivity_shutdown_time = apr_time_now();
        wsgi_inactivity_shutdown_time += wsgi_inactivity_timeout;
        apr_thread_mutex_unlock(wsgi_shutdown_lock);
    }
#endif

    vars = Adapter_environ(self);

    start = PyObject_GetAttrString((PyObject *)self, "start_response");

    args = Py_BuildValue("(OO)", vars, start);

    self->sequence = PyEval_CallObject(object, args);

    if (self->sequence != NULL) {
        if (!Adapter_process_file_wrapper(self)) {
            int aborted = 0;

            iterator = PyObject_GetIter(self->sequence);

            if (iterator != NULL) {
                PyObject *item = NULL;

                while ((item = PyIter_Next(iterator))) {
#if PY_MAJOR_VERSION >= 3
                    if (PyUnicode_Check(item)) {
                        PyObject *latin_item;
                        latin_item = PyUnicode_AsLatin1String(item);
                        if (!latin_item) {
                            PyErr_Format(PyExc_TypeError, "sequence of "
                                         "byte string values expected, value "
                                         "containing non 'latin-1' characters "
                                         "found");
                            Py_DECREF(item);
                            break;
                        }

                        Py_DECREF(item);
                        item = latin_item;
                    }
#endif

                    if (!PyString_Check(item)) {
                        PyErr_Format(PyExc_TypeError, "sequence of byte "
                                     "string values expected, value of "
                                     "type %.200s found",
                                     item->ob_type->tp_name);
                        Py_DECREF(item);
                        break;
                    }

                    msg = PyString_AsString(item);
                    length = PyString_Size(item);

                    if (!msg) {
                        Py_DECREF(item);
                        break;
                    }

                    if (length && !Adapter_output(self, msg, length, 0)) {
                        if (!PyErr_Occurred())
                            aborted = 1;
                        Py_DECREF(item);
                        break;
                    }

                    Py_DECREF(item);
                }
            }

            if (!PyErr_Occurred() && !aborted) {
                if (Adapter_output(self, "", 0, 0))
                    self->result = OK;
            }

            Py_XDECREF(iterator);
        }

        if (PyErr_Occurred()) {
            /*
             * Response content has already been sent, so cannot
             * return an internal server error as Apache will
             * append its own error page. Thus need to return OK
             * and just truncate the response.
             */

            if (self->status_line && !self->headers)
                self->result = OK;

            wsgi_log_python_error(self->r, self->log, self->r->filename);
        }

        if (PyObject_HasAttrString(self->sequence, "close")) {
            PyObject *args = NULL;
            PyObject *data = NULL;

            close = PyObject_GetAttrString(self->sequence, "close");

            args = Py_BuildValue("()");
            data = PyEval_CallObject(close, args);

            Py_DECREF(args);
            Py_XDECREF(data);
            Py_DECREF(close);
        }

        if (PyErr_Occurred())
            wsgi_log_python_error(self->r, self->log, self->r->filename);

        Py_DECREF(self->sequence);

        self->sequence = NULL;
    }

    Py_DECREF(args);
    Py_DECREF(start);
    Py_DECREF(vars);

    /*
     * Log warning if more response content generated than was
     * indicated, or less if there was no errors generated by
     * the application.
     */

    if (self->content_length_set && ((!PyErr_Occurred() &&
        self->output_length != self->content_length) ||
        (self->output_length > self->content_length))) {
        ap_log_rerror(APLOG_MARK, WSGI_LOG_DEBUG(0), self->r,
                      "mod_wsgi (pid=%d): Content length mismatch, "
                      "expected %s, response generated %s: %s", getpid(),
                      apr_off_t_toa(self->r->pool, self->content_length),
                      apr_off_t_toa(self->r->pool, self->output_length),
                      self->r->filename);
    }

    /* Log details of any final Python exceptions. */

    if (PyErr_Occurred())
        wsgi_log_python_error(self->r, self->log, self->r->filename);

    /*
     * If result indicates an internal server error, then
     * replace the status line in the request object else
     * that provided by the application will be what is used
     * in any error page automatically generated by Apache.
     */

    if (self->result == HTTP_INTERNAL_SERVER_ERROR)
        self->r->status_line = "500 Internal Server Error";

    return self->result;
}

static PyObject *Adapter_write(AdapterObject *self, PyObject *args)
{
    PyObject *item = NULL;
    const char *data = NULL;
    int length = 0;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:write", &item))
        return NULL;

#if PY_MAJOR_VERSION >= 3
    if (PyUnicode_Check(item)) {
        PyObject *latin_item;
        latin_item = PyUnicode_AsLatin1String(item);
        if (!latin_item) {
            PyErr_Format(PyExc_TypeError, "byte string value expected, "
                         "value containing non 'latin-1' characters found");
            Py_DECREF(item);
            return NULL;
        }

        Py_DECREF(item);
        item = latin_item;
    }
#endif

    if (!PyString_Check(item)) {
        PyErr_Format(PyExc_TypeError, "byte string value expected, value "
                     "of type %.200s found", item->ob_type->tp_name);
        Py_DECREF(item);
        return NULL;
    }

    data = PyString_AsString(item);
    length = PyString_Size(item);

    if (!Adapter_output(self, data, length, 1))
        return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *newStreamObject(AdapterObject *adapter, PyObject *filelike,
                                 apr_size_t blksize);

static PyObject *Adapter_file_wrapper(AdapterObject *self, PyObject *args)
{
    PyObject *filelike = NULL;
    apr_size_t blksize = HUGE_STRING_LEN;
    PyObject *result = NULL;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O|l:file_wrapper", &filelike, &blksize))
        return NULL;

    return newStreamObject(self, filelike, blksize);
}

static PyMethodDef Adapter_methods[] = {
    { "start_response", (PyCFunction)Adapter_start_response, METH_VARARGS, 0 },
    { "write",          (PyCFunction)Adapter_write, METH_VARARGS, 0 },
    { "file_wrapper",   (PyCFunction)Adapter_file_wrapper, METH_VARARGS, 0 },
    { NULL, NULL}
};

static PyTypeObject Adapter_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "mod_wsgi.Adapter",     /*tp_name*/
    sizeof(AdapterObject),  /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Adapter_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    Adapter_methods,        /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

static PyObject *newStreamObject(AdapterObject *adapter, PyObject *filelike,
                                 apr_size_t blksize)
{
    StreamObject *self;

    self = PyObject_New(StreamObject, &Stream_Type);
    if (self == NULL)
        return NULL;

    self->adapter = adapter;
    self->filelike = filelike;
    self->blksize = blksize;

    Py_INCREF(self->adapter);
    Py_INCREF(self->filelike);

    return (PyObject *)self;
}

static void Stream_dealloc(StreamObject *self)
{
    Py_DECREF(self->filelike);
    Py_DECREF(self->adapter);

    PyObject_Del(self);
}

static PyObject *Stream_iter(StreamObject *self)
{
    if (!self->adapter->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    Py_INCREF(self);
    return (PyObject *)self;
}

static PyObject *Stream_iternext(StreamObject *self)
{
    PyObject *method = NULL;
    PyObject *args = NULL;
    PyObject *result = NULL;

    if (!self->adapter->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    method = PyObject_GetAttrString(self->filelike, "read");

    if (!method) {
        PyErr_SetString(PyExc_KeyError,
                        "file like object has no read() method");
        return 0;
    }

    args = Py_BuildValue("(l)", self->blksize);
    result = PyEval_CallObject(method, args);

    Py_DECREF(method);
    Py_DECREF(args);

    if (!result)
        return 0;

    if (PyString_Check(result)) {
        if (PyString_Size(result) == 0) {
            PyErr_SetObject(PyExc_StopIteration, Py_None);
            Py_DECREF(result);
            return 0;
        }

        return result;
    }

#if PY_MAJOR_VERSION >= 3
    if (PyUnicode_Check(result)) {
        if (PyUnicode_GetSize(result) == 0) {
            PyErr_SetObject(PyExc_StopIteration, Py_None);
            Py_DECREF(result);
            return 0;
        }

        return result;
    }
#endif

    Py_DECREF(result);

    PyErr_SetString(PyExc_TypeError,
                    "file like object yielded non string type");

    return 0;
}

static PyObject *Stream_close(StreamObject *self, PyObject *args)
{
    PyObject *method = NULL;
    PyObject *result = NULL;

    method = PyObject_GetAttrString(self->filelike, "close");

    if (method) {
        result = PyEval_CallObject(method, (PyObject *)NULL);
        if (!result)
            PyErr_Clear();
        Py_DECREF(method);
    }

    Py_XDECREF(result);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef Stream_methods[] = {
    { "close",      (PyCFunction)Stream_close,      METH_VARARGS, 0 },
    { NULL, NULL}
};

static PyTypeObject Stream_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "mod_wsgi.Stream",      /*tp_name*/
    sizeof(StreamObject),   /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Stream_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
#if defined(Py_TPFLAGS_HAVE_ITER)
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER, /*tp_flags*/
#else
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
#endif
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    (getiterfunc)Stream_iter, /*tp_iter*/
    (iternextfunc)Stream_iternext, /*tp_iternext*/
    Stream_methods,         /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

/* Restricted object to stop access to STDIN/STDOUT. */

typedef struct {
    PyObject_HEAD
    const char *s;
} RestrictedObject;

static PyTypeObject Restricted_Type;

static RestrictedObject *newRestrictedObject(const char *s)
{
    RestrictedObject *self;

    self = PyObject_New(RestrictedObject, &Restricted_Type);
    if (self == NULL)
        return NULL;

    self->s = s;

    return self;
}

static void Restricted_dealloc(RestrictedObject *self)
{
    PyObject_Del(self);
}

static PyObject *Restricted_getattr(RestrictedObject *self, char *name)
{
    PyErr_Format(PyExc_IOError, "%s access restricted by mod_wsgi", self->s);

    return NULL;
}

static PyTypeObject Restricted_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "mod_wsgi.Restricted",  /*tp_name*/
    sizeof(RestrictedObject), /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Restricted_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    (getattrfunc)Restricted_getattr, /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    0,                      /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

/* Function to restrict access to use of signal(). */

static PyObject *wsgi_signal_intercept(PyObject *self, PyObject *args)
{
    PyObject *h = NULL;
    int n = 0;

    PyObject *m = NULL;

    if (!PyArg_ParseTuple(args, "iO:signal", &n, &h))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    ap_log_error(APLOG_MARK, WSGI_LOG_WARNING(0), wsgi_server,
                 "mod_wsgi (pid=%d): Callback registration for "
                 "signal %d ignored.", getpid(), n);
    Py_END_ALLOW_THREADS

    m = PyImport_ImportModule("traceback");

    if (m) {
        PyObject *d = NULL;
        PyObject *o = NULL;
        d = PyModule_GetDict(m);
        o = PyDict_GetItemString(d, "print_stack");
        if (o) {
            PyObject *log = NULL;
            PyObject *args = NULL;
            PyObject *result = NULL;
            Py_INCREF(o);
            log = newLogObject(NULL, APLOG_WARNING, NULL);
            args = Py_BuildValue("(OOO)", Py_None, Py_None, log);
            result = PyEval_CallObject(o, args);
            Py_XDECREF(result);
            Py_DECREF(args);
            Py_DECREF(log);
            Py_DECREF(o);
        }
    }

    Py_XDECREF(m);

    Py_INCREF(h);

    return h;
}

static PyMethodDef wsgi_signal_method[] = {
    { "signal", (PyCFunction)wsgi_signal_intercept, METH_VARARGS, 0 },
    { NULL, NULL }
};

/* Wrapper around Python interpreter instances. */

static const char *wsgi_python_path = NULL;
static const char *wsgi_python_eggs = NULL;

#if APR_HAS_THREADS
static int wsgi_thread_count = 0;
static apr_threadkey_t *wsgi_thread_key;
#endif

typedef struct {
    PyObject_HEAD
    char *name;
    PyInterpreterState *interp;
    int owner;
#if APR_HAS_THREADS
    apr_hash_t *tstate_table;
#else
    PyThreadState *tstate;
#endif
} InterpreterObject;

static PyTypeObject Interpreter_Type;

static InterpreterObject *newInterpreterObject(const char *name)
{
    PyInterpreterState *interp = NULL;
    InterpreterObject *self = NULL;
    PyThreadState *tstate = NULL;
    PyThreadState *save_tstate = NULL;
    PyObject *module = NULL;
    PyObject *object = NULL;
    PyObject *item = NULL;

    /* Create handle for interpreter and local data. */

    self = PyObject_New(InterpreterObject, &Interpreter_Type);
    if (self == NULL)
        return NULL;

    /*
     * If interpreter not named, then we want to bind
     * to the first Python interpreter instance created.
     * Give this interpreter an empty string as name.
     */

    if (!name) {
        interp = PyInterpreterState_Head();
        while (interp->next)
            interp = interp->next;

        name = "";
    }

    /* Save away the interpreter name. */

    self->name = strdup(name);

    if (interp) {
        /*
         * Interpreter provided to us so will not be
         * responsible for deleting it later. This will
         * be the case for the main Python interpreter.
         */

        ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                     "mod_wsgi (pid=%d): Attach interpreter '%s'.",
                     getpid(), name);

        self->interp = interp;
        self->owner = 0;
    }
    else {
        /*
         * Remember active thread state so can restore
         * it. This is actually the thread state
         * associated with simplified GIL state API.
         */

        save_tstate = PyThreadState_Swap(NULL);

        /*
         * Create the interpreter. If creation of the
         * interpreter fails it will restore the
         * existing active thread state for us so don't
         * need to worry about it in that case.
         */

        tstate = Py_NewInterpreter();

        if (!tstate) {
            PyErr_SetString(PyExc_RuntimeError, "Py_NewInterpreter() failed");

            Py_DECREF(self);

            return NULL;
        }

        Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                     "mod_wsgi (pid=%d): Create interpreter '%s'.",
                     getpid(), name);
        Py_END_ALLOW_THREADS

        self->interp = tstate->interp;
        self->owner = 1;
    }

    /*
     * Install restricted objects for STDIN and STDOUT,
     * or log object for STDOUT as appropriate. Don't do
     * this if not running on Win32 and we believe we
     * are running in single process mode, otherwise
     * it prevents use of interactive debuggers such as
     * the 'pdb' module.
     */

    object = newLogObject(NULL, APLOG_ERR, "stderr");
    PySys_SetObject("stderr", object);
    Py_DECREF(object);

#ifndef WIN32
    if (wsgi_parent_pid != getpid()) {
#endif
        if (wsgi_server_config->restrict_stdout == 1) {
            object = (PyObject *)newRestrictedObject("sys.stdout");
            PySys_SetObject("stdout", object);
            Py_DECREF(object);
        }
        else {
            object = newLogObject(NULL, APLOG_ERR, "stdout");
            PySys_SetObject("stdout", object);
            Py_DECREF(object);
        }

        if (wsgi_server_config->restrict_stdin == 1) {
            object = (PyObject *)newRestrictedObject("sys.stdin");
            PySys_SetObject("stdin", object);
            Py_DECREF(object);
        }
#ifndef WIN32
    }
#endif

    /*
     * Set sys.argv to one element list to fake out
     * modules that look there for Python command
     * line arguments as appropriate.
     */

    object = PyList_New(0);
#if PY_MAJOR_VERSION >= 3
    item = PyUnicode_FromString("mod_wsgi");
#else
    item = PyString_FromString("mod_wsgi");
#endif
    PyList_Append(object, item);
    PySys_SetObject("argv", object);
    Py_DECREF(item);
    Py_DECREF(object);

    /*
     * Install intercept for signal handler registration
     * if appropriate.
     */

    if (wsgi_server_config->restrict_signal != 0) {
        module = PyImport_ImportModule("signal");
        PyModule_AddObject(module, "signal", PyCFunction_New(
                           &wsgi_signal_method[0], NULL));
        Py_DECREF(module);
    }

    /*
     * If running in daemon process, override as appropriate
     * the USER, USERNAME or LOGNAME environment  variables
     * so that they match the user that the process is running
     * as. Need to do this else we inherit the value from the
     * Apache parent process which is likely wrong as will be
     * root or the user than ran sudo when Apache started.
     * Can't update these for normal Apache child processes
     * as that would change the expected environment of other
     * Apache modules.
     */

#ifndef WIN32
    if (wsgi_daemon_pool) {
        module = PyImport_ImportModule("os");

        if (module) {
            PyObject *dict = NULL;
            PyObject *key = NULL;
            PyObject *value = NULL;

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "environ");

            if (object) {
                struct passwd *pwent;

                pwent = getpwuid(geteuid());

                if (getenv("USER")) {
#if PY_MAJOR_VERSION >= 3
                    key = PyUnicode_FromString("USER");
                    value = PyUnicode_Decode(pwent->pw_name,
                                             strlen(pwent->pw_name),
                                             Py_FileSystemDefaultEncoding,
                                             "surrogateescape");
#else
                    key = PyString_FromString("USER");
                    value = PyString_FromString(pwent->pw_name);
#endif

                    PyObject_SetItem(object, key, value);

                    Py_DECREF(key);
                    Py_DECREF(value);
                }

                if (getenv("USERNAME")) {
#if PY_MAJOR_VERSION >= 3
                    key = PyUnicode_FromString("USERNAME");
                    value = PyUnicode_Decode(pwent->pw_name,
                                             strlen(pwent->pw_name),
                                             Py_FileSystemDefaultEncoding,
                                             "surrogateescape");
#else
                    key = PyString_FromString("USERNAME");
                    value = PyString_FromString(pwent->pw_name);
#endif

                    PyObject_SetItem(object, key, value);

                    Py_DECREF(key);
                    Py_DECREF(value);
                }

                if (getenv("LOGNAME")) {
#if PY_MAJOR_VERSION >= 3
                    key = PyUnicode_FromString("LOGNAME");
                    value = PyUnicode_Decode(pwent->pw_name,
                                             strlen(pwent->pw_name),
                                             Py_FileSystemDefaultEncoding,
                                             "surrogateescape");
#else
                    key = PyString_FromString("LOGNAME");
                    value = PyString_FromString(pwent->pw_name);
#endif

                    PyObject_SetItem(object, key, value);

                    Py_DECREF(key);
                    Py_DECREF(value);
                }
            }

            Py_DECREF(module);
        }
    }
#endif

    /*
     * If running in daemon process, override HOME environment
     * variable so that is matches the home directory of the
     * user that the process is running as. Need to do this as
     * Apache will inherit HOME from root user or user that ran
     * sudo and started Apache and this would be wrong. Can't
     * update HOME for normal Apache child processes as that
     * would change the expected environment of other Apache
     * modules.
     */

#ifndef WIN32
    if (wsgi_daemon_pool) {
        module = PyImport_ImportModule("os");

        if (module) {
            PyObject *dict = NULL;
            PyObject *key = NULL;
            PyObject *value = NULL;

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "environ");

            if (object) {
                struct passwd *pwent;

                pwent = getpwuid(geteuid());
#if PY_MAJOR_VERSION >= 3
                key = PyUnicode_FromString("HOME");
                value = PyUnicode_Decode(pwent->pw_dir, strlen(pwent->pw_dir),
                                         Py_FileSystemDefaultEncoding,
                                         "surrogateescape");
#else
                key = PyString_FromString("HOME");
                value = PyString_FromString(pwent->pw_dir);
#endif

                PyObject_SetItem(object, key, value);

                Py_DECREF(key);
                Py_DECREF(value);
            }

            Py_DECREF(module);
        }
    }
#endif

    /*
     * Explicitly override the PYTHON_EGG_CACHE variable if it
     * was defined by Apache configuration. For embedded processes
     * this would have been done by using WSGIPythonEggs directive.
     * For daemon processes the 'python-eggs' option to the
     * WSGIDaemonProcess directive would have needed to be used.
     */

    if (!wsgi_daemon_pool)
        wsgi_python_eggs = wsgi_server_config->python_eggs;

    if (wsgi_python_eggs) {
        module = PyImport_ImportModule("os");

        if (module) {
            PyObject *dict = NULL;
            PyObject *key = NULL;
            PyObject *value = NULL;

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "environ");

            if (object) {
#if PY_MAJOR_VERSION >= 3
                key = PyUnicode_FromString("PYTHON_EGG_CACHE");
                value = PyUnicode_Decode(wsgi_python_eggs,
                                         strlen(wsgi_python_eggs),
                                         Py_FileSystemDefaultEncoding,
                                         "surrogateescape");
#else
                key = PyString_FromString("PYTHON_EGG_CACHE");
                value = PyString_FromString(wsgi_python_eggs);
#endif

                PyObject_SetItem(object, key, value);

                Py_DECREF(key);
                Py_DECREF(value);
            }

            Py_DECREF(module);
        }
    }

    /*
     * Install user defined Python module search path. This is
     * added using site.addsitedir() so that any Python .pth
     * files are opened and additional directories so defined
     * are added to default Python search path as well. This
     * allows virtual Python environments to work. Note that
     * site.addsitedir() adds new directories at the end of
     * sys.path when they really need to be added in order at
     * the start. We therefore need to do a fiddle and shift
     * any newly added directories to the start of sys.path.
     */

    if (!wsgi_daemon_pool)
        wsgi_python_path = wsgi_server_config->python_path;

    if (wsgi_python_path) {
        PyObject *path = NULL;

        module = PyImport_ImportModule("site");
        path = PySys_GetObject("path");

        if (module && path) {
            PyObject *dict = NULL;

            PyObject *old = NULL;
            PyObject *new = NULL;
            PyObject *tmp = NULL;

            PyObject *item = NULL;

            int i = 0;

            old = PyList_New(0);
            new = PyList_New(0);
            tmp = PyList_New(0);

            for (i=0; i<PyList_Size(path); i++)
                PyList_Append(old, PyList_GetItem(path, i));

            dict = PyModule_GetDict(module);
            object = PyDict_GetItemString(dict, "addsitedir");

            if (object) {
                const char *start;
                const char *end;
                const char *value;

                PyObject *item;
                PyObject *args;

                PyObject *result = NULL;

                Py_INCREF(object);

                start = wsgi_python_path;
                end = strchr(start, DELIM);

                if (end) {
#if PY_MAJOR_VERSION >= 3
                    item = PyUnicode_Decode(start, end-start,
                                            Py_FileSystemDefaultEncoding,
                                            "surrogateescape");
#else
                    item = PyString_FromStringAndSize(start, end-start);
#endif
                    start = end+1;

                    value = PyString_AsString(item);

                    Py_BEGIN_ALLOW_THREADS
                    ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                                 "mod_wsgi (pid=%d): Adding '%s' to "
                                 "path.", getpid(), value);
                    Py_END_ALLOW_THREADS

                    args = Py_BuildValue("(O)", item);
                    result = PyEval_CallObject(object, args);

                    if (!result) {
                        Py_BEGIN_ALLOW_THREADS
                        ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                                     "mod_wsgi (pid=%d): Call to "
                                     "'site.addsitedir()' failed for '%s', "
                                     "stopping.", getpid(), value);
                        Py_END_ALLOW_THREADS
                    }

                    Py_XDECREF(result);
                    Py_DECREF(item);
                    Py_DECREF(args);

                    end = strchr(start, DELIM);

                    while (result && end) {
#if PY_MAJOR_VERSION >= 3
                        item = PyUnicode_Decode(start, end-start,
                                                Py_FileSystemDefaultEncoding,
                                                "surrogateescape");
#else
                        item = PyString_FromStringAndSize(start, end-start);
#endif
                        start = end+1;

                        value = PyString_AsString(item);

                        Py_BEGIN_ALLOW_THREADS
                        ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                                     "mod_wsgi (pid=%d): Adding '%s' to "
                                     "path.", getpid(), value);
                        Py_END_ALLOW_THREADS

                        args = Py_BuildValue("(O)", item);
                        result = PyEval_CallObject(object, args);

                        if (!result) {
                            Py_BEGIN_ALLOW_THREADS
                            ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0),
                                         wsgi_server, "mod_wsgi (pid=%d): "
                                         "Call to 'site.addsitedir()' failed "
                                         "for '%s', stopping.",
                                         getpid(), value);
                            Py_END_ALLOW_THREADS
                        }

                        Py_XDECREF(result);
                        Py_DECREF(item);
                        Py_DECREF(args);

                        end = strchr(start, DELIM);
                    }
                }

                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                             "mod_wsgi (pid=%d): Adding '%s' to "
                             "path.", getpid(), start);
                Py_END_ALLOW_THREADS

                args = Py_BuildValue("(s)", start);
                result = PyEval_CallObject(object, args);

                if (!result) {
                    Py_BEGIN_ALLOW_THREADS
                    ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                                 "mod_wsgi (pid=%d): Call to "
                                 "'site.addsitedir()' failed for '%s'.",
                                 getpid(), start);
                    Py_END_ALLOW_THREADS
                }

                Py_XDECREF(result);
                Py_DECREF(args);

                Py_DECREF(object);
            }
            else {
                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                             "mod_wsgi (pid=%d): Unable to locate "
                             "'site.addsitedir()'.", getpid());
                Py_END_ALLOW_THREADS
            }

            for (i=0; i<PyList_Size(path); i++)
                PyList_Append(tmp, PyList_GetItem(path, i));

            for (i=0; i<PyList_Size(tmp); i++) {
                item = PyList_GetItem(tmp, i);
                if (!PySequence_Contains(old, item)) {
                    int index = PySequence_Index(path, item);
                    PyList_Append(new, item);
                    if (index != -1)
                        PySequence_DelItem(path, index); 
                }
            }

            PyList_SetSlice(path, 0, 0, new);

            Py_DECREF(old);
            Py_DECREF(new);
            Py_DECREF(tmp);
        }
        else {
            if (!module) {
                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                             "mod_wsgi (pid=%d): Unable to import 'site' "
                             "module.", getpid());
                Py_END_ALLOW_THREADS
            }

            if (!path) {
                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                             "mod_wsgi (pid=%d): Lookup for 'sys.path' "
                             "failed.", getpid());
                Py_END_ALLOW_THREADS
            }
        }

        Py_XDECREF(module);
    }

    /*
     * Create 'mod_wsgi' Python module. We first try and import an
     * external Python module of the same name. The intent is
     * that this external module would provide optional features
     * implementable using pure Python code. Don't want to
     * include them in the main Apache mod_wsgi package as that
     * complicates that package and also wouldn't allow them to
     * be released to a separate schedule. It is easier for
     * people to replace Python modules package with a new
     * version than it is to replace Apache module package.
     */

    module = PyImport_ImportModule("mod_wsgi");

    if (!module) {
        PyObject *modules = NULL;

        modules = PyImport_GetModuleDict();
        module = PyDict_GetItemString(modules, "mod_wsgi");

        if (module) {
            PyErr_Print();

            PyDict_DelItemString(modules, "mod_wsgi");
        }

        PyErr_Clear();

        module = PyImport_AddModule("mod_wsgi");

        Py_INCREF(module);
    }
    else if (!*name) {
        Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                     "mod_wsgi (pid=%d): Imported 'mod_wsgi'.",
                     getpid());
        Py_END_ALLOW_THREADS
    }

    /*
     * Add Apache module version information to the Python
     * 'mod_wsgi' module.
     */

    PyModule_AddObject(module, "version", Py_BuildValue("(ii)",
                       MOD_WSGI_MAJORVERSION_NUMBER,
                       MOD_WSGI_MINORVERSION_NUMBER));

    /*
     * Add information about process group and application
     * group to the Python 'mod_wsgi' module.
     */

#if PY_MAJOR_VERSION >= 3
    PyModule_AddObject(module, "process_group",
                       PyUnicode_DecodeLatin1(wsgi_daemon_group,
                       strlen(wsgi_daemon_group), NULL));
    PyModule_AddObject(module, "application_group",
                       PyUnicode_DecodeLatin1(name, strlen(name), NULL));
#else
    PyModule_AddObject(module, "process_group",
                       PyString_FromString(wsgi_daemon_group));
    PyModule_AddObject(module, "application_group",
                       PyString_FromString(name));
#endif

    Py_DECREF(module);

    /*
     * Create 'apache' Python module. If this is not a daemon
     * process and it is the first interpreter created by
     * Python, we first try and import an external Python module
     * of the same name. The intent is that this external module
     * would provide the SWIG bindings for the internal Apache
     * APIs. Only support use of such bindings in the first
     * interpreter created due to threading issues in SWIG
     * generated.
     */

    module = NULL;

    if (!wsgi_daemon_pool) {
        module = PyImport_ImportModule("apache");

        if (!module) {
            PyObject *modules = NULL;

            modules = PyImport_GetModuleDict();
            module = PyDict_GetItemString(modules, "apache");

            if (module) {
                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                             "mod_wsgi (pid=%d): Unable to import "
                             "'apache' extension module.", getpid());
                Py_END_ALLOW_THREADS

                PyErr_Print();

                PyDict_DelItemString(modules, "apache");

                module = NULL;
            }

            PyErr_Clear();
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                         "mod_wsgi (pid=%d): Imported 'apache'.",
                         getpid());
            Py_END_ALLOW_THREADS
        }
    }

    if (!module) {
        module = PyImport_AddModule("apache");

        Py_INCREF(module);
    }

    /*
     * Add Apache version information to the Python 'apache'
     * module.
     */

    PyModule_AddObject(module, "version", Py_BuildValue("(ii)",
                       AP_SERVER_MAJORVERSION_NUMBER,
                       AP_SERVER_MINORVERSION_NUMBER));

    Py_DECREF(module);

    /*
     * Restore previous thread state. Only need to do
     * this where had to create a new interpreter. This
     * is basically anything except the first Python
     * interpreter instance. We need to restore it in
     * these cases as came into the function holding the
     * simplified GIL state for this thread but creating
     * the interpreter has resulted in a new thread
     * state object being created bound to the newly
     * created interpreter. In doing this though we want
     * to cache the thread state object which has been
     * created when interpreter is created. This is so
     * it can be reused later ensuring that thread local
     * data persists between requests.
     */

    if (self->owner) {
#if APR_HAS_THREADS
        int thread_id = 0;
        int *thread_handle = NULL;

        self->tstate_table = apr_hash_make(wsgi_server->process->pool);

        apr_threadkey_private_get((void**)&thread_handle, wsgi_thread_key);

        if (!thread_handle) {
            thread_id = wsgi_thread_count++;
            thread_handle = (int*)apr_pmemdup(wsgi_server->process->pool,
                                              &thread_id, sizeof(thread_id));
            apr_threadkey_private_set(thread_handle, wsgi_thread_key);
        }
        else {
            thread_id = *thread_handle;
        }

        if (wsgi_server_config->verbose_debugging) {
            ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                         "mod_wsgi (pid=%d): Bind thread state for "
                         "thread %d against interpreter '%s'.", getpid(),
                         thread_id, self->name);
        }

        apr_hash_set(self->tstate_table, thread_handle,
                     sizeof(*thread_handle), tstate);

        PyThreadState_Swap(save_tstate);
#else
        self->tstate = tstate;
        PyThreadState_Swap(save_tstate);
#endif
    }

    return self;
}

static void Interpreter_dealloc(InterpreterObject *self)
{
    PyThreadState *tstate = NULL;
    PyObject *exitfunc = NULL;
    PyObject *module = NULL;

    /*
     * We should always enter here with the Python GIL held, but
     * there will be no active thread state. Note that it should
     * be safe to always assume that the simplified GIL state
     * API lock was originally unlocked as always calling in
     * from an Apache thread outside of Python.
     */

    PyEval_ReleaseLock();

    if (*self->name) {
#if APR_HAS_THREADS
        int thread_id = 0;
        int *thread_handle = NULL;

        apr_threadkey_private_get((void**)&thread_handle, wsgi_thread_key);

        if (!thread_handle) {
            thread_id = wsgi_thread_count++;
            thread_handle = (int*)apr_pmemdup(wsgi_server->process->pool,
                                              &thread_id, sizeof(thread_id));
            apr_threadkey_private_set(thread_handle, wsgi_thread_key);
        }
        else {
            thread_id = *thread_handle;
        }

        tstate = apr_hash_get(self->tstate_table, &thread_id,
                              sizeof(thread_id));

        if (!tstate) {
            tstate = PyThreadState_New(self->interp);

            if (wsgi_server_config->verbose_debugging) {
                ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                             "mod_wsgi (pid=%d): Create thread state for "
                             "thread %d against interpreter '%s'.", getpid(),
                             thread_id, self->name);
            }

            apr_hash_set(self->tstate_table, thread_handle,
                         sizeof(*thread_handle), tstate);
        }
#else
        tstate = self->tstate;
#endif

        PyEval_AcquireThread(tstate);
    }
    else
        PyGILState_Ensure();

    if (self->owner) {
        Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                     "mod_wsgi (pid=%d): Destroy interpreter '%s'.",
                     getpid(), self->name);
        Py_END_ALLOW_THREADS
    }
    else {
        Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                     "mod_wsgi (pid=%d): Cleanup interpreter '%s'.",
                     getpid(), self->name);
        Py_END_ALLOW_THREADS
    }

    /*
     * Because the thread state we are using was created outside
     * of any Python code and is not the same as the Python main
     * thread, there is no record of it within the 'threading'
     * module. We thus need to access current thread function of
     * the 'threading' module to force it to create a thread
     * handle for the thread. If we do not do this, then the
     * 'threading' modules exit function will always fail
     * because it will not be able to find a handle for this
     * thread.
     */

    module = PyImport_ImportModule("threading");

    if (!module)
        PyErr_Clear();

    if (module) {
        PyObject *dict = NULL;
        PyObject *func = NULL;

        dict = PyModule_GetDict(module);
#if PY_MAJOR_VERSION >= 3
        func = PyDict_GetItemString(dict, "current_thread");
#else
        func = PyDict_GetItemString(dict, "currentThread");
#endif
        if (func) {
            PyObject *res = NULL;
            Py_INCREF(func);
            res = PyEval_CallObject(func, (PyObject *)NULL);
            if (!res) {
                PyErr_Clear();
            }
            Py_XDECREF(res);
            Py_DECREF(func);
        }
    }

    /*
     * In Python 2.5.1 an exit function is no longer used to
     * shutdown and wait on non daemon threads which were created
     * from Python code. Instead, in Py_Main() it explicitly
     * calls 'threading._shutdown()'. Thus need to emulate this
     * behaviour for those versions.
     */

    if (module) {
        PyObject *dict = NULL;
        PyObject *func = NULL;

        dict = PyModule_GetDict(module);
        func = PyDict_GetItemString(dict, "_shutdown");
        if (func) {
            PyObject *res = NULL;
            Py_INCREF(func);
            res = PyEval_CallObject(func, (PyObject *)NULL);

            if (res == NULL) {
                PyObject *m = NULL;
                PyObject *result = NULL;

                PyObject *type = NULL;
                PyObject *value = NULL;
                PyObject *traceback = NULL;

                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                             "mod_wsgi (pid=%d): Exception occurred within "
                             "threading._shutdown().", getpid());
                Py_END_ALLOW_THREADS

                PyErr_Fetch(&type, &value, &traceback);
                PyErr_NormalizeException(&type, &value, &traceback);

                if (!value) {
                    value = Py_None;
                    Py_INCREF(value);
                }

                if (!traceback) {
                    traceback = Py_None;
                    Py_INCREF(traceback);
                }

                m = PyImport_ImportModule("traceback");

                if (m) {
                    PyObject *d = NULL;
                    PyObject *o = NULL;
                    d = PyModule_GetDict(m);
                    o = PyDict_GetItemString(d, "print_exception");
                    if (o) {
                        PyObject *log = NULL;
                        PyObject *args = NULL;
                        Py_INCREF(o);
                        log = newLogObject(NULL, APLOG_ERR, NULL);
                        args = Py_BuildValue("(OOOOO)", type, value,
                                             traceback, Py_None, log);
                        result = PyEval_CallObject(o, args);
                        Py_DECREF(args);
                        Py_DECREF(log);
                        Py_DECREF(o);
                    }
                }

                if (!result) {
                    /*
                     * If can't output exception and traceback then
                     * use PyErr_Print to dump out details of the
                     * exception. For SystemExit though if we do
                     * that the process will actually be terminated
                     * so can only clear the exception information
                     * and keep going.
                     */

                    PyErr_Restore(type, value, traceback);

                    if (!PyErr_ExceptionMatches(PyExc_SystemExit)) {
                        PyErr_Print();
                        PyErr_Clear();
                    }
                    else {
                        PyErr_Clear();
                    }
                }
                else {
                    Py_XDECREF(type);
                    Py_XDECREF(value);
                    Py_XDECREF(traceback);
                }

                Py_XDECREF(result);

                Py_XDECREF(m);
            }

            Py_XDECREF(res);
            Py_DECREF(func);
        }
    }

    /* Finally done with 'threading' module. */

    Py_XDECREF(module);

    /*
     * Invoke exit functions by calling sys.exitfunc() for
     * Python 2.X and atexit._run_exitfuncs() for Python 3.X.
     * Note that in Python 3.X we can't call this on main Python
     * interpreter as for Python 3.X it doesn't deregister
     * functions as called, so have no choice but to rely on
     * Py_Finalize() to do it for the main interpreter. Now
     * that simplified GIL state API usage sorted out, this
     * should be okay.
     */

    module = NULL;

#if PY_MAJOR_VERSION >= 3
    if (self->owner) {
        module = PyImport_ImportModule("atexit");

        if (module) {
            PyObject *dict = NULL;

            dict = PyModule_GetDict(module);
            exitfunc = PyDict_GetItemString(dict, "_run_exitfuncs");
        }
        else
            PyErr_Clear();
    }
#else
    exitfunc = PySys_GetObject("exitfunc");
#endif

    if (exitfunc) {
        PyObject *res = NULL;
        Py_INCREF(exitfunc);
        PySys_SetObject("exitfunc", (PyObject *)NULL);
        res = PyEval_CallObject(exitfunc, (PyObject *)NULL);

        if (res == NULL) {
            PyObject *m = NULL;
            PyObject *result = NULL;

            PyObject *type = NULL;
            PyObject *value = NULL;
            PyObject *traceback = NULL;

            if (PyErr_ExceptionMatches(PyExc_SystemExit)) {
                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                             "mod_wsgi (pid=%d): SystemExit exception "
                             "raised by exit functions ignored.", getpid());
                Py_END_ALLOW_THREADS
            }
            else {
                Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                             "mod_wsgi (pid=%d): Exception occurred within "
                             "exit functions.", getpid());
                Py_END_ALLOW_THREADS
            }

            PyErr_Fetch(&type, &value, &traceback);
            PyErr_NormalizeException(&type, &value, &traceback);

            if (!value) {
                value = Py_None;
                Py_INCREF(value);
            }

            if (!traceback) {
                traceback = Py_None;
                Py_INCREF(traceback);
            }

            m = PyImport_ImportModule("traceback");

            if (m) {
                PyObject *d = NULL;
                PyObject *o = NULL;
                d = PyModule_GetDict(m);
                o = PyDict_GetItemString(d, "print_exception");
                if (o) {
                    PyObject *log = NULL;
                    PyObject *args = NULL;
                    Py_INCREF(o);
                    log = newLogObject(NULL, APLOG_ERR, NULL);
                    args = Py_BuildValue("(OOOOO)", type, value,
                                         traceback, Py_None, log);
                    result = PyEval_CallObject(o, args);
                    Py_DECREF(args);
                    Py_DECREF(log);
                    Py_DECREF(o);
                }
            }

            if (!result) {
                /*
                 * If can't output exception and traceback then
                 * use PyErr_Print to dump out details of the
                 * exception. For SystemExit though if we do
                 * that the process will actually be terminated
                 * so can only clear the exception information
                 * and keep going.
                 */

                PyErr_Restore(type, value, traceback);

                if (!PyErr_ExceptionMatches(PyExc_SystemExit)) {
                    PyErr_Print();
                    PyErr_Clear();
                }
                else {
                    PyErr_Clear();
                }
            }
            else {
                Py_XDECREF(type);
                Py_XDECREF(value);
                Py_XDECREF(traceback);
            }

            Py_XDECREF(result);

            Py_XDECREF(m);
        }

        Py_XDECREF(res);
        Py_DECREF(exitfunc);
    }

    Py_XDECREF(module);

    /* If we own it, we destroy it. */

    if (!self->owner) {
        if (*self->name) {
            tstate = PyThreadState_Get();

            PyThreadState_Clear(tstate);
            PyEval_ReleaseThread(tstate);
            PyThreadState_Delete(tstate);
        }
        else
            PyGILState_Release(PyGILState_UNLOCKED);

        PyEval_AcquireLock();
    }
    else {
        /*
         * We need to destroy all the thread state objects
         * associated with the interpreter. If there are
         * background threads that were created then this
         * may well cause them to crash the next time they
         * try to run. Only saving grace is that we are
         * trying to shutdown the process.
         */

        PyThreadState *tstate_save = tstate;
        PyThreadState *tstate_next = NULL;

        PyThreadState_Swap(NULL);

        tstate = tstate->interp->tstate_head;
        while (tstate) {
            tstate_next = tstate->next;
            if (tstate != tstate_save) {
                PyThreadState_Swap(tstate);
                PyThreadState_Clear(tstate);
                PyThreadState_Swap(NULL);
                PyThreadState_Delete(tstate);
            }
            tstate = tstate_next;
        }

        tstate = tstate_save;

        PyThreadState_Swap(tstate);

        /* Can now destroy the interpreter. */

        Py_EndInterpreter(tstate);
    }

    free(self->name);

    PyObject_Del(self);
}

static PyTypeObject Interpreter_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "mod_wsgi.Interpreter",  /*tp_name*/
    sizeof(InterpreterObject), /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Interpreter_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    0,                      /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

/*
 * Startup and shutdown of Python interpreter. In mod_wsgi if
 * the Python interpreter hasn't been initialised by another
 * Apache module such as mod_python, we will take control and
 * initialise it. Need to remember that we initialised Python
 * and whether done in parent or child process as when done in
 * the parent we also take responsibility for performing special
 * Python fixups after Apache is forked and child process has
 * run.
 *
 * Note that by default we now defer initialisation of Python
 * until after the fork of processes as Python 3.X by design
 * doesn't clean up properly when it is destroyed causing
 * significant memory leaks into Apache parent process on an
 * Apache restart. Some Python 2.X versions also have real
 * memory leaks but not near as much. The result of deferring
 * initialisation is that can't benefit from copy on write
 * semantics for loaded data across a fork. Each process will
 * therefore have higher memory requirement where Python needs
 * to be used.
 */

static int wsgi_python_initialized = 0;

#if defined(MOD_WSGI_DISABLE_EMBEDDED)
static int wsgi_python_required = 0;
#else
static int wsgi_python_required = -1;
#endif

static int wsgi_python_after_fork = 1;

static void wsgi_python_version(void)
{
    const char *compile = PY_VERSION;
    const char *dynamic = 0;

    dynamic = strtok((char *)Py_GetVersion(), " ");

    if (strcmp(compile, dynamic) != 0) {
        ap_log_error(APLOG_MARK, WSGI_LOG_WARNING(0), wsgi_server,
                     "mod_wsgi: Compiled for Python/%s.", compile);
        ap_log_error(APLOG_MARK, WSGI_LOG_WARNING(0), wsgi_server,
                     "mod_wsgi: Runtime using Python/%s.", dynamic);
    }
}

static apr_status_t wsgi_python_term()
{
    PyInterpreterState *interp = NULL;
    PyThreadState *tstate = NULL;

    PyObject *module = NULL;

    ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                 "mod_wsgi (pid=%d): Terminating Python.", getpid());

    PyGILState_Ensure();

    /*
     * Work around bug in Python 3.X whereby it will crash if
     * atexit imported into sub interpreter, but never imported
     * into main interpreter before calling Py_Finalize(). We
     * perform an import of atexit module and it as side effect
     * must be performing required initialisation.
     */

    module = PyImport_ImportModule("atexit");
    Py_XDECREF(module);

    /*
     * In Python 2.6.5 and Python 3.1.2 the shutdown of
     * threading was moved back into Py_Finalize() for the main
     * Python interpreter. Because we shutting down threading
     * ourselves, the second call results in errors being logged
     * when Py_Finalize() is called and the shutdown function
     * called a second time. The errors don't indicate any real
     * problem and the threading module ignores them anyway.
     * Whether we are using Python with this changed behaviour
     * can only be checked by looking at run time version.
     * Rather than try and add a dynamic check, create a fake
     * 'dummy_threading' module as the presence of that shuts up
     * the messages. It doesn't matter that the rest of the
     * shutdown function still runs as everything is already
     * stopped so doesn't do anything.
     */

    if (!PyImport_AddModule("dummy_threading"))
        PyErr_Clear();

    Py_Finalize();

    wsgi_python_initialized = 0;

    ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                 "mod_wsgi (pid=%d): Python has shutdown.", getpid());

    return APR_SUCCESS;
}

#if AP_SERVER_MAJORVERSION_NUMBER < 2
static void wsgi_python_parent_cleanup(void *data)
#else
static apr_status_t wsgi_python_parent_cleanup(void *data)
#endif
{
    if (wsgi_parent_pid == getpid()) {
        /*
         * Destroy Python itself including the main
         * interpreter. If mod_python is being loaded it
         * is left to mod_python to destroy Python,
         * although it currently doesn't do so.
         */

        if (wsgi_python_initialized)
            wsgi_python_term();
    }

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    return APR_SUCCESS;
#endif
}


static void wsgi_python_init(apr_pool_t *p)
{
#if defined(DARWIN) && (AP_SERVER_MAJORVERSION_NUMBER < 2)
    static int initialized = 0;
#else
    static int initialized = 1;
#endif

    /* Perform initialisation if required. */

    if (!Py_IsInitialized() || !initialized) {

        /* Enable Python 3.0 migration warnings. */

#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 6
        if (wsgi_server_config->py3k_warning_flag == 1)
            Py_Py3kWarningFlag++;
#endif

        /* Check for Python paths and optimisation flag. */

        if (wsgi_server_config->python_optimize > 0)
            Py_OptimizeFlag = wsgi_server_config->python_optimize;
        else
            Py_OptimizeFlag = 0;

        /* Check for control options for Python warnings. */

        if (wsgi_server_config->python_warnings) {
            apr_array_header_t *options = NULL;
            char **entries;

            int i;

            options = wsgi_server_config->python_warnings;
            entries = (char **)options->elts;

            for (i = 0; i < options->nelts; ++i) {
#if PY_MAJOR_VERSION >= 3
                wchar_t *s = NULL;
                int len = strlen(entries[i])+1;

                s = (wchar_t *)apr_palloc(p, len*sizeof(wchar_t));

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
                wsgi_utf8_to_unicode_path(s, len, entries[i]);
#else
                mbstowcs(s, entries[i], len);
#endif
                PySys_AddWarnOption(s);
#else
                PySys_AddWarnOption(entries[i]);
#endif
            }
        }

        /* Check for Python HOME being overridden. */

#if PY_MAJOR_VERSION >= 3
        if (wsgi_server_config->python_home) {
            wchar_t *s = NULL;
            int len = strlen(wsgi_server_config->python_home)+1;

            ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                         "mod_wsgi (pid=%d): Python home %s.", getpid(),
                         wsgi_server_config->python_home);

            s = (wchar_t *)apr_palloc(p, len*sizeof(wchar_t));

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
            wsgi_utf8_to_unicode_path(s, len, wsgi_server_config->python_home);
#else
            mbstowcs(s, wsgi_server_config->python_home, len);
#endif
            Py_SetPythonHome(s);
        }
#else
        if (wsgi_server_config->python_home) {
            ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                         "mod_wsgi (pid=%d): Python home %s.", getpid(),
                         wsgi_server_config->python_home);

            Py_SetPythonHome((char *)wsgi_server_config->python_home);
        }
#endif

        /*
         * Work around bug in Python 3.1 where it will crash
         * when used in non console application on Windows if
         * stdin/stdout have been initialised and aren't null.
         */

#if defined(WIN32) && PY_MAJOR_VERSION >= 3
        _wputenv(L"PYTHONIOENCODING=cp1252:backslashreplace");
#endif

        /* Initialise Python. */

        ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                     "mod_wsgi (pid=%d): Initializing Python.", getpid());

        initialized = 1;

        Py_Initialize();

        /* Initialise threading. */

        PyEval_InitThreads();
        PyThreadState_Swap(NULL);
        PyEval_ReleaseLock();

        wsgi_python_initialized = 1;

    /*
     * Register cleanups to be performed on parent restart
     * or shutdown. This will destroy Python itself.
     */

#if AP_SERVER_MAJORVERSION_NUMBER < 2
        ap_register_cleanup(p, NULL, wsgi_python_parent_cleanup,
                            ap_null_cleanup);
#else
        apr_pool_cleanup_register(p, NULL, wsgi_python_parent_cleanup,
                                  apr_pool_cleanup_null);
#endif
    }
}

/*
 * Functions for acquiring and subsequently releasing desired
 * Python interpreter instance. When acquiring the interpreter
 * a new interpreter instance will be created on demand if it
 * is required. The Python GIL will be held on return when the
 * interpreter is acquired.
 */

#if APR_HAS_THREADS
static apr_thread_mutex_t* wsgi_interp_lock = NULL;
static apr_thread_mutex_t* wsgi_module_lock = NULL;
#endif

static PyObject *wsgi_interpreters = NULL;

static InterpreterObject *wsgi_acquire_interpreter(const char *name)
{
    PyThreadState *tstate = NULL;
    PyInterpreterState *interp = NULL;
    InterpreterObject *handle = NULL;

    PyGILState_STATE state;

    /*
     * In a multithreaded MPM must protect the
     * interpreters table. This lock is only needed to
     * avoid a secondary thread coming in and creating
     * the same interpreter if Python releases the GIL
     * when an interpreter is being created.
     */

#if APR_HAS_THREADS
    apr_thread_mutex_lock(wsgi_interp_lock);
#endif

    /*
     * This function should never be called when the
     * Python GIL is held, so need to acquire it.
     */

    state = PyGILState_Ensure();

    /*
     * Check if already have interpreter instance and
     * if not need to create one.
     */

    handle = (InterpreterObject *)PyDict_GetItemString(wsgi_interpreters,
                                                       name);

    if (!handle) {
        handle = newInterpreterObject(name);

        if (!handle) {
            ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(0), wsgi_server,
                         "mod_wsgi (pid=%d): Cannot create interpreter '%s'.",
                         getpid(), name);

            PyErr_Print();
            PyErr_Clear();

            PyGILState_Release(state);

#if APR_HAS_THREADS
            apr_thread_mutex_unlock(wsgi_interp_lock);
#endif
            return NULL;
        }

        PyDict_SetItemString(wsgi_interpreters, name, (PyObject *)handle);
    }
    else
        Py_INCREF(handle);

    interp = handle->interp;

    /*
     * Create new thread state object. We should only be
     * getting called where no current active thread
     * state, so no need to remember the old one. When
     * working with the main Python interpreter always
     * use the simplified API for GIL locking so any
     * extension modules which use that will still work.
     */

    PyGILState_Release(state);

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_interp_lock);
#endif

    if (*name) {
#if APR_HAS_THREADS
        int thread_id = 0;
        int *thread_handle = NULL;

        apr_threadkey_private_get((void**)&thread_handle, wsgi_thread_key);

        if (!thread_handle) {
            thread_id = wsgi_thread_count++;
            thread_handle = (int*)apr_pmemdup(wsgi_server->process->pool,
                                              &thread_id, sizeof(thread_id));
            apr_threadkey_private_set(thread_handle, wsgi_thread_key);
        }
        else {
            thread_id = *thread_handle;
        }

        tstate = apr_hash_get(handle->tstate_table, &thread_id,
                              sizeof(thread_id));

        if (!tstate) {
            tstate = PyThreadState_New(interp);

            if (wsgi_server_config->verbose_debugging) {
                ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                             "mod_wsgi (pid=%d): Create thread state for "
                             "thread %d against interpreter '%s'.", getpid(),
                             thread_id, handle->name);
            }

            apr_hash_set(handle->tstate_table, thread_handle,
                         sizeof(*thread_handle), tstate);
        }
#else
        tstate = handle->tstate;
#endif

        PyEval_AcquireThread(tstate);
    }
    else {
        PyGILState_Ensure();

        /*
         * When simplified GIL state API is used, the thread
         * local data only persists for the extent of the top
         * level matching ensure/release calls. We want to
         * extend lifetime of the thread local data beyond
         * that, retaining it for all requests within the one
         * thread for the life of the process. To do that we
         * need to artificially increment the reference count
         * for the associated thread state object.
         */

        tstate = PyThreadState_Get();
        if (tstate && tstate->gilstate_counter == 1)
            tstate->gilstate_counter++;
    }

    return handle;
}

static void wsgi_release_interpreter(InterpreterObject *handle)
{
    PyThreadState *tstate = NULL;

    /*
     * Need to release and destroy the thread state that
     * was created against the interpreter. This will
     * release the GIL. Note that it should be safe to
     * always assume that the simplified GIL state API
     * lock was originally unlocked as always calling in
     * from an Apache thread when we acquire the
     * interpreter in the first place.
     */

    if (*handle->name) {
        tstate = PyThreadState_Get();
        PyEval_ReleaseThread(tstate);
    }
    else
        PyGILState_Release(PyGILState_UNLOCKED);

    /*
     * Need to reacquire the Python GIL just so we can
     * decrement our reference count to the interpreter
     * itself. If the interpreter has since been removed
     * from the table of interpreters this will result
     * in its destruction if its the last reference.
     */

    PyEval_AcquireLock();

    Py_DECREF(handle);

    PyEval_ReleaseLock();
}

/*
 * Code for importing a module from source by absolute path.
 */

static PyObject *wsgi_load_source(apr_pool_t *pool, request_rec *r,
                                  const char *name, int exists,
                                  const char* filename,
                                  const char *process_group,
                                  const char *application_group)
{
    FILE *fp = NULL;
    PyObject *m = NULL;
    PyObject *co = NULL;
    struct _node *n = NULL;

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
    apr_wchar_t wfilename[APR_PATH_MAX];
#endif

    if (exists) {
        Py_BEGIN_ALLOW_THREADS
        if (r) {
            ap_log_rerror(APLOG_MARK, WSGI_LOG_INFO(0), r,
                          "mod_wsgi (pid=%d, process='%s', application='%s'): "
                          "Reloading WSGI script '%s'.", getpid(),
                          process_group, application_group, filename);
        }
        else {
            ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                         "mod_wsgi (pid=%d, process='%s', application='%s'): "
                         "Reloading WSGI script '%s'.", getpid(),
                         process_group, application_group, filename);
        }
        Py_END_ALLOW_THREADS
    }
    else {
        Py_BEGIN_ALLOW_THREADS
        if (r) {
            ap_log_rerror(APLOG_MARK, WSGI_LOG_INFO(0), r,
                          "mod_wsgi (pid=%d, process='%s', application='%s'): "
                          "Loading WSGI script '%s'.", getpid(),
                          process_group, application_group, filename);
        }
        else {
            ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                         "mod_wsgi (pid=%d, process='%s', application='%s'): "
                         "Loading WSGI script '%s'.", getpid(),
                         process_group, application_group, filename);
        }
        Py_END_ALLOW_THREADS
    }

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
    if (wsgi_utf8_to_unicode_path(wfilename, sizeof(wfilename) /
                                  sizeof(apr_wchar_t), filename)) {

        Py_BEGIN_ALLOW_THREADS
        if (r) {
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                          "mod_wsgi (pid=%d, process='%s', "
                          "application='%s'): Failed to convert '%s' "
                          "to UCS2 filename.", getpid(),
                          process_group, application_group, filename);
        }
        else {
            ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                         "mod_wsgi (pid=%d, process='%s', "
                         "application='%s'): Failed to convert '%s' "
                         "to UCS2 filename.", getpid(),
                         process_group, application_group, filename);
        }
        Py_END_ALLOW_THREADS
        return NULL;
    }

    fp = _wfopen(wfilename, "r");
#else
    fp = fopen(filename, "r");
#endif

    if (!fp) {
        Py_BEGIN_ALLOW_THREADS
        if (r) {
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(errno), r,
                          "mod_wsgi (pid=%d, process='%s', application='%s'): "
                          "Call to fopen() failed for '%s'.", getpid(),
                          process_group, application_group, filename);
        }
        else {
            ap_log_error(APLOG_MARK, WSGI_LOG_ERR(errno), wsgi_server,
                         "mod_wsgi (pid=%d, process='%s', application='%s'): "
                         "Call to fopen() failed for '%s'.", getpid(),
                         process_group, application_group, filename);
        }
        Py_END_ALLOW_THREADS
        return NULL;
    }

    n = PyParser_SimpleParseFile(fp, filename, Py_file_input);

    fclose(fp);

    if (!n) {
        Py_BEGIN_ALLOW_THREADS
        if (r) {
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                          "mod_wsgi (pid=%d, process='%s', application='%s'): "
                          "Failed to parse WSGI script file '%s'.", getpid(),
                          process_group, application_group, filename);
        }
        else {
            ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                         "mod_wsgi (pid=%d, process='%s', application='%s'): "
                         "Failed to parse WSGI script file '%s'.", getpid(),
                         process_group, application_group, filename);
        }
        Py_END_ALLOW_THREADS
        return NULL;
    }

    co = (PyObject *)PyNode_Compile(n, filename);
    PyNode_Free(n);

    if (co)
        m = PyImport_ExecCodeModuleEx((char *)name, co, (char *)filename);

    Py_XDECREF(co);

    if (m) {
        PyObject *object = NULL;

        if (!r || strcmp(r->filename, filename)) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
            struct stat finfo;
            if (stat(filename, &finfo) == -1) {
                object = PyLong_FromLongLong(0);
            }
            else {
                object = PyLong_FromLongLong(finfo.st_mtime);
            }
#else
            apr_finfo_t finfo;
            if (apr_stat(&finfo, filename, APR_FINFO_NORM,
                         pool) != APR_SUCCESS) {
                object = PyLong_FromLongLong(0);
            }
            else {
                object = PyLong_FromLongLong(finfo.mtime);
            }
#endif
        }
        else {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
            object = PyLong_FromLongLong(r->finfo.st_mtime);
#else
            object = PyLong_FromLongLong(r->finfo.mtime);
#endif
        }
        PyModule_AddObject(m, "__mtime__", object);
    }
    else {
        Py_BEGIN_ALLOW_THREADS
        if (r) {
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                          "mod_wsgi (pid=%d): Target WSGI script '%s' cannot "
                          "be loaded as Python module.", getpid(), filename);
        }
        else {
            ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                         "mod_wsgi (pid=%d): Target WSGI script '%s' cannot "
                         "be loaded as Python module.", getpid(), filename);
        }
        Py_END_ALLOW_THREADS

        wsgi_log_python_error(r, NULL, filename);
    }

    return m;
}

static int wsgi_reload_required(apr_pool_t *pool, request_rec *r,
                                const char *filename, PyObject *module,
                                const char *resource)
{
    PyObject *dict = NULL;
    PyObject *object = NULL;
    apr_time_t mtime = 0;

    dict = PyModule_GetDict(module);
    object = PyDict_GetItemString(dict, "__mtime__");

    if (object) {
        mtime = PyLong_AsLongLong(object);

        if (!r || strcmp(r->filename, filename)) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
            struct stat finfo;
            if (stat(filename, &finfo) == -1) {
                return 1;
            }
            else if (mtime != finfo.st_mtime) {
                return 1;
            }
#else
            apr_finfo_t finfo;
            if (apr_stat(&finfo, filename, APR_FINFO_NORM,
                         pool) != APR_SUCCESS) {
                return 1;
            }
            else if (mtime != finfo.mtime) {
                return 1;
            }
#endif
        }
        else {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
            if (mtime != r->finfo.st_mtime)
                return 1;
#else
            if (mtime != r->finfo.mtime)
                return 1;
#endif
        }
    }
    else
        return 1;

    if (resource) {
        PyObject *dict = NULL;
        PyObject *object = NULL;

        dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(dict, "reload_required");

        if (object) {
            PyObject *args = NULL;
            PyObject *result = NULL;

            Py_INCREF(object);
            args = Py_BuildValue("(s)", resource);
            result = PyEval_CallObject(object, args);
            Py_DECREF(args);
            Py_DECREF(object);

            if (result && PyObject_IsTrue(result)) {
                Py_DECREF(result);

                return 1;
            }

            if (PyErr_Occurred())
                wsgi_log_python_error(r, NULL, filename);

            Py_XDECREF(result);
        }
    }

    return 0;
}

static char *wsgi_module_name(apr_pool_t *pool, const char *filename)
{
    char *hash = NULL;
    char *file = NULL;

    /*
     * Calculate a name for the module using the MD5 of its full
     * pathname. This is so that different code files with the
     * same basename are still considered unique. Note that where
     * we believe a case insensitive file system is being used,
     * we always change the file name to lower case so that use
     * of different case in name doesn't result in duplicate
     * modules being loaded for the same file.
     */

    file = (char *)filename;

    if (wsgi_server_config->case_sensitivity) {
        file = apr_pstrdup(pool, file);
        ap_str_tolower(file);
    }

    hash = ap_md5(pool, (const unsigned char *)file);
    return apr_pstrcat(pool, "_mod_wsgi_", hash, NULL);
}

static int wsgi_execute_script(request_rec *r)
{
    WSGIRequestConfig *config = NULL;

    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    const char *script = NULL;
    const char *name = NULL;
    int exists = 0;

    int status;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    interp = wsgi_acquire_interpreter(config->application_group);

    if (!interp) {
        ap_log_rerror(APLOG_MARK, WSGI_LOG_CRIT(0), r,
                      "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                      getpid(), config->application_group);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Calculate the Python module name to be used for script. */

    if (config->handler_script && *config->handler_script)
        script = config->handler_script;
    else
        script = r->filename;

    name = wsgi_module_name(r->pool, script);

    /*
     * Use a lock around the check to see if the module is
     * already loaded and the import of the module to prevent
     * two request handlers trying to import the module at the
     * same time.
     */

#if APR_HAS_THREADS
    Py_BEGIN_ALLOW_THREADS
    apr_thread_mutex_lock(wsgi_module_lock);
    Py_END_ALLOW_THREADS
#endif

    modules = PyImport_GetModuleDict();
    module = PyDict_GetItemString(modules, name);

    Py_XINCREF(module);

    if (module)
        exists = 1;

    /*
     * If script reloading is enabled and the module for it has
     * previously been loaded, see if it has been modified since
     * the last time it was accessed. For a handler script will
     * also see if it contains a custom function for determining
     * if a reload should be performed.
     */

    if (module && config->script_reloading) {
        if (wsgi_reload_required(r->pool, r, script, module, r->filename)) {
            /*
             * Script file has changed. Discard reference to
             * loaded module and work out what action we are
             * supposed to take. Choices are process reloading
             * and module reloading. Process reloading cannot be
             * performed unless a daemon process is being used.
             */

            Py_DECREF(module);
            module = NULL;

#if defined(MOD_WSGI_WITH_DAEMONS)
            if (*config->process_group) {
                /*
                 * Need to restart the daemon process. We bail
                 * out on the request process here, sending back
                 * a special response header indicating that
                 * process is being restarted and that remote
                 * end should abandon connection and attempt to
                 * reconnect again. We also need to signal this
                 * process so it will actually shutdown. The
                 * process supervisor code will ensure that it
                 * is restarted.
                 */

                Py_BEGIN_ALLOW_THREADS
                ap_log_rerror(APLOG_MARK, WSGI_LOG_INFO(0), r,
                             "mod_wsgi (pid=%d): Force restart of "
                             "process '%s'.", getpid(),
                             config->process_group);
                Py_END_ALLOW_THREADS

#if APR_HAS_THREADS
                apr_thread_mutex_unlock(wsgi_module_lock);
#endif

                wsgi_release_interpreter(interp);

                r->status = HTTP_INTERNAL_SERVER_ERROR;
                r->status_line = "0 Rejected";

                wsgi_daemon_shutdown++;
                kill(getpid(), SIGINT);

                return OK;
            }
            else {
                /*
                 * Need to reload just the script module. Remove
                 * the module from the modules dictionary before
                 * reloading it again. If code is executing
                 * within the module at the time, the callers
                 * reference count on the module should ensure
                 * it isn't actually destroyed until it is
                 * finished.
                 */

                PyDict_DelItemString(modules, name);
            }
#else
            /*
             * Need to reload just the script module. Remove
             * the module from the modules dictionary before
             * reloading it again. If code is executing
             * within the module at the time, the callers
             * reference count on the module should ensure
             * it isn't actually destroyed until it is
             * finished.
             */

            PyDict_DelItemString(modules, name);
#endif
        }
    }

    /*
     * When process reloading is in use need to indicate
     * that request content should now be sent through.
     * This is done by writing a special response header
     * directly out onto the appropriate network output
     * filter. The special response is picked up by
     * remote end and data will then be sent.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (*config->process_group) {
        ap_filter_t *filters;
        apr_bucket_brigade *bb;
        apr_bucket *b;

        const char *data = "Status: 0 Continue\r\n\r\n";
        int length = strlen(data);

        filters = r->output_filters;
        while (filters && filters->frec->ftype != AP_FTYPE_NETWORK) {
            filters = filters->next;
        }

        bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

        b = apr_bucket_transient_create(data, length,
                                        r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);

        b = apr_bucket_flush_create(r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);

        /*
         * This should always work, so ignore any errors
         * from passing the brigade to the network
         * output filter. If there are are problems they
         * will be picked up further down in processing
         * anyway.
         */

        ap_pass_brigade(filters, bb);
    }
#endif

    /* Load module if not already loaded. */

    if (!module) {
        module = wsgi_load_source(r->pool, r, name, exists, script,
                                  config->process_group,
                                  config->application_group);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Assume an internal server error unless everything okay. */

    status = HTTP_INTERNAL_SERVER_ERROR;

    /* Determine if script exists and execute it. */

    if (module) {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;

        module_dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(module_dict, config->callable_object);

        if (object) {
            AdapterObject *adapter = NULL;
            adapter = newAdapterObject(r);

            if (adapter) {
                PyObject *method = NULL;
                PyObject *args = NULL;

                Py_INCREF(object);
                status = Adapter_run(adapter, object);
                Py_DECREF(object);

                /*
                 * Wipe out references to Apache request object
                 * held by Python objects, so can detect when an
                 * application holds on to the transient Python
                 * objects beyond the life of the request and
                 * thus raise an exception if they are used.
                 */

                adapter->r = NULL;
                adapter->input->r = NULL;

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method) {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else {
                    args = PyTuple_New(0);
                    object = PyEval_CallObject(method, args);
                    Py_DECREF(args);
                }

                Py_XDECREF(object);
                Py_XDECREF(method);

#if defined(MOD_WSGI_WITH_BUCKETS)
                adapter->bb = NULL;
#endif
            }

            Py_XDECREF((PyObject *)adapter);
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                          "mod_wsgi (pid=%d): Target WSGI script '%s' does "
                          "not contain WSGI application '%s'.",
                          getpid(), script, config->callable_object);
            Py_END_ALLOW_THREADS

            status = HTTP_NOT_FOUND;
        }
    }

    /* Log any details of exceptions if execution failed. */

    if (PyErr_Occurred())
        wsgi_log_python_error(r, NULL, r->filename);

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    return status;
}

/*
 * Apache child process initialisation and cleanup. Initialise
 * global table containing Python interpreter instances and
 * cache reference to main interpreter. Also register cleanup
 * function to delete interpreter on process shutdown.
 */

#if AP_SERVER_MAJORVERSION_NUMBER < 2
static void wsgi_python_child_cleanup(void *data)
#else
static apr_status_t wsgi_python_child_cleanup(void *data)
#endif
{
    PyObject *interp = NULL;

    /* In a multithreaded MPM must protect table. */

#if APR_HAS_THREADS
    apr_thread_mutex_lock(wsgi_interp_lock);
#endif

    PyEval_AcquireLock();

    /*
     * Extract a handle to the main Python interpreter from
     * interpreters dictionary as want to process that one last.
     */

    interp = PyDict_GetItemString(wsgi_interpreters, "");
    Py_INCREF(interp);

    /*
     * Remove all items from interpreters dictionary. This will
     * have side affect of calling any exit functions and
     * destroying interpreters we own.
     */

    ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                 "mod_wsgi (pid=%d): Destroying interpreters.", getpid());

    PyDict_Clear(wsgi_interpreters);

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_interp_lock);
#endif

    /*
     * Now we decrement reference on handle for main Python
     * interpreter. This only causes exit functions to be called
     * and doesn't result in interpreter being destroyed as we
     * we didn't previously mark ourselves as the owner of the
     * interpreter. Note that when Python as a whole is later
     * being destroyed it will also call exit functions, but by
     * then the exit function registrations have been removed
     * and so they will not actually be run a second time.
     */

    Py_DECREF(interp);

    PyEval_ReleaseLock();

    /*
     * Destroy Python itself including the main interpreter.
     * If mod_python is being loaded it is left to mod_python to
     * destroy Python, although it currently doesn't do so.
     */

    if (wsgi_python_initialized)
        wsgi_python_term();

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    return APR_SUCCESS;
#endif
}

static void wsgi_python_child_init(apr_pool_t *p)
{
    PyGILState_STATE state;
    PyInterpreterState *interp = NULL;
    PyObject *object = NULL;

    int thread_id = 0;
    int *thread_handle = NULL;

    /* Working with Python, so must acquire GIL. */

    state = PyGILState_Ensure();

    /*
     * Trigger any special Python stuff required after a fork.
     * Only do this though if we were responsible for the
     * initialisation of the Python interpreter in the first
     * place to avoid it being done multiple times. Also only
     * do it if Python was initialised in parent process.
     */

    if (wsgi_python_initialized && !wsgi_python_after_fork)
        PyOS_AfterFork();

    /* Finalise any Python objects required by child process. */

    PyType_Ready(&Log_Type);
    PyType_Ready(&Stream_Type);
    PyType_Ready(&Input_Type);
    PyType_Ready(&Adapter_Type);
    PyType_Ready(&Restricted_Type);
    PyType_Ready(&Interpreter_Type);
    PyType_Ready(&Dispatch_Type);

#if defined(MOD_WSGI_WITH_AAA_HANDLERS)
    PyType_Ready(&Auth_Type);
#endif

    /* Initialise Python interpreter instance table and lock. */

    wsgi_interpreters = PyDict_New();

#if APR_HAS_THREADS
    apr_thread_mutex_create(&wsgi_interp_lock, APR_THREAD_MUTEX_UNNESTED, p);
    apr_thread_mutex_create(&wsgi_module_lock, APR_THREAD_MUTEX_UNNESTED, p);
#endif

    /*
     * Initialise the key for data related to a thread. At
     * the moment we only record an integer thread ID to be
     * used in lookup table to thread states associated with
     * an interprter.
     */

#if APR_HAS_THREADS
    apr_threadkey_private_create(&wsgi_thread_key, NULL, p);

    thread_id = wsgi_thread_count++;
    thread_handle = (int*)apr_pmemdup(wsgi_server->process->pool,
                                      &thread_id, sizeof(thread_id));
    apr_threadkey_private_set(thread_handle, wsgi_thread_key);
#endif

    /*
     * Cache a reference to the first Python interpreter
     * instance. This interpreter is special as some third party
     * Python modules will only work when used from within this
     * interpreter. This is generally when they use the Python
     * simplified GIL API or otherwise don't use threading API
     * properly. An empty string for name is used to identify
     * the first Python interpreter instance.
     */

    object = (PyObject *)newInterpreterObject(NULL);
    PyDict_SetItemString(wsgi_interpreters, "", object);
    Py_DECREF(object);

    /* Restore the prior thread state and release the GIL. */

    PyGILState_Release(state);

    /* Register cleanups to performed on process shutdown. */

#if AP_SERVER_MAJORVERSION_NUMBER < 2
    ap_register_cleanup(p, NULL, wsgi_python_child_cleanup,
                        ap_null_cleanup);
#else
    apr_pool_cleanup_register(p, NULL, wsgi_python_child_cleanup,
                              apr_pool_cleanup_null);
#endif

    /* Loop through import scripts for this process and load them. */

    if (wsgi_import_list) {
        apr_array_header_t *scripts = NULL;

        WSGIScriptFile *entries;
        WSGIScriptFile *entry;

        int i;

        scripts = wsgi_import_list;
        entries = (WSGIScriptFile *)scripts->elts;

        for (i = 0; i < scripts->nelts; ++i) {
            int l = 0;

            entry = &entries[i];

            if (!strcmp(wsgi_daemon_group, entry->process_group)) {
                InterpreterObject *interp = NULL;
                PyObject *modules = NULL;
                PyObject *module = NULL;
                char *name = NULL;
                int exists = 0;

                interp = wsgi_acquire_interpreter(entry->application_group);

                if (!interp) {
                    ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(0), wsgi_server,
                                  "mod_wsgi (pid=%d): Cannot acquire "
                                  "interpreter '%s'.", getpid(),
                                  entry->application_group);
                }

                /* Calculate the Python module name to be used for script. */

                name = wsgi_module_name(p, entry->handler_script);

                /*
                 * Use a lock around the check to see if the module is
                 * already loaded and the import of the module. Strictly
                 * speaking shouldn't be required at this point.
                 */

#if APR_HAS_THREADS
                Py_BEGIN_ALLOW_THREADS
                apr_thread_mutex_lock(wsgi_module_lock);
                Py_END_ALLOW_THREADS
#endif

                modules = PyImport_GetModuleDict();
                module = PyDict_GetItemString(modules, name);

                Py_XINCREF(module);

                if (module)
                    exists = 1;

                /*
                 * If script reloading is enabled and the module for it has
                 * previously been loaded, see if it has been modified since
                 * the last time it was accessed.
                 */

                if (module && wsgi_server_config->script_reloading) {
                    if (wsgi_reload_required(p, NULL, entry->handler_script,
                                             module, NULL)) {
                        /*
                         * Script file has changed. Only support module
                         * reloading for dispatch scripts. Remove the
                         * module from the modules dictionary before
                         * reloading it again. If code is executing within
                         * the module at the time, the callers reference
                         * count on the module should ensure it isn't
                         * actually destroyed until it is finished.
                         */

                        Py_DECREF(module);
                        module = NULL;

                        PyDict_DelItemString(modules, name);
                    }
                }

                if (!module) {
                    module = wsgi_load_source(p, NULL, name, exists,
                                              entry->handler_script,
                                              entry->process_group,
                                              entry->application_group);

                    if (PyErr_Occurred()) 
                        PyErr_Clear(); 
                }

                /* Safe now to release the module lock. */

#if APR_HAS_THREADS
                apr_thread_mutex_unlock(wsgi_module_lock);
#endif

                /* Cleanup and release interpreter, */

                Py_XDECREF(module);

                wsgi_release_interpreter(interp);
            }
        }
    }
}

/* The processors for directives. */

static int wsgi_parse_option(apr_pool_t *p, const char **line,
                             const char **name, const char **value)
{
    const char *str = *line, *strend;

    while (*str && apr_isspace(*str))
        ++str;

    if (!*str || *str == '=') {
        *line = str;
        return !APR_SUCCESS;
    }

    /* Option must be of form name=value. Extract the name. */

    strend = str;
    while (*strend && *strend != '=' && !apr_isspace(*strend))
        ++strend;

    if (*strend != '=') {
        *line = str;
        return !APR_SUCCESS;
    }

    *name = apr_pstrndup(p, str, strend-str);

    *line = strend+1;

    /* Now extract the value. Note that value can be quoted. */

    *value = ap_getword_conf(p, line);

    return APR_SUCCESS;
}

static const char *wsgi_add_script_alias(cmd_parms *cmd, void *mconfig,
                                         const char *args)
{
    const char *l = NULL;
    const char *a = NULL;

    WSGIServerConfig *sconfig = NULL;
    WSGIAliasEntry *entry = NULL;

    const char *option = NULL;
    const char *value = NULL;

#if defined(MOD_WSGI_WITH_DAEMONS)
    const char *process_group = NULL;
#else
    const char *process_group = "";
#endif

    const char *application_group = NULL;
    const char *callable_object = NULL;

    int pass_authorization = -1;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (!sconfig->alias_list) {
        sconfig->alias_list = apr_array_make(sconfig->pool, 20,
                                            sizeof(WSGIAliasEntry));
    }

    l = ap_getword_conf(cmd->pool, &args);

    if (*l == '\0' || *args == 0) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " requires at least two arguments",
                           cmd->cmd->errmsg ? ", " : NULL,
                           cmd->cmd->errmsg, NULL);
    }

    a = ap_getword_conf(cmd->pool, &args);

    if (*a == '\0') {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " requires at least two arguments",
                           cmd->cmd->errmsg ? ", " : NULL,
                           cmd->cmd->errmsg, NULL);
    }

    while (*args) {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS) {
            return "Invalid option to WSGI script alias definition.";
        }

        if (!cmd->info && !strcmp(option, "application-group")) {
            if (!*value)
                return "Invalid name for WSGI application group.";

            if (!strcmp(value, "%{GLOBAL}"))
                value = "";

            application_group = value;
        }
#if defined(MOD_WSGI_WITH_DAEMONS)
        else if (!cmd->info && !strcmp(option, "process-group")) {
            if (!*value)
                return "Invalid name for WSGI process group.";

            if (!strcmp(value, "%{GLOBAL}"))
                value = "";

            process_group = value;
        }
#endif
        else if (!strcmp(option, "callable-object")) {
            if (!*value)
                return "Invalid name for WSGI callable object.";

            callable_object = value;
        }
        else if (!strcmp(option, "pass-authorization")) {
            if (!*value)
                return "Invalid value for authorization flag.";

            if (strcasecmp(value, "Off") == 0)
                pass_authorization = 0;
            else if (strcasecmp(value, "On") == 0)
                pass_authorization = 1;
            else
                return "Invalid value for authorization flag.";
        }
        else
            return "Invalid option to WSGI script alias definition.";
    }

    entry = (WSGIAliasEntry *)apr_array_push(sconfig->alias_list);

    if (cmd->info) {
        entry->regexp = ap_pregcomp(cmd->pool, l, AP_REG_EXTENDED);
        if (!entry->regexp)
            return "Regular expression could not be compiled.";
    }

    entry->location = l;
    entry->application = a;

    entry->process_group = process_group;
    entry->application_group = application_group;
    entry->callable_object = callable_object;
    entry->pass_authorization = pass_authorization;

    if (process_group && application_group &&
        !strstr(process_group, "%{") &&
        !strstr(application_group, "%{")) {

        WSGIScriptFile *object = NULL;

        if (!wsgi_import_list) {
            wsgi_import_list = apr_array_make(sconfig->pool, 20,
                                              sizeof(WSGIScriptFile));
        }

        object = (WSGIScriptFile *)apr_array_push(wsgi_import_list);

        object->handler_script = a;
        object->process_group = process_group;
        object->application_group = application_group;

#if defined(MOD_WSGI_WITH_DAEMONS)
        if (*object->process_group) {
            WSGIProcessGroup *group = NULL;
            WSGIProcessGroup *entries = NULL;
            WSGIProcessGroup *entry = NULL;
            int i;

            if (!wsgi_daemon_list)
                return "WSGI process group not yet configured.";

            entries = (WSGIProcessGroup *)wsgi_daemon_list->elts;

            for (i = 0; i < wsgi_daemon_list->nelts; ++i) {
                entry = &entries[i];

                if (!strcmp(entry->name, object->process_group)) {
                    group = entry;
                    break;
                }
            }

            if (!group)
                return "WSGI process group not yet configured.";

            if (group->server != cmd->server && group->server->is_virtual)
                return "WSGI process group not accessible.";
        }
#endif
    }

    return NULL;
}

static const char *wsgi_set_verbose_debugging(cmd_parms *cmd, void *mconfig,
                                              const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->verbose_debugging = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->verbose_debugging = 1;
    else
        return "WSGIVerboseDebugging must be one of: Off | On";

    return NULL;
}

static const char *wsgi_set_lazy_initialization(cmd_parms *cmd, void *mconfig,
                                                const char *f)
{
    const char *error = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    if (strcasecmp(f, "Off") == 0)
        wsgi_python_after_fork = 0;
    else if (strcasecmp(f, "On") == 0)
        wsgi_python_after_fork = 1;
    else
        return "WSGILazyInitialization must be one of: Off | On";

    return NULL;
}

static const char *wsgi_add_python_warnings(cmd_parms *cmd, void *mconfig,
                                            const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    char **entry = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (!sconfig->python_warnings) {
        sconfig->python_warnings = apr_array_make(sconfig->pool, 5,
                                                  sizeof(char*));
    }

    entry = (char **)apr_array_push(sconfig->python_warnings);
    *entry = apr_pstrdup(sconfig->pool, f);

    return NULL;
}

static const char *wsgi_set_py3k_warning_flag(cmd_parms *cmd, void *mconfig,
                                              const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->py3k_warning_flag = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->py3k_warning_flag = 1;
    else
        return "WSGIPy3kWarningFlag must be one of: Off | On";

    return NULL;
}

static const char *wsgi_set_python_optimize(cmd_parms *cmd, void *mconfig,
                                            const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->python_optimize = atoi(f);

    return NULL;
}

static const char *wsgi_set_python_home(cmd_parms *cmd, void *mconfig,
                                        const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->python_home = f;

    return NULL;
}

static const char *wsgi_set_python_path(cmd_parms *cmd, void *mconfig,
                                        const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->python_path = f;

    return NULL;
}

static const char *wsgi_set_python_eggs(cmd_parms *cmd, void *mconfig,
                                        const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->python_eggs = f;

    return NULL;
}

static const char *wsgi_set_restrict_embedded(cmd_parms *cmd, void *mconfig,
                                              const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->restrict_embedded = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->restrict_embedded = 1;
    else
        return "WSGIRestrictEmbedded must be one of: Off | On";

    if (sconfig->restrict_embedded) {
        if (wsgi_python_required == -1)
            wsgi_python_required = 0;
    }

    return NULL;
}

static const char *wsgi_set_restrict_stdin(cmd_parms *cmd, void *mconfig,
                                           const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->restrict_stdin = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->restrict_stdin = 1;
    else
        return "WSGIRestrictStdin must be one of: Off | On";

    return NULL;
}

static const char *wsgi_set_restrict_stdout(cmd_parms *cmd, void *mconfig,
                                            const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->restrict_stdout = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->restrict_stdout = 1;
    else
        return "WSGIRestrictStdout must be one of: Off | On";

    return NULL;
}

static const char *wsgi_set_restrict_signal(cmd_parms *cmd, void *mconfig,
                                            const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->restrict_signal = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->restrict_signal = 1;
    else
        return "WSGIRestrictSignal must be one of: Off | On";

    return NULL;
}

static const char *wsgi_set_case_sensitivity(cmd_parms *cmd, void *mconfig,
                                           const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->case_sensitivity = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->case_sensitivity = 1;
    else
        return "WSGICaseSensitivity must be one of: Off | On";

    return NULL;
}

static const char *wsgi_set_restrict_process(cmd_parms *cmd, void *mconfig,
                                             const char *args)
{
    apr_table_t *index = apr_table_make(cmd->pool, 5);

    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        dconfig->restrict_process = index;
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        sconfig->restrict_process = index;
    }

    while (*args) {
        const char *option;

        option = ap_getword_conf(cmd->pool, &args);

        if (!strcmp(option, "%{GLOBAL}"))
            option = "";

        apr_table_setn(index, option, option);
    }

    return NULL;
}

static const char *wsgi_set_process_group(cmd_parms *cmd, void *mconfig,
                                          const char *n)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->process_group = n;
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->process_group = n;
    }

    return NULL;
}

static const char *wsgi_set_application_group(cmd_parms *cmd, void *mconfig,
                                              const char *n)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->application_group = n;
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->application_group = n;
    }

    return NULL;
}

static const char *wsgi_set_callable_object(cmd_parms *cmd, void *mconfig,
                                            const char *n)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->callable_object = n;
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->callable_object = n;
    }

    return NULL;
}

static const char *wsgi_add_import_script(cmd_parms *cmd, void *mconfig,
                                          const char *args)
{
    const char *error = NULL;
    WSGIScriptFile *object = NULL;

    const char *option = NULL;
    const char *value = NULL;

    if (!wsgi_import_list) {
        wsgi_import_list = apr_array_make(cmd->pool, 20,
                                          sizeof(WSGIScriptFile));
    }

    object = (WSGIScriptFile *)apr_array_push(wsgi_import_list);

    object->handler_script = ap_getword_conf(cmd->pool, &args);
    object->process_group = NULL;
    object->application_group = NULL;

    if (!object->handler_script || !*object->handler_script)
        return "Location of import script not supplied.";

    while (*args) {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS) {
            return "Invalid option to WSGI import script definition.";
        }

        if (!strcmp(option, "application-group")) {
            if (!*value)
                return "Invalid name for WSGI application group.";

            object->application_group = value;
        }
#if defined(MOD_WSGI_WITH_DAEMONS)
        else if (!strcmp(option, "process-group")) {
            if (!*value)
                return "Invalid name for WSGI process group.";

            object->process_group = value;
        }
#endif
        else
            return "Invalid option to WSGI import script definition.";
    }

    if (!object->application_group)
        return "Name of WSGI application group required.";

    if (!strcmp(object->application_group, "%{GLOBAL}"))
        object->application_group = "";

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (!object->process_group)
        return "Name of WSGI process group required.";

    if (!strcmp(object->process_group, "%{GLOBAL}"))
        object->process_group = "";

    if (*object->process_group) {
        WSGIProcessGroup *group = NULL;
        WSGIProcessGroup *entries = NULL;
        WSGIProcessGroup *entry = NULL;
        int i;

        if (!wsgi_daemon_list)
            return "WSGI process group not yet configured.";

        entries = (WSGIProcessGroup *)wsgi_daemon_list->elts;

        for (i = 0; i < wsgi_daemon_list->nelts; ++i) {
            entry = &entries[i];

            if (!strcmp(entry->name, object->process_group)) {
                group = entry;
                break;
            }
        }

        if (!group)
            return "WSGI process group not yet configured.";

        if (group->server != cmd->server && group->server->is_virtual)
            return "WSGI process group not accessible.";
    }
#else
    object->process_group = "";
#endif

    if (!*object->process_group)
        wsgi_python_required = 1;

    return NULL;
}

static const char *wsgi_set_dispatch_script(cmd_parms *cmd, void *mconfig,
                                            const char *args)
{
    WSGIScriptFile *object = NULL;

    const char *option = NULL;
    const char *value = NULL;

    object = newWSGIScriptFile(cmd->pool);

    object->handler_script = ap_getword_conf(cmd->pool, &args);

    if (!object->handler_script || !*object->handler_script)
        return "Location of dispatch script not supplied.";

    while (*args) {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS) {
            return "Invalid option to WSGI dispatch script definition.";
        }

        if (!strcmp(option, "application-group")) {
            if (!*value)
                return "Invalid name for WSGI application group.";

            object->application_group = value;
        }
        else
            return "Invalid option to WSGI dispatch script definition.";
    }

    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->dispatch_script = object;
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->dispatch_script = object;
    }

    wsgi_python_required = 1;

    return NULL;
}

static const char *wsgi_set_pass_apache_request(cmd_parms *cmd, void *mconfig,
                                                const char *f)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->pass_apache_request = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->pass_apache_request = 1;
        else
            return "WSGIPassApacheRequest must be one of: Off | On";
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->pass_apache_request = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->pass_apache_request = 1;
        else
            return "WSGIPassApacheRequest must be one of: Off | On";
    }

    return NULL;
}

static const char *wsgi_set_pass_authorization(cmd_parms *cmd, void *mconfig,
                                               const char *f)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->pass_authorization = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->pass_authorization = 1;
        else
            return "WSGIPassAuthorization must be one of: Off | On";
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->pass_authorization = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->pass_authorization = 1;
        else
            return "WSGIPassAuthorization must be one of: Off | On";
    }

    return NULL;
}

static const char *wsgi_set_script_reloading(cmd_parms *cmd, void *mconfig,
                                             const char *f)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->script_reloading = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->script_reloading = 1;
        else
            return "WSGIScriptReloading must be one of: Off | On";
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->script_reloading = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->script_reloading = 1;
        else
            return "WSGIScriptReloading must be one of: Off | On";
    }

    return NULL;
}

static const char *wsgi_set_error_override(cmd_parms *cmd, void *mconfig,
                                           const char *f)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->error_override = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->error_override = 1;
        else
            return "WSGIErrorOverride must be one of: Off | On";
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->error_override = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->error_override = 1;
        else
            return "WSGIErrorOverride must be one of: Off | On";
    }

    return NULL;
}

static const char *wsgi_set_chunked_request(cmd_parms *cmd, void *mconfig,
                                            const char *f)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->chunked_request = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->chunked_request = 1;
        else
            return "WSGIChunkedRequest must be one of: Off | On";
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->chunked_request = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->chunked_request = 1;
        else
            return "WSGIChunkedRequest must be one of: Off | On";
    }

    return NULL;
}

static const char *wsgi_set_access_script(cmd_parms *cmd, void *mconfig,
                                          const char *args)
{
    WSGIDirectoryConfig *dconfig = NULL;
    WSGIScriptFile *object = NULL;

    const char *option = NULL;
    const char *value = NULL;

    object = newWSGIScriptFile(cmd->pool);

    object->handler_script = ap_getword_conf(cmd->pool, &args);

    if (!object->handler_script || !*object->handler_script)
        return "Location of access script not supplied.";

    while (*args) {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS) {
            return "Invalid option to WSGI access script definition.";
        }

        if (!strcmp(option, "application-group")) {
            if (!*value)
                return "Invalid name for WSGI application group.";

            object->application_group = value;
        }
        else
            return "Invalid option to WSGI access script definition.";
    }

    dconfig = (WSGIDirectoryConfig *)mconfig;
    dconfig->access_script = object;

    wsgi_python_required = 1;

    return NULL;
}

static const char *wsgi_set_auth_user_script(cmd_parms *cmd, void *mconfig,
                                             const char *args)
{
    WSGIDirectoryConfig *dconfig = NULL;
    WSGIScriptFile *object = NULL;

    const char *option = NULL;
    const char *value = NULL;

    object = newWSGIScriptFile(cmd->pool);

    object->handler_script = ap_getword_conf(cmd->pool, &args);

    if (!object->handler_script || !*object->handler_script)
        return "Location of auth user script not supplied.";

    while (*args) {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS) {
            return "Invalid option to WSGI auth user script definition.";
        }

        if (!strcmp(option, "application-group")) {
            if (!*value)
                return "Invalid name for WSGI application group.";

            object->application_group = value;
        }
        else
            return "Invalid option to WSGI auth user script definition.";
    }

    dconfig = (WSGIDirectoryConfig *)mconfig;
    dconfig->auth_user_script = object;

    wsgi_python_required = 1;

    return NULL;
}

static const char *wsgi_set_auth_group_script(cmd_parms *cmd, void *mconfig,
                                               const char *args)
{
    WSGIDirectoryConfig *dconfig = NULL;
    WSGIScriptFile *object = NULL;

    const char *option = NULL;
    const char *value = NULL;

    object = newWSGIScriptFile(cmd->pool);

    object->handler_script = ap_getword_conf(cmd->pool, &args);

    if (!object->handler_script || !*object->handler_script)
        return "Location of auth group script not supplied.";

    while (*args) {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS) {
            return "Invalid option to WSGI auth group script definition.";
        }

        if (!strcmp(option, "application-group")) {
            if (!*value)
                return "Invalid name for WSGI application group.";

            object->application_group = value;
        }
        else
            return "Invalid option to WSGI auth group script definition.";
    }

    dconfig = (WSGIDirectoryConfig *)mconfig;
    dconfig->auth_group_script = object;

    wsgi_python_required = 1;

    return NULL;
}

static const char *wsgi_set_user_authoritative(cmd_parms *cmd, void *mconfig,
                                               const char *f)
{
    WSGIDirectoryConfig *dconfig = NULL;
    dconfig = (WSGIDirectoryConfig *)mconfig;

    if (strcasecmp(f, "Off") == 0)
        dconfig->user_authoritative = 0;
    else if (strcasecmp(f, "On") == 0)
        dconfig->user_authoritative = 1;
    else
        return "WSGIUserAuthoritative must be one of: Off | On";

    return NULL;
}

static const char *wsgi_set_group_authoritative(cmd_parms *cmd, void *mconfig,
                                                const char *f)
{
    WSGIDirectoryConfig *dconfig = NULL;
    dconfig = (WSGIDirectoryConfig *)mconfig;

    if (strcasecmp(f, "Off") == 0)
        dconfig->group_authoritative = 0;
    else if (strcasecmp(f, "On") == 0)
        dconfig->group_authoritative = 1;
    else
        return "WSGIGroupAuthoritative must be one of: Off | On";

    return NULL;
}

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
static const char *wsgi_add_handler_script(cmd_parms *cmd, void *mconfig,
                                           const char *args)
{
    WSGIServerConfig *sconfig = NULL;
    WSGIDirectoryConfig *dconfig = NULL;
    WSGIScriptFile *object = NULL;

    const char *name = NULL;
    const char *option = NULL;
    const char *value = NULL;

    name = ap_getword_conf(cmd->pool, &args);

    if (!name || !*name)
        return "Name for handler script not supplied.";

    object = newWSGIScriptFile(cmd->pool);

    object->handler_script = ap_getword_conf(cmd->pool, &args);

    if (!object->handler_script || !*object->handler_script)
        return "Location of handler script not supplied.";

    while (*args) {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS) {
            return "Invalid option to WSGI handler script definition.";
        }

        if (!strcmp(option, "process-group")) {
            if (!*value)
                return "Invalid name for WSGI process group.";

            object->process_group = value;
        }
        else if (!strcmp(option, "application-group")) {
            if (!*value)
                return "Invalid name for WSGI application group.";

            object->application_group = value;
        }
        else if (!strcmp(option, "pass-authorization")) {
            if (!*value)
                return "Invalid value for authorization flag.";

            if (strcasecmp(value, "Off") == 0)
                object->pass_authorization = "0";
            else if (strcasecmp(value, "On") == 0)
                object->pass_authorization = "1";
            else
                return "Invalid value for authorization flag.";
        }
        else
            return "Invalid option to WSGI handler script definition.";
    }

    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (!dconfig->handler_scripts)
            dconfig->handler_scripts = apr_hash_make(cmd->pool);

        apr_hash_set(dconfig->handler_scripts, name, APR_HASH_KEY_STRING,
                     object);
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (!sconfig->handler_scripts)
            sconfig->handler_scripts = apr_hash_make(cmd->pool);

        apr_hash_set(sconfig->handler_scripts, name, APR_HASH_KEY_STRING,
                     object);
    }

    return NULL;
}
#endif

/* Handler for the translate name phase. */

static int wsgi_alias_matches(const char *uri, const char *alias_fakename)
{
    /* Code for this function from Apache mod_alias module. */

    const char *aliasp = alias_fakename, *urip = uri;

    while (*aliasp) {
        if (*aliasp == '/') {
            /* any number of '/' in the alias matches any number in
             * the supplied URI, but there must be at least one...
             */
            if (*urip != '/')
                return 0;

            do {
                ++aliasp;
            } while (*aliasp == '/');
            do {
                ++urip;
            } while (*urip == '/');
        }
        else {
            /* Other characters are compared literally */
            if (*urip++ != *aliasp++)
                return 0;
        }
    }

    /* Check last alias path component matched all the way */

    if (aliasp[-1] != '/' && *urip != '\0' && *urip != '/')
        return 0;

    /* Return number of characters from URI which matched (may be
     * greater than length of alias, since we may have matched
     * doubled slashes)
     */

    return urip - uri;
}

static int wsgi_hook_intercept(request_rec *r)
{
    WSGIServerConfig *config = NULL;

    apr_array_header_t *aliases = NULL;

    WSGIAliasEntry *entries = NULL;
    WSGIAliasEntry *entry = NULL;

    ap_regmatch_t matches[AP_MAX_REG_MATCH];

    const char *location = NULL;
    const char *application = NULL;

    int i = 0;

    config = ap_get_module_config(r->server->module_config, &wsgi_module);

    if (!config->alias_list)
        return DECLINED;

    if (r->uri[0] != '/' && r->uri[0])
        return DECLINED;

    aliases = config->alias_list;
    entries = (WSGIAliasEntry *)aliases->elts;

    for (i = 0; i < aliases->nelts; ++i) {
        int l = 0;

        entry = &entries[i];

        if (entry->regexp) {
            if (!ap_regexec(entry->regexp, r->uri, AP_MAX_REG_MATCH,
                matches, 0)) {
                if (entry->application) {
                    l = matches[0].rm_eo;

                    location = apr_pstrndup(r->pool, r->uri, l);
                    application = ap_pregsub(r->pool, entry->application,
                                             r->uri, AP_MAX_REG_MATCH,
                                             matches);
                }
            }
        }
        else if (entry->location) {
            l = wsgi_alias_matches(r->uri, entry->location);

            location = entry->location;
            application = entry->application;
        }

        if (l > 0) {
            if (!strcmp(location, "/")) {
                r->filename = apr_pstrcat(r->pool, application,
                                          r->uri, NULL);
            }
            else {
                r->filename = apr_pstrcat(r->pool, application,
                                          r->uri + l, NULL);
            }

            r->handler = "wsgi-script";
            apr_table_setn(r->notes, "alias-forced-type", r->handler);

            if (entry->process_group) {
                apr_table_setn(r->notes, "mod_wsgi.process_group",
                               entry->process_group);
            }
            if (entry->application_group) {
                apr_table_setn(r->notes, "mod_wsgi.application_group",
                               entry->application_group);
            }
            if (entry->callable_object) {
                apr_table_setn(r->notes, "mod_wsgi.callable_object",
                               entry->callable_object);
            }

            if (entry->pass_authorization == 0)
                apr_table_setn(r->notes, "mod_wsgi.pass_authorization", "0");
            else if (entry->pass_authorization == 1)
                apr_table_setn(r->notes, "mod_wsgi.pass_authorization", "1");

            return OK;
        }
    }

    return DECLINED;
}

/* Handler for the response handler phase. */

static void wsgi_log_script_error(request_rec *r, const char *e, const char *n)
{
    char *message = NULL;

    if (!n)
        n = r->filename;

    message = apr_psprintf(r->pool, "%s: %s", e, n);

    ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r, "%s", message);
}

static void wsgi_build_environment(request_rec *r)
{
    WSGIRequestConfig *config = NULL;

    const char *value = NULL;
    const char *script_name = NULL;
    const char *path_info = NULL;

    conn_rec *c = r->connection;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    /* Populate environment with standard CGI variables. */

    ap_add_cgi_vars(r);
    ap_add_common_vars(r);

    /*
     * Mutate a HEAD request into a GET request. This is
     * required because WSGI specification doesn't lay out
     * clearly how WSGI applications should treat a HEAD
     * request. Generally authors of WSGI applications or
     * frameworks take it that they do not need to return any
     * content, but this screws up any Apache output filters
     * which need to see all the response content in order to
     * correctly set up response headers for a HEAD request such
     * that they are the same as a GET request. Thus change a
     * HEAD request into a GET request to ensure that request
     * content is generated. If using Apache 2.X we can skip
     * doing this if we know there is no output filter that
     * might change the content and/or headers.
     */

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    if (r->method_number == M_GET && r->header_only &&
        r->output_filters->frec->ftype < AP_FTYPE_PROTOCOL)
        apr_table_setn(r->subprocess_env, "REQUEST_METHOD", "GET");
#else
    if (r->method_number == M_GET && r->header_only)
        apr_table_setn(r->subprocess_env, "REQUEST_METHOD", "GET");
#endif

    /* Determine whether connection uses HTTPS protocol. */

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    if (!wsgi_is_https)
        wsgi_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

    if (wsgi_is_https && wsgi_is_https(r->connection))
        apr_table_set(r->subprocess_env, "HTTPS", "1");
#endif

    /*
     * If enabled, pass along authorisation headers which Apache
     * leaves out of CGI environment. WSGI still needs to see
     * these if it needs to implement any of the standard
     * authentication schemes such as Basic and Digest. We do
     * not pass these through by default though as it can result
     * in passwords being leaked though to a WSGI application
     * when it shouldn't. This would be a problem where there is
     * some sort of site wide authorisation scheme in place
     * which has got nothing to do with specific applications.
     */

    if (config->pass_authorization) {
        value = apr_table_get(r->headers_in, "Authorization");
        if (value)
            apr_table_setn(r->subprocess_env, "HTTP_AUTHORIZATION", value);
    }

    /* If PATH_INFO not set, set it to an empty string. */

    value = apr_table_get(r->subprocess_env, "PATH_INFO");
    if (!value)
        apr_table_setn(r->subprocess_env, "PATH_INFO", "");

    /*
     * Multiple slashes are not always collapsed into a single
     * slash in SCRIPT_NAME and PATH_INFO with Apache 1.3 and
     * Apache 2.X behaving a bit differently. Because some WSGI
     * applications don't deal with multiple slashes properly we
     * collapse any duplicate slashes to a single slash so
     * Apache behaviour is consistent across all versions. We
     * don't care that PATH_TRANSLATED can on Apache 1.3 still
     * contain multiple slashes as that should not be getting
     * used from a WSGI application anyway.
     */

    script_name = apr_table_get(r->subprocess_env, "SCRIPT_NAME");

    if (*script_name) {
        while (*script_name && (*(script_name+1) == '/'))
            script_name++;
        script_name = apr_pstrdup(r->pool, script_name);
        ap_no2slash((char*)script_name);
        apr_table_setn(r->subprocess_env, "SCRIPT_NAME", script_name);
    }

    path_info = apr_table_get(r->subprocess_env, "PATH_INFO");

    if (*path_info) {
        while (*path_info && (*(path_info+1) == '/'))
            path_info++;
        path_info = apr_pstrdup(r->pool, path_info);
        ap_no2slash((char*)path_info);
        apr_table_setn(r->subprocess_env, "PATH_INFO", path_info);
    }

    /*
     * Set values specific to mod_wsgi configuration. These control
     * aspects of how a request is managed but don't strictly need
     * to be passed through to the application itself. It is though
     * easier to set them here as then they are carried across to
     * the daemon process as part of the environment where they can
     * be extracted and used.
     */

    apr_table_setn(r->subprocess_env, "mod_wsgi.process_group",
                   config->process_group);
    apr_table_setn(r->subprocess_env, "mod_wsgi.application_group",
                   config->application_group);
    apr_table_setn(r->subprocess_env, "mod_wsgi.callable_object",
                   config->callable_object);

    apr_table_setn(r->subprocess_env, "mod_wsgi.request_handler", r->handler);
    apr_table_setn(r->subprocess_env, "mod_wsgi.handler_script",
                   config->handler_script);

    apr_table_setn(r->subprocess_env, "mod_wsgi.script_reloading",
                   apr_psprintf(r->pool, "%d", config->script_reloading));

#if defined(MOD_WSGI_WITH_DAEMONS)
    apr_table_setn(r->subprocess_env, "mod_wsgi.listener_host",
                   c->local_addr->hostname ? c->local_addr->hostname : "");
    apr_table_setn(r->subprocess_env, "mod_wsgi.listener_port",
                   apr_psprintf(r->pool, "%d", c->local_addr->port));
#endif

    apr_table_setn(r->subprocess_env, "mod_wsgi.input_chunked",
                   apr_psprintf(r->pool, "%d", !!r->read_chunked));
}

typedef struct {
        PyObject_HEAD
        request_rec *r;
        WSGIRequestConfig *config;
        PyObject *log;
} DispatchObject;

static DispatchObject *newDispatchObject(request_rec *r,
                                         WSGIRequestConfig *config)
{
    DispatchObject *self;

    self = PyObject_New(DispatchObject, &Dispatch_Type);
    if (self == NULL)
        return NULL;

    self->config = config;

    self->r = r;

    self->log = newLogObject(r, APLOG_ERR, NULL);

    return self;
}

static void Dispatch_dealloc(DispatchObject *self)
{
    Py_DECREF(self->log);

    PyObject_Del(self);
}

static PyObject *Dispatch_environ(DispatchObject *self, const char *group)
{
    request_rec *r = NULL;

    PyObject *vars = NULL;
    PyObject *object = NULL;

    const apr_array_header_t *head = NULL;
    const apr_table_entry_t *elts = NULL;

    int i = 0;

    /* Create the WSGI environment dictionary. */

    vars = PyDict_New();

    /* Merge the CGI environment into the WSGI environment. */

    r = self->r;

    head = apr_table_elts(r->subprocess_env);
    elts = (apr_table_entry_t *)head->elts;

    for (i = 0; i < head->nelts; ++i) {
        if (elts[i].key) {
            if (elts[i].val) {
#if PY_MAJOR_VERSION >= 3
                object = PyUnicode_DecodeLatin1(elts[i].val,
                                                strlen(elts[i].val), NULL);
#else
                object = PyString_FromString(elts[i].val);
#endif
                PyDict_SetItemString(vars, elts[i].key, object);
                Py_DECREF(object);
            }
            else
                PyDict_SetItemString(vars, elts[i].key, Py_None);
        }
    }

    /*
     * Need to override process and application group as they
     * are set to the default target, where as we need to set
     * them to context dispatch script is run in. Also need
     * to remove callable object reference.
     */

#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_FromString("");
#else
    object = PyString_FromString("");
#endif
    PyDict_SetItemString(vars, "mod_wsgi.process_group", object);
    Py_DECREF(object);

#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(group, strlen(group), NULL);
#else
    object = PyString_FromString(group);
#endif
    PyDict_SetItemString(vars, "mod_wsgi.application_group", object);
    Py_DECREF(object);

    PyDict_DelItemString(vars, "mod_wsgi.callable_object");

    /*
     * Setup log object for WSGI errors. Don't decrement
     * reference to log object as keep reference to it.
     */

    object = (PyObject *)self->log;
    PyDict_SetItemString(vars, "wsgi.errors", object);

    /*
     * If Apache extensions are enabled add a CObject reference
     * to the Apache request_rec structure instance.
     */

    if (!wsgi_daemon_pool && self->config->pass_apache_request) {
        object = PyCObject_FromVoidPtr(self->r, 0);
        PyDict_SetItemString(vars, "apache.request_rec", object);
        Py_DECREF(object);
    }

    return vars;
}

static PyTypeObject Dispatch_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "mod_wsgi.Dispatch",    /*tp_name*/
    sizeof(DispatchObject), /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Dispatch_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    0,                      /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

static int wsgi_execute_dispatch(request_rec *r)
{
    WSGIRequestConfig *config;

    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    char *name = NULL;
    int exists = 0;

    const char *script = NULL;
    const char *group = NULL;

    int status;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    if (!config->dispatch_script) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                     "mod_wsgi (pid=%d): Location of WSGI dispatch "
                     "script not provided.", getpid());

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    script = config->dispatch_script->handler_script;
    group = wsgi_server_group(r, config->dispatch_script->application_group);

    interp = wsgi_acquire_interpreter(group);

    if (!interp) {
        ap_log_rerror(APLOG_MARK, WSGI_LOG_CRIT(0), r,
                      "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                      getpid(), group);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Calculate the Python module name to be used for script. */

    name = wsgi_module_name(r->pool, script);

    /*
     * Use a lock around the check to see if the module is
     * already loaded and the import of the module to prevent
     * two request handlers trying to import the module at the
     * same time.
     */

#if APR_HAS_THREADS
    Py_BEGIN_ALLOW_THREADS
    apr_thread_mutex_lock(wsgi_module_lock);
    Py_END_ALLOW_THREADS
#endif

    modules = PyImport_GetModuleDict();
    module = PyDict_GetItemString(modules, name);

    Py_XINCREF(module);

    if (module)
        exists = 1;

    /*
     * If script reloading is enabled and the module for it has
     * previously been loaded, see if it has been modified since
     * the last time it was accessed.
     */

    if (module && config->script_reloading) {
        if (wsgi_reload_required(r->pool, r, script, module, NULL)) {
            /*
             * Script file has changed. Only support module
             * reloading for dispatch scripts. Remove the
             * module from the modules dictionary before
             * reloading it again. If code is executing within
             * the module at the time, the callers reference
             * count on the module should ensure it isn't
             * actually destroyed until it is finished.
             */

            Py_DECREF(module);
            module = NULL;

            PyDict_DelItemString(modules, name);
        }
    }

    if (!module) {
        module = wsgi_load_source(r->pool, r, name, exists, script, "", group);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Assume everything will be okay for now. */

    status = OK;

    /* Determine if script exists and execute it. */

    if (module) {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;
        DispatchObject *adapter = NULL;

        module_dict = PyModule_GetDict(module);

        adapter = newDispatchObject(r, config);

        if (adapter) {
            PyObject *vars = NULL;
            PyObject *args = NULL;
            PyObject *method = NULL;

            vars = Dispatch_environ(adapter, group);

            /* First check process_group(). */

#if defined(MOD_WSGI_WITH_DAEMONS)
            object = PyDict_GetItemString(module_dict, "process_group");

            if (object) {
                PyObject *result = NULL;

                if (adapter) {
                    Py_INCREF(object);
                    args = Py_BuildValue("(O)", vars);
                    result = PyEval_CallObject(object, args);
                    Py_DECREF(args);
                    Py_DECREF(object);

                    if (result) {
                        if (result != Py_None) {
                            if (PyString_Check(result)) {
                                const char *s;

                                s = PyString_AsString(result);
                                s = apr_pstrdup(r->pool, s);
                                s = wsgi_process_group(r, s);
                                config->process_group = s;

                                apr_table_setn(r->subprocess_env,
                                               "mod_wsgi.process_group",
                                               config->process_group);
                            }
#if PY_MAJOR_VERSION >= 3
                            else if (PyUnicode_Check(result)) {
                                PyObject *latin_item;
                                latin_item = PyUnicode_AsLatin1String(result);
                                if (!latin_item) {
                                    PyErr_SetString(PyExc_TypeError,
                                                    "Process group must be "
                                                    "a byte string, value "
                                                    "containing non 'latin-1' "
                                                    "characters found");

                                    status = HTTP_INTERNAL_SERVER_ERROR;
                                }
                                else {
                                    const char *s;

                                    Py_DECREF(result);
                                    result = latin_item;

                                    s = PyString_AsString(result);
                                    s = apr_pstrdup(r->pool, s);
                                    s = wsgi_process_group(r, s);
                                    config->process_group = s;

                                    apr_table_setn(r->subprocess_env,
                                                   "mod_wsgi.process_group",
                                                   config->process_group);
                                }
                            }
#endif
                            else {
                                PyErr_SetString(PyExc_TypeError, "Process "
                                                "group must be a byte string");

                                status = HTTP_INTERNAL_SERVER_ERROR;
                            }
                        }

                        Py_DECREF(result);
                    }
                    else
                        status = HTTP_INTERNAL_SERVER_ERROR;
                }
                else
                    Py_DECREF(object);

                object = NULL;
            }
#endif

            /* Now check application_group(). */

            if (status == OK)
                object = PyDict_GetItemString(module_dict, "application_group");

            if (object) {
                PyObject *result = NULL;

                if (adapter) {
                    Py_INCREF(object);
                    args = Py_BuildValue("(O)", vars);
                    result = PyEval_CallObject(object, args);
                    Py_DECREF(args);
                    Py_DECREF(object);

                    if (result) {
                        if (result != Py_None) {
                            if (PyString_Check(result)) {
                                const char *s;

                                s = PyString_AsString(result);
                                s = apr_pstrdup(r->pool, s);
                                s = wsgi_application_group(r, s);
                                config->application_group = s;

                                apr_table_setn(r->subprocess_env,
                                               "mod_wsgi.application_group",
                                               config->application_group);
                            }
#if PY_MAJOR_VERSION >= 3
                            else if (PyUnicode_Check(result)) {
                                PyObject *latin_item;
                                latin_item = PyUnicode_AsLatin1String(result);
                                if (!latin_item) {
                                    PyErr_SetString(PyExc_TypeError,
                                                    "Application group must "
                                                    "be a byte string, value "
                                                    "containing non 'latin-1' "
                                                    "characters found");

                                    status = HTTP_INTERNAL_SERVER_ERROR;
                                }
                                else {
                                    const char *s;

                                    Py_DECREF(result);
                                    result = latin_item;

                                    s = PyString_AsString(result);
                                    s = apr_pstrdup(r->pool, s);
                                    s = wsgi_application_group(r, s);
                                    config->application_group = s;

                                    apr_table_setn(r->subprocess_env,
                                                   "mod_wsgi.application_group",
                                                   config->application_group);
                                }
                            }
#endif
                            else {
                                PyErr_SetString(PyExc_TypeError, "Application "
                                                "group must be a string "
                                                "object");

                                status = HTTP_INTERNAL_SERVER_ERROR;
                            }
                        }

                        Py_DECREF(result);
                    }
                    else
                        status = HTTP_INTERNAL_SERVER_ERROR;
                }
                else
                    Py_DECREF(object);

                object = NULL;
            }

            /* Now check callable_object(). */

            if (status == OK)
                object = PyDict_GetItemString(module_dict, "callable_object");

            if (object) {
                PyObject *result = NULL;

                if (adapter) {
                    Py_INCREF(object);
                    args = Py_BuildValue("(O)", vars);
                    result = PyEval_CallObject(object, args);
                    Py_DECREF(args);
                    Py_DECREF(object);

                    if (result) {
                        if (result != Py_None) {
                            if (PyString_Check(result)) {
                                const char *s;

                                s = PyString_AsString(result);
                                s = apr_pstrdup(r->pool, s);
                                s = wsgi_callable_object(r, s);
                                config->callable_object = s;

                                apr_table_setn(r->subprocess_env,
                                               "mod_wsgi.callable_object",
                                               config->callable_object);
                            }
#if PY_MAJOR_VERSION >= 3
                            else if (PyUnicode_Check(result)) {
                                PyObject *latin_item;
                                latin_item = PyUnicode_AsLatin1String(result);
                                if (!latin_item) {
                                    PyErr_SetString(PyExc_TypeError,
                                                    "Callable object must "
                                                    "be a byte string, value "
                                                    "containing non 'latin-1' "
                                                    "characters found");

                                    status = HTTP_INTERNAL_SERVER_ERROR;
                                }
                                else {
                                    const char *s;

                                    Py_DECREF(result);
                                    result = latin_item;

                                    s = PyString_AsString(result);
                                    s = apr_pstrdup(r->pool, s);
                                    s = wsgi_callable_object(r, s);
                                    config->callable_object = s;

                                    apr_table_setn(r->subprocess_env,
                                                   "mod_wsgi.callable_object",
                                                   config->callable_object);
                                }
                            }
#endif
                            else {
                                PyErr_SetString(PyExc_TypeError, "Callable "
                                                "object must be a string "
                                                "object");

                                status = HTTP_INTERNAL_SERVER_ERROR;
                            }
                        }

                        Py_DECREF(result);
                    }
                    else
                        status = HTTP_INTERNAL_SERVER_ERROR;
                }
                else
                    Py_DECREF(object);

                object = NULL;
            }

            /*
             * Wipe out references to Apache request object
             * held by Python objects, so can detect when an
             * application holds on to the transient Python
             * objects beyond the life of the request and
             * thus raise an exception if they are used.
             */

            adapter->r = NULL;

            /* Close the log object so data is flushed. */

            method = PyObject_GetAttrString(adapter->log, "close");

            if (!method) {
                PyErr_Format(PyExc_AttributeError,
                             "'%s' object has no attribute 'close'",
                             adapter->log->ob_type->tp_name);
            }
            else {
                args = PyTuple_New(0);
                object = PyEval_CallObject(method, args);
                Py_DECREF(args);
            }

            Py_XDECREF(object);
            Py_XDECREF(method);

            /* No longer need adapter object. */

            Py_DECREF((PyObject *)adapter);

            /* Log any details of exceptions if execution failed. */

            if (PyErr_Occurred())
                wsgi_log_python_error(r, NULL, script);

            Py_DECREF(vars);
        }
    }

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    return status;
}

static int wsgi_is_script_aliased(request_rec *r)
{
    const char *t = NULL;

    t = apr_table_get(r->notes, "alias-forced-type");
    return t && (!strcasecmp(t, "wsgi-script"));
}

#if defined(MOD_WSGI_WITH_DAEMONS)
static int wsgi_execute_remote(request_rec *r);
#endif

static int wsgi_hook_handler(request_rec *r)
{
    int status;
    apr_off_t limit = 0;

    WSGIRequestConfig *config = NULL;

    const char *value = NULL;

    /* Filter out the obvious case of no handler defined. */

    if (!r->handler)
        return DECLINED;

    /*
     * Construct request configuration and cache it in the
     * request object against this module so can access it later
     * from handler code.
     */

    config = wsgi_create_req_config(r->pool, r);

    ap_set_module_config(r->request_config, &wsgi_module, config);

    /*
     * Only process requests for this module. First check for
     * where target is the actual WSGI script. Then need to
     * check for the case where handler name mapped to a handler
     * script definition.
     */

    if (!strcmp(r->handler, "wsgi-script") ||
        !strcmp(r->handler, "application/x-httpd-wsgi")) {

        /*
         * Ensure that have adequate privileges to run the WSGI
         * script. Require ExecCGI to be specified in Options for
         * this. In doing this, using the wider interpretation that
         * ExecCGI refers to any executable like script even though
         * not a separate process execution.
         */

        if (!(ap_allow_options(r) & OPT_EXECCGI) &&
            !wsgi_is_script_aliased(r)) {
            wsgi_log_script_error(r, "Options ExecCGI is off in this "
                                  "directory", r->filename);
            return HTTP_FORBIDDEN;
        }

        /* Ensure target script exists and is a file. */

#if AP_SERVER_MAJORVERSION_NUMBER < 2
        if (r->finfo.st_mode == 0) {
            wsgi_log_script_error(r, "Target WSGI script not found or unable "
                                  "to stat", r->filename);
            return HTTP_NOT_FOUND;
        }
#else
        if (r->finfo.filetype == 0) {
            wsgi_log_script_error(r, "Target WSGI script not found or unable "
                                  "to stat", r->filename);
            return HTTP_NOT_FOUND;
        }
#endif

#if AP_SERVER_MAJORVERSION_NUMBER < 2
        if (S_ISDIR(r->finfo.st_mode)) {
            wsgi_log_script_error(r, "Attempt to invoke directory as WSGI "
                                  "application", r->filename);
            return HTTP_FORBIDDEN;
        }
#else
        if (r->finfo.filetype == APR_DIR) {
            wsgi_log_script_error(r, "Attempt to invoke directory as WSGI "
                                  "application", r->filename);
            return HTTP_FORBIDDEN;
        }
#endif

        if (wsgi_is_script_aliased(r)) {
            /*
             * Allow any configuration supplied through request notes to
             * override respective values. Request notes are used when
             * configuration supplied with WSGIScriptAlias directives.
             */

            if (value = apr_table_get(r->notes, "mod_wsgi.process_group"))
                config->process_group = wsgi_process_group(r, value);
            if (value = apr_table_get(r->notes, "mod_wsgi.application_group"))
                config->application_group = wsgi_application_group(r, value);
            if (value = apr_table_get(r->notes, "mod_wsgi.callable_object"))
                config->callable_object = value;

            if (value = apr_table_get(r->notes,
                                      "mod_wsgi.pass_authorization")) {
                if (!strcmp(value, "1"))
                    config->pass_authorization = 1;
                else
                    config->pass_authorization = 0;
            }
        }
    }
#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    else if (config->handler_scripts) {
        WSGIScriptFile *entry;

        entry = (WSGIScriptFile *)apr_hash_get(config->handler_scripts,
                                               r->handler,
                                               APR_HASH_KEY_STRING);

        if (entry) {
            config->handler_script = entry->handler_script;
            config->callable_object = "handle_request";

            if (value = entry->process_group)
                config->process_group = wsgi_process_group(r, value);
            if (value = entry->application_group)
                config->application_group = wsgi_application_group(r, value);

            if (value = entry->pass_authorization) {
                if (!strcmp(value, "1"))
                    config->pass_authorization = 1;
                else
                    config->pass_authorization = 0;
            }
        }
        else
            return DECLINED;
    }
#endif
    else
        return DECLINED;

    /*
     * For Apache 2.0+ honour AcceptPathInfo directive. Default
     * behaviour is accept additional path information. Under
     * Apache 1.3, WSGI application would need to check itself.
     */

#if AP_MODULE_MAGIC_AT_LEAST(20011212,0)
    if ((r->used_path_info == AP_REQ_REJECT_PATH_INFO) &&
        r->path_info && *r->path_info) {
        wsgi_log_script_error(r, "AcceptPathInfo off disallows user's path",
                              r->filename);
        return HTTP_NOT_FOUND;
    }
#endif

    /*
     * Setup policy to apply if request contains a body. Note
     * that WSGI specification doesn't strictly allow for chunked
     * request content as CONTENT_LENGTH required when reading
     * input and application isn't meant to read more than what
     * is defined by CONTENT_LENGTH. To allow chunked request
     * content tell Apache to dechunk it. For application to use
     * the content, it has to ignore WSGI specification and use
     * read() with no arguments to read all available input, or
     * call read() with specific block size until read() returns
     * an empty string.
     */

    if (config->chunked_request)
        status = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK);
    else
        status = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);

    if (status != OK)
        return status;

    /*
     * Check to see if request content is too large and end
     * request here. We do this as otherwise it will not be done
     * until first time input data is read in application.
     * Problem is that underlying HTTP output filter will
     * also generate a 413 response and the error raised from
     * the application will be appended to that. The call to
     * ap_discard_request_body() is hopefully enough to trigger
     * sending of the 413 response by the HTTP filter.
     */

    limit = ap_get_limit_req_body(r);

    if (limit && limit < r->remaining) {
        ap_discard_request_body(r);
        return OK;
    }

    /* Build the sub process environment. */

    wsgi_build_environment(r);

    /*
     * If a dispatch script has been provided, as appropriate
     * allow it to override any of the configuration related
     * to what context the script will be executed in and what
     * the target callable object for the application is.
     */

    if (config->dispatch_script) {
        status = wsgi_execute_dispatch(r);

        if (status != OK)
            return status;
    }

    /*
     * Execute the target WSGI application script or proxy
     * request to one of the daemon processes as appropriate.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    status = wsgi_execute_remote(r);

    if (status != DECLINED)
        return status;
#endif

#if defined(MOD_WSGI_DISABLE_EMBEDDED)
    wsgi_log_script_error(r, "Embedded mode of mod_wsgi disabled at compile "
                          "time", r->filename);
    return HTTP_INTERNAL_SERVER_ERROR;
#endif

    if (wsgi_server_config->restrict_embedded == 1) {
        wsgi_log_script_error(r, "Embedded mode of mod_wsgi disabled by "
                              "runtime configuration", r->filename);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return wsgi_execute_script(r);
}

#if AP_SERVER_MAJORVERSION_NUMBER < 2

/*
 * Apache 1.3 module initialisation functions.
 */

static void wsgi_hook_init(server_rec *s, apr_pool_t *p)
{
    char package[128];

    /* Setup module version information. */

    sprintf(package, "mod_wsgi/%s", MOD_WSGI_VERSION_STRING);

    ap_add_version_component(package);

    /* Record Python version string with Apache. */

    if (!Py_IsInitialized()) {
        char buffer[256];
        const char *token = NULL;
        const char *version = NULL;
        
        version = Py_GetVersion();

        token = version;
        while (*token && *token != ' ')
            token++;

        strcpy(buffer, "Python/");
        strncat(buffer, version, token - version);

        ap_add_version_component(buffer);
    }

    /* Retain reference to base server. */

    wsgi_server = s;

    /* Retain record of parent process ID. */

    wsgi_parent_pid = getpid();

    /* Determine whether multiprocess and/or multithreaded. */

    wsgi_multiprocess = 1;
    wsgi_multithread = 0;

    /* Retain reference to main server config. */

    wsgi_server_config = ap_get_module_config(s->module_config, &wsgi_module);

    /*
     * Check that the version of Python found at
     * runtime is what was used at compilation.
     */

    wsgi_python_version();

    /*
     * Initialise Python if required to be done in
     * the parent process. Note that it will not be
     * initialised if mod_python loaded and it has
     * already been done.
     */

    if (!wsgi_python_after_fork)
        wsgi_python_init(p);
}

static void wsgi_hook_child_init(server_rec *s, apr_pool_t *p)
{
    if (wsgi_python_required) {
        /*
         * Initialise Python if required to be done in
         * the child process. Note that it will not be
         * initialised if mod_python loaded and it has
         * already been done.
         */

        if (wsgi_python_after_fork)
            wsgi_python_init(p);

        /*
         * Now perform additional initialisation steps
         * always done in child process.
         */

        wsgi_python_child_init(p);
    }
}

/* Dispatch list of content handlers */
static const handler_rec wsgi_handlers[] = {
    { "wsgi-script", wsgi_hook_handler },
    { "application/x-httpd-wsgi", wsgi_hook_handler },
    { NULL, NULL }
};

static const command_rec wsgi_commands[] =
{
    { "WSGIScriptAlias", wsgi_add_script_alias, NULL,
        RSRC_CONF, RAW_ARGS, "Map location to target WSGI script file." },
    { "WSGIScriptAliasMatch", wsgi_add_script_alias, "*",
        RSRC_CONF, RAW_ARGS, "Map location to target WSGI script file." },

    { "WSGIVerboseDebugging", wsgi_set_verbose_debugging, NULL,
        RSRC_CONF, TAKE1, "Enable/Disable verbose debugging messages." },

#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 6
    { "WSGIPy3kWarningFlag", wsgi_set_py3k_warning_flag, NULL,
        RSRC_CONF, TAKE1, "Enable/Disable Python 3.0 warnings." },
#endif

    { "WSGIPythonWarnings", wsgi_add_python_warnings, NULL,
        RSRC_CONF, TAKE1, "Control Python warning messages." },
    { "WSGIPythonOptimize", wsgi_set_python_optimize, NULL,
        RSRC_CONF, TAKE1, "Set level of Python compiler optimisations." },
    { "WSGIPythonHome", wsgi_set_python_home, NULL,
        RSRC_CONF, TAKE1, "Python prefix/exec_prefix absolute path names." },
    { "WSGIPythonPath", wsgi_set_python_path, NULL,
        RSRC_CONF, TAKE1, "Python module search path." },
    { "WSGIPythonEggs", wsgi_set_python_eggs, NULL,
        RSRC_CONF, TAKE1, "Python eggs cache directory." },

    { "WSGIRestrictStdin", wsgi_set_restrict_stdin, NULL,
        RSRC_CONF, TAKE1, "Enable/Disable restrictions on use of STDIN." },
    { "WSGIRestrictStdout", wsgi_set_restrict_stdout, NULL,
        RSRC_CONF, TAKE1, "Enable/Disable restrictions on use of STDOUT." },
    { "WSGIRestrictSignal", wsgi_set_restrict_signal, NULL,
        RSRC_CONF, TAKE1, "Enable/Disable restrictions on use of signal()." },

    { "WSGICaseSensitivity", wsgi_set_case_sensitivity, NULL,
        RSRC_CONF, TAKE1, "Define whether file system is case sensitive." },

    { "WSGIApplicationGroup", wsgi_set_application_group, NULL,
        ACCESS_CONF|RSRC_CONF, TAKE1, "Application interpreter group." },
    { "WSGICallableObject", wsgi_set_callable_object, NULL,
        OR_FILEINFO, TAKE1, "Name of entry point in WSGI script file." },

    { "WSGIImportScript", wsgi_add_import_script, NULL,
        RSRC_CONF, RAW_ARGS, "Location of WSGI import script." },
    { "WSGIDispatchScript", wsgi_set_dispatch_script, NULL,
        ACCESS_CONF|RSRC_CONF, RAW_ARGS, "Location of WSGI dispatch script." },

    { "WSGIPassAuthorization", wsgi_set_pass_authorization, NULL,
        OR_FILEINFO, TAKE1, "Enable/Disable WSGI authorization." },
    { "WSGIScriptReloading", wsgi_set_script_reloading, NULL,
        OR_FILEINFO, TAKE1, "Enable/Disable script reloading mechanism." },
    { "WSGIChunkedRequest", wsgi_set_chunked_request, NULL,
        OR_FILEINFO, TAKE1, "Enable/Disable support for chunked request." },

    { NULL }
};

/* Dispatch list for API hooks */

module MODULE_VAR_EXPORT wsgi_module = {
    STANDARD_MODULE_STUFF,
    wsgi_hook_init,            /* module initializer                  */
    wsgi_create_dir_config,    /* create per-dir    config structures */
    wsgi_merge_dir_config,     /* merge  per-dir    config structures */
    wsgi_create_server_config, /* create per-server config structures */
    wsgi_merge_server_config,  /* merge  per-server config structures */
    wsgi_commands,             /* table of config file commands       */
    wsgi_handlers,             /* [#8] MIME-typed-dispatched handlers */
    wsgi_hook_intercept,       /* [#1] URI to filename translation    */
    NULL,                      /* [#4] validate user id from request  */
    NULL,                      /* [#5] check if the user is ok _here_ */
    NULL,                      /* [#3] check access by host address   */
    NULL,                      /* [#6] determine MIME type            */
    NULL,                      /* [#7] pre-run fixups                 */
    NULL,                      /* [#9] log a transaction              */
    NULL,                      /* [#2] header parser                  */
    wsgi_hook_child_init,      /* child_init                          */
    NULL,                      /* child_exit                          */
    NULL                       /* [#0] post read-request              */
#ifdef EAPI
   ,NULL,                      /* EAPI: add_module                    */
    NULL,                      /* EAPI: remove_module                 */
    NULL,                      /* EAPI: rewrite_command               */
    NULL                       /* EAPI: new_connection                */
#endif
};

#else

/*
 * Apache 2.X and UNIX specific code for creation and management
 * of distinct daemon processes.
 */

#if defined(MOD_WSGI_WITH_DAEMONS)

static const char *wsgi_add_daemon_process(cmd_parms *cmd, void *mconfig,
                                           const char *args)
{
    const char *name = NULL;
    const char *user = NULL;
    const char *group = NULL;

    int processes = 1;
    int multiprocess = 0;
    int threads = 15;
    int umask = -1;

    const char *root = NULL;
    const char *home = NULL;
    const char *python_path = NULL;
    const char *python_eggs = NULL;

    int stack_size = 0;
    int maximum_requests = 0;
    int shutdown_timeout = 5;
    int deadlock_timeout = 300;
    int inactivity_timeout = 0;

    const char *display_name = NULL;

    int send_buffer_size = 0;
    int recv_buffer_size = 0;

    const char *script_user = NULL;
    const char *script_group = NULL;

    int cpu_time_limit = 0;
    int cpu_priority = 0;

    uid_t uid;
    uid_t gid;

    const char *option = NULL;
    const char *value = NULL;

    WSGIProcessGroup *entries = NULL;
    WSGIProcessGroup *entry = NULL;

    int i;

    /*
     * Set the defaults for user/group from values
     * defined for the User/Group directives in main
     * Apache configuration.
     */

    uid = ap_unixd_config.user_id;
    user = ap_unixd_config.user_name;

    gid = ap_unixd_config.group_id;

    /* Now parse options for directive. */

    name = ap_getword_conf(cmd->pool, &args);

    if (!name || !*name)
        return "Name of WSGI daemon process not supplied.";

    while (*args) {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS) {
            return "Invalid option to WSGI daemon process definition.";
        }

        if (!strcmp(option, "user")) {
            if (!*value)
                return "Invalid user for WSGI daemon process.";

            user = value;
            uid = ap_uname2id(user);
            if (uid == 0)
                return "WSGI process blocked from running as root.";

            if (*user == '#') {
                struct passwd *entry = NULL;

                if ((entry = getpwuid(uid)) == NULL)
                    return "Couldn't determine user name from uid.";

                user = entry->pw_name;
            }
        }
        else if (!strcmp(option, "group")) {
            if (!*value)
                return "Invalid group for WSGI daemon process.";

            group = value;
            gid = ap_gname2id(group);
        }
        else if (!strcmp(option, "processes")) {
            if (!*value)
                return "Invalid process count for WSGI daemon process.";

            processes = atoi(value);
            if (processes < 1)
                return "Invalid process count for WSGI daemon process.";

            multiprocess = 1;
        }
        else if (!strcmp(option, "threads")) {
            if (!*value)
                return "Invalid thread count for WSGI daemon process.";

            threads = atoi(value);
            if (threads < 1 || threads >= WSGI_STACK_LAST-1)
                return "Invalid thread count for WSGI daemon process.";
        }
        else if (!strcmp(option, "umask")) {
            if (!*value)
                return "Invalid umask for WSGI daemon process.";

            errno = 0;
            umask = strtol(value, (char **)&value, 8);

            if (*value || errno == ERANGE || umask < 0)
                return "Invalid umask for WSGI daemon process.";
        }
        else if (!strcmp(option, "chroot")) {
            if (geteuid())
                return "Cannot chroot WSGI daemon process when not root.";

            if (*value != '/')
                return "Invalid chroot directory for WSGI daemon process.";

            root = value;
        }
        else if (!strcmp(option, "home")) {
            if (*value != '/')
                return "Invalid home directory for WSGI daemon process.";

            home = value;
        }
        else if (!strcmp(option, "python-path")) {
            python_path = value;
        }
        else if (!strcmp(option, "python-eggs")) {
            python_eggs = value;
        }
#if (APR_MAJOR_VERSION >= 1)
        else if (!strcmp(option, "stack-size")) {
            if (!*value)
                return "Invalid stack size for WSGI daemon process.";

            stack_size = atoi(value);
            if (stack_size <= 0)
                return "Invalid stack size for WSGI daemon process.";
        }
#endif
        else if (!strcmp(option, "maximum-requests")) {
            if (!*value)
                return "Invalid request count for WSGI daemon process.";

            maximum_requests = atoi(value);
            if (maximum_requests < 0)
                return "Invalid request count for WSGI daemon process.";
        }
        else if (!strcmp(option, "shutdown-timeout")) {
            if (!*value)
                return "Invalid shutdown timeout for WSGI daemon process.";

            shutdown_timeout = atoi(value);
            if (shutdown_timeout < 0)
                return "Invalid shutdown timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "deadlock-timeout")) {
            if (!*value)
                return "Invalid deadlock timeout for WSGI daemon process.";

            deadlock_timeout = atoi(value);
            if (deadlock_timeout < 0)
                return "Invalid deadlock timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "inactivity-timeout")) {
            if (!*value)
                return "Invalid inactivity timeout for WSGI daemon process.";

            inactivity_timeout = atoi(value);
            if (inactivity_timeout < 0)
                return "Invalid inactivity timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "display-name")) {
            display_name = value;
        }
        else if (!strcmp(option, "send-buffer-size")) {
            if (!*value)
                return "Invalid send buffer size for WSGI daemon process.";

            send_buffer_size = atoi(value);
            if (send_buffer_size < 512 && send_buffer_size != 0) {
                return "Send buffer size must be >= 512 bytes, "
                       "or 0 for system default.";
            }
        }
        else if (!strcmp(option, "receive-buffer-size")) {
            if (!*value)
                return "Invalid receive buffer size for WSGI daemon process.";

            recv_buffer_size = atoi(value);
            if (recv_buffer_size < 512 && recv_buffer_size != 0) {
                return "Receive buffer size must be >= 512 bytes, "
                       "or 0 for system default.";
            }
        }
        else if (!strcmp(option, "script-user")) {
            uid_t script_uid;

            if (!*value)
                return "Invalid script user for WSGI daemon process.";

            script_uid = ap_uname2id(value);

            if (*value == '#') {
                struct passwd *entry = NULL;

                if ((entry = getpwuid(script_uid)) == NULL)
                    return "Couldn't determine uid from script user.";

                value = entry->pw_name;
            }

            script_user = value;
        }
        else if (!strcmp(option, "script-group")) {
            gid_t script_gid;

            if (!*value)
                return "Invalid script group for WSGI daemon process.";

            script_gid = ap_gname2id(value);

            if (*value == '#') {
                struct group *entry = NULL;

                if ((entry = getgrgid(script_gid)) == NULL)
                    return "Couldn't determine gid from script group.";

                value = entry->gr_name;
            }

            script_group = value;
        }
        else if (!strcmp(option, "cpu-time-limit")) {
            if (!*value)
                return "Invalid CPU time limit for WSGI daemon process.";

            cpu_time_limit = atoi(value);
            if (cpu_time_limit < 0)
                return "Invalid CPU time limit for WSGI daemon process.";
        }
        else if (!strcmp(option, "cpu-priority")) {
            if (!*value)
                return "Invalid CPU priority for WSGI daemon process.";

            cpu_priority = atoi(value);
        }
        else
            return "Invalid option to WSGI daemon process definition.";
    }

    if (script_user && script_group)
        return "Only one of script-user and script-group allowed.";

    if (!wsgi_daemon_list) {
        wsgi_daemon_list = apr_array_make(cmd->pool, 20,
                                          sizeof(WSGIProcessGroup));
    }

    entries = (WSGIProcessGroup *)wsgi_daemon_list->elts;

    for (i = 0; i < wsgi_daemon_list->nelts; ++i) {
        entry = &entries[i];

        if (!strcmp(entry->name, name))
            return "Name duplicates previous WSGI daemon definition.";
    }

    wsgi_daemon_count++;

    entry = (WSGIProcessGroup *)apr_array_push(wsgi_daemon_list);

    entry->server = cmd->server;

    entry->random = random();
    entry->id = wsgi_daemon_count;

    entry->name = apr_pstrdup(cmd->pool, name);
    entry->user = apr_pstrdup(cmd->pool, user);
    entry->group = apr_pstrdup(cmd->pool, group);

    entry->uid = uid;
    entry->gid = gid;

    entry->processes = processes;
    entry->multiprocess = multiprocess;
    entry->threads = threads;

    entry->umask = umask;
    entry->root = root;
    entry->home = home;

    entry->python_path = python_path;
    entry->python_eggs = python_eggs;

    entry->stack_size = stack_size;
    entry->maximum_requests = maximum_requests;
    entry->shutdown_timeout = shutdown_timeout;
    entry->deadlock_timeout = apr_time_from_sec(deadlock_timeout);
    entry->inactivity_timeout = apr_time_from_sec(inactivity_timeout);

    entry->display_name = display_name;

    entry->send_buffer_size = send_buffer_size;
    entry->recv_buffer_size = recv_buffer_size;

    entry->script_user = script_user;
    entry->script_group = script_group;

    entry->cpu_time_limit = cpu_time_limit;
    entry->cpu_priority = cpu_priority;

    entry->listener_fd = -1;

    return NULL;
}

static const char *wsgi_set_socket_prefix(cmd_parms *cmd, void *mconfig,
                                         const char *arg)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    sconfig->socket_prefix = ap_server_root_relative(cmd->pool, arg);

    if (!sconfig->socket_prefix) {
        return apr_pstrcat(cmd->pool, "Invalid WSGISocketPrefix '",
                           arg, "'.", NULL);
    }

    return NULL;
}

static const char wsgi_valid_accept_mutex_string[] =
    "Valid accept mutex mechanisms for this platform are: default"
#if APR_HAS_FLOCK_SERIALIZE
    ", flock"
#endif
#if APR_HAS_FCNTL_SERIALIZE
    ", fcntl"
#endif
#if APR_HAS_SYSVSEM_SERIALIZE
    ", sysvsem"
#endif
#if APR_HAS_POSIXSEM_SERIALIZE
    ", posixsem"
#endif
#if APR_HAS_PROC_PTHREAD_SERIALIZE
    ", pthread"
#endif
    ".";

static const char *wsgi_set_accept_mutex(cmd_parms *cmd, void *mconfig,
                                         const char *arg)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

#if !defined(AP_ACCEPT_MUTEX_TYPE)
    sconfig->lock_mechanism = ap_accept_lock_mech;
#else
    sconfig->lock_mechanism = APR_LOCK_DEFAULT;
#endif

    if (!strcasecmp(arg, "default")) {
        sconfig->lock_mechanism = APR_LOCK_DEFAULT;
    }
#if APR_HAS_FLOCK_SERIALIZE
    else if (!strcasecmp(arg, "flock")) {
        sconfig->lock_mechanism = APR_LOCK_FLOCK;
    }
#endif
#if APR_HAS_FCNTL_SERIALIZE
    else if (!strcasecmp(arg, "fcntl")) {
        sconfig->lock_mechanism = APR_LOCK_FCNTL;
    }
#endif
#if APR_HAS_SYSVSEM_SERIALIZE && !defined(PERCHILD_MPM)
    else if (!strcasecmp(arg, "sysvsem")) {
        sconfig->lock_mechanism = APR_LOCK_SYSVSEM;
    }
#endif
#if APR_HAS_POSIXSEM_SERIALIZE
    else if (!strcasecmp(arg, "posixsem")) {
        sconfig->lock_mechanism = APR_LOCK_POSIXSEM;
    }
#endif
#if APR_HAS_PROC_PTHREAD_SERIALIZE
    else if (!strcasecmp(arg, "pthread")) {
        sconfig->lock_mechanism = APR_LOCK_PROC_PTHREAD;
    }
#endif
    else {
        return apr_pstrcat(cmd->pool, "Accept mutex lock mechanism '", arg,
                           "' is invalid. ", wsgi_valid_accept_mutex_string,
                           NULL);
    }

    return NULL;
}

static apr_file_t *wsgi_signal_pipe_in = NULL;
static apr_file_t *wsgi_signal_pipe_out = NULL;

static int wsgi_cpu_time_limit_exceeded = 0;

static void wsgi_signal_handler(int signum)
{
    apr_size_t nbytes = 1;

    if (signum == SIGXCPU)
        wsgi_cpu_time_limit_exceeded = 1;

    apr_file_write(wsgi_signal_pipe_out, "X", &nbytes);
    apr_file_flush(wsgi_signal_pipe_out);

    wsgi_daemon_shutdown++;
}

static int wsgi_start_process(apr_pool_t *p, WSGIDaemonProcess *daemon);

static void wsgi_manage_process(int reason, void *data, apr_wait_t status)
{
    WSGIDaemonProcess *daemon = data;

    switch (reason) {

        /* Child daemon process has died. */

        case APR_OC_REASON_DEATH: {
            int mpm_state;
            int stopping;

            /* Stop watching the existing process. */

            apr_proc_other_child_unregister(daemon);

            /*
             * Determine if Apache is being shutdown or not and
             * if it is not being shutdown, restart the child
             * daemon process that has died. If MPM doesn't
             * support query assume that child daemon process
             * shouldn't be restarted. Both prefork and worker
             * MPMs support this query so should always be okay.
             */

            stopping = 1;

            if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state) == APR_SUCCESS
                && mpm_state != AP_MPMQ_STOPPING) {
                stopping = 0;
            }

            if (!stopping) {
                ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0),
                             wsgi_server, "mod_wsgi (pid=%d): "
                             "Process '%s' has died, restarting.",
                             daemon->process.pid, daemon->group->name);

                wsgi_start_process(wsgi_parent_pool, daemon);
            }

            break;
        }

        /* Apache is being restarted or shutdown. */

        case APR_OC_REASON_RESTART: {

            /* Stop watching the existing process. */

            apr_proc_other_child_unregister(daemon);

            break;
        }

        /* Child daemon process vanished. */

        case APR_OC_REASON_LOST: {

            /* Stop watching the existing process. */

            apr_proc_other_child_unregister(daemon);

            /* Restart the child daemon process that has died. */

            ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0),
                         wsgi_server, "mod_wsgi (pid=%d): "
                         "Process '%s' has died, restarting.",
                         daemon->process.pid, daemon->group->name);

            wsgi_start_process(wsgi_parent_pool, daemon);

            break;
        }

        /* Call to unregister the process. */

        case APR_OC_REASON_UNREGISTER: {

            /* Nothing to do at present. */

            break;
        }
    }
}

static void wsgi_setup_daemon_name(WSGIDaemonProcess *daemon, apr_pool_t *p)
{
    const char *display_name = NULL;

#if !(defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__))
    int slen = 0;
    int dlen = 0;

    char *argv0 = NULL;
#endif

    display_name = daemon->group->display_name;

    if (!display_name)
        return;

    if (!strcmp(display_name, "%{GROUP}")) {
        display_name = apr_pstrcat(p, "(wsgi:", daemon->group->name,
                                   ")", NULL);
    }

    /*
     * Only argv[0] is guaranteed to be the real things as MPM
     * modules may make modifications to subsequent arguments.
     * Thus can only replace the argv[0] value. Because length
     * is restricted, need to truncate display name if too long.
     */

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    setproctitle("%s", display_name);
#else
    argv0 = (char*)wsgi_server->process->argv[0];

    dlen = strlen(argv0);
    slen = strlen(display_name);

    memset(argv0, ' ', dlen);

    if (slen < dlen)
        memcpy(argv0, display_name, slen);
    else
        memcpy(argv0, display_name, dlen);
#endif
}

static void wsgi_setup_access(WSGIDaemonProcess *daemon)
{
    /* Setup the umask for the effective user. */

    if (daemon->group->umask != -1)
        umask(daemon->group->umask);

    /* Change to chroot environment. */

    if (daemon->group->root) {
        if (chroot(daemon->group->root) == -1) {
            ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno), wsgi_server,
                         "mod_wsgi (pid=%d): Unable to change root "
                         "directory to '%s'.", getpid(), daemon->group->root);
        }
    }

    /* Setup the working directory.*/

    if (daemon->group->home) {
        if (chdir(daemon->group->home) == -1) {
            ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno), wsgi_server,
                         "mod_wsgi (pid=%d): Unable to change working "
                         "directory to '%s'.", getpid(), daemon->group->home);
        }
    }
    else if (geteuid()) {
        struct passwd *pwent;

        pwent = getpwuid(geteuid());

        if (pwent) {
            if (chdir(pwent->pw_dir) == -1) {
                ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno), wsgi_server,
                             "mod_wsgi (pid=%d): Unable to change working "
                             "directory to '%s'.", getpid(), pwent->pw_dir);
            }
        }
        else {
            ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno), wsgi_server,
                         "mod_wsgi (pid=%d): Unable to determine home "
                         "directory for uid=%ld.", getpid(), (long)geteuid());
        }
    }
    else {
        struct passwd *pwent;

        pwent = getpwuid(daemon->group->uid);

        if (pwent) {
            if (chdir(pwent->pw_dir) == -1) {
                ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno), wsgi_server,
                             "mod_wsgi (pid=%d): Unable to change working "
                             "directory to '%s'.", getpid(), pwent->pw_dir);
            }
        }
        else {
            ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno), wsgi_server,
                         "mod_wsgi (pid=%d): Unable to determine home "
                         "directory for uid=%ld.", getpid(),
                         (long)daemon->group->uid);
        }
    }

    /* Don't bother switch user/group if not root. */

    if (geteuid())
        return;

    /* Setup the daemon process real and effective group. */

    if (setgid(daemon->group->gid) == -1) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno), wsgi_server,
                     "mod_wsgi (pid=%d): Unable to set group id to gid=%u.",
                     getpid(), (unsigned)daemon->group->gid);
    }
    else {
        if (initgroups(daemon->group->user, daemon->group->gid) == -1) {
            ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno),
                         wsgi_server, "mod_wsgi (pid=%d): Unable "
                         "to set groups for uname=%s and gid=%u.", getpid(),
                         daemon->group->user, (unsigned)daemon->group->gid);
        }
    }

    /* Setup the daemon process real and effective user. */

    if (setuid(daemon->group->uid) == -1) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno), wsgi_server,
                     "mod_wsgi (pid=%d): Unable to change to uid=%ld.",
                     getpid(), (long)daemon->group->uid);
    }
}

static int wsgi_setup_socket(WSGIProcessGroup *process)
{
    int sockfd = -1;
    struct sockaddr_un addr;
    mode_t omask;
    int rc;

    int sendsz = process->send_buffer_size;
    int recvsz = process->recv_buffer_size;

    ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                 "mod_wsgi (pid=%d): Socket for '%s' is '%s'.",
                 getpid(), process->name, process->socket);

    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno), wsgi_server,
                     "mod_wsgi (pid=%d): Couldn't create unix domain "
                     "socket.", getpid());
        return -1;
    }

#ifdef SO_SNDBUF
    if (sendsz) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF,
                       (void *)&sendsz, sizeof(sendsz)) == -1) {
            ap_log_error(APLOG_MARK, WSGI_LOG_WARNING(errno), wsgi_server,
                         "mod_wsgi (pid=%d): Failed to set send buffer "
                         "size on daemon process socket.", getpid());
        }
    }
#endif
#ifdef SO_RCVBUF
    if (recvsz) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF,
                       (void *)&recvsz, sizeof(recvsz)) == -1) {
            ap_log_error(APLOG_MARK, WSGI_LOG_WARNING(errno), wsgi_server,
                         "mod_wsgi (pid=%d): Failed to set receive buffer "
                         "size on daemon process socket.", getpid());
        }
    }
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    apr_cpystrn(addr.sun_path, process->socket, sizeof(addr.sun_path));

    omask = umask(0077);
    rc = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    if (rc < 0 && errno == EADDRINUSE) {
        ap_log_error(APLOG_MARK, WSGI_LOG_WARNING(errno), wsgi_server,
                     "mod_wsgi (pid=%d): Removing stale unix domain "
                     "socket '%s'.", getpid(), process->socket);

        unlink(process->socket);

        rc = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    }

    umask(omask);

    if (rc < 0) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno), wsgi_server,
                     "mod_wsgi (pid=%d): Couldn't bind unix domain "
                     "socket '%s'.", getpid(), process->socket);
        return -1;
    }

    if (listen(sockfd, WSGI_LISTEN_BACKLOG) < 0) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno), wsgi_server,
                     "mod_wsgi (pid=%d): Couldn't listen on unix domain "
                     "socket.", getpid());
        return -1;
    }

    /*
     * Set the ownership of the UNIX listener socket. This would
     * normally be the Apache user that the Apache server child
     * processes run as, as they are the only processes that
     * would connect to the sockets. In the case of ITK MPM,
     * having them owned by Apache user is useless as at the
     * time the request is to be proxied, the Apache server
     * child process will have uid corresponding to the user
     * whose request they are handling. For ITK, thus set the
     * ownership to be the same as the daemon processes. This is
     * still restrictive, in that can only connect to daemon
     * process group running under same user, but most of the
     * time that is what you would want anyway when using ITK
     * MPM.
     */

    if (!geteuid()) {
#if defined(MPM_ITK)
        if (chown(process->socket, process->uid, -1) < 0) {
#else
        if (chown(process->socket, ap_unixd_config.user_id, -1) < 0) {
#endif
            ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno), wsgi_server,
                         "mod_wsgi (pid=%d): Couldn't change owner of unix "
                         "domain socket '%s'.", getpid(),
                         process->socket);
            return -1;
        }
    }

    return sockfd;
}

static int wsgi_hook_daemon_handler(conn_rec *c);

static void wsgi_process_socket(apr_pool_t *p, apr_socket_t *sock,
                                apr_bucket_alloc_t *bucket_alloc,
                                WSGIDaemonProcess *daemon)
{
    apr_status_t rv;

    conn_rec *c;
    ap_sb_handle_t *sbh;
    core_net_rec *net;

    /*
     * This duplicates Apache connection setup. This is done
     * here rather than letting Apache do it so that avoid the
     * possibility that any Apache modules, such as mod_ssl
     * will add their own input/output filters to the chain.
     */

    ap_create_sb_handle(&sbh, p, -1, 0);

    c = (conn_rec *)apr_pcalloc(p, sizeof(conn_rec));

    c->sbh = sbh;

    c->conn_config = ap_create_conn_config(p);
    c->notes = apr_table_make(p, 5);
    c->pool = p;

    if ((rv = apr_socket_addr_get(&c->local_addr, APR_LOCAL, sock))
        != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, WSGI_LOG_INFO(rv), wsgi_server,
                     "mod_wsgi (pid=%d): Failed call "
                     "apr_socket_addr_get(APR_LOCAL).", getpid());
        apr_socket_close(sock);
        return;
    }
    apr_sockaddr_ip_get(&c->local_ip, c->local_addr);

    if ((rv = apr_socket_addr_get(&c->remote_addr, APR_REMOTE, sock))
        != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, WSGI_LOG_INFO(rv), wsgi_server,
                     "mod_wsgi (pid=%d): Failed call "
                     "apr_socket_addr_get(APR_REMOTE).", getpid());
        apr_socket_close(sock);
        return;
    }
    apr_sockaddr_ip_get(&c->remote_ip, c->remote_addr);

    c->base_server = daemon->group->server;

    c->bucket_alloc = bucket_alloc;
    c->id = 1;

    net = apr_palloc(c->pool, sizeof(core_net_rec));

    rv = apr_socket_timeout_set(sock, c->base_server->timeout);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(rv), wsgi_server,
                      "mod_wsgi (pid=%d): Failed call "
                      "apr_socket_timeout_set().", getpid());
    }

    net->c = c;
    net->in_ctx = NULL;
    net->out_ctx = NULL;
    net->client_socket = sock;

    ap_set_module_config(net->c->conn_config, &core_module, sock);
    ap_add_input_filter_handle(ap_core_input_filter_handle,
                               net, NULL, net->c);
    ap_add_output_filter_handle(ap_core_output_filter_handle,
                                net, NULL, net->c);

    wsgi_hook_daemon_handler(c);

    ap_lingering_close(c);
}

static apr_status_t wsgi_worker_acquire(int id)
{
    WSGIThreadStack *stack = wsgi_worker_stack;
    WSGIDaemonThread *thread = &wsgi_worker_threads[id];

    while (1) {
        apr_uint32_t state = stack->state;
        if (state & (WSGI_STACK_TERMINATED | WSGI_STACK_NO_LISTENER)) {
            if (state & WSGI_STACK_TERMINATED) {
                return APR_EINVAL;
            }
            if (apr_atomic_cas32(&(stack->state), WSGI_STACK_LAST, state) !=
                state) {
                continue;
            }
            else {
                return APR_SUCCESS;
            }
        }
        thread->next = state;
        if (apr_atomic_cas32(&(stack->state), (unsigned)id, state) != state) {
            continue;
        }
        else {
            apr_status_t rv;

            if (thread->wakeup) {
                thread->wakeup = 0;

                return APR_SUCCESS;
            }

            rv = apr_thread_cond_wait(thread->condition, thread->mutex);

            while (rv == APR_SUCCESS && !thread->wakeup)
                rv = apr_thread_cond_wait(thread->condition, thread->mutex);

            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(rv),
                             wsgi_server, "mod_wsgi (pid=%d): "
                             "Wait on thread %d wakeup condition variable "
                             "failed.", getpid(), id);
            }

            thread->wakeup = 0;

            return rv;
        }
    }
}

static apr_status_t wsgi_worker_release()
{
    WSGIThreadStack *stack = wsgi_worker_stack;

    while (1) {
        apr_uint32_t state = stack->state;
        unsigned int first = state & WSGI_STACK_HEAD;
        if (first == WSGI_STACK_LAST) {
            if (apr_atomic_cas32(&(stack->state),
                                 state | WSGI_STACK_NO_LISTENER,
                                 state) != state) {
                continue;
            }
            else {
                return APR_SUCCESS;
            }
        }
        else {
            WSGIDaemonThread *thread = &wsgi_worker_threads[first];
            if (apr_atomic_cas32(&(stack->state),
                                 (state ^ first) | thread->next,
                                 state) != state) {
                continue;
            }
            else {
                /*
                 * Flag that thread should be woken up and then
                 * signal it via the condition variable.
                 */

                apr_status_t rv;
                if ((rv = apr_thread_mutex_lock(thread->mutex)) !=
                    APR_SUCCESS) {
                    return rv;
                }

                thread->wakeup = 1;

                if ((rv = apr_thread_mutex_unlock(thread->mutex)) !=
                    APR_SUCCESS) {
                    return rv;
                }

                return apr_thread_cond_signal(thread->condition);
            }
        }
    }
}

static apr_status_t wsgi_worker_shutdown()
{
    int i;
    apr_status_t rv;
    WSGIThreadStack *stack = wsgi_worker_stack;

    while (1) {
        apr_uint32_t state = stack->state;
        if (apr_atomic_cas32(&(stack->state), state | WSGI_STACK_TERMINATED,
                           state) == state) {
            break;
        }
    }
    for (i = 0; i < wsgi_daemon_process->group->threads; i++) {
        if ((rv = wsgi_worker_release()) != APR_SUCCESS) {
            return rv;
        }
    }
    return APR_SUCCESS;
}

static void wsgi_daemon_worker(apr_pool_t *p, WSGIDaemonThread *thread)
{
    apr_status_t status;
    apr_socket_t *socket;

    apr_pool_t *ptrans;

    apr_pollset_t *pollset;
    apr_pollfd_t pfd = { 0 };
    apr_int32_t numdesc;
    const apr_pollfd_t *pdesc;

    apr_bucket_alloc_t *bucket_alloc;

    WSGIDaemonProcess *daemon = thread->process;
    WSGIProcessGroup *group = daemon->group;

    /* Loop until signal received to shutdown daemon process. */

    while (!wsgi_daemon_shutdown) {
        apr_status_t rv;

        apr_time_t start;
        apr_time_t duration;

        /*
         * Only allow one thread in this process to attempt to
         * acquire the global process lock as the global process
         * lock will actually allow all threads in this process
         * through once one in this process acquires lock. Only
         * allowing one means better chance of another process
         * subsequently getting it thereby distributing requests
         * across processes better and reducing chance of Python
         * GIL contention.
         */

        wsgi_worker_acquire(thread->id);

        if (wsgi_daemon_shutdown)
            break;

        if (group->mutex) {
            /*
             * Grab the accept mutex across all daemon processes
             * in this process group.
             */

            rv = apr_proc_mutex_lock(group->mutex);

            if (rv != APR_SUCCESS) {
#if defined(EIDRM)
                /*
                 * When using multiple threads locking the
                 * process accept mutex fails with an EIDRM when
                 * process being shutdown but signal check
                 * hasn't triggered quick enough to set shutdown
                 * flag. This causes lots of error messages to
                 * be logged which make it look like something
                 * nasty has happened even when it hasn't. For
                 * now assume that if multiple threads and EIDRM
                 * occurs that it is okay and the process is
                 * being shutdown. The condition should by
                 * rights only occur when the Apache parent
                 * process is being shutdown or has died for
                 * some reason so daemon process would logically
                 * therefore also be in process of being
                 * shutdown or killed.
                 */
                if (!strcmp(apr_proc_mutex_name(group->mutex), "sysvsem")) {
                    if (errno == EIDRM && group->threads > 1)
                        wsgi_daemon_shutdown = 1;
                }
#endif

                if (!wsgi_daemon_shutdown) {
                    ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(rv),
                                 wsgi_server, "mod_wsgi (pid=%d): "
                                 "Couldn't acquire accept mutex '%s'. "
                                 "Shutting down daemon process.",
                                 getpid(), group->socket);

                    kill(getpid(), SIGTERM);
                    sleep(5);
                }

                break;
            }

            /*
             * Daemon process being shutdown so don't accept the
             * connection after all.
             */

            if (wsgi_daemon_shutdown) {
                apr_proc_mutex_unlock(group->mutex);

                wsgi_worker_release();

                break;
            }
        }

        apr_pool_create(&ptrans, p);

        /*
         * Accept socket connection from the child process. We
         * test the socket for whether it is ready before actually
         * performing the accept() so that can know for sure that
         * we will be processing a request and flag thread as
         * running. Only bother to do join with thread which is
         * actually running when process is being shutdown.
         */

        apr_pollset_create(&pollset, 1, ptrans, 0);

        memset(&pfd, '\0', sizeof(pfd));
        pfd.desc_type = APR_POLL_SOCKET;
        pfd.desc.s = daemon->listener;
        pfd.reqevents = APR_POLLIN;
        pfd.client_data = daemon;

        apr_pollset_add(pollset, &pfd);

        rv = apr_pollset_poll(pollset, -1, &numdesc, &pdesc);

        if (rv != APR_SUCCESS && !APR_STATUS_IS_EINTR(rv)) {
            ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(rv),
                         wsgi_server, "mod_wsgi (pid=%d): "
                         "Unable to poll daemon socket for '%s'. "
                         "Shutting down daemon process.",
                         getpid(), group->socket);

            wsgi_daemon_shutdown++;
            kill(getpid(), SIGTERM);
            sleep(5);

            break;
        }

        if (wsgi_daemon_shutdown) {
            if (group->mutex)
                apr_proc_mutex_unlock(group->mutex);

            wsgi_worker_release();

            apr_pool_destroy(ptrans);

            break;
        }

        if (rv != APR_SUCCESS && APR_STATUS_IS_EINTR(rv)) {
            if (group->mutex)
                apr_proc_mutex_unlock(group->mutex);

            wsgi_worker_release();

            apr_pool_destroy(ptrans);

            continue;
        }

        thread->running = 1;

        status = apr_socket_accept(&socket, daemon->listener, ptrans);

        if (group->mutex) {
            apr_status_t rv;
            rv = apr_proc_mutex_unlock(group->mutex);
            if (rv != APR_SUCCESS) {
                if (!wsgi_daemon_shutdown) {
                    wsgi_worker_release();

                    ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(rv),
                                 wsgi_server, "mod_wsgi (pid=%d): "
                                 "Couldn't release accept mutex '%s'.",
                                 getpid(), group->socket);

                    apr_pool_destroy(ptrans);
                    thread->running = 0;

                    break;
                }
            }
        }

        wsgi_worker_release();

        if (status != APR_SUCCESS && APR_STATUS_IS_EINTR(status)) {
            apr_pool_destroy(ptrans);
            thread->running = 0;

            continue;
        }

        /* Process the request proxied from the child process. */

        bucket_alloc = apr_bucket_alloc_create(ptrans);
        wsgi_process_socket(ptrans, socket, bucket_alloc, daemon);

        /* Cleanup ready for next request. */

        apr_pool_destroy(ptrans);

        thread->running = 0;

        /* Check to see if maximum number of requests reached. */

        if (daemon->group->maximum_requests) {
            if (--wsgi_request_count <= 0) {
                if (!wsgi_daemon_shutdown) {
                    ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                                 "mod_wsgi (pid=%d): Maximum requests "
                                 "reached '%s'.", getpid(),
                                 daemon->group->name);
                }

                wsgi_daemon_shutdown++;
                kill(getpid(), SIGINT);
            }
        }
    }
}

static void *wsgi_daemon_thread(apr_thread_t *thd, void *data)
{
    WSGIDaemonThread *thread = data;
    apr_pool_t *p = apr_thread_pool_get(thd);

    apr_thread_mutex_lock(thread->mutex);

    wsgi_daemon_worker(p, thread);

    apr_thread_exit(thd, APR_SUCCESS);

    return NULL;
}

static void *wsgi_reaper_thread(apr_thread_t *thd, void *data)
{
    WSGIDaemonProcess *daemon = data;

    sleep(daemon->group->shutdown_timeout);

    ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                 "mod_wsgi (pid=%d): Aborting process '%s'.",
                 getpid(), daemon->group->name);

    exit(-1);

    return NULL;
}

static void *wsgi_deadlock_thread(apr_thread_t *thd, void *data)
{
    WSGIDaemonProcess *daemon = data;

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                     "mod_wsgi (pid=%d): Enable deadlock thread in "
                     "process '%s'.", getpid(), daemon->group->name);
    }

    apr_thread_mutex_lock(wsgi_shutdown_lock);
    wsgi_deadlock_shutdown_time = apr_time_now();
    wsgi_deadlock_shutdown_time += wsgi_deadlock_timeout;
    apr_thread_mutex_unlock(wsgi_shutdown_lock);

    while (1) {
        apr_sleep(apr_time_from_sec(1));

        PyEval_AcquireLock();
        PyEval_ReleaseLock();

        apr_thread_mutex_lock(wsgi_shutdown_lock);
        wsgi_deadlock_shutdown_time = apr_time_now();
        wsgi_deadlock_shutdown_time += wsgi_deadlock_timeout;
        apr_thread_mutex_unlock(wsgi_shutdown_lock);
    }

    return NULL;
}

static void *wsgi_monitor_thread(apr_thread_t *thd, void *data)
{
    WSGIDaemonProcess *daemon = data;

    int restart = 0;

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                     "mod_wsgi (pid=%d): Enable monitor thread in "
                     "process '%s'.", getpid(), daemon->group->name);

        ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                     "mod_wsgi (pid=%d): Deadlock timeout is %d.",
                     getpid(), (int)(apr_time_sec(wsgi_deadlock_timeout)));
        ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                     "mod_wsgi (pid=%d): Inactivity timeout is %d.",
                     getpid(), (int)(apr_time_sec(wsgi_inactivity_timeout)));
    }

    while (1) {
        apr_time_t now;

        apr_time_t deadlock_time;
        apr_time_t inactivity_time;

        apr_interval_time_t period = 0;

        now = apr_time_now();

        apr_thread_mutex_lock(wsgi_shutdown_lock);
        deadlock_time = wsgi_deadlock_shutdown_time;
        inactivity_time = wsgi_inactivity_shutdown_time;
        apr_thread_mutex_unlock(wsgi_shutdown_lock);

        if (!restart && wsgi_deadlock_timeout) {
            if (deadlock_time) {
                if (deadlock_time <= now) {
                    ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                                 "mod_wsgi (pid=%d): Daemon process deadlock "
                                 "timer expired, stopping process '%s'.",
                                 getpid(), daemon->group->name);

                    restart = 1;
                }
                else {
                    period = deadlock_time - now;
                }
            }
            else {
                period = wsgi_deadlock_timeout;
            }
        }

        if (!restart && wsgi_inactivity_timeout) {
            if (inactivity_time) {
                if (inactivity_time <= now) {
                    ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                                 "mod_wsgi (pid=%d): Daemon process "
                                 "inactivity timer expired, stopping "
                                 "process '%s'.", getpid(),
                                 daemon->group->name);

                    restart = 1;
                }
                else {
                    if (!period || ((inactivity_time - now) < period))
                        period = inactivity_time - now;
                }
            }
            else {
                if (!period || (wsgi_inactivity_timeout < period))
                    period = wsgi_inactivity_timeout;
            }
        }

        if (restart) {
            wsgi_daemon_shutdown++;
            kill(getpid(), SIGINT);
        }

        if (restart || period <= 0)
            period = apr_time_from_sec(1);

        apr_sleep(period);
    }

    return NULL;
}

static void wsgi_daemon_main(apr_pool_t *p, WSGIDaemonProcess *daemon)
{
    apr_threadattr_t *thread_attr;
    apr_thread_t *reaper = NULL;

    int i;
    apr_status_t rv;
    apr_status_t thread_rv;

    apr_pollfd_t poll_fd;
    apr_int32_t poll_count = 0;

    /*
     * Create pipe by which signal handler can notify the main
     * thread that signal has arrived indicating that process
     * needs to shutdown.
     */

    rv = apr_file_pipe_create(&wsgi_signal_pipe_in, &wsgi_signal_pipe_out, p);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, WSGI_LOG_EMERG(rv), wsgi_server,
                     "mod_wsgi (pid=%d): Couldn't initialise signal "
                     "pipe in daemon process '%s'.", getpid(),
                     daemon->group->name);
        sleep(20);

        return;
    }

    poll_fd.desc_type = APR_POLL_FILE;
    poll_fd.reqevents = APR_POLLIN;
    poll_fd.desc.f = wsgi_signal_pipe_in;

    /* Initialise maximum request count for daemon. */

    if (daemon->group->maximum_requests)
        wsgi_request_count = daemon->group->maximum_requests;

    /* Ensure that threads are joinable. */

    apr_threadattr_create(&thread_attr, p);
    apr_threadattr_detach_set(thread_attr, 0);

#if (APR_MAJOR_VERSION >= 1)
    if (daemon->group->stack_size) {
        apr_threadattr_stacksize_set(thread_attr, daemon->group->stack_size);
    }
#endif

    /* Start monitoring thread if required. */

    wsgi_deadlock_timeout = daemon->group->deadlock_timeout;
    wsgi_inactivity_timeout = daemon->group->inactivity_timeout;

    if (wsgi_deadlock_timeout || wsgi_inactivity_timeout) {
        apr_thread_mutex_create(&wsgi_shutdown_lock,
                                APR_THREAD_MUTEX_UNNESTED, p);

        rv = apr_thread_create(&reaper, thread_attr, wsgi_monitor_thread,
                               daemon, p);

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(rv), wsgi_server,
                         "mod_wsgi (pid=%d): Couldn't create monitor "
                         "thread in daemon process '%s'.", getpid(),
                         daemon->group->name);
        }
    }

    if (wsgi_deadlock_timeout) {
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(rv), wsgi_server,
                         "mod_wsgi (pid=%d): Couldn't create deadlock "
                         "thread in daemon process '%s'.", getpid(),
                         daemon->group->name);
        }

        rv = apr_thread_create(&reaper, thread_attr, wsgi_deadlock_thread,
                               daemon, p);
    }

    /* Initialise worker stack. */

    wsgi_worker_stack = (WSGIThreadStack *)apr_palloc(p,
            sizeof(WSGIThreadStack));
    wsgi_worker_stack->state = WSGI_STACK_NO_LISTENER | WSGI_STACK_LAST;

    /* Start the required number of threads. */

    wsgi_worker_threads = (WSGIDaemonThread *)apr_pcalloc(p,
                           daemon->group->threads * sizeof(WSGIDaemonThread));

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                     "mod_wsgi (pid=%d): Starting %d threads in daemon "
                     "process '%s'.", getpid(), daemon->group->threads,
                     daemon->group->name);
    }

    for (i=0; i<daemon->group->threads; i++) {
        WSGIDaemonThread *thread = &wsgi_worker_threads[i];

        if (wsgi_server_config->verbose_debugging) {
            ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                         "mod_wsgi (pid=%d): Starting thread %d in daemon "
                         "process '%s'.", getpid(), i+1, daemon->group->name);
        }

        /* Create the mutex and condition variable for this thread. */

        rv = apr_thread_cond_create(&thread->condition, p);

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(rv), wsgi_server,
                         "mod_wsgi (pid=%d): Couldn't create worker "
                         "thread %d state condition variable in daemon "
                         "process '%s'.", getpid(), i, daemon->group->name);

            /*
             * Try to force an exit of the process if fail
             * to create the worker threads.
             */

            kill(getpid(), SIGTERM);
            sleep(5);
        }

        rv = apr_thread_mutex_create(&thread->mutex,
                                     APR_THREAD_MUTEX_DEFAULT, p);

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(rv), wsgi_server,
                         "mod_wsgi (pid=%d): Couldn't create worker "
                         "thread %d state mutex variable in daemon "
                         "process '%s'.", getpid(), i, daemon->group->name);

            /*
             * Try to force an exit of the process if fail
             * to create the worker threads.
             */

            kill(getpid(), SIGTERM);
            sleep(5);
        }

        /* Now create the actual thread. */

        thread->id = i;
        thread->process = daemon;
        thread->running = 0;

        rv = apr_thread_create(&thread->thread, thread_attr,
                               wsgi_daemon_thread, thread, p);

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(rv), wsgi_server,
                         "mod_wsgi (pid=%d): Couldn't create worker "
                         "thread %d in daemon process '%s'.", getpid(),
                         i, daemon->group->name);

            /*
             * Try to force an exit of the process if fail
             * to create the worker threads.
             */

            kill(getpid(), SIGTERM);
            sleep(5);
        }
    }

    /* Block until we get a process shutdown signal. */

    do {
        rv = apr_poll(&poll_fd, 1, &poll_count, -1);
    } while (APR_STATUS_IS_EINTR(rv));

    if (wsgi_cpu_time_limit_exceeded) {
        ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                     "mod_wsgi (pid=%d): Exceeded CPU time limit '%s'.",
                     getpid(), daemon->group->name);
    }

    ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                 "mod_wsgi (pid=%d): Shutdown requested '%s'.",
                 getpid(), daemon->group->name);

    /*
     * Create a reaper thread to abort process if graceful
     * shutdown takes too long. Not recommended to disable
     * this unless external process is controlling shutdown.
     */

    if (daemon->group->shutdown_timeout) {
        rv = apr_thread_create(&reaper, thread_attr, wsgi_reaper_thread,
                               daemon, p);

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(rv), wsgi_server,
                         "mod_wsgi (pid=%d): Couldn't create reaper "
                         "thread in daemon process '%s'.", getpid(),
                         daemon->group->name);
        }
    }

    /*
     * Attempt a graceful shutdown by waiting for any
     * threads which were processing a request at the time
     * of shutdown. In some respects this is a bit pointless
     * as even though we allow the requests to be completed,
     * the Apache child process which proxied the request
     * through to this daemon process could get killed off
     * before the daemon process and so the response gets
     * cut off or lost.
     */

    wsgi_worker_shutdown();

    for (i=0; i<daemon->group->threads; i++) {
        if (wsgi_worker_threads[i].thread && wsgi_worker_threads[i].running) {
            rv = apr_thread_join(&thread_rv, wsgi_worker_threads[i].thread);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(rv), wsgi_server,
                             "mod_wsgi (pid=%d): Couldn't join with "
                             "worker thread %d in daemon process '%s'.",
                             getpid(), i, daemon->group->name);
            }
        }
    }
}

static apr_status_t wsgi_cleanup_process(void *data)
{
    WSGIProcessGroup *group = (WSGIProcessGroup *)data;

    /* Only do cleanup if in Apache parent process. */

    if (wsgi_parent_pid != getpid())
        return APR_SUCCESS;

    if (group->listener_fd != -1) {
        if (close(group->listener_fd) < 0) {
            ap_log_error(APLOG_MARK, WSGI_LOG_ERR(errno),
                         wsgi_server, "mod_wsgi (pid=%d): "
                         "Couldn't close unix domain socket '%s'.",
                         getpid(), group->socket);
        }

        if (unlink(group->socket) < 0 && errno != ENOENT) {
            ap_log_error(APLOG_MARK, WSGI_LOG_ERR(errno),
                         wsgi_server, "mod_wsgi (pid=%d): "
                         "Couldn't unlink unix domain socket '%s'.",
                         getpid(), group->socket);
        }
    }

    return APR_SUCCESS;
}

static int wsgi_start_process(apr_pool_t *p, WSGIDaemonProcess *daemon)
{
    apr_status_t status;

    ap_listen_rec *lr;

    WSGIProcessGroup *entries = NULL;
    WSGIProcessGroup *entry = NULL;
    int i = 0;

    if ((status = apr_proc_fork(&daemon->process, p)) < 0) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(errno), wsgi_server,
                     "mod_wsgi: Couldn't spawn process '%s'.",
                     daemon->group->name);
        return DECLINED;
    }
    else if (status == APR_INCHILD) {
        if (!geteuid()) {
            ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                         "mod_wsgi (pid=%d): Starting process '%s' with "
                         "uid=%ld, gid=%u and threads=%d.", getpid(),
                         daemon->group->name, (long)daemon->group->uid,
                         (unsigned)daemon->group->gid, daemon->group->threads);
        }
        else {
            ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                         "mod_wsgi (pid=%d): Starting process '%s' with "
                         "threads=%d.", getpid(), daemon->group->name,
                         daemon->group->threads);
        }

#ifdef HAVE_BINDPROCESSOR
        /*
         * By default, AIX binds to a single processor.  This
         * bit unbinds children which will then bind to another
         * CPU.
         */

        status = bindprocessor(BINDPROCESS, (int)getpid(),
                               PROCESSOR_CLASS_ANY);
        if (status != OK) {
            ap_log_error(APLOG_MARK, WSGI_LOG_ERR(errno), wsgi_server,
                         "mod_wsgi (pid=%d): Failed to unbind processor.",
                         getpid());
        }
#endif

        /* Setup daemon process name displayed by 'ps'. */

        wsgi_setup_daemon_name(daemon, p);

        /* Adjust CPU priority if overridden. */

        if (daemon->group->cpu_priority != 0) {
            if (setpriority(PRIO_PROCESS, 0,
                            daemon->group->cpu_priority) == -1) {
                ap_log_error(APLOG_MARK, WSGI_LOG_ERR(errno), wsgi_server,
                             "mod_wsgi (pid=%d): Couldn't set CPU priority "
                             "in daemon process '%d'.", getpid(),
                             daemon->group->cpu_priority);
            }
        }

        /* Setup daemon process user/group/umask etc. */

        wsgi_setup_access(daemon);

        /* Reinitialise accept mutex in daemon process. */

        if (daemon->group->mutex) {
            status = apr_proc_mutex_child_init(&daemon->group->mutex,
                                               daemon->group->mutex_path, p);

            if (status != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(0), wsgi_server,
                             "mod_wsgi (pid=%d): Couldn't intialise accept "
                             "mutex in daemon process '%s'.",
                             getpid(), daemon->group->mutex_path);

                /* Don't die immediately to avoid a fork bomb. */

                sleep(20);

                exit(-1);
            }
        }

        /*
         * Create a lookup table of listener socket address
         * details so can use it later in daemon when trying
         * to map request to correct virtual host server.
         */

        wsgi_daemon_listeners = apr_hash_make(p);

        for (lr = ap_listeners; lr; lr = lr->next) {
            char *key;
            char *host;
            apr_port_t port;

            host = lr->bind_addr->hostname;
            port = lr->bind_addr->port;

            if (!host)
                host = "";

            key = apr_psprintf(p, "%s|%d", host, port);

            apr_hash_set(wsgi_daemon_listeners, key, APR_HASH_KEY_STRING,
                         lr->bind_addr);
        }

        /*
         * Close child copy of the listening sockets for the
         * Apache parent process so we don't interfere with
         * the parent process.
         */

        ap_close_listeners();

        /*
         * Cleanup the Apache scoreboard to ensure that any
         * shared memory segments or memory mapped files not
         * available to code in daemon processes.
         */

        ap_cleanup_scoreboard(0);

        /*
         * Wipe out random value used in magic token so that not
         * possible for user code running in daemon process to
         * discover this value for other daemon process groups.
         * In other words, wipe out all but our own.
         */

        entries = (WSGIProcessGroup *)wsgi_daemon_list->elts;

        for (i = 0; i < wsgi_daemon_list->nelts; ++i) {
            entry = &entries[i];

            if (entry != daemon->group)
                entry->random = 0;
        }

        /*
         * Close listener socket for daemon processes for other
         * daemon process groups. In other words, close all but
         * our own.
         */

        entries = (WSGIProcessGroup *)wsgi_daemon_list->elts;

        for (i = 0; i < wsgi_daemon_list->nelts; ++i) {
            entry = &entries[i];

            if (entry != daemon->group && entry->listener_fd != -1) {
                close(entry->listener_fd);
                entry->listener_fd = -1;
            }
        }

        /*
         * Register signal handler to receive shutdown signal
         * from Apache parent process.
         */

        wsgi_daemon_shutdown = 0;

        apr_signal(SIGINT, wsgi_signal_handler);
        apr_signal(SIGTERM, wsgi_signal_handler);
#ifdef SIGXCPU
        apr_signal(SIGXCPU, wsgi_signal_handler);
#endif

        /* Set limits on amount of CPU time that can be used. */

        if (daemon->group->cpu_time_limit > 0) {
            struct rlimit limit;

            limit.rlim_cur = daemon->group->cpu_time_limit;

            limit.rlim_max = daemon->group->cpu_time_limit + 1;
            limit.rlim_max += daemon->group->shutdown_timeout;

            if (setrlimit(RLIMIT_CPU, &limit) == -1) {
                ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(0), wsgi_server,
                             "mod_wsgi (pid=%d): Couldn't set CPU time "
                             "limit of %d seconds for process '%s'.", getpid(),
                             daemon->group->cpu_time_limit,
                             daemon->group->name);
            }
        }

        /*
         * Flag whether multiple daemon processes or denoted
         * that requests could be spread across multiple daemon
         * process groups.
         */

        wsgi_multiprocess = daemon->group->multiprocess;
        wsgi_multithread = daemon->group->threads != 1;

        /*
         * Create a pool for the child daemon process so
         * we can trigger various events off it at shutdown.
         */

        apr_pool_create(&wsgi_daemon_pool, p);

        /*
         * Initialise Python if required to be done in the child
         * process. Note that it will not be initialised if
         * mod_python loaded and it has already been done.
         */

        if (wsgi_python_after_fork)
            wsgi_python_init(p);

        /*
         * If mod_python is also being loaded and thus it was
         * responsible for initialising Python it can leave in
         * place an active thread state. Under normal conditions
         * this would be eliminated in Apache child process by
         * the time that mod_wsgi got to do its own child
         * initialisation but in daemon process we skip the
         * mod_python child initialisation so the active thread
         * state still exists. Thus need to do a bit of a fiddle
         * to ensure there is no active thread state.
         */

        if (!wsgi_python_initialized) {
            PyGILState_STATE state;

            PyEval_AcquireLock();

            state = PyGILState_Ensure();
            PyGILState_Release(state);

            if (state == PyGILState_LOCKED)
                PyThreadState_Swap(NULL);

            PyEval_ReleaseLock();
        }

        /*
         * If the daemon is associated with a virtual host then
         * we can close all other error logs so long as they
         * aren't the same one as being used for the virtual
         * host. If the virtual host error log is different to
         * the main server error log, then also tie stderr to
         * that log file instead. This way any debugging sent
         * direct to stderr from C code also goes to the virtual
         * host error log. We close the error logs that aren't
         * required as that eliminates possibility that user
         * code executing in daemon process could maliciously
         * dump messages into error log for a different virtual
         * host, as well as stop them being reopened with mode
         * that would allow seeking back to start of file and
         * read any information in them.
         */

        if (daemon->group->server->is_virtual) {
            server_rec *server = NULL;
            apr_file_t *errfile = NULL;

            /*
             * Iterate over all servers and close any error
             * logs different to that for virtual host. Note that
             * if errors are being redirected to syslog, then
             * the server error log reference will actually be
             * a null pointer, so need to ensure that check for
             * that and don't attempt to close it in that case.
             */

            server = wsgi_server;

            while (server != NULL) {
                if (server->error_log &&
                    server->error_log != daemon->group->server->error_log) {
                    apr_file_close(server->error_log);
                }

                server = server->next;
            }

            /*
             * Reassociate stderr output with error log from the
             * virtual host the daemon is associated with. Close
             * the virtual host error log and point it at stderr
             * log instead. Do the latter so don't get two
             * references to same open file. Just in case
             * anything still accesses error log of main server,
             * map main server error log to that of the virtual
             * host. Note that cant do this if errors are being
             * redirected to syslog, as indicated by virtual
             * host error log being a null pointer. In that case
             * just leave everything as it was. Also can't remap
             * the error log for main server if it was being
             * redirected to syslog but virtual host wasn't.
             */

            if (daemon->group->server->error_log  &&
                daemon->group->server->error_log != wsgi_server->error_log) {

                apr_file_t *oldfile = NULL;

                apr_file_open_stderr(&errfile, wsgi_server->process->pool);
                apr_file_dup2(errfile, daemon->group->server->error_log,
                              wsgi_server->process->pool);

                oldfile = daemon->group->server->error_log;

                server = wsgi_server;

                while (server != NULL) {
                    if (server->error_log == oldfile)
                        server->error_log = errfile;
                    server = server->next;
                }

                apr_file_close(oldfile);

                if (wsgi_server->error_log)
                    wsgi_server->error_log = errfile;
            }
        }

        /*
         * Update reference to server object in case daemon
         * process is actually associated with a virtual host.
         * This way all logging actually goes into the virtual
         * hosts log file.
         */

        if (daemon->group->server) {
            if (wsgi_server_config->verbose_debugging) {
                ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                             "mod_wsgi (pid=%d): Process '%s' logging to "
                             "'%s'.", getpid(), daemon->group->name,
                             daemon->group->server->server_hostname);
            }

            wsgi_server = daemon->group->server;
        }
        else {
            if (wsgi_server_config->verbose_debugging) {
                ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                             "mod_wsgi (pid=%d): Process '%s' forced to log "
                             "to '%s'.", getpid(), daemon->group->name,
                             wsgi_server->server_hostname);
            }
        }

        /* Retain a reference to daemon process details. */

        wsgi_daemon_group = daemon->group->name;
        wsgi_daemon_process = daemon;

        /*
         * Setup Python in the child daemon process. Note that
         * we ensure that we are now marked as the original
         * initialiser of the Python interpreter even though
         * mod_python might have done it, as we will be the one
         * to cleanup the child daemon process and not
         * mod_python. We also need to perform the special
         * Python setup which has to be done after a fork.
         */

        wsgi_python_initialized = 1;
        wsgi_python_path = daemon->group->python_path;
        wsgi_python_eggs = daemon->group->python_eggs;
        wsgi_python_child_init(wsgi_daemon_pool);

        /*
         * Create socket wrapper for listener file descriptor
         * and mutex for controlling which thread gets to
         * perform the accept() when a connection is ready.
         */

        apr_os_sock_put(&daemon->listener, &daemon->group->listener_fd, p);

        /* Run the main routine for the daemon process. */

        wsgi_daemon_main(p, daemon);

        /*
         * Destroy the pool for the daemon process. This will
         * have the side affect of also destroying Python.
         */

        ap_log_error(APLOG_MARK, WSGI_LOG_INFO(0), wsgi_server,
                     "mod_wsgi (pid=%d): Stopping process '%s'.", getpid(),
                     daemon->group->name);

        apr_pool_destroy(wsgi_daemon_pool);

        /* Exit the daemon process when being shutdown. */

        exit(-1);
    }

    apr_pool_note_subprocess(p, &daemon->process, APR_KILL_AFTER_TIMEOUT);
    apr_proc_other_child_register(&daemon->process, wsgi_manage_process,
                                  daemon, NULL, p);

    return OK;
}

static int wsgi_start_daemons(apr_pool_t *p)
{
    WSGIProcessGroup *entries = NULL;
    WSGIProcessGroup *entry = NULL;
    WSGIDaemonProcess *process = NULL;

    int mpm_generation = 0;

    int i, j;

    /* Do we need to create any daemon processes. */

    if (!wsgi_daemon_list)
        return OK;

    /* What server generation is this. */

#if defined(AP_MPMQ_GENERATION)
    ap_mpm_query(AP_MPMQ_GENERATION, &mpm_generation);
#else
    mpm_generation = ap_my_generation;
#endif

    /*
     * Cache references to root server and pool as will need
     * to access these when restarting daemon process when
     * they die.
     */

    wsgi_parent_pool = p;

    /*
     * Startup in turn the required number of daemon processes
     * for each of the named process groups.
     */

    wsgi_daemon_index = apr_hash_make(p);

    entries = (WSGIProcessGroup *)wsgi_daemon_list->elts;

    for (i = 0; i < wsgi_daemon_list->nelts; ++i) {
        int status;

        entry = &entries[i];

        /*
         * Check for whether the daemon process user and
         * group are the default Apache values. If they are
         * then reset them to the current values configured for
         * Apache. This is to work around where the User/Group
         * directives had not been set before the WSGIDaemonProcess
         * directive was used in configuration file. In this case,
         * where no 'user' and 'group' options were provided,
         * the default values would have been used, but these
         * were later overridden thus why we need to update it.
         */

        if (entry->uid == ap_uname2id(DEFAULT_USER)) {
            entry->uid = ap_unixd_config.user_id;
            entry->user = ap_unixd_config.user_name;

            ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                         "mod_wsgi (pid=%d): Reset default user for "
                         "daemon process group '%s' to uid=%ld.",
                         getpid(), entry->name, (long)entry->uid);
        }

        if (entry->gid == ap_gname2id(DEFAULT_GROUP)) {
            entry->gid = ap_unixd_config.group_id;

            ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                         "mod_wsgi (pid=%d): Reset default group for "
                         "daemon process group '%s' to gid=%ld.",
                         getpid(), entry->name, (long)entry->gid);
        }

        /*
         * Calculate path for socket to accept requests on and
         * create the socket.
         */

        entry->socket = apr_psprintf(p, "%s.%d.%d.%d.sock",
                                     wsgi_server_config->socket_prefix,
                                     getpid(), mpm_generation, entry->id);

        apr_hash_set(wsgi_daemon_index, entry->name, APR_HASH_KEY_STRING,
                     entry);

        entry->listener_fd = wsgi_setup_socket(entry);

        if (entry->listener_fd == -1)
            return DECLINED;

        /*
         * Register cleanup so that listener socket is cleaned
         * up properly on a restart and on shutdown.
         */

        apr_pool_cleanup_register(p, entry, wsgi_cleanup_process,
                                  apr_pool_cleanup_null);

        /*
         * If there is more than one daemon process in the group
         * then need to create an accept mutex for the daemon
         * processes to use so they don't interfere with each
         * other.
         */

        if (entry->processes > 1) {
            entry->mutex_path = apr_psprintf(p, "%s.%d.%d.%d.lock",
                                             wsgi_server_config->socket_prefix,
                                             getpid(), mpm_generation,
                                             entry->id);

            status = apr_proc_mutex_create(&entry->mutex, entry->mutex_path,
                                           wsgi_server_config->lock_mechanism,
                                           p);

            if (status != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(errno), wsgi_server,
                             "mod_wsgi (pid=%d): Couldn't create accept "
                             "lock '%s' (%d).", getpid(), entry->mutex_path,
                             wsgi_server_config->lock_mechanism);
                return DECLINED;
            }

            /*
             * Depending on the locking mechanism being used
             * need to change the permissions of the lock. Can't
             * use unixd_set_proc_mutex_perms() as it uses the
             * default Apache child process uid/gid where the
             * daemon process uid/gid can be different.
             */

            if (!geteuid()) {
#if APR_HAS_SYSVSEM_SERIALIZE
                if (!strcmp(apr_proc_mutex_name(entry->mutex), "sysvsem")) {
                    apr_os_proc_mutex_t ospmutex;
#if !APR_HAVE_UNION_SEMUN
                    union semun {
                        long val;
                        struct semid_ds *buf;
                        unsigned short *array;
                    };
#endif
                    union semun ick;
                    struct semid_ds buf;

                    apr_os_proc_mutex_get(&ospmutex, entry->mutex);
                    buf.sem_perm.uid = entry->uid;
                    buf.sem_perm.gid = entry->gid;
                    buf.sem_perm.mode = 0600;
                    ick.buf = &buf;
                    if (semctl(ospmutex.crossproc, 0, IPC_SET, ick) < 0) {
                        ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(errno),
                                     wsgi_server, "mod_wsgi (pid=%d): "
                                     "Couldn't set permissions on accept "
                                     "mutex '%s' (sysvsem).", getpid(),
                                     entry->mutex_path);
                        return DECLINED;
                    }
                }
#endif
#if APR_HAS_FLOCK_SERIALIZE
                if (!strcmp(apr_proc_mutex_name(entry->mutex), "flock")) {
                    if (chown(entry->mutex_path, entry->uid, -1) < 0) {
                        ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(errno),
                                     wsgi_server, "mod_wsgi (pid=%d): "
                                     "Couldn't set permissions on accept "
                                     "mutex '%s' (flock).", getpid(),
                                     entry->mutex_path);
                        return DECLINED;
                    }
                }
#endif
            }
        }

        /* Create the actual required daemon processes. */

        for (j = 1; j <= entry->processes; j++) {
            process = (WSGIDaemonProcess *)apr_pcalloc(p, sizeof(
                                                       WSGIDaemonProcess));

            process->group = entry;
            process->instance = j;

            status = wsgi_start_process(p, process);

            if (status != OK)
                return status;
        }
    }

    return OK;
}

static apr_status_t wsgi_close_socket(void *data)
{
    WSGIDaemonSocket *daemon = NULL;

    daemon = (WSGIDaemonSocket *)data;

    return close(daemon->fd);
}

static int wsgi_connect_daemon(request_rec *r, WSGIDaemonSocket *daemon)
{
    struct sockaddr_un addr;

    int retries = 0;
    apr_interval_time_t timer = 0;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    apr_cpystrn(addr.sun_path, daemon->socket, sizeof addr.sun_path);

    while (1) {
        retries++;

        if ((daemon->fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(errno), r,
                         "mod_wsgi (pid=%d): Unable to create socket to "
                         "connect to WSGI daemon process.", getpid());

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        if (connect(daemon->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            if (errno == ECONNREFUSED && retries < WSGI_CONNECT_ATTEMPTS) {
                ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(errno), r,
                             "mod_wsgi (pid=%d): Connection attempt #%d to "
                             "WSGI daemon process '%s' on '%s' failed, "
                             "sleeping before retrying again.", getpid(),
                             retries, daemon->name, daemon->socket);

                close(daemon->fd);

                /*
		 * Progressively increase time we wait between
		 * connection attempts. Start at 0.1 second and
                 * double each time but apply ceiling at 2.0
                 * seconds.
                 */

                if (!timer)
                    timer = apr_time_make(0, 100000);

                apr_sleep(timer);

                timer = (2 * timer) % apr_time_make(2, 0);
            }
            else {
                ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(errno), r,
                             "mod_wsgi (pid=%d): Unable to connect to "
                             "WSGI daemon process '%s' on '%s' after "
                             "multiple attempts.", getpid(), daemon->name,
                             daemon->socket);

                close(daemon->fd);

                return HTTP_SERVICE_UNAVAILABLE;
            }
        }
        else {
            apr_pool_cleanup_register(r->pool, daemon, wsgi_close_socket,
                                      apr_pool_cleanup_null);

            break;
        }
    }

    return OK;
}

static apr_status_t wsgi_socket_send(int fd, const void *buf, size_t buf_size)
{
    int rc;

    do {
        rc = write(fd, buf, buf_size);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        return errno;
    }

    return APR_SUCCESS;
}

static apr_status_t wsgi_send_strings(apr_pool_t *p, int fd, const char **s)
{
    apr_status_t rv;

    apr_size_t total = 0;

    apr_size_t n;
    apr_size_t i;
    apr_size_t l;

    char *buffer;
    char *offset;

    total += sizeof(n);

    for (n = 0; s[n]; n++)
        total += (strlen(s[n]) + 1);

    buffer = apr_palloc(p, total + sizeof(total));
    offset = buffer;

    memcpy(offset, &total, sizeof(total));
    offset += sizeof(total);

    memcpy(offset, &n, sizeof(n));
    offset += sizeof(n);

    for (i = 0; i < n; i++) {
        l = (strlen(s[i]) + 1);
        memcpy(offset, s[i], l);
        offset += l;
    }

    total += sizeof(total);

    if ((rv = wsgi_socket_send(fd, buffer, total)) != APR_SUCCESS)
        return rv;

    return APR_SUCCESS;
}

static apr_status_t wsgi_send_request(request_rec *r,
                                      WSGIRequestConfig *config,
                                      WSGIDaemonSocket *daemon)
{
    int rv;

    char **vars;
    const apr_array_header_t *env_arr;
    const apr_table_entry_t *elts;
    int i, j;

    /* Send subprocess environment from request object. */

    env_arr = apr_table_elts(r->subprocess_env);
    elts = (const apr_table_entry_t *)env_arr->elts;

    vars = (char **)apr_palloc(r->pool,
                               ((2*env_arr->nelts)+1)*sizeof(char *));

    for (i=0, j=0; i<env_arr->nelts; ++i) {
        if (!elts[i].key)
            continue;

        vars[j++] = elts[i].key;
        vars[j++] = elts[i].val ? elts[i].val : "";
    }

    vars[j] = NULL;

    rv = wsgi_send_strings(r->pool, daemon->fd, (const char **)vars);

    if (rv != APR_SUCCESS)
        return rv;

    return APR_SUCCESS;
}

static void wsgi_discard_output(apr_bucket_brigade *bb)
{
    apr_bucket *e;
    const char *buf;
    apr_size_t len;
    apr_status_t rv;

    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e))
    {
        if (APR_BUCKET_IS_EOS(e)) {
            break;
        }
        rv = apr_bucket_read(e, &buf, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS) {
            break;
        }
    }
}

static int wsgi_execute_remote(request_rec *r)
{
    WSGIRequestConfig *config = NULL;
    WSGIDaemonSocket *daemon = NULL;
    WSGIProcessGroup *group = NULL;

    char *key = NULL;
    const char *hash = NULL;

    int status;
    apr_status_t rv;

    apr_interval_time_t timeout;
    int seen_eos;
    int child_stopped_reading;
    apr_file_t *tmpsock;
    apr_bucket_brigade *bbout;
    apr_bucket_brigade *bbin;
    apr_bucket *b;

    const char *location = NULL;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    /*
     * Only allow the process group to match against a restricted
     * set of processes if such a restricted set has been defined.
     */

    if (config->restrict_process) {
        if (!apr_table_get(config->restrict_process,
                           config->process_group)) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Daemon "
                                  "process called '%s' cannot be "
                                  "accessed by this WSGI application",
                                  config->process_group), r->filename);

            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /*
     * Do not process request as remote if actually targeted at
     * the main Apache processes.
     */

    if (!*config->process_group)
        return DECLINED;

    /* Grab details of matching process group. */

    if (!wsgi_daemon_index) {
        wsgi_log_script_error(r, apr_psprintf(r->pool, "No WSGI daemon "
                              "process called '%s' has been configured",
                              config->process_group), r->filename);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    group = (WSGIProcessGroup *)apr_hash_get(wsgi_daemon_index,
                                             config->process_group,
                                             APR_HASH_KEY_STRING);

    if (!group) {
        wsgi_log_script_error(r, apr_psprintf(r->pool, "No WSGI daemon "
                              "process called '%s' has been configured",
                              config->process_group), r->filename);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Only allow the process group to match against a daemon
     * process defined within a virtual host with the same
     * server name or a daemon process defined at global server
     * scope.
     */

    if (group->server != r->server && group->server != wsgi_server) {
        if (strcmp(group->server->server_hostname,
                   r->server->server_hostname) != 0) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Daemon "
                                  "process called '%s' cannot be "
                                  "accessed by this WSGI application",
                                  config->process_group), r->filename);

            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /*
     * Check restrictions related to the group of the WSGI
     * script file and who has write access to the directory it
     * is contained in. If not satisfied forbid access.
     */

    if (group->script_group) {
        apr_uid_t gid;
        struct group *grent = NULL;
        const char *grname = NULL;
        apr_finfo_t finfo;
        const char *path = NULL;

        if (!(r->finfo.valid & APR_FINFO_GROUP)) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Group "
                                  "information not available for WSGI "
                                  "script file"), r->filename);
            return HTTP_FORBIDDEN;
        }

        gid = r->finfo.group;

        if ((grent = getgrgid(gid)) == NULL) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Couldn't "
                                  "determine group of WSGI script file, "
                                  "gid=%ld", (long)gid), r->filename);
            return HTTP_FORBIDDEN;
        }

        grname = grent->gr_name;

        if (strcmp(group->script_group, grname)) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Group of WSGI "
                                  "script file does not match required group "
                                  "for daemon process, group=%s", grname),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        if (!(r->finfo.valid & APR_FINFO_WPROT)) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "World "
                                  "permissions not available for WSGI "
                                  "script file"), r->filename);
            return HTTP_FORBIDDEN;
        }

        if (r->finfo.protection & APR_FPROT_WWRITE) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "WSGI script "
                                  "file is writable to world"), r->filename);
            return HTTP_FORBIDDEN;
        }

        path = ap_make_dirstr_parent(r->pool, r->filename);

        if (apr_stat(&finfo, path, APR_FINFO_NORM, r->pool) != APR_SUCCESS) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Unable to stat "
                                  "parent directory of WSGI script"), path);
            return HTTP_FORBIDDEN;
        }

        gid = finfo.group;

        if ((grent = getgrgid(gid)) == NULL) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Couldn't "
                                  "determine group of parent directory of "
                                  "WSGI script file, gid=%ld", (long)gid),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        grname = grent->gr_name;

        if (strcmp(group->script_group, grname)) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Group of parent "
                                  "directory of WSGI script file does not "
                                  "match required group for daemon process, "
                                  "group=%s", grname), r->filename);
            return HTTP_FORBIDDEN;
        }

        if (finfo.protection & APR_FPROT_WWRITE) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Parent directory "
                                  "of WSGI script file is writable to world"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }
    }

    /*
     * Check restrictions related to who can be the owner of
     * the WSGI script file and who has write access to the
     * directory it is contained in. If not satisfied forbid
     * access.
     */

    if (group->script_user) {
        apr_uid_t uid;
        struct passwd *pwent = NULL;
        const char *pwname = NULL;
        apr_finfo_t finfo;
        const char *path = NULL;

        if (!(r->finfo.valid & APR_FINFO_USER)) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "User "
                                  "information not available for WSGI "
                                  "script file"), r->filename);
            return HTTP_FORBIDDEN;
        }

        uid = r->finfo.user;

        if ((pwent = getpwuid(uid)) == NULL) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Couldn't "
                                  "determine owner of WSGI script file, "
                                  "uid=%ld", (long)uid), r->filename);
            return HTTP_FORBIDDEN;
        }

        pwname = pwent->pw_name;

        if (strcmp(group->script_user, pwname)) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Owner of WSGI "
                                  "script file does not match required user "
                                  "for daemon process, user=%s", pwname),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        if (!(r->finfo.valid & APR_FINFO_GPROT)) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Group "
                                  "permissions not available for WSGI "
                                  "script file"), r->filename);
            return HTTP_FORBIDDEN;
        }

        if (r->finfo.protection & APR_FPROT_GWRITE) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "WSGI script "
                                  "file is writable to group"), r->filename);
            return HTTP_FORBIDDEN;
        }

        if (!(r->finfo.valid & APR_FINFO_WPROT)) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "World "
                                  "permissions not available for WSGI "
                                  "script file"), r->filename);
            return HTTP_FORBIDDEN;
        }

        if (r->finfo.protection & APR_FPROT_WWRITE) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "WSGI script "
                                  "file is writable to world"), r->filename);
            return HTTP_FORBIDDEN;
        }

        path = ap_make_dirstr_parent(r->pool, r->filename);

        if (apr_stat(&finfo, path, APR_FINFO_NORM, r->pool) != APR_SUCCESS) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Unable to stat "
                                  "parent directory of WSGI script"), path);
            return HTTP_FORBIDDEN;
        }

        uid = finfo.user;

        if ((pwent = getpwuid(uid)) == NULL) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Couldn't "
                                  "determine owner of parent directory of "
                                  "WSGI script file, uid=%ld", (long)uid),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        pwname = pwent->pw_name;

        if (strcmp(group->script_user, pwname)) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Owner of parent "
                                  "directory of WSGI script file does not "
                                  "match required user for daemon process, "
                                  "user=%s", pwname), r->filename);
            return HTTP_FORBIDDEN;
        }

        if (finfo.protection & APR_FPROT_WWRITE) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Parent directory "
                                  "of WSGI script file is writable to world"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        if (finfo.protection & APR_FPROT_GWRITE) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Parent directory "
                                  "of WSGI script file is writable to group"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }
    }

    /*
     * Add magic marker into request environment so that daemon
     * process can verify that request is from a sender that can
     * be trusted. Wipe out original key to make it a bit harder
     * for rogue code in Apache child processes to trawl through
     * memory looking for unhashed string.
     */

    key = apr_psprintf(r->pool, "%ld|%s|%s|%s", group->random,
                       group->socket, r->filename, config->handler_script);
    hash = ap_md5(r->pool, (const unsigned char *)key);
    memset(key, '\0', strlen(key));

    apr_table_setn(r->subprocess_env, "mod_wsgi.magic", hash);

    /* Create connection to the daemon process. */

    daemon = (WSGIDaemonSocket *)apr_pcalloc(r->pool,
                                             sizeof(WSGIDaemonSocket));

    daemon->name = config->process_group;
    daemon->socket = group->socket;

    if ((status = wsgi_connect_daemon(r, daemon)) != OK)
        return status;

    /* Send request details and subprocess environment. */

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                     "mod_wsgi (pid=%d): Request server was "
                     "'%s|%d'.", getpid(), r->server->server_hostname,
                     r->server->port);
    }

    if ((rv = wsgi_send_request(r, config, daemon)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(rv), r,
                     "mod_wsgi (pid=%d): Unable to send request details "
                     "to WSGI daemon process '%s' on '%s'.", getpid(),
                     daemon->name, daemon->socket);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Wrap the socket in an APR file object so that socket can
     * be more easily written to and so that pipe bucket can be
     * created later for reading from it. Note the file object is
     * initialised such that it will close socket when no longer
     * required so can kill off registration done at higher
     * level to close socket.
     */

    apr_os_pipe_put_ex(&tmpsock, &daemon->fd, 1, r->pool);
    apr_pool_cleanup_kill(r->pool, daemon, wsgi_close_socket);

    apr_file_pipe_timeout_get(tmpsock, &timeout);
    apr_file_pipe_timeout_set(tmpsock, r->server->timeout);

    /* Setup bucket brigade for reading response from daemon. */

    bbin = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    b = apr_bucket_pipe_create(tmpsock, r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bbin, b);
    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bbin, b);

    /*
     * If process reload mechanism enabled, then we need to look
     * for marker indicating it is okay to transfer content, or
     * whether process is being restarted and that we should
     * therefore create a connection to daemon process again.
     */

    if (*config->process_group) {
        int retries = 0;
        int maximum = (2*group->processes)+1;

        /*
         * While special header indicates a restart is being
         * done, then keep trying to reconnect. Cap the number
         * of retries to at most about 2 times the number of
         * daemon processes in the process group. If still being
         * told things are being restarted, then we will error
         * indicating service is unavailable.
         */

        while (retries < maximum) {

            /* Scan the CGI script like headers from daemon. */

            if ((status = ap_scan_script_header_err_brigade(r, bbin, NULL)))
                return HTTP_INTERNAL_SERVER_ERROR;

            /* Status must be zero for our special headers. */

            if (r->status != 0) {
                ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                             "mod_wsgi (pid=%d): Unexpected status from "
                             "WSGI daemon process '%d'.", getpid(), r->status);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            if (!strcmp(r->status_line, "0 Continue"))
                break;

            if (strcmp(r->status_line, "0 Rejected")) {
                ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                             "mod_wsgi (pid=%d): Unexpected status from "
                             "WSGI daemon process '%d'.", getpid(), r->status);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            /* Need to close previous socket connection first. */

            apr_file_close(tmpsock);

            /* Has maximum number of attempts been reached. */

            if (retries == maximum) {
                ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(rv), r,
                             "mod_wsgi (pid=%d): Maximum number of WSGI "
                             "daemon process restart connects reached '%d'.",
                             getpid(), maximum);
                return HTTP_SERVICE_UNAVAILABLE;
            }

            retries++;

            ap_log_rerror(APLOG_MARK, WSGI_LOG_INFO(0), r,
                         "mod_wsgi (pid=%d): Connect after WSGI daemon "
                         "process restart, attempt #%d.", getpid(),
                         retries);

            /* Connect and setup connection just like before. */

            if ((status = wsgi_connect_daemon(r, daemon)) != OK)
                return status;

            if ((rv = wsgi_send_request(r, config, daemon)) != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(rv), r,
                             "mod_wsgi (pid=%d): Unable to send request "
                             "details to WSGI daemon process '%s' on '%s'.",
                             getpid(), daemon->name, daemon->socket);

                return HTTP_INTERNAL_SERVER_ERROR;
            }

            apr_os_pipe_put_ex(&tmpsock, &daemon->fd, 1, r->pool);
            apr_pool_cleanup_kill(r->pool, daemon, wsgi_close_socket);

            apr_file_pipe_timeout_get(tmpsock, &timeout);
            apr_file_pipe_timeout_set(tmpsock, r->server->timeout);

            apr_brigade_destroy(bbin);

            bbin = apr_brigade_create(r->pool, r->connection->bucket_alloc);
            b = apr_bucket_pipe_create(tmpsock, r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bbin, b);
            b = apr_bucket_eos_create(r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bbin, b);
        }
    }


    /*
     * Need to reset request status value to HTTP_OK else it
     * screws up HTTP input filter when processing a POST
     * request with 100-continue requirement.
     */

    r->status = HTTP_OK;

    /* Transfer any request content which was provided. */

    seen_eos = 0;
    child_stopped_reading = 0;

    bbout = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    do {
        apr_bucket *bucket;

        rv = ap_get_brigade(r->input_filters, bbout, AP_MODE_READBYTES,
                            APR_BLOCK_READ, HUGE_STRING_LEN);

        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(rv), r,
                         "mod_wsgi (pid=%d): Unable to get bucket brigade "
                         "for request.", getpid());
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        for (bucket = APR_BRIGADE_FIRST(bbout);
             bucket != APR_BRIGADE_SENTINEL(bbout);
             bucket = APR_BUCKET_NEXT(bucket))
        {
            const char *data;
            apr_size_t len;

            if (APR_BUCKET_IS_EOS(bucket)) {
                seen_eos = 1;
                break;
            }

            /* We can't do much with this. */
            if (APR_BUCKET_IS_FLUSH(bucket)) {
                continue;
            }

            /* If the child stopped, we still must read to EOS. */
            if (child_stopped_reading) {
                continue;
            }

            /* Read block. */
            apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);

            /*
             * Keep writing data to the child until done or too
             * much time elapses with no progress or an error
             * occurs.
             */
            rv = apr_file_write_full(tmpsock, data, len, NULL);

            if (rv != APR_SUCCESS) {
                /* Daemon stopped reading, discard remainder. */
                child_stopped_reading = 1;
            }
        }
        apr_brigade_cleanup(bbout);
    }
    while (!seen_eos);

    apr_file_pipe_timeout_set(tmpsock, timeout);

    /*
     * Close socket for writing so that daemon detects end of
     * request content.
     */

    shutdown(daemon->fd, 1);

    /* Scan the CGI script like headers from daemon. */

    if ((status = ap_scan_script_header_err_brigade(r, bbin, NULL)))
        return HTTP_INTERNAL_SERVER_ERROR;

    /*
     * Look for special case of status being 0 and
     * translate it into a 500 error so that error
     * document processing will occur for those cases
     * where WSGI application wouldn't have supplied
     * their own error document.
     */

    if (r->status == 0)
        return HTTP_INTERNAL_SERVER_ERROR;

    /*
     * Look for 'Location' header and if an internal
     * redirect, execute the redirect. This behaviour is
     * consistent with how mod_cgi and mod_cgid work and
     * what is permitted by the CGI specification.
     */

    location = apr_table_get(r->headers_out, "Location");

    if (location && location[0] == '/' && r->status == 200) {
        /*
         * Discard all response content returned from
         * the daemon process.
         */

        wsgi_discard_output(bbin);
        apr_brigade_destroy(bbin);

        /*
         * The internal redirect needs to be a GET no
         * matter what the original method was.
         */

        r->method = apr_pstrdup(r->pool, "GET");
        r->method_number = M_GET;

        /*
         * We already read the message body (if any), so
         * don't allow the redirected request to think
         * it has one. Not sure if we need to worry
         * about removing 'Transfer-Encoding' header.
         */

        apr_table_unset(r->headers_in, "Content-Length");

        ap_internal_redirect_handler(location, r);

        return OK;
    }

    /*
     * Allow the web server to override any error
     * page produced by the WSGI application.
     */

    if (config->error_override && ap_is_HTTP_ERROR(r->status)) {
        status = r->status;

        r->status = HTTP_OK;
        r->status_line = NULL;

        /*
         * Discard all response content returned from
         * the daemon process if any expected.
         */

        if (!r->header_only && /* not HEAD request */
            (status != HTTP_NO_CONTENT) && /* not 204 */
            (status != HTTP_NOT_MODIFIED)) { /* not 304 */
            wsgi_discard_output(bbin);
            apr_brigade_destroy(bbin);
        }

        return status;
    }

    /* Transfer any response content. */

    ap_pass_brigade(r->output_filters, bbin);

    return OK;
}

static apr_status_t wsgi_socket_read(apr_socket_t *sock, void *vbuf,
                                     apr_size_t size)
{
    char *buf = vbuf;
    apr_status_t rv;
    apr_size_t count = 0;
    apr_size_t len = 0;

    do {
        len = size - count;
        if ((rv = apr_socket_recv(sock, buf + count, &len)) != APR_SUCCESS)
             return rv;
        count += len;
    } while (count < size);

    return APR_SUCCESS;
}

static apr_status_t wsgi_read_strings(apr_socket_t *sock, char ***s,
                                      apr_pool_t *p)
{
    apr_status_t rv;

    apr_size_t total;

    apr_size_t n;
    apr_size_t i;
    apr_size_t l;

    char *buffer;
    char *offset;

    if ((rv = wsgi_socket_read(sock, &total, sizeof(total))) != APR_SUCCESS)
        return rv;

    buffer = apr_palloc(p, total);
    offset = buffer;

    if ((rv = wsgi_socket_read(sock, buffer, total)) != APR_SUCCESS)
        return rv;

    memcpy(&n, offset, sizeof(n));
    offset += sizeof(n);

    *s = apr_pcalloc(p, (n+1)*sizeof(**s));

    for (i = 0; i < n; i++) {
        l = strlen(offset) + 1;
        (*s)[i] = offset;
        offset += l;
    }

    return APR_SUCCESS;
}

static apr_status_t wsgi_read_request(apr_socket_t *sock, request_rec *r)
{
    int rv;

    char **vars;

    /* Read subprocess environment from request object. */

    rv = wsgi_read_strings(sock, &vars, r->pool);

    if (rv != APR_SUCCESS)
        return rv;

    while (*vars) {
        char *key = *vars++;

        apr_table_setn(r->subprocess_env, key, *vars++);
    }

    return APR_SUCCESS;
}

static ap_filter_rec_t *wsgi_header_filter_handle;

static apr_status_t wsgi_header_filter(ap_filter_t *f, apr_bucket_brigade *b)
{
    request_rec *r = f->r;

    struct iovec vec1[4];
    apr_bucket_brigade *b2;
    char crlf[] = CRLF;
    apr_size_t buflen;

    const apr_array_header_t *elts;
    const apr_table_entry_t *t_elt;
    const apr_table_entry_t *t_end;
    struct iovec *vec2;
    struct iovec *vec2_next;

    /* Output status line. */

    vec1[0].iov_base = (void *)"Status:";
    vec1[0].iov_len  = strlen("Status:");
    vec1[1].iov_base = (void *)" ";
    vec1[1].iov_len  = sizeof(" ") - 1;
    vec1[2].iov_base = (void *)(r->status_line);
    vec1[2].iov_len  = strlen(r->status_line);
    vec1[3].iov_base = (void *)CRLF;
    vec1[3].iov_len  = sizeof(CRLF) - 1;

    b2 = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    apr_brigade_writev(b2, NULL, NULL, vec1, 4);

    /* Merge response header tables together. */

    if (!apr_is_empty_table(r->err_headers_out)) {
        r->headers_out = apr_table_overlay(r->pool, r->err_headers_out,
                                           r->headers_out);
    }

    /* Override the content type for response. */

    if (r->content_type)
        apr_table_setn(r->headers_out, "Content-Type", r->content_type);

    /* Formt the response headers for output. */

    elts = apr_table_elts(r->headers_out);
    if (elts->nelts != 0) {
        t_elt = (const apr_table_entry_t *)(elts->elts);
        t_end = t_elt + elts->nelts;
        vec2 = (struct iovec *)apr_palloc(r->pool, 4 * elts->nelts *
                                          sizeof(struct iovec));
        vec2_next = vec2;

        do {
            vec2_next->iov_base = (void*)(t_elt->key);
            vec2_next->iov_len = strlen(t_elt->key);
            vec2_next++;
            vec2_next->iov_base = ": ";
            vec2_next->iov_len = sizeof(": ") - 1;
            vec2_next++;
            vec2_next->iov_base = (void*)(t_elt->val);
            vec2_next->iov_len = strlen(t_elt->val);
            vec2_next++;
            vec2_next->iov_base = CRLF;
            vec2_next->iov_len = sizeof(CRLF) - 1;
            vec2_next++;
            t_elt++;
        } while (t_elt < t_end);

        apr_brigade_writev(b2, NULL, NULL, vec2, vec2_next - vec2);
    }

    /* Format terminating blank line for response headers. */

    buflen = strlen(crlf);
    apr_brigade_write(b2, NULL, NULL, crlf, buflen);

    /* Output the response headers. */

    ap_pass_brigade(f->next, b2);

    /* Remove ourselves from filter chain so we aren't called again. */

    ap_remove_output_filter(f);

    /* Output the partial response content. */

    return ap_pass_brigade(f->next, b);
}

static int wsgi_hook_daemon_handler(conn_rec *c)
{
    apr_socket_t *csd;
    request_rec *r;
    apr_pool_t *p;
    apr_status_t rv;

    char *key;
    apr_sockaddr_t *addr;

    const char *filename;
    const char *script;
    const char *magic;
    const char *hash;

    WSGIRequestConfig *config;

    apr_bucket *e;
    apr_bucket_brigade *bb;

    core_request_config *req_cfg;

    ap_filter_t *current = NULL;
    ap_filter_t *next = NULL;

    const apr_array_header_t *head = NULL;
    const apr_table_entry_t *elts = NULL;

    int i = 0;

    const char *item;

    /* Don't do anything if not in daemon process. */

    if (!wsgi_daemon_pool)
        return DECLINED;

    /*
     * Remove all input/output filters except the core filters.
     * This will ensure that any SSL filters we don't want are
     * removed. This is a bit of a hack. Only other option is to
     * duplicate the code for core input/output filters so can
     * avoid full Apache connection processing, which is what is
     * installed the SSL filters and possibly other filters for
     * logging etc.
     */

    current = c->input_filters;
    next = current->next;

    while (current) {
        if (current->frec == ap_core_input_filter_handle) {
            current = next;
            if (!current)
                break;
            next = current->next;
            continue;
        }

        ap_remove_input_filter(current);

        current = next;
        if (current)
            next = current->next;
    }

    current = c->output_filters;
    next = current->next;

    while (current) {
        if (current->frec == ap_core_output_filter_handle) {
            current = next;
            if (!current)
                break;
            next = current->next;
            continue;
        }

        ap_remove_output_filter(current);

        current = next;
        if (current)
            next = current->next;
    }

    /* Create and populate our own request object. */

    apr_pool_create(&p, c->pool);
    r = apr_pcalloc(p, sizeof(request_rec));

    r->pool = p;
    r->connection = c;
    r->server = c->base_server;

    r->user = NULL;
    r->ap_auth_type = NULL;

    r->allowed_methods = ap_make_method_list(p, 2);

    r->headers_in = apr_table_make(r->pool, 25);
    r->subprocess_env = apr_table_make(r->pool, 25);
    r->headers_out = apr_table_make(r->pool, 12);
    r->err_headers_out = apr_table_make(r->pool, 5);
    r->notes = apr_table_make(r->pool, 5);

    r->request_config  = ap_create_request_config(r->pool);

    r->proto_output_filters = c->output_filters;
    r->output_filters = r->proto_output_filters;
    r->proto_input_filters = c->input_filters;
    r->input_filters = r->proto_input_filters;

    r->per_dir_config  = r->server->lookup_defaults;

    r->sent_bodyct = 0;

    r->read_length = 0;
    r->read_body = REQUEST_NO_BODY;

    r->status = HTTP_OK;
    r->the_request = NULL;

    r->used_path_info = AP_REQ_DEFAULT_PATH_INFO;

    /*
     * Install our own output filter for writing back headers in
     * CGI script style.
     */

    ap_add_output_filter_handle(wsgi_header_filter_handle,
                                NULL, r, r->connection);

    /* Create and install the WSGI request config. */

    config = (WSGIRequestConfig *)apr_pcalloc(r->pool,
                                              sizeof(WSGIRequestConfig));
    ap_set_module_config(r->request_config, &wsgi_module, (void *)config);

    /* Grab the socket from the connection core config. */

    csd = ap_get_module_config(c->conn_config, &core_module);

    /*
     * Fake up parts of the internal per request core
     * configuration. If we don't do this then when Apache is
     * compiled with the symbol AP_DEBUG, internal checks made
     * by Apache will result in process crashing.
     */

    req_cfg = apr_pcalloc(r->pool, sizeof(core_request_config));

    req_cfg->bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    ap_set_module_config(r->request_config, &core_module, req_cfg);

    /* Read in the request details and setup request object. */

    if ((rv = wsgi_read_request(csd, r)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(rv), wsgi_server,
                     "mod_wsgi (pid=%d): Unable to read WSGI request.",
                     getpid());

        apr_pool_destroy(p);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check magic marker used to validate origin of request. */

    filename = apr_table_get(r->subprocess_env, "SCRIPT_FILENAME");
    script = apr_table_get(r->subprocess_env, "mod_wsgi.handler_script");

    magic = apr_table_get(r->subprocess_env, "mod_wsgi.magic");

    if (!magic) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(rv), wsgi_server,
                     "mod_wsgi (pid=%d): Request origin could not be "
                     "validated.", getpid());

        apr_pool_destroy(p);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    key = apr_psprintf(r->pool, "%ld|%s|%s|%s",
                       wsgi_daemon_process->group->random,
                       wsgi_daemon_process->group->socket, filename, script);
    hash = ap_md5(r->pool, (const unsigned char *)key);
    memset(key, '\0', strlen(key));

    if (strcmp(magic, hash) != 0) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ALERT(rv), wsgi_server,
                     "mod_wsgi (pid=%d): Request origin could not be "
                     "validated.", getpid());

        apr_pool_destroy(p);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_table_unset(r->subprocess_env, "mod_wsgi.magic");

    /*
     * If we are executing in a chroot environment, we need to
     * adjust SCRIPT_FILENAME to remove leading portion of path
     * that corresponds to the location of the chroot directory.
     * Also need to adjust DOCUMENT_ROOT as well, although in
     * that case if it doesn't actually fall within the choot
     * directory, we just delete it outright as would be incorrect
     * if that directory lay outside of the chroot directory.
     */

    if (wsgi_daemon_process->group->root) {
        const char *root;
        const char *path;

        root = wsgi_daemon_process->group->root;

        path = filename;

        if (strstr(path, root) == path && path[strlen(root)] == '/') {
            path += strlen(root);

            apr_table_set(r->subprocess_env, "SCRIPT_FILENAME", path);

            filename = path;
        }
        else {
            ap_log_error(APLOG_MARK, WSGI_LOG_CRIT(rv), wsgi_server,
                         "mod_wsgi (pid=%d): WSGI script '%s' not located "
                         "within chroot directory '%s'.", getpid(), path, root);

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        path = (char *)apr_table_get(r->subprocess_env, "DOCUMENT_ROOT");

        if (strstr(path, root) == path) {
            path += strlen(root);

            apr_table_set(r->subprocess_env, "DOCUMENT_ROOT", path);
        }
        else {
            apr_table_unset(r->subprocess_env, "DOCUMENT_ROOT");
        }
    }

    r->filename = (char *)filename;

    /* Recalculate WSGI script file modification time. */

    if ((rv = apr_stat(&r->finfo, filename, APR_FINFO_NORM,
                       r->pool)) != APR_SUCCESS) {
        /*
         * Don't fail at this point. Allow the lack of file to
         * be detected later when trying to load the script file.
         */

        ap_log_error(APLOG_MARK, WSGI_LOG_WARNING(rv), wsgi_server,
                     "mod_wsgi (pid=%d): Unable to stat target WSGI script "
                     "'%s'.", getpid(), filename);

        r->finfo.mtime = 0;
    }

    /*
     * Trigger mapping of host information to server configuration
     * so that when logging errors they go to the correct error log
     * file for the host.
     */

    r->connection->remote_ip = (char *)apr_table_get(r->subprocess_env,
                                                     "REMOTE_ADDR");

    key = apr_psprintf(p, "%s|%s",
                       apr_table_get(r->subprocess_env,
                                     "mod_wsgi.listener_host"),
                       apr_table_get(r->subprocess_env,
                                     "mod_wsgi.listener_port"));

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                     "mod_wsgi (pid=%d): Server listener address '%s'.",
                     getpid(), key);
    }

    addr = (apr_sockaddr_t *)apr_hash_get(wsgi_daemon_listeners,
                                          key, APR_HASH_KEY_STRING);

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                     "mod_wsgi (pid=%d): Server listener address '%s' was"
                     "%s found.", getpid(), key, addr ? "" : " not");
    }

    if (addr) {
        c->local_addr = addr;
    }

    ap_update_vhost_given_ip(r->connection);

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                     "mod_wsgi (pid=%d): Connection server matched was "
                     "'%s|%d'.", getpid(), c->base_server->server_hostname,
                     c->base_server->port);
    }

    r->server = c->base_server;

    if (apr_table_get(r->subprocess_env, "HTTP_HOST")) {
        apr_table_setn(r->headers_in, "Host",
                       apr_table_get(r->subprocess_env, "HTTP_HOST"));
    }

    ap_update_vhost_from_headers(r);

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, WSGI_LOG_DEBUG(0), wsgi_server,
                     "mod_wsgi (pid=%d): Request server matched was '%s|%d'.",
                     getpid(), r->server->server_hostname, r->server->port);
    }

    /*
     * Set content length of any request content and add the
     * standard HTTP input filter so that standard input routines
     * for request content will work.
     */

    item = apr_table_get(r->subprocess_env, "CONTENT_LENGTH");

    if (item)
        apr_table_setn(r->headers_in, "Content-Length", item);

    /* Install the standard HTTP input filter. */

    ap_add_input_filter("HTTP_IN", NULL, r, r->connection);

    /* Set details of WSGI specific request config. */

    config->process_group = apr_table_get(r->subprocess_env,
                                          "mod_wsgi.process_group");
    config->application_group = apr_table_get(r->subprocess_env,
                                              "mod_wsgi.application_group");
    config->callable_object = apr_table_get(r->subprocess_env,
                                            "mod_wsgi.callable_object");

    config->handler_script = apr_table_get(r->subprocess_env,
                                           "mod_wsgi.handler_script");

    config->script_reloading = atoi(apr_table_get(r->subprocess_env,
                                                  "mod_wsgi.script_reloading"));

    /*
     * Define how input data is to be processed. This
     * was already done in the Apache child process and
     * so it shouldn't fail. More importantly, it sets
     * up request data tracking how much input has been
     * read or if more remains.
     */

    ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);

    /*
     * Where original request used chunked transfer
     * encoding, we have to do a further fiddle here and
     * make Apache think that request content length is
     * maximum length possible. This is to satisfy the
     * HTTP_IN input filter. Also flag request as being
     * chunked so WSGI input function doesn't think that
     * there may actually be that amount of data
     * remaining.
     */

    item = apr_table_get(r->subprocess_env, "mod_wsgi.input_chunked");

    if (item && !strcasecmp(item, "1")) {
        if (sizeof(apr_off_t) == sizeof(long)) {
            apr_table_setn(r->headers_in, "Content-Length",
                           apr_psprintf(r->pool, "%ld", LONG_MAX));
        }
        else {
            apr_table_setn(r->headers_in, "Content-Length",
                           apr_psprintf(r->pool, "%d", INT_MAX));
        }

        r->read_chunked = 1;
    }

    /*
     * Execute the actual target WSGI application. In
     * normal cases OK should always be returned. If
     * however an error occurs in importing or executing
     * the script or the Python code raises an exception
     * which is not caught and handled, then an internal
     * server error can be returned. As we don't want to
     * be triggering any error document handlers in the
     * daemon process we use a fake status line with 0
     * as the status value. This will be picked up in
     * the Apache child process which will translate it
     * back to a 500 error so that normal error document
     * processing occurs.
     */

    r->status = HTTP_OK;

    if (wsgi_execute_script(r) != OK) {
        r->status = HTTP_INTERNAL_SERVER_ERROR;
        r->status_line = "0 Error";
    }

    /*
     * Ensure that request is finalised and any response
     * is flushed out. This will as a side effect read
     * any input data which wasn't consumed, thus
     * ensuring that the Apache child process isn't hung
     * waiting to send the request content and can
     * therefore process the response correctly.
     */

    ap_finalize_request_protocol(r);

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    e = apr_bucket_flush_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_HEAD(bb, e);
    ap_pass_brigade(r->connection->output_filters, bb);

    apr_pool_destroy(p);

    return OK;
}

#endif

/*
 * Apache 2.X module initialisation functions.
 */

static int wsgi_hook_init(apr_pool_t *pconf, apr_pool_t *ptemp,
                          apr_pool_t *plog, server_rec *s)
{
    void *data = NULL;
    const char *userdata_key = "wsgi_init";
    char package[128];

    int status = OK;

    /*
     * Init function gets called twice during startup, we only
     * need to actually do anything on the second time it is
     * called. This avoids unecessarily initialising and then
     * destroying Python for no reason.
     */

    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *)1, userdata_key,
                              apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    /* Setup module version information. */

    sprintf(package, "mod_wsgi/%s", MOD_WSGI_VERSION_STRING);

    ap_add_version_component(pconf, package);

    /* Record Python version string with Apache. */

    if (!Py_IsInitialized()) {
        char buffer[256];
        const char *token = NULL;
        const char *version = NULL;
        
        version = Py_GetVersion();

        token = version;
        while (*token && *token != ' ')
            token++;

        strcpy(buffer, "Python/");
        strncat(buffer, version, token - version);

        ap_add_version_component(pconf, buffer);
    }

    /* Retain reference to base server. */

    wsgi_server = s;

    /* Retain record of parent process ID. */

    wsgi_parent_pid = getpid();

    /* Determine whether multiprocess and/or multithread. */

    ap_mpm_query(AP_MPMQ_IS_THREADED, &wsgi_multithread);
    wsgi_multithread = (wsgi_multithread != AP_MPMQ_NOT_SUPPORTED);

    ap_mpm_query(AP_MPMQ_IS_FORKED, &wsgi_multiprocess);
    if (wsgi_multiprocess != AP_MPMQ_NOT_SUPPORTED) {
        ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &wsgi_multiprocess);
        wsgi_multiprocess = (wsgi_multiprocess != 1);
    }

    /* Retain reference to main server config. */

    wsgi_server_config = ap_get_module_config(s->module_config, &wsgi_module);

    /*
     * Check that the version of Python found at
     * runtime is what was used at compilation.
     */

    wsgi_python_version();

    /*
     * Initialise Python if required to be done in
     * the parent process. Note that it will not be
     * initialised if mod_python loaded and it has
     * already been done.
     */

    if (wsgi_python_required == -1)
        wsgi_python_required = 1;

    if (!wsgi_python_after_fork)
        wsgi_python_init(pconf);

    /* Startup separate named daemon processes. */

#if defined(MOD_WSGI_WITH_DAEMONS)
    status = wsgi_start_daemons(pconf);
#endif

    return status;
}

static void wsgi_hook_child_init(apr_pool_t *p, server_rec *s)
{
#if defined(MOD_WSGI_WITH_DAEMONS) 
    WSGIProcessGroup *entries = NULL;
    WSGIProcessGroup *entry = NULL;

    int i;

    /* Close listener sockets for daemon processes. */

    if (wsgi_daemon_list) {
        entries = (WSGIProcessGroup *)wsgi_daemon_list->elts;

        for (i = 0; i < wsgi_daemon_list->nelts; ++i) {
            entry = &entries[i];

            close(entry->listener_fd);
            entry->listener_fd = -1;
        }
    }
#endif

    if (wsgi_python_required) {
        /*
         * Initialise Python if required to be done in
         * the child process. Note that it will not be
         * initialised if mod_python loaded and it has
         * already been done.
         */

        if (wsgi_python_after_fork)
            wsgi_python_init(p);

        /*
         * Now perform additional initialisation steps
         * always done in child process.
         */

        wsgi_python_child_init(p);
    }
}

#if defined(MOD_WSGI_WITH_AAA_HANDLERS)

#include "apr_lib.h"

static char *wsgi_original_uri(request_rec *r)
{
    char *first, *last;

    if (r->the_request == NULL) {
        return (char *) apr_pcalloc(r->pool, 1);
    }

    first = r->the_request;     /* use the request-line */

    while (*first && !apr_isspace(*first)) {
        ++first;                /* skip over the method */
    }
    while (apr_isspace(*first)) {
        ++first;                /*   and the space(s)   */
    }

    last = first;
    while (*last && !apr_isspace(*last)) {
        ++last;                 /* end at next whitespace */
    }

    return apr_pstrmemdup(r->pool, first, last - first);
}

static char *wsgi_http2env(apr_pool_t *a, const char *w)
{
    char *res = (char *)apr_palloc(a, sizeof("HTTP_") + strlen(w));
    char *cp = res;
    char c;

    *cp++ = 'H';
    *cp++ = 'T';
    *cp++ = 'T';
    *cp++ = 'P';
    *cp++ = '_';

    while ((c = *w++) != 0) {
        if (!apr_isalnum(c)) {
            *cp++ = '_';
        }
        else {
            *cp++ = apr_toupper(c);
        }
    }
    *cp = 0;

    return res;
}

typedef struct {
        PyObject_HEAD
        request_rec *r;
        WSGIRequestConfig *config;
        PyObject *log;
} AuthObject;

static AuthObject *newAuthObject(request_rec *r, WSGIRequestConfig *config)
{
    AuthObject *self;

    self = PyObject_New(AuthObject, &Auth_Type);
    if (self == NULL)
        return NULL;

    self->config = config;

    self->r = r;

    self->log = newLogObject(r, APLOG_ERR, NULL);

    return self;
}

static void Auth_dealloc(AuthObject *self)
{
    Py_DECREF(self->log);

    PyObject_Del(self);
}

static PyObject *Auth_environ(AuthObject *self, const char *group)
{
    PyObject *vars;
    PyObject *object;

    request_rec *r = self->r;
    server_rec *s = r->server;
    conn_rec *c = r->connection;
    apr_port_t rport;

    const apr_array_header_t *hdrs_arr;
    const apr_table_entry_t *hdrs;

    const char *value = NULL;

    int i;

    vars = PyDict_New();

    hdrs_arr = apr_table_elts(r->headers_in);
    hdrs = (const apr_table_entry_t *) hdrs_arr->elts;

    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (!hdrs[i].key) {
            continue;
        }

        if (!strcasecmp(hdrs[i].key, "Content-type")) {
#if PY_MAJOR_VERSION >= 3
            object = PyUnicode_DecodeLatin1(hdrs[i].val,
                                            strlen(hdrs[i].val), NULL);
#else
            object = PyString_FromString(hdrs[i].val);
#endif
            PyDict_SetItemString(vars, "CONTENT_TYPE", object);
            Py_DECREF(object);
        }
        else if (!strcasecmp(hdrs[i].key, "Content-length")) {
#if PY_MAJOR_VERSION >= 3
            object = PyUnicode_DecodeLatin1(hdrs[i].val,
                                            strlen(hdrs[i].val), NULL);
#else
            object = PyString_FromString(hdrs[i].val);
#endif
            PyDict_SetItemString(vars, "CONTENT_LENGTH", object);
            Py_DECREF(object);
        }
        else if (!strcasecmp(hdrs[i].key, "Authorization")
                 || !strcasecmp(hdrs[i].key, "Proxy-Authorization")) {
            continue;
        }
        else {
#if PY_MAJOR_VERSION >= 3
            object = PyUnicode_DecodeLatin1(hdrs[i].val,
                                            strlen(hdrs[i].val), NULL);
#else
            object = PyString_FromString(hdrs[i].val);
#endif
            PyDict_SetItemString(vars, wsgi_http2env(r->pool, hdrs[i].key),
                                 object);
            Py_DECREF(object);
        }
    }

    value = ap_psignature("", r);
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    object = PyString_FromString(value);
#endif
    PyDict_SetItemString(vars, "SERVER_SIGNATURE", object);
    Py_DECREF(object);

#if AP_MODULE_MAGIC_AT_LEAST(20060905,0)
    value = ap_get_server_banner();
#else
    value = ap_get_server_version();
#endif
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    object = PyString_FromString(value);
#endif
    PyDict_SetItemString(vars, "SERVER_SOFTWARE", object);
    Py_DECREF(object);

    value = ap_escape_html(r->pool, ap_get_server_name(r));
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    object = PyString_FromString(value);
#endif
    PyDict_SetItemString(vars, "SERVER_NAME", object);
    Py_DECREF(object);

    if (r->connection->local_ip) {
        value = r->connection->local_ip;
#if PY_MAJOR_VERSION >= 3
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
        object = PyString_FromString(value);
#endif
        PyDict_SetItemString(vars, "SERVER_ADDR", object);
        Py_DECREF(object);
    }

    value = apr_psprintf(r->pool, "%u", ap_get_server_port(r));
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    object = PyString_FromString(value);
#endif
    PyDict_SetItemString(vars, "SERVER_PORT", object);
    Py_DECREF(object);

    value = ap_get_remote_host(c, r->per_dir_config, REMOTE_HOST, NULL);
    if (value) {
#if PY_MAJOR_VERSION >= 3
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
        object = PyString_FromString(value);
#endif
        PyDict_SetItemString(vars, "REMOTE_HOST", object);
        Py_DECREF(object);
    }

    if (c->remote_ip) {
        value = c->remote_ip;
#if PY_MAJOR_VERSION >= 3
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
        object = PyString_FromString(value);
#endif
        PyDict_SetItemString(vars, "REMOTE_ADDR", object);
        Py_DECREF(object);
    }

#if PY_MAJOR_VERSION >= 3
    value = ap_document_root(r);
    object = PyUnicode_Decode(value, strlen(value),
                             Py_FileSystemDefaultEncoding,
                             "surrogateescape");
#else
    object = PyString_FromString(ap_document_root(r));
#endif
    PyDict_SetItemString(vars, "DOCUMENT_ROOT", object);
    Py_DECREF(object);

    if (s->server_admin) {
        value = s->server_admin;
#if PY_MAJOR_VERSION >= 3
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
        object = PyString_FromString(value);
#endif
        PyDict_SetItemString(vars, "SERVER_ADMIN", object);
        Py_DECREF(object);
    }

    rport = c->remote_addr->port;
    value = apr_itoa(r->pool, rport);
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    object = PyString_FromString(value);
#endif
    PyDict_SetItemString(vars, "REMOTE_PORT", object);
    Py_DECREF(object);

    value = r->protocol;
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    object = PyString_FromString(value);
#endif
    PyDict_SetItemString(vars, "SERVER_PROTOCOL", object);
    Py_DECREF(object);

    value = r->method;
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    object = PyString_FromString(value);
#endif
    PyDict_SetItemString(vars, "REQUEST_METHOD", object);
    Py_DECREF(object);

    value = r->args ? r->args : "";
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    object = PyString_FromString(value);
#endif
    PyDict_SetItemString(vars, "QUERY_STRING", object);
    Py_DECREF(object);

    value = wsgi_original_uri(r);
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    object = PyString_FromString(value);
#endif
    PyDict_SetItemString(vars, "REQUEST_URI", object);
    Py_DECREF(object);

#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_FromString("");
#else
    object = PyString_FromString("");
#endif
    PyDict_SetItemString(vars, "mod_wsgi.process_group", object);
    Py_DECREF(object);

#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(group, strlen(group), NULL);
#else
    object = PyString_FromString(group);
#endif
    PyDict_SetItemString(vars, "mod_wsgi.application_group", object);
    Py_DECREF(object);

    object = PyLong_FromLong(self->config->script_reloading);
    PyDict_SetItemString(vars, "mod_wsgi.script_reloading", object);
    Py_DECREF(object);

    /*
     * Setup log object for WSGI errors. Don't decrement
     * reference to log object as keep reference to it.
     */

    object = (PyObject *)self->log;
    PyDict_SetItemString(vars, "wsgi.errors", object);

    /*
     * If Apache extensions are enabled add a CObject reference
     * to the Apache request_rec structure instance.
     */

    if (!wsgi_daemon_pool && self->config->pass_apache_request) {
        object = PyCObject_FromVoidPtr(self->r, 0);
        PyDict_SetItemString(vars, "apache.request_rec", object);
        Py_DECREF(object);
    }

    return vars;
}

static PyTypeObject Auth_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "mod_wsgi.Auth",        /*tp_name*/
    sizeof(AuthObject),     /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Auth_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    0,                      /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

#if defined(MOD_WSGI_WITH_AUTHN_PROVIDER)
static authn_status wsgi_check_password(request_rec *r, const char *user,
                                        const char *password)
{
    WSGIRequestConfig *config;

    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    char *name = NULL;
    int exists = 0;

    const char *script;
    const char *group;

    authn_status status;

    config = wsgi_create_req_config(r->pool, r);

    if (!config->auth_user_script) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                     "mod_wsgi (pid=%d): Location of WSGI user "
                     "authentication script not provided.", getpid());

        return AUTH_GENERAL_ERROR;
    }

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    script = config->auth_user_script->handler_script;
    group = wsgi_server_group(r, config->auth_user_script->application_group);

    interp = wsgi_acquire_interpreter(group);

    if (!interp) {
        ap_log_rerror(APLOG_MARK, WSGI_LOG_CRIT(0), r,
                      "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                      getpid(), group);

        return AUTH_GENERAL_ERROR;
    }

    /* Calculate the Python module name to be used for script. */

    name = wsgi_module_name(r->pool, script);

    /*
     * Use a lock around the check to see if the module is
     * already loaded and the import of the module to prevent
     * two request handlers trying to import the module at the
     * same time.
     */

#if APR_HAS_THREADS
    Py_BEGIN_ALLOW_THREADS
    apr_thread_mutex_lock(wsgi_module_lock);
    Py_END_ALLOW_THREADS
#endif

    modules = PyImport_GetModuleDict();
    module = PyDict_GetItemString(modules, name);

    Py_XINCREF(module);

    if (module)
        exists = 1;

    /*
     * If script reloading is enabled and the module for it has
     * previously been loaded, see if it has been modified since
     * the last time it was accessed.
     */

    if (module && config->script_reloading) {
        if (wsgi_reload_required(r->pool, r, script, module, NULL)) {
            /*
             * Script file has changed. Only support module
             * reloading for authentication scripts. Remove the
             * module from the modules dictionary before
             * reloading it again. If code is executing within
             * the module at the time, the callers reference
             * count on the module should ensure it isn't
             * actually destroyed until it is finished.
             */

            Py_DECREF(module);
            module = NULL;

            PyDict_DelItemString(modules, name);
        }
    }

    if (!module) {
        module = wsgi_load_source(r->pool, r, name, exists, script, "", group);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Assume an internal server error unless everything okay. */

    status = AUTH_GENERAL_ERROR;

    /* Determine if script exists and execute it. */

    if (module) {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;

        module_dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(module_dict, "check_password");

        if (object) {
            PyObject *vars = NULL;
            PyObject *args = NULL;
            PyObject *result = NULL;
            PyObject *method = NULL;

            AuthObject *adapter = NULL;

            adapter = newAuthObject(r, config);

            if (adapter) {
                vars = Auth_environ(adapter, group);

                Py_INCREF(object);
                args = Py_BuildValue("(Oss)", vars, user, password);
                result = PyEval_CallObject(object, args);
                Py_DECREF(args);
                Py_DECREF(object);
                Py_DECREF(vars);

                if (result) {
                    if (result == Py_None) {
                        status = AUTH_USER_NOT_FOUND;
                    }
                    else if (result == Py_True) {
                        status = AUTH_GRANTED;
                    }
                    else if (result == Py_False) {
                        status = AUTH_DENIED;
                    }
                    else {
                        PyErr_SetString(PyExc_TypeError, "Basic auth "
                                        "provider must return True, False "
                                        "or None");
                    }

                    Py_DECREF(result);
                }

                /*
                 * Wipe out references to Apache request object
                 * held by Python objects, so can detect when an
                 * application holds on to the transient Python
                 * objects beyond the life of the request and
                 * thus raise an exception if they are used.
                 */

                adapter->r = NULL;

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method) {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else {
                    args = PyTuple_New(0);
                    object = PyEval_CallObject(method, args);
                    Py_DECREF(args);
                }

                Py_XDECREF(object);
                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
            else
                Py_DECREF(object);
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                          "mod_wsgi (pid=%d): Target WSGI user "
                          "authentication script '%s' does not provide "
                          "'Basic' auth provider.", getpid(), script);
            Py_END_ALLOW_THREADS
        }

        /* Log any details of exceptions if execution failed. */

        if (PyErr_Occurred())
            wsgi_log_python_error(r, NULL, script);
    }

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    return status;
}

static authn_status wsgi_get_realm_hash(request_rec *r, const char *user,
                                        const char *realm, char **rethash)
{
    WSGIRequestConfig *config;

    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    char *name = NULL;
    int exists = 0;

    const char *script;
    const char *group;

    authn_status status;

    config = wsgi_create_req_config(r->pool, r);

    if (!config->auth_user_script) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                     "mod_wsgi (pid=%d): Location of WSGI user "
                     "authentication script not provided.", getpid());

        return AUTH_GENERAL_ERROR;
    }

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    script = config->auth_user_script->handler_script;
    group = wsgi_server_group(r, config->auth_user_script->application_group);

    interp = wsgi_acquire_interpreter(group);

    if (!interp) {
        ap_log_rerror(APLOG_MARK, WSGI_LOG_CRIT(0), r,
                      "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                      getpid(), group);

        return AUTH_GENERAL_ERROR;
    }

    /* Calculate the Python module name to be used for script. */

    name = wsgi_module_name(r->pool, script);

    /*
     * Use a lock around the check to see if the module is
     * already loaded and the import of the module to prevent
     * two request handlers trying to import the module at the
     * same time.
     */

#if APR_HAS_THREADS
    Py_BEGIN_ALLOW_THREADS
    apr_thread_mutex_lock(wsgi_module_lock);
    Py_END_ALLOW_THREADS
#endif

    modules = PyImport_GetModuleDict();
    module = PyDict_GetItemString(modules, name);

    Py_XINCREF(module);

    if (module)
        exists = 1;

    /*
     * If script reloading is enabled and the module for it has
     * previously been loaded, see if it has been modified since
     * the last time it was accessed.
     */

    if (module && config->script_reloading) {
        if (wsgi_reload_required(r->pool, r, script, module, NULL)) {
            /*
             * Script file has changed. Only support module
             * reloading for authentication scripts. Remove the
             * module from the modules dictionary before
             * reloading it again. If code is executing within
             * the module at the time, the callers reference
             * count on the module should ensure it isn't
             * actually destroyed until it is finished.
             */

            Py_DECREF(module);
            module = NULL;

            PyDict_DelItemString(modules, name);
        }
    }

    if (!module) {
        module = wsgi_load_source(r->pool, r, name, exists, script, "", group);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Assume an internal server error unless everything okay. */

    status = AUTH_GENERAL_ERROR;

    /* Determine if script exists and execute it. */

    if (module) {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;

        module_dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(module_dict, "get_realm_hash");

        if (object) {
            PyObject *vars = NULL;
            PyObject *args = NULL;
            PyObject *result = NULL;
            PyObject *method = NULL;

            AuthObject *adapter = NULL;

            adapter = newAuthObject(r, config);

            if (adapter) {
                vars = Auth_environ(adapter, group);

                Py_INCREF(object);
                args = Py_BuildValue("(Oss)", vars, user, realm);
                result = PyEval_CallObject(object, args);
                Py_DECREF(args);
                Py_DECREF(object);
                Py_DECREF(vars);

                if (result) {
                    if (result == Py_None) {
                        status = AUTH_USER_NOT_FOUND;
                    }
                    else if (PyString_Check(result)) {
                        *rethash = PyString_AsString(result);
                        *rethash = apr_pstrdup(r->pool, *rethash);

                        status = AUTH_USER_FOUND;
                    }
#if PY_MAJOR_VERSION >= 3
                    else if (PyUnicode_Check(result)) {
                        PyObject *latin_item;
                        latin_item = PyUnicode_AsLatin1String(result);
                        if (!latin_item) {
                            PyErr_SetString(PyExc_TypeError, "Digest auth "
                                            "provider must return None "
                                            "or string object, value "
                                            "containing non 'latin-1' "
                                            "characters found");
                        }
                        else {
                            Py_DECREF(result);
                            result = latin_item;

                            *rethash = PyString_AsString(result);
                            *rethash = apr_pstrdup(r->pool, *rethash);

                            status = AUTH_USER_FOUND;
                        }
                    }
#endif
                    else {
                        PyErr_SetString(PyExc_TypeError, "Digest auth "
                                        "provider must return None "
                                        "or string object");
                    }

                    Py_DECREF(result);
                }

                /*
                 * Wipe out references to Apache request object
                 * held by Python objects, so can detect when an
                 * application holds on to the transient Python
                 * objects beyond the life of the request and
                 * thus raise an exception if they are used.
                 */

                adapter->r = NULL;

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method) {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else {
                    args = PyTuple_New(0);
                    object = PyEval_CallObject(method, args);
                    Py_DECREF(args);
                }

                Py_XDECREF(object);
                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
            else
                Py_DECREF(object);
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                          "mod_wsgi (pid=%d): Target WSGI user "
                          "authentication script '%s' does not provide "
                          "'Digest' auth provider.", getpid(), script);
            Py_END_ALLOW_THREADS
        }

        /* Log any details of exceptions if execution failed. */

        if (PyErr_Occurred())
            wsgi_log_python_error(r, NULL, script);
    }

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    return status;
}

static const authn_provider wsgi_authn_provider =
{
    &wsgi_check_password,
    &wsgi_get_realm_hash
};
#endif

static int wsgi_groups_for_user(request_rec *r, WSGIRequestConfig *config,
                                apr_table_t **grpstatus)
{
    apr_table_t *grps = apr_table_make(r->pool, 15);

    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    char *name = NULL;
    int exists = 0;

    const char *script;
    const char *group;

    int status = HTTP_INTERNAL_SERVER_ERROR;

    if (!config->auth_group_script) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                     "mod_wsgi (pid=%d): Location of WSGI group "
                     "authentication script not provided.", getpid());

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    script = config->auth_group_script->handler_script;
    group = wsgi_server_group(r, config->auth_group_script->application_group);

    interp = wsgi_acquire_interpreter(group);

    if (!interp) {
        ap_log_rerror(APLOG_MARK, WSGI_LOG_CRIT(0), r,
                      "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                      getpid(), group);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Calculate the Python module name to be used for script. */

    name = wsgi_module_name(r->pool, script);

    /*
     * Use a lock around the check to see if the module is
     * already loaded and the import of the module to prevent
     * two request handlers trying to import the module at the
     * same time.
     */

#if APR_HAS_THREADS
    Py_BEGIN_ALLOW_THREADS
    apr_thread_mutex_lock(wsgi_module_lock);
    Py_END_ALLOW_THREADS
#endif

    modules = PyImport_GetModuleDict();
    module = PyDict_GetItemString(modules, name);

    Py_XINCREF(module);

    if (module)
        exists = 1;

    /*
     * If script reloading is enabled and the module for it has
     * previously been loaded, see if it has been modified since
     * the last time it was accessed.
     */

    if (module && config->script_reloading) {
        if (wsgi_reload_required(r->pool, r, script, module, NULL)) {
            /*
             * Script file has changed. Only support module
             * reloading for authentication scripts. Remove the
             * module from the modules dictionary before
             * reloading it again. If code is executing within
             * the module at the time, the callers reference
             * count on the module should ensure it isn't
             * actually destroyed until it is finished.
             */

            Py_DECREF(module);
            module = NULL;

            PyDict_DelItemString(modules, name);
        }
    }

    if (!module) {
        module = wsgi_load_source(r->pool, r, name, exists, script, "", group);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Assume an internal server error unless everything okay. */

    status = HTTP_INTERNAL_SERVER_ERROR;

    /* Determine if script exists and execute it. */

    if (module) {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;

        module_dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(module_dict, "groups_for_user");

        if (object) {
            PyObject *vars = NULL;
            PyObject *args = NULL;
            PyObject *sequence = NULL;
            PyObject *method = NULL;

            AuthObject *adapter = NULL;

            adapter = newAuthObject(r, config);

            if (adapter) {
                vars = Auth_environ(adapter, group);

                Py_INCREF(object);
                args = Py_BuildValue("(Os)", vars, r->user);
                sequence = PyEval_CallObject(object, args);
                Py_DECREF(args);
                Py_DECREF(object);
                Py_DECREF(vars);

                if (sequence) {
                    PyObject *iterator;

                    iterator = PyObject_GetIter(sequence);

                    if (iterator) {
                        PyObject *item;
                        const char *name;

                        status = OK;

                        while ((item = PyIter_Next(iterator))) {
#if PY_MAJOR_VERSION >= 3
                            if (PyUnicode_Check(item)) {
                                PyObject *latin_item;
                                latin_item = PyUnicode_AsLatin1String(item);
                                if (!latin_item) {
                                    Py_BEGIN_ALLOW_THREADS
                                    ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0),
                                                  r, "mod_wsgi (pid=%d): "
                                                  "Groups for user returned "
                                                  "from '%s' must be an "
                                                  "iterable sequence of "
                                                  "byte strings, value "
                                                  "containing non 'latin-1' "
                                                  "characters found",
                                                  getpid(), script);
                                    Py_END_ALLOW_THREADS

                                    Py_DECREF(item);

                                    status = HTTP_INTERNAL_SERVER_ERROR;

                                    break;
                                }
                                else {
                                    Py_DECREF(item);
                                    item = latin_item;
                                }
                            }
#endif

                            if (!PyString_Check(item)) {
                                Py_BEGIN_ALLOW_THREADS
                                ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                                              "mod_wsgi (pid=%d): Groups for "
                                              "user returned from '%s' must "
                                              "be an iterable sequence of "
                                              "byte strings.", getpid(),
                                              script);
                                Py_END_ALLOW_THREADS

                                Py_DECREF(item);

                                status = HTTP_INTERNAL_SERVER_ERROR;

                                break;
                            }

                            name = PyString_AsString(item);

                            apr_table_setn(grps, apr_pstrdup(r->pool, name),
                                           "1");

                            Py_DECREF(item);
                        }

                        Py_DECREF(iterator);
                    }
                    else {
                        Py_BEGIN_ALLOW_THREADS
                        ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                                      "mod_wsgi (pid=%d): Groups for user "
                                      "returned from '%s' must be an iterable "
                                      "sequence of byte strings.", getpid(),
                                      script);
                        Py_END_ALLOW_THREADS
                    }

                    Py_DECREF(sequence);
                }

                /*
                 * Wipe out references to Apache request object
                 * held by Python objects, so can detect when an
                 * application holds on to the transient Python
                 * objects beyond the life of the request and
                 * thus raise an exception if they are used.
                 */

                adapter->r = NULL;

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method) {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else {
                    args = PyTuple_New(0);
                    object = PyEval_CallObject(method, args);
                    Py_DECREF(args);
                }

                Py_XDECREF(object);
                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
            else
                Py_DECREF(object);
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                          "mod_wsgi (pid=%d): Target WSGI group "
                          "authentication script '%s' does not provide "
                          "group provider.", getpid(), script);
            Py_END_ALLOW_THREADS
        }

        /* Log any details of exceptions if execution failed. */

        if (PyErr_Occurred())
            wsgi_log_python_error(r, NULL, script);
    }

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    if (status == OK)
        *grpstatus = grps;

    return status;
}

static int wsgi_allow_access(request_rec *r, WSGIRequestConfig *config,
                             const char *host)
{
    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    char *name = NULL;
    int exists = 0;

    const char *script;
    const char *group;

    int result = 0;

    if (!config->access_script) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                     "mod_wsgi (pid=%d): Location of WSGI host "
                     "access script not provided.", getpid());

        return 0;
    }

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    script = config->access_script->handler_script;
    group = wsgi_server_group(r, config->access_script->application_group);

    interp = wsgi_acquire_interpreter(group);

    if (!interp) {
        ap_log_rerror(APLOG_MARK, WSGI_LOG_CRIT(0), r,
                      "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                      getpid(), group);

        return 0;
    }

    /* Calculate the Python module name to be used for script. */

    name = wsgi_module_name(r->pool, script);

    /*
     * Use a lock around the check to see if the module is
     * already loaded and the import of the module to prevent
     * two request handlers trying to import the module at the
     * same time.
     */

#if APR_HAS_THREADS
    Py_BEGIN_ALLOW_THREADS
    apr_thread_mutex_lock(wsgi_module_lock);
    Py_END_ALLOW_THREADS
#endif

    modules = PyImport_GetModuleDict();
    module = PyDict_GetItemString(modules, name);

    Py_XINCREF(module);

    if (module)
        exists = 1;

    /*
     * If script reloading is enabled and the module for it has
     * previously been loaded, see if it has been modified since
     * the last time it was accessed.
     */

    if (module && config->script_reloading) {
        if (wsgi_reload_required(r->pool, r, script, module, NULL)) {
            /*
             * Script file has changed. Only support module
             * reloading for authentication scripts. Remove the
             * module from the modules dictionary before
             * reloading it again. If code is executing within
             * the module at the time, the callers reference
             * count on the module should ensure it isn't
             * actually destroyed until it is finished.
             */

            Py_DECREF(module);
            module = NULL;

            PyDict_DelItemString(modules, name);
        }
    }

    if (!module) {
        module = wsgi_load_source(r->pool, r, name, exists, script, "", group);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Assume not allowed unless everything okay. */

    result = 0;

    /* Determine if script exists and execute it. */

    if (module) {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;

        module_dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(module_dict, "allow_access");

        if (object) {
            PyObject *vars = NULL;
            PyObject *args = NULL;
            PyObject *flag = NULL;
            PyObject *method = NULL;

            AuthObject *adapter = NULL;

            adapter = newAuthObject(r, config);

            if (adapter) {
                vars = Auth_environ(adapter, group);

                Py_INCREF(object);
                args = Py_BuildValue("(Oz)", vars, host);
                flag = PyEval_CallObject(object, args);
                Py_DECREF(args);
                Py_DECREF(object);
                Py_DECREF(vars);

                if (flag) {
                    if (flag == Py_None) {
                        result = -1;
                    }
                    else if (PyBool_Check(flag)) {
                        if (flag == Py_True)
                            result = 1;
                    }
                    else {
                        Py_BEGIN_ALLOW_THREADS
                        ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                                      "mod_wsgi (pid=%d): Indicator of "
                                      "host accessibility returned from '%s' "
                                      "must a boolean or None.", getpid(),
                                      script);
                        Py_END_ALLOW_THREADS
                    }

                    Py_DECREF(flag);
                }

                /*
                 * Wipe out references to Apache request object
                 * held by Python objects, so can detect when an
                 * application holds on to the transient Python
                 * objects beyond the life of the request and
                 * thus raise an exception if they are used.
                 */

                adapter->r = NULL;

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method) {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else {
                    args = PyTuple_New(0);
                    object = PyEval_CallObject(method, args);
                    Py_DECREF(args);
                }

                Py_XDECREF(object);
                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
            else
                Py_DECREF(object);
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                          "mod_wsgi (pid=%d): Target WSGI host "
                          "access script '%s' does not provide "
                          "host validator.", getpid(), script);
            Py_END_ALLOW_THREADS
        }

        /* Log any details of exceptions if execution failed. */

        if (PyErr_Occurred())
            wsgi_log_python_error(r, NULL, script);
    }

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    return result;
}

static int wsgi_hook_access_checker(request_rec *r)
{
    WSGIRequestConfig *config;

    int allow = 0;
    const char *host = NULL;

    config = wsgi_create_req_config(r->pool, r);

    if (!config->access_script)
        return DECLINED;

    host = ap_get_remote_host(r->connection, r->per_dir_config,
                              REMOTE_HOST, NULL);

    if (!host)
        host = r->connection->remote_ip;

    allow = wsgi_allow_access(r, config, host);

    if (allow < 0)
        return DECLINED;
    else if (allow)
        return OK;

    if (ap_satisfies(r) != SATISFY_ANY || !ap_some_auth_required(r)) {
        ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r, "mod_wsgi (pid=%d): "
                      "Client denied by server configuration: '%s'.",
                      getpid(), r->filename);
    }

    return HTTP_FORBIDDEN;
}

static int wsgi_hook_check_user_id(request_rec *r)
{
    WSGIRequestConfig *config;

    int status = -1;

    const char *password;

    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    char *name = NULL;
    int exists = 0;

    const char *script;
    const char *group;

    if ((status = ap_get_basic_auth_pw(r, &password)))
        return status;

    config = wsgi_create_req_config(r->pool, r);

    if (!config->auth_user_script)
        return DECLINED;

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    script = config->auth_user_script->handler_script;
    group = wsgi_server_group(r, config->auth_user_script->application_group);

    interp = wsgi_acquire_interpreter(group);

    if (!interp) {
        ap_log_rerror(APLOG_MARK, WSGI_LOG_CRIT(0), r,
                      "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                      getpid(), group);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Calculate the Python module name to be used for script. */

    name = wsgi_module_name(r->pool, script);

    /*
     * Use a lock around the check to see if the module is
     * already loaded and the import of the module to prevent
     * two request handlers trying to import the module at the
     * same time.
     */

#if APR_HAS_THREADS
    Py_BEGIN_ALLOW_THREADS
    apr_thread_mutex_lock(wsgi_module_lock);
    Py_END_ALLOW_THREADS
#endif

    modules = PyImport_GetModuleDict();
    module = PyDict_GetItemString(modules, name);

    Py_XINCREF(module);

    if (module)
        exists = 1;

    /*
     * If script reloading is enabled and the module for it has
     * previously been loaded, see if it has been modified since
     * the last time it was accessed.
     */

    if (module && config->script_reloading) {
        if (wsgi_reload_required(r->pool, r, script, module, NULL)) {
            /*
             * Script file has changed. Only support module
             * reloading for authentication scripts. Remove the
             * module from the modules dictionary before
             * reloading it again. If code is executing within
             * the module at the time, the callers reference
             * count on the module should ensure it isn't
             * actually destroyed until it is finished.
             */

            Py_DECREF(module);
            module = NULL;

            PyDict_DelItemString(modules, name);
        }
    }

    if (!module) {
        module = wsgi_load_source(r->pool, r, name, exists, script, "", group);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Assume an internal server error unless everything okay. */

    status = HTTP_INTERNAL_SERVER_ERROR;

    /* Determine if script exists and execute it. */

    if (module) {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;

        module_dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(module_dict, "check_password");

        if (object) {
            PyObject *vars = NULL;
            PyObject *args = NULL;
            PyObject *result = NULL;
            PyObject *method = NULL;

            AuthObject *adapter = NULL;

            adapter = newAuthObject(r, config);

            if (adapter) {
                vars = Auth_environ(adapter, group);

                Py_INCREF(object);
                args = Py_BuildValue("(Oss)", vars, r->user, password);
                result = PyEval_CallObject(object, args);
                Py_DECREF(args);
                Py_DECREF(object);
                Py_DECREF(vars);

                if (result) {
                    if (result == Py_None) {
                        if (config->user_authoritative) {
                            ap_note_basic_auth_failure(r);
                            status = HTTP_UNAUTHORIZED;

                            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                                          "mod_wsgi (pid=%d): User '%s' not "
                                          "found in executing authentication "
                                          "script '%s', for uri '%s'.",
                                          getpid(), r->user, script, r->uri);
                        }
                        else
                            status = DECLINED;
                    }
                    else if (result == Py_True) {
                        status = OK;
                    }
                    else if (result == Py_False) {
                        ap_note_basic_auth_failure(r);
                        status = HTTP_UNAUTHORIZED;

                        ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                                      "mod_wsgi (pid=%d): Password mismatch "
                                      "for user '%s' in executing "
                                      "authentication script '%s', for uri "
                                      "'%s'.", getpid(), r->user, script,
                                      r->uri);
                    }
                    else {
                        PyErr_SetString(PyExc_TypeError, "Basic auth "
                                        "provider must return True, False "
                                        "or None");
                    }

                    Py_DECREF(result);
                }

                /*
                 * Wipe out references to Apache request object
                 * held by Python objects, so can detect when an
                 * application holds on to the transient Python
                 * objects beyond the life of the request and
                 * thus raise an exception if they are used.
                 */

                adapter->r = NULL;

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method) {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else {
                    args = PyTuple_New(0);
                    object = PyEval_CallObject(method, args);
                    Py_DECREF(args);
                }

                Py_XDECREF(object);
                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
            else
                Py_DECREF(object);
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r,
                          "mod_wsgi (pid=%d): Target WSGI user "
                          "authentication script '%s' does not provide "
                          "'Basic' auth provider.", getpid(), script);
            Py_END_ALLOW_THREADS
        }

        /* Log any details of exceptions if execution failed. */

        if (PyErr_Occurred())
            wsgi_log_python_error(r, NULL, script);
    }

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    return status;
}

#if defined(MOD_WSGI_WITH_AUTHZ_PROVIDER)

static authz_status wsgi_check_authorization(request_rec *r,
                                             const char *require_args)
{
    WSGIRequestConfig *config;

    apr_table_t *grpstatus = NULL;
    const char *t, *w;
    int status;

    config = wsgi_create_req_config(r->pool, r);

    if (!config->auth_group_script) {
        ap_log_error(APLOG_MARK, WSGI_LOG_ERR(0), wsgi_server,
                     "mod_wsgi (pid=%d): Location of WSGI group "
                     "authorization script not provided.", getpid());

        return AUTHZ_DENIED;
    }

    status = wsgi_groups_for_user(r, config, &grpstatus);

    if (status != OK)
        return AUTHZ_DENIED;

    if (apr_table_elts(grpstatus)->nelts == 0) {
        ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r, "mod_wsgi (pid=%d): "
                      "Authorization of user '%s' to access '%s' failed. "
                      "User is not a member of any groups.", getpid(),
                      r->user, r->uri);
        return AUTHZ_DENIED;
    }

    t = require_args;
    while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
        if (apr_table_get(grpstatus, w)) {
            return AUTHZ_GRANTED;
        }
    }

    ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r, "mod_wsgi (pid=%d): "
                  "Authorization of user '%s' to access '%s' failed. "
                  "User is not a member of designated groups.", getpid(),
                  r->user, r->uri);

    return AUTHZ_DENIED;
}

static const authz_provider wsgi_authz_provider =
{
    &wsgi_check_authorization,
};

#else

static int wsgi_hook_auth_checker(request_rec *r)
{
    WSGIRequestConfig *config;

    int m = r->method_number;
    const apr_array_header_t *reqs_arr;
    require_line *reqs;
    int required_group = 0;
    register int x;
    const char *t, *w;
    apr_table_t *grpstatus = NULL;
    char *reason = NULL;

    config = wsgi_create_req_config(r->pool, r);

    if (!config->auth_group_script)
        return DECLINED;

    reqs_arr = ap_requires(r);

    if (!reqs_arr)
        return DECLINED;

    reqs = (require_line *)reqs_arr->elts;

    for (x = 0; x < reqs_arr->nelts; x++) {

        if (!(reqs[x].method_mask & (AP_METHOD_BIT << m))) {
            continue;
        }

        t = reqs[x].requirement;
        w = ap_getword_white(r->pool, &t);

        if (!strcasecmp(w, "group") || !strcasecmp(w, "wsgi-group")) {
            required_group = 1;

            if (!grpstatus) {
                int status;

                status = wsgi_groups_for_user(r, config, &grpstatus);

                if (status != OK)
                    return status;

                if (apr_table_elts(grpstatus)->nelts == 0) {
                    reason = "User is not a member of any groups";
                    break;
                }
            }

            while (t[0]) {
                w = ap_getword_conf(r->pool, &t);
                if (apr_table_get(grpstatus, w)) {
                    return OK;
                }
            }
        }
    }

    if (!required_group || !config->group_authoritative)
        return DECLINED;

    ap_log_rerror(APLOG_MARK, WSGI_LOG_ERR(0), r, "mod_wsgi (pid=%d): "
                  "Authorization of user '%s' to access '%s' failed. %s.",
                  getpid(), r->user, r->uri, reason ? reason : "User is not "
                  "a member of designated groups");

    ap_note_auth_failure(r);

    return HTTP_UNAUTHORIZED;
}

#endif

#endif

APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_out) *wsgi_logio_add_bytes_out;

static void ap_logio_add_bytes_out(conn_rec *c, apr_off_t bytes)
{
    if (!wsgi_daemon_pool && wsgi_logio_add_bytes_out)
        wsgi_logio_add_bytes_out(c, bytes);
}

static int wsgi_hook_logio(apr_pool_t *pconf, apr_pool_t *ptemp,
                           apr_pool_t *plog, server_rec *s)
{
    /*
     * This horrible fiddle is to insert a proxy function before
     * the normal ap_logio_add_bytes_out() function so that the
     * call to it can be disabled when mod_wsgi running in daemon
     * mode. If this is not done, then daemon process will crash
     * when mod_logio has been loaded.
     */

    wsgi_logio_add_bytes_out = APR_RETRIEVE_OPTIONAL_FN(ap_logio_add_bytes_out);

    APR_REGISTER_OPTIONAL_FN(ap_logio_add_bytes_out);

    return OK;
}

static void wsgi_register_hooks(apr_pool_t *p)
{
    static const char * const p1[] = { "mod_alias.c", NULL };
    static const char * const n1[]= { "mod_userdir.c",
                                      "mod_vhost_alias.c", NULL };

    static const char * const n2[] = { "core.c", NULL };

#if defined(MOD_WSGI_WITH_AAA_HANDLERS)
#if !defined(MOD_WSGI_WITH_AUTHN_PROVIDER)
    static const char * const p3[] = { "mod_auth.c", NULL };
#endif
#if !defined(MOD_WSGI_WITH_AUTHZ_PROVIDER)
    static const char * const n4[] = { "mod_authz_user.c", NULL };
#endif
    static const char * const n5[] = { "mod_authz_host.c", NULL };
#endif

    static const char * const p6[] = { "mod_python.c", NULL };

    ap_hook_post_config(wsgi_hook_init, p6, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(wsgi_hook_child_init, p6, NULL, APR_HOOK_MIDDLE);

    ap_hook_translate_name(wsgi_hook_intercept, p1, n1, APR_HOOK_MIDDLE);
    ap_hook_handler(wsgi_hook_handler, NULL, NULL, APR_HOOK_MIDDLE);

#if defined(MOD_WSGI_WITH_DAEMONS)
    ap_hook_post_config(wsgi_hook_logio, NULL, n2, APR_HOOK_REALLY_FIRST);

    wsgi_header_filter_handle =
        ap_register_output_filter("WSGI_HEADER", wsgi_header_filter,
                                  NULL, AP_FTYPE_PROTOCOL);
#endif

#if defined(MOD_WSGI_WITH_AAA_HANDLERS)
#if !defined(MOD_WSGI_WITH_AUTHN_PROVIDER)
    ap_hook_check_user_id(wsgi_hook_check_user_id, p3, NULL, APR_HOOK_MIDDLE);
#else
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "wsgi",
                         AUTHN_PROVIDER_VERSION, &wsgi_authn_provider);
#endif
#if !defined(MOD_WSGI_WITH_AUTHZ_PROVIDER)
    ap_hook_auth_checker(wsgi_hook_auth_checker, NULL, n4, APR_HOOK_MIDDLE);
#else
    ap_register_provider(p, AUTHZ_PROVIDER_GROUP, "wsgi-group",
                         AUTHZ_PROVIDER_VERSION, &wsgi_authz_provider);
#endif
    ap_hook_access_checker(wsgi_hook_access_checker, NULL, n5, APR_HOOK_MIDDLE);
#endif
}

static const command_rec wsgi_commands[] =
{
    AP_INIT_RAW_ARGS("WSGIScriptAlias", wsgi_add_script_alias,
        NULL, RSRC_CONF, "Map location to target WSGI script file."),
    AP_INIT_RAW_ARGS("WSGIScriptAliasMatch", wsgi_add_script_alias,
        "*", RSRC_CONF, "Map location pattern to target WSGI script file."),

#if defined(MOD_WSGI_WITH_DAEMONS)
    AP_INIT_RAW_ARGS("WSGIDaemonProcess", wsgi_add_daemon_process,
        NULL, RSRC_CONF, "Specify details of daemon processes to start."),
    AP_INIT_TAKE1("WSGISocketPrefix", wsgi_set_socket_prefix,
        NULL, RSRC_CONF, "Path prefix for the daemon process sockets."),
    AP_INIT_TAKE1("WSGIAcceptMutex", wsgi_set_accept_mutex,
        NULL, RSRC_CONF, "Set accept mutex type for daemon processes."),

    AP_INIT_TAKE1("WSGILazyInitialization", wsgi_set_lazy_initialization,
        NULL, RSRC_CONF, "Enable/Disable lazy Python initialization."),
#endif

    AP_INIT_TAKE1("WSGIVerboseDebugging", wsgi_set_verbose_debugging,
        NULL, RSRC_CONF, "Enable/Disable verbose debugging messages."),

#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 6
    AP_INIT_TAKE1("WSGIPy3kWarningFlag", wsgi_set_py3k_warning_flag,
        NULL, RSRC_CONF, "Enable/Disable Python 3.0 warnings."),
#endif

    AP_INIT_TAKE1("WSGIPythonWarnings", wsgi_add_python_warnings,
        NULL, RSRC_CONF, "Control Python warning messages."),
    AP_INIT_TAKE1("WSGIPythonOptimize", wsgi_set_python_optimize,
        NULL, RSRC_CONF, "Set level of Python compiler optimisations."),
    AP_INIT_TAKE1("WSGIPythonHome", wsgi_set_python_home,
        NULL, RSRC_CONF, "Python prefix/exec_prefix absolute path names."),
    AP_INIT_TAKE1("WSGIPythonPath", wsgi_set_python_path,
        NULL, RSRC_CONF, "Python module search path."),
    AP_INIT_TAKE1("WSGIPythonEggs", wsgi_set_python_eggs,
        NULL, RSRC_CONF, "Python eggs cache directory."),

#if defined(MOD_WSGI_WITH_DAEMONS)
    AP_INIT_TAKE1("WSGIRestrictEmbedded", wsgi_set_restrict_embedded,
        NULL, RSRC_CONF, "Enable/Disable use of embedded mode."),
#endif
    AP_INIT_TAKE1("WSGIRestrictStdin", wsgi_set_restrict_stdin,
        NULL, RSRC_CONF, "Enable/Disable restrictions on use of STDIN."),
    AP_INIT_TAKE1("WSGIRestrictStdout", wsgi_set_restrict_stdout,
        NULL, RSRC_CONF, "Enable/Disable restrictions on use of STDOUT."),
    AP_INIT_TAKE1("WSGIRestrictSignal", wsgi_set_restrict_signal,
        NULL, RSRC_CONF, "Enable/Disable restrictions on use of signal()."),

    AP_INIT_TAKE1("WSGICaseSensitivity", wsgi_set_case_sensitivity,
        NULL, RSRC_CONF, "Define whether file system is case sensitive."),

#if defined(MOD_WSGI_WITH_DAEMONS)
    AP_INIT_RAW_ARGS("WSGIRestrictProcess", wsgi_set_restrict_process,
        NULL, ACCESS_CONF|RSRC_CONF, "Limit selectable WSGI process groups."),
    AP_INIT_TAKE1("WSGIProcessGroup", wsgi_set_process_group,
        NULL, ACCESS_CONF|RSRC_CONF, "Name of the WSGI process group."),
#endif

    AP_INIT_TAKE1("WSGIApplicationGroup", wsgi_set_application_group,
        NULL, ACCESS_CONF|RSRC_CONF, "Application interpreter group."),
    AP_INIT_TAKE1("WSGICallableObject", wsgi_set_callable_object,
        NULL, OR_FILEINFO, "Name of entry point in WSGI script file."),

    AP_INIT_RAW_ARGS("WSGIImportScript", wsgi_add_import_script,
        NULL, RSRC_CONF, "Location of WSGI import script."),
    AP_INIT_RAW_ARGS("WSGIDispatchScript", wsgi_set_dispatch_script,
        NULL, ACCESS_CONF|RSRC_CONF, "Location of WSGI dispatch script."),

    AP_INIT_TAKE1("WSGIPassApacheRequest", wsgi_set_pass_apache_request,
        NULL, ACCESS_CONF|RSRC_CONF, "Enable/Disable Apache request object."),
    AP_INIT_TAKE1("WSGIPassAuthorization", wsgi_set_pass_authorization,
        NULL, OR_FILEINFO, "Enable/Disable WSGI authorization."),
    AP_INIT_TAKE1("WSGIScriptReloading", wsgi_set_script_reloading,
        NULL, OR_FILEINFO, "Enable/Disable script reloading mechanism."),
    AP_INIT_TAKE1("WSGIErrorOverride", wsgi_set_error_override,
        NULL, OR_FILEINFO, "Enable/Disable overriding of error pages."),
    AP_INIT_TAKE1("WSGIChunkedRequest", wsgi_set_chunked_request,
        NULL, OR_FILEINFO, "Enable/Disable support for chunked requests."),

#if defined(MOD_WSGI_WITH_AAA_HANDLERS)
    AP_INIT_RAW_ARGS("WSGIAccessScript", wsgi_set_access_script,
        NULL, OR_AUTHCFG, "Location of WSGI host access script file."),
    AP_INIT_RAW_ARGS("WSGIAuthUserScript", wsgi_set_auth_user_script,
        NULL, OR_AUTHCFG, "Location of WSGI user auth script file."),
    AP_INIT_RAW_ARGS("WSGIAuthGroupScript", wsgi_set_auth_group_script,
        NULL, OR_AUTHCFG, "Location of WSGI group auth script file."),
#if !defined(MOD_WSGI_WITH_AUTHN_PROVIDER)
    AP_INIT_TAKE1("WSGIUserAuthoritative", wsgi_set_user_authoritative,
        NULL, OR_AUTHCFG, "Enable/Disable as being authoritative on users."),
#endif
    AP_INIT_TAKE1("WSGIGroupAuthoritative", wsgi_set_group_authoritative,
        NULL, OR_AUTHCFG, "Enable/Disable as being authoritative on groups."),
#endif

    AP_INIT_RAW_ARGS("WSGIHandlerScript", wsgi_add_handler_script,
        NULL, ACCESS_CONF|RSRC_CONF, "Location of WSGI handler script file."),

    { NULL }
};

/* Dispatch list for API hooks */

module AP_MODULE_DECLARE_DATA wsgi_module = {
    STANDARD20_MODULE_STUFF,
    wsgi_create_dir_config,    /* create per-dir    config structures */
    wsgi_merge_dir_config,     /* merge  per-dir    config structures */
    wsgi_create_server_config, /* create per-server config structures */
    wsgi_merge_server_config,  /* merge  per-server config structures */
    wsgi_commands,             /* table of config file commands       */
    wsgi_register_hooks        /* register hooks                      */
};

#endif
