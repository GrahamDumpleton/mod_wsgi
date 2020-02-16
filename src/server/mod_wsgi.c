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

#include "wsgi_apache.h"
#include "wsgi_python.h"

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifndef WIN32
#include <pwd.h>
#endif

static PyTypeObject Auth_Type;
#if AP_SERVER_MINORVERSION_NUMBER >= 2
#define MOD_WSGI_WITH_AUTHN_PROVIDER 1
#endif
#if AP_MODULE_MAGIC_AT_LEAST(20060110,0)
#define MOD_WSGI_WITH_AUTHZ_PROVIDER 1
#if AP_MODULE_MAGIC_AT_LEAST(20100919,0)
#define MOD_WSGI_WITH_AUTHZ_PROVIDER_PARSED 1
#endif
#endif

#if defined(MOD_WSGI_WITH_AUTHN_PROVIDER)
#include "mod_auth.h"
#include "ap_provider.h"
#ifndef AUTHN_PROVIDER_VERSION
#define AUTHN_PROVIDER_VERSION "0"
#endif
#endif

/* Local project header files. */

#include "wsgi_version.h"
#include "wsgi_convert.h"
#include "wsgi_validate.h"
#include "wsgi_interp.h"
#include "wsgi_server.h"
#include "wsgi_logger.h"
#include "wsgi_restrict.h"
#include "wsgi_stream.h"
#include "wsgi_metrics.h"
#include "wsgi_daemon.h"
#include "wsgi_buckets.h"
#include "wsgi_thread.h"

/* Module information. */

module AP_MODULE_DECLARE_DATA wsgi_module;

/* Process information. */

static int wsgi_multiprocess = 1;
static int wsgi_multithread = 1;

/* Daemon information. */

static apr_array_header_t *wsgi_daemon_list = NULL;

static apr_pool_t *wsgi_parent_pool = NULL;

int volatile wsgi_daemon_shutdown = 0;
static int volatile wsgi_daemon_graceful = 0;
static int wsgi_dump_stack_traces = 0;
static char *wsgi_shutdown_reason = "";

#if defined(MOD_WSGI_WITH_DAEMONS)
static apr_interval_time_t wsgi_startup_timeout = 0;
static apr_interval_time_t wsgi_deadlock_timeout = 0;
static apr_interval_time_t wsgi_idle_timeout = 0;
static apr_interval_time_t wsgi_request_timeout = 0;
static apr_interval_time_t wsgi_graceful_timeout = 0;
static apr_interval_time_t wsgi_eviction_timeout = 0;
static apr_interval_time_t wsgi_restart_interval = 0;
static apr_time_t volatile wsgi_startup_shutdown_time = 0;
static apr_time_t volatile wsgi_deadlock_shutdown_time = 0;
static apr_time_t volatile wsgi_idle_shutdown_time = 0;
static apr_time_t volatile wsgi_graceful_shutdown_time = 0;
static apr_time_t volatile wsgi_restart_shutdown_time = 0;
#endif

/* Script information. */

static apr_array_header_t *wsgi_import_list = NULL;

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

    if (child->map_head_to_get != -1)
        config->map_head_to_get = child->map_head_to_get;
    else
        config->map_head_to_get = parent->map_head_to_get;

    if (child->ignore_activity != -1)
        config->ignore_activity = child->ignore_activity;
    else
        config->ignore_activity = parent->ignore_activity;

    if (child->trusted_proxy_headers)
        config->trusted_proxy_headers = child->trusted_proxy_headers;
    else
        config->trusted_proxy_headers = parent->trusted_proxy_headers;

    if (child->trusted_proxies)
        config->trusted_proxies = child->trusted_proxies;
    else
        config->trusted_proxies = parent->trusted_proxies;

    if (child->enable_sendfile != -1)
        config->enable_sendfile = child->enable_sendfile;
    else
        config->enable_sendfile = parent->enable_sendfile;

    if (!child->handler_scripts)
        config->handler_scripts = parent->handler_scripts;
    else if (!parent->handler_scripts)
        config->handler_scripts = child->handler_scripts;
    else {
        config->handler_scripts = apr_hash_overlay(p, child->handler_scripts,
                                                   parent->handler_scripts);
    }

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
    int map_head_to_get;
    int ignore_activity;

    apr_array_header_t *trusted_proxy_headers;
    apr_array_header_t *trusted_proxies;

    int enable_sendfile;

    WSGIScriptFile *access_script;
    WSGIScriptFile *auth_user_script;
    WSGIScriptFile *auth_group_script;
    int user_authoritative;
    int group_authoritative;

    apr_hash_t *handler_scripts;
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
    object->map_head_to_get = -1;
    object->ignore_activity = -1;

    object->trusted_proxy_headers = NULL;
    object->trusted_proxies = NULL;

    object->enable_sendfile = -1;

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

    if (child->map_head_to_get != -1)
        config->map_head_to_get = child->map_head_to_get;
    else
        config->map_head_to_get = parent->map_head_to_get;

    if (child->ignore_activity != -1)
        config->ignore_activity = child->ignore_activity;
    else
        config->ignore_activity = parent->ignore_activity;

    if (child->trusted_proxy_headers)
        config->trusted_proxy_headers = child->trusted_proxy_headers;
    else
        config->trusted_proxy_headers = parent->trusted_proxy_headers;

    if (child->trusted_proxies)
        config->trusted_proxies = child->trusted_proxies;
    else
        config->trusted_proxies = parent->trusted_proxies;

    if (child->enable_sendfile != -1)
        config->enable_sendfile = child->enable_sendfile;
    else
        config->enable_sendfile = parent->enable_sendfile;

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

    if (!child->handler_scripts)
        config->handler_scripts = parent->handler_scripts;
    else if (!parent->handler_scripts)
        config->handler_scripts = child->handler_scripts;
    else {
        config->handler_scripts = apr_hash_overlay(p, child->handler_scripts,
                                                   parent->handler_scripts);
    }

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
    int map_head_to_get;
    int ignore_activity;

    apr_array_header_t *trusted_proxy_headers;
    apr_array_header_t *trusted_proxies;

    int enable_sendfile;

    WSGIScriptFile *access_script;
    WSGIScriptFile *auth_user_script;
    WSGIScriptFile *auth_group_script;
    int user_authoritative;
    int group_authoritative;

    apr_hash_t *handler_scripts;
    const char *handler_script;

    int daemon_connects;
    int daemon_restarts;

    apr_time_t request_start;
    apr_time_t queue_start;
    apr_time_t daemon_start;
} WSGIRequestConfig;

static long wsgi_find_path_info(const char *uri, const char *path_info)
{
    long lu = strlen(uri);
    long lp = strlen(path_info);

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
    long path_info_start = 0;

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

    const char *h = NULL;
    apr_port_t p = 0;
    const char *n = NULL;

    if (!s)
        return "";

    if (*s != '%')
        return s;

    name = s + 1;

    if (*name) {
        if (!strcmp(name, "{GLOBAL}"))
            return "";

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

        if (!strcmp(name, "{HOST}")) {
            h = r->hostname;
            p = ap_get_server_port(r);

            /*
             * The Host header could be empty or absent for HTTP/1.0
             * or older. In that case fallback to ServerName.
             */

            if (h == NULL || *h == 0)
                h = r->server->server_hostname;

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u", h, p);
            else
                return h;
        }

        if (strstr(name, "{ENV:") == name) {
            long len = 0;

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

    const char *h = NULL;
    apr_port_t p = 0;

    if (!s)
        return "";

    if (*s != '%')
        return s;

    name = s + 1;

    if (*name) {
        if (!strcmp(name, "{GLOBAL}"))
            return "";

        if (!strcmp(name, "{SERVER}")) {
            h = r->server->server_hostname;
            p = ap_get_server_port(r);

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u", h, p);
            else
                return h;
        }

        if (!strcmp(name, "{HOST}")) {
            h = r->hostname;
            p = ap_get_server_port(r);

            /*
             * The Host header could be empty or absent for HTTP/1.0
             * or older. In that case fallback to ServerName.
             */

            if (h == NULL || *h == 0)
                h = r->server->server_hostname;

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u", h, p);
            else
                return h;
        }
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
        if (!strcmp(name, "{GLOBAL}"))
            return "";

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

        if (!strcmp(name, "{HOST}")) {
            h = r->hostname;
            p = ap_get_server_port(r);

            /*
             * The Host header could be empty or absent for HTTP/1.0
             * or older. In that case fallback to ServerName.
             */

            if (h == NULL || *h == 0)
                h = r->server->server_hostname;

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u", h, p);
            else
                return h;
        }

        if (strstr(name, "{ENV:") == name) {
            long len = 0;

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
        long len = 0;

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

    config->map_head_to_get = dconfig->map_head_to_get;

    if (config->map_head_to_get < 0) {
        config->map_head_to_get = sconfig->map_head_to_get;
        if (config->map_head_to_get < 0)
            config->map_head_to_get = 2;
    }

    config->ignore_activity = dconfig->ignore_activity;

    if (config->ignore_activity < 0) {
        config->ignore_activity = sconfig->ignore_activity;
        if (config->ignore_activity < 0)
            config->ignore_activity = 0;
    }

    config->trusted_proxy_headers = dconfig->trusted_proxy_headers;

    if (!config->trusted_proxy_headers)
        config->trusted_proxy_headers = sconfig->trusted_proxy_headers;

    config->trusted_proxies = dconfig->trusted_proxies;

    if (!config->trusted_proxies)
        config->trusted_proxies = sconfig->trusted_proxies;

    config->enable_sendfile = dconfig->enable_sendfile;

    if (config->enable_sendfile < 0) {
        config->enable_sendfile = sconfig->enable_sendfile;
        if (config->enable_sendfile < 0)
            config->enable_sendfile = 0;
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

    if (!dconfig->handler_scripts)
        config->handler_scripts = sconfig->handler_scripts;
    else if (!sconfig->handler_scripts)
        config->handler_scripts = dconfig->handler_scripts;
    else {
        config->handler_scripts = apr_hash_overlay(p, dconfig->handler_scripts,
                                                   sconfig->handler_scripts);
    }

    config->handler_script = "";

    config->daemon_connects = 0;
    config->daemon_restarts = 0;

    config->request_start = 0;
    config->queue_start = 0;
    config->daemon_start = 0;

    return config;
}

/* Error reporting. */

static void wsgi_log_script_error(request_rec *r, const char *e, const char *n)
{
    char *message = NULL;

    if (!n)
        n = r->filename;

    message = apr_psprintf(r->pool, "%s: %s", e, n);

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", message);
}

/* Class objects used by response handler. */

static PyTypeObject Dispatch_Type;

typedef struct {
        PyObject_HEAD
        request_rec *r;
        int init;
        int done;
        char *buffer;
        apr_off_t size;
        apr_off_t offset;
        apr_off_t length;
        apr_bucket_brigade *bb;
        int seen_eos;
        int seen_error;
        apr_off_t bytes;
        apr_off_t reads;
        apr_time_t time;
        int ignore_activity;
} InputObject;

static PyTypeObject Input_Type;

static InputObject *newInputObject(request_rec *r, int ignore_activity)
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

    self->bb = NULL;

    self->seen_eos = 0;
    self->seen_error = 0;

    self->bytes = 0;
    self->reads = 0;
    self->time = 0;

    self->ignore_activity = ignore_activity;

    return self;
}

static void Input_dealloc(InputObject *self)
{
    if (self->buffer)
        free(self->buffer);

    PyObject_Del(self);
}

static void Input_finish(InputObject *self)
{
    if (self->bb) {
        Py_BEGIN_ALLOW_THREADS
        apr_brigade_destroy(self->bb);
        Py_END_ALLOW_THREADS

        self->bb = NULL;
    }

    self->r = NULL;
}

static PyObject *Input_close(InputObject *self, PyObject *args)
{
    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static apr_status_t wsgi_strtoff(apr_off_t *offset, const char *nptr,
                                 char **endptr, int base)
{
   errno = 0;
   if (sizeof(apr_off_t) == 4) {
       *offset = strtol(nptr, endptr, base);
   }
   else {
       *offset = apr_strtoi64(nptr, endptr, base);
   }
   return APR_FROM_OS_ERROR(errno);
}

static apr_int64_t Input_read_from_input(InputObject *self, char *buffer,
                                  apr_size_t bufsiz)
{
    request_rec *r = self->r;
    apr_bucket_brigade *bb = self->bb;

    apr_status_t rv;

    apr_status_t error_status = 0;
    const char *error_message = NULL;

    apr_time_t start = 0;
    apr_time_t finish = 0;

    /* If have already seen end of input, return an empty string. */

    if (self->seen_eos)
        return 0;

    /* If have already encountered an error, then raise a new error. */

    if (self->seen_error) {
        PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi request data read "
                "error: Input is already in error state.");

        return -1;
    }

    /*
     * When reaading the request content we will be saying that we
     * should block if there is no input data available at that
     * point but not all data has been exhausted. We therefore need
     * to ensure that we do not cause Python as a whole to block by
     * releasing the GIL, but also must remember to reacquire the GIL
     * when we exit.
     */

    Py_BEGIN_ALLOW_THREADS

    start = apr_time_now();

    self->reads += 1;

    /*
     * Create the bucket brigade the first time it is required and
     * save it against the input object. We need to make sure we
     * perform a cleanup, but not destroy, the bucket brigade each
     * time we exit this function.
     */

    if (!bb) {
        bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

        if (bb == NULL) {
            r->connection->keepalive = AP_CONN_CLOSE;
            error_message = "Unable to create bucket brigade";
            goto finally;
        }

        self->bb = bb;
    }

    /* Force the required amount of input to be read. */

    rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                        APR_BLOCK_READ, bufsiz);

    if (rv != APR_SUCCESS) {
        /*
         * If we actually fail here, we want to just return and
         * stop trying to read data from the client. The HTTP_IN
         * input filter is a bit of a pain here as it can return
         * EAGAIN in various strange situations where it isn't
         * believed that it means to retry, but that it is still
         * a permanent failure. This can include timeouts and
         * errors in chunked encoding format. To avoid a message
         * of 'Resource temporarily unavailable' which could be
         * confusing, replace it with a generic message that the
         * connection was terminated.
         */

        r->connection->keepalive = AP_CONN_CLOSE;

        if (APR_STATUS_IS_EAGAIN(rv))
            error_message = "Connection was terminated";
        else
            error_status = rv;

        goto finally;
    }

    /*
     * If this fails, it means that a filter is written incorrectly and
     * that it needs to learn how to properly handle APR_BLOCK_READ
     * requests by returning data when requested.
     */

    AP_DEBUG_ASSERT(!APR_BRIGADE_EMPTY(bb));

    /*
     * Check to see if EOS terminates the brigade. If so, we remember
     * this to avoid any attempts to read more data in future calls.
     */

    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb)))
        self->seen_eos = 1;

    /* Now extract the actual data from the bucket brigade. */

    rv = apr_brigade_flatten(bb, buffer, &bufsiz);

    if (rv != APR_SUCCESS) {
        error_status = rv;
        goto finally;
    }

finally:
    /*
     * We must always cleanup up, not destroy, the brigade after
     * each call.
     */

    if (bb)
        apr_brigade_cleanup(bb);

    finish = apr_time_now();

    if (finish > start)
        self->time += (finish - start);

    /* Make sure we reacquire the GIL when all done. */

    Py_END_ALLOW_THREADS

    /*
     * Set any Python exception when an error has occurred and
     * remember there was an error so can flag on subsequent
     * reads that already in an error state.
     */

    if (error_status) {
        char status_buffer[512];

        error_message = apr_psprintf(r->pool, "Apache/mod_wsgi request "
                "data read error: %s.", apr_strerror(error_status,
                status_buffer, sizeof(status_buffer)-1));

        PyErr_SetString(PyExc_IOError, error_message);

        self->seen_error = 1;

        return -1;
    }
    else if (error_message) {
        error_message = apr_psprintf(r->pool, "Apache/mod_wsgi request "
                "data read error: %s.", error_message);

        PyErr_SetString(PyExc_IOError, error_message);

        self->seen_error = 1;

        return -1;
    }

    /*
     * Finally return the amount of data that was read. This will be
     * zero if all data has been consumed.
     */

    return bufsiz;
}

static PyObject *Input_read(InputObject *self, PyObject *args)
{
#if defined(HAVE_LONG_LONG)
    PY_LONG_LONG size = -1;
#else
    long size = -1;
#endif

    PyObject *result = NULL;
    char *buffer = NULL;
    apr_off_t length = 0;
    int init = 0;

    apr_int64_t n;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

#if defined(HAVE_LONG_LONG)
    if (!PyArg_ParseTuple(args, "|L:read", &size))
        return NULL;
#else
    if (!PyArg_ParseTuple(args, "|l:read", &size))
        return NULL;
#endif

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_idle_timeout && !self->ignore_activity) {
        apr_thread_mutex_lock(wsgi_monitor_lock);

        if (wsgi_idle_timeout) {
            wsgi_idle_shutdown_time = apr_time_now();
            wsgi_idle_shutdown_time += wsgi_idle_timeout;
        }

        apr_thread_mutex_unlock(wsgi_monitor_lock);
    }
#endif

    if (self->seen_error) {
        PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi request data read "
                "error: Input is already in error state.");

        return NULL;
    }

    init = self->init;

    if (!self->init)
        self->init = 1;

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

            n = Input_read_from_input(self, dummy, 0);

            if (n == -1)
                return NULL;
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
                n = Input_read_from_input(self, buffer+length, size-length);

                if (n == -1) {
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

        if (self->buffer) {
            size = self->length;
            size = size + (size >> 2);

            if (size < HUGE_STRING_LEN)
                size = HUGE_STRING_LEN;
        }
        else
            size = HUGE_STRING_LEN;

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

        n = Input_read_from_input(self, buffer+length, size-length);

        if (n == -1) {
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

            n = Input_read_from_input(self, buffer+length, size-length);

            if (n == -1) {
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

    self->bytes += length;

    return result;
}

static PyObject *Input_readline(InputObject *self, PyObject *args)
{
#if defined(HAVE_LONG_LONG)
    PY_LONG_LONG size = -1;
#else
    long size = -1;
#endif

    PyObject *result = NULL;
    char *buffer = NULL;
    apr_off_t length = 0;

    apr_int64_t n;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

#if defined(HAVE_LONG_LONG)
    if (!PyArg_ParseTuple(args, "|L:readline", &size))
        return NULL;
#else
    if (!PyArg_ParseTuple(args, "|l:readline", &size))
        return NULL;
#endif

    if (self->seen_error) {
        PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi request data read "
                "error: Input is already in error state.");

        return NULL;
    }

    if (!self->init)
        self->init = 1;

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

            n = Input_read_from_input(self, buffer+length, size-length);

            if (n == -1) {
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

            n = Input_read_from_input(self, buffer+length, size-length);

            if (n == -1) {
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

    self->bytes += length;

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
        long n;

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
    { "close",     (PyCFunction)Input_close,     METH_NOARGS, 0 },
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
        apr_bucket_brigade *bb;
        WSGIRequestConfig *config;
        InputObject *input;
        PyObject *log_buffer;
        PyObject *log;
        int status;
        const char *status_line;
        PyObject *headers;
        PyObject *sequence;
        int content_length_set;
        apr_off_t content_length;
        apr_off_t output_length;
        apr_off_t output_writes;
        apr_time_t output_time;
        apr_time_t start_time;
} AdapterObject;

static PyTypeObject Adapter_Type;

static AdapterObject *newAdapterObject(request_rec *r)
{
    AdapterObject *self;

    self = PyObject_New(AdapterObject, &Adapter_Type);
    if (self == NULL)
        return NULL;

    self->result = HTTP_INTERNAL_SERVER_ERROR;

    self->r = r;

    self->bb = NULL;

    self->config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                             &wsgi_module);

    self->status = HTTP_INTERNAL_SERVER_ERROR;
    self->status_line = NULL;
    self->headers = NULL;
    self->sequence = NULL;

    self->content_length_set = 0;
    self->content_length = 0;
    self->output_length = 0;
    self->output_writes = 0;

    self->output_time = 0;

    self->input = newInputObject(r, self->config->ignore_activity);

    self->log_buffer = newLogBufferObject(r, APLOG_ERR, "<wsgi.errors>", 0);
    self->log = newLogWrapperObject(self->log_buffer);

    return self;
}

static void Adapter_dealloc(AdapterObject *self)
{
    Py_XDECREF(self->headers);
    Py_XDECREF(self->sequence);

    Py_DECREF(self->input);

    Py_DECREF(self->log_buffer);
    Py_DECREF(self->log);

    PyObject_Del(self);
}

static PyObject *Adapter_start_response(AdapterObject *self, PyObject *args)
{
    PyObject *result = NULL;

    PyObject *status_line = NULL;
    PyObject *headers = NULL;
    PyObject *exc_info = Py_None;

    PyObject *status_line_as_bytes = NULL;
    PyObject *headers_as_bytes = NULL;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "OO!|O:start_response",
        &status_line, &PyList_Type, &headers, &exc_info)) {
        return NULL;
    }

    if (exc_info != Py_None && !PyTuple_Check(exc_info)) {
        PyErr_SetString(PyExc_RuntimeError, "exception info must be a tuple");
        return NULL;
    }

    if (exc_info != Py_None) {
        if (self->status_line && !self->headers) {
            PyObject *type = NULL;
            PyObject *value = NULL;
            PyObject *traceback = NULL;

            if (!PyArg_ParseTuple(exc_info, "OOO", &type,
                                  &value, &traceback)) {
                return NULL;
            }

            Py_INCREF(type);
            Py_INCREF(value);
            Py_INCREF(traceback);

            PyErr_Restore(type, value, traceback);

            return NULL;
        }
    }
    else if (self->status_line && !self->headers) {
        PyErr_SetString(PyExc_RuntimeError, "headers have already been sent");
        return NULL;
    }

    /* Publish event for the start of the response. */

    if (wsgi_event_subscribers()) {
        WSGIThreadInfo *thread_info;

        PyObject *event = NULL;
        PyObject *value = NULL;

        thread_info = wsgi_thread_info(0, 0);

        event = PyDict_New();

#if AP_MODULE_MAGIC_AT_LEAST(20100923,2)
        if (self->r->log_id) {
#if PY_MAJOR_VERSION >= 3
	    value = PyUnicode_DecodeLatin1(self->r->log_id,
                                           strlen(self->r->log_id), NULL);
#else
	    value = PyString_FromString(self->r->log_id);
#endif
            PyDict_SetItemString(event, "request_id", value);
            Py_DECREF(value);
        }
#endif

        PyDict_SetItemString(event, "response_status", status_line);
        PyDict_SetItemString(event, "response_headers", headers);
        PyDict_SetItemString(event, "exception_info", exc_info);

        PyDict_SetItemString(event, "request_data", thread_info->request_data);

        wsgi_publish_event("response_started", event);

        Py_DECREF(event);
    }

    status_line_as_bytes = wsgi_convert_status_line_to_bytes(status_line);

    if (!status_line_as_bytes)
        goto finally;

    headers_as_bytes = wsgi_convert_headers_to_bytes(headers);

    if (!headers_as_bytes)
        goto finally;

    self->status_line = apr_pstrdup(self->r->pool, PyString_AsString(
                                    status_line_as_bytes));
    self->status = (int)strtol(self->status_line, NULL, 10);

    Py_XDECREF(self->headers);
    self->headers = headers_as_bytes;
    Py_INCREF(headers_as_bytes);

    result = PyObject_GetAttrString((PyObject *)self, "write");

finally:
    Py_XDECREF(status_line_as_bytes);
    Py_XDECREF(headers_as_bytes);

    return result;
}

static int Adapter_output(AdapterObject *self, const char *data,
                          apr_off_t length, PyObject *string_object,
                          int exception_when_aborted)
{
    int i = 0;
    apr_status_t rv;
    request_rec *r;

    apr_time_t output_start = 0;
    apr_time_t output_finish = 0;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_idle_timeout && !self->config->ignore_activity) {
        apr_thread_mutex_lock(wsgi_monitor_lock);

        if (wsgi_idle_timeout) {
            wsgi_idle_shutdown_time = apr_time_now();
            wsgi_idle_shutdown_time += wsgi_idle_timeout;
        }

        apr_thread_mutex_unlock(wsgi_monitor_lock);
    }
#endif

    if (!self->status_line) {
        PyErr_SetString(PyExc_RuntimeError, "response has not been started");
        return 0;
    }

    r = self->r;

    /* Remember we started sending this block of output. */

    output_start = apr_time_now();

    /* Count how many separate blocks have been output. */

    if (string_object)
        self->output_writes++;

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

#if (AP_SERVER_MAJORVERSION_NUMBER == 2 && \
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

        /*
         * Now setup the response headers in request object. We
         * have already converted any native strings in the
         * headers to byte strings and validated the format of
         * the header names and values so can skip all the error
         * checking.
         */

        r->status = self->status;
        r->status_line = self->status_line;

        for (i = 0; i < PyList_Size(self->headers); i++) {
            PyObject *tuple = NULL;

            PyObject *object1 = NULL;
            PyObject *object2 = NULL;

            char *name = NULL;
            char *value = NULL;

            tuple = PyList_GetItem(self->headers, i);

            object1 = PyTuple_GetItem(tuple, 0);
            object2 = PyTuple_GetItem(tuple, 1);

            name = PyBytes_AsString(object1);
            value = PyBytes_AsString(object2);

            if (!strcasecmp(name, "Content-Type")) {
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
                    ap_set_content_type(r, apr_pstrdup(r->pool, value));
            }
            else if (!strcasecmp(name, "Content-Length")) {
                char *endstr;
                apr_off_t length;

                if (wsgi_strtoff(&length, value, &endstr, 10)
                    || *endstr || length < 0) {

                    PyErr_SetString(PyExc_ValueError,
                                    "invalid content length");

                    output_finish = apr_time_now();

                    if (output_finish > output_start)
                        self->output_time += (output_finish - output_start);

                    return 0;
                }

                ap_set_content_length(r, length);

                self->content_length_set = 1;
                self->content_length = length;
            }
            else if (!strcasecmp(name, "WWW-Authenticate")) {
                apr_table_add(r->err_headers_out, name, value);
            }
            else {
                apr_table_add(r->headers_out, name, value);
            }
        }

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
        apr_off_t output_length = length;

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
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, self->r,
                              "mod_wsgi (pid=%d): Client closed connection.",
                              getpid());
            }
            else
                PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi client "
                                "connection closed.");

            output_finish = apr_time_now();

            if (output_finish > output_start)
                self->output_time += (output_finish - output_start);

            return 0;
        }

        if (!self->bb) {
            self->bb = apr_brigade_create(r->pool,
                                          r->connection->bucket_alloc);
        }

#if 0
        if (string_object) {
            b = wsgi_apr_bucket_python_create(data, length,
                    self->config->application_group, string_object,
                    r->connection->bucket_alloc);
        }
        else {
#endif
            b = apr_bucket_transient_create(data, (apr_size_t)length,
                                            r->connection->bucket_alloc);
#if 0
        }
#endif

        APR_BRIGADE_INSERT_TAIL(self->bb, b);

        b = apr_bucket_flush_create(r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(self->bb, b);

        Py_BEGIN_ALLOW_THREADS
        rv = ap_pass_brigade(r->output_filters, self->bb);
        Py_END_ALLOW_THREADS

        if (rv != APR_SUCCESS) {
            char status_buffer[512];
            const char *error_message;

            if (!exception_when_aborted) {
                error_message = apr_psprintf(r->pool, "Failed to write "
                        "response data: %s", apr_strerror(rv, status_buffer,
                        sizeof(status_buffer)-1));

                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, self->r,
                              "mod_wsgi (pid=%d): %s.", getpid(),
                              error_message);
            }
            else {
                error_message = apr_psprintf(r->pool, "Apache/mod_wsgi "
                        "failed to write response data: %s",
                        apr_strerror(rv, status_buffer,
                        sizeof(status_buffer)-1));

                PyErr_SetString(PyExc_IOError, error_message);
            }

            output_finish = apr_time_now();

            if (output_finish > output_start)
                self->output_time += (output_finish - output_start);

            return 0;
        }

        Py_BEGIN_ALLOW_THREADS
        apr_brigade_cleanup(self->bb);
        Py_END_ALLOW_THREADS
    }

    /* Add how much time we spent send this block of output. */

    output_finish = apr_time_now();

    if (output_finish > output_start)
        self->output_time += (output_finish - output_start);

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
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, self->r,
                          "mod_wsgi (pid=%d): Client closed connection.",
                          getpid());
        }
        else
            PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi client "
                            "connection closed.");

        return 0;
    }

    return 1;
}

/* Split buckets at 1GB when sending large files. */

#define MAX_BUCKET_SIZE (0x40000000)

static int Adapter_output_file(AdapterObject *self, apr_file_t* tmpfile,
                               apr_off_t offset, apr_off_t len)
{
    request_rec *r;
    apr_bucket *b;
    apr_status_t rv;
    apr_bucket_brigade *bb;

    apr_file_t* dupfile = NULL;

    r = self->r;

    if (r->connection->aborted) {
        PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi client "
                        "connection closed.");
        return 0;
    }

    if (len == 0)
        return 1;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    apr_file_dup(&dupfile, tmpfile, r->pool);

    if (sizeof(apr_off_t) == sizeof(apr_size_t) || len < MAX_BUCKET_SIZE) {
        /* Can use a single bucket to send file. */

#if 0
        b = apr_bucket_file_create(tmpfile, offset, (apr_size_t)len, r->pool,
                                   r->connection->bucket_alloc);
#endif
        b = apr_bucket_file_create(dupfile, offset, (apr_size_t)len, r->pool,
                                   r->connection->bucket_alloc);
    }
    else {
        /* Need to create multiple buckets to send file. */

#if 0
        b = apr_bucket_file_create(tmpfile, offset, MAX_BUCKET_SIZE, r->pool,
                                   r->connection->bucket_alloc);
#endif
        b = apr_bucket_file_create(dupfile, offset, MAX_BUCKET_SIZE, r->pool,
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
        char status_buffer[512];
        const char *error_message;

        error_message = apr_psprintf(r->pool, "Apache/mod_wsgi failed "
                "to write response data: %s.", apr_strerror(rv,
                status_buffer, sizeof(status_buffer)-1));

        PyErr_SetString(PyExc_IOError, error_message);
        return 0;
    }

    Py_BEGIN_ALLOW_THREADS
    apr_brigade_destroy(bb);
    Py_END_ALLOW_THREADS

    if (r->connection->aborted) {
        PyErr_SetString(PyExc_IOError, "Apache/mod_wsgi client connection "
                        "closed.");
        return 0;
    }

    return 1;
}

static APR_OPTIONAL_FN_TYPE(ssl_is_https) *wsgi_is_https = NULL;

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

    object = Py_BuildValue("(ii)", 1, 0);
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
     * We remove the HTTPS variable because WSGI compliant
     * applications shouldn't rely on it. Instead they should
     * use wsgi.url_scheme. We do this even if SetEnv was
     * used to set HTTPS from Apache configuration. That is
     * we convert it into the correct variable and remove the
     * original.
     */

    if (scheme)
        PyDict_DelItemString(vars, "HTTPS");

    /*
     * Setup log object for WSGI errors. Don't decrement
     * reference to log object as keep reference to it.
     */

    object = (PyObject *)self->log;
    PyDict_SetItemString(vars, "wsgi.errors", object);

    /* Setup input object for request content. */

    object = (PyObject *)self->input;
    PyDict_SetItemString(vars, "wsgi.input", object);

    PyDict_SetItemString(vars, "wsgi.input_terminated", Py_True);

    /* Setup file wrapper object for efficient file responses. */

    PyDict_SetItemString(vars, "wsgi.file_wrapper", (PyObject *)&Stream_Type);

    /* Add Apache and mod_wsgi version information. */

    object = Py_BuildValue("(iii)", AP_SERVER_MAJORVERSION_NUMBER,
                           AP_SERVER_MINORVERSION_NUMBER,
                           AP_SERVER_PATCHLEVEL_NUMBER);
    PyDict_SetItemString(vars, "apache.version", object);
    Py_DECREF(object);

    object = Py_BuildValue("(iii)", MOD_WSGI_MAJORVERSION_NUMBER,
                           MOD_WSGI_MINORVERSION_NUMBER,
                           MOD_WSGI_MICROVERSION_NUMBER);
    PyDict_SetItemString(vars, "mod_wsgi.version", object);
    Py_DECREF(object);

    /*
     * If Apache extensions are enabled and running in embedded
     * mode add a CObject reference to the Apache request_rec
     * structure instance.
     */

    if (!wsgi_daemon_pool && self->config->pass_apache_request) {
#if (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 2) || \
    (PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 7)
        object = PyCapsule_New(self->r, 0, 0);
#else
        object = PyCObject_FromVoidPtr(self->r, 0);
#endif
        PyDict_SetItemString(vars, "apache.request_rec", object);
        Py_DECREF(object);
    }

    /*
     * Extensions for accessing SSL certificate information from
     * mod_ssl when in use.
     */

#if 0
    if (!wsgi_daemon_pool) {
        object = PyObject_GetAttrString((PyObject *)self, "ssl_is_https");
        PyDict_SetItemString(vars, "mod_ssl.is_https", object);
        Py_DECREF(object);

        object = PyObject_GetAttrString((PyObject *)self, "ssl_var_lookup");
        PyDict_SetItemString(vars, "mod_ssl.var_lookup", object);
        Py_DECREF(object);
    }
#endif

    return vars;
}

static int Adapter_process_file_wrapper(AdapterObject *self)
{
    int done = 0;

#ifndef WIN32
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

    if (!PyObject_IsInstance(self->sequence, (PyObject *)&Stream_Type))
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


    filelike = PyObject_GetAttrString((PyObject *)self->sequence, "filelike");

    if (!filelike) {
        PyErr_SetString(PyExc_KeyError,
                        "file wrapper no filelike attribute");
        return 0;
    }

    fd = PyObject_AsFileDescriptor(filelike);
    if (fd == -1) {
        PyErr_Clear();
        Py_DECREF(filelike);
        return 0;
    }

    Py_DECREF(filelike);

    /*
     * On some platforms, such as Linux, sendfile() system call
     * will not work on UNIX sockets. Thus when using daemon mode
     * cannot enable that feature.
     */

    if (self->config->enable_sendfile)
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

    if (!Adapter_output(self, "", 0, NULL, 0))
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

    return done;
}

static int Adapter_run(AdapterObject *self, PyObject *object)
{
    PyObject *vars = NULL;
    PyObject *start = NULL;
    PyObject *args = NULL;
    PyObject *iterator = NULL;
    PyObject *close = NULL;

    PyObject *nrwrapper = NULL;
    PyObject *evwrapper = NULL;

    PyObject *value = NULL;
    PyObject *event = NULL;

    const char *msg = NULL;
    apr_off_t length = 0;

    WSGIThreadInfo *thread_handle = NULL;

    apr_time_t finish_time;

    WSGIThreadCPUUsage start_usage;
    WSGIThreadCPUUsage end_usage;

    int aborted = 0;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_idle_timeout && !self->config->ignore_activity) {
        apr_thread_mutex_lock(wsgi_monitor_lock);

        if (wsgi_idle_timeout) {
            wsgi_idle_shutdown_time = apr_time_now();
            wsgi_idle_shutdown_time += wsgi_idle_timeout;
        }

        apr_thread_mutex_unlock(wsgi_monitor_lock);
    }
#endif

    if (wsgi_newrelic_config_file) {
        PyObject *module = NULL;

        module = PyImport_ImportModule("newrelic.agent");

        if (module) {
            PyObject *dict;
            PyObject *factory;

            dict = PyModule_GetDict(module);
            factory = PyDict_GetItemString(dict, "WSGIApplicationWrapper");

            if (factory) {
                Py_INCREF(factory);

                nrwrapper = PyObject_CallFunctionObjArgs(
                        factory, object, Py_None, NULL);

                if (!nrwrapper) {
                    wsgi_log_python_error(self->r, self->log,
                                          self->r->filename, 0);
                    PyErr_Clear();
                }

                Py_DECREF(factory);
            }

            Py_DECREF(module);
        }
    }

    if (nrwrapper)
        object = nrwrapper;

    self->start_time = apr_time_now();

    apr_table_setn(self->r->subprocess_env, "mod_wsgi.script_start",
                   apr_psprintf(self->r->pool, "%" APR_TIME_T_FMT,
                   self->start_time));

    vars = Adapter_environ(self);

    value = wsgi_PyInt_FromLongLong(wsgi_total_requests);
    PyDict_SetItemString(vars, "mod_wsgi.total_requests", value);
    Py_DECREF(value);

    thread_handle = wsgi_thread_info(1, 1);

    value = wsgi_PyInt_FromLong(thread_handle->thread_id);
    PyDict_SetItemString(vars, "mod_wsgi.thread_id", value);
    Py_DECREF(value);

    value = wsgi_PyInt_FromLongLong(thread_handle->request_count);
    PyDict_SetItemString(vars, "mod_wsgi.thread_requests", value);
    Py_DECREF(value);

    /* Publish event for the start of the request. */

    start_usage.user_time = 0.0;
    start_usage.system_time = 0.0;

    if (wsgi_event_subscribers()) {
        wsgi_thread_cpu_usage(&start_usage);

        event = PyDict_New();

#if AP_MODULE_MAGIC_AT_LEAST(20100923,2)
        if (self->r->log_id) {
#if PY_MAJOR_VERSION >= 3
	    value = PyUnicode_DecodeLatin1(self->r->log_id,
                                           strlen(self->r->log_id), NULL);
#else
	    value = PyString_FromString(self->r->log_id);
#endif
            PyDict_SetItemString(event, "request_id", value);
            Py_DECREF(value);
        }
#endif

        value = wsgi_PyInt_FromLong(thread_handle->thread_id);
        PyDict_SetItemString(event, "thread_id", value);
        Py_DECREF(value);

        value = wsgi_PyInt_FromLong(self->config->daemon_connects);
        PyDict_SetItemString(event, "daemon_connects", value);
        Py_DECREF(value);

        value = wsgi_PyInt_FromLong(self->config->daemon_restarts);
        PyDict_SetItemString(event, "daemon_restarts", value);
        Py_DECREF(value);

        value = PyFloat_FromDouble(apr_time_sec(
                                   (double)self->config->request_start));
        PyDict_SetItemString(event, "request_start", value);
        Py_DECREF(value);

        value = PyFloat_FromDouble(apr_time_sec(
                                   (double)self->config->queue_start));
        PyDict_SetItemString(event, "queue_start", value);
        Py_DECREF(value);

        value = PyFloat_FromDouble(apr_time_sec(
                                   (double)self->config->daemon_start));
        PyDict_SetItemString(event, "daemon_start", value);
        Py_DECREF(value);

        PyDict_SetItemString(event, "application_object", object);

        PyDict_SetItemString(event, "request_environ", vars);

        value = PyFloat_FromDouble(apr_time_sec((double)self->start_time));
        PyDict_SetItemString(event, "application_start", value);
        Py_DECREF(value);

        PyDict_SetItemString(event, "request_data", thread_handle->request_data);

        wsgi_publish_event("request_started", event);

        evwrapper = PyDict_GetItemString(event, "application_object");

        if (evwrapper) {
            if (evwrapper != object) {
                Py_INCREF(evwrapper);
                object = evwrapper;
            }
            else
                evwrapper = NULL;
        }

        Py_DECREF(event);
    }

    /* Pass the request through to the WSGI application. */

    thread_handle->request_count++;

    start = PyObject_GetAttrString((PyObject *)self, "start_response");

    args = Py_BuildValue("(OO)", vars, start);

    self->sequence = PyEval_CallObject(object, args);

    if (self->sequence != NULL) {
        if (!Adapter_process_file_wrapper(self)) {
            iterator = PyObject_GetIter(self->sequence);

            if (iterator != NULL) {
                PyObject *item = NULL;

                while ((item = PyIter_Next(iterator))) {
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

                    if (length && !Adapter_output(self, msg, length,
                                item, 0)) {
                        if (!PyErr_Occurred())
                            aborted = 1;
                        Py_DECREF(item);
                        break;
                    }

                    Py_DECREF(item);
                }
            }

            if (!PyErr_Occurred()) {
                if (!aborted) {
                    /*
                     * In the case where the response was empty we
                     * need to ensure we explicitly flush out the
                     * headers. This is done by calling the output
                     * routine but with an empty string as content.
                     * This could be gated on whether any content
                     * had already been sent, but easier to just call
                     * it all the time.
                     */

                    if (Adapter_output(self, "", 0, NULL, 0))
                        self->result = OK;
                }
                else {
                    /*
                     * If the client connection was already marked
                     * as aborted, then it indicates the client has
                     * closed the connection. In this case mark the
                     * final result as okay rather than an error so
                     * that the access log still records the original
                     * HTTP response code for the request rather than
                     * overriding it. If don't do this then access
                     * log will show 500 when the WSGI application
                     * itself had run fine.
                     */

                    self->result = OK;
                }
            }

            Py_XDECREF(iterator);
        }

        /*
         * Log warning if more response content generated than was
         * indicated, or less, if there was no errors generated by
         * the application and connection wasn't aborted.
         */

        if (self->content_length_set && ((!PyErr_Occurred() && !aborted &&
            self->output_length != self->content_length) ||
            (self->output_length > self->content_length))) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, self->r,
                          "mod_wsgi (pid=%d): Content length mismatch, "
                          "expected %s, response generated %s: %s", getpid(),
                          apr_off_t_toa(self->r->pool, self->content_length),
                          apr_off_t_toa(self->r->pool, self->output_length),
                          self->r->filename);
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

            wsgi_log_python_error(self->r, self->log, self->r->filename, 1);

            /*
             * If response content is being chunked and an error
             * occurred, we need to prevent the sending of the EOS
             * bucket so a client is able to detect that the the
             * response was incomplete.
             */

            if (self->r->chunked)
                self->r->eos_sent = 1;
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
            wsgi_log_python_error(self->r, self->log, self->r->filename, 1);
    }
    else
        wsgi_log_python_error(self->r, self->log, self->r->filename, 1);

    /* Publish event for the end of the request. */

    if (wsgi_event_subscribers()) {
        double application_time = 0.0;
        double output_time = 0.0;

        event = PyDict_New();

#if AP_MODULE_MAGIC_AT_LEAST(20100923,2)
        if (self->r->log_id) {
#if PY_MAJOR_VERSION >= 3
	    value = PyUnicode_DecodeLatin1(self->r->log_id,
                                           strlen(self->r->log_id), NULL);
#else
	    value = PyString_FromString(self->r->log_id);
#endif
            PyDict_SetItemString(event, "request_id", value);
            Py_DECREF(value);
        }
#endif

        value = wsgi_PyInt_FromLongLong(self->input->reads);
        PyDict_SetItemString(event, "input_reads", value);
        Py_DECREF(value);

        value = wsgi_PyInt_FromLongLong(self->input->bytes);
        PyDict_SetItemString(event, "input_length", value);
        Py_DECREF(value);

        value = PyFloat_FromDouble(apr_time_sec((double)self->input->time));
        PyDict_SetItemString(event, "input_time", value);
        Py_DECREF(value);

        value = wsgi_PyInt_FromLongLong(self->output_length);
        PyDict_SetItemString(event, "output_length", value);
        Py_DECREF(value);

        value = wsgi_PyInt_FromLongLong(self->output_writes);
        PyDict_SetItemString(event, "output_writes", value);
        Py_DECREF(value);

        output_time = apr_time_sec((double)self->output_time);

        if (output_time < 0.0)
            output_time = 0.0;

        finish_time = apr_time_now();

        application_time = apr_time_sec((double)finish_time-self->start_time);

        if (application_time < 0.0)
            application_time = 0.0;

        if (start_usage.user_time != 0.0) {
            if (wsgi_thread_cpu_usage(&end_usage)) {
                double user_seconds;
                double system_seconds;
                double total_seconds;

                user_seconds = end_usage.user_time;
                user_seconds -= start_usage.user_time;

                if (user_seconds < 0.0)
                    user_seconds = 0.0;

                system_seconds = end_usage.system_time;
                system_seconds -= start_usage.system_time;

                if (system_seconds < 0.0)
                    system_seconds = 0.0;

                total_seconds = user_seconds + system_seconds;

                if (total_seconds && total_seconds > application_time) {
                    user_seconds = (user_seconds/total_seconds)*application_time;
                    system_seconds = application_time - user_seconds;
                }

                value = PyFloat_FromDouble(user_seconds);
                PyDict_SetItemString(event, "cpu_user_time", value);
                Py_DECREF(value);

                value = PyFloat_FromDouble(system_seconds);
                PyDict_SetItemString(event, "cpu_system_time", value);
                Py_DECREF(value);
            }
        }

        value = PyFloat_FromDouble(output_time);
        PyDict_SetItemString(event, "output_time", value);
        Py_DECREF(value);

        value = PyFloat_FromDouble(apr_time_sec((double)finish_time));
        PyDict_SetItemString(event, "application_finish", value);
        Py_DECREF(value);

        value = PyFloat_FromDouble(application_time);
        PyDict_SetItemString(event, "application_time", value);
        Py_DECREF(value);

        PyDict_SetItemString(event, "request_data", thread_handle->request_data);

        wsgi_publish_event("request_finished", event);

        Py_DECREF(event);
    }

    /*
     * If result indicates an internal server error, then
     * replace the status line in the request object else
     * that provided by the application will be what is used
     * in any error page automatically generated by Apache.
     */

    if (self->result == HTTP_INTERNAL_SERVER_ERROR)
        self->r->status_line = "500 Internal Server Error";

    Py_DECREF(args);
    Py_DECREF(start);
    Py_DECREF(vars);

    Py_XDECREF(nrwrapper);
    Py_XDECREF(evwrapper);

    Py_XDECREF(self->sequence);
    self->sequence = NULL;

    return self->result;
}

static PyObject *Adapter_write(AdapterObject *self, PyObject *args)
{
    PyObject *item = NULL;
    const char *data = NULL;
    long length = 0;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:write", &item))
        return NULL;

    if (!PyString_Check(item)) {
        PyErr_Format(PyExc_TypeError, "byte string value expected, value "
                     "of type %.200s found", item->ob_type->tp_name);
        return NULL;
    }

    data = PyString_AsString(item);
    length = PyString_Size(item);

    if (!Adapter_output(self, data, length, item, 1)) {
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *Adapter_ssl_is_https(AdapterObject *self, PyObject *args)
{
    APR_OPTIONAL_FN_TYPE(ssl_is_https) *ssl_is_https = 0;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, ":ssl_is_https"))
        return NULL;

    ssl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

    if (ssl_is_https == 0)
      return Py_BuildValue("i", 0);

    return Py_BuildValue("i", ssl_is_https(self->r->connection));
}

static PyObject *Adapter_ssl_var_lookup(AdapterObject *self, PyObject *args)
{
    APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *ssl_var_lookup = 0;

    PyObject *item = NULL;
    PyObject *latin_item = NULL;

    char *name = 0;
    char *value = 0;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:ssl_var_lookup", &item))
        return NULL;

#if PY_MAJOR_VERSION >= 3
    if (PyUnicode_Check(item)) {
        latin_item = PyUnicode_AsLatin1String(item);
        if (!latin_item) {
            PyErr_Format(PyExc_TypeError, "byte string value expected, "
                         "value containing non 'latin-1' characters found");

            return NULL;
        }

        item = latin_item;
    }
#endif

    if (!PyString_Check(item)) {
        PyErr_Format(PyExc_TypeError, "byte string value expected, value "
                     "of type %.200s found", item->ob_type->tp_name);

        Py_XDECREF(latin_item);

        return NULL;
    }

    name = PyString_AsString(item);

    ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);

    if (ssl_var_lookup == 0)
    {
        Py_XDECREF(latin_item);

        Py_INCREF(Py_None);

        return Py_None;
    }

    value = ssl_var_lookup(self->r->pool, self->r->server,
                           self->r->connection, self->r, name);

    Py_XDECREF(latin_item);

    if (!value) {
        Py_INCREF(Py_None);

        return Py_None;
    }

#if PY_MAJOR_VERSION >= 3
    return PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    return PyString_FromString(value);
#endif
}

static PyMethodDef Adapter_methods[] = {
    { "start_response", (PyCFunction)Adapter_start_response, METH_VARARGS, 0 },
    { "write",          (PyCFunction)Adapter_write, METH_VARARGS, 0 },
    { "ssl_is_https",   (PyCFunction)Adapter_ssl_is_https, METH_VARARGS, 0 },
    { "ssl_var_lookup", (PyCFunction)Adapter_ssl_var_lookup, METH_VARARGS, 0 },
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

/*
 * Code for importing a module from source by absolute path.
 */

static PyObject *wsgi_load_source(apr_pool_t *pool, request_rec *r,
                                  const char *name, int exists,
                                  const char* filename,
                                  const char *process_group,
                                  const char *application_group,
                                  int ignore_system_exit)
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
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "mod_wsgi (pid=%d, process='%s', application='%s'): "
                          "Reloading WSGI script '%s'.", getpid(),
                          process_group, application_group, filename);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                         "mod_wsgi (pid=%d, process='%s', application='%s'): "
                         "Reloading WSGI script '%s'.", getpid(),
                         process_group, application_group, filename);
        }
        Py_END_ALLOW_THREADS
    }
    else {
        Py_BEGIN_ALLOW_THREADS
        if (r) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "mod_wsgi (pid=%d, process='%s', application='%s'): "
                          "Loading Python script file '%s'.", getpid(),
                          process_group, application_group, filename);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                         "mod_wsgi (pid=%d, process='%s', application='%s'): "
                         "Loading Python script file '%s'.", getpid(),
                         process_group, application_group, filename);
        }
        Py_END_ALLOW_THREADS
    }

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
    if (wsgi_utf8_to_unicode_path(wfilename, sizeof(wfilename) /
                                  sizeof(apr_wchar_t), filename)) {

        Py_BEGIN_ALLOW_THREADS
        if (r) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_wsgi (pid=%d, process='%s', "
                          "application='%s'): Failed to convert '%s' "
                          "to UCS2 filename.", getpid(),
                          process_group, application_group, filename);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                         "mod_wsgi (pid=%d, process='%s', "
                         "application='%s'): Failed to convert '%s' "
                         "to UCS2 filename.", getpid(),
                         process_group, application_group, filename);
        }
        Py_END_ALLOW_THREADS
        return NULL;
    }

    fp = _wfopen(wfilename, L"r");
#else
    fp = fopen(filename, "r");
#endif

    if (!fp) {
        Py_BEGIN_ALLOW_THREADS
        if (r) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
                          "mod_wsgi (pid=%d, process='%s', application='%s'): "
                          "Call to fopen() failed for '%s'.", getpid(),
                          process_group, application_group, filename);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR, errno, wsgi_server,
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
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_wsgi (pid=%d, process='%s', application='%s'): "
                          "Failed to parse Python script file '%s'.", getpid(),
                          process_group, application_group, filename);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                         "mod_wsgi (pid=%d, process='%s', application='%s'): "
                         "Failed to parse Python script file '%s'.", getpid(),
                         process_group, application_group, filename);
        }
        Py_END_ALLOW_THREADS

        wsgi_log_python_error(r, NULL, filename, 0);

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
            apr_finfo_t finfo;
            if (apr_stat(&finfo, filename, APR_FINFO_NORM,
                         pool) != APR_SUCCESS) {
                object = PyLong_FromLongLong(0);
            }
            else {
                object = PyLong_FromLongLong(finfo.mtime);
            }
        }
        else {
            object = PyLong_FromLongLong(r->finfo.mtime);
        }
        PyModule_AddObject(m, "__mtime__", object);
    }
    else {
        if (PyErr_ExceptionMatches(PyExc_SystemExit)) {
            if (!ignore_system_exit) {
                Py_BEGIN_ALLOW_THREADS
                if (r) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "mod_wsgi (pid=%d): SystemExit exception "
                                  "raised when doing exec of Python script "
                                  "file '%s'.", getpid(), filename);
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): SystemExit exception "
                                 "raised when doing exec of Python script "
                                 "file '%s'.", getpid(), filename);
                }
                Py_END_ALLOW_THREADS
            }
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            if (r) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "mod_wsgi (pid=%d): Failed to exec Python script "
                              "file '%s'.", getpid(), filename);
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Failed to exec Python script "
                             "file '%s'.", getpid(), filename);
            }
            Py_END_ALLOW_THREADS

            wsgi_log_python_error(r, NULL, filename, 0);
        }
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
            apr_finfo_t finfo;
            if (apr_stat(&finfo, filename, APR_FINFO_NORM,
                         pool) != APR_SUCCESS) {
                return 1;
            }
            else if (mtime != finfo.mtime) {
                return 1;
            }
        }
        else {
            if (mtime != r->finfo.mtime)
                return 1;
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
                wsgi_log_python_error(r, NULL, filename, 0);

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

#if APR_HAS_THREADS
static apr_thread_mutex_t* wsgi_module_lock = NULL;
#endif

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

    WSGIThreadInfo *thread_info = NULL;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    interp = wsgi_acquire_interpreter(config->application_group);

    if (!interp) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                      "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                      getpid(), config->application_group);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Setup startup timeout if first request and specified. */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process) {
        if (wsgi_startup_shutdown_time == 0) {
            if (wsgi_startup_timeout > 0) {
                apr_thread_mutex_lock(wsgi_monitor_lock);
                wsgi_startup_shutdown_time = apr_time_now();
                wsgi_startup_shutdown_time += wsgi_startup_timeout;
                apr_thread_mutex_unlock(wsgi_monitor_lock);
            }
        }
    }
#endif

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

    /* Calculate the Python module name to be used for script. */

    if (config->handler_script && *config->handler_script) {
        script = config->handler_script;

#if 0
        /*
         * Check for whether a module reference is provided
         * as opposed to a filesystem path.
         */

        if (strlen(script) > 2 && script[0] == '(' &&
            script[strlen(script)-1] == ')') {
            name = apr_pstrndup(r->pool, script+1, strlen(script)-2);

            module = PyImport_ImportModule(name);

            if (!module) {
                Py_BEGIN_ALLOW_THREADS
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                             "mod_wsgi (pid=%d): Failed to import handler "
                             "via Python module reference %s.", getpid(),
                             script);
                Py_END_ALLOW_THREADS

                wsgi_log_python_error(r, NULL, r->filename, 0);
            }
        }
#endif
    }
    else
        script = r->filename;

    if (!module) {
        name = wsgi_module_name(r->pool, script);

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
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                                 "mod_wsgi (pid=%d): Force restart of "
                                 "process '%s'.", getpid(),
                                 config->process_group);
                    Py_END_ALLOW_THREADS

#if APR_HAS_THREADS
                    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

                    wsgi_release_interpreter(interp);

                    r->status = HTTP_INTERNAL_SERVER_ERROR;
                    r->status_line = "200 Rejected";

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

        const char *data = "Status: 200 Continue\r\n\r\n";
        long length = strlen(data);

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

    /* Setup metrics for start of request. */

    thread_info = wsgi_start_request(r);

    /* Load module if not already loaded. */

    if (!module) {
        module = wsgi_load_source(r->pool, r, name, exists, script,
                                  config->process_group,
                                  config->application_group, 0);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /*
     * Clear startup timeout and prevent from running again if the
     * module was successfully loaded.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (module && wsgi_startup_shutdown_time > 0) {
        wsgi_startup_shutdown_time = -1;
    }
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

                Py_INCREF(adapter->log_buffer);
                thread_info->log_buffer = adapter->log_buffer;

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

                Input_finish(adapter->input);

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

                Py_CLEAR(thread_info->log_buffer);

                adapter->bb = NULL;
            }

            Py_XDECREF((PyObject *)adapter);
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_wsgi (pid=%d): Target WSGI script '%s' does "
                          "not contain WSGI application '%s'.",
                          getpid(), script, config->callable_object);
            Py_END_ALLOW_THREADS

            status = HTTP_NOT_FOUND;
        }
    }

    /* Log any details of exceptions if execution failed. */

    if (PyErr_Occurred())
        wsgi_log_python_error(r, NULL, r->filename, 0);

    Py_XDECREF(module);

    /* Finalise any metrics at end of the request. */

    wsgi_end_request();

    /* Cleanup and release interpreter, */

    wsgi_release_interpreter(interp);

    return status;
}

/*
 * Apache child process initialisation and cleanup. Initialise
 * global table containing Python interpreter instances and
 * cache reference to main interpreter. Also register cleanup
 * function to delete interpreter on process shutdown.
 */

static apr_status_t wsgi_python_child_cleanup(void *data)
{
    PyObject *interp = NULL;

    /*
     * If not a daemon process need to publish that process
     * is shutting down here. For daemon we did it earlier
     * before trying to wait on request threads.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (!wsgi_daemon_process)
        wsgi_publish_process_stopping(wsgi_shutdown_reason);
#else
    wsgi_publish_process_stopping(wsgi_shutdown_reason);
#endif

    /* In a multithreaded MPM must protect table. */

#if APR_HAS_THREADS
    apr_thread_mutex_lock(wsgi_interp_lock);
#endif

    /*
     * We should be executing in the main thread again at this
     * point but without the GIL, so simply restore the original
     * thread state for that thread that we remembered when we
     * initialised the interpreter.
     */

    PyEval_AcquireThread(wsgi_main_tstate);

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

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
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

    /*
     * The code which performs actual shutdown of the main
     * interpreter expects to be called without the GIL, so
     * we release it here again.
     */

    PyEval_ReleaseThread(wsgi_main_tstate);

    /*
     * Destroy Python itself including the main interpreter.
     * If mod_python is being loaded it is left to mod_python to
     * destroy Python, although it currently doesn't do so.
     */

    if (wsgi_python_initialized)
        wsgi_python_term();

    return APR_SUCCESS;
}

static void wsgi_python_child_init(apr_pool_t *p)
{
    PyGILState_STATE state;
    PyObject *object = NULL;

    int ignore_system_exit = 0;

    /* Working with Python, so must acquire GIL. */

    state = PyGILState_Ensure();

    /*
     * Trigger any special Python stuff required after a fork.
     * Only do this though if we were responsible for the
     * initialisation of the Python interpreter in the first
     * place to avoid it being done multiple times. Also only
     * do it if Python was initialised in parent process.
     */

#ifdef HAVE_FORK
    if (wsgi_python_initialized && !wsgi_python_after_fork) {
#if PY_MAJOR_VERSION > 3 || (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 7)
        PyOS_AfterFork_Child();
#else
        PyOS_AfterFork();
#endif
    }
#endif

    /* Finalise any Python objects required by child process. */

    PyType_Ready(&Log_Type);
    PyType_Ready(&Stream_Type);
    PyType_Ready(&Input_Type);
    PyType_Ready(&Adapter_Type);
    PyType_Ready(&Restricted_Type);
    PyType_Ready(&Interpreter_Type);
    PyType_Ready(&Dispatch_Type);
    PyType_Ready(&Auth_Type);

    PyType_Ready(&SignalIntercept_Type);

#if PY_MAJOR_VERSION > 3 || (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 4)
    PyType_Ready(&ShutdownInterpreter_Type);
#endif

    /* Initialise Python interpreter instance table and lock. */

    wsgi_interpreters = PyDict_New();

#if APR_HAS_THREADS
    apr_thread_mutex_create(&wsgi_interp_lock, APR_THREAD_MUTEX_UNNESTED, p);
    apr_thread_mutex_create(&wsgi_module_lock, APR_THREAD_MUTEX_UNNESTED, p);
    apr_thread_mutex_create(&wsgi_shutdown_lock, APR_THREAD_MUTEX_UNNESTED, p);
#endif

    /*
     * Create an interpreters index using Apache data structure so
     * can iterate over interpreter names without needing Python GIL.
     */

    wsgi_interpreters_index = apr_hash_make(p);

    /*
     * Initialise the key for data related to a thread and force
     * creation of thread info.
     */

    apr_threadkey_private_create(&wsgi_thread_key, NULL, p);

    wsgi_thread_info(1, 0);

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

    apr_hash_set(wsgi_interpreters_index, "", APR_HASH_KEY_STRING, "");

    /* Restore the prior thread state and release the GIL. */

    PyGILState_Release(state);

    /* Register cleanups to performed on process shutdown. */

    apr_pool_cleanup_register(p, NULL, wsgi_python_child_cleanup,
                              apr_pool_cleanup_null);

    /* Loop through import scripts for this process and load them. */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process && wsgi_daemon_process->group->threads == 0)
        ignore_system_exit = 1;
#endif

    if (wsgi_import_list) {
        apr_array_header_t *scripts = NULL;

        WSGIScriptFile *entries;
        WSGIScriptFile *entry;

        int i;

        scripts = wsgi_import_list;
        entries = (WSGIScriptFile *)scripts->elts;

        for (i = 0; i < scripts->nelts; ++i) {
            entry = &entries[i];

            /*
             * Stop loading scripts if this is a daemon process and
             * we have already been flagged to be shutdown.
             */

            if (wsgi_daemon_shutdown)
                break;

            if (!strcmp(wsgi_daemon_group, entry->process_group)) {
                InterpreterObject *interp = NULL;
                PyObject *modules = NULL;
                PyObject *module = NULL;
                char *name = NULL;
                int exists = 0;

                interp = wsgi_acquire_interpreter(entry->application_group);

                if (!interp) {
                    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, wsgi_server,
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
                                              entry->application_group,
                                              ignore_system_exit);

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

        if (!strcmp(option, "application-group")) {
            if (!*value)
                return "Invalid name for WSGI application group.";

            if (!strcmp(value, "%{GLOBAL}"))
                value = "";

            application_group = value;
        }
#if defined(MOD_WSGI_WITH_DAEMONS)
        else if (!strcmp(option, "process-group")) {
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

    /*
     * Only add to import list if both process group and application
     * group are specified, that they don't include substitution values,
     * and in the case of WSGIScriptAliasMatch, that the WSGI script
     * target path doesn't include substitutions from URL pattern.
     */

    if (process_group && application_group &&
        !strstr(process_group, "%{") &&
        !strstr(application_group, "%{") &&
        (!cmd->info || !strstr(a, "$"))) {

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
        if (*object->process_group &&
            strcmp(object->process_group, "%{RESOURCE}") != 0 &&
            strcmp(object->process_group, "%{SERVER}") != 0 &&
            strcmp(object->process_group, "%{HOST}") != 0) {

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

            if (cmd->server->server_hostname &&
                group->server->server_hostname &&
                strcmp(cmd->server->server_hostname,
                group->server->server_hostname) &&
                group->server->is_virtual) {

                return "WSGI process group not accessible.";
            }

            if (!cmd->server->server_hostname &&
                group->server->server_hostname &&
                group->server->is_virtual) {

                return "WSGI process group not matchable.";
            }

            if (cmd->server->server_hostname &&
                !group->server->server_hostname &&
                group->server->is_virtual) {

                return "WSGI process group not matchable.";
            }
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

#if PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 6
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
#endif

#if (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 3) || \
    (PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 6)
static const char *wsgi_set_dont_write_bytecode(cmd_parms *cmd, void *mconfig,
                                                const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->dont_write_bytecode = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->dont_write_bytecode = 1;
    else
        return "WSGIDontWriteBytecode must be one of: Off | On";

    return NULL;
}
#endif

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

static const char *wsgi_set_python_hash_seed(cmd_parms *cmd, void *mconfig,
                                             const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    /*
     * Must check this here because if we don't and is wrong, then
     * Python interpreter will check later and may kill the process.
     */

    if (f && *f != '\0' && strcmp(f, "random") != 0) {
        const char *endptr = f;
        unsigned long seed;

        seed = PyOS_strtoul((char *)f, (char **)&endptr, 10);

        if (*endptr != '\0' || seed > 4294967295UL
                || (errno == ERANGE && seed == ULONG_MAX))
        {
            return "WSGIPythonHashSeed must be \"random\" or an integer "
                              "in range [0; 4294967295]";
        }
    }

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->python_hash_seed = f;

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

        if (cmd->server->server_hostname &&
            group->server->server_hostname &&
            strcmp(cmd->server->server_hostname,
            group->server->server_hostname) &&
            group->server->is_virtual) {

            return "WSGI process group not accessible.";
        }

        if (!cmd->server->server_hostname &&
            group->server->server_hostname &&
            group->server->is_virtual) {

            return "WSGI process group not matchable.";
        }

        if (cmd->server->server_hostname &&
            !group->server->server_hostname &&
            group->server->is_virtual) {

            return "WSGI process group not matchable.";
        }
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

static const char *wsgi_set_map_head_to_get(cmd_parms *cmd, void *mconfig,
                                            const char *f)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->map_head_to_get = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->map_head_to_get = 1;
        else if (strcasecmp(f, "Auto") == 0)
            dconfig->map_head_to_get = 2;
        else
            return "WSGIMapHEADToGET must be one of: Off | On | Auto";
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->map_head_to_get = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->map_head_to_get = 1;
        else if (strcasecmp(f, "Auto") == 0)
            sconfig->map_head_to_get = 2;
        else
            return "WSGIMapHEADToGET must be one of: Off | On | Auto";
    }

    return NULL;
}

static const char *wsgi_set_ignore_activity(cmd_parms *cmd, void *mconfig,
                                            const char *f)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->ignore_activity = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->ignore_activity = 1;
        else
            return "WSGIIgnoreActivity must be one of: Off | On";
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->ignore_activity = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->ignore_activity = 1;
        else
            return "WSGIIgnoreActivity must be one of: Off | On";
    }

    return NULL;
}

static char *wsgi_http2env(apr_pool_t *a, const char *w);

static const char *wsgi_set_trusted_proxy_headers(cmd_parms *cmd,
                                                  void *mconfig,
                                                  const char *args)
{
    apr_array_header_t *headers = NULL;

    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (!dconfig->trusted_proxy_headers) {
            headers = apr_array_make(cmd->pool, 3, sizeof(char*));
            dconfig->trusted_proxy_headers = headers;
        }
        else
            headers = dconfig->trusted_proxy_headers;
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (!sconfig->trusted_proxy_headers) {
            headers = apr_array_make(cmd->pool, 3, sizeof(char*));
            sconfig->trusted_proxy_headers = headers;
        }
        else
            headers = sconfig->trusted_proxy_headers;
    }

    while (*args) {
        const char **entry = NULL;

        entry = (const char **)apr_array_push(headers);
        *entry = wsgi_http2env(cmd->pool, ap_getword_conf(cmd->pool, &args));
    }

    return NULL;
}

static int wsgi_looks_like_ip(const char *ip) {
    static const char ipv4_set[] = "0123456789./";
    static const char ipv6_set[] = "0123456789abcdef:/";

    const char *ptr;

    /* Zero length value is not valid. */

    if (!*ip)
      return 0;

    /* Determine if this could be a IPv6 or IPv4 address. */

    ptr = ip;

    if (strchr(ip, ':')) {
        while(*ptr && strchr(ipv6_set, *ptr) != NULL)
            ++ptr;
    }
    else {
        while(*ptr && strchr(ipv4_set, *ptr) != NULL)
            ++ptr;
    }

    return (*ptr == '\0');
}

static const char *wsgi_set_trusted_proxies(cmd_parms *cmd,
                                              void *mconfig, const char *args)
{
    apr_array_header_t *proxy_ips = NULL;

    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (!dconfig->trusted_proxies) {
            proxy_ips = apr_array_make(cmd->pool, 3, sizeof(char*));
            dconfig->trusted_proxies = proxy_ips;
        }
        else
            proxy_ips = dconfig->trusted_proxies;
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (!sconfig->trusted_proxies) {
            proxy_ips = apr_array_make(cmd->pool, 3, sizeof(char*));
            sconfig->trusted_proxies = proxy_ips;
        }
        else
            proxy_ips = sconfig->trusted_proxies;
    }

    while (*args) {
        const char *proxy_ip;

        proxy_ip = ap_getword_conf(cmd->pool, &args);

        if (wsgi_looks_like_ip(proxy_ip)) {
            char *ip;
            char *mask;
            apr_ipsubnet_t **sub;
            apr_status_t rv;

            ip = apr_pstrdup(cmd->temp_pool, proxy_ip);

            if ((mask = ap_strchr(ip, '/')))
                *mask++ = '\0';

            sub = (apr_ipsubnet_t **)apr_array_push(proxy_ips);

            rv = apr_ipsubnet_create(sub, ip, mask, cmd->pool);

            if (rv != APR_SUCCESS) {
                char msgbuf[128];
                apr_strerror(rv, msgbuf, sizeof(msgbuf));

                return apr_pstrcat(cmd->pool, "Unable to parse trusted "
                                   "proxy IP address/subnet of \"", proxy_ip,
                                   "\". ", msgbuf, NULL);
            }
        }
        else {
            return apr_pstrcat(cmd->pool, "Unable to parse trusted proxy "
                               "IP address/subnet of \"", proxy_ip, "\".",
                               NULL);
        }
    }

    return NULL;
}

static const char *wsgi_set_enable_sendfile(cmd_parms *cmd, void *mconfig,
                                            const char *f)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->enable_sendfile = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->enable_sendfile = 1;
        else
            return "WSGIEnableSendfile must be one of: Off | On";
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->enable_sendfile = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->enable_sendfile = 1;
        else
            return "WSGIEnableSendfile must be one of: Off | On";
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

#if !defined(MOD_WSGI_WITH_AUTHN_PROVIDER)
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
#endif

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

static const char *wsgi_add_handler_script(cmd_parms *cmd, void *mconfig,
                                           const char *args)
{
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

static const char *wsgi_set_server_metrics(cmd_parms *cmd, void *mconfig,
                                           const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->server_metrics = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->server_metrics = 1;
    else
        return "WSGIServerMetrics must be one of: Off | On";

    return NULL;
}

static const char *wsgi_set_newrelic_config_file(
        cmd_parms *cmd, void *mconfig, const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->newrelic_config_file = f;

    return NULL;
}

static const char *wsgi_set_newrelic_environment(
        cmd_parms *cmd, void *mconfig, const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->newrelic_environment = f;

    return NULL;
}

/* Handler for the translate name phase. */

static long wsgi_alias_matches(const char *uri, const char *alias_fakename)
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
        long l = 0;

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

static void wsgi_drop_invalid_headers(request_rec *r);
static void wsgi_process_proxy_headers(request_rec *r);

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

    /*
     * Remove any invalid headers which use invalid characters.
     * This is necessary to ensure that someone doesn't try and
     * take advantage of header spoofing. This can come about
     * where characters other than alphanumerics or '-' are used
     * as the conversion of non alphanumerics to '_' means one
     * can get collisions. This is technically only an issue
     * with Apache 2.2 as Apache 2.4 addresses the problem and
     * drops them anyway. Still go through and drop them even
     * for Apache 2.4 as not sure which version of Apache 2.4
     * introduces the change.
     */

    wsgi_drop_invalid_headers(r);

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
     *
     * The default behaviour here of changing it if an output
     * filter is detected can be overridden using the directive
     * WSGIMapHEADToGet. The default value is 'Auto'. If set to
     * 'On' then it remapped regardless of whether an output
     * filter is present. If 'Off' then it will be left alone
     * and the original value used.
     */

    if (config->map_head_to_get == 2) {
        if (r->method_number == M_GET && r->header_only &&
            r->output_filters->frec->ftype < AP_FTYPE_PROTOCOL)
            apr_table_setn(r->subprocess_env, "REQUEST_METHOD", "GET");
    }
    else if (config->map_head_to_get == 1) {
        if (r->method_number == M_GET)
            apr_table_setn(r->subprocess_env, "REQUEST_METHOD", "GET");
    }

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

    if (*script_name == '/') {
        while (*script_name && (*(script_name+1) == '/'))
            script_name++;
        script_name = apr_pstrdup(r->pool, script_name);
        ap_no2slash((char*)script_name);
        apr_table_setn(r->subprocess_env, "SCRIPT_NAME", script_name);
    }

    path_info = apr_table_get(r->subprocess_env, "PATH_INFO");

    if (*path_info == '/') {
        while (*path_info && (*(path_info+1) == '/'))
            path_info++;
        path_info = apr_pstrdup(r->pool, path_info);
        ap_no2slash((char*)path_info);
        apr_table_setn(r->subprocess_env, "PATH_INFO", path_info);
    }

    /*
     * Save away the SCRIPT_NAME and PATH_INFO values at this point
     * so we have a way of determining if they are rewritten somehow.
     * This can be important when dealing with rewrite rules and
     * a trusted header was being handled for SCRIPT_NAME.
     */

    apr_table_setn(r->subprocess_env, "mod_wsgi.script_name", script_name);
    apr_table_setn(r->subprocess_env, "mod_wsgi.path_info", path_info);

    /*
     * Perform fixups on environment based on trusted proxy headers
     * sent through from a front end proxy.
     */

    wsgi_process_proxy_headers(r);

    /*
     * Determine whether connection uses HTTPS protocol. This has
     * to be done after and fixups due to trusted proxy headers.
     */

    if (!wsgi_is_https)
        wsgi_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

    if (wsgi_is_https && wsgi_is_https(r->connection))
        apr_table_set(r->subprocess_env, "HTTPS", "1");

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

    apr_table_setn(r->subprocess_env, "mod_wsgi.enable_sendfile",
                   apr_psprintf(r->pool, "%d", config->enable_sendfile));
    apr_table_setn(r->subprocess_env, "mod_wsgi.ignore_activity",
                   apr_psprintf(r->pool, "%d", config->ignore_activity));

    apr_table_setn(r->subprocess_env, "mod_wsgi.request_start",
                   apr_psprintf(r->pool, "%" APR_TIME_T_FMT, r->request_time));

#if AP_MODULE_MAGIC_AT_LEAST(20100923,2)
    if (!r->log_id) {
        const char **id;

        /* Need to cast const away. */

        id = &((request_rec *)r)->log_id;

        ap_run_generate_log_id(c, r, id);
    }

    if (r->log_id)
        apr_table_setn(r->subprocess_env, "mod_wsgi.request_id", r->log_id);
    if (r->connection->log_id)
        apr_table_setn(r->subprocess_env, "mod_wsgi.connection_id",
                       r->connection->log_id);
#endif
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

    self->log = newLogObject(r, APLOG_ERR, NULL, 0);

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
#if (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 2) || \
    (PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 7)
        object = PyCapsule_New(self->r, 0, 0);
#else
        object = PyCObject_FromVoidPtr(self->r, 0);
#endif
        PyDict_SetItemString(vars, "apache.request_rec", object);
        Py_DECREF(object);
    }

    /*
     * Extensions for accessing SSL certificate information from
     * mod_ssl when in use.
     */

#if 0
    object = PyObject_GetAttrString((PyObject *)self, "ssl_is_https");
    PyDict_SetItemString(vars, "mod_ssl.is_https", object);
    Py_DECREF(object);

    object = PyObject_GetAttrString((PyObject *)self, "ssl_var_lookup");
    PyDict_SetItemString(vars, "mod_ssl.var_lookup", object);
    Py_DECREF(object);
#endif

    return vars;
}

static PyObject *Dispatch_ssl_is_https(DispatchObject *self, PyObject *args)
{
    APR_OPTIONAL_FN_TYPE(ssl_is_https) *ssl_is_https = 0;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, ":ssl_is_https"))
        return NULL;

    ssl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

    if (ssl_is_https == 0)
      return Py_BuildValue("i", 0);

    return Py_BuildValue("i", ssl_is_https(self->r->connection));
}

static PyObject *Dispatch_ssl_var_lookup(DispatchObject *self, PyObject *args)
{
    APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *ssl_var_lookup = 0;

    PyObject *item = NULL;

    char *name = 0;
    char *value = 0;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:ssl_var_lookup", &item))
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

    name = PyString_AsString(item);

    ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);

    if (ssl_var_lookup == 0)
    {
        Py_INCREF(Py_None);

        return Py_None;
    }

    value = ssl_var_lookup(self->r->pool, self->r->server,
                           self->r->connection, self->r, name);

    if (!value) {
        Py_INCREF(Py_None);

        return Py_None;
    }

#if PY_MAJOR_VERSION >= 3
    return PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    return PyString_FromString(value);
#endif
}

static PyMethodDef Dispatch_methods[] = {
    { "ssl_is_https",   (PyCFunction)Dispatch_ssl_is_https, METH_VARARGS, 0 },
    { "ssl_var_lookup", (PyCFunction)Dispatch_ssl_var_lookup, METH_VARARGS, 0 },
    { NULL, NULL}
};

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
    Dispatch_methods,       /*tp_methods*/
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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
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
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
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
        module = wsgi_load_source(r->pool, r, name, exists, script,
                                  "", group, 0);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Log any details of exceptions if import failed. */

    if (PyErr_Occurred())
        wsgi_log_python_error(r, NULL, script, 0);

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

                    /* Log any details of exceptions if execution failed. */

                    if (PyErr_Occurred())
                        wsgi_log_python_error(r, NULL, script, 0);
                }

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

                    /* Log any details of exceptions if execution failed. */

                    if (PyErr_Occurred())
                        wsgi_log_python_error(r, NULL, script, 0);
                }

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

                    /* Log any details of exceptions if execution failed. */

                    if (PyErr_Occurred())
                        wsgi_log_python_error(r, NULL, script, 0);
                }

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
                wsgi_log_python_error(r, NULL, script, 0);

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

    const char *tenc = NULL;
    const char *lenp = NULL;

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

        if (r->finfo.filetype == 0) {
            wsgi_log_script_error(r, "Target WSGI script not found or unable "
                                  "to stat", r->filename);
            return HTTP_NOT_FOUND;
        }

        if (r->finfo.filetype == APR_DIR) {
            wsgi_log_script_error(r, "Attempt to invoke directory as WSGI "
                                  "application", r->filename);
            return HTTP_FORBIDDEN;
        }

        if (wsgi_is_script_aliased(r)) {
            /*
             * Allow any configuration supplied through request notes to
             * override respective values. Request notes are used when
             * configuration supplied with WSGIScriptAlias directives.
             */

            if ((value = apr_table_get(r->notes, "mod_wsgi.process_group")))
                config->process_group = wsgi_process_group(r, value);
            if ((value = apr_table_get(r->notes, "mod_wsgi.application_group")))
                config->application_group = wsgi_application_group(r, value);
            if ((value = apr_table_get(r->notes, "mod_wsgi.callable_object")))
                config->callable_object = value;

            if ((value = apr_table_get(r->notes,
                                      "mod_wsgi.pass_authorization"))) {
                if (!strcmp(value, "1"))
                    config->pass_authorization = 1;
                else
                    config->pass_authorization = 0;
            }
        }
    }
#if 0
    else if (strstr(r->handler, "wsgi-handler=") == r->handler) {
        config->handler_script = apr_pstrcat(r->pool, r->handler+13, NULL);
        config->callable_object = "handle_request";
    }
#endif
    else if (config->handler_scripts) {
        WSGIScriptFile *entry;

        entry = (WSGIScriptFile *)apr_hash_get(config->handler_scripts,
                                               r->handler,
                                               APR_HASH_KEY_STRING);

        if (entry) {
            config->handler_script = entry->handler_script;
            config->callable_object = "handle_request";

            if ((value = entry->process_group))
                config->process_group = wsgi_process_group(r, value);
            if ((value = entry->application_group))
                config->application_group = wsgi_application_group(r, value);

            if ((value = entry->pass_authorization)) {
                if (!strcmp(value, "1"))
                    config->pass_authorization = 1;
                else
                    config->pass_authorization = 0;
            }
        }
        else
            return DECLINED;
    }
    else
        return DECLINED;

    /*
     * Honour AcceptPathInfo directive. Default behaviour is
     * accept additional path information.
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
     * Setup policy to apply if request contains a body. Note that the
     * WSGI specification doesn't strictly allow for chunked request
     * content as CONTENT_LENGTH is required when reading input and
     * an application isn't meant to read more than what is defined by
     * CONTENT_LENGTH. We still optionally allow chunked request content.
     * For an application to use the content, it has to ignore the WSGI
     * specification and use read() with no arguments to read all
     * available input, or call read() with specific block size until
     * read() returns an empty string.
     */

    tenc = apr_table_get(r->headers_in, "Transfer-Encoding");

    if (tenc) {
        /* Only chunked transfer encoding is supported. */

        if (strcasecmp(tenc, "chunked")) {
            wsgi_log_script_error(r, apr_psprintf(r->pool,
                    "Unexpected value for Transfer-Encoding of '%s' "
                    "supplied. Only 'chunked' supported.", tenc),
                    r->filename);
            return HTTP_NOT_IMPLEMENTED;
        }

        /* Only allow chunked requests when explicitly enabled. */

        if (!config->chunked_request) {
            wsgi_log_script_error(r, "Received request requiring chunked "
                    "transfer encoding, but optional support for chunked "
                    "transfer encoding has not been enabled.", r->filename);
            return HTTP_LENGTH_REQUIRED;
        }

        /*
         * When chunked transfer encoding is specified, there should
         * not be any content length specified.
         */

        if (lenp) {
            wsgi_log_script_error(r, "Unexpected Content-Length header "
                    "supplied where Transfer-Encoding was specified "
                    "as 'chunked'.", r->filename);
            return HTTP_BAD_REQUEST;
        }
    }

    /*
     * Check to see if the request content is too large if the
     * Content-Length header is defined then end the request here. We do
     * this as otherwise it will not be done until first time input data
     * is read in by the application. Problem is that underlying HTTP
     * output filter will also generate a 413 response and the error
     * raised from the application will be appended to that. The call to
     * ap_discard_request_body() is hopefully enough to trigger sending
     * of the 413 response by the HTTP filter.
     */

    lenp = apr_table_get(r->headers_in, "Content-Length");

    if (lenp) {
        char *endstr;
        apr_off_t length;

        if (wsgi_strtoff(&length, lenp, &endstr, 10)
            || *endstr || length < 0) {

            wsgi_log_script_error(r, apr_psprintf(r->pool,
                    "Invalid Content-Length header value of '%s' was "
                    "supplied.", lenp), r->filename);

            return HTTP_BAD_REQUEST;
        }

        limit = ap_get_limit_req_body(r);

        if (limit && limit < length) {
            ap_discard_request_body(r);
            return OK;
        }
    }

    /* Build the sub process environment. */

    config->request_start = r->request_time;

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
    long umask = -1;

    const char *root = NULL;
    const char *home = NULL;

    const char *lang = NULL;
    const char *locale = NULL;

    const char *python_home = NULL;
    const char *python_path = NULL;
    const char *python_eggs = NULL;

    int stack_size = 0;
    int maximum_requests = 0;
    int startup_timeout = 0;
    int shutdown_timeout = 5;
    int deadlock_timeout = 300;
    int inactivity_timeout = 0;
    int request_timeout = 0;
    int graceful_timeout = 0;
    int eviction_timeout = 0;
    int restart_interval = 0;
    int connect_timeout = 15;
    int socket_timeout = 0;
    int queue_timeout = 0;

    const char *socket_user = NULL;

    int listen_backlog = WSGI_LISTEN_BACKLOG;

    const char *display_name = NULL;

    int send_buffer_size = 0;
    int recv_buffer_size = 0;
    int header_buffer_size = 0;
    int response_buffer_size = 0;

    int response_socket_timeout = 0;

    const char *script_user = NULL;
    const char *script_group = NULL;

    int cpu_time_limit = 0;
    int cpu_priority = 0;

    apr_int64_t memory_limit = 0;
    apr_int64_t virtual_memory_limit = 0;

    uid_t uid;
    uid_t gid;

    const char *groups_list = NULL;
    int groups_count = 0;
    gid_t *groups = NULL;

    int server_metrics = 0;

    const char *newrelic_config_file = NULL;
    const char *newrelic_environment = NULL;

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
        else if (!strcmp(option, "supplementary-groups")) {
            groups_list = value;
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
            if (threads < 0 || threads >= WSGI_STACK_LAST-1)
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
        else if (!strcmp(option, "lang")) {
            lang = value;
        }
        else if (!strcmp(option, "locale")) {
            locale = value;
        }
        else if (!strcmp(option, "python-home")) {
            python_home = value;
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
        else if (!strcmp(option, "startup-timeout")) {
            if (!*value)
                return "Invalid startup timeout for WSGI daemon process.";

            startup_timeout = atoi(value);
            if (startup_timeout < 0)
                return "Invalid startup timeout for WSGI daemon process.";
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
        else if (!strcmp(option, "request-timeout")) {
            if (!*value)
                return "Invalid request timeout for WSGI daemon process.";

            request_timeout = atoi(value);
            if (request_timeout < 0)
                return "Invalid request timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "graceful-timeout")) {
            if (!*value)
                return "Invalid graceful timeout for WSGI daemon process.";

            graceful_timeout = atoi(value);
            if (graceful_timeout < 0)
                return "Invalid graceful timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "eviction-timeout")) {
            if (!*value)
                return "Invalid eviction timeout for WSGI daemon process.";

            eviction_timeout = atoi(value);
            if (eviction_timeout < 0)
                return "Invalid eviction timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "restart-interval")) {
            if (!*value)
                return "Invalid restart interval for WSGI daemon process.";

            restart_interval = atoi(value);
            if (restart_interval < 0)
                return "Invalid restart interval for WSGI daemon process.";
        }
        else if (!strcmp(option, "connect-timeout")) {
            if (!*value)
                return "Invalid connect timeout for WSGI daemon process.";

            connect_timeout = atoi(value);
            if (connect_timeout < 0)
                return "Invalid connect timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "socket-timeout")) {
            if (!*value)
                return "Invalid socket timeout for WSGI daemon process.";

            socket_timeout = atoi(value);
            if (socket_timeout < 0)
                return "Invalid socket timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "queue-timeout")) {
            if (!*value)
                return "Invalid queue timeout for WSGI daemon process.";

            queue_timeout = atoi(value);
            if (queue_timeout < 0)
                return "Invalid queue timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "listen-backlog")) {
            if (!*value)
                return "Invalid listen backlog for WSGI daemon process.";

            listen_backlog = atoi(value);
            if (listen_backlog < 0)
                return "Invalid listen backlog for WSGI daemon process.";
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
        else if (!strcmp(option, "header-buffer-size")) {
            if (!*value)
                return "Invalid header buffer size for WSGI daemon process.";

            header_buffer_size = atoi(value);
            if (header_buffer_size < 8192 && header_buffer_size != 0) {
                return "Header buffer size must be >= 8192 bytes, "
                       "or 0 for default.";
            }
        }
        else if (!strcmp(option, "response-buffer-size")) {
            if (!*value)
                return "Invalid response buffer size for WSGI daemon process.";

            response_buffer_size = atoi(value);
            if (response_buffer_size < 65536 && response_buffer_size != 0) {
                return "Response buffer size must be >= 65536 bytes, "
                       "or 0 for default.";
            }
        }
        else if (!strcmp(option, "response-socket-timeout")) {
            if (!*value)
                return "Invalid response socket timeout for WSGI daemon process.";

            response_socket_timeout = atoi(value);
            if (response_socket_timeout < 0)
                return "Invalid response socket timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "socket-user")) {
            uid_t socket_uid;

            if (!*value)
                return "Invalid socket user for WSGI daemon process.";

            socket_uid = ap_uname2id(value);

            if (*value == '#') {
                struct passwd *entry = NULL;

                if ((entry = getpwuid(socket_uid)) == NULL)
                    return "Couldn't determine user name from socket user.";

                value = entry->pw_name;
            }

            socket_user = value;
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
        else if (!strcmp(option, "memory-limit")) {
            if (!*value)
                return "Invalid memory limit for WSGI daemon process.";

            memory_limit = apr_atoi64(value);
            if (memory_limit < 0)
                return "Invalid memory limit for WSGI daemon process.";
        }
        else if (!strcmp(option, "virtual-memory-limit")) {
            if (!*value)
                return "Invalid virtual memory limit for WSGI daemon process.";

            virtual_memory_limit = apr_atoi64(value);
            if (virtual_memory_limit < 0)
                return "Invalid virtual memory limit for WSGI daemon process.";
        }
        else if (!strcmp(option, "server-metrics")) {
            if (!*value)
                return "Invalid server metrics flag for WSGI daemon process.";

            if (strcasecmp(value, "Off") == 0)
                server_metrics = 0;
            else if (strcasecmp(value, "On") == 0)
                server_metrics = 1;
            else
                return "Invalid server metrics flag for WSGI daemon process.";
        }
        else if (!strcmp(option, "newrelic-config-file")) {
            newrelic_config_file = value;
        }
        else if (!strcmp(option, "newrelic-environment")) {
            newrelic_environment = value;
        }
        else
            return "Invalid option to WSGI daemon process definition.";
    }

    if (script_user && script_group)
        return "Only one of script-user and script-group allowed.";

    if (groups_list) {
        const char *group_name = NULL;
        long groups_maximum = NGROUPS_MAX;
        const char *items = NULL;

#ifdef _SC_NGROUPS_MAX
        groups_maximum = sysconf(_SC_NGROUPS_MAX);
        if (groups_maximum < 0)
            groups_maximum = NGROUPS_MAX;
#endif
        groups = (gid_t *)apr_pcalloc(cmd->pool,
                                      groups_maximum*sizeof(groups[0]));

        groups[groups_count++] = gid;

        items = groups_list;
        group_name = ap_getword(cmd->pool, &items, ',');

        while (group_name && *group_name) {
            if (groups_count >= groups_maximum)
                return "Too many supplementary groups WSGI daemon process";

            groups[groups_count++] = ap_gname2id(group_name);
            group_name = ap_getword(cmd->pool, &items, ',');
        }
    }

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

    entry->groups_list = groups_list;
    entry->groups_count = groups_count;
    entry->groups = groups;

    entry->processes = processes;
    entry->multiprocess = multiprocess;
    entry->threads = threads;

    entry->umask = umask;
    entry->root = root;
    entry->home = home;

    entry->lang = lang;
    entry->locale = locale;

    entry->python_home = python_home;
    entry->python_path = python_path;
    entry->python_eggs = python_eggs;

    entry->stack_size = stack_size;
    entry->maximum_requests = maximum_requests;
    entry->shutdown_timeout = shutdown_timeout;
    entry->startup_timeout = apr_time_from_sec(startup_timeout);
    entry->deadlock_timeout = apr_time_from_sec(deadlock_timeout);
    entry->inactivity_timeout = apr_time_from_sec(inactivity_timeout);
    entry->request_timeout = apr_time_from_sec(request_timeout);
    entry->graceful_timeout = apr_time_from_sec(graceful_timeout);
    entry->eviction_timeout = apr_time_from_sec(eviction_timeout);
    entry->restart_interval = apr_time_from_sec(restart_interval);
    entry->connect_timeout = apr_time_from_sec(connect_timeout);
    entry->socket_timeout = apr_time_from_sec(socket_timeout);
    entry->queue_timeout = apr_time_from_sec(queue_timeout);

    entry->socket_user = apr_pstrdup(cmd->pool, socket_user);

    entry->listen_backlog = listen_backlog;

    entry->display_name = display_name;

    entry->send_buffer_size = send_buffer_size;
    entry->recv_buffer_size = recv_buffer_size;
    entry->header_buffer_size = header_buffer_size;
    entry->response_buffer_size = response_buffer_size;

    if (response_socket_timeout == 0)
        response_socket_timeout = socket_timeout;

    entry->response_socket_timeout = apr_time_from_sec(response_socket_timeout);

    entry->script_user = script_user;
    entry->script_group = script_group;

    entry->cpu_time_limit = cpu_time_limit;
    entry->cpu_priority = cpu_priority;

    entry->memory_limit = memory_limit;
    entry->virtual_memory_limit = virtual_memory_limit;

    entry->server_metrics = server_metrics;

    entry->newrelic_config_file = newrelic_config_file;
    entry->newrelic_environment = newrelic_environment;

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

static const char *wsgi_set_socket_rotation(cmd_parms *cmd, void *mconfig,
                                            const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->socket_rotation = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->socket_rotation = 1;
    else
        return "WSGISocketRotation must be one of: Off | On";

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
#if APR_HAS_SYSVSEM_SERIALIZE
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

static void wsgi_signal_handler(int signum)
{
    apr_size_t nbytes = 1;

    if (wsgi_daemon_pid != 0 && wsgi_daemon_pid != getpid())
        exit(-1);

    if (signum == AP_SIG_GRACEFUL) {
        apr_file_write(wsgi_signal_pipe_out, "G", &nbytes);
        apr_file_flush(wsgi_signal_pipe_out);
    }
    else if (signum == SIGXCPU) {
        if (!wsgi_graceful_timeout)
            wsgi_daemon_shutdown++;

        apr_file_write(wsgi_signal_pipe_out, "C", &nbytes);
        apr_file_flush(wsgi_signal_pipe_out);
    }
    else {
        wsgi_daemon_shutdown++;

        apr_file_write(wsgi_signal_pipe_out, "S", &nbytes);
        apr_file_flush(wsgi_signal_pipe_out);
    }
}

static void wsgi_exit_daemon_process(int status)
{
    if (wsgi_server && wsgi_daemon_group) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Exiting process '%s'.", getpid(),
                     wsgi_daemon_group);
    }

    exit(status);
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

            /*
             * Determine if Apache is being shutdown or not and
             * if it is not being shutdown, we will need to
             * restart the child daemon process that has died.
             * If MPM doesn't support query assume that child
             * daemon process shouldn't be restarted. Both
             * prefork and worker MPMs support this query so
             * should always be okay.
             */

            stopping = 1;

            if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state) == APR_SUCCESS
                && mpm_state != AP_MPMQ_STOPPING) {
                stopping = 0;
            }

            if (!stopping) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                             wsgi_server, "mod_wsgi (pid=%d): "
                             "Process '%s' has died, deregister and "
                             "restart it.", daemon->process.pid,
                             daemon->group->name);

                if (WIFEXITED(status)) {
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                             wsgi_server, "mod_wsgi (pid=%d): "
                             "Process '%s' terminated normally, exit code %d",
                             daemon->process.pid, daemon->group->name,
                             WEXITSTATUS(status));
                }
                else if (WIFSIGNALED(status)) {
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                             wsgi_server, "mod_wsgi (pid=%d): "
                             "Process '%s' terminated by signal %d",
                             daemon->process.pid, daemon->group->name,
                             WTERMSIG(status));
                }
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                             wsgi_server, "mod_wsgi (pid=%d): "
                             "Process '%s' has died but server is "
                             "being stopped, deregister it.",
                             daemon->process.pid, daemon->group->name);
            }

            /* Deregister existing process so we stop watching it. */

            apr_proc_other_child_unregister(daemon);

            /* Now restart process if not shutting down. */

            if (!stopping)
                wsgi_start_process(wsgi_parent_pool, daemon);

            break;
        }

        /* Apache is being restarted or shutdown. */

        case APR_OC_REASON_RESTART: {

            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                         wsgi_server, "mod_wsgi (pid=%d): "
                         "Process '%s' to be deregistered, as server is "
                         "restarting or being shutdown.",
                         daemon->process.pid, daemon->group->name);

            /* Deregister existing process so we stop watching it. */

            apr_proc_other_child_unregister(daemon);

            break;
        }

        /* Child daemon process vanished. */

        case APR_OC_REASON_LOST: {

            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                         wsgi_server, "mod_wsgi (pid=%d): "
                         "Process '%s' appears to have been lost, "
                         "deregister and restart it.",
                         daemon->process.pid, daemon->group->name);

            /* Deregister existing process so we stop watching it. */

            apr_proc_other_child_unregister(daemon);

            /* Restart the child daemon process that has died. */

            wsgi_start_process(wsgi_parent_pool, daemon);

            break;
        }

        /* Call to unregister the process. */

        case APR_OC_REASON_UNREGISTER: {

            /* Nothing to do at present. */

            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                         wsgi_server, "mod_wsgi (pid=%d): "
                         "Process '%s' has been deregistered and will "
                         "no longer be monitored.", daemon->process.pid,
                         daemon->group->name);

            break;
        }

        default: {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                         wsgi_server, "mod_wsgi (pid=%d): "
                         "Process '%s' targeted by unexpected event %d.",
                         daemon->process.pid, daemon->group->name, reason);
        }
    }
}

static void wsgi_setup_daemon_name(WSGIDaemonProcess *daemon, apr_pool_t *p)
{
    const char *display_name = NULL;

#if !(defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__))
    long slen = 0;
    long dlen = 0;

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

static int wsgi_setup_access(WSGIDaemonProcess *daemon)
{
    /* Change to chroot environment. */

    if (daemon->group->root) {
        if (chroot(daemon->group->root) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, wsgi_server,
                         "mod_wsgi (pid=%d): Unable to change root "
                         "directory to '%s'.", getpid(), daemon->group->root);

            return -1;
        }
    }

    /* We don't need to switch user/group if not root. */

    if (geteuid() == 0) {
        /* Setup the daemon process real and effective group. */

        if (setgid(daemon->group->gid) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, wsgi_server,
                         "mod_wsgi (pid=%d): Unable to set group id "
                         "to gid=%u.", getpid(),
                         (unsigned)daemon->group->gid);

            return -1;
        }
        else {
            if (daemon->group->groups) {
                if (setgroups(daemon->group->groups_count,
                              daemon->group->groups) == -1) {
                    ap_log_error(APLOG_MARK, APLOG_ALERT, errno,
                                 wsgi_server, "mod_wsgi (pid=%d): Unable "
                                 "to set supplementary groups for uname=%s "
                                 "of '%s'.", getpid(), daemon->group->user,
                                 daemon->group->groups_list);

                    return -1;
                }
            }
            else if (initgroups(daemon->group->user,
                     daemon->group->gid) == -1) {
                ap_log_error(APLOG_MARK, APLOG_ALERT, errno,
                             wsgi_server, "mod_wsgi (pid=%d): Unable "
                             "to set groups for uname=%s and gid=%u.",
                             getpid(), daemon->group->user,
                             (unsigned)daemon->group->gid);

                return -1;
            }
        }

        /* Setup the daemon process real and effective user. */

        if (setuid(daemon->group->uid) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, wsgi_server,
                         "mod_wsgi (pid=%d): Unable to change to uid=%ld.",
                         getpid(), (long)daemon->group->uid);

            /*
             * On true UNIX systems this should always succeed at
             * this point. With certain Linux kernel versions though
             * we can get back EAGAIN where the target user had
             * reached their process limit. In that case will be left
             * running as wrong user. Just exit on all failures to be
             * safe. Don't die immediately to avoid a fork bomb.
             *
             * We could just return -1 here and let the caller do the
             * sleep() and exit() but this failure is critical enough
             * that we still do it here so it is obvious that the issue
             * is being addressed.
             */

            ap_log_error(APLOG_MARK, APLOG_ALERT, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Failure to configure the "
                         "daemon process correctly and process left in "
                         "unspecified state. Restarting daemon process "
                         "after delay.", getpid());

            sleep(20);

            wsgi_exit_daemon_process(-1);

            return -1;
        }
    }

    /*
     * Setup the working directory for the process. It is either set to
     * what the 'home' option explicitly provides, or the home home
     * directory of the user, where it has been set to be different to
     * the user that Apache's own processes run as.
     */

    if (daemon->group->home) {
        if (chdir(daemon->group->home) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, wsgi_server,
                         "mod_wsgi (pid=%d): Unable to change working "
                         "directory to '%s'.", getpid(), daemon->group->home);

            return -1;
        }
    }
    else if (geteuid() != ap_unixd_config.user_id) {
        struct passwd *pwent;

        pwent = getpwuid(geteuid());

        if (pwent) {
            if (chdir(pwent->pw_dir) == -1) {
                ap_log_error(APLOG_MARK, APLOG_ALERT, errno, wsgi_server,
                             "mod_wsgi (pid=%d): Unable to change working "
                             "directory to home directory '%s' for uid=%ld.",
                             getpid(), pwent->pw_dir, (long)geteuid());

            return -1;
            }
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, wsgi_server,
                         "mod_wsgi (pid=%d): Unable to determine home "
                         "directory for uid=%ld.", getpid(), (long)geteuid());

            return -1;
        }
    }

    /* Setup the umask for the effective user. */

    if (daemon->group->umask != -1)
        umask(daemon->group->umask);

    /*
     * Linux prevents generation of core dumps after setuid()
     * has been used. Attempt to reenable ability to dump core
     * so that the CoreDumpDirectory directive still works.
     */

#if defined(HAVE_PRCTL) && defined(PR_SET_DUMPABLE)
    /* This applies to Linux 2.4 and later. */

    if (ap_coredumpdir_configured) {
        if (prctl(PR_SET_DUMPABLE, 1)) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, wsgi_server,
                    "mod_wsgi (pid=%d): Set dumpable failed. This child "
                    "will not coredump after software errors.", getpid());
        }
    }
#endif

    return 0;
}

static int wsgi_setup_socket(WSGIProcessGroup *process)
{
    int sockfd = -1;
    struct sockaddr_un addr;
    mode_t omask;
    int rc;

    int sendsz = process->send_buffer_size;
    int recvsz = process->recv_buffer_size;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                 "mod_wsgi (pid=%d): Socket for '%s' is '%s'.",
                 getpid(), process->name, process->socket_path);

    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, wsgi_server,
                     "mod_wsgi (pid=%d): Couldn't create unix domain "
                     "socket.", getpid());
        return -1;
    }

#ifdef SO_SNDBUF
    if (sendsz) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF,
                       (void *)&sendsz, sizeof(sendsz)) == -1) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, wsgi_server,
                         "mod_wsgi (pid=%d): Failed to set send buffer "
                         "size on daemon process socket.", getpid());
        }
    }
#endif
#ifdef SO_RCVBUF
    if (recvsz) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF,
                       (void *)&recvsz, sizeof(recvsz)) == -1) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, errno, wsgi_server,
                         "mod_wsgi (pid=%d): Failed to set receive buffer "
                         "size on daemon process socket.", getpid());
        }
    }
#endif

    if (strlen(process->socket_path) > sizeof(addr.sun_path)) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Length of path for daemon process "
                     "socket exceeds maxmimum allowed value and will be "
                     "truncated, resulting in likely failure to bind the "
                     "socket, or other later related failure.", getpid());
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    apr_cpystrn(addr.sun_path, process->socket_path, sizeof(addr.sun_path));

    omask = umask(0077);
    rc = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    if (rc < 0 && errno == EADDRINUSE) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, errno, wsgi_server,
                     "mod_wsgi (pid=%d): Removing stale unix domain "
                     "socket '%s'.", getpid(), process->socket_path);

        unlink(process->socket_path);

        rc = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    }

    umask(omask);

    if (rc < 0) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, wsgi_server,
                     "mod_wsgi (pid=%d): Couldn't bind unix domain "
                     "socket '%s'.", getpid(), process->socket_path);

        close(sockfd);

        return -1;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                 "mod_wsgi (pid=%d): Listen backlog for socket '%s' is '%d'.",
                 getpid(), process->socket_path, process->listen_backlog);

    if (listen(sockfd, process->listen_backlog) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, wsgi_server,
                     "mod_wsgi (pid=%d): Couldn't listen on unix domain "
                     "socket.", getpid());

        close(sockfd);

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
#if defined(MPM_ITK) || defined(ITK_MPM)
        uid_t socket_uid = process->uid;
#else
        uid_t socket_uid = ap_unixd_config.user_id;
#endif

        if (process->socket_user)
            socket_uid = ap_uname2id(process->socket_user);

        if (chown(process->socket_path, socket_uid, -1) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, wsgi_server,
                         "mod_wsgi (pid=%d): Couldn't change owner of unix "
                         "domain socket '%s' to uid=%ld.", getpid(),
                         process->socket_path, (long)socket_uid);

            close(sockfd);

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

#if AP_MODULE_MAGIC_AT_LEAST(20110619,0)
    /* For 2.4 a NULL sbh pointer should work. */
    sbh = NULL;
#else
    /* For 2.2 a dummy sbh pointer is needed. */
    ap_create_sb_handle(&sbh, p, -1, 0);
#endif

    c = (conn_rec *)apr_pcalloc(p, sizeof(conn_rec));

    c->sbh = sbh;

    c->conn_config = ap_create_conn_config(p);
    c->notes = apr_table_make(p, 5);
    c->pool = p;

    if ((rv = apr_socket_addr_get(&c->local_addr, APR_LOCAL, sock))
        != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, rv, wsgi_server,
                     "mod_wsgi (pid=%d): Failed call "
                     "apr_socket_addr_get(APR_LOCAL).", getpid());
        apr_socket_close(sock);
        return;
    }
    apr_sockaddr_ip_get(&c->local_ip, c->local_addr);

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    if ((rv = apr_socket_addr_get(&c->client_addr, APR_REMOTE, sock))
        != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, rv, wsgi_server,
                     "mod_wsgi (pid=%d): Failed call "
                     "apr_socket_addr_get(APR_REMOTE).", getpid());
        apr_socket_close(sock);
        return;
    }
    c->client_ip = "unknown";
#else
    if ((rv = apr_socket_addr_get(&c->remote_addr, APR_REMOTE, sock))
        != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, rv, wsgi_server,
                     "mod_wsgi (pid=%d): Failed call "
                     "apr_socket_addr_get(APR_REMOTE).", getpid());
        apr_socket_close(sock);
        return;
    }
    c->remote_ip = "unknown";
#endif

    c->base_server = daemon->group->server;

    c->bucket_alloc = bucket_alloc;
    c->id = 1;

    net = apr_palloc(c->pool, sizeof(core_net_rec));

    if (daemon->group->socket_timeout)
        rv = apr_socket_timeout_set(sock, daemon->group->socket_timeout);
    else
        rv = apr_socket_timeout_set(sock, c->base_server->timeout);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, wsgi_server,
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
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv,
                             wsgi_server, "mod_wsgi (pid=%d): "
                             "Wait on thread %d wakeup condition variable "
                             "failed.", getpid(), id);
            }

            thread->wakeup = 0;

            return rv;
        }
    }
}

static apr_status_t wsgi_worker_release(void)
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

static apr_status_t wsgi_worker_shutdown(void)
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
#if 0
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
#endif

                if (!wsgi_daemon_shutdown) {
                    ap_log_error(APLOG_MARK, APLOG_CRIT, rv,
                                 wsgi_server, "mod_wsgi (pid=%d): "
                                 "Couldn't acquire accept mutex '%s'. "
                                 "Shutting down daemon process.",
                                 getpid(), group->socket_path);

                    wsgi_daemon_shutdown++;
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
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv,
                         wsgi_server, "mod_wsgi (pid=%d): "
                         "Unable to poll daemon socket for '%s'. "
                         "Shutting down daemon process.",
                         getpid(), group->socket_path);

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

                    ap_log_error(APLOG_MARK, APLOG_CRIT, rv,
                                 wsgi_server, "mod_wsgi (pid=%d): "
                                 "Couldn't release accept mutex '%s'.",
                                 getpid(), group->socket_path);

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

        apr_thread_mutex_lock(wsgi_monitor_lock);
        thread->request = apr_time_now();
        apr_thread_mutex_unlock(wsgi_monitor_lock);

        bucket_alloc = apr_bucket_alloc_create(ptrans);
        wsgi_process_socket(ptrans, socket, bucket_alloc, daemon);

        apr_thread_mutex_lock(wsgi_monitor_lock);
        thread->request = 0;
        apr_thread_mutex_unlock(wsgi_monitor_lock);

        /* Cleanup ready for next request. */

        apr_pool_destroy(ptrans);

        thread->running = 0;

        /* Check to see if maximum number of requests reached. */

        if (daemon->group->maximum_requests) {
            if (--wsgi_request_count <= 0) {
                if (wsgi_graceful_timeout && wsgi_active_requests) {
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Maximum requests "
                                 "reached, attempt a graceful shutdown "
                                 "'%s'.", getpid(), daemon->group->name);

                    apr_thread_mutex_lock(wsgi_monitor_lock);
                    wsgi_graceful_shutdown_time = apr_time_now();
                    wsgi_graceful_shutdown_time += wsgi_graceful_timeout;
                    apr_thread_mutex_unlock(wsgi_monitor_lock);
                }
                else {
                    if (!wsgi_daemon_shutdown) {
                        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                     "mod_wsgi (pid=%d): Maximum requests "
                                     "reached, triggering immediate shutdown "
                                     "'%s'.", getpid(), daemon->group->name);
                    }

                    wsgi_daemon_shutdown++;
                    kill(getpid(), SIGINT);
                }
            }
        }
        else if (wsgi_daemon_graceful && !wsgi_daemon_shutdown) {
            if (wsgi_active_requests == 0) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Requests have completed, "
                             "triggering immediate shutdown '%s'.",
                             getpid(), daemon->group->name);

                wsgi_daemon_shutdown++;
                kill(getpid(), SIGINT);
            }
        }
    }

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Exiting thread %d in daemon "
                     "process '%s'.", getpid(), thread->id,
                     thread->process->group->name);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Exiting thread %d in daemon "
                     "process '%s'.", getpid(), thread->id,
                     thread->process->group->name);
    }
}

static void *wsgi_daemon_thread(apr_thread_t *thd, void *data)
{
    WSGIDaemonThread *thread = data;
    apr_pool_t *p = apr_thread_pool_get(thd);

    if (wsgi_server_config->verbose_debugging) {
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                   "mod_wsgi (pid=%d): Started thread %d in daemon "
                   "process '%s'.", getpid(), thread->id,
                   thread->process->group->name);
    }
    else {
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                   "mod_wsgi (pid=%d): Started thread %d in daemon "
                   "process '%s'.", getpid(), thread->id,
                   thread->process->group->name);
    }

    apr_thread_mutex_lock(thread->mutex);

    wsgi_daemon_worker(p, thread);

    apr_thread_exit(thd, APR_SUCCESS);

    return NULL;
}

static void *wsgi_reaper_thread(apr_thread_t *thd, void *data)
{
    WSGIDaemonProcess *daemon = data;

    sleep(daemon->group->shutdown_timeout);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                 "mod_wsgi (pid=%d): Aborting process '%s'.",
                 getpid(), daemon->group->name);

    wsgi_exit_daemon_process(-1);

    return NULL;
}

static void *wsgi_deadlock_thread(apr_thread_t *thd, void *data)
{
    WSGIDaemonProcess *daemon = data;

    PyGILState_STATE gilstate;

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Enable deadlock thread in "
                     "process '%s'.", getpid(), daemon->group->name);
    }

    apr_thread_mutex_lock(wsgi_monitor_lock);
    wsgi_deadlock_shutdown_time = apr_time_now();
    wsgi_deadlock_shutdown_time += wsgi_deadlock_timeout;
    apr_thread_mutex_unlock(wsgi_monitor_lock);

    while (1) {
        apr_sleep(apr_time_from_sec(1));

        apr_thread_mutex_lock(wsgi_shutdown_lock);

        if (!wsgi_daemon_shutdown) {
            gilstate = PyGILState_Ensure();
            PyGILState_Release(gilstate);
        }

        apr_thread_mutex_unlock(wsgi_shutdown_lock);

        apr_thread_mutex_lock(wsgi_monitor_lock);
        wsgi_deadlock_shutdown_time = apr_time_now();
        wsgi_deadlock_shutdown_time += wsgi_deadlock_timeout;
        apr_thread_mutex_unlock(wsgi_monitor_lock);
    }

    return NULL;
}

static void *wsgi_monitor_thread(apr_thread_t *thd, void *data)
{
    WSGIDaemonProcess *daemon = data;
    WSGIProcessGroup *group = daemon->group;

    int restart = 0;

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Enable monitor thread in "
                     "process '%s'.", getpid(), group->name);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Startup timeout is %d.",
                     getpid(), (int)(apr_time_sec(wsgi_startup_timeout)));
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Deadlock timeout is %d.",
                     getpid(), (int)(apr_time_sec(wsgi_deadlock_timeout)));
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Idle inactivity timeout is %d.",
                     getpid(), (int)(apr_time_sec(wsgi_idle_timeout)));
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Request time limit is %d.",
                     getpid(), (int)(apr_time_sec(wsgi_request_timeout)));
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Graceful timeout is %d.",
                     getpid(), (int)(apr_time_sec(wsgi_graceful_timeout)));
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Eviction timeout is %d.",
                     getpid(), (int)(apr_time_sec(wsgi_eviction_timeout)));
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Restart interval is %d.",
                     getpid(), (int)(apr_time_sec(wsgi_restart_interval)));
    }

    /*
     * If a restart interval was specified then set up the time for
     * when the restart should occur.
     */

    if (wsgi_restart_interval) {
        wsgi_restart_shutdown_time = apr_time_now();
        wsgi_restart_shutdown_time += wsgi_restart_interval;
    }

    while (1) {
        apr_time_t now;

        apr_time_t startup_time;
        apr_time_t deadlock_time;
        apr_time_t idle_time;
        apr_time_t graceful_time;
        apr_time_t restart_time;

        apr_time_t request_time = 0;

        apr_interval_time_t period = 0;

        int i = 0;

        now = apr_time_now();

        apr_thread_mutex_lock(wsgi_monitor_lock);

        startup_time = wsgi_startup_shutdown_time;
        deadlock_time = wsgi_deadlock_shutdown_time;
        idle_time = wsgi_idle_shutdown_time;
        graceful_time = wsgi_graceful_shutdown_time;
        restart_time = wsgi_restart_shutdown_time;

        if (wsgi_request_timeout && wsgi_worker_threads) {
            for (i = 0; i<wsgi_daemon_process->group->threads; i++) {
                if (wsgi_worker_threads[i].request)
                    request_time += (now - wsgi_worker_threads[i].request);
            }
        }

        request_time /= wsgi_daemon_process->group->threads;

        apr_thread_mutex_unlock(wsgi_monitor_lock);

        if (!restart && wsgi_request_timeout) {
            if (request_time > wsgi_request_timeout) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Daemon process request "
                             "time limit exceeded, stopping process "
                             "'%s'.", getpid(), group->name);

                wsgi_shutdown_reason = "request_timeout";

                wsgi_dump_stack_traces = 1;

                restart = 1;
            }
        }

        if (!restart && wsgi_startup_timeout) {
            if (startup_time > 0) {
                if (startup_time <= now) {
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Application startup "
                                 "timer expired, stopping process '%s'.",
                                 getpid(), group->name);

                    wsgi_shutdown_reason = "startup_timeout";

                    restart = 1;
                }
                else {
                    period = startup_time - now;
                }
            }
        }

        if (!restart && wsgi_restart_interval) {
            if (restart_time > 0) {
                if (restart_time <= now) {
                    if (!wsgi_daemon_graceful) {
                        if (wsgi_active_requests) {
                            wsgi_daemon_graceful++;

                            apr_thread_mutex_lock(wsgi_monitor_lock);
                            wsgi_graceful_shutdown_time = apr_time_now();
                            wsgi_graceful_shutdown_time += wsgi_graceful_timeout;
                            apr_thread_mutex_unlock(wsgi_monitor_lock);

                            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                                         wsgi_server, "mod_wsgi (pid=%d): "
                                         "Application restart timer expired, "
                                         "waiting for requests to complete "
                                         "'%s'.", getpid(),
                                         daemon->group->name);
                        }
                        else {
                            ap_log_error(APLOG_MARK, APLOG_INFO, 0,
                                         wsgi_server, "mod_wsgi (pid=%d): "
                                         "Application restart timer expired, "
                                         "stopping process '%s'.", getpid(),
                                         daemon->group->name);

                            wsgi_shutdown_reason = "restart_interval";

                            restart = 1;
                        }
                    }
                }
                else {
                    period = restart_time - now;
                }
            }
        }

        if (!restart && wsgi_deadlock_timeout) {
            if (deadlock_time) {
                if (deadlock_time <= now) {
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Daemon process deadlock "
                                 "timer expired, stopping process '%s'.",
                                 getpid(), group->name);

                    restart = 1;
                }
                else {
                    if (!period || ((deadlock_time - now) < period))
                        period = deadlock_time - now;
                }
            }
            else {
                if (!period || (wsgi_deadlock_timeout < period))
                    period = wsgi_deadlock_timeout;
            }
        }

        if (!restart && wsgi_idle_timeout) {
            if (idle_time) {
                if (idle_time <= now) {
                    if (wsgi_active_requests == 0) {
                        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                     "mod_wsgi (pid=%d): Daemon process "
                                     "idle inactivity timer expired, "
                                     "stopping process '%s'.", getpid(),
                                     group->name);

                        wsgi_shutdown_reason = "inactivity_timeout";

                        restart = 1;
                    }
                    else {
                        /* Ignore for now as still have requests. */

                        if (!period || (wsgi_idle_timeout < period))
                            period = wsgi_idle_timeout;
                    }
                }
                else {
                    if (!period || ((idle_time - now) < period))
                        period = idle_time - now;
                }
            }
            else {
                if (!period || (wsgi_idle_timeout < period))
                    period = wsgi_idle_timeout;
            }
        }

        if (!restart && wsgi_graceful_timeout) {
            if (graceful_time) {
                if (graceful_time <= now) {
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Daemon process "
                                 "graceful timer expired '%s'.", getpid(),
                                 group->name);

                    restart = 1;
                }
                else {
                    if (!period || ((graceful_time - now) < period))
                        period = graceful_time - now;
                    else if (wsgi_graceful_timeout < period)
                        period = wsgi_graceful_timeout;
                }
            }
            else {
                if (!period || (wsgi_graceful_timeout < period))
                    period = wsgi_graceful_timeout;
            }
        }

        if (!restart && wsgi_eviction_timeout) {
            if (graceful_time) {
                if (graceful_time <= now) {
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Daemon process "
                                 "graceful timer expired '%s'.", getpid(),
                                 group->name);

                    restart = 1;
                }
                else {
                    if (!period || ((graceful_time - now) < period))
                        period = graceful_time - now;
                    else if (wsgi_eviction_timeout < period)
                        period = wsgi_eviction_timeout;
                }
            }
            else {
                if (!period || (wsgi_eviction_timeout < period))
                    period = wsgi_eviction_timeout;
            }
        }

        if (restart) {
            wsgi_daemon_shutdown++;
            kill(getpid(), SIGINT);
        }

        if (restart || wsgi_request_timeout || period <= 0)
            period = apr_time_from_sec(1);

        apr_sleep(period);
    }

    return NULL;
}

#if (PY_MAJOR_VERSION >= 3) || (PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 5)
static void wsgi_log_stack_traces(void)
{
    PyGILState_STATE state;

    PyObject *threads = NULL;

    /*
     * This should only be called on shutdown so don't try and log
     * any errors, just dump them straight out.
     */

    state = PyGILState_Ensure();

    threads = _PyThread_CurrentFrames();

    if (threads && PyDict_Size(threads) != 0) {
        PyObject *seq = NULL;

        seq = PyObject_GetIter(threads);

        if (seq) {
            PyObject *id = NULL;
            PyObject *frame = NULL;

            Py_ssize_t i = 0;

            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                          "mod_wsgi (pid=%d): Dumping stack trace for "
                          "active Python threads.", getpid());

            while (PyDict_Next(threads, &i, &id, &frame)) {
                apr_int64_t thread_id = 0;

                PyFrameObject *current = NULL;

                thread_id = PyLong_AsLong(id);

                current = (PyFrameObject *)frame;

                while (current) {
                    int lineno;

                    const char *filename = NULL;
                    const char *name = NULL;

                    if (current->f_trace) {
                        lineno = current->f_lineno;
                    }
                    else {
                        lineno = PyCode_Addr2Line(current->f_code,
                                                  current->f_lasti);
                    }

#if PY_MAJOR_VERSION >= 3
                    filename = PyUnicode_AsUTF8(current->f_code->co_filename);
                    name = PyUnicode_AsUTF8(current->f_code->co_name);
#else
                    filename = PyString_AsString(current->f_code->co_filename);
                    name = PyString_AsString(current->f_code->co_name);
#endif

                    if (current == (PyFrameObject *)frame) {
                        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                "mod_wsgi (pid=%d): Thread %" APR_INT64_T_FMT
                                " executing file \"%s\", line %d, in %s",
                                getpid(), thread_id, filename, lineno, name);
                    }
                    else {
                        if (current->f_back) {
                            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                    "mod_wsgi (pid=%d): called from file "
                                    "\"%s\", line %d, in %s,", getpid(),
                                    filename, lineno, name);
                        }
                        else {
                            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                    "mod_wsgi (pid=%d): called from file "
                                    "\"%s\", line %d, in %s.", getpid(),
                                    filename, lineno, name);
                        }
                    }

                    current = current->f_back;
                }
            }
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                          "mod_wsgi (pid=%d): Failed to iterate over "
                          "current frames for active threads.", getpid());

            PyErr_Print();
            PyErr_Clear();
        }
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                      "mod_wsgi (pid=%d): Failed to get current frames "
                      "for active threads.", getpid());

        PyErr_Print();
        PyErr_Clear();
    }

    Py_XDECREF(threads);

    PyGILState_Release(state);
}
#endif

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
     * Setup poll object for listening for shutdown notice from
     * signal handler.
     */

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

    wsgi_startup_timeout = daemon->group->startup_timeout;
    wsgi_deadlock_timeout = daemon->group->deadlock_timeout;
    wsgi_idle_timeout = daemon->group->inactivity_timeout;
    wsgi_request_timeout = daemon->group->request_timeout;
    wsgi_graceful_timeout = daemon->group->graceful_timeout;
    wsgi_eviction_timeout = daemon->group->eviction_timeout;
    wsgi_restart_interval = daemon->group->restart_interval;

    if (wsgi_deadlock_timeout || wsgi_idle_timeout) {
        rv = apr_thread_create(&reaper, thread_attr, wsgi_monitor_thread,
                               daemon, p);

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, rv, wsgi_server,
                         "mod_wsgi (pid=%d): Couldn't create monitor "
                         "thread in daemon process '%s'.", getpid(),
                         daemon->group->name);
        }
    }

    if (wsgi_deadlock_timeout) {
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, rv, wsgi_server,
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
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Starting %d threads in daemon "
                     "process '%s'.", getpid(), daemon->group->threads,
                     daemon->group->name);
    }

    for (i=0; i<daemon->group->threads; i++) {
        WSGIDaemonThread *thread = &wsgi_worker_threads[i];

        if (wsgi_server_config->verbose_debugging) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Starting thread %d in daemon "
                         "process '%s'.", getpid(), i+1, daemon->group->name);
        }

        /* Create the mutex and condition variable for this thread. */

        rv = apr_thread_cond_create(&thread->condition, p);

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, rv, wsgi_server,
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
            ap_log_error(APLOG_MARK, APLOG_ALERT, rv, wsgi_server,
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
        thread->request = 0;

        rv = apr_thread_create(&thread->thread, thread_attr,
                               wsgi_daemon_thread, thread, p);

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, rv, wsgi_server,
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

    while (1) {
        char buf[1];
        apr_size_t nbytes = 1;

        rv = apr_poll(&poll_fd, 1, &poll_count, -1);
        if (APR_STATUS_IS_EINTR(rv))
            continue;

        rv = apr_file_read(wsgi_signal_pipe_in, buf, &nbytes);

        if (rv != APR_SUCCESS || nbytes != 1) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Failed read on signal pipe '%s'.",
                         getpid(), daemon->group->name);

            break;
        }

        if (buf[0] == 'C') {
            if (!wsgi_daemon_graceful) {
                wsgi_shutdown_reason = "cpu_time_limit";

                if (wsgi_active_requests) {
                    wsgi_daemon_graceful++;

                    apr_thread_mutex_lock(wsgi_monitor_lock);
                    wsgi_graceful_shutdown_time = apr_time_now();
                    wsgi_graceful_shutdown_time += wsgi_graceful_timeout;
                    apr_thread_mutex_unlock(wsgi_monitor_lock);

                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Exceeded CPU time "
                                 "limit, waiting for requests to complete "
                                 "'%s'.", getpid(), daemon->group->name);
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Exceeded CPU time "
                                 "limit, triggering immediate shutdown "
                                 "'%s'.", getpid(), daemon->group->name);

                    wsgi_daemon_shutdown++;
                    kill(getpid(), SIGINT);
                }
            }
        }
        else if (buf[0] == 'G') {
            if (!wsgi_daemon_graceful) {
                wsgi_shutdown_reason = "graceful_signal";

                if (wsgi_active_requests) {
                    wsgi_daemon_graceful++;

                    apr_thread_mutex_lock(wsgi_monitor_lock);
                    wsgi_graceful_shutdown_time = apr_time_now();
                    if (wsgi_eviction_timeout)
                        wsgi_graceful_shutdown_time += wsgi_eviction_timeout;
                    else
                        wsgi_graceful_shutdown_time += wsgi_graceful_timeout;
                    apr_thread_mutex_unlock(wsgi_monitor_lock);

                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Process eviction "
                                 "requested, waiting for requests to complete "
                                 "'%s'.", getpid(), daemon->group->name);
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                                 "mod_wsgi (pid=%d): Process eviction "
                                 "requested, triggering immediate shutdown "
                                 "'%s'.", getpid(), daemon->group->name);

                    wsgi_daemon_shutdown++;
                    kill(getpid(), SIGINT);
                }
            }
        }
        else
            break;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
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
            ap_log_error(APLOG_MARK, APLOG_ALERT, rv, wsgi_server,
                         "mod_wsgi (pid=%d): Couldn't create reaper "
                         "thread in daemon process '%s'.", getpid(),
                         daemon->group->name);
        }
    }

    /*
     * If shutting down process due to reaching request time
     * limit, then try and dump out stack traces of any threads
     * which are running as a debugging aid.
     */

    wsgi_publish_process_stopping(wsgi_shutdown_reason);

#if (PY_MAJOR_VERSION >= 3) || (PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 5)
    if (wsgi_dump_stack_traces)
        wsgi_log_stack_traces();
#endif

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
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, wsgi_server,
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
            ap_log_error(APLOG_MARK, APLOG_ERR, errno,
                         wsgi_server, "mod_wsgi (pid=%d): "
                         "Couldn't close unix domain socket '%s'.",
                         getpid(), group->socket_path);
        }

        if (unlink(group->socket_path) < 0 && errno != ENOENT) {
            ap_log_error(APLOG_MARK, APLOG_ERR, errno,
                         wsgi_server, "mod_wsgi (pid=%d): "
                         "Couldn't unlink unix domain socket '%s'.",
                         getpid(), group->socket_path);
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
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, wsgi_server,
                     "mod_wsgi: Couldn't spawn process '%s'.",
                     daemon->group->name);
        return DECLINED;
    }
    else if (status == APR_INCHILD) {
        if (!geteuid()) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Starting process '%s' with "
                         "uid=%ld, gid=%u and threads=%d.", getpid(),
                         daemon->group->name, (long)daemon->group->uid,
                         (unsigned)daemon->group->gid, daemon->group->threads);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
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
            ap_log_error(APLOG_MARK, APLOG_ERR, errno, wsgi_server,
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
                ap_log_error(APLOG_MARK, APLOG_ERR, errno, wsgi_server,
                             "mod_wsgi (pid=%d): Couldn't set CPU priority "
                             "in daemon process '%d'.", getpid(),
                             daemon->group->cpu_priority);
            }
        }

        /* Setup daemon process user/group/umask etc. */

        if (wsgi_setup_access(daemon) == -1) {
            /*
             * If we get any failure from setting up the appropriate
             * permissions or working directory for the daemon process
             * then we exit the process. Don't die immediately to avoid
             * a fork bomb.
             */

            ap_log_error(APLOG_MARK, APLOG_ALERT, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Failure to configure the "
                         "daemon process correctly and process left in "
                         "unspecified state. Restarting daemon process "
                         "after delay.", getpid());

            sleep(20);

            wsgi_exit_daemon_process(-1);
        }

        /* Reinitialise accept mutex in daemon process. */

        if (daemon->group->mutex) {
            status = apr_proc_mutex_child_init(&daemon->group->mutex,
                                               daemon->group->mutex_path, p);

            if (status != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Couldn't intialise accept "
                             "mutex in daemon process '%s'.",
                             getpid(), daemon->group->mutex_path);

                /* Don't die immediately to avoid a fork bomb. */

                sleep(20);

                wsgi_exit_daemon_process(-1);
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

        /*
         * XXX If this is closed, under Apache 2.4 then daemon
         * mode processes will crash. Not much choice but to
         * leave it open. Daemon mode really needs to be
         * rewritten not to use normal Apache request object and
         * output bucket chain to avoid potential for problems.
         */

#if 0
        ap_cleanup_scoreboard(0);
#endif

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
         * from Apache parent process. We need to first create
         * pipe by which signal handler can notify the main
         * thread that signal has arrived indicating that
         * process needs to shutdown.
         */

        status = apr_file_pipe_create(&wsgi_signal_pipe_in,
                                      &wsgi_signal_pipe_out, p);

        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, status, wsgi_server,
                         "mod_wsgi (pid=%d): Couldn't initialise signal "
                         "pipe in daemon process '%s'.", getpid(),
                         daemon->group->name);

            /* Don't die immediately to avoid a fork bomb. */

            sleep(20);

            wsgi_exit_daemon_process(-1);
        }

        wsgi_daemon_shutdown = 0;

        wsgi_daemon_pid = getpid();

        apr_signal(SIGINT, wsgi_signal_handler);
        apr_signal(SIGTERM, wsgi_signal_handler);

        apr_signal(AP_SIG_GRACEFUL, wsgi_signal_handler);

#ifdef SIGXCPU
        apr_signal(SIGXCPU, wsgi_signal_handler);
#endif

        /* Set limits on amount of CPU time that can be used. */

        if (daemon->group->cpu_time_limit > 0) {
            struct rlimit limit;
            int result = -1;

            limit.rlim_cur = daemon->group->cpu_time_limit;

            limit.rlim_max = daemon->group->cpu_time_limit + 1;
            limit.rlim_max += daemon->group->shutdown_timeout;

#if defined(RLIMIT_CPU)
            result = setrlimit(RLIMIT_CPU, &limit);
#endif

            if (result == -1) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Couldn't set CPU time "
                             "limit of %d seconds for process '%s'.", getpid(),
                             daemon->group->cpu_time_limit,
                             daemon->group->name);
            }
        }

        /*
         * Set limits on amount of date segment memory that can
         * be used. Although this is done, some platforms
         * doesn't actually support it.
         */

        if (daemon->group->memory_limit > 0) {
            struct rlimit limit;
            int result = -1;

            limit.rlim_cur = daemon->group->memory_limit;

            limit.rlim_max = daemon->group->memory_limit;

#if defined(RLIMIT_DATA)
            result = setrlimit(RLIMIT_DATA, &limit);
#endif

            if (result == -1) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Couldn't set memory "
                             "limit of %ld for process '%s'.", getpid(),
                             (long)daemon->group->memory_limit,
                             daemon->group->name);
            }
        }

        /*
         * Set limits on amount of virtual memory that can be used.
         * Although this is done, some platforms doesn't actually
         * support it.
         */

        if (daemon->group->virtual_memory_limit > 0) {
            struct rlimit limit;
            int result = -1;

            limit.rlim_cur = daemon->group->virtual_memory_limit;

            limit.rlim_max = daemon->group->virtual_memory_limit;

#if defined(RLIMIT_AS)
            result = setrlimit(RLIMIT_AS, &limit);
#elif defined(RLIMIT_VMEM)
            result = setrlimit(RLIMIT_VMEM, &limit);
#endif

            if (result == -1) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Couldn't set virtual memory "
                             "limit of %ld for process '%s'.", getpid(),
                             (long)daemon->group->virtual_memory_limit,
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
         * Retain a reference to daemon process details. Do
         * this here as when doing lazy initialisation of
         * the interpreter we want to know if in a daemon
         * process so can pick any daemon process specific
         * home directory for Python installation.
         */

        wsgi_daemon_group = daemon->group->name;
        wsgi_daemon_process = daemon;

        /* Set lang/locale if specified for daemon process. */

        if (daemon->group->lang) {
            char *envvar;

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Setting lang to %s for "
                         "daemon process group %s.", getpid(),
                         daemon->group->lang, daemon->group->name);

            envvar = apr_pstrcat(p, "LANG=", daemon->group->lang, NULL);
            putenv(envvar);
        }

        if (daemon->group->locale) {
            char *envvar;
            char *result;

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Setting locale to %s for "
                         "daemon process group %s.", getpid(),
                         daemon->group->locale, daemon->group->name);

            envvar = apr_pstrcat(p, "LC_ALL=", daemon->group->locale, NULL);
            putenv(envvar);

            result = setlocale(LC_ALL, daemon->group->locale);

            if (!result) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Unsupported locale setting "
                             "%s specified for daemon process group %s. "
                             "Consider using 'C.UTF-8' as fallback setting.",
                             getpid(), daemon->group->locale,
                             daemon->group->name);
            }
        }

        /* Create lock for request monitoring. */

        apr_thread_mutex_create(&wsgi_monitor_lock,
                                APR_THREAD_MUTEX_UNNESTED, p);

        /*
         * Initialise Python if required to be done in the child
         * process. Note that it will not be initialised if
         * mod_python loaded and it has already been done.
         */

        if (wsgi_python_after_fork)
            wsgi_python_init(p);

#if PY_MAJOR_VERSION < 3
        /*
         * If mod_python is also being loaded and thus it was
         * responsible for initialising Python it can leave in
         * place an active thread state. Under normal conditions
         * this would be eliminated in Apache child process by
         * the time that mod_wsgi got to do its own child
         * initialisation but in daemon process we skip the
         * mod_python child initialisation so the active thread
         * state still exists. Thus need to do a bit of a fiddle
         * to ensure there is no active thread state. Don't need
         * to worry about this with Python 3.X as mod_python
         * only supports Python 2.X.
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
#endif

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
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Process '%s' logging to "
                             "'%s'.", getpid(), daemon->group->name,
                             daemon->group->server->server_hostname);
            }

            wsgi_server = daemon->group->server;
        }
        else {
            if (wsgi_server_config->verbose_debugging) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Process '%s' forced to log "
                             "to '%s'.", getpid(), daemon->group->name,
                             wsgi_server->server_hostname);
            }
        }

        /* Time daemon process started waiting for requests. */

        wsgi_restart_time = apr_time_now();

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

        wsgi_newrelic_config_file = daemon->group->newrelic_config_file;
        wsgi_newrelic_environment = daemon->group->newrelic_environment;

        wsgi_python_child_init(wsgi_daemon_pool);

        /*
         * Create socket wrapper for listener file descriptor
         * and mutex for controlling which thread gets to
         * perform the accept() when a connection is ready.
         */

        apr_os_sock_put(&daemon->listener, &daemon->group->listener_fd, p);

        /*
         * Run the main routine for the daemon process if there
         * is a non zero number of threads. When number of threads
         * is zero we actually go on and shutdown immediately.
         */

        if (daemon->group->threads != 0)
            wsgi_daemon_main(p, daemon);

        /*
         * Destroy the pool for the daemon process. This will
         * have the side affect of also destroying Python.
         */

        ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Stopping process '%s'.", getpid(),
                     daemon->group->name);

        apr_pool_destroy(wsgi_daemon_pool);

        /* Exit the daemon process when being shutdown. */

        wsgi_exit_daemon_process(0);
    }

#ifdef HAVE_FORK
    if (wsgi_python_initialized) {
#if PY_MAJOR_VERSION > 3 || (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 7)
        PyOS_AfterFork_Parent();
#endif
    }
#endif

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

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Reset default user for "
                         "daemon process group '%s' to uid=%ld.",
                         getpid(), entry->name, (long)entry->uid);
        }

        if (entry->gid == ap_gname2id(DEFAULT_GROUP)) {
            entry->gid = ap_unixd_config.group_id;

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Reset default group for "
                         "daemon process group '%s' to gid=%ld.",
                         getpid(), entry->name, (long)entry->gid);
        }

        /*
         * Calculate path for socket to accept requests on and
         * create the socket.
         */

        entry->socket_rotation = wsgi_server_config->socket_rotation;

        if (entry->socket_rotation) {
            entry->socket_path = apr_psprintf(p, "%s.%d.%d.%d.sock",
                                         wsgi_server_config->socket_prefix,
                                         getpid(), mpm_generation, entry->id);
        }
        else {
            entry->socket_path = apr_psprintf(p, "%s.%d.u%d.%d.sock",
                                         wsgi_server_config->socket_prefix,
                                         getpid(), entry->uid, entry->id);
        }

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
                ap_log_error(APLOG_MARK, APLOG_CRIT, errno, wsgi_server,
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
                        ap_log_error(APLOG_MARK, APLOG_CRIT, errno,
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
                        ap_log_error(APLOG_MARK, APLOG_CRIT, errno,
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

static apr_pool_t *wsgi_pconf_pool = NULL;

static int wsgi_deferred_start_daemons(apr_pool_t *p, ap_scoreboard_e sb_type)
{
    return wsgi_start_daemons(wsgi_pconf_pool);
}

static apr_status_t wsgi_socket_connect_un(apr_socket_t *sock,
                                           struct sockaddr_un *sa)
{
    apr_status_t rv;
    apr_os_sock_t rawsock;
    apr_interval_time_t t;

    rv = apr_os_sock_get(&rawsock, sock);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_socket_timeout_get(sock, &t);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    do {
        rv = connect(rawsock, (struct sockaddr*)sa,
                     APR_OFFSETOF(struct sockaddr_un, sun_path)
                     + strlen(sa->sun_path) + 1);
    } while (rv == -1 && errno == EINTR);

    if ((rv == -1) && (errno == EINPROGRESS || errno == EALREADY)
        && (t > 0)) {
#if APR_MAJOR_VERSION < 2
        rv = apr_wait_for_io_or_timeout(NULL, sock, 0);
#else
        rv = apr_socket_wait(sock, APR_WAIT_WRITE);
#endif

        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    if (rv == -1 && errno != EISCONN) {
        return errno;
    }

    return APR_SUCCESS;
}

static int wsgi_connect_daemon(request_rec *r, WSGIDaemonSocket *daemon)
{
    WSGIRequestConfig *config = NULL;

    apr_status_t rv;

    struct sockaddr_un addr;

    int retries = 0;
    apr_interval_time_t timer = 0;
    apr_interval_time_t total_time = 0;

    apr_time_t start_time = 0;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    apr_cpystrn(addr.sun_path, daemon->socket_path, sizeof(addr.sun_path));

    start_time = apr_time_now();

    while (1) {
        retries++;

        config->daemon_connects++;

        rv = apr_socket_create(&daemon->socket, AF_UNIX, SOCK_STREAM,
                               0, r->pool);
        
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
                         "mod_wsgi (pid=%d): Unable to create socket to "
                         "connect to WSGI daemon process.", getpid());

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /*
         * Apply timeout before issuing the socket connection in
         * case this hangs for some reason. Would have to be an extreme
         * event for a UNIX socket connect to hang, but have had some
         * unexplained situations which look exactly like that.
         */

        if (daemon->socket_timeout)
            apr_socket_timeout_set(daemon->socket, daemon->socket_timeout);
        else
            apr_socket_timeout_set(daemon->socket, r->server->timeout);

        rv = wsgi_socket_connect_un(daemon->socket, &addr);

        if (rv != APR_SUCCESS) {
            /*
             * We need to check for both connection refused and
             * connection unavailable as Linux systems when
             * connecting to a UNIX listener socket in non
             * blocking mode, where the listener backlog is full
             * will return the error EAGAIN rather than returning
             * ECONNREFUSED as is supposedly dictated by POSIX.
             */

            if (APR_STATUS_IS_ECONNREFUSED(rv) || APR_STATUS_IS_EAGAIN(rv)) {
                if ((apr_time_now()-start_time) < daemon->connect_timeout) {
                    if (wsgi_server_config->verbose_debugging) {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                                     "mod_wsgi (pid=%d): Connection attempt "
                                     "#%d to WSGI daemon process '%s' on "
                                     "'%s' failed, sleeping before retrying "
                                     "again.", getpid(), retries,
                                     daemon->name, daemon->socket_path);
                    }

                    apr_socket_close(daemon->socket);

                    /*
                     * Progressively increase time we wait between
                     * connection attempts. Start at 0.125 second, but
                     * back off to 1 second interval after 2 seconds.
                     */

                    if (total_time < apr_time_make(2, 0))
                        timer = apr_time_make(0, 125000);
                    else
                        timer = apr_time_make(1, 0);

                    apr_sleep(timer);

                    total_time += timer;
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                                 "mod_wsgi (pid=%d): Unable to connect to "
                                 "WSGI daemon process '%s' on '%s' after "
                                 "multiple attempts as listener backlog "
                                 "limit was exceeded or the socket does "
                                 "not exist.", getpid(), daemon->name,
                                 daemon->socket_path);

                    apr_socket_close(daemon->socket);

                    return HTTP_SERVICE_UNAVAILABLE;
                }
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                             "mod_wsgi (pid=%d): Unable to connect to "
                             "WSGI daemon process '%s' on '%s' as user "
                             "with uid=%ld.", getpid(), daemon->name,
                             daemon->socket_path, (long)geteuid());

                apr_socket_close(daemon->socket);

                return HTTP_SERVICE_UNAVAILABLE;
            }
        }
        else
            break;
    }

    return OK;
}

static apr_status_t wsgi_socket_send(apr_socket_t *sock, const char *buf,
                                     size_t buf_size)
{
    apr_status_t rv;
    apr_size_t len;

    while (buf_size > 0)
    {
        len = buf_size;

        rv = apr_socket_send(sock, buf, &len);

        if (rv != APR_SUCCESS)
            return rv;

        buf += len;
        buf_size -= len;
    }

    return APR_SUCCESS;
}

static apr_status_t wsgi_socket_sendv_limit(apr_socket_t *sock,
        struct iovec *vec, size_t nvec)
{
    apr_status_t rv;
    apr_size_t written = 0;
    apr_size_t to_write = 0;
    size_t i, offset;

    /* Calculate how much has to be sent. */

    for (i = 0; i < nvec; i++) {
        to_write += vec[i].iov_len;
    }

    /* Loop until all data has been sent. */

    offset = 0;

    while (to_write) {
        apr_size_t n = 0;

        rv = apr_socket_sendv(sock, vec+offset, nvec-offset, &n);

        if (rv != APR_SUCCESS)
            return rv;

        if (n > 0) {
            /* Bail out of all data has been sent. */

            written += n;

            if (written >= to_write)
                break;

            /*
             * Not all data was sent, so ween need to try
             * again with the remainder of the data. We
             * first need to work out where to start from.
             */

            for (i = offset; i < nvec; ) {
                if (n >= vec[i].iov_len) {
                    offset++;
                    n -= vec[i++].iov_len;
                } else {
                    vec[i].iov_len -= n;
                    vec[i].iov_base = (char *) vec[i].iov_base + n;
                    break;
                }
            }
        }
    }

    return APR_SUCCESS;
}

static apr_status_t wsgi_socket_sendv(apr_socket_t *sock, struct iovec *vec,
                                      size_t nvec)
{
#if defined(_SC_IOV_MAX)
    static size_t iov_max = 0;
    
    if (iov_max == 0)
        iov_max = sysconf(_SC_IOV_MAX);
#else
    static size_t iov_max = APR_MAX_IOVEC_SIZE;
#endif

    if (nvec > iov_max) {
        int offset = 0;

        while (nvec != 0) {
            apr_status_t rv;

            rv = wsgi_socket_sendv_limit(sock, &vec[offset],
                    (nvec < iov_max ? nvec : (int)iov_max));

            if (rv != APR_SUCCESS)
                return rv;

            if (nvec > iov_max) {
                nvec -= iov_max;
                offset += iov_max;
            } else {
                nvec = 0;
            }
        }

        return APR_SUCCESS;
    }
    else
        return wsgi_socket_sendv_limit(sock, vec, nvec);
}

static apr_status_t wsgi_send_request(request_rec *r,
                                      WSGIRequestConfig *config,
                                      WSGIDaemonSocket *daemon)
{
    int rv;

    const apr_array_header_t *env_arr;
    const apr_table_entry_t *elts;
    int i;

    struct iovec *vec;
    struct iovec *vec_start;
    struct iovec *vec_next;

    apr_size_t total = 0;
    apr_size_t count = 0;

    apr_table_setn(r->subprocess_env, "mod_wsgi.daemon_connects",
                   apr_psprintf(r->pool, "%d", config->daemon_connects));
    apr_table_setn(r->subprocess_env, "mod_wsgi.daemon_restarts",
                   apr_psprintf(r->pool, "%d", config->daemon_restarts));

    /* Send subprocess environment from request object. */

    env_arr = apr_table_elts(r->subprocess_env);
    elts = (const apr_table_entry_t *)env_arr->elts;

    /*
     * Sending total amount of data, followed by count of separate
     * strings and then each null terminated string. The total is
     * inclusive of the bytes used for the count of the strings.
     */

    vec = (struct iovec *)apr_palloc(r->pool, (2+(2*env_arr->nelts))*
                                     sizeof(struct iovec));

    vec_start = &vec[2];
    vec_next = vec_start;

    for (i=0; i<env_arr->nelts; ++i) {
        if (!elts[i].key)
            continue;

        vec_next->iov_base = (void*)elts[i].key;
        vec_next->iov_len = strlen(elts[i].key) + 1;

        total += vec_next->iov_len;

        vec_next++;

        if (elts[i].val) {
            vec_next->iov_base = (void*)elts[i].val;
            vec_next->iov_len = strlen(elts[i].val) + 1;
        }
        else
        {
            vec_next->iov_base = (void*)"";
            vec_next->iov_len = 1;
        }

        total += vec_next->iov_len;

        vec_next++;
    }

    count = vec_next - vec_start;

    vec[1].iov_base = (void*)&count;
    vec[1].iov_len = sizeof(count);

    total += vec[1].iov_len;

    vec[0].iov_base = (void*)&total;
    vec[0].iov_len = sizeof(total);

    rv = wsgi_socket_sendv(daemon->socket, vec, (int)(vec_next-vec));

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

static int wsgi_copy_header(void *v, const char *key, const char *val)
{
    apr_table_addn(v, key, val);
    return 1;
}

#define HTTP_UNSET (-HTTP_OK)

static int wsgi_scan_headers(request_rec *r, char *buffer, int buflen,
                             int (*getsfunc) (char *, int, void *),
                             void *getsfunc_data)
{
    char x[32768];
    char *w, *l;
    size_t p;

    int cgi_status = HTTP_UNSET;

    apr_table_t *merge;
    apr_table_t *cookie_table;
    apr_table_t *authen_table;

    WSGIRequestConfig *config = NULL;

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    /*
     * Default to internal fixed size buffer for reading headers if one
     * is not supplied explicitly with the call.
     */

    if (buffer)
        *buffer = '\0';

    w = buffer ? buffer : x;
    buflen = buffer ? buflen : sizeof(x);

    /* Temporary place to hold headers as we read them. */

    merge = apr_table_make(r->pool, 10);

    /*
     * The HTTP specification says that it is legal to merge duplicate
     * headers into one. Some browsers don't like certain headers being
     * merged however. These headers are Set-Cookie and WWW-Authenticate.
     * We will therefore keep these separate and merge them back in
     * independently at the end. Before we start though, we need to make
     * sure we save away any instances of these headers which may already
     * be listed in the request structure for some reason.
     */

    cookie_table = apr_table_make(r->pool, 2);
    apr_table_do(wsgi_copy_header, cookie_table, r->headers_out,
                 "Set-Cookie", NULL);

    authen_table = apr_table_make(r->pool, 2);
    apr_table_do(wsgi_copy_header, authen_table, r->err_headers_out,
                 "WWW-Authenticate", NULL);

    while (1) {
        int rv = (*getsfunc) (w, buflen - 1, getsfunc_data);

        if (rv == 0) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Truncated or "
                                  "oversized response headers received from "
                                  "daemon process '%s'",
                                  config->process_group), r->filename);

            r->status_line = NULL;

            return HTTP_INTERNAL_SERVER_ERROR;
        }
        else if (rv == -1) {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Timeout when "
                                  "reading response headers from daemon "
                                  "process '%s'", config->process_group),
                                  r->filename);

            r->status_line = NULL;

            return HTTP_GATEWAY_TIME_OUT;
        }

        /*
         * Delete any trailing (CR?)LF. Indeed, the host's '\n':
         * '\012' for UNIX; '\015' for MacOS; '\025' for OS/390.
         */

        p = strlen(w);

        if (p > 0 && w[p - 1] == '\n') {
            if (p > 1 && w[p - 2] == CR) {
                w[p - 2] = '\0';
            }
            else {
                w[p - 1] = '\0';
            }
        }

        /*
         * If we've finished reading the headers, check to make sure
         * any HTTP/1.1 conditions are met. If so, we're done; normal
         * processing will handle the script's output. If not, just
         * return the error.
         */

        if (w[0] == '\0') {
            int cond_status = OK;

           /*
            * This fails because it gets confused when a CGI Status
            * header overrides ap_meets_conditions.
            *
            * We can fix that by dropping ap_meets_conditions when
            * Status has been set.  Since this is the only place
            * cgi_status gets used, let's test it explicitly.
            *
            * The alternative would be to ignore CGI Status when
            * ap_meets_conditions returns anything interesting. That
            * would be safer wrt HTTP, but would break CGI.
            */

            if ((cgi_status == HTTP_UNSET) && (r->method_number == M_GET)) {
                cond_status = ap_meets_conditions(r);
            }

            /*
             * Merge the headers received back into the request
             * structure. There should only be one per header with
             * values combined for these.
             */

            apr_table_overlap(r->headers_out, merge,
                              APR_OVERLAP_TABLES_MERGE);

            /*
             * Now add in the special headers which we can't merge
             * because it gives certain browsers problems.
             */

            if (!apr_is_empty_table(cookie_table)) {
                apr_table_unset(r->headers_out, "Set-Cookie");
                r->headers_out = apr_table_overlay(r->pool,
                    r->headers_out, cookie_table);
            }

            if (!apr_is_empty_table(authen_table)) {
                apr_table_unset(r->err_headers_out, "WWW-Authenticate");
                r->err_headers_out = apr_table_overlay(r->pool,
                    r->err_headers_out, authen_table);
            }

            return cond_status;
        }

        /* If we see a bogus header don't ignore it. Shout and scream. */

        if (!(l = strchr(w, ':'))) {
            char malformed[32];

            strncpy(malformed, w, sizeof(malformed)-1);
            malformed[sizeof(malformed)-1] = '\0';

            if (!buffer) {
                /* Soak up all the script output. */

                while ((*getsfunc)(w, buflen - 1, getsfunc_data) > 0) {
                    continue;
                }
            }

            wsgi_log_script_error(r, apr_psprintf(r->pool, "Malformed "
                                  "header '%s' found when reading script "
                                  "headers from daemon process '%s'",
                                  malformed, config->process_group),
                                  r->filename);

            r->status_line = NULL;

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Strip leading white space from header value. */

        *l++ = '\0';
        while (*l && apr_isspace(*l)) {
            ++l;
        }

        if (!strcasecmp(w, "Content-type")) {
            char *tmp;

            /* Nuke trailing whitespace. */

            char *endp = l + strlen(l) - 1;
            while (endp > l && apr_isspace(*endp)) {
                *endp-- = '\0';
            }

            tmp = apr_pstrdup(r->pool, l);
            ap_content_type_tolower(tmp);
            ap_set_content_type(r, tmp);
        }
        else if (!strcasecmp(w, "Status")) {
            /*
             * If the script returned a specific status, that's what
             * we'll use, otherwise we assume 200 OK.
             */

            r->status = cgi_status = atoi(l);
            r->status_line = apr_pstrdup(r->pool, l);
        }
        else if (!strcasecmp(w, "Location")) {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Content-Length")) {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Content-Range")) {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Transfer-Encoding")) {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Last-Modified")) {
            /*
             * If the script gave us a Last-Modified header, we can't just
             * pass it on blindly because of restrictions on future values.
             */

            ap_update_mtime(r, apr_date_parse_http(l));
            ap_set_last_modified(r);
        }
        else if (!strcasecmp(w, "Set-Cookie")) {
            apr_table_add(cookie_table, w, l);
        }
        else if (!strcasecmp(w, "WWW-Authenticate")) {
            apr_table_add(authen_table, w, l);
        }
        else {
            apr_table_add(merge, w, l);
        }
    }

    return OK;
}

static int wsgi_getsfunc_brigade(char *buf, int len, void *arg)
{
    apr_bucket_brigade *bb = (apr_bucket_brigade *)arg;
    const char *dst_end = buf + len - 1;
    char *dst = buf;
    apr_bucket *e = APR_BRIGADE_FIRST(bb);
    apr_status_t rv;
    int done = 0;

    while ((dst < dst_end) && !done && e != APR_BRIGADE_SENTINEL(bb)
           && !APR_BUCKET_IS_EOS(e)) {
        const char *bucket_data;
        apr_size_t bucket_data_len;
        const char *src;
        const char *src_end;
        apr_bucket * next;

        rv = apr_bucket_read(e, &bucket_data, &bucket_data_len,
                             APR_BLOCK_READ);
        if (rv != APR_SUCCESS || (bucket_data_len == 0)) {
            *dst = '\0';
            return APR_STATUS_IS_TIMEUP(rv) ? -1 : 0;
        }
        src = bucket_data;
        src_end = bucket_data + bucket_data_len;
        while ((src < src_end) && (dst < dst_end) && !done) {
            if (*src == '\n') {
                done = 1;
            }
            else if (*src != '\r') {
                *dst++ = *src;
            }
            src++;
        }

        if (src < src_end) {
            apr_bucket_split(e, src - bucket_data);
        }
        next = APR_BUCKET_NEXT(e);
        APR_BUCKET_REMOVE(e);
        apr_bucket_destroy(e);
        e = next;
    }
    *dst = '\0';
    return done;
}

static int wsgi_scan_headers_brigade(request_rec *r,
                                     apr_bucket_brigade *bb,
                                     char *buffer, int buflen)
{
    return wsgi_scan_headers(r, buffer, buflen, wsgi_getsfunc_brigade, bb);
}

static int wsgi_transfer_response(request_rec *r, apr_bucket_brigade *bb,
                                  apr_size_t buffer_size, apr_time_t timeout)
{
    apr_bucket *e;
    apr_read_type_e mode = APR_NONBLOCK_READ;

    apr_bucket_brigade *tmpbb;

    const char *data = NULL;
    apr_size_t length = 0;

    apr_size_t bytes_transfered = 0;

    int bucket_count = 0;

    apr_status_t rv;

#if AP_MODULE_MAGIC_AT_LEAST(20110605, 2)
    apr_socket_t *sock;
    apr_interval_time_t existing_timeout = 0;
#endif

    if (buffer_size == 0)
        buffer_size = 65536;

    /*
     * Override the socket timeout for writing back data to the
     * client. If that wasn't defined this will be the same as
     * the timeout for the socket used in communicating with the
     * daemon, or left as the overall server timeout if that
     * isn't specified. Just to be safe we remember the existing
     * timeout and restore it at the end of a successful request
     * in case the same connection if kept alive and used for a
     * subsequent request with a different handler.
     */

#if AP_MODULE_MAGIC_AT_LEAST(20110605, 2)
    sock = ap_get_conn_socket(r->connection);

    rv = apr_socket_timeout_get(sock, &existing_timeout);

    if (rv != APR_SUCCESS) {
        existing_timeout = 0;
    }
    else {
        if (timeout)
            apr_socket_timeout_set(sock, timeout);
    }
#endif

    /*
     * Transfer any response content. We want to avoid the
     * problem where the core output filter has no flow control
     * to deal with slow HTTP clients and can actually buffer up
     * excessive amounts of response content in memory. A fix
     * for this was only introduced in Apache 2.3.3, with
     * possible further tweaks in Apache 2.4.1. To avoid issue of
     * what version it was implemented in, just employ a
     * strategy of forcing a flush every time we pass through
     * more than a certain amount of data.
     */

    tmpbb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    while ((e = APR_BRIGADE_FIRST(bb)) != APR_BRIGADE_SENTINEL(bb)) {
        /* If we have reached end of stream, we need to pass it on */

        if (APR_BUCKET_IS_EOS(e)) {
            /*
             * Probably do not need to force a flush as EOS should
             * do that, but do it just in case when we potentially
             * have pending data to be written out.
             */

            if (bytes_transfered != 0) {
                APR_BRIGADE_INSERT_TAIL(tmpbb, apr_bucket_flush_create(
                                        r->connection->bucket_alloc));
            }

            APR_BRIGADE_INSERT_TAIL(tmpbb, apr_bucket_eos_create(
                                    r->connection->bucket_alloc));

            rv = ap_pass_brigade(r->output_filters, tmpbb);

            apr_brigade_cleanup(tmpbb);

            if (rv != APR_SUCCESS) {
                apr_brigade_destroy(bb);

                /*
                 * Don't flag error if client connection was aborted
                 * so that access log still records the original HTTP
                 * response code returned by the WSGI application.
                 */

                if (r->connection->aborted)
                    return OK;

                return HTTP_INTERNAL_SERVER_ERROR;
            }

            break;
        }

        /*
         * Force the reading in of next block of data to be
         * transfered if necessary. If the bucket is a heap
         * bucket, then it will be whatever data is in it. If it
         * is a socket bucket, this will result in the bucket
         * being converted to a heap bucket with some amount of
         * data and the socket bucket added back in after it. Any
         * non data buckets should be skipped and discarded. The
         * result should always be that the first bucket is a
         * heap bucket.
         */

        rv = apr_bucket_read(e, &data, &length, mode);

        /*
         * If we would have blocked if not in non blocking mode
         * we send a flush bucket to ensure that all buffered
         * data is sent out before we block waiting for more.
         */

        if (rv == APR_EAGAIN && mode == APR_NONBLOCK_READ) {
            APR_BRIGADE_INSERT_TAIL(tmpbb, apr_bucket_flush_create(
                                    r->connection->bucket_alloc));

            rv = ap_pass_brigade(r->output_filters, tmpbb);

            apr_brigade_cleanup(tmpbb);

            if (rv == APR_TIMEUP) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                             "mod_wsgi (pid=%d): Failed to proxy response "
                             "to client.", getpid());
            }

            if (rv != APR_SUCCESS) {
                apr_brigade_destroy(bb);

                /*
                 * Don't flag error if client connection was aborted
                 * so that access log still records the original HTTP
                 * response code returned by the WSGI application.
                 */

                if (r->connection->aborted)
                    return OK;

                return HTTP_INTERNAL_SERVER_ERROR;
            }

            bytes_transfered = 0;

            bucket_count = 0;

            /*
             * Retry read from daemon using a blocking read. We do
             * not delete the bucket as we want to operate on the
             * same one as we would have blocked.
             */

            mode = APR_BLOCK_READ;

            continue;

        } else if (rv != APR_SUCCESS) {
            apr_brigade_destroy(bb);

            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                         "mod_wsgi (pid=%d): Failed to proxy response "
                         "from daemon.", getpid());

            /*
             * Don't flag error if couldn't read from daemon
             * so that access log still records the original HTTP
             * response code returned by the WSGI application.
             */

            return OK;
        }

        /*
         * We had some data to transfer. Next time round we need to
         * always be try a non-blocking read first.
         */

        mode = APR_NONBLOCK_READ;

        /*
         * Now we don't actually work with the data which was
         * read direct and instead simply remove what should be a
         * heap bucket from the start of the bucket brigade and
         * then place in a new bucket brigade to be pushed out to
         * the client. By passing down the bucket, it avoids the
         * need to create a transient bucket holding a reference
         * to the data from the first bucket.
         */

        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(tmpbb, e);

        /*
         * If we have reached the buffer size threshold, we want
         * to flush the data so that we aren't buffering too much
         * in memory and blowing out memory size. We also have a
         * check on the number of buckets we have accumulated as
         * a large number of buckets with very small amounts of
         * data will also accumulate a lot of memory. Apache's
         * own flow control doesn't cope with such a situation.
         * Right now hard wire the max number of buckets at 16
         * which equates to worst case number of separate data
         * blocks can be written by a writev() call on systems
         * such as Solaris.
         */

        bytes_transfered += length;

        bucket_count += 1;

        if (bytes_transfered > buffer_size || bucket_count >= 16) {
            APR_BRIGADE_INSERT_TAIL(tmpbb, apr_bucket_flush_create(
                                    r->connection->bucket_alloc));

            bytes_transfered = 0;

            bucket_count = 0;

            /*
             * Since we flushed the data out to the client, it is
             * okay to go back and do a blocking read the next time.
             */

            mode = APR_BLOCK_READ;
        }

        /* Pass the heap bucket and any flush bucket on. */

        rv = ap_pass_brigade(r->output_filters, tmpbb);

        apr_brigade_cleanup(tmpbb);

        if (rv == APR_TIMEUP) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                         "mod_wsgi (pid=%d): Failed to proxy response "
                         "to client.", getpid());
        }

        if (rv != APR_SUCCESS) {
            apr_brigade_destroy(bb);

            /*
             * Don't flag error if client connection was aborted
             * so that access log still records the original HTTP
             * response code returned by the WSGI application.
             */

            if (r->connection->aborted)
                return OK;

            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

#if AP_MODULE_MAGIC_AT_LEAST(20110605, 2)
    if (existing_timeout)
        apr_socket_timeout_set(sock, existing_timeout);
#endif

    apr_brigade_destroy(bb);

    return OK;
}

#define ASCII_CRLF  "\015\012"
#define ASCII_ZERO  "\060"

static int wsgi_execute_remote(request_rec *r)
{
    WSGIRequestConfig *config = NULL;
    WSGIDaemonSocket *daemon = NULL;
    WSGIProcessGroup *group = NULL;

    char *key = NULL;
    const char *hash = NULL;

    int status;
    apr_status_t rv;

    int seen_eos;
    int child_stopped_reading;
    apr_bucket_brigade *bbout;
    apr_bucket_brigade *bbin;
    apr_bucket *b;

    const char *location = NULL;

    char *header_buffer = NULL;
    int header_buflen = 0;

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
                                  "accessed by this WSGI application "
                                  "as not a member of allowed groups",
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
                       group->socket_path, r->filename,
                       config->handler_script);
    hash = ap_md5(r->pool, (const unsigned char *)key);
    memset(key, '\0', strlen(key));

    apr_table_setn(r->subprocess_env, "mod_wsgi.magic", hash);

    /* Create connection to the daemon process. */

    apr_table_setn(r->subprocess_env, "mod_wsgi.queue_start",
                   apr_psprintf(r->pool, "%" APR_TIME_T_FMT, apr_time_now()));

    daemon = (WSGIDaemonSocket *)apr_pcalloc(r->pool,
                                             sizeof(WSGIDaemonSocket));

    daemon->name = config->process_group;
    daemon->socket_path = group->socket_path;
    daemon->connect_timeout = group->connect_timeout;
    daemon->socket_timeout = group->socket_timeout;

    if ((status = wsgi_connect_daemon(r, daemon)) != OK)
        return status;

    /* Send request details and subprocess environment. */

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Request server was "
                     "'%s|%d'.", getpid(), r->server->server_hostname,
                     r->server->port);
    }

    if ((rv = wsgi_send_request(r, config, daemon)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                     "mod_wsgi (pid=%d): Unable to send request details "
                     "to WSGI daemon process '%s' on '%s'.", getpid(),
                     daemon->name, daemon->socket_path);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Setup bucket brigade for reading response from daemon. */

    bbin = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    b = apr_bucket_socket_create(daemon->socket, r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bbin, b);
    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bbin, b);

    /* Create alternate buffer for reading in response header values. */

    if (group->header_buffer_size != 0) {
        header_buflen = group->header_buffer_size;
        header_buffer = apr_pcalloc(r->pool, header_buflen);
    }

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

            status = wsgi_scan_headers_brigade(r, bbin, header_buffer,
                                               header_buflen);

            if (status != OK)
                return status;

            /*
             * Status must be 200 for our special headers. Ideally
             * we would use 0 as did in the past but Apache 2.4
             * complains if use 0 as not a valid status value.
             */

            if (r->status != 200) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                             "mod_wsgi (pid=%d): Unexpected status from "
                             "WSGI daemon process '%d'.", getpid(),
                             r->status);

                r->status_line = NULL;

                return HTTP_INTERNAL_SERVER_ERROR;
            }

            if (!strcmp(r->status_line, "200 Continue")) {
                r->status_line = NULL;

                break;
            }

            if (!strcmp(r->status_line, "200 Timeout")) {
                r->status_line = NULL;

                return HTTP_GATEWAY_TIME_OUT;
            }

            if (strcmp(r->status_line, "200 Rejected")) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                             "mod_wsgi (pid=%d): Unexpected status from "
                             "WSGI daemon process '%d'.", getpid(), r->status);

                r->status_line = NULL;

                return HTTP_INTERNAL_SERVER_ERROR;
            }

            r->status_line = NULL;

            /* Need to close previous socket connection first. */

            apr_socket_close(daemon->socket);

            /* Has maximum number of attempts been reached. */

            if (retries == maximum) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                             "mod_wsgi (pid=%d): Maximum number of WSGI "
                             "daemon process restart connects reached '%d'.",
                             getpid(), maximum);
                return HTTP_SERVICE_UNAVAILABLE;
            }

            retries++;

            config->daemon_restarts++;

            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                         "mod_wsgi (pid=%d): Connect after WSGI daemon "
                         "process restart, attempt #%d.", getpid(),
                         retries);

            /* Connect and setup connection just like before. */

            if ((status = wsgi_connect_daemon(r, daemon)) != OK)
                return status;

            if ((rv = wsgi_send_request(r, config, daemon)) != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                             "mod_wsgi (pid=%d): Unable to send request "
                             "details to WSGI daemon process '%s' on '%s'.",
                             getpid(), daemon->name, daemon->socket_path);

                return HTTP_INTERNAL_SERVER_ERROR;
            }

            apr_brigade_destroy(bbin);

            bbin = apr_brigade_create(r->pool, r->connection->bucket_alloc);
            b = apr_bucket_socket_create(daemon->socket,
                                       r->connection->bucket_alloc);
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

    /*
     * Transfer any request content which was provided. Note that we
     * actually frame each data block sent with same format as is used
     * for chunked transfer encoding. This will be decoded in the
     * daemon process. This is done so that the EOS can be properly
     * identified by the daemon process in the absence of a value for
     * CONTENT_LENGTH that can be relied on. The CONTENT_LENGTH is
     * dodgy when have mutating input filters and none will be present
     * at all if chunked request content was used.
     */

    seen_eos = 0;
    child_stopped_reading = 0;

    bbout = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    do {
        apr_bucket *bucket;

        rv = ap_get_brigade(r->input_filters, bbout, AP_MODE_READBYTES,
                            APR_BLOCK_READ, HUGE_STRING_LEN);

        if (rv != APR_SUCCESS) {
            char status_buffer[512];
            const char *error_message;

            error_message = apr_psprintf(r->pool, "Request data read "
                    "error when proxying data to daemon process: %s",
                    apr_strerror(rv, status_buffer, sizeof(
                    status_buffer)-1));

            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                         "mod_wsgi (pid=%d): %s.", getpid(), error_message);

            if (APR_STATUS_IS_TIMEUP(rv))
                return HTTP_REQUEST_TIME_OUT;

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        for (bucket = APR_BRIGADE_FIRST(bbout);
             bucket != APR_BRIGADE_SENTINEL(bbout);
             bucket = APR_BUCKET_NEXT(bucket))
        {
            const char *data;
            apr_size_t len;

            char chunk_hdr[20];
            apr_size_t hdr_len;

            struct iovec vec[3];

            if (APR_BUCKET_IS_EOS(bucket)) {
                /* Send closing frame for chunked content. */

                rv = wsgi_socket_send(daemon->socket,
                        ASCII_ZERO ASCII_CRLF ASCII_CRLF, 5);

                if (rv != APR_SUCCESS) {
                    char status_buffer[512];
                    const char *error_message;

                    error_message = apr_psprintf(r->pool, "Request data write "
                            "error when proxying data to daemon process: %s",
                            apr_strerror(rv, status_buffer, sizeof(
                            status_buffer)-1));

                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                 "mod_wsgi (pid=%d): %s.", getpid(),
                                 error_message);
                }

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

            rv = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);

            if (rv != APR_SUCCESS) {
                char status_buffer[512];
                const char *error_message;

                error_message = apr_psprintf(r->pool, "Request data read "
                        "error when proxying data to daemon process: %s",
                        apr_strerror(rv, status_buffer, sizeof(
                        status_buffer)-1));

                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                             "mod_wsgi (pid=%d): %s.", getpid(),
                             error_message);

                break;
            }

            /*
             * Keep writing data to the child until done or too
             * much time elapses with no progress or an error
             * occurs. Frame the data being sent with format used
             * for chunked transfer encoding.
             */

            hdr_len = apr_snprintf(chunk_hdr, sizeof(chunk_hdr),
                    "%" APR_UINT64_T_HEX_FMT ASCII_CRLF, (apr_uint64_t)len);

            vec[0].iov_base = (void *)chunk_hdr;
            vec[0].iov_len = hdr_len;
            vec[1].iov_base = (void *)data;
            vec[1].iov_len = len;
            vec[2].iov_base = (void *)ASCII_CRLF;
            vec[2].iov_len = 2;

            rv = wsgi_socket_sendv(daemon->socket, vec, 3);

            if (rv != APR_SUCCESS) {
                char status_buffer[512];
                const char *error_message;

                error_message = apr_psprintf(r->pool, "Request data write "
                        "error when proxying data to daemon process: %s",
                        apr_strerror(rv, status_buffer, sizeof(
                        status_buffer)-1));

                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                             "mod_wsgi (pid=%d): %s.", getpid(),
                             error_message);

                /* Daemon stopped reading, discard remainder. */

                child_stopped_reading = 1;
            }
        }
        apr_brigade_cleanup(bbout);
    }
    while (!seen_eos);

    /*
     * Close socket for writing so that daemon detects end of
     * request content.
     */

    apr_socket_shutdown(daemon->socket, APR_SHUTDOWN_WRITE);

    /* Scan the CGI script like headers from daemon. */

    status = wsgi_scan_headers_brigade(r, bbin, header_buffer,
                                       header_buflen);

    if (status != OK)
        return status;

    /*
     * Look for the special case of status being 200 but the
     * status line indicating an error and translate it into a
     * 500 error so that error document processing will occur
     * for those cases where WSGI application wouldn't have
     * supplied their own error document. We used to use 0
     * here for status but Apache 2.4 prohibits it now.
     */

    if (r->status == 200 && !strcmp(r->status_line, "200 Error")) {
        r->status_line = NULL;

        return HTTP_INTERNAL_SERVER_ERROR;
    }

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

    return wsgi_transfer_response(r, bbin, group->response_buffer_size,
                                  group->response_socket_timeout);
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

typedef struct cve_2013_5704_fields cve_2013_5704_fields;
typedef struct cve_2013_5704_apache22 cve_2013_5704_apache22;
typedef struct cve_2013_5704_apache24 cve_2013_5704_apache24;

struct cve_2013_5704_fields {
    apr_table_t *trailers_in;
    apr_table_t *trailers_out;
};

struct cve_2013_5704_apache22 {
    struct ap_filter_t *proto_input_filters;
    int eos_sent;
    cve_2013_5704_fields fields;
};

struct cve_2013_5704_apache24 {
    apr_sockaddr_t *useragent_addr;
    char *useragent_ip;
    cve_2013_5704_fields fields;
};

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

    const char *item;

    int queue_timeout_occurred = 0;

#if ! (AP_MODULE_MAGIC_AT_LEAST(20120211, 37) || \
    (AP_SERVER_MAJORVERSION_NUMBER == 2 && \
     AP_SERVER_MINORVERSION_NUMBER <= 2 && \
     AP_MODULE_MAGIC_AT_LEAST(20051115, 36)))
    apr_size_t size = 0;
#endif

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

    /*
     * Create and populate our own request object. We allocate more
     * memory than we require here for the request_rec in order to
     * implement an opimistic hack for the case where mod_wsgi is built
     * against an Apache version prior to CVE-2013-6704 being applied to
     * it. If that Apache is upgraded but mod_wsgi not recompiled then
     * it will crash in daemon mode. We therefore use the extra space to
     * set the structure members which are added by CVE-2013-6704 to try
     * and avoid that situation. Note that this is distinct from the
     * hack down below to deal with where mod_wsgi was compiled against
     * an Apache version which had CVE-2013-6704 backported.
     */

    apr_pool_create(&p, c->pool);

    r = apr_pcalloc(p, sizeof(request_rec)+sizeof(cve_2013_5704_fields));

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

#if AP_MODULE_MAGIC_AT_LEAST(20120211, 37) || \
    (AP_SERVER_MAJORVERSION_NUMBER == 2 && \
     AP_SERVER_MINORVERSION_NUMBER <= 2 && \
     AP_MODULE_MAGIC_AT_LEAST(20051115, 36))

    /*
     * New request_rec fields were added to Apache because of changes
     * related to CVE-2013-5704. The change means that mod_wsgi version
     * 4.4.0-4.4.5 will crash if run on the Apache versions with the
     * addition fields if mod_wsgi daemon mode is used. If we are using
     * Apache 2.2.29 or 2.4.11, we set the fields direct against the
     * new structure members.
     */

    r->trailers_in = apr_table_make(r->pool, 5);
    r->trailers_out = apr_table_make(r->pool, 5);
#else
    /*
     * We use a huge hack here to try and identify when CVE-2013-5704
     * has been back ported to older Apache version. This is necessary
     * as when backported the Apache module magic number will not be
     * updated and it isn't possible to determine from that at compile
     * time if the new structure members exist and so that they should
     * be set. We therefore try and work out whether the extra structure
     * members exist through looking at the size of request_rec and
     * whether memory has been allocated above what is known to be the
     * last member in the structure before the new members were added.
     */

#if AP_SERVER_MINORVERSION_NUMBER <= 2
    size = offsetof(request_rec, eos_sent);
    size += sizeof(r->eos_sent);
#else
    size = offsetof(request_rec, useragent_ip);
    size += sizeof(r->useragent_ip);
#endif

    /*
     * Check whether request_rec is at least as large as minimal size
     * plus the size of the extra fields. If it is, then we need to
     * set the additional fields.
     */

    if (sizeof(request_rec) >= size + sizeof(cve_2013_5704_fields)) {
#if AP_SERVER_MINORVERSION_NUMBER <= 2
        cve_2013_5704_apache22 *rext;
        rext = (cve_2013_5704_apache22 *)&r->proto_input_filters;
#else
        cve_2013_5704_apache24 *rext;
        rext = (cve_2013_5704_apache24 *)&r->useragent_addr;
#endif

        rext->fields.trailers_in = apr_table_make(r->pool, 5);
        rext->fields.trailers_out = apr_table_make(r->pool, 5);
    }
    else {
        /*
         * Finally, to allow forward portability of a compiled mod_wsgi
         * binary from an Apache version without the CVE-2013-5704
         * change to one where it is, without needing to recompile
         * mod_wsgi, we set fields in the extra memory we added before
         * the actual request_rec.
         */

        cve_2013_5704_fields *rext;
        rext = (cve_2013_5704_fields *)(r+1);

        rext->trailers_in = apr_table_make(r->pool, 5);
        rext->trailers_out = apr_table_make(r->pool, 5);
    }
#endif

    r->per_dir_config  = r->server->lookup_defaults;

    r->sent_bodyct = 0;

    r->read_length = 0;
    r->read_body = REQUEST_NO_BODY;

    r->status = HTTP_OK;
    r->status_line = NULL;
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
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, wsgi_server,
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
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, wsgi_server,
                     "mod_wsgi (pid=%d): Request origin could not be "
                     "validated.", getpid());

        apr_pool_destroy(p);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    key = apr_psprintf(r->pool, "%ld|%s|%s|%s",
                       wsgi_daemon_process->group->random,
                       wsgi_daemon_process->group->socket_path,
                       filename, script);
    hash = ap_md5(r->pool, (const unsigned char *)key);
    memset(key, '\0', strlen(key));

    if (strcmp(magic, hash) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, wsgi_server,
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
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, wsgi_server,
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

    /* Recalculate WSGI script or handler script modification time. */

    if (script && *script) {
        if ((rv = apr_stat(&r->finfo, script, APR_FINFO_NORM,
                           r->pool)) != APR_SUCCESS) {
            /*
             * Don't fail at this point. Allow the lack of file to
             * be detected later when trying to load the script file.
             */

            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, wsgi_server,
                         "mod_wsgi (pid=%d): Unable to stat target handler "
                         "script '%s'.", getpid(), script);

            r->finfo.mtime = 0;
        }
    }
    else {
        if ((rv = apr_stat(&r->finfo, filename, APR_FINFO_NORM,
                           r->pool)) != APR_SUCCESS) {
            /*
             * Don't fail at this point. Allow the lack of file to
             * be detected later when trying to load the script file.
             */

            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, wsgi_server,
                         "mod_wsgi (pid=%d): Unable to stat target WSGI "
                         "script '%s'.", getpid(), filename);

            r->finfo.mtime = 0;
        }
    }

    /*
     * Trigger mapping of host information to server configuration
     * so that when logging errors they go to the correct error log
     * file for the host.
     */

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    r->connection->client_ip = (char *)apr_table_get(r->subprocess_env,
                                                     "REMOTE_ADDR");
    r->connection->client_addr->port = atoi(apr_table_get(r->subprocess_env,
                                                          "REMOTE_PORT"));
#else
    r->connection->remote_ip = (char *)apr_table_get(r->subprocess_env,
                                                     "REMOTE_ADDR");
    r->connection->remote_addr->port = atoi(apr_table_get(r->subprocess_env,
                                                          "REMOTE_PORT"));
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    r->useragent_addr = c->client_addr;
    r->useragent_ip = c->client_ip;
#endif

    key = apr_psprintf(p, "%s|%s",
                       apr_table_get(r->subprocess_env,
                                     "mod_wsgi.listener_host"),
                       apr_table_get(r->subprocess_env,
                                     "mod_wsgi.listener_port"));

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Server listener address '%s'.",
                     getpid(), key);
    }

    addr = (apr_sockaddr_t *)apr_hash_get(wsgi_daemon_listeners,
                                          key, APR_HASH_KEY_STRING);

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Server listener address '%s' was"
                     "%s found.", getpid(), key, addr ? "" : " not");
    }

    if (addr) {
        c->local_addr = addr;
    }

    ap_update_vhost_given_ip(r->connection);

    if (wsgi_server_config->verbose_debugging) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
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
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, wsgi_server,
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

    item = apr_table_get(r->subprocess_env, "mod_wsgi.enable_sendfile");

    if (item && !strcasecmp(item, "1"))
        config->enable_sendfile = 1;
    else
        config->enable_sendfile = 0;

    item = apr_table_get(r->subprocess_env, "mod_wsgi.ignore_activity");

    if (item && !strcasecmp(item, "1"))
        config->ignore_activity = 1;
    else
        config->ignore_activity = 0;

    config->daemon_connects = atoi(apr_table_get(r->subprocess_env,
                                                 "mod_wsgi.daemon_connects"));
    config->daemon_restarts = atoi(apr_table_get(r->subprocess_env,
                                                 "mod_wsgi.daemon_restarts"));

    item = apr_table_get(r->subprocess_env, "mod_wsgi.request_start");

    if (item) {
        errno = 0;
        config->request_start = apr_strtoi64(item, (char **)&item, 10);

        if (!*item && errno != ERANGE)
            r->request_time = config->request_start;
        else
            config->request_start = 0.0;
    }

    item = apr_table_get(r->subprocess_env, "mod_wsgi.queue_start");

    if (item) {
        errno = 0;
        config->queue_start = apr_strtoi64(item, (char **)&item, 10);

        if (!(!*item && errno != ERANGE))
            config->queue_start = 0.0;
    }

    config->daemon_start = apr_time_now();

    apr_table_setn(r->subprocess_env, "mod_wsgi.daemon_start",
                   apr_psprintf(r->pool, "%" APR_TIME_T_FMT,
                   config->daemon_start));

#if AP_MODULE_MAGIC_AT_LEAST(20100923,2)
    item = apr_table_get(r->subprocess_env, "mod_wsgi.request_id");

    if (item)
        r->log_id = item;

    item = apr_table_get(r->subprocess_env, "mod_wsgi.connection_id");

    if (item)
        r->connection->log_id = item;
#endif

    /*
     * Install the standard HTTP input filter and set header for
     * chunked transfer encoding to force it to dechunk the input.
     * This is necessary as we chunk the data that is proxied to
     * the daemon processes so that we can determining whether we
     * actually receive all input or it was truncated.
     *
     * Note that the subprocess_env table that gets passed to the
     * WSGI environ dictionary has already been populated, so the
     * Transfer-Encoding header will not be passed in the WSGI
     * environ dictionary as a result of this.
     */

    apr_table_setn(r->headers_in, "Transfer-Encoding", "chunked");

    ap_add_input_filter("HTTP_IN", NULL, r, r->connection);

    /* Check for queue timeout. */

    r->status = HTTP_OK;

    if (wsgi_daemon_process->group->queue_timeout) {
        if (config->request_start) {
            apr_time_t queue_time = 0;

            queue_time = config->daemon_start - config->request_start;

            if (queue_time > wsgi_daemon_process->group->queue_timeout) {
                queue_timeout_occurred = 1;

                r->status = HTTP_INTERNAL_SERVER_ERROR;
                r->status_line = "200 Timeout";

                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                             "mod_wsgi (pid=%d): Queue timeout expired "
                             "for WSGI daemon process '%s'.", getpid(),
                             wsgi_daemon_process->group->name);
            }
        }
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

    if (!queue_timeout_occurred) {
        if (wsgi_execute_script(r) != OK) {
            r->status = HTTP_INTERNAL_SERVER_ERROR;
            r->status_line = "200 Error";
        }
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
    const char *userdata_key;
    char package[128];
    char interpreter[256];

    int status = OK;

    /*
     * No longer support using mod_python at the same time as
     * mod_wsgi as becoming too painful to hack around
     * mod_python's broken usage of threading APIs when align
     * code to the stricter API requirements of Python 3.2.
     */

    userdata_key = "python_init";

    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (data) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL,
                     "mod_wsgi (pid=%d): The mod_python module can "
                     "not be used in conjunction with mod_wsgi 4.0+. "
                     "Remove the mod_python module from the Apache "
                     "configuration.", getpid());

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Init function gets called twice during startup, we only
     * need to actually do anything on the second time it is
     * called. This avoids unecessarily initialising and then
     * destroying Python for no reason. We also though have to
     * deal with a special case when a graceful restart is done.
     * For that we are only called once, which is generally okay
     * as the 'wsgi_init' key will be set from initial start up
     * of the server. The exception to this is where the module
     * is only loaded into Apache when the server is already
     * running. In this case we have to detect that it is not
     * the initial startup, but a subsequent restart. We can do
     * this by looking at whether the scoreboard has been
     * initialised yet. That is probably enough, but to be safe,
     * also check what generation it is.
     */

    userdata_key = "wsgi_init";

    apr_pool_userdata_get(&data, userdata_key, s->process->pool);

    if (!data) {
        apr_pool_userdata_set((const void *)1, userdata_key,
                              apr_pool_cleanup_null, s->process->pool);

        /*
         * Check for the special case of a graceful restart and
         * the module being loaded for the first time. In this
         * case we still go onto perform initialisation as the
         * initialisation routine for the module will not be
         * called a second time.
         */

        if (!ap_scoreboard_image ||
            ap_get_scoreboard_global()->running_generation == 0) {

            return OK;
        }
    }

    /* Setup module version information. */

    sprintf(package, "mod_wsgi/%s", MOD_WSGI_VERSION_STRING);

    ap_add_version_component(pconf, package);

    /* Record Python version string with Apache. */

    sprintf(interpreter, "Python/%d.%d", PY_MAJOR_VERSION, PY_MINOR_VERSION);
    ap_add_version_component(pconf, interpreter);

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
     *
     * XXX Can't do this as will cause Anaconda
     * Python to fail as not safe to call the
     * Py_GetVersion() function before one calls
     * the Py_Initialize() function when using
     * Anaconda Python.
     */

#if 0
    wsgi_python_version();
#endif

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

    /*
     * Startup separate named daemon processes. This is
     * a bit tricky as we only want to do this after the
     * scoreboard has been created. On the initial server
     * startup though, this hook function is called prior
     * to the MPM being run, which means the scoreboard
     * hasn't been created yet. In that case we need to
     * defer process creation until after that, which we
     * can only do by hooking into the pre_mpm hook after
     * scoreboard creation has been done. On a server
     * restart, the scoreboard will be preserved, so we
     * can do it here, which is just as well as the pre_mpm
     * hook isn't run on a restart.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (!ap_scoreboard_image) {
        /*
         * Need to remember the pool we were given here as
         * the pre_mpm hook functions get given a different
         * pool which isn't the one we want and if we use
         * that then Apache will crash when it is being
         * shutdown. So our pre_mpm hook will use the pool
         * we have remembered here.
         */

        wsgi_pconf_pool = pconf;

        ap_hook_pre_mpm(wsgi_deferred_start_daemons, NULL, NULL,
                        APR_HOOK_REALLY_LAST);
    }
    else
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

            if (entry->listener_fd != -1) {
                close(entry->listener_fd);
                entry->listener_fd = -1;
            }
        }
    }
#endif

    /* Remember worker process ID. */

    wsgi_worker_pid = getpid();

    /* Time child process started waiting for requests. */

    wsgi_restart_time = apr_time_now();

    /* Create lock for request monitoring. */

    apr_thread_mutex_create(&wsgi_monitor_lock,
                            APR_THREAD_MUTEX_UNNESTED, p);

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

static int wsgi_http_invalid_header(const char *w)
{
    char c;

    while ((c = *w++) != 0) {
        if (!apr_isalnum(c) && c != '-')
            return 1;
    }

    return 0;
}

static void wsgi_drop_invalid_headers(request_rec *r)
{
    /*
     * Apache 2.2 when converting headers for CGI variables, doesn't
     * ignore headers with invalid names. That is, any which use any
     * characters besides alphanumerics and the '-' character. This
     * opens us up to header spoofing whereby something can inject
     * multiple headers which differ by using non alphanumeric
     * characters in the same position, which would then encode to same
     * value. Since not easy to cleanup after the fact, as a workaround,
     * is easier to simply remove the invalid headers. This will make
     * things end up being the same as Apache 2.4. Doing this could
     * annoy some users of Apache 2.2 who were using invalid headers,
     * but things will break for them under Apache 2.4 anyway.
     */

    apr_array_header_t *to_delete = NULL;

    const apr_array_header_t *hdrs_arr;
    const apr_table_entry_t *hdrs;

    int i;

    hdrs_arr = apr_table_elts(r->headers_in);
    hdrs = (const apr_table_entry_t *) hdrs_arr->elts;

    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (!hdrs[i].key) {
            continue;
        }

        if (wsgi_http_invalid_header(hdrs[i].key)) {
            char **new;

            if (!to_delete)
                to_delete = apr_array_make(r->pool, 1, sizeof(char *));

            new = (char **)apr_array_push(to_delete);
            *new = hdrs[i].key;
        }
    }

    if (to_delete) {
        char *key;

        for (i = 0; i < to_delete->nelts; i++) {
            key = ((char **)to_delete->elts)[i];

            apr_table_unset(r->headers_in, key);
        }
    }
}

static const char *wsgi_proxy_client_headers[] = {
    "HTTP_X_FORWARDED_FOR",
    "HTTP_X_CLIENT_IP",
    "HTTP_X_REAL_IP",
    NULL,
};

static const char *wsgi_proxy_scheme_headers[] = {
    "HTTP_X_FORWARDED_HTTPS",
    "HTTP_X_FORWARDED_PROTO",
    "HTTP_X_FORWARDED_SCHEME",
    "HTTP_X_FORWARDED_SSL",
    "HTTP_X_HTTPS",
    "HTTP_X_SCHEME",
    NULL,
};

static const char *wsgi_proxy_host_headers[] = {
    "HTTP_X_FORWARDED_HOST",
    "HTTP_X_HOST",
    NULL,
};

static const char *wsgi_proxy_script_name_headers[] = {
    "HTTP_X_SCRIPT_NAME",
    "HTTP_X_FORWARDED_SCRIPT_NAME",
    NULL,
};

static int wsgi_ip_is_in_array(apr_sockaddr_t *client_ip,
                               apr_array_header_t *proxy_ips) {
    int i;
    apr_ipsubnet_t **subs = (apr_ipsubnet_t **)proxy_ips->elts;

    for (i = 0; i < proxy_ips->nelts; i++) {
        if (apr_ipsubnet_test(subs[i], client_ip)) {
            return 1;
        }
    }

    return 0;
}

static void wsgi_process_forwarded_for(request_rec *r,
                                       WSGIRequestConfig *config,
                                       const char *value
)
{
    if (config->trusted_proxies) {
        /*
         * A potentially comma separated list where client we are
         * interested in will be that immediately before the last
         * trusted proxy working from the end forwards. If there
         * are no trusted proxies then we use the last.
         */

        apr_array_header_t *arr;

        arr = apr_array_make(r->pool, 3, sizeof(char *));

        while (*value != '\0') {
            /* Skip leading whitespace for item. */

            while (*value != '\0' && apr_isspace(*value))
                value++;

            if (*value != '\0') {
                const char *end = NULL;
                const char *next = NULL;

                char **entry = NULL;

                end = value;

                while (*end != '\0' && *end != ',')
                    end++;

                if (*end == '\0')
                    next = end;
                else if (*end == ',')
                    next = end+1;

                /* Need deal with trailing whitespace. */

                while (end != value) {
                    if (!apr_isspace(*(end-1)))
                        break;

                    end--;
                }

                entry = (char **)apr_array_push(arr);
                *entry = apr_pstrndup(r->pool, value, (end-value));

                value = next;
            }
        }

        if (arr->nelts != 0) {
            /* HTTP_X_FORDWARDED_FOR wasn't just an empty string. */

            char **items;
            int first = -1;
            int i;

            items = (char **)arr->elts;

            /*
             * Work out the position of the IP closest to the start
             * that we actually trusted.
             */

            for (i=arr->nelts; i>0; ) {
                apr_sockaddr_t *sa;
                apr_status_t rv;

                i--;

                rv = apr_sockaddr_info_get(&sa, items[i], APR_UNSPEC,
                                           0, 0, r->pool);

                if (rv == APR_SUCCESS) {
                    if (!wsgi_ip_is_in_array(sa, config->trusted_proxies))
                        break;

                    first = i;
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r,
                              "mod_wsgi (pid=%d): Forwarded IP of \"%s\" is "
                              "not a valid IP address.", getpid(), items[i]);
                    break;
                }
            }

            if (first >= 0) {
                /*
                 * We found at least one trusted IP. We use the
                 * IP that may have appeared before that as
                 * REMOTE_ADDR. We rewrite HTTP_X_FORWARDED_FOR
                 * to record only from REMOTE_ADDR onwards.
                 */

                char *list;

                i = first-1;
                if (i<0)
                    i = 0;

                apr_table_setn(r->subprocess_env, "REMOTE_ADDR", items[i]);

                list = items[i];

                i++;

                while (arr->nelts != i) {
                    list = apr_pstrcat(r->pool, list, ", ", items[i], NULL);
                    i++;
                }

                apr_table_setn(r->subprocess_env, "HTTP_X_FORWARDED_FOR",
                               list);
            }
            else {
                /*
                 * No trusted IP. Use the last for REMOTE_ADDR.
                 * We rewrite HTTP_X_FORWARDED_FOR to record only
                 * the last.
                 */

                apr_table_setn(r->subprocess_env, "REMOTE_ADDR",
                        items[arr->nelts-1]);
                apr_table_setn(r->subprocess_env, "HTTP_X_FORWARDED_FOR",
                        items[arr->nelts-1]);
            }
        }
    }
    else {
        /*
         * We do not need to validate the proxies. We will have a
         * potentially comma separated list where the client we
         * are interested in will be listed first.
         */

        const char *end = NULL;

        /* Skip leading whitespace for item. */

        while (*value != '\0' && apr_isspace(*value))
            value++;

        if (*value != '\0') {
            end = value;

            while (*end != '\0' && *end != ',')
                end++;

            /* Need deal with trailing whitespace. */

            while (end != value) {
                if (!apr_isspace(*(end-1)))
                    break;

                end--;
            }

            /* Override REMOTE_ADDR. Leave HTTP_X_FORWARDED_FOR. */

            apr_table_setn(r->subprocess_env, "REMOTE_ADDR",
                    apr_pstrndup(r->pool, value, (end-value)));
        }
    }
}

static void wsgi_process_proxy_headers(request_rec *r)
{
    WSGIRequestConfig *config = NULL;

    apr_array_header_t *trusted_proxy_headers = NULL;

    int match_client_header = 0;
    int match_host_header = 0;
    int match_script_name_header = 0;
    int match_scheme_header = 0;

    const char *trusted_client_header = NULL;
    const char *trusted_host_header = NULL;
    const char *trusted_script_name_header = NULL;
    const char *trusted_scheme_header = NULL;

    int i = 0;

    int trusted_proxy = 1;

    const char *client_ip = NULL;

    apr_status_t rv;

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    trusted_proxy_headers = config->trusted_proxy_headers;

    /* Nothing to do if no trusted headers have been specified. */

    if (!trusted_proxy_headers)
        return;

    /*
     * Check for any special processing required for each trusted
     * header which has been specified. We should only do this if
     * there was no list of trusted proxies, or if the client IP
     * was that of a trusted proxy.
     */

    if (config->trusted_proxies) {
        client_ip = apr_table_get(r->subprocess_env, "REMOTE_ADDR");

        if (client_ip) {
            apr_sockaddr_t *sa;

            rv = apr_sockaddr_info_get(&sa, client_ip, APR_UNSPEC,
                                       0, 0, r->pool);

            if (rv == APR_SUCCESS) {
                if (!wsgi_ip_is_in_array(sa, config->trusted_proxies))
                    trusted_proxy = 0;
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "mod_wsgi (pid=%d): REMOTE_ADDR of \"%s\" is "
                              "not a valid IP address.", getpid(), client_ip);

                trusted_proxy = 0;
            }
        }
        else
            trusted_proxy = 0;
    }

    if (trusted_proxy) {
        for (i=0; i<trusted_proxy_headers->nelts; i++) {
            const char *name;
            const char *value;

            name = ((const char**)trusted_proxy_headers->elts)[i];
            value = apr_table_get(r->subprocess_env, name);

            if (!strcmp(name, "HTTP_X_FORWARDED_FOR")) {
                match_client_header = 1;

                if (value) {
                    wsgi_process_forwarded_for(r, config, value);

                    trusted_client_header = name;
                }
            }
            else if (!strcmp(name, "HTTP_X_CLIENT_IP") ||
                    !strcmp(name, "HTTP_X_REAL_IP")) {

                match_client_header = 1;

                if (value) {
                    /* Use the value as is. */

                    apr_table_setn(r->subprocess_env, "REMOTE_ADDR", value);

                    trusted_client_header = name;
                }
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_HOST") ||
                     !strcmp(name, "HTTP_X_HOST")) {

                match_host_header = 1;

                if (value) {
                    /* Use the value as is. May include a port. */

                    trusted_host_header = name;

                    apr_table_setn(r->subprocess_env, "HTTP_HOST", value);
                }
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_SERVER")) {
                if (value) {
                    /* Use the value as is. */

                    apr_table_setn(r->subprocess_env, "SERVER_NAME", value);
                }
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_PORT")) {
                if (value) {
                    /* Use the value as is. */

                    apr_table_setn(r->subprocess_env, "SERVER_PORT", value);
                }
            }
            else if (!strcmp(name, "HTTP_X_SCRIPT_NAME") ||
                     !strcmp(name, "HTTP_X_FORWARDED_SCRIPT_NAME")) {

                match_script_name_header = 1;

                if (value) {
                    /*
                     * Use the value as is. We want to remember what the
                     * original value for SCRIPT_NAME was though.
                     */

                    apr_table_setn(r->subprocess_env, "mod_wsgi.mount_point",
                                   value);

                    trusted_script_name_header = name;

                    apr_table_setn(r->subprocess_env, "SCRIPT_NAME", value);
                }
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_PROTO") ||
                !strcmp(name, "HTTP_X_FORWARDED_SCHEME") ||
                !strcmp(name, "HTTP_X_SCHEME")) {

                match_scheme_header = 1;

                if (value) {
                    trusted_scheme_header = name;

                    /* Value can be either 'http' or 'https'. */

                    if (!strcasecmp(value, "https"))
                        apr_table_setn(r->subprocess_env, "HTTPS", "1");
                    else if (!strcasecmp(value, "http"))
                        apr_table_unset(r->subprocess_env, "HTTPS");
                }
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_HTTPS") ||
                     !strcmp(name, "HTTP_X_FORWARDED_SSL") ||
                     !strcmp(name, "HTTP_X_HTTPS")) {

                match_scheme_header = 1;

                if (value) {
                    trusted_scheme_header = name;

                    /*
                     * Value can be a boolean like flag such as 'On',
                     * 'Off', 'true', 'false', '1' or '0'.
                     */

                    if (!strcasecmp(value, "On") ||
                        !strcasecmp(value, "true") ||
                        !strcasecmp(value, "1")) {

                        apr_table_setn(r->subprocess_env, "HTTPS", "1");
                    }
                    else if (!strcasecmp(value, "Off") ||
                        !strcasecmp(value, "false") ||
                        !strcasecmp(value, "0")) {

                        apr_table_unset(r->subprocess_env, "HTTPS");
                    }
                }
            }
        }
    }
    else {
        /*
         * If it isn't a trusted proxy, we still need to knock
         * out any headers for categories we were interested in.
         */

        for (i=0; i<trusted_proxy_headers->nelts; i++) {
            const char *name;

            name = ((const char**)trusted_proxy_headers->elts)[i];

            if (!strcmp(name, "HTTP_X_FORWARDED_FOR") ||
                     !strcmp(name, "HTTP_X_REAL_IP")) {

                match_client_header = 1;
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_HOST") ||
                     !strcmp(name, "HTTP_X_HOST")) {

                match_host_header = 1;
            }
            else if (!strcmp(name, "HTTP_X_SCRIPT_NAME") ||
                     !strcmp(name, "HTTP_X_FORWARDED_SCRIPT_NAME")) {

                match_script_name_header = 1;
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_PROTO") ||
                !strcmp(name, "HTTP_X_FORWARDED_SCHEME") ||
                !strcmp(name, "HTTP_X_SCHEME") ||
                !strcmp(name, "HTTP_X_FORWARDED_HTTPS") ||
                !strcmp(name, "HTTP_X_FORWARDED_SSL") ||
                !strcmp(name, "HTTP_X_HTTPS")) {

                match_scheme_header = 1;
            }
        }
    }

    /*
     * Remove all client IP headers from request environment which
     * weren't matched as being trusted.
     */

    if (match_client_header) {
        const char *name = NULL;

        for (i=0; (name=wsgi_proxy_client_headers[i]); i++) {
            if (!trusted_client_header || strcmp(name, trusted_client_header)) {
                apr_table_unset(r->subprocess_env, name);
            }
        }
    }

    /*
     * Remove all proxy scheme headers from request environment
     * which weren't matched as being trusted.
     */

    if (match_scheme_header) {
        const char *name = NULL;

        for (i=0; (name=wsgi_proxy_scheme_headers[i]); i++) {
            if (!trusted_scheme_header || strcmp(name, trusted_scheme_header)) {
                apr_table_unset(r->subprocess_env, name);
            }
        }
    }

    /*
     * Remove all proxy host from request environment which weren't
     * matched as being trusted.
     */

    if (match_host_header) {
        const char *name = NULL;

        for (i=0; (name=wsgi_proxy_host_headers[i]); i++) {
            if (!trusted_host_header || strcmp(name, trusted_host_header))
                apr_table_unset(r->subprocess_env, name);
        }
    }

    /*
     * Remove all proxy script name headers from request environment
     * which weren't matched as being trusted.
     */

    if (match_script_name_header) {
        const char *name = NULL;

        for (i=0; (name=wsgi_proxy_script_name_headers[i]); i++) {
            if (!trusted_script_name_header ||
                strcmp(name, trusted_script_name_header)) {
                apr_table_unset(r->subprocess_env, name);
            }
        }
    }
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
        if (apr_isalnum(c)) {
            *cp++ = apr_toupper(c);
        }
        else if (c == '-') {
            *cp++ = '_';
        }
        else
            return NULL;
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

    self->log = newLogObject(r, APLOG_ERR, NULL, 0);

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
            if (hdrs[i].val) {
                char *header = wsgi_http2env(r->pool, hdrs[i].key);

                if (header) {
#if PY_MAJOR_VERSION >= 3
                    object = PyUnicode_DecodeLatin1(hdrs[i].val,
                                                    strlen(hdrs[i].val), NULL);
#else
                    object = PyString_FromString(hdrs[i].val);
#endif

                    PyDict_SetItemString(vars, header, object);

                    Py_DECREF(object);
                }
            }
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

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    if (r->useragent_ip) {
        value = r->useragent_ip;
#if PY_MAJOR_VERSION >= 3
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
        object = PyString_FromString(value);
#endif
        PyDict_SetItemString(vars, "REMOTE_ADDR", object);
        Py_DECREF(object);
    }
#else
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
#endif

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

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    rport = c->client_addr->port;
    value = apr_itoa(r->pool, rport);
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    object = PyString_FromString(value);
#endif
    PyDict_SetItemString(vars, "REMOTE_PORT", object);
    Py_DECREF(object);
#else
    rport = c->remote_addr->port;
    value = apr_itoa(r->pool, rport);
#if PY_MAJOR_VERSION >= 3
    object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    object = PyString_FromString(value);
#endif
    PyDict_SetItemString(vars, "REMOTE_PORT", object);
    Py_DECREF(object);
#endif

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

    /*
     * XXX Apparently webdav does actually do modifications to
     * the uri and path_info attributes of request and they
     * could be used as part of authorisation.
     */

    if (!strcmp(r->protocol, "INCLUDED")) {
        value = r->uri;
#if PY_MAJOR_VERSION >= 3
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
        object = PyString_FromString(value);
#endif
        PyDict_SetItemString(vars, "SCRIPT_NAME", object);
        Py_DECREF(object);

        value = r->path_info ? r->path_info : "";
#if PY_MAJOR_VERSION >= 3
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
        object = PyString_FromString(value);
#endif
        PyDict_SetItemString(vars, "PATH_INFO", object);
        Py_DECREF(object);
    }
    else if (!r->path_info || !*r->path_info) {
        value = r->uri;
#if PY_MAJOR_VERSION >= 3
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
        object = PyString_FromString(value);
#endif
        PyDict_SetItemString(vars, "SCRIPT_NAME", object);
        Py_DECREF(object);

        value = "";
#if PY_MAJOR_VERSION >= 3
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
        object = PyString_FromString(value);
#endif
        PyDict_SetItemString(vars, "PATH_INFO", object);
        Py_DECREF(object);
    }
    else {
        int path_info_start = ap_find_path_info(r->uri, r->path_info);
        value = apr_pstrndup(r->pool, r->uri, path_info_start);
#if PY_MAJOR_VERSION >= 3
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
        object = PyString_FromString(value);
#endif
        PyDict_SetItemString(vars, "SCRIPT_NAME", object);
        Py_DECREF(object);

        value = r->path_info ? r->path_info : "";
#if PY_MAJOR_VERSION >= 3
        object = PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
        object = PyString_FromString(value);
#endif
        PyDict_SetItemString(vars, "PATH_INFO", object);
        Py_DECREF(object);
    }

    object = Py_BuildValue("(iii)", AP_SERVER_MAJORVERSION_NUMBER,
                           AP_SERVER_MINORVERSION_NUMBER,
                           AP_SERVER_PATCHLEVEL_NUMBER);
    PyDict_SetItemString(vars, "apache.version", object);
    Py_DECREF(object);

    object = Py_BuildValue("(iii)", MOD_WSGI_MAJORVERSION_NUMBER,
                           MOD_WSGI_MINORVERSION_NUMBER,
                           MOD_WSGI_MICROVERSION_NUMBER);
    PyDict_SetItemString(vars, "mod_wsgi.version", object);
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
#if (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 2) || \
    (PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 7)
        object = PyCapsule_New(self->r, 0, 0);
#else
        object = PyCObject_FromVoidPtr(self->r, 0);
#endif
        PyDict_SetItemString(vars, "apache.request_rec", object);
        Py_DECREF(object);
    }

    /*
     * Extensions for accessing SSL certificate information from
     * mod_ssl when in use.
     */

    object = PyObject_GetAttrString((PyObject *)self, "ssl_is_https");
    PyDict_SetItemString(vars, "mod_ssl.is_https", object);
    Py_DECREF(object);

    object = PyObject_GetAttrString((PyObject *)self, "ssl_var_lookup");
    PyDict_SetItemString(vars, "mod_ssl.var_lookup", object);
    Py_DECREF(object);

    return vars;
}

static PyObject *Auth_ssl_is_https(AuthObject *self, PyObject *args)
{
    APR_OPTIONAL_FN_TYPE(ssl_is_https) *ssl_is_https = 0;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, ":ssl_is_https"))
        return NULL;

    ssl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

    if (ssl_is_https == 0)
      return Py_BuildValue("i", 0);

    return Py_BuildValue("i", ssl_is_https(self->r->connection));
}

static PyObject *Auth_ssl_var_lookup(AuthObject *self, PyObject *args)
{
    APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *ssl_var_lookup = 0;

    PyObject *item = NULL;
    PyObject *latin_item = NULL;

    char *name = 0;
    char *value = 0;

    if (!self->r) {
        PyErr_SetString(PyExc_RuntimeError, "request object has expired");
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "O:ssl_var_lookup", &item))
        return NULL;

#if PY_MAJOR_VERSION >= 3
    if (PyUnicode_Check(item)) {
        latin_item = PyUnicode_AsLatin1String(item);
        if (!latin_item) {
            PyErr_Format(PyExc_TypeError, "byte string value expected, "
                         "value containing non 'latin-1' characters found");

            return NULL;
        }

        item = latin_item;
    }
#endif

    if (!PyString_Check(item)) {
        PyErr_Format(PyExc_TypeError, "byte string value expected, value "
                     "of type %.200s found", item->ob_type->tp_name);

        Py_XDECREF(latin_item);

        return NULL;
    }

    name = PyString_AsString(item);

    ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);

    if (ssl_var_lookup == 0)
    {
        Py_XDECREF(latin_item);

        Py_INCREF(Py_None);

        return Py_None;
    }

    value = ssl_var_lookup(self->r->pool, self->r->server,
                           self->r->connection, self->r, name);

    Py_XDECREF(latin_item);

    if (!value) {
        Py_INCREF(Py_None);

        return Py_None;
    }

#if PY_MAJOR_VERSION >= 3
    return PyUnicode_DecodeLatin1(value, strlen(value), NULL);
#else
    return PyString_FromString(value);
#endif
}

static PyMethodDef Auth_methods[] = {
    { "ssl_is_https",   (PyCFunction)Auth_ssl_is_https, METH_VARARGS, 0 },
    { "ssl_var_lookup", (PyCFunction)Auth_ssl_var_lookup, METH_VARARGS, 0 },
    { NULL, NULL}
};

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
    Auth_methods,           /*tp_methods*/
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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
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
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
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
        module = wsgi_load_source(r->pool, r, name, exists, script,
                                  "", group, 0);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Log any details of exceptions if import failed. */

    if (PyErr_Occurred())
        wsgi_log_python_error(r, NULL, script, 0);

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
#if PY_MAJOR_VERSION >= 3
                    else if (PyUnicode_Check(result)) {
                        PyObject *str = NULL;

                        str = PyUnicode_AsUTF8String(result);

                        if (str) {
                            adapter->r->user = apr_pstrdup(adapter->r->pool,
                                    PyString_AsString(str));

                            status = AUTH_GRANTED;
                        }
                    }
#else
                    else if (PyString_Check(result)) {
                        adapter->r->user = apr_pstrdup(adapter->r->pool,
                                PyString_AsString(result));

                        status = AUTH_GRANTED;
                    }
#endif
                    else {
                        PyErr_SetString(PyExc_TypeError, "Basic auth "
                                        "provider must return True, False "
                                        "None or user name as string");
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

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method) {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else {
                    args = PyTuple_New(0);
                    result = PyEval_CallObject(method, args);
                    Py_XDECREF(result);
                    Py_DECREF(args);
                }

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_wsgi (pid=%d): Target WSGI user "
                          "authentication script '%s' does not provide "
                          "'Basic' auth provider.", getpid(), script);
            Py_END_ALLOW_THREADS
        }
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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
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
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
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
        module = wsgi_load_source(r->pool, r, name, exists, script,
                                  "", group, 0);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Log any details of exceptions if import failed. */

    if (PyErr_Occurred())
        wsgi_log_python_error(r, NULL, script, 0);

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

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method) {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else {
                    args = PyTuple_New(0);
                    result = PyEval_CallObject(method, args);
                    Py_XDECREF(result);
                    Py_DECREF(args);
                }

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_wsgi (pid=%d): Target WSGI user "
                          "authentication script '%s' does not provide "
                          "'Digest' auth provider.", getpid(), script);
            Py_END_ALLOW_THREADS
        }
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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
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
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
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
        module = wsgi_load_source(r->pool, r, name, exists, script,
                                  "", group, 0);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Log any details of exceptions if import failed. */

    if (PyErr_Occurred())
        wsgi_log_python_error(r, NULL, script, 0);

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
            PyObject *result = NULL;
            PyObject *method = NULL;

            AuthObject *adapter = NULL;

            adapter = newAuthObject(r, config);

            if (adapter) {
                vars = Auth_environ(adapter, group);

                Py_INCREF(object);
                args = Py_BuildValue("(Os)", vars, r->user);
                result = PyEval_CallObject(object, args);
                Py_DECREF(args);
                Py_DECREF(object);
                Py_DECREF(vars);

                if (result) {
                    PyObject *iterator;

                    iterator = PyObject_GetIter(result);

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
                                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0,
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
                                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
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
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                      "mod_wsgi (pid=%d): Groups for user "
                                      "returned from '%s' must be an iterable "
                                      "sequence of byte strings.", getpid(),
                                      script);
                        Py_END_ALLOW_THREADS
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

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method) {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else {
                    args = PyTuple_New(0);
                    result = PyEval_CallObject(method, args);
                    Py_XDECREF(result);
                    Py_DECREF(args);
                }

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_wsgi (pid=%d): Target WSGI group "
                          "authentication script '%s' does not provide "
                          "group provider.", getpid(), script);
            Py_END_ALLOW_THREADS
        }
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

    int allow = 0;

    if (!config->access_script) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
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
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
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
        module = wsgi_load_source(r->pool, r, name, exists, script,
                                  "", group, 0);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Log any details of exceptions if import failed. */

    if (PyErr_Occurred())
        wsgi_log_python_error(r, NULL, script, 0);

    /* Assume not allowed unless everything okay. */

    allow = 0;

    /* Determine if script exists and execute it. */

    if (module) {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;

        module_dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(module_dict, "allow_access");

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
                args = Py_BuildValue("(Oz)", vars, host);
                result = PyEval_CallObject(object, args);
                Py_DECREF(args);
                Py_DECREF(object);
                Py_DECREF(vars);

                if (result) {
                    if (result == Py_None) {
                        allow = -1;
                    }
                    else if (PyBool_Check(result)) {
                        if (result == Py_True)
                            allow = 1;
                    }
                    else {
                        Py_BEGIN_ALLOW_THREADS
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                      "mod_wsgi (pid=%d): Indicator of "
                                      "host accessibility returned from '%s' "
                                      "must a boolean or None.", getpid(),
                                      script);
                        Py_END_ALLOW_THREADS
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

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method) {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else {
                    args = PyTuple_New(0);
                    result = PyEval_CallObject(method, args);
                    Py_XDECREF(result);
                    Py_DECREF(args);
                }

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_wsgi (pid=%d): Target WSGI host "
                          "access script '%s' does not provide "
                          "host validator.", getpid(), script);
            Py_END_ALLOW_THREADS
        }
    }

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    return allow;
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

#if AP_MODULE_MAGIC_AT_LEAST(20111130,0)
    if (!host)
        host = r->useragent_ip;
#else
    if (!host)
        host = r->connection->remote_ip;
#endif

    allow = wsgi_allow_access(r, config, host);

    if (allow < 0)
        return DECLINED;
    else if (allow)
        return OK;

    if (ap_satisfies(r) != SATISFY_ANY || !ap_some_auth_required(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_wsgi (pid=%d): "
                      "Client denied by server configuration: '%s'.",
                      getpid(), r->filename);
    }

    return HTTP_FORBIDDEN;
}

#if !defined(MOD_WSGI_WITH_AUTHN_PROVIDER)
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
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
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
        module = wsgi_load_source(r->pool, r, name, exists, script,
                                  "", group, 0);
    }

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
#endif

    /* Log any details of exceptions if import failed. */

    if (PyErr_Occurred())
        wsgi_log_python_error(r, NULL, script, 0);

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

                            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
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

                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
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

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                /* Close the log object so data is flushed. */

                method = PyObject_GetAttrString(adapter->log, "close");

                if (!method) {
                    PyErr_Format(PyExc_AttributeError,
                                 "'%s' object has no attribute 'close'",
                                 adapter->log->ob_type->tp_name);
                }
                else {
                    args = PyTuple_New(0);
                    result = PyEval_CallObject(method, args);
                    Py_XDECREF(result);
                    Py_DECREF(args);
                }

                /* Log any details of exceptions if execution failed. */

                if (PyErr_Occurred())
                    wsgi_log_python_error(r, NULL, script, 0);

                Py_XDECREF(method);

                /* No longer need adapter object. */

                Py_DECREF((PyObject *)adapter);
            }
        }
        else {
            Py_BEGIN_ALLOW_THREADS
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_wsgi (pid=%d): Target WSGI user "
                          "authentication script '%s' does not provide "
                          "'Basic' auth provider.", getpid(), script);
            Py_END_ALLOW_THREADS
        }
    }

    /* Cleanup and release interpreter, */

    Py_XDECREF(module);

    wsgi_release_interpreter(interp);

    return status;
}
#endif

#if defined(MOD_WSGI_WITH_AUTHZ_PROVIDER)

#if MOD_WSGI_WITH_AUTHZ_PROVIDER_PARSED
static authz_status wsgi_check_authorization(request_rec *r,
                                             const char *require_args,
                                             const void *parsed_require_line)
#else
static authz_status wsgi_check_authorization(request_rec *r,
                                             const char *require_args)
#endif
{
    WSGIRequestConfig *config;

    apr_table_t *grpstatus = NULL;
    const char *t, *w;
    int status;

#if AP_MODULE_MAGIC_AT_LEAST(20100714,0)
    if (!r->user)
        return AUTHZ_DENIED_NO_USER;
#endif

    config = wsgi_create_req_config(r->pool, r);

    if (!config->auth_group_script) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Location of WSGI group "
                     "authorization script not provided.", getpid());

        return AUTHZ_DENIED;
    }

    status = wsgi_groups_for_user(r, config, &grpstatus);

    if (status != OK)
        return AUTHZ_DENIED;

    if (apr_table_elts(grpstatus)->nelts == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_wsgi (pid=%d): "
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

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_wsgi (pid=%d): "
                  "Authorization of user '%s' to access '%s' failed. "
                  "User is not a member of designated groups.", getpid(),
                  r->user, r->uri);

    return AUTHZ_DENIED;
}

static const authz_provider wsgi_authz_provider =
{
    &wsgi_check_authorization,
#if MOD_WSGI_WITH_AUTHZ_PROVIDER_PARSED
    NULL,
#endif
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

#if AP_MODULE_MAGIC_AT_LEAST(20100714,0)
        if (!strcasecmp(w, "wsgi-group")) {
#else
        if (!strcasecmp(w, "group") || !strcasecmp(w, "wsgi-group")) {
#endif
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

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_wsgi (pid=%d): "
                  "Authorization of user '%s' to access '%s' failed. %s.",
                  getpid(), r->user, r->uri, reason ? reason : "User is not "
                  "a member of designated groups");

    ap_note_auth_failure(r);

    return HTTP_UNAUTHORIZED;
}

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

#if !defined(MOD_WSGI_WITH_AUTHN_PROVIDER)
    static const char * const p3[] = { "mod_auth.c", NULL };
#endif
#if !defined(MOD_WSGI_WITH_AUTHZ_PROVIDER)
    static const char * const n4[] = { "mod_authz_user.c", NULL };
#endif
    static const char * const n5[] = { "mod_authz_host.c", NULL };

    static const char * const p6[] = { "mod_python.c", NULL };

    static const char * const p7[] = { "mod_ssl.c", NULL };

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
    ap_hook_access_checker(wsgi_hook_access_checker, p7, n5, APR_HOOK_MIDDLE);
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
    AP_INIT_TAKE1("WSGISocketRotation", wsgi_set_socket_rotation,
        NULL, RSRC_CONF, "Enable/Disable rotation of daemon process sockets."),
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

#if (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 3) || \
    (PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 6)
    AP_INIT_TAKE1("WSGIDontWriteBytecode", wsgi_set_dont_write_bytecode,
        NULL, RSRC_CONF, "Enable/Disable writing of byte code."),
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
    AP_INIT_TAKE1("WSGIPythonHashSeed", wsgi_set_python_hash_seed,
        NULL, RSRC_CONF, "Python hash seed."),

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
    AP_INIT_TAKE1("WSGIMapHEADToGET", wsgi_set_map_head_to_get,
        NULL, OR_FILEINFO, "Enable/Disable mapping of HEAD to GET."),
    AP_INIT_TAKE1("WSGIIgnoreActivity", wsgi_set_ignore_activity,
        NULL, OR_FILEINFO, "Enable/Disable reset of inactvity timeout."),

    AP_INIT_RAW_ARGS("WSGITrustedProxyHeaders", wsgi_set_trusted_proxy_headers,
        NULL, OR_FILEINFO, "Specify a list of trusted proxy headers."),
    AP_INIT_RAW_ARGS("WSGITrustedProxies", wsgi_set_trusted_proxies,
        NULL, OR_FILEINFO, "Specify a list of trusted proxies."),

#ifndef WIN32
    AP_INIT_TAKE1("WSGIEnableSendfile", wsgi_set_enable_sendfile,
        NULL, OR_FILEINFO, "Enable/Disable support for kernel sendfile."),
#endif

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

    AP_INIT_RAW_ARGS("WSGIHandlerScript", wsgi_add_handler_script,
        NULL, ACCESS_CONF|RSRC_CONF, "Location of WSGI handler script file."),

    AP_INIT_TAKE1("WSGIServerMetrics", wsgi_set_server_metrics,
        NULL, RSRC_CONF, "Enabled/Disable access to server metrics."),

    AP_INIT_TAKE1("WSGINewRelicConfigFile", wsgi_set_newrelic_config_file,
        NULL, RSRC_CONF, "New Relic monitoring agent configuration file."),
    AP_INIT_TAKE1("WSGINewRelicEnvironment", wsgi_set_newrelic_environment,
        NULL, RSRC_CONF, "New Relic monitoring agent environment."),

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

/* ------------------------------------------------------------------------- */

#if defined(_WIN32)
#if PY_MAJOR_VERSION < 3
PyMODINIT_FUNC initmod_wsgi(void)
{
}
#else
PyMODINIT_FUNC PyInit_mod_wsgi(void)
{
    return NULL;
}
#endif
#endif

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
