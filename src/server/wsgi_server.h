#ifndef WSGI_SERVER_H
#define WSGI_SERVER_H

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

#include "wsgi_python.h"
#include "wsgi_apache.h"

/* ------------------------------------------------------------------------- */

extern server_rec *wsgi_server;
extern pid_t wsgi_parent_pid;
extern pid_t wsgi_worker_pid;
extern pid_t wsgi_daemon_pid;
extern const char *wsgi_daemon_group;

/* Python interpreter state. */

extern PyThreadState *wsgi_main_tstate;

typedef struct
{
    const char *location;
    const char *application;
    ap_regex_t *regexp;
    const char *process_group;
    const char *application_group;
    const char *callable_object;
    int pass_authorization;
} WSGIAliasEntry;

typedef struct
{
    const char *handler_script;
    const char *process_group;
    const char *application_group;
    const char *callable_object;
    const char *pass_authorization;
} WSGIScriptFile;

typedef struct
{
    const char *process_group;
    const char *application_group;
    int per_interpreter_gil;
    int free_threading;
    double switch_interval;
    int restrict_stdin;
    int restrict_stdout;
    int restrict_signal;
    const char *python_path;
} WSGIInterpreterOptionsBlock;

extern module AP_MODULE_DECLARE_DATA wsgi_module;

extern int wsgi_multiprocess;
extern int wsgi_multithread;

typedef struct
{
    apr_pool_t *pool;

    apr_array_header_t *alias_list;

    const char *socket_prefix;
    int socket_rotation;
    apr_lockmech_e lock_mechanism;

    int verbose_debugging;

    apr_array_header_t *python_warnings;

    int python_optimize;
    int dont_write_bytecode;

    const char *lang;
    const char *locale;

    const char *python_home;
    const char *python_path;
    const char *python_eggs;

    const char *python_hash_seed;

    double switch_interval;

    int destroy_interpreter;
    int restrict_embedded;
    int restrict_stdin;
    int restrict_stdout;
    int restrict_signal;

    int per_interpreter_gil;
    int free_threading;

    apr_array_header_t *interpreter_option_blocks;

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
    int map_head_to_get;
    int ignore_activity;

    apr_array_header_t *trusted_proxy_headers;
    apr_array_header_t *trusted_proxies;

    int enable_sendfile;

    apr_hash_t *handler_scripts;

    int server_metrics;
} WSGIServerConfig;

extern WSGIServerConfig *wsgi_server_config;

extern WSGIScriptFile *newWSGIScriptFile(apr_pool_t *p);
extern WSGIServerConfig *newWSGIServerConfig(apr_pool_t *p);

typedef struct
{
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

typedef struct
{
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

extern apr_pool_t *wsgi_daemon_pool;

extern WSGIRequestConfig *wsgi_create_req_config(apr_pool_t *p,
                                                 request_rec *r);

extern const char *wsgi_process_group(request_rec *r, const char *s);
extern const char *wsgi_server_group(request_rec *r, const char *s);
extern const char *wsgi_application_group(request_rec *r, const char *s);
extern const char *wsgi_callable_object(request_rec *r, const char *s);

extern char *wsgi_original_uri(request_rec *r);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
