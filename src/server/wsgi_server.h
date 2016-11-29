#ifndef WSGI_SERVER_H
#define WSGI_SERVER_H

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

extern server_rec *wsgi_server;
extern pid_t wsgi_parent_pid;
extern pid_t wsgi_worker_pid;
extern pid_t wsgi_daemon_pid;
extern const char *wsgi_daemon_group;

extern apr_time_t wsgi_restart_time;

/* New Relic monitoring agent. */

extern const char *wsgi_newrelic_config_file;
extern const char *wsgi_newrelic_environment;

/* Python interpreter state. */

extern PyThreadState *wsgi_main_tstate;

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
    int dont_write_bytecode;

    const char *lang;
    const char *locale;

    const char *python_home;
    const char *python_path;
    const char *python_eggs;

    const char *python_hash_seed;

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
    int map_head_to_get;
    int ignore_activity;

    apr_array_header_t *trusted_proxy_headers;
    apr_array_header_t *trusted_proxies;

    int enable_sendfile;

    apr_hash_t *handler_scripts;

    int server_metrics;

    const char *newrelic_config_file;
    const char *newrelic_environment;
} WSGIServerConfig;
  
extern WSGIServerConfig *wsgi_server_config;

extern WSGIScriptFile *newWSGIScriptFile(apr_pool_t *p);
extern WSGIServerConfig *newWSGIServerConfig(apr_pool_t *p);

extern apr_pool_t *wsgi_daemon_pool;

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
