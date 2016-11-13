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

#include "wsgi_server.h"

#include "wsgi_daemon.h"

/* ------------------------------------------------------------------------- */

/* Base server object. */

server_rec *wsgi_server = NULL;

apr_pool_t *wsgi_daemon_pool = NULL;
const char *wsgi_daemon_group = "";

/* Process information. */

pid_t wsgi_parent_pid = 0;
pid_t wsgi_worker_pid = 0;
pid_t wsgi_daemon_pid = 0;

apr_time_t wsgi_restart_time = 0;

/* New Relic monitoring agent. */

const char *wsgi_newrelic_config_file = NULL;
const char *wsgi_newrelic_environment = NULL;

/* Python interpreter state. */

PyThreadState *wsgi_main_tstate = NULL;

/* Configuration objects. */

WSGIServerConfig *wsgi_server_config = NULL;

WSGIScriptFile *newWSGIScriptFile(apr_pool_t *p)
{
    WSGIScriptFile *object = NULL;

    object = (WSGIScriptFile *)apr_pcalloc(p, sizeof(WSGIScriptFile));

    object->handler_script = NULL;
    object->application_group = NULL;
    object->process_group = NULL;

    return object;
}

WSGIServerConfig *newWSGIServerConfig(apr_pool_t *p)
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
    object->dont_write_bytecode = -1;

    object->lang = NULL;
    object->locale = NULL;

    object->python_home = NULL;
    object->python_path = NULL;
    object->python_eggs = NULL;

    object->python_hash_seed = NULL;

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
    object->ignore_activity = -1;

    object->enable_sendfile = -1;

    object->server_metrics = -1;

    object->newrelic_config_file = NULL;
    object->newrelic_environment = NULL;

    return object;
}
/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
