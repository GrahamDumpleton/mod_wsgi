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

#include "wsgi_daemon.h"
#include "wsgi_server.h"
#include "wsgi_interp.h"
#include "wsgi_config.h"
#include "wsgi_remote.h"
#include "wsgi_metrics.h"
#include "wsgi_shutdown.h"
#include "wsgi_logger.h"
#include "wsgi_thread.h"
#include "wsgi_signal.h"
#include "wsgi_version.h"
#include "wsgi_execute.h"

/* ------------------------------------------------------------------------- */

char *wsgi_shutdown_reason = "";

#if defined(MOD_WSGI_WITH_DAEMONS)

int wsgi_daemon_count = 0;
apr_hash_t *wsgi_daemon_index = NULL;
apr_hash_t *wsgi_daemon_listeners = NULL;

WSGIDaemonProcess *wsgi_daemon_process = NULL;

int volatile wsgi_request_count = 0;

WSGIDaemonThread *wsgi_worker_threads = NULL;

WSGIThreadStack *wsgi_worker_stack = NULL;

apr_array_header_t *wsgi_daemon_list = NULL;

static apr_pool_t *wsgi_parent_pool = NULL;
apr_pool_t *wsgi_pconf_pool = NULL;

int volatile wsgi_daemon_shutdown = 0;
static int volatile wsgi_daemon_graceful = 0;
static int volatile wsgi_daemon_draining = 0;
static int wsgi_dump_stack_traces = 0;

apr_interval_time_t wsgi_startup_timeout = 0;
static apr_interval_time_t wsgi_deadlock_timeout = 0;
apr_interval_time_t wsgi_idle_timeout = 0;
static apr_interval_time_t wsgi_request_timeout = 0;
static apr_interval_time_t wsgi_graceful_timeout = 0;
static apr_interval_time_t wsgi_eviction_timeout = 0;
static apr_interval_time_t wsgi_restart_interval = 0;
apr_time_t volatile wsgi_startup_shutdown_time = 0;
static apr_time_t volatile wsgi_deadlock_shutdown_time = 0;
apr_time_t volatile wsgi_idle_shutdown_time = 0;
static apr_time_t volatile wsgi_graceful_shutdown_time = 0;
static apr_time_t volatile wsgi_restart_shutdown_time = 0;

#endif

/* ------------------------------------------------------------------------- */

#if defined(MOD_WSGI_WITH_DAEMONS)

const char *wsgi_add_daemon_process(cmd_parms *cmd, void *mconfig,
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
    int graceful_timeout = 15;
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

    while (*args)
    {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS)
        {
            return "Invalid option to WSGI daemon process definition.";
        }

        if (!strcmp(option, "user"))
        {
            if (!*value)
                return "Invalid user for WSGI daemon process.";

            user = value;
            uid = ap_uname2id(user);
            if (uid == 0)
                return "WSGI process blocked from running as root.";

            if (*user == '#')
            {
                struct passwd *entry = NULL;

                if ((entry = getpwuid(uid)) == NULL)
                    return "Couldn't determine user name from uid.";

                user = entry->pw_name;
            }
        }
        else if (!strcmp(option, "group"))
        {
            if (!*value)
                return "Invalid group for WSGI daemon process.";

            group = value;
            gid = ap_gname2id(group);
        }
        else if (!strcmp(option, "supplementary-groups"))
        {
            groups_list = value;
        }
        else if (!strcmp(option, "processes"))
        {
            if (!*value)
                return "Invalid process count for WSGI daemon process.";

            processes = atoi(value);
            if (processes < 1)
                return "Invalid process count for WSGI daemon process.";

            multiprocess = 1;
        }
        else if (!strcmp(option, "threads"))
        {
            if (!*value)
                return "Invalid thread count for WSGI daemon process.";

            threads = atoi(value);
            if (threads < 0 || threads >= WSGI_STACK_LAST - 1)
                return "Invalid thread count for WSGI daemon process.";
        }
        else if (!strcmp(option, "umask"))
        {
            if (!*value)
                return "Invalid umask for WSGI daemon process.";

            errno = 0;
            umask = strtol(value, (char **)&value, 8);

            if (*value || errno == ERANGE || umask < 0)
                return "Invalid umask for WSGI daemon process.";
        }
        else if (!strcmp(option, "chroot"))
        {
            if (geteuid())
                return "Cannot chroot WSGI daemon process when not root.";

            if (*value != '/')
                return "Invalid chroot directory for WSGI daemon process.";

            root = value;
        }
        else if (!strcmp(option, "home"))
        {
            if (*value != '/')
                return "Invalid home directory for WSGI daemon process.";

            home = value;
        }
        else if (!strcmp(option, "lang"))
        {
            lang = value;
        }
        else if (!strcmp(option, "locale"))
        {
            locale = value;
        }
        else if (!strcmp(option, "python-home"))
        {
            python_home = value;
        }
        else if (!strcmp(option, "python-path"))
        {
            python_path = value;
        }
        else if (!strcmp(option, "python-eggs"))
        {
            python_eggs = value;
        }
#if (APR_MAJOR_VERSION >= 1)
        else if (!strcmp(option, "stack-size"))
        {
            if (!*value)
                return "Invalid stack size for WSGI daemon process.";

            stack_size = atoi(value);
            if (stack_size <= 0)
                return "Invalid stack size for WSGI daemon process.";
        }
#endif
        else if (!strcmp(option, "maximum-requests"))
        {
            if (!*value)
                return "Invalid request count for WSGI daemon process.";

            maximum_requests = atoi(value);
            if (maximum_requests < 0)
                return "Invalid request count for WSGI daemon process.";
        }
        else if (!strcmp(option, "startup-timeout"))
        {
            if (!*value)
                return "Invalid startup timeout for WSGI daemon process.";

            startup_timeout = atoi(value);
            if (startup_timeout < 0)
                return "Invalid startup timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "shutdown-timeout"))
        {
            if (!*value)
                return "Invalid shutdown timeout for WSGI daemon process.";

            shutdown_timeout = atoi(value);
            if (shutdown_timeout < 0)
                return "Invalid shutdown timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "deadlock-timeout"))
        {
            if (!*value)
                return "Invalid deadlock timeout for WSGI daemon process.";

            deadlock_timeout = atoi(value);
            if (deadlock_timeout < 0)
                return "Invalid deadlock timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "inactivity-timeout"))
        {
            if (!*value)
                return "Invalid inactivity timeout for WSGI daemon process.";

            inactivity_timeout = atoi(value);
            if (inactivity_timeout < 0)
                return "Invalid inactivity timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "request-timeout"))
        {
            if (!*value)
                return "Invalid request timeout for WSGI daemon process.";

            request_timeout = atoi(value);
            if (request_timeout < 0)
                return "Invalid request timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "graceful-timeout"))
        {
            if (!*value)
                return "Invalid graceful timeout for WSGI daemon process.";

            graceful_timeout = atoi(value);
            if (graceful_timeout < 0)
                return "Invalid graceful timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "eviction-timeout"))
        {
            if (!*value)
                return "Invalid eviction timeout for WSGI daemon process.";

            eviction_timeout = atoi(value);
            if (eviction_timeout < 0)
                return "Invalid eviction timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "restart-interval"))
        {
            if (!*value)
                return "Invalid restart interval for WSGI daemon process.";

            restart_interval = atoi(value);
            if (restart_interval < 0)
                return "Invalid restart interval for WSGI daemon process.";
        }
        else if (!strcmp(option, "connect-timeout"))
        {
            if (!*value)
                return "Invalid connect timeout for WSGI daemon process.";

            connect_timeout = atoi(value);
            if (connect_timeout < 0)
                return "Invalid connect timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "socket-timeout"))
        {
            if (!*value)
                return "Invalid socket timeout for WSGI daemon process.";

            socket_timeout = atoi(value);
            if (socket_timeout < 0)
                return "Invalid socket timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "queue-timeout"))
        {
            if (!*value)
                return "Invalid queue timeout for WSGI daemon process.";

            queue_timeout = atoi(value);
            if (queue_timeout < 0)
                return "Invalid queue timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "listen-backlog"))
        {
            if (!*value)
                return "Invalid listen backlog for WSGI daemon process.";

            listen_backlog = atoi(value);
            if (listen_backlog < 0)
                return "Invalid listen backlog for WSGI daemon process.";
        }
        else if (!strcmp(option, "display-name"))
        {
            display_name = value;
        }
        else if (!strcmp(option, "send-buffer-size"))
        {
            if (!*value)
                return "Invalid send buffer size for WSGI daemon process.";

            send_buffer_size = atoi(value);
            if (send_buffer_size < 512 && send_buffer_size != 0)
            {
                return "Send buffer size must be >= 512 bytes, "
                       "or 0 for system default.";
            }
        }
        else if (!strcmp(option, "receive-buffer-size"))
        {
            if (!*value)
                return "Invalid receive buffer size for WSGI daemon process.";

            recv_buffer_size = atoi(value);
            if (recv_buffer_size < 512 && recv_buffer_size != 0)
            {
                return "Receive buffer size must be >= 512 bytes, "
                       "or 0 for system default.";
            }
        }
        else if (!strcmp(option, "header-buffer-size"))
        {
            if (!*value)
                return "Invalid header buffer size for WSGI daemon process.";

            header_buffer_size = atoi(value);
            if (header_buffer_size < 8192 && header_buffer_size != 0)
            {
                return "Header buffer size must be >= 8192 bytes, "
                       "or 0 for default.";
            }
        }
        else if (!strcmp(option, "response-buffer-size"))
        {
            if (!*value)
                return "Invalid response buffer size for WSGI daemon process.";

            response_buffer_size = atoi(value);
            if (response_buffer_size < 65536 && response_buffer_size != 0)
            {
                return "Response buffer size must be >= 65536 bytes, "
                       "or 0 for default.";
            }
        }
        else if (!strcmp(option, "response-socket-timeout"))
        {
            if (!*value)
                return "Invalid response socket timeout for WSGI daemon process.";

            response_socket_timeout = atoi(value);
            if (response_socket_timeout < 0)
                return "Invalid response socket timeout for WSGI daemon process.";
        }
        else if (!strcmp(option, "socket-user"))
        {
            uid_t socket_uid;

            if (!*value)
                return "Invalid socket user for WSGI daemon process.";

            socket_uid = ap_uname2id(value);

            if (*value == '#')
            {
                struct passwd *entry = NULL;

                if ((entry = getpwuid(socket_uid)) == NULL)
                    return "Couldn't determine user name from socket user.";

                value = entry->pw_name;
            }

            socket_user = value;
        }
        else if (!strcmp(option, "script-user"))
        {
            uid_t script_uid;

            if (!*value)
                return "Invalid script user for WSGI daemon process.";

            script_uid = ap_uname2id(value);

            if (*value == '#')
            {
                struct passwd *entry = NULL;

                if ((entry = getpwuid(script_uid)) == NULL)
                    return "Couldn't determine uid from script user.";

                value = entry->pw_name;
            }

            script_user = value;
        }
        else if (!strcmp(option, "script-group"))
        {
            gid_t script_gid;

            if (!*value)
                return "Invalid script group for WSGI daemon process.";

            script_gid = ap_gname2id(value);

            if (*value == '#')
            {
                struct group *entry = NULL;

                if ((entry = getgrgid(script_gid)) == NULL)
                    return "Couldn't determine gid from script group.";

                value = entry->gr_name;
            }

            script_group = value;
        }
        else if (!strcmp(option, "cpu-time-limit"))
        {
            if (!*value)
                return "Invalid CPU time limit for WSGI daemon process.";

            cpu_time_limit = atoi(value);
            if (cpu_time_limit < 0)
                return "Invalid CPU time limit for WSGI daemon process.";
        }
        else if (!strcmp(option, "cpu-priority"))
        {
            if (!*value)
                return "Invalid CPU priority for WSGI daemon process.";

            cpu_priority = atoi(value);
        }
        else if (!strcmp(option, "memory-limit"))
        {
            if (!*value)
                return "Invalid memory limit for WSGI daemon process.";

            memory_limit = apr_atoi64(value);
            if (memory_limit < 0)
                return "Invalid memory limit for WSGI daemon process.";
        }
        else if (!strcmp(option, "virtual-memory-limit"))
        {
            if (!*value)
                return "Invalid virtual memory limit for WSGI daemon process.";

            virtual_memory_limit = apr_atoi64(value);
            if (virtual_memory_limit < 0)
                return "Invalid virtual memory limit for WSGI daemon process.";
        }
        else if (!strcmp(option, "server-metrics"))
        {
            if (!*value)
                return "Invalid server metrics flag for WSGI daemon process.";

            if (strcasecmp(value, "Off") == 0)
                server_metrics = 0;
            else if (strcasecmp(value, "On") == 0)
                server_metrics = 1;
            else
                return "Invalid server metrics flag for WSGI daemon process.";
        }
        else
            return "Invalid option to WSGI daemon process definition.";
    }

    if (script_user && script_group)
        return "Only one of script-user and script-group allowed.";

    if (groups_list)
    {
        const char *group_name = NULL;
        long groups_maximum = NGROUPS_MAX;
        const char *items = NULL;

#ifdef _SC_NGROUPS_MAX
        groups_maximum = sysconf(_SC_NGROUPS_MAX);
        if (groups_maximum < 0)
            groups_maximum = NGROUPS_MAX;
#endif
        groups = (gid_t *)apr_pcalloc(cmd->pool,
                                      groups_maximum * sizeof(groups[0]));

        groups[groups_count++] = gid;

        items = groups_list;
        group_name = ap_getword(cmd->pool, &items, ',');

        while (group_name && *group_name)
        {
            if (groups_count >= groups_maximum)
                return "Too many supplementary groups WSGI daemon process";

            groups[groups_count++] = ap_gname2id(group_name);
            group_name = ap_getword(cmd->pool, &items, ',');
        }
    }

    if (!wsgi_daemon_list)
    {
        wsgi_daemon_list = apr_array_make(cmd->pool, 20,
                                          sizeof(WSGIProcessGroup));
        apr_pool_cleanup_register(cmd->pool, &wsgi_daemon_list,
                                  ap_pool_cleanup_set_null,
                                  apr_pool_cleanup_null);
    }

    entries = (WSGIProcessGroup *)wsgi_daemon_list->elts;

    for (i = 0; i < wsgi_daemon_list->nelts; ++i)
    {
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

    entry->listener_fd = -1;

    return NULL;
}

const char *wsgi_set_socket_prefix(cmd_parms *cmd, void *mconfig,
                                   const char *arg)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    sconfig->socket_prefix = ap_server_root_relative(cmd->pool, arg);

    if (!sconfig->socket_prefix)
    {
        return apr_pstrcat(cmd->pool, "Invalid WSGISocketPrefix '",
                           arg, "'.", NULL);
    }

    return NULL;
}

const char *wsgi_set_socket_rotation(cmd_parms *cmd, void *mconfig,
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

const char *wsgi_set_accept_mutex(cmd_parms *cmd, void *mconfig,
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

    if (!strcasecmp(arg, "default"))
    {
        sconfig->lock_mechanism = APR_LOCK_DEFAULT;
    }
#if APR_HAS_FLOCK_SERIALIZE
    else if (!strcasecmp(arg, "flock"))
    {
        sconfig->lock_mechanism = APR_LOCK_FLOCK;
    }
#endif
#if APR_HAS_FCNTL_SERIALIZE
    else if (!strcasecmp(arg, "fcntl"))
    {
        sconfig->lock_mechanism = APR_LOCK_FCNTL;
    }
#endif
#if APR_HAS_SYSVSEM_SERIALIZE
    else if (!strcasecmp(arg, "sysvsem"))
    {
        sconfig->lock_mechanism = APR_LOCK_SYSVSEM;
    }
#endif
#if APR_HAS_POSIXSEM_SERIALIZE
    else if (!strcasecmp(arg, "posixsem"))
    {
        sconfig->lock_mechanism = APR_LOCK_POSIXSEM;
    }
#endif
#if APR_HAS_PROC_PTHREAD_SERIALIZE
    else if (!strcasecmp(arg, "pthread"))
    {
        sconfig->lock_mechanism = APR_LOCK_PROC_PTHREAD;
    }
#endif
    else
    {
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

    if (signum == AP_SIG_GRACEFUL)
    {
        apr_file_write(wsgi_signal_pipe_out, "G", &nbytes);
        apr_file_flush(wsgi_signal_pipe_out);
    }
    else if (signum == SIGXCPU)
    {
        if (!wsgi_graceful_timeout)
            wsgi_daemon_shutdown++;

        apr_file_write(wsgi_signal_pipe_out, "C", &nbytes);
        apr_file_flush(wsgi_signal_pipe_out);
    }
    else
    {
        wsgi_daemon_shutdown++;

        apr_file_write(wsgi_signal_pipe_out, "S", &nbytes);
        apr_file_flush(wsgi_signal_pipe_out);
    }
}

static void wsgi_exit_daemon_process(int status)
{
    if (wsgi_server && wsgi_daemon_group)
    {
        wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                       "Exiting process '%s'.", wsgi_daemon_group);
    }

    exit(status);
}

/*
 * Exit the daemon process after applying the anti-fork-bomb delay.
 * Use only at daemon-process initialisation failures where the next
 * fork would deterministically hit the same problem (file descriptors
 * exhausted, RLIMIT_NPROC reached, missing user, missing socket
 * directory, broken Python install, etc). The 20-second delay caps
 * Apache's respawn rate at 3/minute under a persistent failure.
 */

static void wsgi_daemon_init_failure_exit(void)
{
    sleep(20);
    wsgi_exit_daemon_process(-1);
}

static int wsgi_start_process(apr_pool_t *p, WSGIDaemonProcess *daemon);

static void wsgi_manage_process(int reason, void *data, apr_wait_t status)
{
    WSGIDaemonProcess *daemon = data;

    switch (reason)
    {

        /* Child daemon process has died. */

    case APR_OC_REASON_DEATH:
    {
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

        if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state) == APR_SUCCESS && mpm_state != AP_MPMQ_STOPPING)
        {
            stopping = 0;
        }

        if (!stopping)
        {
            wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                           "Process '%s' (pid=%d) has died, deregister and "
                           "restart it.",
                           daemon->group->name, daemon->process.pid);

            if (WIFEXITED(status))
            {
                wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                               "Process '%s' (pid=%d) terminated normally, "
                               "exit code %d",
                               daemon->group->name, daemon->process.pid,
                               WEXITSTATUS(status));
            }
            else if (WIFSIGNALED(status))
            {
                wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                               "Process '%s' (pid=%d) terminated by "
                               "signal %d",
                               daemon->group->name, daemon->process.pid,
                               WTERMSIG(status));
            }
        }
        else
        {
            wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                           "Process '%s' (pid=%d) has died but server is "
                           "being stopped, deregister it.",
                           daemon->group->name, daemon->process.pid);
        }

        /* Deregister existing process so we stop watching it. */

        apr_proc_other_child_unregister(daemon);

        /* Now restart process if not shutting down. */

        if (!stopping)
            wsgi_start_process(wsgi_parent_pool, daemon);

        break;
    }

        /* Apache is being restarted or shutdown. */

    case APR_OC_REASON_RESTART:
    {

        wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                       "Process '%s' (pid=%d) to be deregistered, as server "
                       "is restarting or being shutdown.",
                       daemon->group->name, daemon->process.pid);

        /* Deregister existing process so we stop watching it. */

        apr_proc_other_child_unregister(daemon);

        break;
    }

        /* Child daemon process vanished. */

    case APR_OC_REASON_LOST:
    {

        wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                       "Process '%s' (pid=%d) appears to have been lost, "
                       "deregister and restart it.",
                       daemon->group->name, daemon->process.pid);

        /* Deregister existing process so we stop watching it. */

        apr_proc_other_child_unregister(daemon);

        /* Restart the child daemon process that has died. */

        wsgi_start_process(wsgi_parent_pool, daemon);

        break;
    }

        /* Call to unregister the process. */

    case APR_OC_REASON_UNREGISTER:
    {

        /* Nothing to do at present. */

        wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                       "Process '%s' (pid=%d) has been deregistered and "
                       "will no longer be monitored.",
                       daemon->group->name, daemon->process.pid);

        break;
    }

    default:
    {
        wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                       "Process '%s' (pid=%d) targeted by unexpected "
                       "event %d.",
                       daemon->group->name, daemon->process.pid, reason);
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

    if (!strcmp(display_name, "%{GROUP}"))
    {
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
    argv0 = (char *)wsgi_server->process->argv[0];

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

    if (daemon->group->root)
    {
        if (chroot(daemon->group->root) == -1)
        {
            wsgi_log_error(APLOG_ALERT, errno, wsgi_server, WSGI_APLOGNO(0003)
                           "Unable to change root directory to '%s'. "
                           "Daemon process will exit.",
                           daemon->group->root);

            return -1;
        }
    }

    /* We don't need to switch user/group if not root. */

    if (geteuid() == 0)
    {
        /* Setup the daemon process real and effective group. */

        if (setgid(daemon->group->gid) == -1)
        {
            wsgi_log_error(APLOG_ALERT, errno, wsgi_server, WSGI_APLOGNO(0004)
                           "Unable to set group id to gid=%u. "
                           "Daemon process will exit.",
                           (unsigned)daemon->group->gid);

            return -1;
        }
        else
        {
            if (daemon->group->groups)
            {
                if (setgroups(daemon->group->groups_count,
                              daemon->group->groups) == -1)
                {
                    wsgi_log_error(APLOG_ALERT, errno, wsgi_server, WSGI_APLOGNO(0005)
                                   "Unable to set supplementary groups "
                                   "for uname=%s of '%s'. Daemon process "
                                   "will exit.",
                                   daemon->group->user,
                                   daemon->group->groups_list);

                    return -1;
                }
            }
            else if (initgroups(daemon->group->user,
                                daemon->group->gid) == -1)
            {
                wsgi_log_error(APLOG_ALERT, errno, wsgi_server, WSGI_APLOGNO(0006)
                               "Unable to initialise groups for uname=%s "
                               "and gid=%u. Daemon process will exit.",
                               daemon->group->user,
                               (unsigned)daemon->group->gid);

                return -1;
            }
        }

        /* Setup the daemon process real and effective user. */

        if (setuid(daemon->group->uid) == -1)
        {
            wsgi_log_error(APLOG_ALERT, errno, wsgi_server, WSGI_APLOGNO(0007)
                           "Unable to change to uid=%ld. "
                           "Daemon process will exit.",
                           (long)daemon->group->uid);

            /*
             * On true UNIX systems setuid should always succeed at
             * this point. With certain Linux kernel versions we can
             * get back EAGAIN where the target user has reached their
             * process limit; the daemon would otherwise be left
             * running as the Apache user, so just exit on any
             * failure.
             */

            wsgi_log_error(APLOG_ALERT, 0, wsgi_server, WSGI_APLOGNO(0008)
                           "Daemon process configuration failed; process "
                           "left in unspecified state. Daemon process "
                           "will exit and be restarted after a delay.");

            wsgi_daemon_init_failure_exit();

            return -1;
        }
    }

    /*
     * Setup the working directory for the process. It is either set to
     * what the 'home' option explicitly provides, or the home home
     * directory of the user, where it has been set to be different to
     * the user that Apache's own processes run as.
     */

    if (daemon->group->home)
    {
        if (chdir(daemon->group->home) == -1)
        {
            wsgi_log_error(APLOG_ALERT, errno, wsgi_server, WSGI_APLOGNO(0009)
                           "Unable to change working directory to '%s'. "
                           "Daemon process will exit.",
                           daemon->group->home);

            return -1;
        }
    }
    else if (geteuid() != ap_unixd_config.user_id)
    {
        struct passwd *pwent;

        pwent = getpwuid(geteuid());

        if (pwent)
        {
            if (chdir(pwent->pw_dir) == -1)
            {
                wsgi_log_error(APLOG_ALERT, errno, wsgi_server, WSGI_APLOGNO(0010)
                               "Unable to change working directory to "
                               "home directory '%s' for uid=%ld. "
                               "Daemon process will exit.",
                               pwent->pw_dir, (long)geteuid());

                return -1;
            }
        }
        else
        {
            wsgi_log_error(APLOG_ALERT, errno, wsgi_server, WSGI_APLOGNO(0011)
                           "Unable to determine home directory for "
                           "uid=%ld. Daemon process will exit.",
                           (long)geteuid());

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

    if (ap_coredumpdir_configured)
    {
        if (prctl(PR_SET_DUMPABLE, 1))
        {
            wsgi_log_error(APLOG_WARNING, errno, wsgi_server, WSGI_APLOGNO(0061)
                           "Unable to set process dumpable flag in "
                           "Apache child; coredumps will not be produced "
                           "after software errors.");
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

    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Socket for '%s' is '%s'.",
                   process->name, process->socket_path);

    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        wsgi_log_error(APLOG_ALERT, errno, wsgi_server, WSGI_APLOGNO(0012)
                       "Unable to create unix domain socket for daemon "
                       "process '%s'. Daemon group will not start.",
                       process->name);
        return -1;
    }

#ifdef SO_SNDBUF
    if (sendsz)
    {
        if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF,
                       (void *)&sendsz, sizeof(sendsz)) == -1)
        {
            wsgi_log_error(APLOG_WARNING, errno, wsgi_server, WSGI_APLOGNO(0062)
                           "Unable to set send buffer size on daemon "
                           "process socket; default size will be used.");
        }
    }
#endif
#ifdef SO_RCVBUF
    if (recvsz)
    {
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF,
                       (void *)&recvsz, sizeof(recvsz)) == -1)
        {
            wsgi_log_error(APLOG_WARNING, errno, wsgi_server, WSGI_APLOGNO(0063)
                           "Unable to set receive buffer size on daemon "
                           "process socket; default size will be used.");
        }
    }
#endif

    if (strlen(process->socket_path) > sizeof(addr.sun_path))
    {
        wsgi_log_error(APLOG_WARNING, 0, wsgi_server, WSGI_APLOGNO(0064)
                       "Length of path for daemon process socket exceeds "
                       "maximum allowed value and will be truncated; the "
                       "subsequent bind() is likely to fail.");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    apr_cpystrn(addr.sun_path, process->socket_path, sizeof(addr.sun_path));

    omask = umask(0077);
    rc = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    if (rc < 0 && errno == EADDRINUSE)
    {
        wsgi_log_error(APLOG_WARNING, errno, wsgi_server, WSGI_APLOGNO(0065)
                       "Removing stale unix domain socket '%s' before "
                       "re-binding daemon process listener.",
                       process->socket_path);

        unlink(process->socket_path);

        rc = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    }

    umask(omask);

    if (rc < 0)
    {
        wsgi_log_error(APLOG_ALERT, errno, wsgi_server, WSGI_APLOGNO(0013)
                       "Unable to bind unix domain socket '%s'. "
                       "Daemon group will not start.",
                       process->socket_path);

        close(sockfd);

        return -1;
    }

    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Listen backlog for socket '%s' is '%d'.",
                   process->socket_path, process->listen_backlog);

    if (listen(sockfd, process->listen_backlog) < 0)
    {
        wsgi_log_error(APLOG_ALERT, errno, wsgi_server, WSGI_APLOGNO(0014)
                       "Unable to listen on unix domain socket '%s'. "
                       "Daemon group will not start.",
                       process->socket_path);

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

    if (!geteuid())
    {
#if defined(MPM_ITK) || defined(ITK_MPM)
        uid_t socket_uid = process->uid;
#else
        uid_t socket_uid = ap_unixd_config.user_id;
#endif

        if (process->socket_user)
            socket_uid = ap_uname2id(process->socket_user);

        if (chown(process->socket_path, socket_uid, -1) < 0)
        {
            wsgi_log_error(APLOG_ALERT, errno, wsgi_server, WSGI_APLOGNO(0015)
                           "Unable to change owner of unix domain socket "
                           "'%s' to uid=%ld. Daemon group will not start.",
                           process->socket_path, (long)socket_uid);

            close(sockfd);

            return -1;
        }
    }

    return sockfd;
}

int wsgi_hook_daemon_handler(conn_rec *c);

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

    sbh = NULL;

    c = (conn_rec *)apr_pcalloc(p, sizeof(conn_rec));

    c->sbh = sbh;

    c->conn_config = ap_create_conn_config(p);
    c->notes = apr_table_make(p, 5);
    c->pool = p;

    if ((rv = apr_socket_addr_get(&c->local_addr, APR_LOCAL, sock)) != APR_SUCCESS)
    {
        wsgi_log_error(APLOG_INFO, rv, wsgi_server,
                       "Failed call apr_socket_addr_get(APR_LOCAL).");
        apr_socket_close(sock);
        return;
    }
    apr_sockaddr_ip_get(&c->local_ip, c->local_addr);

    if ((rv = apr_socket_addr_get(&c->client_addr, APR_REMOTE, sock)) != APR_SUCCESS)
    {
        wsgi_log_error(APLOG_INFO, rv, wsgi_server,
                       "Failed call apr_socket_addr_get(APR_REMOTE).");
        apr_socket_close(sock);
        return;
    }
    c->client_ip = "unknown";

    c->base_server = daemon->group->server;

    c->bucket_alloc = bucket_alloc;
    c->id = 1;

    net = apr_palloc(c->pool, sizeof(core_net_rec));

    if (daemon->group->socket_timeout)
        rv = apr_socket_timeout_set(sock, daemon->group->socket_timeout);
    else
        rv = apr_socket_timeout_set(sock, c->base_server->timeout);

    if (rv != APR_SUCCESS)
    {
        wsgi_log_error(APLOG_DEBUG, rv, wsgi_server,
                       "Failed call apr_socket_timeout_set().");
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

    while (1)
    {
        apr_uint32_t state = stack->state;
        if (state & (WSGI_STACK_TERMINATED | WSGI_STACK_NO_LISTENER))
        {
            if (state & WSGI_STACK_TERMINATED)
            {
                return APR_EINVAL;
            }
            if (apr_atomic_cas32(&(stack->state), WSGI_STACK_LAST, state) !=
                state)
            {
                continue;
            }
            else
            {
                return APR_SUCCESS;
            }
        }
        thread->next = state;
        if (apr_atomic_cas32(&(stack->state), (unsigned)id, state) != state)
        {
            continue;
        }
        else
        {
            apr_status_t rv;

            if (thread->wakeup)
            {
                thread->wakeup = 0;

                return APR_SUCCESS;
            }

            rv = apr_thread_cond_wait(thread->condition, thread->mutex);

            while (rv == APR_SUCCESS && !thread->wakeup)
                rv = apr_thread_cond_wait(thread->condition, thread->mutex);

            if (rv != APR_SUCCESS)
            {
                wsgi_log_error(APLOG_CRIT, rv, wsgi_server, WSGI_APLOGNO(0016)
                               "Wait on thread %d wakeup condition "
                               "variable failed; worker thread will exit.",
                               id);
            }

            thread->wakeup = 0;

            return rv;
        }
    }
}

static apr_status_t wsgi_worker_release(void)
{
    WSGIThreadStack *stack = wsgi_worker_stack;

    while (1)
    {
        apr_uint32_t state = stack->state;
        unsigned int first = state & WSGI_STACK_HEAD;
        if (first == WSGI_STACK_LAST)
        {
            if (apr_atomic_cas32(&(stack->state),
                                 state | WSGI_STACK_NO_LISTENER,
                                 state) != state)
            {
                continue;
            }
            else
            {
                return APR_SUCCESS;
            }
        }
        else
        {
            WSGIDaemonThread *thread = &wsgi_worker_threads[first];
            if (apr_atomic_cas32(&(stack->state),
                                 (state ^ first) | thread->next,
                                 state) != state)
            {
                continue;
            }
            else
            {
                /*
                 * Flag that thread should be woken up and then
                 * signal it via the condition variable.
                 */

                apr_status_t rv;
                if ((rv = apr_thread_mutex_lock(thread->mutex)) !=
                    APR_SUCCESS)
                {
                    return rv;
                }

                thread->wakeup = 1;

                if ((rv = apr_thread_mutex_unlock(thread->mutex)) !=
                    APR_SUCCESS)
                {
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

    while (1)
    {
        apr_uint32_t state = stack->state;
        if (apr_atomic_cas32(&(stack->state), state | WSGI_STACK_TERMINATED,
                             state) == state)
        {
            break;
        }
    }
    for (i = 0; i < wsgi_daemon_process->group->threads; i++)
    {
        if ((rv = wsgi_worker_release()) != APR_SUCCESS)
        {
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
    apr_pollfd_t pfd = {0};
    apr_int32_t numdesc;
    const apr_pollfd_t *pdesc;

    apr_bucket_alloc_t *bucket_alloc;

    WSGIDaemonProcess *daemon = thread->process;
    WSGIProcessGroup *group = daemon->group;

    /* Loop until signal received to shutdown daemon process. */

    while (!wsgi_daemon_shutdown)
    {
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

        if (wsgi_daemon_draining)
        {
            /*
             * Request-timeout drain in progress. Don't compete
             * for the cross-process accept mutex so peer daemons
             * in this process group absorb new connections. Hand
             * listener status to the next worker on the stack so
             * it can observe the drain and exit similarly. The
             * drain-complete check below and the graceful-timer
             * expiry in the monitor thread will take this process
             * down once in-flight requests finish or the timer
             * expires, respectively.
             */

            wsgi_worker_release();

            break;
        }

        if (group->mutex)
        {
            /*
             * Grab the accept mutex across all daemon processes
             * in this process group.
             */

            rv = apr_proc_mutex_lock(group->mutex);

            if (rv != APR_SUCCESS)
            {
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

                if (!wsgi_daemon_shutdown)
                {
                    wsgi_log_error(APLOG_CRIT, rv, wsgi_server, WSGI_APLOGNO(0017)
                                   "Unable to acquire accept mutex '%s'. "
                                   "Daemon process will shut down.",
                                   group->socket_path);

                    /*
                     * SIGTERM the daemon's main thread so it observes
                     * the shutdown signal via the signal pipe and
                     * starts the orderly shutdown sequence. The brief
                     * sleep here is to give the main thread a chance
                     * to act before this worker thread breaks out of
                     * its loop; it is not an anti-fork-bomb guard.
                     */

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

            if (wsgi_daemon_shutdown)
            {
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

        if (rv != APR_SUCCESS && !APR_STATUS_IS_EINTR(rv))
        {
            wsgi_log_error(APLOG_CRIT, rv, wsgi_server, WSGI_APLOGNO(0018)
                           "Unable to poll daemon socket for '%s'. "
                           "Daemon process will shut down.",
                           group->socket_path);

            /*
             * SIGTERM the daemon's main thread so it observes the
             * shutdown signal via the signal pipe. The brief sleep
             * gives the main thread a chance to act before this
             * worker breaks out of its loop; it is not an
             * anti-fork-bomb guard.
             */

            wsgi_daemon_shutdown++;
            kill(getpid(), SIGTERM);
            sleep(5);

            break;
        }

        if (wsgi_daemon_shutdown)
        {
            if (group->mutex)
                apr_proc_mutex_unlock(group->mutex);

            wsgi_worker_release();

            apr_pool_destroy(ptrans);

            break;
        }

        if (rv != APR_SUCCESS && APR_STATUS_IS_EINTR(rv))
        {
            if (group->mutex)
                apr_proc_mutex_unlock(group->mutex);

            wsgi_worker_release();

            apr_pool_destroy(ptrans);

            continue;
        }

        thread->running = 1;

        status = apr_socket_accept(&socket, daemon->listener, ptrans);

        if (group->mutex)
        {
            apr_status_t rv;
            rv = apr_proc_mutex_unlock(group->mutex);

            if (rv != APR_SUCCESS)
            {
                if (!wsgi_daemon_shutdown)
                {
                    wsgi_worker_release();

                    wsgi_log_error(APLOG_CRIT, rv, wsgi_server, WSGI_APLOGNO(0019)
                                   "Unable to release accept mutex '%s'; "
                                   "worker thread will exit.",
                                   group->socket_path);

                    apr_pool_destroy(ptrans);
                    thread->running = 0;

                    break;
                }
            }
        }

        wsgi_worker_release();

        if (status != APR_SUCCESS && APR_STATUS_IS_EINTR(status))
        {
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

        if (daemon->group->maximum_requests)
        {
            if (--wsgi_request_count <= 0)
            {
                if (wsgi_graceful_timeout && wsgi_active_requests)
                {
                    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                   "Maximum requests reached, attempt a "
                                   "graceful shutdown '%s'.",
                                   daemon->group->name);

                    apr_thread_mutex_lock(wsgi_monitor_lock);
                    wsgi_graceful_shutdown_time = apr_time_now();
                    wsgi_graceful_shutdown_time += wsgi_graceful_timeout;
                    apr_thread_mutex_unlock(wsgi_monitor_lock);
                }
                else
                {
                    if (!wsgi_daemon_shutdown)
                    {
                        wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                       "Maximum requests reached, "
                                       "triggering immediate shutdown "
                                       "'%s'.", daemon->group->name);
                    }

                    wsgi_daemon_shutdown++;
                    kill(getpid(), SIGINT);
                }
            }
        }

        /* Check if graceful shutdown and no active requests. */

        if ((wsgi_daemon_graceful || wsgi_daemon_draining) &&
            !wsgi_daemon_shutdown)
        {
            if (wsgi_active_requests == 0)
            {
                wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                               "Requests have completed, triggering "
                               "immediate shutdown '%s'.",
                               daemon->group->name);

                wsgi_daemon_shutdown++;
                kill(getpid(), SIGINT);
            }
        }
    }

    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Exiting thread %d in daemon process '%s'.",
                   thread->id, thread->process->group->name);
}

static void *wsgi_daemon_thread(apr_thread_t *thd, void *data)
{
    WSGIDaemonThread *thread = data;
    apr_pool_t *p = apr_thread_pool_get(thd);

    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Started thread %d in daemon process '%s'.",
                   thread->id, thread->process->group->name);

    apr_thread_mutex_lock(thread->mutex);

    wsgi_daemon_worker(p, thread);

    apr_thread_exit(thd, APR_SUCCESS);

    return NULL;
}

static void *wsgi_reaper_thread(apr_thread_t *thd, void *data)
{
    WSGIDaemonProcess *daemon = data;

    sleep(daemon->group->shutdown_timeout);

    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                   "Aborting process '%s'.", daemon->group->name);

    wsgi_exit_daemon_process(-1);

    return NULL;
}

static void *wsgi_deadlock_thread(apr_thread_t *thd, void *data)
{
    WSGIDaemonProcess *daemon = data;

    PyGILState_STATE gilstate;

    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Enable deadlock thread in process '%s'.",
                   daemon->group->name);

    apr_thread_mutex_lock(wsgi_monitor_lock);
    wsgi_deadlock_shutdown_time = apr_time_now();
    wsgi_deadlock_shutdown_time += wsgi_deadlock_timeout;
    apr_thread_mutex_unlock(wsgi_monitor_lock);

    while (1)
    {
        apr_sleep(apr_time_from_sec(1));

        apr_thread_mutex_lock(wsgi_shutdown_lock);

        if (!wsgi_daemon_shutdown)
        {
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

    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Enable monitor thread in process '%s'.", group->name);

    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Startup timeout is %d.",
                   (int)(apr_time_sec(wsgi_startup_timeout)));
    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Deadlock timeout is %d.",
                   (int)(apr_time_sec(wsgi_deadlock_timeout)));
    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Idle inactivity timeout is %d.",
                   (int)(apr_time_sec(wsgi_idle_timeout)));
    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Request time limit is %d.",
                   (int)(apr_time_sec(wsgi_request_timeout)));
    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Graceful timeout is %d.",
                   (int)(apr_time_sec(wsgi_graceful_timeout)));
    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Eviction timeout is %d.",
                   (int)(apr_time_sec(wsgi_eviction_timeout)));
    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Restart interval is %d.",
                   (int)(apr_time_sec(wsgi_restart_interval)));

    /*
     * If a restart interval was specified then set up the time for
     * when the restart should occur.
     */

    if (wsgi_restart_interval)
    {
        wsgi_restart_shutdown_time = apr_time_now();
        wsgi_restart_shutdown_time += wsgi_restart_interval;
    }

    while (1)
    {
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

        if (wsgi_request_timeout && wsgi_worker_threads)
        {
            for (i = 0; i < wsgi_daemon_process->group->threads; i++)
            {
                if (wsgi_worker_threads[i].request)
                    request_time += (now - wsgi_worker_threads[i].request);
            }
        }

        request_time /= wsgi_daemon_process->group->threads;

        apr_thread_mutex_unlock(wsgi_monitor_lock);

        if (!restart && wsgi_request_timeout)
        {
            if (request_time > wsgi_request_timeout)
            {
                if (!wsgi_daemon_graceful && !wsgi_daemon_draining)
                {
                    wsgi_shutdown_reason = "request_timeout";

                    wsgi_dump_stack_traces = 1;

                    if (group->processes > 1 && wsgi_graceful_timeout)
                    {
                        /*
                         * Multi-process group with a graceful window
                         * configured: stop accepting new work on this
                         * daemon so peer daemons absorb the load,
                         * letting healthy in-flight requests finish.
                         * The stuck request(s) are interrupted when
                         * the graceful timer expires.
                         */

                        wsgi_daemon_draining++;

                        apr_thread_mutex_lock(wsgi_monitor_lock);
                        wsgi_graceful_shutdown_time = apr_time_now();
                        wsgi_graceful_shutdown_time += wsgi_graceful_timeout;
                        apr_thread_mutex_unlock(wsgi_monitor_lock);

                        wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                       "Daemon process request time limit "
                                       "exceeded; draining process '%s' for "
                                       "up to %d seconds, peer daemons will "
                                       "absorb new requests.", group->name,
                                     (int)apr_time_sec(wsgi_graceful_timeout));
                    }
                    else
                    {
                        /*
                         * Single-process group or no graceful-timeout
                         * configured: fall back to today's abrupt
                         * restart. With no peer to absorb work, a
                         * drain would just pile connections in the
                         * OS backlog without benefit.
                         */

                        wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                       "Daemon process request time limit "
                                       "exceeded, stopping process '%s'.",
                                       group->name);

                        restart = 1;
                    }
                }
            }
        }

        if (!restart && wsgi_startup_timeout)
        {
            if (startup_time > 0)
            {
                if (startup_time <= now)
                {
                    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                   "Application startup timer expired, "
                                   "stopping process '%s'.", group->name);

                    wsgi_shutdown_reason = "startup_timeout";

                    restart = 1;
                }
                else
                {
                    period = startup_time - now;
                }
            }
        }

        if (!restart && wsgi_restart_interval)
        {
            if (restart_time > 0)
            {
                if (restart_time <= now)
                {
                    if (!wsgi_daemon_graceful)
                    {
                        if (wsgi_active_requests)
                        {
                            wsgi_daemon_graceful++;

                            apr_thread_mutex_lock(wsgi_monitor_lock);
                            wsgi_graceful_shutdown_time = apr_time_now();
                            wsgi_graceful_shutdown_time += wsgi_graceful_timeout;
                            apr_thread_mutex_unlock(wsgi_monitor_lock);

                            wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                           "Application restart timer "
                                           "expired, waiting for requests "
                                           "to complete '%s'.",
                                           daemon->group->name);
                        }
                        else
                        {
                            wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                           "Application restart timer "
                                           "expired, stopping process "
                                           "'%s'.", daemon->group->name);

                            wsgi_shutdown_reason = "restart_interval";

                            restart = 1;
                        }
                    }
                }
                else
                {
                    if (!period || ((restart_time - now) < period))
                        period = restart_time - now;
                }
            }
        }

        if (!restart && wsgi_deadlock_timeout)
        {
            if (deadlock_time)
            {
                if (deadlock_time <= now)
                {
                    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                   "Daemon process deadlock timer expired, "
                                   "stopping process '%s'.", group->name);

                    restart = 1;
                }
                else
                {
                    if (!period || ((deadlock_time - now) < period))
                        period = deadlock_time - now;
                }
            }
            else
            {
                if (!period || (wsgi_deadlock_timeout < period))
                    period = wsgi_deadlock_timeout;
            }
        }

        if (!restart && wsgi_idle_timeout)
        {
            if (idle_time)
            {
                if (idle_time <= now)
                {
                    if (wsgi_active_requests == 0)
                    {
                        wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                       "Daemon process idle inactivity "
                                       "timer expired, stopping process "
                                       "'%s'.", group->name);

                        wsgi_shutdown_reason = "inactivity_timeout";

                        restart = 1;
                    }
                    else
                    {
                        /* Ignore for now as still have requests. */

                        if (!period || (wsgi_idle_timeout < period))
                            period = wsgi_idle_timeout;
                    }
                }
                else
                {
                    if (!period || ((idle_time - now) < period))
                        period = idle_time - now;
                }
            }
            else
            {
                if (!period || (wsgi_idle_timeout < period))
                    period = wsgi_idle_timeout;
            }
        }

        if (!restart && wsgi_graceful_timeout)
        {
            if (graceful_time)
            {
                if (graceful_time <= now)
                {
                    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                   "Daemon process graceful timer "
                                   "expired '%s'.", group->name);

                    restart = 1;
                }
                else
                {
                    if (!period || ((graceful_time - now) < period))
                        period = graceful_time - now;
                    else if (wsgi_graceful_timeout < period)
                        period = wsgi_graceful_timeout;
                }
            }
            else
            {
                if (!period || (wsgi_graceful_timeout < period))
                    period = wsgi_graceful_timeout;
            }
        }

        if (!restart && wsgi_eviction_timeout)
        {
            if (graceful_time)
            {
                if (graceful_time <= now)
                {
                    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                   "Daemon process graceful timer "
                                   "expired '%s'.", group->name);

                    restart = 1;
                }
                else
                {
                    if (!period || ((graceful_time - now) < period))
                        period = graceful_time - now;
                    else if (wsgi_eviction_timeout < period)
                        period = wsgi_eviction_timeout;
                }
            }
            else
            {
                if (!period || (wsgi_eviction_timeout < period))
                    period = wsgi_eviction_timeout;
            }
        }

        if (restart)
        {
            wsgi_daemon_shutdown++;
            kill(getpid(), SIGINT);
        }

        if (restart || wsgi_request_timeout || period <= 0 ||
            (wsgi_startup_timeout && !wsgi_startup_shutdown_time))
        {
            period = apr_time_from_sec(1);
        }

        apr_sleep(period);
    }

    return NULL;
}

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

    if (threads && PyDict_Size(threads) != 0)
    {
        PyObject *seq = NULL;

        seq = PyObject_GetIter(threads);

        if (seq)
        {
            PyObject *id = NULL;
            PyObject *frame = NULL;

            Py_ssize_t i = 0;

            wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                           "Dumping stack trace for active Python "
                           "threads.");

            while (PyDict_Next(threads, &i, &id, &frame))
            {
                apr_int64_t thread_id = 0;

                PyFrameObject *current = NULL;

                thread_id = PyLong_AsLong(id);

                current = (PyFrameObject *)frame;

                while (current)
                {
                    int lineno;

                    const char *filename = NULL;
                    const char *name = NULL;

                    lineno = PyFrame_GetLineNumber(current);

                    filename = PyUnicode_AsUTF8(PyFrame_GetCode(current)->co_filename);
                    name = PyUnicode_AsUTF8(PyFrame_GetCode(current)->co_name);

                    if (current == (PyFrameObject *)frame)
                    {
                        wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                       "Thread %" APR_INT64_T_FMT
                                       " executing file \"%s\", line "
                                       "%d, in %s",
                                       thread_id, filename, lineno, name);
                    }
                    else
                    {
                        if (PyFrame_GetBack(current))
                        {
                            wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                           "called from file \"%s\", "
                                           "line %d, in %s,",
                                           filename, lineno, name);
                        }
                        else
                        {
                            wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                           "called from file \"%s\", "
                                           "line %d, in %s.",
                                           filename, lineno, name);
                        }
                    }

                    current = PyFrame_GetBack(current);
                }
            }
        }
        else
        {
            wsgi_log_error(APLOG_WARNING, 0, wsgi_server, WSGI_APLOGNO(0066)
                           "Unable to iterate over current frames for "
                           "active threads; stack-trace dump will be "
                           "incomplete.");

            PyErr_Print();
            PyErr_Clear();
        }
    }
    else
    {
        wsgi_log_error(APLOG_WARNING, 0, wsgi_server, WSGI_APLOGNO(0067)
                       "Unable to obtain current frames for active "
                       "threads; stack-trace dump will be skipped.");

        PyErr_Print();
        PyErr_Clear();
    }

    Py_XDECREF(threads);

    PyGILState_Release(state);
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
    if (daemon->group->stack_size)
    {
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

    if (wsgi_deadlock_timeout || wsgi_idle_timeout)
    {
        rv = apr_thread_create(&reaper, thread_attr, wsgi_monitor_thread,
                               daemon, p);

        if (rv != APR_SUCCESS)
        {
            wsgi_log_error(APLOG_ERR, rv, wsgi_server, WSGI_APLOGNO(0068)
                           "Unable to create monitor thread in daemon "
                           "process '%s'; request and idle timeouts will "
                           "not be enforced.", daemon->group->name);
        }
    }

    if (wsgi_deadlock_timeout)
    {
        rv = apr_thread_create(&reaper, thread_attr, wsgi_deadlock_thread,
                               daemon, p);

        if (rv != APR_SUCCESS)
        {
            wsgi_log_error(APLOG_ERR, rv, wsgi_server, WSGI_APLOGNO(0069)
                           "Unable to create deadlock-detection thread "
                           "in daemon process '%s'; deadlock timeouts "
                           "will not be enforced.", daemon->group->name);
        }
    }

    /* Start telemetry reporter if configured. */

    wsgi_telemetry_start_reporter(p);

    /* Initialise worker stack. */

    wsgi_worker_stack = (WSGIThreadStack *)apr_palloc(p,
                                                      sizeof(WSGIThreadStack));
    wsgi_worker_stack->state = WSGI_STACK_NO_LISTENER | WSGI_STACK_LAST;

    /* Start the required number of threads. */

    wsgi_worker_threads = (WSGIDaemonThread *)apr_pcalloc(p,
                                                          daemon->group->threads * sizeof(WSGIDaemonThread));

    wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                   "Starting %d threads in daemon process '%s'.",
                   daemon->group->threads, daemon->group->name);

    for (i = 0; i < daemon->group->threads; i++)
    {
        WSGIDaemonThread *thread = &wsgi_worker_threads[i];

        wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                       "Starting thread %d in daemon process '%s'.",
                       i + 1, daemon->group->name);

        /* Create the mutex and condition variable for this thread. */

        rv = apr_thread_cond_create(&thread->condition, p);

        if (rv != APR_SUCCESS)
        {
            wsgi_log_error(APLOG_ALERT, rv, wsgi_server, WSGI_APLOGNO(0020)
                           "Unable to create worker thread %d condition "
                           "variable in daemon process '%s'. Daemon "
                           "process will exit and be restarted after "
                           "a delay.",
                           i, daemon->group->name);

            wsgi_daemon_init_failure_exit();
        }

        rv = apr_thread_mutex_create(&thread->mutex,
                                     APR_THREAD_MUTEX_DEFAULT, p);

        if (rv != APR_SUCCESS)
        {
            wsgi_log_error(APLOG_ALERT, rv, wsgi_server, WSGI_APLOGNO(0021)
                           "Unable to create worker thread %d mutex in "
                           "daemon process '%s'. Daemon process will "
                           "exit and be restarted after a delay.",
                           i, daemon->group->name);

            wsgi_daemon_init_failure_exit();
        }

        /* Now create the actual thread. */

        thread->id = i;
        thread->process = daemon;
        thread->running = 0;
        thread->request = 0;

        rv = apr_thread_create(&thread->thread, thread_attr,
                               wsgi_daemon_thread, thread, p);

        if (rv != APR_SUCCESS)
        {
            wsgi_log_error(APLOG_ALERT, rv, wsgi_server, WSGI_APLOGNO(0022)
                           "Unable to create worker thread %d in daemon "
                           "process '%s'. Daemon process will exit and "
                           "be restarted after a delay.",
                           i, daemon->group->name);

            wsgi_daemon_init_failure_exit();
        }
    }

    /* Block until we get a process shutdown signal. */

    while (1)
    {
        char buf[1];
        apr_size_t nbytes = 1;

        rv = apr_poll(&poll_fd, 1, &poll_count, -1);
        if (APR_STATUS_IS_EINTR(rv))
            continue;

        rv = apr_file_read(wsgi_signal_pipe_in, buf, &nbytes);

        if (rv != APR_SUCCESS || nbytes != 1)
        {
            wsgi_log_error(APLOG_ALERT, 0, wsgi_server, WSGI_APLOGNO(0023)
                           "Read failed on signal pipe in daemon process "
                           "'%s'; daemon process will shut down.",
                           daemon->group->name);

            break;
        }

        if (buf[0] == 'C')
        {
            if (!wsgi_daemon_graceful)
            {
                wsgi_shutdown_reason = "cpu_time_limit";

                if (wsgi_active_requests)
                {
                    wsgi_daemon_graceful++;

                    apr_thread_mutex_lock(wsgi_monitor_lock);
                    wsgi_graceful_shutdown_time = apr_time_now();
                    wsgi_graceful_shutdown_time += wsgi_graceful_timeout;
                    apr_thread_mutex_unlock(wsgi_monitor_lock);

                    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                   "Exceeded CPU time limit, waiting for "
                                   "requests to complete '%s'.",
                                   daemon->group->name);
                }
                else
                {
                    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                   "Exceeded CPU time limit, triggering "
                                   "immediate shutdown '%s'.",
                                   daemon->group->name);

                    wsgi_daemon_shutdown++;
                    kill(getpid(), SIGINT);
                }
            }
        }
        else if (buf[0] == 'G')
        {
            if (!wsgi_daemon_graceful)
            {
                wsgi_shutdown_reason = "graceful_signal";

                if (wsgi_active_requests)
                {
                    wsgi_daemon_graceful++;

                    apr_thread_mutex_lock(wsgi_monitor_lock);
                    wsgi_graceful_shutdown_time = apr_time_now();
                    if (wsgi_eviction_timeout)
                        wsgi_graceful_shutdown_time += wsgi_eviction_timeout;
                    else
                        wsgi_graceful_shutdown_time += wsgi_graceful_timeout;
                    apr_thread_mutex_unlock(wsgi_monitor_lock);

                    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                   "Process eviction requested, waiting "
                                   "for requests to complete '%s'.",
                                   daemon->group->name);
                }
                else
                {
                    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                                   "Process eviction requested, "
                                   "triggering immediate shutdown '%s'.",
                                   daemon->group->name);

                    wsgi_daemon_shutdown++;
                    kill(getpid(), SIGINT);
                }
            }
        }
        else
            break;
    }

    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                   "Shutdown requested '%s'.", daemon->group->name);

    /*
     * Create a reaper thread to abort process if graceful
     * shutdown takes too long. Not recommended to disable
     * this unless external process is controlling shutdown.
     */

    if (daemon->group->shutdown_timeout)
    {
        rv = apr_thread_create(&reaper, thread_attr, wsgi_reaper_thread,
                               daemon, p);

        if (rv != APR_SUCCESS)
        {
            wsgi_log_error(APLOG_WARNING, rv, wsgi_server, WSGI_APLOGNO(0070)
                           "Unable to create reaper thread in daemon "
                           "process '%s'; shutdown timeout will not be "
                           "enforced.", daemon->group->name);
        }
    }

    /*
     * If shutting down process due to reaching request time
     * limit, then try and dump out stack traces of any threads
     * which are running as a debugging aid.
     */

    wsgi_publish_process_stopping(wsgi_shutdown_reason);

    if (wsgi_dump_stack_traces)
        wsgi_log_stack_traces();

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

    for (i = 0; i < daemon->group->threads; i++)
    {
        if (wsgi_worker_threads[i].thread && wsgi_worker_threads[i].running)
        {
            rv = apr_thread_join(&thread_rv, wsgi_worker_threads[i].thread);
            if (rv != APR_SUCCESS)
            {
                wsgi_log_error(APLOG_WARNING, rv, wsgi_server, WSGI_APLOGNO(0071)
                               "Unable to join with worker thread %d in "
                               "daemon process '%s' during shutdown.",
                               i, daemon->group->name);
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

    if (group->listener_fd != -1)
    {
        if (close(group->listener_fd) < 0)
        {
            wsgi_log_error(APLOG_WARNING, errno, wsgi_server, WSGI_APLOGNO(0072)
                           "Unable to close unix domain socket '%s' "
                           "during daemon process group cleanup.",
                           group->socket_path);
        }

        if (unlink(group->socket_path) < 0 && errno != ENOENT)
        {
            wsgi_log_error(APLOG_WARNING, errno, wsgi_server, WSGI_APLOGNO(0073)
                           "Unable to unlink unix domain socket '%s' "
                           "during daemon process group cleanup.",
                           group->socket_path);
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

    if ((status = apr_proc_fork(&daemon->process, p)) < 0)
    {
        wsgi_log_error(APLOG_ALERT, errno, wsgi_server, WSGI_APLOGNO(0024)
                       "Unable to spawn daemon process '%s'. "
                       "Daemon group will not start.",
                       daemon->group->name);
        return DECLINED;
    }
    else if (status == APR_INCHILD)
    {
        if (!geteuid())
        {
            wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                           "Starting process '%s' with uid=%ld, gid=%u "
                           "and threads=%d.",
                           daemon->group->name, (long)daemon->group->uid,
                           (unsigned)daemon->group->gid,
                           daemon->group->threads);
        }
        else
        {
            wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                           "Starting process '%s' with threads=%d.",
                           daemon->group->name, daemon->group->threads);
        }

#ifdef HAVE_BINDPROCESSOR
        /*
         * By default, AIX binds to a single processor.  This
         * bit unbinds children which will then bind to another
         * CPU.
         */

        status = bindprocessor(BINDPROCESS, (int)getpid(),
                               PROCESSOR_CLASS_ANY);
        if (status != OK)
        {
            wsgi_log_error(APLOG_WARNING, errno, wsgi_server, WSGI_APLOGNO(0074)
                           "Unable to unbind processor for daemon "
                           "process; daemon will run with default CPU "
                           "affinity.");
        }
#endif

        /* Setup daemon process name displayed by 'ps'. */

        wsgi_setup_daemon_name(daemon, p);

        /* Adjust CPU priority if overridden. */

        if (daemon->group->cpu_priority != 0)
        {
            if (setpriority(PRIO_PROCESS, 0,
                            daemon->group->cpu_priority) == -1)
            {
                wsgi_log_error(APLOG_WARNING, errno, wsgi_server, WSGI_APLOGNO(0075)
                               "Unable to set CPU priority of %d for "
                               "daemon process '%s'; daemon will run "
                               "with default priority.",
                               daemon->group->cpu_priority,
                               daemon->group->name);
            }
        }

        /* Setup daemon process user/group/umask etc. */

        if (wsgi_setup_access(daemon) == -1)
        {
            wsgi_log_error(APLOG_ALERT, 0, wsgi_server, WSGI_APLOGNO(0025)
                           "Daemon process configuration failed; process "
                           "left in unspecified state. Daemon process "
                           "will exit and be restarted after a delay.");

            wsgi_daemon_init_failure_exit();
        }

        /* Reinitialise accept mutex in daemon process. */

        if (daemon->group->mutex)
        {
            status = apr_proc_mutex_child_init(&daemon->group->mutex,
                                               daemon->group->mutex_path, p);

            if (status != APR_SUCCESS)
            {
                wsgi_log_error(APLOG_CRIT, 0, wsgi_server, WSGI_APLOGNO(0026)
                               "Unable to initialise accept mutex '%s' "
                               "in daemon process. Daemon process will "
                               "exit and be restarted after a delay.",
                               daemon->group->mutex_path);

                wsgi_daemon_init_failure_exit();
            }
        }

        /*
         * Create a lookup table of listener socket address
         * details so can use it later in daemon when trying
         * to map request to correct virtual host server.
         */

        wsgi_daemon_listeners = apr_hash_make(p);

        for (lr = ap_listeners; lr; lr = lr->next)
        {
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

        for (i = 0; i < wsgi_daemon_list->nelts; ++i)
        {
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

        for (i = 0; i < wsgi_daemon_list->nelts; ++i)
        {
            entry = &entries[i];

            if (entry != daemon->group && entry->listener_fd != -1)
            {
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

        if (status != APR_SUCCESS)
        {
            wsgi_log_error(APLOG_ALERT, status, wsgi_server, WSGI_APLOGNO(0027)
                           "Unable to initialise signal pipe in daemon "
                           "process '%s'. Daemon process will exit and "
                           "be restarted after a delay.",
                           daemon->group->name);

            wsgi_daemon_init_failure_exit();
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

        if (daemon->group->cpu_time_limit > 0)
        {
            struct rlimit limit;
            int result = -1;
            errno = ENOSYS;

            limit.rlim_cur = daemon->group->cpu_time_limit;

            limit.rlim_max = daemon->group->cpu_time_limit + 1;
            limit.rlim_max += daemon->group->shutdown_timeout;

#if defined(RLIMIT_CPU)
            result = setrlimit(RLIMIT_CPU, &limit);
#endif

            if (result == -1)
            {
                wsgi_log_error(APLOG_WARNING, errno, wsgi_server, WSGI_APLOGNO(0076)
                               "Unable to set CPU time limit of %d seconds "
                               "for daemon process '%s'; daemon will run "
                               "without the configured limit.",
                               daemon->group->cpu_time_limit,
                               daemon->group->name);
            }
        }

        /*
         * Set limits on amount of date segment memory that can
         * be used. Although this is done, some platforms
         * doesn't actually support it.
         */

        if (daemon->group->memory_limit > 0)
        {
            struct rlimit limit;
            int result = -1;
            errno = ENOSYS;

            limit.rlim_cur = daemon->group->memory_limit;

            limit.rlim_max = daemon->group->memory_limit;

#if defined(RLIMIT_DATA)
            result = setrlimit(RLIMIT_DATA, &limit);
#endif

            if (result == -1)
            {
                wsgi_log_error(APLOG_WARNING, errno, wsgi_server, WSGI_APLOGNO(0077)
                               "Unable to set memory limit of %ld for "
                               "daemon process '%s'; daemon will run "
                               "without the configured limit.",
                               (long)daemon->group->memory_limit,
                               daemon->group->name);
            }
        }

        /*
         * Set limits on amount of virtual memory that can be used.
         * Although this is done, some platforms doesn't actually
         * support it.
         */

        if (daemon->group->virtual_memory_limit > 0)
        {
            struct rlimit limit;
            int result = -1;
            errno = ENOSYS;

            limit.rlim_cur = daemon->group->virtual_memory_limit;

            limit.rlim_max = daemon->group->virtual_memory_limit;

#if defined(RLIMIT_AS)
            result = setrlimit(RLIMIT_AS, &limit);
#elif defined(RLIMIT_VMEM)
            result = setrlimit(RLIMIT_VMEM, &limit);
#endif

            if (result == -1)
            {
                wsgi_log_error(APLOG_WARNING, errno, wsgi_server, WSGI_APLOGNO(0078)
                               "Unable to set virtual memory limit of "
                               "%ld for daemon process '%s'; daemon "
                               "will run without the configured limit.",
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

        if (daemon->group->lang)
        {
            char *envvar;

            wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                           "Setting lang to %s for daemon process group "
                           "%s.", daemon->group->lang, daemon->group->name);

            envvar = apr_pstrcat(p, "LANG=", daemon->group->lang, NULL);
            putenv(envvar);
        }

        if (daemon->group->locale)
        {
            char *envvar;
            char *result;

            wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                           "Setting locale to %s for daemon process group "
                           "%s.",
                           daemon->group->locale, daemon->group->name);

            envvar = apr_pstrcat(p, "LC_ALL=", daemon->group->locale, NULL);
            putenv(envvar);

            result = setlocale(LC_ALL, daemon->group->locale);

            if (!result)
            {
                wsgi_log_error(APLOG_WARNING, 0, wsgi_server, WSGI_APLOGNO(0079)
                               "Unsupported locale setting '%s' "
                               "specified for daemon process group "
                               "'%s'; daemon will run with the inherited "
                               "locale. Consider 'C.UTF-8' as a "
                               "fallback.",
                               daemon->group->locale,
                               daemon->group->name);
            }
        }

        /* Create lock for request monitoring. */

        apr_thread_mutex_create(&wsgi_monitor_lock,
                                APR_THREAD_MUTEX_UNNESTED, p);

        /*
         * Initialise Python if required to be done in the child
         * process. If initialisation fails the daemon process is
         * essentially useless, but rather than exit (which Apache
         * would just respawn) log a critical error and continue.
         * The wsgi_python_initialized flag will remain 0 so code
         * paths gated on it will short circuit and request handlers
         * will return errors when Python operations are attempted.
         */

        if (wsgi_python_init(p) != APR_SUCCESS)
        {
            wsgi_log_error(APLOG_CRIT, 0, wsgi_server, WSGI_APLOGNO(0028)
                           "Python initialisation failed in daemon "
                           "process '%s'; Python based handlers will "
                           "not be available.",
                           daemon->group->name);
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

        if (daemon->group->server->is_virtual)
        {
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

            while (server != NULL)
            {
                if (server->error_log &&
                    server->error_log != daemon->group->server->error_log)
                {
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

            if (daemon->group->server->error_log &&
                daemon->group->server->error_log != wsgi_server->error_log)
            {

                apr_file_t *oldfile = NULL;

                apr_file_open_stderr(&errfile, wsgi_server->process->pool);
                apr_file_dup2(errfile, daemon->group->server->error_log,
                              wsgi_server->process->pool);

                oldfile = daemon->group->server->error_log;

                server = wsgi_server;

                while (server != NULL)
                {
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

        if (daemon->group->server)
        {
            wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                           "Process '%s' logging to '%s'.",
                           daemon->group->name,
                           daemon->group->server->server_hostname);

            wsgi_server = daemon->group->server;
        }
        else
        {
            wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                           "Process '%s' forced to log to '%s'.",
                           daemon->group->name,
                           wsgi_server->server_hostname);
        }

        /* Time daemon process started waiting for requests. */

        wsgi_restart_time = apr_time_now();

        /*
         * Setup Python in the child daemon process. We need
         * to perform the special Python setup which has to be
         * done after a fork. Skip this if Python initialisation
         * failed earlier as the interpreter is not usable.
         */

        if (wsgi_python_initialized)
        {
            wsgi_python_path = daemon->group->python_path;
            wsgi_python_eggs = daemon->group->python_eggs;

            if (wsgi_python_child_init(wsgi_daemon_pool) != APR_SUCCESS)
            {
                wsgi_log_error(APLOG_CRIT, 0, wsgi_server, WSGI_APLOGNO(0029)
                               "Python child initialisation failed in "
                               "daemon process '%s'; Python based "
                               "handlers will not be available.",
                               daemon->group->name);
            }
        }

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

        wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                       "Stopping process '%s'.", daemon->group->name);

        apr_pool_destroy(wsgi_daemon_pool);

        /* Exit the daemon process when being shutdown. */

        wsgi_exit_daemon_process(0);
    }

#ifdef HAVE_FORK
    if (wsgi_python_initialized)
    {
#if 0
        /*
         * XXX Appears to be wrong to call this at this point especially
         * since we haven't acquired the GIL. It wouldn't have been possible
         * for any user code to have registered a Python callback to run
         * in parent after fork either. Leave in code for now but disabled.
         */

        PyOS_AfterFork_Parent();
#endif
    }
#endif

    apr_pool_note_subprocess(p, &daemon->process, APR_KILL_AFTER_TIMEOUT);
    apr_proc_other_child_register(&daemon->process, wsgi_manage_process,
                                  daemon, NULL, p);

    return OK;
}

int wsgi_start_daemons(apr_pool_t *p)
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

    for (i = 0; i < wsgi_daemon_list->nelts; ++i)
    {
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

        if (entry->uid == ap_uname2id(DEFAULT_USER))
        {
            entry->uid = ap_unixd_config.user_id;
            entry->user = ap_unixd_config.user_name;

            wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                           "Reset default user for daemon process group "
                           "'%s' to uid=%ld.",
                           entry->name, (long)entry->uid);
        }

        if (entry->gid == ap_gname2id(DEFAULT_GROUP))
        {
            entry->gid = ap_unixd_config.group_id;

            wsgi_log_error(APLOG_DEBUG, 0, wsgi_server,
                           "Reset default group for daemon process group "
                           "'%s' to gid=%ld.",
                           entry->name, (long)entry->gid);
        }

        /*
         * Calculate path for socket to accept requests on and
         * create the socket.
         */

        entry->socket_rotation = wsgi_server_config->socket_rotation;

        if (entry->socket_rotation)
        {
            entry->socket_path = apr_psprintf(p, "%s.%d.%d.%d.sock",
                                              wsgi_server_config->socket_prefix,
                                              getpid(), mpm_generation, entry->id);
        }
        else
        {
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

        if (entry->processes > 1)
        {
            entry->mutex_path = apr_psprintf(p, "%s.%d.%d.%d.lock",
                                             wsgi_server_config->socket_prefix,
                                             getpid(), mpm_generation,
                                             entry->id);

            status = apr_proc_mutex_create(&entry->mutex, entry->mutex_path,
                                           wsgi_server_config->lock_mechanism,
                                           p);

            if (status != APR_SUCCESS)
            {
                wsgi_log_error(APLOG_CRIT, status, wsgi_server, WSGI_APLOGNO(0030)
                               "Unable to create accept lock '%s'. "
                               "Daemon group will not start.",
                               entry->mutex_path);
                return DECLINED;
            }

            /*
             * Depending on the locking mechanism being used
             * need to change the permissions of the lock. Can't
             * use unixd_set_proc_mutex_perms() as it uses the
             * default Apache child process uid/gid where the
             * daemon process uid/gid can be different.
             */

            if (!geteuid())
            {
#if APR_HAS_SYSVSEM_SERIALIZE
                if (!strcmp(apr_proc_mutex_name(entry->mutex), "sysvsem"))
                {
                    apr_os_proc_mutex_t ospmutex;
#if !APR_HAVE_UNION_SEMUN
                    union semun
                    {
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
                    if (semctl(ospmutex.crossproc, 0, IPC_SET, ick) < 0)
                    {
                        wsgi_log_error(APLOG_CRIT, errno, wsgi_server, WSGI_APLOGNO(0031)
                                       "Unable to set permissions on "
                                       "sysvsem accept mutex '%s'. "
                                       "Daemon group will not start.",
                                       entry->mutex_path);
                        return DECLINED;
                    }
                }
#endif
#if APR_HAS_FLOCK_SERIALIZE
                if (!strcmp(apr_proc_mutex_name(entry->mutex), "flock"))
                {
                    if (chown(entry->mutex_path, entry->uid, -1) < 0)
                    {
                        wsgi_log_error(APLOG_CRIT, errno, wsgi_server, WSGI_APLOGNO(0032)
                                       "Unable to set permissions on "
                                       "flock accept mutex '%s'. "
                                       "Daemon group will not start.",
                                       entry->mutex_path);
                        return DECLINED;
                    }
                }
#endif
            }
        }

        /* Create the actual required daemon processes. */

        for (j = 1; j <= entry->processes; j++)
        {
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

int wsgi_deferred_start_daemons(apr_pool_t *p, ap_scoreboard_e sb_type)
{
    return wsgi_start_daemons(wsgi_pconf_pool);
}

int wsgi_hook_daemon_handler(conn_rec *c)
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
    core_dir_config *d;

    const char *item;

    int queue_timeout_occurred = 0;

    apr_time_t daemon_start = 0;

    /* Don't do anything if not in daemon process. */

    if (!wsgi_daemon_pool)
        return DECLINED;

    /*
     * Mark this as start of daemon process even though connection
     * setup has already been done. Otherwise need to carry through
     * a time value somehow.
     */

    daemon_start = apr_time_now();

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

    r->request_config = ap_create_request_config(r->pool);

    r->proto_output_filters = c->output_filters;
    r->output_filters = r->proto_output_filters;
    r->proto_input_filters = c->input_filters;
    r->input_filters = r->proto_input_filters;

    r->trailers_in = apr_table_make(r->pool, 5);
    r->trailers_out = apr_table_make(r->pool, 5);

    r->per_dir_config = r->server->lookup_defaults;

    /*
     * Try and ensure that request body limit in daemon mode process
     * is unlimited as Apache 2.4.54 changed rules for limit and if
     * unset is now overridden by HTTP filters to be 1GiB rather than
     * unlimited. This is required since we populate configuration
     * from the base server config only so setting unlimited in a more
     * specific context such as a virtual host wouldn't be visible.
     * Note that setting this to unlimited in the daemon mode process
     * is okay as the request limit body is checked in the Apache
     * child process before request is proxied specifically to avoid
     * unecessarily passing the content across to the daemon process.
     */

    d = (core_dir_config *)ap_get_core_module_config(r->per_dir_config);

    d->limit_req_body = 0;

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

    if ((rv = wsgi_read_request(csd, r)) != APR_SUCCESS)
    {
        wsgi_log_error(APLOG_ERR, rv, wsgi_server, WSGI_APLOGNO(0080)
                       "Unable to read incoming WSGI request from "
                       "Apache child; request will be aborted with 500.");

        apr_pool_destroy(p);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check magic marker used to validate origin of request. */

    filename = apr_table_get(r->subprocess_env, "SCRIPT_FILENAME");
    script = apr_table_get(r->subprocess_env, "mod_wsgi.handler_script");

    magic = apr_table_get(r->subprocess_env, "mod_wsgi.magic");

    if (!magic)
    {
        wsgi_log_error(APLOG_ALERT, 0, wsgi_server, WSGI_APLOGNO(0033)
                       "Request origin could not be validated; "
                       "missing magic token.");

        apr_pool_destroy(p);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    key = apr_psprintf(r->pool, "%ld|%s|%s|%s",
                       wsgi_daemon_process->group->random,
                       wsgi_daemon_process->group->socket_path,
                       filename, script);
    hash = ap_md5(r->pool, (const unsigned char *)key);
    memset(key, '\0', strlen(key));

    if (strcmp(magic, hash) != 0)
    {
        wsgi_log_error(APLOG_ALERT, 0, wsgi_server, WSGI_APLOGNO(0034)
                       "Request origin could not be validated; "
                       "magic token mismatch.");

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

    if (wsgi_daemon_process->group->root)
    {
        const char *root;
        const char *path;

        root = wsgi_daemon_process->group->root;

        path = filename;

        if (strstr(path, root) == path && path[strlen(root)] == '/')
        {
            path += strlen(root);

            apr_table_set(r->subprocess_env, "SCRIPT_FILENAME", path);

            filename = path;
        }
        else
        {
            wsgi_log_error(APLOG_ERR, 0, wsgi_server, WSGI_APLOGNO(0081)
                           "WSGI script '%s' is not located within "
                           "chroot directory '%s'; rejecting request.",
                           path, root);

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        path = (char *)apr_table_get(r->subprocess_env, "DOCUMENT_ROOT");

        if (strstr(path, root) == path)
        {
            path += strlen(root);

            apr_table_set(r->subprocess_env, "DOCUMENT_ROOT", path);
        }
        else
        {
            apr_table_unset(r->subprocess_env, "DOCUMENT_ROOT");
        }
    }

    r->filename = (char *)filename;

    /* Recalculate WSGI script or handler script modification time. */

    if (script && *script)
    {
        if ((rv = apr_stat(&r->finfo, script, APR_FINFO_NORM,
                           r->pool)) != APR_SUCCESS)
        {
            /*
             * Don't fail at this point. Allow the lack of file to
             * be detected later when trying to load the script file.
             */

            wsgi_log_error(APLOG_WARNING, rv, wsgi_server, WSGI_APLOGNO(0082)
                           "Unable to stat target handler script '%s'.",
                           script);

            r->finfo.mtime = 0;
        }
    }
    else
    {
        if ((rv = apr_stat(&r->finfo, filename, APR_FINFO_NORM,
                           r->pool)) != APR_SUCCESS)
        {
            /*
             * Don't fail at this point. Allow the lack of file to
             * be detected later when trying to load the script file.
             */

            wsgi_log_error(APLOG_WARNING, rv, wsgi_server, WSGI_APLOGNO(0083)
                           "Unable to stat target WSGI script '%s'.",
                           filename);

            r->finfo.mtime = 0;
        }
    }

    /*
     * Trigger mapping of host information to server configuration
     * so that when logging errors they go to the correct error log
     * file for the host.
     */

    r->connection->client_ip = (char *)apr_table_get(r->subprocess_env,
                                                     "REMOTE_ADDR");
    r->connection->client_addr->port = atoi(apr_table_get(r->subprocess_env,
                                                          "REMOTE_PORT"));

    r->useragent_addr = c->client_addr;
    r->useragent_ip = c->client_ip;

    key = apr_psprintf(p, "%s|%s",
                       apr_table_get(r->subprocess_env,
                                     "mod_wsgi.listener_host"),
                       apr_table_get(r->subprocess_env,
                                     "mod_wsgi.listener_port"));

    wsgi_log_error(APLOG_TRACE1, 0, wsgi_server,
                   "Server listener address '%s'.", key);

    addr = (apr_sockaddr_t *)apr_hash_get(wsgi_daemon_listeners,
                                          key, APR_HASH_KEY_STRING);

    wsgi_log_error(APLOG_TRACE1, 0, wsgi_server,
                   "Server listener address '%s' was%s found.",
                   key, addr ? "" : " not");

    if (addr)
    {
        c->local_addr = addr;
    }

    ap_update_vhost_given_ip(r->connection);

    wsgi_log_error(APLOG_TRACE1, 0, wsgi_server,
                   "Connection server matched was '%s|%d'.",
                   c->base_server->server_hostname,
                   c->base_server->port);

    r->server = c->base_server;

    if (apr_table_get(r->subprocess_env, "HTTP_HOST"))
    {
        apr_table_setn(r->headers_in, "Host",
                       apr_table_get(r->subprocess_env, "HTTP_HOST"));
    }

    ap_update_vhost_from_headers(r);

    wsgi_log_error(APLOG_TRACE1, 0, wsgi_server,
                   "Request server matched was '%s|%d'.",
                   r->server->server_hostname, r->server->port);

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

    if (item)
    {
        errno = 0;
        config->request_start = apr_strtoi64(item, (char **)&item, 10);

        if (!*item && errno != ERANGE)
            r->request_time = config->request_start;
        else
            config->request_start = 0.0;
    }

    item = apr_table_get(r->subprocess_env, "mod_wsgi.queue_start");

    if (item)
    {
        errno = 0;
        config->queue_start = apr_strtoi64(item, (char **)&item, 10);

        if (!(!*item && errno != ERANGE))
            config->queue_start = 0.0;
    }

    config->daemon_start = daemon_start;

    apr_table_setn(r->subprocess_env, "mod_wsgi.daemon_start",
                   apr_psprintf(r->pool, "%" APR_TIME_T_FMT,
                                config->daemon_start));

    item = apr_table_get(r->subprocess_env, "mod_wsgi.request_id");

    if (item)
        r->log_id = item;

    item = apr_table_get(r->subprocess_env, "mod_wsgi.connection_id");

    if (item)
        r->connection->log_id = item;

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

    if (wsgi_daemon_process->group->queue_timeout)
    {
        if (config->request_start)
        {
            apr_time_t queue_time = 0;

            queue_time = config->daemon_start - config->request_start;

            if (queue_time > wsgi_daemon_process->group->queue_timeout)
            {
                queue_timeout_occurred = 1;

                r->status = HTTP_INTERNAL_SERVER_ERROR;
                r->status_line = "200 Timeout";

                wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0084)
                                "Queue timeout expired for WSGI daemon "
                                "process '%s'.",
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

    if (!queue_timeout_occurred)
    {
        if (wsgi_execute_script(r) != OK)
        {
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

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
