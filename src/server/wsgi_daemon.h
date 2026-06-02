#ifndef WSGI_DAEMON_H
#define WSGI_DAEMON_H

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
#include "wsgi_thread.h"

/* ------------------------------------------------------------------------- */

extern char *wsgi_shutdown_reason;

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
#include "apr_poll.h"
#include "apr_signal.h"
#include "http_vhost.h"

#if APR_MAJOR_VERSION < 2
#include "apr_support.h"
#endif

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

#include <locale.h>
#include <sys/un.h>

#ifndef WSGI_LISTEN_BACKLOG
#define WSGI_LISTEN_BACKLOG 100
#endif

#define WSGI_STACK_HEAD 0xffff
#define WSGI_STACK_LAST 0xffff
#define WSGI_STACK_TERMINATED 0x10000
#define WSGI_STACK_NO_LISTENER 0x20000

typedef struct
{
    server_rec *server;
    long random;
    int id;
    const char *name;
    const char *user;
    uid_t uid;
    const char *group;
    gid_t gid;
    const char *groups_list;
    int groups_count;
    gid_t *groups;
    int processes;
    int multiprocess;
    int threads;
    long umask;
    const char *root;
    const char *home;
    const char *lang;
    const char *locale;
    const char *python_home;
    const char *python_path;
    const char *python_eggs;
    double switch_interval;
    int stack_size;
    int maximum_requests;
    int shutdown_timeout;
    apr_time_t startup_timeout;
    apr_time_t deadlock_timeout;
    apr_time_t inactivity_timeout;
    apr_time_t request_timeout;
    apr_time_t interrupt_timeout;
    apr_time_t graceful_timeout;
    apr_time_t eviction_timeout;
    apr_time_t restart_interval;
    apr_time_t connect_timeout;
    apr_time_t socket_timeout;
    apr_time_t queue_timeout;
    const char *socket_user;
    int listen_backlog;
    const char *display_name;
    int send_buffer_size;
    int recv_buffer_size;
    int header_buffer_size;
    int response_buffer_size;
    apr_time_t response_socket_timeout;
    const char *script_user;
    const char *script_group;
    int cpu_time_limit;
    int cpu_priority;
    rlim_t memory_limit;
    rlim_t virtual_memory_limit;
    const char *socket_path;
    int socket_rotation;
    int listener_fd;
    const char *mutex_path;
    apr_proc_mutex_t *mutex;
    int server_metrics;
} WSGIProcessGroup;

typedef struct
{
    WSGIProcessGroup *group;
    int instance;
    apr_proc_t process;
    apr_socket_t *listener;
} WSGIDaemonProcess;

typedef struct
{
    int id;
    WSGIDaemonProcess *process;
    apr_thread_t *thread;
    int running;
    int next;
    int wakeup;
    apr_thread_cond_t *condition;
    apr_thread_mutex_t *mutex;
    apr_time_t request;
    unsigned long python_thread_id;
    apr_time_t injected_at;

    /* Back-pointer to this worker's WSGIThreadInfo, published once at
     * thread startup. Lets the daemon monitor follow the chain to per-
     * thread per-request state (specifically current_application_group)
     * without needing apr_threadkey access from outside the worker's
     * own thread. NULL until the worker thread has run far enough
     * through wsgi_daemon_thread to publish it. */
    WSGIThreadInfo *thread_info;
} WSGIDaemonThread;

typedef struct
{
    apr_uint32_t state;
} WSGIThreadStack;

typedef struct
{
    const char *name;
    const char *socket_path;
    apr_time_t connect_timeout;
    apr_time_t socket_timeout;
    apr_socket_t *socket;
} WSGIDaemonSocket;

extern apr_array_header_t *wsgi_daemon_list;

extern int wsgi_daemon_count;
extern apr_hash_t *wsgi_daemon_index;
extern apr_hash_t *wsgi_daemon_listeners;

extern WSGIDaemonProcess *wsgi_daemon_process;

extern int volatile wsgi_request_count;

extern WSGIDaemonThread *wsgi_worker_threads;

extern WSGIThreadStack *wsgi_worker_stack;

extern int volatile wsgi_daemon_shutdown;

extern apr_interval_time_t wsgi_idle_timeout;
extern apr_time_t volatile wsgi_idle_shutdown_time;

extern apr_interval_time_t wsgi_startup_timeout;
extern apr_time_t volatile wsgi_startup_shutdown_time;

extern apr_pool_t *wsgi_pconf_pool;

extern const char *wsgi_add_daemon_process(cmd_parms *cmd, void *mconfig,
                                           const char *args);
extern const char *wsgi_set_socket_prefix(cmd_parms *cmd, void *mconfig,
                                          const char *arg);
extern const char *wsgi_set_socket_rotation(cmd_parms *cmd, void *mconfig,
                                            const char *f);
extern const char *wsgi_set_accept_mutex(cmd_parms *cmd, void *mconfig,
                                         const char *arg);

extern int wsgi_start_daemons(apr_pool_t *p);
extern int wsgi_deferred_start_daemons(apr_pool_t *p, ap_scoreboard_e sb_type);
extern int wsgi_hook_daemon_handler(conn_rec *c);

#endif

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
