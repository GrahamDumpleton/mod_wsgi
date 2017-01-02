#ifndef WSGI_DAEMON_H
#define WSGI_DAEMON_H

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

#ifndef WIN32
#if APR_HAS_OTHER_CHILD && APR_HAS_THREADS && APR_HAS_FORK
#define MOD_WSGI_WITH_DAEMONS 1
#endif
#endif

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
    int stack_size;
    int maximum_requests;
    int shutdown_timeout;
    apr_time_t startup_timeout;
    apr_time_t deadlock_timeout;
    apr_time_t inactivity_timeout;
    apr_time_t request_timeout;
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
    const char *script_user;
    const char *script_group;
    int cpu_time_limit;
    int cpu_priority;
    rlim_t memory_limit;
    rlim_t virtual_memory_limit;
    const char *socket_path;
    int listener_fd;
    const char* mutex_path;
    apr_proc_mutex_t* mutex;
    int server_metrics;
    const char *newrelic_config_file;
    const char *newrelic_environment;
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
    apr_time_t request;
} WSGIDaemonThread;

typedef struct {
    apr_uint32_t state;
} WSGIThreadStack;

typedef struct {
    const char *name;
    const char *socket_path;
    apr_time_t connect_timeout;
    apr_time_t socket_timeout;
    apr_socket_t *socket;
} WSGIDaemonSocket;

extern int wsgi_daemon_count;
extern apr_hash_t *wsgi_daemon_index;
extern apr_hash_t *wsgi_daemon_listeners;

extern WSGIDaemonProcess *wsgi_daemon_process;

extern int volatile wsgi_request_count;

extern WSGIDaemonThread *wsgi_worker_threads;

extern WSGIThreadStack *wsgi_worker_stack;

#endif

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
