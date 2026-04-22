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
 * Telemetry reporter. When enabled via WSGIMetricsService, each mod_wsgi
 * process spawns a single background thread that periodically takes a
 * C-native metrics snapshot (wsgi_metrics_snapshot) and ships it as a
 * binary TLV datagram to a local socket. The encoder emits the format
 * documented in wsgi_telemetry.h.
 *
 * Transport is SOCK_DGRAM, fire-and-forget. If the ingester is down or
 * restarting, the kernel discards the datagram and the reporter continues
 * without blocking.
 */

#include "wsgi_python.h"
#include "wsgi_apache.h"
#include "wsgi_server.h"
#include "wsgi_daemon.h"
#include "wsgi_metrics.h"
#include "wsgi_telemetry.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/* ------------------------------------------------------------------------- */

static const char *wsgi_telemetry_target = NULL;
static double wsgi_telemetry_interval = 1.0;
static int wsgi_telemetry_enabled = 0;
static int wsgi_telemetry_started = 0;

static apr_thread_t *wsgi_telemetry_thread = NULL;
static volatile int wsgi_telemetry_shutdown = 0;

/* ------------------------------------------------------------------------- */

/*
 * Parse "unix:/path" or "udp:host:port" into a ready-to-use socket + dest
 * address. Returns a bound (for UNIX-reply, not really used) or unbound
 * socket configured for sendto(). Caller must close on failure paths.
 */

static int wsgi_telemetry_open(const char *target,
                               int *out_fd,
                               struct sockaddr_storage *out_addr,
                               socklen_t *out_addrlen)
{
    int fd = -1;

    if (!target || !*target)
        return -1;

    memset(out_addr, 0, sizeof(*out_addr));
    *out_addrlen = 0;

    if (strncmp(target, "unix:", 5) == 0) {
        const char *path = target + 5;
        struct sockaddr_un *sa = (struct sockaddr_un *)out_addr;

        if (strlen(path) >= sizeof(sa->sun_path))
            return -1;

        fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (fd < 0)
            return -1;

        sa->sun_family = AF_UNIX;
        strncpy(sa->sun_path, path, sizeof(sa->sun_path) - 1);
        *out_addrlen = (socklen_t)sizeof(*sa);
    }
    else if (strncmp(target, "udp:", 4) == 0) {
        char host[256];
        const char *rest = target + 4;
        const char *colon = strrchr(rest, ':');
        int port;
        struct sockaddr_in *sa = (struct sockaddr_in *)out_addr;

        if (!colon || colon == rest)
            return -1;
        if ((size_t)(colon - rest) >= sizeof(host))
            return -1;

        memcpy(host, rest, colon - rest);
        host[colon - rest] = '\0';
        port = atoi(colon + 1);
        if (port <= 0 || port > 65535)
            return -1;

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
            return -1;

        sa->sin_family = AF_INET;
        sa->sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, host, &sa->sin_addr) != 1) {
            close(fd);
            return -1;
        }
        *out_addrlen = (socklen_t)sizeof(*sa);
    }
    else {
        return -1;
    }

    *out_fd = fd;
    return 0;
}

/* ------------------------------------------------------------------------- */

static size_t wsgi_telemetry_encode(const wsgi_telemetry_sample_t *s,
                                    uint32_t pid, uint32_t seq,
                                    uint8_t *buf, size_t buflen)
{
    uint8_t *p = buf;
    uint8_t *end = buf + buflen;
    uint64_t stamp_us = (uint64_t)apr_time_now();  /* apr_time_t is usec */

    (void)end;  /* encoder sizes are deterministic; see WSGI_METRICS_MAX_DATAGRAM */

    wsgi_metrics_put_header(&p, WSGI_METRICS_KIND_REQUEST, pid, seq, stamp_us);

    if (s->hostname[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_HOSTNAME, s->hostname,
                       (uint16_t)strlen(s->hostname));
    if (s->process_group[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_PROCESS_GROUP, s->process_group,
                       (uint16_t)strlen(s->process_group));

    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SAMPLE_PERIOD, s->sample_period);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_REQUEST_COUNT, s->request_count);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_REQUEST_THROUGHPUT, s->request_throughput);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_CAPACITY_UTILIZATION, s->capacity_utilization);

    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_CPU_USER_UTILIZATION, s->cpu_user_utilization);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_CPU_SYSTEM_UTILIZATION, s->cpu_system_utilization);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_CPU_UTILIZATION, s->cpu_utilization);

    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_MEMORY_RSS, s->memory_rss);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_MEMORY_MAX_RSS, s->memory_max_rss);

    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_REQUEST_THREADS_MAXIMUM, s->request_threads_maximum);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_REQUEST_THREADS_STARTED, s->request_threads_started);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_REQUEST_THREADS_ACTIVE, s->request_threads_active);

    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SERVER_TIME, s->server_time);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_APPLICATION_TIME, s->application_time);
    if (s->has_daemon_timing) {
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_QUEUE_TIME, s->queue_time);
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_DAEMON_TIME, s->daemon_time);
    }

    wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_SERVER_TIME_BUCKETS,
                       s->server_time_buckets, WSGI_TELEMETRY_BUCKET_COUNT);
    wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_APPLICATION_TIME_BUCKETS,
                       s->application_time_buckets, WSGI_TELEMETRY_BUCKET_COUNT);
    if (s->has_daemon_timing) {
        wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_QUEUE_TIME_BUCKETS,
                           s->queue_time_buckets, WSGI_TELEMETRY_BUCKET_COUNT);
        wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_DAEMON_TIME_BUCKETS,
                           s->daemon_time_buckets, WSGI_TELEMETRY_BUCKET_COUNT);
    }

    if (s->slot_count > 0) {
        uint16_t n = (uint16_t)s->slot_count;
        wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_SLOT_REQUEST_COUNT,
                                   s->slot_request_count, n);
        wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_SLOT_BUSY_TIME_US,
                                   s->slot_busy_time_us, n);
        wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_SLOT_CPU_TIME_US,
                                   s->slot_cpu_time_us, n);
        wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_SLOT_CURRENT_ELAPSED_MS,
                                   s->slot_current_elapsed_ms, n);
        wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_SLOT_MAX_DURATION_MS,
                                   s->slot_max_duration_ms, n);
    }

    return (size_t)(p - buf);
}

static size_t wsgi_telemetry_encode_slow(const wsgi_slow_request_t *s,
                                         uint32_t pid, uint32_t seq,
                                         uint64_t stamp_us,
                                         uint8_t *buf, size_t buflen)
{
    uint8_t *p = buf;

    (void)buflen;  /* deterministic; WSGI_METRICS_MAX_DATAGRAM sizes it */

    wsgi_metrics_put_header(&p, WSGI_METRICS_KIND_SLOW_REQUEST, pid, seq,
                            stamp_us);

    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_STATE, s->state);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_START_STAMP_US,
                         s->start_stamp_us);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_DURATION_US, s->duration_us);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_THREAD_ID, s->thread_id);

    if (s->log_id[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_SLOW_LOG_ID, s->log_id,
                               (uint16_t)strlen(s->log_id));
    if (s->method[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_SLOW_METHOD, s->method,
                               (uint16_t)strlen(s->method));
    if (s->scheme[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_SLOW_SCHEME, s->scheme,
                               (uint16_t)strlen(s->scheme));
    if (s->hostname[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_SLOW_HOSTNAME, s->hostname,
                               (uint16_t)strlen(s->hostname));
    if (s->script_name[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_SLOW_SCRIPT_NAME,
                               s->script_name,
                               (uint16_t)strlen(s->script_name));
    if (s->path_info[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_SLOW_PATH_INFO,
                               s->path_info,
                               (uint16_t)strlen(s->path_info));

    return (size_t)(p - buf);
}

/* ------------------------------------------------------------------------- */

static void *APR_THREAD_FUNC wsgi_telemetry_thread_main(apr_thread_t *t,
                                                        void *data)
{
    int fd = -1;
    struct sockaddr_storage addr;
    socklen_t addrlen = 0;
    uint8_t buf[WSGI_METRICS_MAX_DATAGRAM];
    uint32_t seq = 0;
    uint32_t pid = (uint32_t)getpid();
    char hostname[128];
    const char *group_name = "";
    apr_interval_time_t sleep_us;

    if (wsgi_telemetry_open(wsgi_telemetry_target, &fd, &addr, &addrlen) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Telemetry reporter could not open "
                     "target '%s'.", (int)pid, wsgi_telemetry_target);
        return NULL;
    }

    if (gethostname(hostname, sizeof(hostname)) != 0)
        hostname[0] = '\0';
    hostname[sizeof(hostname) - 1] = '\0';

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process && wsgi_daemon_process->group &&
        wsgi_daemon_process->group->name)
        group_name = wsgi_daemon_process->group->name;
#endif

    sleep_us = (apr_interval_time_t)(wsgi_telemetry_interval * APR_USEC_PER_SEC);
    if (sleep_us < 100000)   /* floor at 100ms */
        sleep_us = 100000;

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, wsgi_server,
                 "mod_wsgi (pid=%d): Telemetry reporter started, "
                 "target='%s', interval=%.3f",
                 (int)pid, wsgi_telemetry_target, wsgi_telemetry_interval);

    while (!wsgi_telemetry_shutdown) {
        wsgi_telemetry_sample_t sample;
        size_t n;

        apr_sleep(sleep_us);

        if (wsgi_telemetry_shutdown)
            break;

        if (!wsgi_metrics_snapshot(&sample))
            continue;

        /* Populate identity that the snapshot function does not fill. */
        strncpy(sample.hostname, hostname, sizeof(sample.hostname) - 1);
        sample.hostname[sizeof(sample.hostname) - 1] = '\0';
        strncpy(sample.process_group, group_name,
                sizeof(sample.process_group) - 1);
        sample.process_group[sizeof(sample.process_group) - 1] = '\0';

        if (!sample.seeded)
            continue;  /* first call seeded counters; skip send */

        seq++;
        n = wsgi_telemetry_encode(&sample, pid, seq, buf, sizeof(buf));
        if (n == 0)
            continue;

        if (sendto(fd, buf, n, 0,
                   (struct sockaddr *)&addr, addrlen) < 0) {
            /* Datagram sockets: ENOENT / ECONNREFUSED when ingester isn't
             * up. Silently drop; the ingester will pick up on next tick
             * once listening. Don't flood the error log. */
        }

        /* Slow-request tracking — one datagram per record. Completed
         * records drain first so their final duration arrives before
         * any heartbeat that would otherwise make the UI age the entry
         * out as "lost". Active-scan uses a consistent now_us so all
         * elapsed values in this tick share a reference. */

        if (wsgi_slow_threshold_us > 0) {
            wsgi_slow_request_t rec;
            wsgi_slow_request_t actives[16];
            int n_active;
            int i;
            uint64_t tick_stamp_us = (uint64_t)apr_time_now();

            while (wsgi_metrics_pop_slow_completed(&rec)) {
                seq++;
                n = wsgi_telemetry_encode_slow(&rec, pid, seq, tick_stamp_us,
                                               buf, sizeof(buf));
                if (n == 0)
                    continue;
                if (sendto(fd, buf, n, 0, (struct sockaddr *)&addr,
                           addrlen) < 0) {
                    /* silently drop; see comment above */
                }
            }

            n_active = wsgi_metrics_snapshot_slow_active(
                actives, (int)(sizeof(actives) / sizeof(actives[0])),
                (apr_time_t)tick_stamp_us, wsgi_slow_threshold_us);

            for (i = 0; i < n_active; i++) {
                seq++;
                n = wsgi_telemetry_encode_slow(&actives[i], pid, seq,
                                               tick_stamp_us, buf,
                                               sizeof(buf));
                if (n == 0)
                    continue;
                if (sendto(fd, buf, n, 0, (struct sockaddr *)&addr,
                           addrlen) < 0) {
                    /* silently drop */
                }
            }
        }
    }

    if (fd >= 0)
        close(fd);

    return NULL;
}

/* ------------------------------------------------------------------------- */

/*
 * Directive handler: WSGIMetricsService <target> [interval=N]
 * Target is "unix:/path" or "udp:host:port".
 */

const char *wsgi_set_metrics_service(cmd_parms *cmd, void *mconfig,
                                     const char *arg1, const char *arg2)
{
    const char *error = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    if (!arg1 || !*arg1)
        return "WSGIMetricsService target required";

    if (strncmp(arg1, "unix:", 5) != 0 && strncmp(arg1, "udp:", 4) != 0)
        return "WSGIMetricsService target must be 'unix:/path' "
               "or 'udp:host:port'";

    wsgi_telemetry_target = apr_pstrdup(cmd->pool, arg1);
    wsgi_telemetry_enabled = 1;

    if (arg2) {
        double v = 0.0;
        if (strncmp(arg2, "interval=", 9) == 0) {
            v = atof(arg2 + 9);
            if (v <= 0.0)
                return "WSGIMetricsService interval must be positive";
            wsgi_telemetry_interval = v;
        }
        else {
            return "WSGIMetricsService second argument must be "
                   "'interval=N'";
        }
    }

    return NULL;
}

/*
 * Directive handler: WSGISlowRequests <seconds>
 *
 * Presence enables per-request "slow request" reporting in addition to
 * the periodic KIND_REQUEST sampling. Argument is the duration threshold
 * above which an in-flight request becomes eligible for reporting. Only
 * meaningful when WSGIMetricsService is also configured; without a
 * metrics service there is nowhere to send records.
 */

const char *wsgi_set_slow_requests(cmd_parms *cmd, void *mconfig,
                                   const char *arg)
{
    const char *error = NULL;
    double seconds = 0.0;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    if (!arg || !*arg)
        return "WSGISlowRequests threshold (seconds) required";

    seconds = atof(arg);
    if (seconds < 0.0)
        return "WSGISlowRequests threshold must be non-negative";

    wsgi_slow_threshold_us =
        (apr_time_t)(seconds * APR_USEC_PER_SEC);

    return NULL;
}

/* ------------------------------------------------------------------------- */

void wsgi_telemetry_start_reporter(apr_pool_t *pool)
{
    apr_status_t rv;

    if (!wsgi_telemetry_enabled || wsgi_telemetry_started)
        return;

    wsgi_telemetry_started = 1;

    rv = apr_thread_create(&wsgi_telemetry_thread, NULL,
                           wsgi_telemetry_thread_main, NULL, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, wsgi_server,
                     "mod_wsgi (pid=%d): Telemetry reporter thread "
                     "creation failed.", getpid());
        wsgi_telemetry_started = 0;
    }
}

/* ------------------------------------------------------------------------- */

void wsgi_telemetry_stop_reporter(void)
{
    if (!wsgi_telemetry_started)
        return;

    wsgi_telemetry_shutdown = 1;
    if (wsgi_telemetry_thread) {
        apr_status_t rv = APR_SUCCESS;
        apr_thread_join(&rv, wsgi_telemetry_thread);
        wsgi_telemetry_thread = NULL;
    }
    wsgi_telemetry_started = 0;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
