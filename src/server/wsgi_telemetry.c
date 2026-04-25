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
 * Transport is UNIX SOCK_DGRAM, fire-and-forget. If the ingester is down
 * or restarting, the kernel discards the datagram and the reporter
 * continues without blocking. Remote (IPv4 UDP) targets are not
 * supported — telemetry is intended for a co-located ingester so that
 * IP-fragmentation, MTU sizing and packet loss across a real network
 * are all non-concerns; the per-tick datagram is allowed to grow well
 * past the Ethernet MTU as a result.
 */

#include "wsgi_python.h"
#include "wsgi_apache.h"
#include "wsgi_server.h"
#include "wsgi_daemon.h"
#include "wsgi_logger.h"
#include "wsgi_metrics.h"
#include "wsgi_telemetry.h"
#include "wsgi_version.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/* ------------------------------------------------------------------------- */

static const char *wsgi_telemetry_target = NULL;
/* Non-static so wsgi_metrics.c can read it when sizing the slow-
 * completion ring (worst-case completions per tick depends on the
 * reporter interval). */
double wsgi_telemetry_interval = 1.0;
static int wsgi_telemetry_enabled = 0;
static int wsgi_telemetry_started = 0;

static apr_thread_t *wsgi_telemetry_thread = NULL;
static volatile int wsgi_telemetry_shutdown = 0;

/* ------------------------------------------------------------------------- */

/*
 * Parse "unix:/path" into a ready-to-use socket + dest address.
 * Configures the socket for sendto(). Caller must close on failure
 * paths. Only UNIX SOCK_DGRAM targets are accepted; remote IPv4 UDP
 * targets are rejected at config-parse time.
 */

static int wsgi_telemetry_open(const char *target,
                               int *out_fd,
                               struct sockaddr_storage *out_addr,
                               socklen_t *out_addrlen)
{
    int fd = -1;
    const char *path;
    struct sockaddr_un *sa;

    if (!target || !*target)
        return -1;
    if (strncmp(target, "unix:", 5) != 0)
        return -1;

    memset(out_addr, 0, sizeof(*out_addr));
    *out_addrlen = 0;

    path = target + 5;
    sa = (struct sockaddr_un *)out_addr;

    if (strlen(path) >= sizeof(sa->sun_path))
        return -1;

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    sa->sun_family = AF_UNIX;
    strncpy(sa->sun_path, path, sizeof(sa->sun_path) - 1);
    *out_addrlen = (socklen_t)sizeof(*sa);

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

    if (s->mod_wsgi_version[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_MOD_WSGI_VERSION,
                       s->mod_wsgi_version,
                       (uint16_t)strlen(s->mod_wsgi_version));
    if (s->python_version[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_PYTHON_VERSION,
                       s->python_version,
                       (uint16_t)strlen(s->python_version));
    if (s->apache_version[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_APACHE_VERSION,
                       s->apache_version,
                       (uint16_t)strlen(s->apache_version));
    if (s->mpm_name[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_MPM_NAME, s->mpm_name,
                       (uint16_t)strlen(s->mpm_name));
    if (s->hostname[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_HOSTNAME, s->hostname,
                       (uint16_t)strlen(s->hostname));
    if (s->process_group[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_PROCESS_GROUP, s->process_group,
                       (uint16_t)strlen(s->process_group));

    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SAMPLE_PERIOD, s->sample_period);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_TELEMETRY_INTERVAL,
                         s->telemetry_interval);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SLOW_REQUESTS_THRESHOLD,
                         s->slow_requests_threshold);

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
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_REQUEST_TIME, s->request_time);
    if (s->has_daemon_timing) {
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_QUEUE_TIME, s->queue_time);
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_DAEMON_TIME, s->daemon_time);
    }

    /* Per-phase exact min/max for the interval. Skip the field entirely
     * on ticks where the phase saw no requests; the decoder treats
     * absence as "no data this tick". Min and max are paired — if min
     * was set, max was set too. */
    if (s->server_time_min_us != UINT64_MAX) {
        wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SERVER_TIME_MIN_US,
                             s->server_time_min_us);
        wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SERVER_TIME_MAX_US,
                             s->server_time_max_us);
    }
    if (s->application_time_min_us != UINT64_MAX) {
        wsgi_metrics_put_u64(&p, WSGI_METRICS_F_APPLICATION_TIME_MIN_US,
                             s->application_time_min_us);
        wsgi_metrics_put_u64(&p, WSGI_METRICS_F_APPLICATION_TIME_MAX_US,
                             s->application_time_max_us);
    }
    if (s->request_time_min_us != UINT64_MAX) {
        wsgi_metrics_put_u64(&p, WSGI_METRICS_F_REQUEST_TIME_MIN_US,
                             s->request_time_min_us);
        wsgi_metrics_put_u64(&p, WSGI_METRICS_F_REQUEST_TIME_MAX_US,
                             s->request_time_max_us);
    }
    if (s->has_daemon_timing) {
        if (s->queue_time_min_us != UINT64_MAX) {
            wsgi_metrics_put_u64(&p, WSGI_METRICS_F_QUEUE_TIME_MIN_US,
                                 s->queue_time_min_us);
            wsgi_metrics_put_u64(&p, WSGI_METRICS_F_QUEUE_TIME_MAX_US,
                                 s->queue_time_max_us);
        }
        if (s->daemon_time_min_us != UINT64_MAX) {
            wsgi_metrics_put_u64(&p, WSGI_METRICS_F_DAEMON_TIME_MIN_US,
                                 s->daemon_time_min_us);
            wsgi_metrics_put_u64(&p, WSGI_METRICS_F_DAEMON_TIME_MAX_US,
                                 s->daemon_time_max_us);
        }
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
    wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_REQUEST_TIME_BUCKETS,
                       s->request_time_buckets, WSGI_TELEMETRY_BUCKET_COUNT);

    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_INPUT_BYTES_TOTAL,
                         s->input_bytes_total);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_INPUT_READS_TOTAL,
                         s->input_reads_total);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_OUTPUT_BYTES_TOTAL,
                         s->output_bytes_total);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_OUTPUT_WRITES_TOTAL,
                         s->output_writes_total);

    /* Per-interval HTTP response class totals. Always emitted (even
     * when zero) so consumers can distinguish "zero of this class"
     * from "older encoder that didn't have the field". Sum equals
     * request_count for the same interval, modulo the status==0 fold
     * into 5xx. */
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_STATUS_1XX_TOTAL,
                         s->status_1xx_total);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_STATUS_2XX_TOTAL,
                         s->status_2xx_total);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_STATUS_3XX_TOTAL,
                         s->status_3xx_total);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_STATUS_4XX_TOTAL,
                         s->status_4xx_total);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_STATUS_5XX_TOTAL,
                         s->status_5xx_total);

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

    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_INPUT_BYTES, s->input_bytes);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_INPUT_READS, s->input_reads);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_OUTPUT_BYTES,
                         s->output_bytes);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_OUTPUT_WRITES,
                         s->output_writes);

    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_CPU_USER_US,
                         s->cpu_user_us);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_CPU_SYSTEM_US,
                         s->cpu_system_us);

    /* Final HTTP response status. Zero for active records (the WSGI
     * app may not have called start_response yet); always emitted so
     * consumers see the "0 = not yet known" sentinel rather than a
     * missing field. */
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_STATUS, s->status);

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
    char mod_wsgi_version[32];
    char python_version[64];
    char apache_version[64];
    char mpm_name[32];
    apr_interval_time_t sleep_us;

    if (wsgi_telemetry_open(wsgi_telemetry_target, &fd, &addr, &addrlen) != 0) {
        wsgi_log_error(APLOG_ERR, 0, wsgi_server,
                       "Telemetry reporter could not open target '%s'.",
                       wsgi_telemetry_target);
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

    /* Build / runtime identity. Populated once; these strings are
     * static for the life of the process and are copied into each
     * sample below. Empty values are tolerated — the encoder skips
     * fields with a leading nul so an ingester never sees an empty
     * string where it expects a real version. */
    strncpy(mod_wsgi_version, MOD_WSGI_VERSION_STRING,
            sizeof(mod_wsgi_version) - 1);
    mod_wsgi_version[sizeof(mod_wsgi_version) - 1] = '\0';

    {
        /* Py_GetVersion() returns "3.14.0 (main, Jan 15 2026, ...)";
         * trim to the leading version token so the banner stays
         * compact. Same approach as wsgi_interp.c uses for the
         * SERVER_SOFTWARE construction. */
        const char *pv = Py_GetVersion();
        size_t i = 0;
        if (pv) {
            while (i < sizeof(python_version) - 1 && pv[i] &&
                   pv[i] != ' ' && pv[i] != '\t') {
                python_version[i] = pv[i];
                i++;
            }
        }
        python_version[i] = '\0';
    }

    /* AP_SERVER_BASEVERSION is the compile-time Apache version
     * ("Apache/2.4.62") and isn't subject to the ServerTokens
     * directive — which we want here: telemetry needs the actual
     * binary version regardless of whether the admin has redacted
     * the public banner. */
    strncpy(apache_version, AP_SERVER_BASEVERSION,
            sizeof(apache_version) - 1);
    apache_version[sizeof(apache_version) - 1] = '\0';

    {
        const char *mpm = ap_show_mpm();
        if (mpm) {
            strncpy(mpm_name, mpm, sizeof(mpm_name) - 1);
            mpm_name[sizeof(mpm_name) - 1] = '\0';
        }
        else {
            mpm_name[0] = '\0';
        }
    }

    sleep_us = (apr_interval_time_t)(wsgi_telemetry_interval * APR_USEC_PER_SEC);
    if (sleep_us < 100000)   /* floor at 100ms */
        sleep_us = 100000;

    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                   "Telemetry reporter started, target='%s', interval=%.3f",
                   wsgi_telemetry_target, wsgi_telemetry_interval);

    while (!wsgi_telemetry_shutdown) {
        wsgi_telemetry_sample_t sample;
        size_t n;

        apr_sleep(sleep_us);

        if (wsgi_telemetry_shutdown)
            break;

        if (!wsgi_metrics_snapshot(&sample))
            continue;

        /* Populate identity + reporter config that the snapshot
         * function does not fill. wsgi_slow_threshold_us is in
         * microseconds, exposed as seconds on the wire so the UI can
         * compare directly with the heatmap stuck-threshold dropdown
         * (also in seconds). */
        strncpy(sample.hostname, hostname, sizeof(sample.hostname) - 1);
        sample.hostname[sizeof(sample.hostname) - 1] = '\0';
        strncpy(sample.process_group, group_name,
                sizeof(sample.process_group) - 1);
        sample.process_group[sizeof(sample.process_group) - 1] = '\0';
        strncpy(sample.mod_wsgi_version, mod_wsgi_version,
                sizeof(sample.mod_wsgi_version) - 1);
        sample.mod_wsgi_version[sizeof(sample.mod_wsgi_version) - 1] = '\0';
        strncpy(sample.python_version, python_version,
                sizeof(sample.python_version) - 1);
        sample.python_version[sizeof(sample.python_version) - 1] = '\0';
        strncpy(sample.apache_version, apache_version,
                sizeof(sample.apache_version) - 1);
        sample.apache_version[sizeof(sample.apache_version) - 1] = '\0';
        strncpy(sample.mpm_name, mpm_name, sizeof(sample.mpm_name) - 1);
        sample.mpm_name[sizeof(sample.mpm_name) - 1] = '\0';
        sample.telemetry_interval = wsgi_telemetry_interval;
        sample.slow_requests_threshold =
            (double)wsgi_slow_threshold_us / 1.0e6;

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
 * Target must be "unix:/path"; remote IPv4 UDP targets are not
 * supported (the reporter assumes a co-located ingester so that
 * MTU / IP-fragmentation / packet-loss across a real network are
 * non-concerns).
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

    if (strncmp(arg1, "unix:", 5) != 0)
        return "WSGIMetricsService target must be 'unix:/path' "
               "(remote 'udp:host:port' targets are no longer supported)";

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
        wsgi_log_error(APLOG_ERR, rv, wsgi_server,
                       "Telemetry reporter thread creation failed.");
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
