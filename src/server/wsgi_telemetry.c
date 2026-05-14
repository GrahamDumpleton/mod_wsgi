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
 * Telemetry reporter. When enabled via WSGITelemetryService, each mod_wsgi
 * process spawns a single background thread that periodically takes a
 * C-native metrics snapshot (wsgi_metrics_snapshot) and ships it as a
 * binary TLV datagram to a local socket. The encoder emits the format
 * documented in wsgi_telemetry.h.
 *
 * Transport is UNIX SOCK_DGRAM, fire-and-forget. If the ingester is
 * down or restarting, the kernel discards the datagram and the
 * reporter continues without blocking. Remote (IPv4 UDP) targets are
 * not supported; telemetry is intended for a co-located ingester so
 * that IP-fragmentation, MTU sizing and packet loss across a real
 * network are all non-concerns. The per-tick datagram is allowed to
 * grow well past the Ethernet MTU as a result.
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

/*
 * Non-static so wsgi_metrics.c can read it when sizing the slow-
 * completion ring (worst-case completions per tick depends on the
 * reporter interval).
 */

double wsgi_telemetry_interval = 1.0;
static int wsgi_telemetry_enabled = 0;
static int wsgi_telemetry_started = 0;

int wsgi_telemetry_is_enabled(void)
{
    return wsgi_telemetry_enabled;
}

static apr_thread_t *wsgi_telemetry_thread = NULL;
static volatile int wsgi_telemetry_shutdown = 0;

/*
 * Reporter context. Populated by the reporter thread before it begins
 * the periodic loop, and read by both the reporter thread and the
 * daemon main thread (which emits lifecycle datagrams sharing the same
 * socket and identity). The context outlives the reporter thread:
 * pause_reporter joins the thread but leaves these fields populated so
 * emit_final_tick / STOPPED can still send before close.
 */

typedef struct
{
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    uint32_t pid;
    uint32_t parent_pid;
    apr_time_t process_start_us;
    char hostname[128];
    char process_group[64];
    char mod_wsgi_version[32];
    char python_version[64];
    char apache_version[64];
    char mpm_name[32];
    double switch_interval;
} wsgi_telemetry_ctx_t;

static wsgi_telemetry_ctx_t wsgi_telemetry_ctx;
static volatile int wsgi_telemetry_ctx_ready = 0;
static volatile apr_uint32_t wsgi_telemetry_seq = 0;

/*
 * STOPPED-emit idempotency flag. The graceful shutdown path emits
 * STOPPED from the daemon main thread once worker drain completes;
 * the reaper thread (wsgi_reaper_thread) emits it before forcibly
 * exiting when shutdown_timeout fires. Whichever fires first wins
 * the CAS and sends the datagram; the other becomes a no-op. Without
 * this guard we would either lose STOPPED whenever drain exceeds
 * shutdown_timeout, or risk emitting it twice.
 */

static volatile apr_uint32_t wsgi_telemetry_stopped_emitted = 0;

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

    /*
     * On macOS / BSD, AF_UNIX SOCK_DGRAM defaults to a 2 KB max
     * datagram size from net.local.dgram.maxdgram. Periodic telemetry
     * samples can exceed this once histograms and per-phase min/max
     * are populated, so set SO_SNDBUF explicitly to override the
     * per-socket cap. Linux is unaffected (default is far higher), but
     * the call is harmless there: the kernel clamps to its own max if
     * our request is too large. Errors are non-fatal: if setsockopt
     * fails the socket still works for smaller datagrams; the periodic
     * stream will just drop the occasional oversize record.
     */

    {
        int bufsize = 65536;
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF,
                         &bufsize, sizeof(bufsize));
    }

    sa->sun_family = AF_UNIX;
    strncpy(sa->sun_path, path, sizeof(sa->sun_path) - 1);
    *out_addrlen = (socklen_t)sizeof(*sa);

    *out_fd = fd;
    return 0;
}

static uint32_t wsgi_telemetry_next_seq(void)
{
    return apr_atomic_inc32(&wsgi_telemetry_seq) + 1;
}

static void wsgi_telemetry_send(const wsgi_telemetry_ctx_t *ctx,
                                const uint8_t *buf, size_t n)
{
    if (n == 0 || ctx->fd < 0)
        return;

    if (sendto(ctx->fd, buf, n, 0,
               (struct sockaddr *)&ctx->addr, ctx->addrlen) < 0)
    {
        /*
         * Datagram sockets: ENOENT / ECONNREFUSED when ingester isn't
         * up. Silently drop; the ingester picks up on the next tick
         * once listening. Don't flood the error log.
         */
    }
}

/* ------------------------------------------------------------------------- */

static size_t wsgi_telemetry_encode(const wsgi_telemetry_sample_t *s,
                                    uint32_t pid, uint32_t seq,
                                    uint8_t *buf, size_t buflen)
{
    uint8_t *p = buf;
    uint8_t *end = buf + buflen;
    double stamp = (double)apr_time_now() / (double)APR_USEC_PER_SEC;

    (void)end; /* encoder sizes are deterministic; see WSGI_METRICS_MAX_DATAGRAM */

    wsgi_metrics_put_header(&p, WSGI_METRICS_KIND_REQUEST, pid, seq, stamp);

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

    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_PROCESS_PARENT_PID, s->parent_pid);

    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SAMPLE_PERIOD, s->sample_period);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_TELEMETRY_INTERVAL,
                         s->telemetry_interval);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SLOW_REQUESTS_THRESHOLD,
                         s->slow_requests_threshold);
    if (s->switch_interval > 0.0)
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SWITCH_INTERVAL,
                             s->switch_interval);

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
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_GIL_WAIT_TIME, s->gil_wait_time);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_INPUT_READ_TIME,
                         s->input_read_time);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_OUTPUT_WRITE_TIME,
                         s->output_write_time);
    if (s->has_daemon_timing)
    {
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_QUEUE_TIME, s->queue_time);
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_DAEMON_TIME, s->daemon_time);
    }

    /*
     * Per-phase exact min/max for the interval. Skip the field
     * entirely on ticks where the phase saw no requests; the decoder
     * treats absence as "no data this tick". Min and max are paired:
     * if min was set, max was set too.
     */

    if (s->server_time_min_us != UINT64_MAX)
    {
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SERVER_TIME_MIN,
                             (double)s->server_time_min_us / (double)APR_USEC_PER_SEC);
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SERVER_TIME_MAX,
                             (double)s->server_time_max_us / (double)APR_USEC_PER_SEC);
    }
    if (s->application_time_min_us != UINT64_MAX)
    {
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_APPLICATION_TIME_MIN,
                             (double)s->application_time_min_us / (double)APR_USEC_PER_SEC);
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_APPLICATION_TIME_MAX,
                             (double)s->application_time_max_us / (double)APR_USEC_PER_SEC);
    }
    if (s->request_time_min_us != UINT64_MAX)
    {
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_REQUEST_TIME_MIN,
                             (double)s->request_time_min_us / (double)APR_USEC_PER_SEC);
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_REQUEST_TIME_MAX,
                             (double)s->request_time_max_us / (double)APR_USEC_PER_SEC);
    }
    if (s->gil_wait_time_min_us != UINT64_MAX)
    {
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_GIL_WAIT_TIME_MIN,
                             (double)s->gil_wait_time_min_us / (double)APR_USEC_PER_SEC);
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_GIL_WAIT_TIME_MAX,
                             (double)s->gil_wait_time_max_us / (double)APR_USEC_PER_SEC);
    }
    if (s->input_read_time_min_us != UINT64_MAX)
    {
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_INPUT_READ_TIME_MIN,
                             (double)s->input_read_time_min_us / (double)APR_USEC_PER_SEC);
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_INPUT_READ_TIME_MAX,
                             (double)s->input_read_time_max_us / (double)APR_USEC_PER_SEC);
    }
    if (s->output_write_time_min_us != UINT64_MAX)
    {
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_OUTPUT_WRITE_TIME_MIN,
                             (double)s->output_write_time_min_us / (double)APR_USEC_PER_SEC);
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_OUTPUT_WRITE_TIME_MAX,
                             (double)s->output_write_time_max_us / (double)APR_USEC_PER_SEC);
    }
    if (s->has_daemon_timing)
    {
        if (s->queue_time_min_us != UINT64_MAX)
        {
            wsgi_metrics_put_f64(&p, WSGI_METRICS_F_QUEUE_TIME_MIN,
                                 (double)s->queue_time_min_us / (double)APR_USEC_PER_SEC);
            wsgi_metrics_put_f64(&p, WSGI_METRICS_F_QUEUE_TIME_MAX,
                                 (double)s->queue_time_max_us / (double)APR_USEC_PER_SEC);
        }
        if (s->daemon_time_min_us != UINT64_MAX)
        {
            wsgi_metrics_put_f64(&p, WSGI_METRICS_F_DAEMON_TIME_MIN,
                                 (double)s->daemon_time_min_us / (double)APR_USEC_PER_SEC);
            wsgi_metrics_put_f64(&p, WSGI_METRICS_F_DAEMON_TIME_MAX,
                                 (double)s->daemon_time_max_us / (double)APR_USEC_PER_SEC);
        }
    }

    wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_SERVER_TIME_BUCKETS,
                               s->server_time_buckets, WSGI_TELEMETRY_BUCKET_COUNT);
    wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_APPLICATION_TIME_BUCKETS,
                               s->application_time_buckets, WSGI_TELEMETRY_BUCKET_COUNT);
    if (s->has_daemon_timing)
    {
        wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_QUEUE_TIME_BUCKETS,
                                   s->queue_time_buckets, WSGI_TELEMETRY_BUCKET_COUNT);
        wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_DAEMON_TIME_BUCKETS,
                                   s->daemon_time_buckets, WSGI_TELEMETRY_BUCKET_COUNT);
    }
    wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_REQUEST_TIME_BUCKETS,
                               s->request_time_buckets, WSGI_TELEMETRY_BUCKET_COUNT);
    wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_GIL_WAIT_TIME_BUCKETS,
                               s->gil_wait_time_buckets, WSGI_TELEMETRY_BUCKET_COUNT);
    wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_INPUT_READ_TIME_BUCKETS,
                               s->input_read_time_buckets,
                               WSGI_TELEMETRY_BUCKET_COUNT);
    wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_OUTPUT_WRITE_TIME_BUCKETS,
                               s->output_write_time_buckets,
                               WSGI_TELEMETRY_BUCKET_COUNT);

    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_INPUT_BYTES_TOTAL,
                         s->input_bytes_total);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_INPUT_READS_TOTAL,
                         s->input_reads_total);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_OUTPUT_BYTES_TOTAL,
                         s->output_bytes_total);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_OUTPUT_WRITES_TOTAL,
                         s->output_writes_total);

    /*
     * Per-interval HTTP response class totals. Always emitted (even
     * when zero) so consumers can distinguish "zero of this class"
     * from "older encoder that didn't have the field". Sum equals
     * request_count for the same interval, modulo the status==0 fold
     * into 5xx.
     */

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

    if (s->slot_count > 0)
    {
        uint16_t n = (uint16_t)s->slot_count;
        wsgi_metrics_put_i32_array(&p, WSGI_METRICS_F_REQUEST_THREADS_COMPLETED,
                                   s->slot_request_count, n);
        wsgi_metrics_put_f64_array_from_i32_us(
            &p, WSGI_METRICS_F_REQUEST_THREADS_BUSY_TIME,
            s->slot_busy_time_us, n);
        wsgi_metrics_put_f64_array_from_i32_us(
            &p, WSGI_METRICS_F_REQUEST_THREADS_CPU_TIME,
            s->slot_cpu_time_us, n);
        wsgi_metrics_put_f64_array_from_i32_ms(
            &p, WSGI_METRICS_F_REQUEST_THREADS_CURRENT_ELAPSED,
            s->slot_current_elapsed_ms, n);
        wsgi_metrics_put_f64_array_from_i32_ms(
            &p, WSGI_METRICS_F_REQUEST_THREADS_MAX_DURATION,
            s->slot_max_duration_ms, n);
    }

    return (size_t)(p - buf);
}

static size_t wsgi_telemetry_encode_slow(const wsgi_slow_request_t *s,
                                         uint32_t pid, uint32_t seq,
                                         double stamp,
                                         uint8_t *buf, size_t buflen)
{
    uint8_t *p = buf;

    (void)buflen; /* deterministic; WSGI_METRICS_MAX_DATAGRAM sizes it */

    wsgi_metrics_put_header(&p, WSGI_METRICS_KIND_SLOW_REQUEST, pid, seq,
                            stamp);

    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_RECORD_STATE, s->state);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SLOW_START_STAMP,
                         (double)s->start_stamp_us / (double)APR_USEC_PER_SEC);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SLOW_DURATION,
                         (double)s->duration_us / (double)APR_USEC_PER_SEC);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_THREAD_ID, s->thread_id);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_SERVER_PID, s->server_pid);

    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_INPUT_BYTES, s->input_bytes);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_INPUT_READS, s->input_reads);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_OUTPUT_BYTES,
                         s->output_bytes);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_OUTPUT_WRITES,
                         s->output_writes);

    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SLOW_CPU_USER_TIME,
                         (double)s->cpu_user_us / (double)APR_USEC_PER_SEC);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SLOW_CPU_SYSTEM_TIME,
                         (double)s->cpu_system_us / (double)APR_USEC_PER_SEC);

    /*
     * Per-phase request timing. Always emitted (including zeros) so
     * consumers can render the breakdown without having to fall back
     * to "field absent means phase unknown" reasoning. queue_time and
     * daemon_time are zero in embedded mode where there is no daemon
     * hand-off; application_time is zero on active records that have
     * not yet entered the WSGI callable, partial otherwise.
     */

    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SLOW_SERVER_TIME,
                         (double)s->server_time_us / (double)APR_USEC_PER_SEC);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SLOW_QUEUE_TIME,
                         (double)s->queue_time_us / (double)APR_USEC_PER_SEC);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SLOW_DAEMON_TIME,
                         (double)s->daemon_time_us / (double)APR_USEC_PER_SEC);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SLOW_APPLICATION_TIME,
                         (double)s->application_time_us / (double)APR_USEC_PER_SEC);

    /*
     * GIL-wait pressure indicator for this single request. Always
     * emitted (including zeros) so the slow-record detail panel can
     * surface the value uniformly. For active records this is the
     * running sum; for completed records it is the final total.
     */

    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SLOW_GIL_WAIT_TIME,
                         (double)s->gil_wait_us / (double)APR_USEC_PER_SEC);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_GIL_WAIT_COUNT,
                         s->gil_wait_count);

    /*
     * I/O time overlap indicators for this single request. Always
     * emitted (including zeros) so the slow-record detail panel can
     * surface them uniformly. For active records these are zero
     * (the slot's io_input_read_us / io_output_write_us are only
     * stamped at end-of-request); for completed records they are the
     * final totals.
     */

    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SLOW_INPUT_READ_TIME,
                         (double)s->input_read_us / (double)APR_USEC_PER_SEC);
    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SLOW_OUTPUT_WRITE_TIME,
                         (double)s->output_write_us / (double)APR_USEC_PER_SEC);

    /*
     * Concurrency context. active_at_completion is zero for active
     * records (the request has not finished yet); always emitted so
     * consumers see the "0 = not yet known" sentinel rather than a
     * missing field.
     */

    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_ACTIVE_AT_START,
                         s->active_at_start);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_SLOW_ACTIVE_AT_COMPLETION,
                         s->active_at_completion);

    /*
     * Final HTTP response status. Zero for active records (the WSGI
     * app may not have called start_response yet); always emitted so
     * consumers see the "0 = not yet known" sentinel rather than a
     * missing field.
     */

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
    if (s->protocol[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_SLOW_PROTOCOL,
                               s->protocol,
                               (uint16_t)strlen(s->protocol));
    if (s->peer_ip[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_SLOW_PEER_IP,
                               s->peer_ip,
                               (uint16_t)strlen(s->peer_ip));
    if (s->user_agent[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_SLOW_USER_AGENT,
                               s->user_agent,
                               (uint16_t)strlen(s->user_agent));

    return (size_t)(p - buf);
}

/* ------------------------------------------------------------------------- */

/*
 * Lifecycle encoders. STARTED carries identity at process birth so the
 * consumer doesn't have to wait for the first periodic tick to register
 * the process exists. STOPPING is the chart-marker, fired at decision
 * time before drain. STOPPED is the end-of-record summary, fired after
 * drain completes and the reporter has been quiesced.
 */

static size_t wsgi_telemetry_encode_started(const wsgi_telemetry_ctx_t *ctx,
                                            uint32_t seq, uint8_t *buf,
                                            size_t buflen)
{
    uint8_t *p = buf;

    (void)buflen;

    wsgi_metrics_put_header(&p, WSGI_METRICS_KIND_PROCESS_STARTED, ctx->pid,
                            seq,
                            (double)ctx->process_start_us /
                            (double)APR_USEC_PER_SEC);

    if (ctx->mod_wsgi_version[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_MOD_WSGI_VERSION,
                               ctx->mod_wsgi_version,
                               (uint16_t)strlen(ctx->mod_wsgi_version));
    if (ctx->python_version[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_PYTHON_VERSION,
                               ctx->python_version,
                               (uint16_t)strlen(ctx->python_version));
    if (ctx->apache_version[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_APACHE_VERSION,
                               ctx->apache_version,
                               (uint16_t)strlen(ctx->apache_version));
    if (ctx->mpm_name[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_MPM_NAME, ctx->mpm_name,
                               (uint16_t)strlen(ctx->mpm_name));
    if (ctx->hostname[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_HOSTNAME, ctx->hostname,
                               (uint16_t)strlen(ctx->hostname));
    if (ctx->process_group[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_PROCESS_GROUP,
                               ctx->process_group,
                               (uint16_t)strlen(ctx->process_group));

    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_PROCESS_PARENT_PID,
                         ctx->parent_pid);

    if (ctx->switch_interval > 0.0)
        wsgi_metrics_put_f64(&p, WSGI_METRICS_F_SWITCH_INTERVAL,
                             ctx->switch_interval);

    return (size_t)(p - buf);
}

static size_t wsgi_telemetry_encode_stopping(const wsgi_telemetry_ctx_t *ctx,
                                             const char *reason,
                                             uint64_t active_at_decision,
                                             uint32_t seq, uint8_t *buf,
                                             size_t buflen)
{
    uint8_t *p = buf;
    double now = (double)apr_time_now() / (double)APR_USEC_PER_SEC;

    (void)buflen;

    wsgi_metrics_put_header(&p, WSGI_METRICS_KIND_PROCESS_STOPPING, ctx->pid,
                            seq, now);

    if (ctx->hostname[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_HOSTNAME, ctx->hostname,
                               (uint16_t)strlen(ctx->hostname));
    if (ctx->process_group[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_PROCESS_GROUP,
                               ctx->process_group,
                               (uint16_t)strlen(ctx->process_group));
    if (reason && *reason)
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_SHUTDOWN_REASON, reason,
                               (uint16_t)strlen(reason));

    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_ACTIVE_REQUESTS_AT_DECISION,
                         active_at_decision);

    return (size_t)(p - buf);
}

static size_t wsgi_telemetry_encode_stopped(const wsgi_telemetry_ctx_t *ctx,
                                            const char *reason,
                                            uint64_t lifetime_count,
                                            uint64_t active_at_exit,
                                            int graceful,
                                            uint32_t seq, uint8_t *buf,
                                            size_t buflen)
{
    uint8_t *p = buf;
    apr_time_t now_us = apr_time_now();
    double now = (double)now_us / (double)APR_USEC_PER_SEC;
    double uptime = (double)(now_us - (apr_time_t)ctx->process_start_us) /
                    (double)APR_USEC_PER_SEC;
    uint64_t graceful_drain = graceful ? 1 : 0;

    (void)buflen;

    wsgi_metrics_put_header(&p, WSGI_METRICS_KIND_PROCESS_STOPPED, ctx->pid,
                            seq, now);

    if (ctx->hostname[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_HOSTNAME, ctx->hostname,
                               (uint16_t)strlen(ctx->hostname));
    if (ctx->process_group[0])
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_PROCESS_GROUP,
                               ctx->process_group,
                               (uint16_t)strlen(ctx->process_group));
    if (reason && *reason)
        wsgi_metrics_put_bytes(&p, WSGI_METRICS_F_SHUTDOWN_REASON, reason,
                               (uint16_t)strlen(reason));

    wsgi_metrics_put_f64(&p, WSGI_METRICS_F_PROCESS_UPTIME, uptime);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_LIFETIME_REQUEST_COUNT,
                         lifetime_count);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_ACTIVE_REQUESTS_AT_EXIT,
                         active_at_exit);
    wsgi_metrics_put_u64(&p, WSGI_METRICS_F_GRACEFUL_DRAIN, graceful_drain);

    return (size_t)(p - buf);
}

/* ------------------------------------------------------------------------- */

/*
 * Per-tick emitter. Snapshots the periodic accumulators, fills in the
 * identity strings the snapshot does not own, encodes / sends the
 * KIND_REQUEST datagram, then drains the slow-completed ring and scans
 * any still-active slow records, emitting one KIND_SLOW_REQUEST
 * datagram per record. Called from the reporter thread on every tick
 * and from emit_final_tick on the daemon main thread when shutting
 * down: accumulators are drained-and-reset, so calling this once more
 * at shutdown captures the partial window since the reporter's last
 * tick that would otherwise be lost.
 */

static void wsgi_telemetry_emit_tick(const wsgi_telemetry_ctx_t *ctx)
{
    wsgi_telemetry_sample_t sample;
    uint8_t buf[WSGI_METRICS_MAX_DATAGRAM];
    size_t n;
    uint32_t seq;

    if (!wsgi_metrics_snapshot(&sample))
        return;

    /*
     * Populate identity + reporter config that the snapshot function
     * does not fill. The slow-request threshold is in microseconds,
     * exposed as seconds on the wire so the UI can compare directly
     * with the heatmap stuck-threshold dropdown.
     */

    strncpy(sample.hostname, ctx->hostname, sizeof(sample.hostname) - 1);
    sample.hostname[sizeof(sample.hostname) - 1] = '\0';
    strncpy(sample.process_group, ctx->process_group,
            sizeof(sample.process_group) - 1);
    sample.process_group[sizeof(sample.process_group) - 1] = '\0';
    strncpy(sample.mod_wsgi_version, ctx->mod_wsgi_version,
            sizeof(sample.mod_wsgi_version) - 1);
    sample.mod_wsgi_version[sizeof(sample.mod_wsgi_version) - 1] = '\0';
    strncpy(sample.python_version, ctx->python_version,
            sizeof(sample.python_version) - 1);
    sample.python_version[sizeof(sample.python_version) - 1] = '\0';
    strncpy(sample.apache_version, ctx->apache_version,
            sizeof(sample.apache_version) - 1);
    sample.apache_version[sizeof(sample.apache_version) - 1] = '\0';
    strncpy(sample.mpm_name, ctx->mpm_name, sizeof(sample.mpm_name) - 1);
    sample.mpm_name[sizeof(sample.mpm_name) - 1] = '\0';
    sample.parent_pid = ctx->parent_pid;
    sample.telemetry_interval = wsgi_telemetry_interval;
    sample.slow_requests_threshold =
        (double)wsgi_slow_threshold_us / 1.0e6;
    sample.switch_interval = ctx->switch_interval;

    if (!sample.seeded)
        return; /* first call seeded counters; skip send */

    seq = wsgi_telemetry_next_seq();
    n = wsgi_telemetry_encode(&sample, ctx->pid, seq, buf, sizeof(buf));
    wsgi_telemetry_send(ctx, buf, n);

    /*
     * Slow-request tracking: one datagram per record. Completed
     * records drain first so their final duration arrives before any
     * heartbeat that would otherwise make the UI age the entry out as
     * "lost". Active-scan uses a consistent now_us so all elapsed
     * values in this tick share a reference.
     */

    if (wsgi_slow_threshold_us > 0)
    {
        wsgi_slow_request_t rec;
        wsgi_slow_request_t actives[16];
        int n_active;
        int i;
        apr_time_t tick_stamp_us = apr_time_now();
        double tick_stamp = (double)tick_stamp_us / (double)APR_USEC_PER_SEC;

        while (wsgi_metrics_pop_slow_completed(&rec))
        {
            seq = wsgi_telemetry_next_seq();
            n = wsgi_telemetry_encode_slow(&rec, ctx->pid, seq, tick_stamp,
                                           buf, sizeof(buf));
            wsgi_telemetry_send(ctx, buf, n);
        }

        n_active = wsgi_metrics_snapshot_slow_active(
            actives, (int)(sizeof(actives) / sizeof(actives[0])),
            tick_stamp_us, wsgi_slow_threshold_us);

        for (i = 0; i < n_active; i++)
        {
            seq = wsgi_telemetry_next_seq();
            n = wsgi_telemetry_encode_slow(&actives[i], ctx->pid, seq,
                                           tick_stamp, buf, sizeof(buf));
            wsgi_telemetry_send(ctx, buf, n);
        }
    }
}

/* ------------------------------------------------------------------------- */

static void *APR_THREAD_FUNC wsgi_telemetry_thread_main(apr_thread_t *t,
                                                        void *data)
{
    uint8_t buf[WSGI_METRICS_MAX_DATAGRAM];
    size_t n;
    uint32_t seq;
    apr_interval_time_t sleep_us;

    /*
     * Populate the reporter context. fd is held here so the daemon
     * main thread can use it for lifecycle datagrams on the same
     * socket; process_start_us is the STARTED header timestamp and
     * the basis for STOPPED's uptime field.
     */

    wsgi_telemetry_ctx.fd = -1;
    wsgi_telemetry_ctx.pid = (uint32_t)getpid();
    wsgi_telemetry_ctx.parent_pid = (uint32_t)getppid();
    wsgi_telemetry_ctx.process_start_us = apr_time_now();

    if (wsgi_telemetry_open(wsgi_telemetry_target,
                            &wsgi_telemetry_ctx.fd,
                            &wsgi_telemetry_ctx.addr,
                            &wsgi_telemetry_ctx.addrlen) != 0)
    {
        wsgi_log_error(APLOG_WARNING, 0, wsgi_server, WSGI_APLOGNO(0132) "Telemetry reporter could not open target '%s'; "
                                                                         "metrics will not be sent.",
                       wsgi_telemetry_target);
        return NULL;
    }

    if (gethostname(wsgi_telemetry_ctx.hostname,
                    sizeof(wsgi_telemetry_ctx.hostname)) != 0)
        wsgi_telemetry_ctx.hostname[0] = '\0';
    wsgi_telemetry_ctx.hostname[sizeof(wsgi_telemetry_ctx.hostname) - 1] = '\0';

    wsgi_telemetry_ctx.process_group[0] = '\0';
#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process && wsgi_daemon_process->group &&
        wsgi_daemon_process->group->name)
    {
        strncpy(wsgi_telemetry_ctx.process_group,
                wsgi_daemon_process->group->name,
                sizeof(wsgi_telemetry_ctx.process_group) - 1);
        wsgi_telemetry_ctx.process_group[sizeof(wsgi_telemetry_ctx.process_group) - 1] = '\0';
    }
#endif

    /*
     * Build / runtime identity. Populated once; static for the life
     * of the process. Empty values are tolerated: the encoder skips
     * fields with a leading nul so an ingester never sees an empty
     * string where it expects a real version.
     */

    strncpy(wsgi_telemetry_ctx.mod_wsgi_version, MOD_WSGI_VERSION_STRING,
            sizeof(wsgi_telemetry_ctx.mod_wsgi_version) - 1);
    wsgi_telemetry_ctx.mod_wsgi_version[sizeof(wsgi_telemetry_ctx.mod_wsgi_version) - 1] = '\0';

    {
        /*
         * Py_GetVersion() returns "3.14.0 (main, Jan 15 2026, ...)";
         * trim to the leading version token so the banner stays
         * compact. Same approach as wsgi_interp.c uses for the
         * SERVER_SOFTWARE construction.
         */

        const char *pv = Py_GetVersion();
        size_t i = 0;
        if (pv)
        {
            while (i < sizeof(wsgi_telemetry_ctx.python_version) - 1 && pv[i] && pv[i] != ' ' && pv[i] != '\t')
            {
                wsgi_telemetry_ctx.python_version[i] = pv[i];
                i++;
            }
        }
        wsgi_telemetry_ctx.python_version[i] = '\0';
    }

    {
        /*
         * Capture sys.getswitchinterval() once. The contract is that
         * the interval is set at process start (via WSGISwitchInterval
         * or the switch-interval option on WSGIDaemonProcess) and not
         * mutated from Python after; the value reported here is the
         * one in effect for every subsequent tick under that contract.
         * If the contract is broken the contention coefficient
         * computed downstream is undefined.
         */

        PyGILState_STATE gstate = PyGILState_Ensure();
        PyObject *sys = PyImport_ImportModule("sys");
        wsgi_telemetry_ctx.switch_interval = 0.0;
        if (sys)
        {
            PyObject *r = PyObject_CallMethod(sys, "getswitchinterval",
                                              NULL);
            if (r)
            {
                double v = PyFloat_AsDouble(r);
                if (!PyErr_Occurred() && v > 0.0)
                    wsgi_telemetry_ctx.switch_interval = v;
                Py_DECREF(r);
            }
            Py_DECREF(sys);
        }
        PyErr_Clear();
        PyGILState_Release(gstate);
    }

    /*
     * AP_SERVER_BASEVERSION is the compile-time Apache version
     * ("Apache/2.4.62") and isn't subject to the ServerTokens
     * directive, which is what is wanted here: telemetry needs the
     * actual binary version regardless of whether the admin has
     * redacted the public banner.
     */

    strncpy(wsgi_telemetry_ctx.apache_version, AP_SERVER_BASEVERSION,
            sizeof(wsgi_telemetry_ctx.apache_version) - 1);
    wsgi_telemetry_ctx.apache_version[sizeof(wsgi_telemetry_ctx.apache_version) - 1] = '\0';

    {
        const char *mpm = ap_show_mpm();
        if (mpm)
        {
            strncpy(wsgi_telemetry_ctx.mpm_name, mpm,
                    sizeof(wsgi_telemetry_ctx.mpm_name) - 1);
            wsgi_telemetry_ctx.mpm_name[sizeof(wsgi_telemetry_ctx.mpm_name) - 1] = '\0';
        }
        else
        {
            wsgi_telemetry_ctx.mpm_name[0] = '\0';
        }
    }

    wsgi_telemetry_ctx_ready = 1;

    /*
     * Emit STARTED before the periodic loop begins so the consumer
     * registers the process without having to wait for the first
     * periodic tick.
     */

    seq = wsgi_telemetry_next_seq();
    n = wsgi_telemetry_encode_started(&wsgi_telemetry_ctx, seq,
                                      buf, sizeof(buf));
    wsgi_telemetry_send(&wsgi_telemetry_ctx, buf, n);

    sleep_us = (apr_interval_time_t)(wsgi_telemetry_interval * APR_USEC_PER_SEC);
    if (sleep_us < 100000) /* floor at 100ms */
        sleep_us = 100000;

    wsgi_log_error(APLOG_INFO, 0, wsgi_server,
                   "Telemetry reporter started; target='%s', "
                   "interval=%.3fs.",
                   wsgi_telemetry_target, wsgi_telemetry_interval);

    while (!wsgi_telemetry_shutdown)
    {
        apr_sleep(sleep_us);
        if (wsgi_telemetry_shutdown)
            break;
        wsgi_telemetry_emit_tick(&wsgi_telemetry_ctx);
    }

    /*
     * Don't close fd here; pause_reporter / stop_reporter manages
     * that. Leaving it open lets the daemon main thread call
     * emit_final_tick to flush the partial window and emit STOPPED
     * via the same socket.
     */

    return NULL;
}

/* ------------------------------------------------------------------------- */

/*
 * Directive handler: WSGITelemetryService <target> [interval=N]
 * Target must be "unix:/path"; remote IPv4 UDP targets are not
 * supported (the reporter assumes a co-located ingester so that
 * MTU / IP-fragmentation / packet-loss across a real network are
 * non-concerns).
 */

const char *wsgi_set_telemetry_service(cmd_parms *cmd, void *mconfig,
                                     const char *arg1, const char *arg2)
{
    const char *error = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    if (!arg1 || !*arg1)
        return "WSGITelemetryService target required";

    if (strncmp(arg1, "unix:", 5) != 0)
        return "WSGITelemetryService target must be 'unix:/path' "
               "(remote 'udp:host:port' targets are no longer supported)";

    wsgi_telemetry_target = apr_pstrdup(cmd->pool, arg1);
    wsgi_telemetry_enabled = 1;

    if (arg2)
    {
        double v = 0.0;
        if (strncmp(arg2, "interval=", 9) == 0)
        {
            v = atof(arg2 + 9);
            if (v < 0.5)
                return "WSGITelemetryService interval must be at least "
                       "0.5 seconds";
            wsgi_telemetry_interval = v;
        }
        else
        {
            return "WSGITelemetryService second argument must be "
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
 * meaningful when WSGITelemetryService is also configured; without a
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

/*
 * Directive handler: WSGITelemetryOptions [+|-]Flag [+|-]Flag ... | None | All
 *
 * Apache-Options-style toggle for metrics capture. Flags can be
 * given absolutely (replaces the current set) or with +/- prefixes
 * (modifies the current set). Mixing absolute and incremental tokens
 * in a single directive is rejected, matching Apache's Options
 * convention. None / All are absolute pseudo-tokens that reset to no
 * flags / every flag respectively.
 *
 * Default flag state is zero (every flag is opt-in). Currently the
 * only flag is CaptureUserAgent, which controls whether the User-
 * Agent request header is included in slow-request records.
 */

int wsgi_telemetry_options = 0;

static const struct
{
    const char *name;
    int flag;
} wsgi_metrics_option_names[] = {
    {"CaptureUserAgent", WSGI_TELEMETRY_OPT_CAPTURE_USER_AGENT},
    {NULL, 0}};

static int wsgi_metrics_option_lookup(const char *name)
{
    int i;
    for (i = 0; wsgi_metrics_option_names[i].name; i++)
    {
        if (strcasecmp(name, wsgi_metrics_option_names[i].name) == 0)
            return wsgi_metrics_option_names[i].flag;
    }
    return 0;
}

const char *wsgi_set_telemetry_options(cmd_parms *cmd, void *mconfig,
                                     const char *args)
{
    const char *error = NULL;
    int seen_incremental = 0;
    int seen_absolute = 0;
    int incremental_options;
    int absolute_options = 0;
    char *token;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    if (!args || !*args)
        return "WSGITelemetryOptions: at least one flag required";

    /*
     * Start the incremental accumulator from the current global so
     * `+Foo` / `-Foo` directives stack. Absolute form fully replaces
     * and ignores the starting value.
     */

    incremental_options = wsgi_telemetry_options;

    while (*args)
    {
        const char *name;
        int is_negation = 0;

        token = ap_getword_conf(cmd->temp_pool, &args);
        if (!*token)
            break;

        if (token[0] == '+' || token[0] == '-')
        {
            is_negation = (token[0] == '-');
            seen_incremental = 1;
            name = token + 1;
            if (!*name)
                return "WSGITelemetryOptions: bare '+' / '-' is not a flag";
        }
        else
        {
            seen_absolute = 1;
            name = token;
        }

        if (seen_incremental && seen_absolute)
            return "WSGITelemetryOptions: cannot mix +/- form with "
                   "absolute names in a single directive";

        if (strcasecmp(name, "None") == 0)
        {
            if (token[0] == '+' || token[0] == '-')
                return "WSGITelemetryOptions: 'None' may not have a "
                       "+/- prefix";
            absolute_options = 0;
            continue;
        }
        if (strcasecmp(name, "All") == 0)
        {
            if (token[0] == '+' || token[0] == '-')
                return "WSGITelemetryOptions: 'All' may not have a "
                       "+/- prefix";
            absolute_options = WSGI_TELEMETRY_OPT_ALL;
            continue;
        }

        int flag = wsgi_metrics_option_lookup(name);
        if (!flag)
            return apr_psprintf(cmd->temp_pool,
                                "WSGITelemetryOptions: unknown flag '%s'", name);

        if (seen_incremental)
        {
            if (is_negation)
                incremental_options &= ~flag;
            else
                incremental_options |= flag;
        }
        else
        {
            absolute_options |= flag;
        }
    }

    if (seen_incremental)
        wsgi_telemetry_options = incremental_options;
    else
        wsgi_telemetry_options = absolute_options;

    return NULL;
}

/* ------------------------------------------------------------------------- */

void wsgi_telemetry_start_reporter(apr_pool_t *pool)
{
    apr_status_t rv;

    if (!wsgi_telemetry_enabled || wsgi_telemetry_started)
        return;

    wsgi_telemetry_started = 1;

    /*
     * Seed the snapshot baselines and turn on per-request accounting
     * before the reporter thread (and any worker thread) starts. The
     * reporter's first periodic tick fires one telemetry interval
     * after spawn; without this seed, every request served in that
     * startup window would be silently dropped at the
     * request_metrics_enabled gate in wsgi_record_request_times.
     */

    wsgi_metrics_telemetry_init();

    rv = apr_thread_create(&wsgi_telemetry_thread, NULL,
                           wsgi_telemetry_thread_main, NULL, pool);
    if (rv != APR_SUCCESS)
    {
        wsgi_log_error(APLOG_WARNING, rv, wsgi_server, WSGI_APLOGNO(0133) "Unable to create telemetry reporter thread; "
                                                                          "metrics will not be sent.");
        wsgi_telemetry_started = 0;
    }
}

/* ------------------------------------------------------------------------- */

void wsgi_telemetry_stop_reporter(void)
{
    if (!wsgi_telemetry_started)
        return;

    wsgi_telemetry_shutdown = 1;
    if (wsgi_telemetry_thread)
    {
        apr_status_t rv = APR_SUCCESS;
        apr_thread_join(&rv, wsgi_telemetry_thread);
        wsgi_telemetry_thread = NULL;
    }
    wsgi_telemetry_started = 0;

    /*
     * Close the socket here for callers that don't go through the
     * graceful pause / final-tick / STOPPED path. emit_final_tick
     * closes it itself and clears ctx_ready, so this branch is a
     * no-op on that path.
     */

    if (wsgi_telemetry_ctx_ready && wsgi_telemetry_ctx.fd >= 0)
    {
        close(wsgi_telemetry_ctx.fd);
        wsgi_telemetry_ctx.fd = -1;
        wsgi_telemetry_ctx_ready = 0;
    }
}

/* ------------------------------------------------------------------------- */

/*
 * Quiesce the reporter thread without closing the socket. Used during
 * graceful daemon shutdown: the daemon main thread first emits
 * STOPPING, lets drain run with the reporter still ticking, then calls
 * pause_reporter to join the thread before doing the final flush + the
 * STOPPED emit on the daemon main thread (see emit_final_tick).
 */

void wsgi_telemetry_pause_reporter(void)
{
    if (!wsgi_telemetry_started)
        return;

    wsgi_telemetry_shutdown = 1;
    if (wsgi_telemetry_thread)
    {
        apr_status_t rv = APR_SUCCESS;
        apr_thread_join(&rv, wsgi_telemetry_thread);
        wsgi_telemetry_thread = NULL;
    }
    wsgi_telemetry_started = 0;
}

/* ------------------------------------------------------------------------- */

/*
 * Emit the STOPPING chart-marker datagram. Called from the daemon
 * main thread (or the embedded-mode child cleanup) at the moment
 * shutdown is decided, before drain begins. Reads active_requests
 * under the monitor lock so the at-decision count is consistent with
 * whoever else may be reading it. Safe to call concurrently with the
 * reporter thread; both share the socket and seq is atomic.
 */

void wsgi_telemetry_emit_process_stopping(const char *reason)
{
    uint8_t buf[WSGI_METRICS_MAX_DATAGRAM];
    uint32_t seq;
    size_t n;
    uint64_t active;

    if (!wsgi_telemetry_ctx_ready)
        return;

    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);
    active = (uint64_t)wsgi_process_metrics->active_requests;
    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);

    seq = wsgi_telemetry_next_seq();
    n = wsgi_telemetry_encode_stopping(&wsgi_telemetry_ctx, reason, active,
                                       seq, buf, sizeof(buf));
    wsgi_telemetry_send(&wsgi_telemetry_ctx, buf, n);
}

/* ------------------------------------------------------------------------- */

/*
 * Encode + send the STOPPED datagram. Idempotent: the first caller
 * wins the CAS on wsgi_telemetry_stopped_emitted and sends; subsequent
 * callers become no-ops. This is the single point of STOPPED
 * emission, called from two paths:
 *
 *   - graceful path: wsgi_telemetry_emit_final_tick on the daemon
 *     main thread after worker drain completes (graceful=1 if no
 *     active requests remain, 0 otherwise).
 *
 *   - reaper path: wsgi_reaper_thread when shutdown_timeout fires
 *     and the process is about to be force-exited (graceful=0). The
 *     reporter thread is still running; sendto() and the seq counter
 *     are both safe under that concurrency.
 *
 * Without the reaper-path emission STOPPED is silently lost whenever
 * worker drain runs longer than shutdown_timeout, which is exactly
 * the case operators most want to see in the lifecycle event log.
 */

void wsgi_telemetry_emit_process_stopped(const char *reason, int graceful)
{
    uint8_t buf[WSGI_METRICS_MAX_DATAGRAM];
    uint32_t seq;
    size_t n;
    uint64_t lifetime;
    uint64_t active;

    if (!wsgi_telemetry_ctx_ready)
        return;

    if (apr_atomic_cas32(&wsgi_telemetry_stopped_emitted, 1, 0) != 0)
        return;

    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);
    lifetime = wsgi_process_metrics->total_requests;
    active = (uint64_t)wsgi_process_metrics->active_requests;
    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);

    seq = wsgi_telemetry_next_seq();
    n = wsgi_telemetry_encode_stopped(&wsgi_telemetry_ctx, reason, lifetime,
                                      active, graceful, seq, buf, sizeof(buf));
    wsgi_telemetry_send(&wsgi_telemetry_ctx, buf, n);
}

/* ------------------------------------------------------------------------- */

/*
 * Graceful-path final flush + STOPPED emit + socket close. Called once
 * on the daemon main thread after pause_reporter has joined the
 * reporter thread. Runs one more emit_tick so the partial window since
 * the reporter's last tick is on the wire (otherwise drain-and-reset
 * semantics would lose those accumulators), then emits STOPPED via the
 * idempotent wsgi_telemetry_emit_process_stopped helper, then closes
 * the socket. If the reaper has already emitted STOPPED, the
 * idempotency guard turns the STOPPED step here into a no-op; the
 * partial-window flush still runs since it isn't gated by the same
 * flag (the reporter is paused, so we can't double-emit it).
 */

void wsgi_telemetry_emit_final_tick(const char *reason)
{
    uint64_t active;

    if (!wsgi_telemetry_ctx_ready)
        return;

    /* Flush the partial window the reporter didn't get to. */
    wsgi_telemetry_emit_tick(&wsgi_telemetry_ctx);

    /*
     * Graceful drain succeeded iff no requests are still in-flight at
     * this point: drain has completed and pause_reporter has joined
     * the reporter, so this is the authoritative reading.
     */

    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);
    active = (uint64_t)wsgi_process_metrics->active_requests;
    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);

    wsgi_telemetry_emit_process_stopped(reason, active == 0);

    if (wsgi_telemetry_ctx.fd >= 0)
    {
        close(wsgi_telemetry_ctx.fd);
        wsgi_telemetry_ctx.fd = -1;
    }
    wsgi_telemetry_ctx_ready = 0;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
