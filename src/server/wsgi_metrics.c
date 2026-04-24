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

#include "wsgi_metrics.h"

#include "wsgi_apache.h"
#include "wsgi_daemon.h"
#include "wsgi_server.h"
#include "wsgi_memory.h"
#include "wsgi_logger.h"
#include "wsgi_thread.h"
#include "wsgi_telemetry.h"

#include <math.h>           /* ceil() — slow-ring sizing math */

/* ------------------------------------------------------------------------- */

/*
 * Thread utilisation. On start and end of requests,
 * and when utilisation is requested, we acrue an
 * ongoing utilisation time value so can monitor how
 * busy we are handling requests.
 */

apr_uint64_t wsgi_total_requests = 0;
int wsgi_active_requests = 0;
static double wsgi_thread_utilization = 0.0;
static apr_time_t wsgi_utilization_last = 0;

/* Request tracking and timing. */

apr_thread_mutex_t *wsgi_monitor_lock = NULL;

/* Caller MUST hold wsgi_monitor_lock. Touches wsgi_thread_utilization,
 * wsgi_utilization_last, wsgi_active_requests and wsgi_total_requests —
 * all covered by that same lock. */

static double wsgi_utilization_time_locked(int adjustment,
                                           apr_uint64_t *request_count)
{
    apr_time_t now;
    double utilization = wsgi_thread_utilization;

    now = apr_time_now();

    if (wsgi_utilization_last != 0)
    {
        utilization = (now - wsgi_utilization_last) / 1000000.0;

        if (utilization < 0)
            utilization = 0;

        utilization = wsgi_active_requests * utilization;
        wsgi_thread_utilization += utilization;
        utilization = wsgi_thread_utilization;
    }

    wsgi_utilization_last = now;
    wsgi_active_requests += adjustment;

    if (adjustment < 0)
        wsgi_total_requests += -adjustment;

    if (request_count)
        *request_count = wsgi_total_requests;

    return utilization;
}

static int wsgi_request_metrics_enabled = 0;
static apr_uint64_t wsgi_sample_requests = 0;
static double wsgi_server_time_total = 0;
static int wsgi_server_time_buckets[16];
static double wsgi_queue_time_total = 0;
static int wsgi_queue_time_buckets[16];
static double wsgi_daemon_time_total = 0;
static int wsgi_daemon_time_buckets[16];
static double wsgi_application_time_total = 0;
static int wsgi_application_time_buckets[16];
/* Total response time = server + queue + daemon + application, bucketed
 * once per request so the UI can show the distribution as the caller
 * actually sees it rather than any single phase. Apache's accept-queue
 * wait isn't measurable from within, so this is still a lower bound. */
static int wsgi_request_time_buckets[16];

/* Per-interval request I/O totals. Folded at end-of-request from the
 * adapter's InputObject/AdapterObject counters; drained and zeroed by
 * whichever reader (telemetry snapshot or Python accessor) fires
 * first, same drain-clash semantics as the time/bucket aggregators. */
static apr_uint64_t wsgi_input_bytes_total = 0;
static apr_uint64_t wsgi_input_reads_total = 0;
static apr_uint64_t wsgi_output_bytes_total = 0;
static apr_uint64_t wsgi_output_writes_total = 0;

/* Per-thread active-slot array. One entry per worker thread (sized to the
 * MPM max_threads in embedded mode or the daemon group's threads count in
 * daemon mode). Each slot carries the live request_rec pointer while the
 * thread is serving a request so the telemetry reporter can read URL /
 * identity fields on demand without copying them at request start. The
 * extra fields (busy_since_us, cpu_user_at_start, cpu_system_at_start)
 * drive the per-slot capacity metrics: busy-fraction of the interval and
 * CPU-time delta contributed by this slot.
 *
 * Slow-request tracking. Threshold is written once at config time via
 * WSGISlowRequests (0 = disabled, i.e. feature off). The completed ring
 * holds fully snapshotted records for requests that finished while slow,
 * so the reporter thread can emit a final datagram at its next tick. */

/* Completed-ring sizing. Floor matches the historical static size so
 * a tiny embedded MPM (a few threads at the default reporter
 * interval) gets the same headroom as before. Cap prevents
 * pathological allocations when WSGISlowRequests is set very low
 * (e.g. 0.01 s for debugging). Safety factor covers inter-tick
 * jitter and bursts where many threads complete near-simultaneously
 * — the formula otherwise assumes uniform distribution which real
 * workloads don't follow. */
#define WSGI_SLOW_RING_FLOOR   32
#define WSGI_SLOW_RING_CAP     4096
#define WSGI_SLOW_RING_SAFETY  5

apr_time_t wsgi_slow_threshold_us = 0;
extern double wsgi_telemetry_interval;

typedef struct
{
    int in_use;
    request_rec *r; /* valid only while in_use; lives in r->pool */
    apr_time_t start_us;
    uint32_t thread_id; /* 1-based, matches WSGIThreadInfo.thread_id */

    /* Per-request baselines captured at wsgi_start_request, consumed by
     * wsgi_end_request and wsgi_metrics_snapshot to compute per-slot
     * interval accumulators. busy_since_us equals start_us at request
     * start and is reset to now() at each tick while the slot stays
     * in use, so long-running requests contribute to every tick they
     * span (not just the tick they complete in). cpu_valid is 0 if the
     * start-time CPU capture failed, so end_request knows not to fold
     * a bogus (thread-lifetime-long) delta. */
    apr_time_t busy_since_us;
    int        cpu_valid;
    double     cpu_user_at_start;
    double     cpu_system_at_start;

    /* Per-request I/O counters, written by wsgi_record_request_times
     * once the adapter knows the final read/write totals and consumed
     * by wsgi_end_request when snapshotting a slow-completion record.
     * Zero while no request is in flight or the request hasn't yet
     * reached its end-of-request hook. Active-record snapshots in
     * wsgi_metrics_snapshot_slow_active() report these as the partial
     * I/O so far (zero until end-of-request). */
    apr_off_t  io_input_bytes;
    apr_off_t  io_input_reads;
    apr_off_t  io_output_bytes;
    apr_off_t  io_output_writes;
} wsgi_active_slot_t;

/* Parallel array of per-slot interval accumulators. Drained and reset at
 * each tick (by either the telemetry reporter or the Python accessor —
 * whichever fires first; the remaining reader gets an empty interval).
 * The drain-clash is accepted here and called out in the plan as a
 * follow-up once a proper per-reader baseline scheme is in place. */

typedef struct
{
    apr_time_t busy_time_us;    /* folded busy time this interval */
    apr_time_t cpu_time_us;     /* folded CPU time this interval */
    uint32_t   completed;       /* completed-request count this interval */
    apr_time_t max_duration_us; /* longest single request this interval */
} wsgi_slot_stats_t;

static wsgi_active_slot_t *wsgi_active_slots = NULL;
static wsgi_slot_stats_t  *wsgi_slot_stats = NULL;
static int wsgi_active_slots_max = 0;

static wsgi_slow_request_t *wsgi_completed_ring = NULL;
static int wsgi_completed_ring_size = 0;
static int wsgi_completed_ring_head = 0;
static int wsgi_completed_ring_count = 0;

/* Forward declarations — implementations live after wsgi_metrics_snapshot. */

static void wsgi_slots_ensure_locked(void);
static void wsgi_slow_snapshot_fields(wsgi_slow_request_t *rec, request_rec *r);
static void wsgi_slow_push_completed_locked(const wsgi_slow_request_t *rec);

void wsgi_record_time_in_buckets(int *buckets, double duration)
{
    int index = 0;
    double threshold = 0.005;

    while (index < 14)
    {
        if (duration <= threshold)
        {
            buckets[index] += 1;
            return;
        }

        threshold *= 2;
        index += 1;
    }

    buckets[index] += 1;
}

void wsgi_record_request_times(apr_time_t request_start,
                               apr_time_t queue_start, apr_time_t daemon_start,
                               apr_time_t application_start, apr_time_t application_finish,
                               apr_off_t input_bytes, apr_off_t input_reads,
                               apr_off_t output_bytes, apr_off_t output_writes)
{

    double server_time = 0.0;
    double queue_time = 0.0;
    double daemon_time = 0.0;
    double application_time = 0.0;
    WSGIThreadInfo *thread_info = NULL;

    if (wsgi_request_metrics_enabled == 0)
        return;

    if (queue_start)
    {
        server_time = apr_time_sec((double)(queue_start - request_start));
        queue_time = apr_time_sec((double)(daemon_start - queue_start));
        daemon_time = apr_time_sec((double)(application_start - daemon_start));
    }
    else
    {
        server_time = apr_time_sec((double)(application_start - request_start));
        daemon_time = 0;
        queue_time = 0;
    }

    application_time = (apr_time_sec((double)(application_finish -
                                              application_start)));

    /* Identify this thread's slot so I/O totals can be stashed where
     * wsgi_end_request will pick them up for a slow-record snapshot.
     * Looked up before taking the lock — wsgi_thread_info() touches
     * only the current thread's APR threadkey storage. */
    thread_info = wsgi_thread_info(0, 1);

    apr_thread_mutex_lock(wsgi_monitor_lock);

    wsgi_sample_requests += 1;
    wsgi_server_time_total += server_time;
    wsgi_queue_time_total += queue_time;
    wsgi_daemon_time_total += daemon_time;
    wsgi_application_time_total += application_time;

    if (input_bytes > 0)
        wsgi_input_bytes_total += (apr_uint64_t)input_bytes;
    if (input_reads > 0)
        wsgi_input_reads_total += (apr_uint64_t)input_reads;
    if (output_bytes > 0)
        wsgi_output_bytes_total += (apr_uint64_t)output_bytes;
    if (output_writes > 0)
        wsgi_output_writes_total += (apr_uint64_t)output_writes;

    if (wsgi_active_slots && thread_info && thread_info->thread_id >= 1 &&
        thread_info->thread_id <= wsgi_active_slots_max)
    {
        wsgi_active_slot_t *slot =
            &wsgi_active_slots[thread_info->thread_id - 1];

        slot->io_input_bytes = input_bytes > 0 ? input_bytes : 0;
        slot->io_input_reads = input_reads > 0 ? input_reads : 0;
        slot->io_output_bytes = output_bytes > 0 ? output_bytes : 0;
        slot->io_output_writes = output_writes > 0 ? output_writes : 0;
    }

    wsgi_record_time_in_buckets(&wsgi_server_time_buckets[0],
                                server_time);

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
    {
        wsgi_record_time_in_buckets(&wsgi_queue_time_buckets[0],
                                    queue_time);
        wsgi_record_time_in_buckets(&wsgi_daemon_time_buckets[0],
                                    daemon_time);
    }
#endif

    wsgi_record_time_in_buckets(&wsgi_application_time_buckets[0],
                                application_time);

    wsgi_record_time_in_buckets(&wsgi_request_time_buckets[0],
                                server_time + queue_time + daemon_time +
                                application_time);

    apr_thread_mutex_unlock(wsgi_monitor_lock);
}

WSGIThreadInfo *wsgi_start_request(request_rec *r)
{
    WSGIThreadInfo *thread_info;

    PyObject *module = NULL;

    thread_info = wsgi_thread_info(1, 1);

    thread_info->request_data = PyDict_New();

    thread_info->request_id = PyUnicode_DecodeLatin1(r->log_id,
                                                     strlen(r->log_id), NULL);

    module = PyImport_ImportModule("mod_wsgi");

    if (module)
    {
        PyObject *dict = NULL;
        PyObject *requests = NULL;

        dict = PyModule_GetDict(module);
        requests = PyDict_GetItemString(dict, "active_requests");

        if (requests)
            PyDict_SetItem(requests, thread_info->request_id,
                           thread_info->request_data);

        Py_DECREF(module);
    }
    else
        PyErr_Clear();

    /* Capture per-thread CPU baselines before taking the lock — the
     * underlying thread_info()/getrusage() syscall only reads this
     * worker's own state and doesn't need synchronisation, and we want
     * to keep the locked region short. */

    WSGIThreadCPUUsage cpu_usage;
    int have_cpu = 0;

    if (thread_info && thread_info->thread_id >= 1)
        have_cpu = wsgi_thread_cpu_usage(&cpu_usage);

    /* Bump utilization, claim this thread's active-request slot, all
     * under one lock acquire. Holding the request_rec pointer (not a
     * copy) lets the telemetry reporter thread read URL / identity
     * fields on demand and keeps the hot path cheap. r->pool stays
     * alive until after wsgi_end_request clears the slot, so reads
     * under wsgi_monitor_lock are always against a live request_rec. */

    apr_thread_mutex_lock(wsgi_monitor_lock);

    wsgi_utilization_time_locked(1, NULL);

    if (thread_info && thread_info->thread_id >= 1)
    {
        wsgi_slots_ensure_locked();

        if (wsgi_active_slots &&
            thread_info->thread_id <= wsgi_active_slots_max)
        {
            wsgi_active_slot_t *slot =
                &wsgi_active_slots[thread_info->thread_id - 1];
            apr_time_t now = apr_time_now();

            slot->in_use = 1;
            slot->r = r;
            slot->start_us = now;
            slot->thread_id = (uint32_t)thread_info->thread_id;
            slot->busy_since_us = now;

            slot->cpu_valid = have_cpu;
            if (have_cpu)
            {
                slot->cpu_user_at_start = cpu_usage.user_time;
                slot->cpu_system_at_start = cpu_usage.system_time;
            }
            else
            {
                slot->cpu_user_at_start = 0.0;
                slot->cpu_system_at_start = 0.0;
            }
        }
    }

    apr_thread_mutex_unlock(wsgi_monitor_lock);

    return thread_info;
}

void wsgi_end_request(void)
{
    WSGIThreadInfo *thread_info;

    PyObject *module = NULL;

    WSGIThreadCPUUsage cpu_usage;
    int have_cpu = 0;

    thread_info = wsgi_thread_info(0, 1);

    /* Capture CPU baseline before the lock — getrusage / thread_info
     * only see the current worker's state. */

    if (thread_info && thread_info->thread_id >= 1)
        have_cpu = wsgi_thread_cpu_usage(&cpu_usage);

    if (thread_info)
    {
        module = PyImport_ImportModule("mod_wsgi");

        if (module)
        {
            PyObject *dict = NULL;
            PyObject *requests = NULL;

            dict = PyModule_GetDict(module);
            requests = PyDict_GetItemString(dict, "active_requests");

            PyDict_DelItem(requests, thread_info->request_id);

            Py_DECREF(module);
        }
        else
            PyErr_Clear();

        if (thread_info->log_buffer)
            Py_CLEAR(thread_info->log_buffer);

        if (thread_info->request_id)
            Py_CLEAR(thread_info->request_id);

        if (thread_info->request_data)
            Py_CLEAR(thread_info->request_data);
    }

    /* Fold the slot's per-request metrics into the interval accumulator,
     * release the active slot, and decrement utilization — all under one
     * lock acquire. If the request exceeded the slow threshold, snapshot
     * a completion record into the finalize ring while r->pool is still
     * alive (Apache destroys it only after wsgi_end_request returns).
     * Clearing the slot under the same lock ensures the reporter never
     * sees a slot with a dangling r. */

    apr_thread_mutex_lock(wsgi_monitor_lock);

    if (wsgi_active_slots && thread_info && thread_info->thread_id >= 1 &&
        thread_info->thread_id <= wsgi_active_slots_max)
    {
        wsgi_active_slot_t *slot =
            &wsgi_active_slots[thread_info->thread_id - 1];
        wsgi_slot_stats_t  *stats =
            &wsgi_slot_stats[thread_info->thread_id - 1];

        if (slot->in_use && slot->r)
        {
            apr_time_t now = apr_time_now();
            apr_time_t elapsed = now - slot->start_us;
            apr_time_t busy_delta = now - slot->busy_since_us;

            if (busy_delta < 0)
                busy_delta = 0;

            stats->busy_time_us += busy_delta;
            stats->completed += 1;
            if (elapsed > stats->max_duration_us)
                stats->max_duration_us = elapsed;

            if (have_cpu && slot->cpu_valid)
            {
                double cpu_delta =
                    (cpu_usage.user_time   - slot->cpu_user_at_start) +
                    (cpu_usage.system_time - slot->cpu_system_at_start);
                if (cpu_delta < 0.0)
                    cpu_delta = 0.0;
                stats->cpu_time_us += (apr_time_t)(cpu_delta * 1.0e6);
            }

            if (wsgi_slow_threshold_us > 0 &&
                elapsed >= wsgi_slow_threshold_us)
            {
                wsgi_slow_request_t rec;
                memset(&rec, 0, sizeof(rec));
                rec.state = 1; /* completed */
                rec.start_stamp_us = (uint64_t)slot->start_us;
                rec.duration_us = (uint64_t)elapsed;
                rec.thread_id = slot->thread_id;
                rec.input_bytes = (uint64_t)slot->io_input_bytes;
                rec.input_reads = (uint64_t)slot->io_input_reads;
                rec.output_bytes = (uint64_t)slot->io_output_bytes;
                rec.output_writes = (uint64_t)slot->io_output_writes;
                wsgi_slow_snapshot_fields(&rec, slot->r);
                wsgi_slow_push_completed_locked(&rec);
            }
        }

        slot->in_use = 0;
        slot->r = NULL;
        slot->start_us = 0;
        slot->busy_since_us = 0;
        slot->cpu_valid = 0;
        slot->io_input_bytes = 0;
        slot->io_input_reads = 0;
        slot->io_output_bytes = 0;
        slot->io_output_writes = 0;
    }

    wsgi_utilization_time_locked(-1, NULL);

    apr_thread_mutex_unlock(wsgi_monitor_lock);
}

/* ------------------------------------------------------------------------- */

/*
 * C-native interval snapshot for the telemetry reporter thread. Reads the
 * same aggregation globals as wsgi_request_metrics() but builds no Python
 * objects, so it does not require the GIL. Maintains its own per-caller
 * state (telemetry_*) so it does not interfere with the Python accessor's
 * sampling window.
 */

int wsgi_metrics_snapshot(wsgi_telemetry_sample_t *out)
{
    static double telemetry_start_time = 0.0;
    static double telemetry_start_request_busy_time = 0.0;
    static apr_uint64_t telemetry_start_request_count = 0;
    static double telemetry_start_cpu_user_time = 0.0;
    static double telemetry_start_cpu_system_time = 0.0;

    static int telemetry_request_threads_maximum = 0;

    apr_time_t stop_time;
    double stop_request_busy_time = 0.0;
    apr_uint64_t stop_request_count = 0;
    double sample_period = 0.0;
    double request_busy_time = 0.0;
    apr_uint64_t interval_requests = 0;

    double server_time_total = 0.0;
    double queue_time_total = 0.0;
    double daemon_time_total = 0.0;
    double application_time_total = 0.0;

    int i;
    int emitted_slots = 0;
    int threads_active = 0;

#ifdef HAVE_TIMES
    struct tms tmsbuf;
    static double tick = 0.0;

    if (!tick)
    {
#ifdef _SC_CLK_TCK
        tick = sysconf(_SC_CLK_TCK);
#else
        tick = HZ;
#endif
    }
#endif

    if (!out)
        return 0;

    memset(out, 0, sizeof(*out));

    if (!telemetry_request_threads_maximum)
    {
        int is_threaded = 0;

#if defined(MOD_WSGI_WITH_DAEMONS)
        if (wsgi_daemon_process)
        {
            telemetry_request_threads_maximum =
                wsgi_daemon_process->group->threads;
        }
        else
        {
            ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded);
            if (is_threaded != AP_MPMQ_NOT_SUPPORTED)
            {
                ap_mpm_query(AP_MPMQ_MAX_THREADS,
                             &telemetry_request_threads_maximum);
            }
        }
#else
        ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded);
        if (is_threaded != AP_MPMQ_NOT_SUPPORTED)
        {
            ap_mpm_query(AP_MPMQ_MAX_THREADS,
                         &telemetry_request_threads_maximum);
        }
#endif

        if (telemetry_request_threads_maximum <= 0)
            telemetry_request_threads_maximum = 1;
    }

    stop_time = apr_time_now();

    apr_thread_mutex_lock(wsgi_monitor_lock);

    stop_request_busy_time = wsgi_utilization_time_locked(0,
                                                          &stop_request_count);

    /* Ensure slot arrays exist even before the first request so a tick
     * that fires on an idle worker can still emit a well-formed
     * (all-zero) slot payload. Idempotent. */

    wsgi_slots_ensure_locked();

    /* First call seeds counters and returns a not-yet-seeded sample. */
    if (!telemetry_start_time)
    {
        wsgi_sample_requests = 0;
        wsgi_server_time_total = 0.0;
        wsgi_queue_time_total = 0.0;
        wsgi_daemon_time_total = 0.0;
        wsgi_application_time_total = 0.0;

        wsgi_input_bytes_total = 0;
        wsgi_input_reads_total = 0;
        wsgi_output_bytes_total = 0;
        wsgi_output_writes_total = 0;

        memset(&wsgi_server_time_buckets, 0, sizeof(wsgi_server_time_buckets));
        memset(&wsgi_queue_time_buckets, 0, sizeof(wsgi_queue_time_buckets));
        memset(&wsgi_daemon_time_buckets, 0, sizeof(wsgi_daemon_time_buckets));
        memset(&wsgi_application_time_buckets, 0,
               sizeof(wsgi_application_time_buckets));
        memset(&wsgi_request_time_buckets, 0,
               sizeof(wsgi_request_time_buckets));

        if (wsgi_slot_stats && wsgi_active_slots_max > 0)
        {
            memset(wsgi_slot_stats, 0,
                   wsgi_active_slots_max * sizeof(wsgi_slot_stats[0]));
        }

        wsgi_request_metrics_enabled = 1;

        apr_thread_mutex_unlock(wsgi_monitor_lock);

        telemetry_start_time = stop_time;
        telemetry_start_request_busy_time = stop_request_busy_time;
        telemetry_start_request_count = stop_request_count;

#ifdef HAVE_TIMES
        times(&tmsbuf);
        telemetry_start_cpu_user_time = tmsbuf.tms_utime / tick;
        telemetry_start_cpu_system_time = tmsbuf.tms_stime / tick;
#endif

        out->seeded = 0;
        return 1;
    }

    interval_requests = wsgi_sample_requests;
    server_time_total = wsgi_server_time_total;
    queue_time_total = wsgi_queue_time_total;
    daemon_time_total = wsgi_daemon_time_total;
    application_time_total = wsgi_application_time_total;

    out->input_bytes_total = wsgi_input_bytes_total;
    out->input_reads_total = wsgi_input_reads_total;
    out->output_bytes_total = wsgi_output_bytes_total;
    out->output_writes_total = wsgi_output_writes_total;

    for (i = 0; i < WSGI_TELEMETRY_BUCKET_COUNT; i++)
    {
        out->server_time_buckets[i] = wsgi_server_time_buckets[i];
        out->queue_time_buckets[i] = wsgi_queue_time_buckets[i];
        out->daemon_time_buckets[i] = wsgi_daemon_time_buckets[i];
        out->application_time_buckets[i] = wsgi_application_time_buckets[i];
        out->request_time_buckets[i] = wsgi_request_time_buckets[i];
    }

    /* Per-slot capacity drain. Fold any in-flight busy-tail so a long
     * request contributes to every tick it spans, not just the tick it
     * completes in. CPU-time tails can't be folded here because
     * getrusage(RUSAGE_THREAD) / thread_info() only sees the current
     * thread; worker threads publish their CPU delta at request-end. */

    emitted_slots = telemetry_request_threads_maximum;
    if (emitted_slots > WSGI_TELEMETRY_MAX_SLOTS)
        emitted_slots = WSGI_TELEMETRY_MAX_SLOTS;
    if (wsgi_active_slots && emitted_slots > wsgi_active_slots_max)
        emitted_slots = wsgi_active_slots_max;

    if (wsgi_active_slots && wsgi_slot_stats && emitted_slots > 0)
    {
        apr_time_t now = apr_time_now();

        for (i = 0; i < emitted_slots; i++)
        {
            wsgi_active_slot_t *slot = &wsgi_active_slots[i];
            wsgi_slot_stats_t  *stats = &wsgi_slot_stats[i];
            apr_time_t busy_tail = 0;
            apr_time_t current_elapsed = 0;

            if (slot->in_use)
            {
                busy_tail = now - slot->busy_since_us;
                if (busy_tail < 0)
                    busy_tail = 0;
                slot->busy_since_us = now;
                current_elapsed = now - slot->start_us;
                if (current_elapsed < 0)
                    current_elapsed = 0;
            }

            out->slot_request_count[i]      = (int32_t)stats->completed;
            out->slot_busy_time_us[i]       =
                (int32_t)(stats->busy_time_us + busy_tail);
            out->slot_cpu_time_us[i]        = (int32_t)stats->cpu_time_us;
            out->slot_current_elapsed_ms[i] =
                (int32_t)(current_elapsed / 1000);
            out->slot_max_duration_ms[i]    =
                (int32_t)(stats->max_duration_us / 1000);

            if (stats->completed || slot->in_use)
                threads_active++;

            stats->busy_time_us = 0;
            stats->cpu_time_us = 0;
            stats->completed = 0;
            stats->max_duration_us = 0;
        }
    }

    out->slot_count = (uint32_t)emitted_slots;

    wsgi_sample_requests = 0;
    wsgi_server_time_total = 0.0;
    wsgi_queue_time_total = 0.0;
    wsgi_daemon_time_total = 0.0;
    wsgi_application_time_total = 0.0;

    wsgi_input_bytes_total = 0;
    wsgi_input_reads_total = 0;
    wsgi_output_bytes_total = 0;
    wsgi_output_writes_total = 0;

    memset(&wsgi_server_time_buckets, 0, sizeof(wsgi_server_time_buckets));
    memset(&wsgi_queue_time_buckets, 0, sizeof(wsgi_queue_time_buckets));
    memset(&wsgi_daemon_time_buckets, 0, sizeof(wsgi_daemon_time_buckets));
    memset(&wsgi_application_time_buckets, 0,
           sizeof(wsgi_application_time_buckets));
    memset(&wsgi_request_time_buckets, 0,
           sizeof(wsgi_request_time_buckets));

    apr_thread_mutex_unlock(wsgi_monitor_lock);

    out->seeded = 1;

    sample_period = apr_time_sec((double)stop_time) -
                    apr_time_sec((double)telemetry_start_time);
    if (sample_period <= 0.0)
        sample_period = 1e-9; /* avoid divide by zero */

    out->sample_period = sample_period;

#ifdef HAVE_TIMES
    times(&tmsbuf);
    {
        double stop_user = tmsbuf.tms_utime / tick;
        double stop_system = tmsbuf.tms_stime / tick;
        double user_rate = (stop_user - telemetry_start_cpu_user_time) /
                           sample_period;
        double system_rate = (stop_system - telemetry_start_cpu_system_time) /
                             sample_period;

        out->cpu_user_utilization = user_rate;
        out->cpu_system_utilization = system_rate;
        out->cpu_utilization = user_rate + system_rate;

        telemetry_start_cpu_user_time = stop_user;
        telemetry_start_cpu_system_time = stop_system;
    }
#endif

    out->memory_rss = (uint64_t)wsgi_get_current_memory_RSS();
    out->memory_max_rss = (uint64_t)wsgi_get_peak_memory_RSS();

    out->request_threads_maximum = (uint32_t)telemetry_request_threads_maximum;
    out->request_threads_started = (uint32_t)wsgi_request_threads;

    request_busy_time = stop_request_busy_time -
                        telemetry_start_request_busy_time;
    out->capacity_utilization = request_busy_time / sample_period /
                                telemetry_request_threads_maximum;

    out->request_count = stop_request_count - telemetry_start_request_count;
    out->request_throughput = (sample_period > 0) ? (double)out->request_count / sample_period : 0.0;

    telemetry_start_time = stop_time;
    telemetry_start_request_busy_time = stop_request_busy_time;
    telemetry_start_request_count = stop_request_count;

    out->request_threads_active = (uint32_t)threads_active;

    if (interval_requests)
    {
        out->server_time = server_time_total / interval_requests;
        out->application_time = application_time_total / interval_requests;
#if defined(MOD_WSGI_WITH_DAEMONS)
        if (wsgi_daemon_process)
        {
            out->queue_time = queue_time_total / interval_requests;
            out->daemon_time = daemon_time_total / interval_requests;
            out->has_daemon_timing = 1;
        }
#endif
    }

    return 1;
}

/* ------------------------------------------------------------------------- */

/* Slow-request helpers. Lazy-allocate the slot array on first request so
 * there is no cost when the feature is off. Copy strings out of a
 * live request_rec under wsgi_monitor_lock, truncating each field with
 * an "..." suffix so the UI can show where the cut was made. */

static void wsgi_slots_ensure_locked(void)
{
    int max = 0;
    int is_threaded = 0;

    if (wsgi_active_slots)
        return;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
    {
        max = wsgi_daemon_process->group->threads;
    }
    else
    {
        ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded);
        if (is_threaded != AP_MPMQ_NOT_SUPPORTED)
            ap_mpm_query(AP_MPMQ_MAX_THREADS, &max);
    }
#else
    ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded);
    if (is_threaded != AP_MPMQ_NOT_SUPPORTED)
        ap_mpm_query(AP_MPMQ_MAX_THREADS, &max);
#endif

    if (max <= 0)
        max = 1;

    wsgi_active_slots = (wsgi_active_slot_t *)apr_pcalloc(
        wsgi_server_config->pool, max * sizeof(*wsgi_active_slots));
    wsgi_slot_stats = (wsgi_slot_stats_t *)apr_pcalloc(
        wsgi_server_config->pool, max * sizeof(*wsgi_slot_stats));
    wsgi_active_slots_max = max;

    /* Size the slow-completion ring from N threads × max
     * completions-per-tick × safety. Each thread can complete at
     * most ceil(T / S) slow requests in a tick, so total per-tick
     * worst case is max * ceil(T / S); the safety factor absorbs
     * inter-tick jitter and burst clustering. Floor + cap keep tiny
     * deployments at the historical 32 and prevent pathological
     * sizing when WSGISlowRequests is set very low. */

    int ring = WSGI_SLOW_RING_FLOOR;
    if (wsgi_slow_threshold_us > 0)
    {
        double tick_s = wsgi_telemetry_interval > 0
            ? wsgi_telemetry_interval : 1.0;
        double thresh_s = (double)wsgi_slow_threshold_us / 1.0e6;
        if (thresh_s > 0)
        {
            double per_thread = ceil(tick_s / thresh_s);
            if (per_thread < 1.0) per_thread = 1.0;
            double sized = (double)max * per_thread *
                           (double)WSGI_SLOW_RING_SAFETY;
            if (sized > (double)ring) ring = (int)sized;
            if (ring > WSGI_SLOW_RING_CAP) ring = WSGI_SLOW_RING_CAP;
        }
    }
    wsgi_completed_ring = (wsgi_slow_request_t *)apr_pcalloc(
        wsgi_server_config->pool, ring * sizeof(*wsgi_completed_ring));
    wsgi_completed_ring_size = ring;
}

static void wsgi_slow_copy_str(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (cap == 0)
        return;

    if (!src)
    {
        dst[0] = '\0';
        return;
    }

    n = strlen(src);

    if (n >= cap)
    {
        if (cap >= 4)
        {
            memcpy(dst, src, cap - 4);
            dst[cap - 4] = '.';
            dst[cap - 3] = '.';
            dst[cap - 2] = '.';
            dst[cap - 1] = '\0';
        }
        else
        {
            memcpy(dst, src, cap - 1);
            dst[cap - 1] = '\0';
        }
    }
    else
    {
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
}

/* Pull URL / identity out of a request_rec into a snapshot record. Does
 * no allocation and never touches r->pool; safe to call under lock. */

static void wsgi_slow_snapshot_fields(wsgi_slow_request_t *rec, request_rec *r)
{
    const char *script_name = NULL;
    const char *path_info = NULL;
    const char *scheme_env = NULL;
    const char *scheme = "http";

    wsgi_slow_copy_str(rec->log_id, sizeof(rec->log_id),
                       r->log_id ? r->log_id : "");
    wsgi_slow_copy_str(rec->hostname, sizeof(rec->hostname),
                       r->hostname ? r->hostname : "");

    /* In daemon mode r->method is NULL — the daemon-side request_rec is
     * synthesised from the subprocess_env stream and wsgi_read_request
     * never fills r->method. REQUEST_METHOD in subprocess_env is the
     * canonical source (ap_add_cgi_vars sets it on the parent) and works
     * in both daemon and embedded modes. */

    const char *method = NULL;

    if (r->subprocess_env)
    {
        method = apr_table_get(r->subprocess_env, "REQUEST_METHOD");

        /* HTTPS in subprocess_env is the authoritative scheme decision
         * after trusted-proxy handling + mod_ssl detection. mod_wsgi
         * strips it from the Python WSGI environ dict later, but the
         * apr_table value survives for the lifetime of the request. */

        scheme_env = apr_table_get(r->subprocess_env, "HTTPS");
        if (scheme_env && (!strcasecmp(scheme_env, "On") ||
                           !strcmp(scheme_env, "1")))
            scheme = "https";

        script_name = apr_table_get(r->subprocess_env, "mod_wsgi.script_name");
        if (!script_name)
            script_name = apr_table_get(r->subprocess_env, "SCRIPT_NAME");

        path_info = apr_table_get(r->subprocess_env, "mod_wsgi.path_info");
        if (!path_info)
            path_info = apr_table_get(r->subprocess_env, "PATH_INFO");
    }

    if (!method)
        method = r->method; /* embedded-mode fallback */

    wsgi_slow_copy_str(rec->method, sizeof(rec->method),
                       method ? method : "");

    wsgi_slow_copy_str(rec->scheme, sizeof(rec->scheme), scheme);
    wsgi_slow_copy_str(rec->script_name, sizeof(rec->script_name),
                       script_name ? script_name : "");

    /* Fall back to r->uri (always query-stripped) when the env keys are
     * absent; never read r->unparsed_uri or r->args so query strings
     * can't leak into telemetry. */

    wsgi_slow_copy_str(rec->path_info, sizeof(rec->path_info),
                       path_info ? path_info : (r->uri ? r->uri : ""));
}

/* Caller must hold wsgi_monitor_lock. */

static void wsgi_slow_push_completed_locked(const wsgi_slow_request_t *rec)
{
    int idx;

    if (!wsgi_completed_ring || wsgi_completed_ring_size <= 0)
        return;

    if (wsgi_completed_ring_count < wsgi_completed_ring_size)
    {
        idx = (wsgi_completed_ring_head + wsgi_completed_ring_count) %
              wsgi_completed_ring_size;
        wsgi_completed_ring_count++;
    }
    else
    {
        /* Ring full — drop oldest so recent slow completions aren't lost.
         * With dynamic sizing this should be rare in practice; if it
         * fires consistently the safety factor needs bumping. */

        idx = wsgi_completed_ring_head;
        wsgi_completed_ring_head = (wsgi_completed_ring_head + 1) %
                                   wsgi_completed_ring_size;
    }

    wsgi_completed_ring[idx] = *rec;
}

int wsgi_metrics_pop_slow_completed(wsgi_slow_request_t *out)
{
    int got = 0;

    if (!out)
        return 0;

    apr_thread_mutex_lock(wsgi_monitor_lock);

    if (wsgi_completed_ring && wsgi_completed_ring_count > 0)
    {
        *out = wsgi_completed_ring[wsgi_completed_ring_head];
        wsgi_completed_ring_head = (wsgi_completed_ring_head + 1) %
                                   wsgi_completed_ring_size;
        wsgi_completed_ring_count--;
        got = 1;
    }

    apr_thread_mutex_unlock(wsgi_monitor_lock);

    return got;
}

int wsgi_metrics_snapshot_slow_active(wsgi_slow_request_t *out, int out_cap,
                                      apr_time_t now_us,
                                      apr_time_t threshold_us)
{
    int i;
    int n = 0;

    if (!out || out_cap <= 0)
        return 0;

    apr_thread_mutex_lock(wsgi_monitor_lock);

    if (!wsgi_active_slots)
    {
        apr_thread_mutex_unlock(wsgi_monitor_lock);
        return 0;
    }

    for (i = 0; i < wsgi_active_slots_max && n < out_cap; i++)
    {
        wsgi_active_slot_t *slot = &wsgi_active_slots[i];
        apr_time_t elapsed;
        wsgi_slow_request_t *rec;

        if (!slot->in_use || !slot->r)
            continue;

        elapsed = now_us - slot->start_us;
        if (elapsed < threshold_us)
            continue;

        rec = &out[n];
        memset(rec, 0, sizeof(*rec));
        rec->state = 0; /* active */
        rec->start_stamp_us = (uint64_t)slot->start_us;
        rec->duration_us = (uint64_t)elapsed;
        rec->thread_id = slot->thread_id;
        rec->input_bytes = (uint64_t)slot->io_input_bytes;
        rec->input_reads = (uint64_t)slot->io_input_reads;
        rec->output_bytes = (uint64_t)slot->io_output_bytes;
        rec->output_writes = (uint64_t)slot->io_output_writes;
        wsgi_slow_snapshot_fields(rec, slot->r);

        n++;
    }

    apr_thread_mutex_unlock(wsgi_monitor_lock);

    return n;
}

/* ------------------------------------------------------------------------- */

static int wsgi_interns_initialized = 0;

WSGI_STATIC_INTERNED_STRING(server_limit);
WSGI_STATIC_INTERNED_STRING(thread_limit);
WSGI_STATIC_INTERNED_STRING(running_generation);
WSGI_STATIC_INTERNED_STRING(restart_time);
WSGI_STATIC_INTERNED_STRING(current_time);
WSGI_STATIC_INTERNED_STRING(running_time);
WSGI_STATIC_INTERNED_STRING(process_num);
WSGI_STATIC_INTERNED_STRING(pid);
WSGI_STATIC_INTERNED_STRING(generation);
WSGI_STATIC_INTERNED_STRING(quiescing);
WSGI_STATIC_INTERNED_STRING(workers);
WSGI_STATIC_INTERNED_STRING(thread_num);
WSGI_STATIC_INTERNED_STRING(status);
WSGI_STATIC_INTERNED_STRING(access_count);
WSGI_STATIC_INTERNED_STRING(bytes_served);
WSGI_STATIC_INTERNED_STRING(start_time);
WSGI_STATIC_INTERNED_STRING(stop_time);
WSGI_STATIC_INTERNED_STRING(last_used);
WSGI_STATIC_INTERNED_STRING(client);
WSGI_STATIC_INTERNED_STRING(request);
WSGI_STATIC_INTERNED_STRING(vhost);
WSGI_STATIC_INTERNED_STRING(processes);

WSGI_STATIC_INTERNED_STRING(request_count);
WSGI_STATIC_INTERNED_STRING(request_busy_time);
WSGI_STATIC_INTERNED_STRING(memory_max_rss);
WSGI_STATIC_INTERNED_STRING(memory_rss);
WSGI_STATIC_INTERNED_STRING(cpu_user_time);
WSGI_STATIC_INTERNED_STRING(cpu_system_time);
WSGI_STATIC_INTERNED_STRING(cpu_time);
WSGI_STATIC_INTERNED_STRING(cpu_user_utilization);
WSGI_STATIC_INTERNED_STRING(cpu_system_utilization);
WSGI_STATIC_INTERNED_STRING(cpu_utilization);
WSGI_STATIC_INTERNED_STRING(request_threads);
WSGI_STATIC_INTERNED_STRING(active_requests);
WSGI_STATIC_INTERNED_STRING(threads);
WSGI_STATIC_INTERNED_STRING(thread_id);

WSGI_STATIC_INTERNED_STRING(sample_period);
WSGI_STATIC_INTERNED_STRING(request_threads_maximum);
WSGI_STATIC_INTERNED_STRING(request_threads_started);
WSGI_STATIC_INTERNED_STRING(request_threads_active);
WSGI_STATIC_INTERNED_STRING(capacity_utilization);
WSGI_STATIC_INTERNED_STRING(request_throughput);
WSGI_STATIC_INTERNED_STRING(server_time);
WSGI_STATIC_INTERNED_STRING(queue_time);
WSGI_STATIC_INTERNED_STRING(daemon_time);
WSGI_STATIC_INTERNED_STRING(application_time);
WSGI_STATIC_INTERNED_STRING(server_time_buckets);
WSGI_STATIC_INTERNED_STRING(queue_time_buckets);
WSGI_STATIC_INTERNED_STRING(daemon_time_buckets);
WSGI_STATIC_INTERNED_STRING(application_time_buckets);
WSGI_STATIC_INTERNED_STRING(request_time_buckets);
WSGI_STATIC_INTERNED_STRING(request_threads_buckets);
WSGI_STATIC_INTERNED_STRING(slot_busy_time_us);
WSGI_STATIC_INTERNED_STRING(slot_cpu_time_us);
WSGI_STATIC_INTERNED_STRING(slot_current_elapsed_ms);
WSGI_STATIC_INTERNED_STRING(slot_max_duration_ms);

static PyObject *wsgi_status_flags[SERVER_NUM_STATUS];

#define WSGI_CREATE_STATUS_FLAG(name, val) \
    wsgi_status_flags[name] = PyUnicode_InternFromString(val)

static void wsgi_initialize_interned_strings(void)
{
    /* Initialise interned strings the first time. */

    if (!wsgi_interns_initialized)
    {
        WSGI_CREATE_INTERNED_STRING_ID(server_limit);
        WSGI_CREATE_INTERNED_STRING_ID(thread_limit);
        WSGI_CREATE_INTERNED_STRING_ID(running_generation);
        WSGI_CREATE_INTERNED_STRING_ID(restart_time);
        WSGI_CREATE_INTERNED_STRING_ID(current_time);
        WSGI_CREATE_INTERNED_STRING_ID(running_time);
        WSGI_CREATE_INTERNED_STRING_ID(process_num);
        WSGI_CREATE_INTERNED_STRING_ID(pid);
        WSGI_CREATE_INTERNED_STRING_ID(generation);
        WSGI_CREATE_INTERNED_STRING_ID(quiescing);
        WSGI_CREATE_INTERNED_STRING_ID(workers);
        WSGI_CREATE_INTERNED_STRING_ID(thread_num);
        WSGI_CREATE_INTERNED_STRING_ID(status);
        WSGI_CREATE_INTERNED_STRING_ID(access_count);
        WSGI_CREATE_INTERNED_STRING_ID(bytes_served);
        WSGI_CREATE_INTERNED_STRING_ID(start_time);
        WSGI_CREATE_INTERNED_STRING_ID(stop_time);
        WSGI_CREATE_INTERNED_STRING_ID(last_used);
        WSGI_CREATE_INTERNED_STRING_ID(client);
        WSGI_CREATE_INTERNED_STRING_ID(request);
        WSGI_CREATE_INTERNED_STRING_ID(vhost);
        WSGI_CREATE_INTERNED_STRING_ID(processes);

        WSGI_CREATE_INTERNED_STRING_ID(request_count);
        WSGI_CREATE_INTERNED_STRING_ID(request_busy_time);
        WSGI_CREATE_INTERNED_STRING_ID(memory_max_rss);
        WSGI_CREATE_INTERNED_STRING_ID(memory_rss);
        WSGI_CREATE_INTERNED_STRING_ID(cpu_user_time);
        WSGI_CREATE_INTERNED_STRING_ID(cpu_system_time);
        WSGI_CREATE_INTERNED_STRING_ID(cpu_time);
        WSGI_CREATE_INTERNED_STRING_ID(cpu_user_utilization);
        WSGI_CREATE_INTERNED_STRING_ID(cpu_system_utilization);
        WSGI_CREATE_INTERNED_STRING_ID(cpu_utilization);
        WSGI_CREATE_INTERNED_STRING_ID(request_threads);
        WSGI_CREATE_INTERNED_STRING_ID(active_requests);
        WSGI_CREATE_INTERNED_STRING_ID(threads);
        WSGI_CREATE_INTERNED_STRING_ID(thread_id);

        WSGI_CREATE_INTERNED_STRING_ID(sample_period);
        WSGI_CREATE_INTERNED_STRING_ID(request_threads_maximum);
        WSGI_CREATE_INTERNED_STRING_ID(request_threads_started);
        WSGI_CREATE_INTERNED_STRING_ID(request_threads_active);
        WSGI_CREATE_INTERNED_STRING_ID(capacity_utilization);
        WSGI_CREATE_INTERNED_STRING_ID(request_throughput);
        WSGI_CREATE_INTERNED_STRING_ID(server_time);
        WSGI_CREATE_INTERNED_STRING_ID(queue_time);
        WSGI_CREATE_INTERNED_STRING_ID(daemon_time);
        WSGI_CREATE_INTERNED_STRING_ID(application_time);
        WSGI_CREATE_INTERNED_STRING_ID(server_time_buckets);
        WSGI_CREATE_INTERNED_STRING_ID(daemon_time_buckets);
        WSGI_CREATE_INTERNED_STRING_ID(queue_time_buckets);
        WSGI_CREATE_INTERNED_STRING_ID(application_time_buckets);
        WSGI_CREATE_INTERNED_STRING_ID(request_time_buckets);
        WSGI_CREATE_INTERNED_STRING_ID(request_threads_buckets);
        WSGI_CREATE_INTERNED_STRING_ID(slot_busy_time_us);
        WSGI_CREATE_INTERNED_STRING_ID(slot_cpu_time_us);
        WSGI_CREATE_INTERNED_STRING_ID(slot_current_elapsed_ms);
        WSGI_CREATE_INTERNED_STRING_ID(slot_max_duration_ms);

        WSGI_CREATE_STATUS_FLAG(SERVER_DEAD, ".");
        WSGI_CREATE_STATUS_FLAG(SERVER_READY, "_");
        WSGI_CREATE_STATUS_FLAG(SERVER_STARTING, "S");
        WSGI_CREATE_STATUS_FLAG(SERVER_BUSY_READ, "R");
        WSGI_CREATE_STATUS_FLAG(SERVER_BUSY_WRITE, "W");
        WSGI_CREATE_STATUS_FLAG(SERVER_BUSY_KEEPALIVE, "K");
        WSGI_CREATE_STATUS_FLAG(SERVER_BUSY_LOG, "L");
        WSGI_CREATE_STATUS_FLAG(SERVER_BUSY_DNS, "D");
        WSGI_CREATE_STATUS_FLAG(SERVER_CLOSING, "C");
        WSGI_CREATE_STATUS_FLAG(SERVER_GRACEFUL, "G");
        WSGI_CREATE_STATUS_FLAG(SERVER_IDLE_KILL, "I");

        wsgi_interns_initialized = 1;
    }
}

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_request_metrics(void)
{
    PyObject *result = NULL;

    PyObject *object = NULL;

    apr_time_t stop_time;
    double stop_request_busy_time = 0.0;
    apr_uint64_t stop_request_count = 0;

    double request_busy_time = 0.0;
    double capacity_utilization = 0.0;

    static double start_time = 0.0;
    static double start_cpu_system_time = 0.0;
    static double start_cpu_user_time = 0.0;
    static double start_request_busy_time = 0.0;
    static apr_uint64_t start_request_count = 0;

    double sample_period = 0.0;
    apr_uint64_t request_count = 0;
    double request_throughput = 0.0;
    double stop_cpu_system_time = 0.0;
    double stop_cpu_user_time = 0.0;

    double cpu_system_time = 0.0;
    double cpu_user_time = 0.0;
    double total_cpu_time = 0.0;

    static int request_threads_maximum = 0;
    static int *slot_completed_snap = NULL;
    static int *slot_busy_us_snap = NULL;
    static int *slot_cpu_us_snap = NULL;
    static int *slot_current_ms_snap = NULL;
    static int *slot_max_ms_snap = NULL;

    apr_uint64_t interval_requests = 0;
    double server_time_total = 0;
    double server_time_avg = 0;
    double queue_time_total = 0;
    double queue_time_avg = 0;
    double daemon_time_total = 0;
    double daemon_time_avg = 0;
    double application_time_total = 0;
    double application_time_avg = 0;

    int server_time_buckets_snap[16];
    int queue_time_buckets_snap[16];
    int daemon_time_buckets_snap[16];
    int application_time_buckets_snap[16];
    int request_time_buckets_snap[16];

    int request_threads_active = 0;

    int i;

#ifdef HAVE_TIMES
    struct tms tmsbuf;
    static double tick = 0.0;

    if (!tick)
    {
#ifdef _SC_CLK_TCK
        tick = sysconf(_SC_CLK_TCK);
#else
        tick = HZ;
#endif
    }
#endif

    if (!wsgi_interns_initialized)
        wsgi_initialize_interned_strings();

    if (!request_threads_maximum)
    {
        int is_threaded = 0;

#if defined(MOD_WSGI_WITH_DAEMONS)
        if (wsgi_daemon_process)
        {
            request_threads_maximum = wsgi_daemon_process->group->threads;
        }
        else
        {
            ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded);
            if (is_threaded != AP_MPMQ_NOT_SUPPORTED)
            {
                ap_mpm_query(AP_MPMQ_MAX_THREADS, &request_threads_maximum);
            }
        }
#else
        ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded);
        if (is_threaded != AP_MPMQ_NOT_SUPPORTED)
        {
            ap_mpm_query(AP_MPMQ_MAX_THREADS, &request_threads_maximum);
        }
#endif

        request_threads_maximum = ((request_threads_maximum <= 0) ? 1 : request_threads_maximum);

        slot_completed_snap = (int *)apr_pcalloc(
            wsgi_server_config->pool,
            request_threads_maximum * sizeof(slot_completed_snap[0]));
        slot_busy_us_snap = (int *)apr_pcalloc(
            wsgi_server_config->pool,
            request_threads_maximum * sizeof(slot_busy_us_snap[0]));
        slot_cpu_us_snap = (int *)apr_pcalloc(
            wsgi_server_config->pool,
            request_threads_maximum * sizeof(slot_cpu_us_snap[0]));
        slot_current_ms_snap = (int *)apr_pcalloc(
            wsgi_server_config->pool,
            request_threads_maximum * sizeof(slot_current_ms_snap[0]));
        slot_max_ms_snap = (int *)apr_pcalloc(
            wsgi_server_config->pool,
            request_threads_maximum * sizeof(slot_max_ms_snap[0]));
    }

    result = PyDict_New();

    stop_time = apr_time_now();

#ifdef HAVE_TIMES
    times(&tmsbuf);
    stop_cpu_user_time = tmsbuf.tms_utime / tick;
    stop_cpu_system_time = tmsbuf.tms_stime / tick;
#endif

    /* One locked region covers the utilization read AND the accumulator
     * drain so the emitted sample is internally consistent. Python object
     * construction happens afterwards, using the local snapshots. */

    apr_thread_mutex_lock(wsgi_monitor_lock);

    stop_request_busy_time = wsgi_utilization_time_locked(0,
                                                          &stop_request_count);

    /* Ensure slot arrays exist even if no request has been served yet. */
    wsgi_slots_ensure_locked();

    if (!start_time)
    {
        wsgi_sample_requests = 0;
        wsgi_server_time_total = 0.0;
        wsgi_queue_time_total = 0.0;
        wsgi_daemon_time_total = 0.0;
        wsgi_application_time_total = 0.0;

        if (wsgi_slot_stats && wsgi_active_slots_max > 0)
        {
            memset(wsgi_slot_stats, 0,
                   wsgi_active_slots_max * sizeof(wsgi_slot_stats[0]));
        }

        wsgi_request_metrics_enabled = 1;

        apr_thread_mutex_unlock(wsgi_monitor_lock);

        start_time = stop_time;
        start_request_busy_time = stop_request_busy_time;
        start_request_count = stop_request_count;
#ifdef HAVE_TIMES
        start_cpu_user_time = stop_cpu_user_time;
        start_cpu_system_time = stop_cpu_system_time;
#else
        start_cpu_user_time = 0.0;
        start_cpu_system_time = 0.0;
#endif

        return result;
    }

    interval_requests = wsgi_sample_requests;
    server_time_total = wsgi_server_time_total;
    queue_time_total = wsgi_queue_time_total;
    daemon_time_total = wsgi_daemon_time_total;
    application_time_total = wsgi_application_time_total;

    memcpy(server_time_buckets_snap, wsgi_server_time_buckets,
           sizeof(server_time_buckets_snap));
    memcpy(queue_time_buckets_snap, wsgi_queue_time_buckets,
           sizeof(queue_time_buckets_snap));
    memcpy(daemon_time_buckets_snap, wsgi_daemon_time_buckets,
           sizeof(daemon_time_buckets_snap));
    memcpy(application_time_buckets_snap, wsgi_application_time_buckets,
           sizeof(application_time_buckets_snap));
    memcpy(request_time_buckets_snap, wsgi_request_time_buckets,
           sizeof(request_time_buckets_snap));

    /* Per-slot capacity drain. Fold in-flight busy-tail so a long request
     * contributes to every interval it spans. CPU tails can't be folded
     * here (cross-thread CPU time isn't available); request-end publishes
     * the final CPU delta. */
    {
        apr_time_t now = apr_time_now();
        int slot_n = request_threads_maximum;
        if (wsgi_active_slots && slot_n > wsgi_active_slots_max)
            slot_n = wsgi_active_slots_max;

        for (i = 0; i < request_threads_maximum; i++)
        {
            slot_completed_snap[i] = 0;
            slot_busy_us_snap[i] = 0;
            slot_cpu_us_snap[i] = 0;
            slot_current_ms_snap[i] = 0;
            slot_max_ms_snap[i] = 0;
        }

        if (wsgi_active_slots && wsgi_slot_stats)
        {
            for (i = 0; i < slot_n; i++)
            {
                wsgi_active_slot_t *slot = &wsgi_active_slots[i];
                wsgi_slot_stats_t  *stats = &wsgi_slot_stats[i];
                apr_time_t busy_tail = 0;
                apr_time_t current_elapsed = 0;

                if (slot->in_use)
                {
                    busy_tail = now - slot->busy_since_us;
                    if (busy_tail < 0)
                        busy_tail = 0;
                    slot->busy_since_us = now;
                    current_elapsed = now - slot->start_us;
                    if (current_elapsed < 0)
                        current_elapsed = 0;
                }

                slot_completed_snap[i] = (int)stats->completed;
                slot_busy_us_snap[i] =
                    (int)(stats->busy_time_us + busy_tail);
                slot_cpu_us_snap[i] = (int)stats->cpu_time_us;
                slot_current_ms_snap[i] = (int)(current_elapsed / 1000);
                slot_max_ms_snap[i] = (int)(stats->max_duration_us / 1000);

                stats->busy_time_us = 0;
                stats->cpu_time_us = 0;
                stats->completed = 0;
                stats->max_duration_us = 0;
            }
        }
    }

    wsgi_sample_requests = 0;
    wsgi_server_time_total = 0.0;
    wsgi_queue_time_total = 0.0;
    wsgi_daemon_time_total = 0.0;
    wsgi_application_time_total = 0.0;

    /* Drain (zero-only) the I/O totals so the telemetry reporter
     * doesn't leak counts across the Python accessor's interval. The
     * Python accessor doesn't currently expose the I/O totals — same
     * drain-clash semantics as wsgi_sample_requests above. */
    wsgi_input_bytes_total = 0;
    wsgi_input_reads_total = 0;
    wsgi_output_bytes_total = 0;
    wsgi_output_writes_total = 0;

    memset(&wsgi_server_time_buckets, 0,
           sizeof(wsgi_server_time_buckets));
    memset(&wsgi_queue_time_buckets, 0,
           sizeof(wsgi_queue_time_buckets));
    memset(&wsgi_daemon_time_buckets, 0,
           sizeof(wsgi_daemon_time_buckets));
    memset(&wsgi_application_time_buckets, 0,
           sizeof(wsgi_application_time_buckets));
    memset(&wsgi_request_time_buckets, 0,
           sizeof(wsgi_request_time_buckets));

    apr_thread_mutex_unlock(wsgi_monitor_lock);

    object = PyLong_FromLong(getpid());
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(pid), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(apr_time_sec((double)start_time));
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(start_time), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(apr_time_sec((double)stop_time));
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(stop_time), object);
    Py_DECREF(object);

    sample_period = (apr_time_sec((double)stop_time) -
                     apr_time_sec((double)start_time));

    object = PyFloat_FromDouble(sample_period);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(sample_period), object);
    Py_DECREF(object);

#ifdef HAVE_TIMES
    cpu_user_time = ((stop_cpu_user_time - start_cpu_user_time) /
                     sample_period);
    cpu_system_time = ((stop_cpu_system_time - start_cpu_system_time) /
                       sample_period);

    total_cpu_time = cpu_user_time + cpu_system_time;

    object = PyFloat_FromDouble(cpu_user_time);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_user_utilization), object);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_user_time), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(cpu_system_time);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_system_utilization), object);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_system_time), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(total_cpu_time);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_utilization), object);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_time), object);
    Py_DECREF(object);
#else
    object = PyFloat_FromDouble(0.0);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_user_utilization), object);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_user_time), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(0.0);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_system_utilization), object);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_system_time), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(0.0);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_utilization), object);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_time), object);
    Py_DECREF(object);
#endif

    object = PyLong_FromLongLong(wsgi_get_peak_memory_RSS());
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(memory_max_rss), object);
    Py_DECREF(object);

    object = PyLong_FromLongLong(wsgi_get_current_memory_RSS());
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(memory_rss), object);
    Py_DECREF(object);

    object = PyLong_FromLong(request_threads_maximum);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(request_threads_maximum), object);
    Py_DECREF(object);

    object = PyLong_FromLong(wsgi_request_threads);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(request_threads_started), object);
    Py_DECREF(object);

    request_busy_time = stop_request_busy_time - start_request_busy_time;

    capacity_utilization = (request_busy_time / sample_period /
                            request_threads_maximum);

    object = PyFloat_FromDouble(capacity_utilization);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(capacity_utilization), object);
    Py_DECREF(object);

    request_count = stop_request_count - start_request_count;

    object = PyLong_FromLongLong(request_count);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(request_count), object);
    Py_DECREF(object);

    request_throughput = sample_period ? request_count / sample_period : 0;

    object = PyFloat_FromDouble(request_throughput);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(request_throughput), object);
    Py_DECREF(object);

    object = PyList_New(16);
    for (i = 0; i < 16; i++)
    {
        PyList_SET_ITEM(object, i,
                        PyLong_FromLong(server_time_buckets_snap[i]));
    }
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(server_time_buckets), object);
    Py_DECREF(object);

    object = PyList_New(16);
    for (i = 0; i < 16; i++)
    {
        PyList_SET_ITEM(object, i,
                        PyLong_FromLong(queue_time_buckets_snap[i]));
    }
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(queue_time_buckets), object);
    Py_DECREF(object);

    object = PyList_New(16);
    for (i = 0; i < 16; i++)
    {
        PyList_SET_ITEM(object, i,
                        PyLong_FromLong(daemon_time_buckets_snap[i]));
    }
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(daemon_time_buckets), object);
    Py_DECREF(object);

    object = PyList_New(16);
    for (i = 0; i < 16; i++)
    {
        PyList_SET_ITEM(object, i,
                        PyLong_FromLong(application_time_buckets_snap[i]));
    }
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(application_time_buckets), object);
    Py_DECREF(object);

    object = PyList_New(16);
    for (i = 0; i < 16; i++)
    {
        PyList_SET_ITEM(object, i,
                        PyLong_FromLong(request_time_buckets_snap[i]));
    }
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(request_time_buckets), object);
    Py_DECREF(object);

    object = PyList_New(request_threads_maximum);
    for (i = 0; i < request_threads_maximum; i++)
    {
        PyList_SET_ITEM(object, i,
                        PyLong_FromLong(slot_completed_snap[i]));
        if (slot_completed_snap[i] || slot_current_ms_snap[i])
            request_threads_active++;
    }
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(request_threads_buckets), object);
    Py_DECREF(object);

    object = PyList_New(request_threads_maximum);
    for (i = 0; i < request_threads_maximum; i++)
        PyList_SET_ITEM(object, i,
                        PyLong_FromLong(slot_busy_us_snap[i]));
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(slot_busy_time_us), object);
    Py_DECREF(object);

    object = PyList_New(request_threads_maximum);
    for (i = 0; i < request_threads_maximum; i++)
        PyList_SET_ITEM(object, i,
                        PyLong_FromLong(slot_cpu_us_snap[i]));
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(slot_cpu_time_us), object);
    Py_DECREF(object);

    object = PyList_New(request_threads_maximum);
    for (i = 0; i < request_threads_maximum; i++)
        PyList_SET_ITEM(object, i,
                        PyLong_FromLong(slot_current_ms_snap[i]));
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(slot_current_elapsed_ms), object);
    Py_DECREF(object);

    object = PyList_New(request_threads_maximum);
    for (i = 0; i < request_threads_maximum; i++)
        PyList_SET_ITEM(object, i,
                        PyLong_FromLong(slot_max_ms_snap[i]));
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(slot_max_duration_ms), object);
    Py_DECREF(object);

    object = PyLong_FromLong(request_threads_active);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(request_threads_active), object);
    Py_DECREF(object);

    start_time = stop_time;
    start_request_busy_time = stop_request_busy_time;
    start_request_count = stop_request_count;
    start_cpu_user_time = stop_cpu_user_time;
    start_cpu_system_time = stop_cpu_system_time;

    server_time_avg = 0;
    queue_time_avg = 0;
    daemon_time_avg = 0;
    application_time_avg = 0;

    if (interval_requests)
    {
        server_time_avg = server_time_total / interval_requests;
        queue_time_avg = queue_time_total / interval_requests;
        daemon_time_avg = daemon_time_total / interval_requests;
        application_time_avg = application_time_total / interval_requests;
    }

    object = PyFloat_FromDouble(server_time_avg);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(server_time), object);
    Py_DECREF(object);

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
    {
        object = PyFloat_FromDouble(queue_time_avg);
        PyDict_SetItem(result,
                       WSGI_INTERNED_STRING(queue_time), object);
        Py_DECREF(object);

        object = PyFloat_FromDouble(daemon_time_avg);
        PyDict_SetItem(result,
                       WSGI_INTERNED_STRING(daemon_time), object);
        Py_DECREF(object);
    }
    else
    {
        PyDict_SetItem(result,
                       WSGI_INTERNED_STRING(queue_time), Py_None);
        PyDict_SetItem(result,
                       WSGI_INTERNED_STRING(daemon_time), Py_None);
    }
#else
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(queue_time), Py_None);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(daemon_time), Py_None);
#endif

    object = PyFloat_FromDouble(application_time_avg);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(application_time), object);
    Py_DECREF(object);

    return result;
}

PyMethodDef wsgi_request_metrics_method[] = {
    {"request_metrics", (PyCFunction)wsgi_request_metrics,
     METH_NOARGS, 0},
    {NULL},
};

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_process_metrics(void)
{
    PyObject *result = NULL;

    PyObject *object = NULL;

    PyObject *thread_list = NULL;
    WSGIThreadInfo **thread_info = NULL;

    apr_uint64_t request_count = 0;

    int i;

#ifdef HAVE_TIMES
    struct tms tmsbuf;
    static double tick = 0.0;
#endif

    apr_time_t current_time;
    apr_interval_time_t running_time;

    if (!wsgi_interns_initialized)
        wsgi_initialize_interned_strings();

    result = PyDict_New();

    object = PyLong_FromLong(getpid());
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(pid), object);
    Py_DECREF(object);

    {
        double busy_time;

        apr_thread_mutex_lock(wsgi_monitor_lock);
        busy_time = wsgi_utilization_time_locked(0, &request_count);
        apr_thread_mutex_unlock(wsgi_monitor_lock);

        object = PyFloat_FromDouble(busy_time);
    }
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(request_busy_time), object);
    Py_DECREF(object);

    object = PyLong_FromLongLong(request_count);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(request_count), object);
    Py_DECREF(object);

    object = PyLong_FromLongLong(wsgi_get_peak_memory_RSS());
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(memory_max_rss), object);
    Py_DECREF(object);

    object = PyLong_FromLongLong(wsgi_get_current_memory_RSS());
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(memory_rss), object);
    Py_DECREF(object);

#ifdef HAVE_TIMES
    if (!tick)
    {
#ifdef _SC_CLK_TCK
        tick = sysconf(_SC_CLK_TCK);
#else
        tick = HZ;
#endif
    }

    times(&tmsbuf);

    object = PyFloat_FromDouble(tmsbuf.tms_utime / tick);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_user_time), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(tmsbuf.tms_stime / tick);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_system_time), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble((tmsbuf.tms_utime + tmsbuf.tms_stime) / tick);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(cpu_time), object);
    Py_DECREF(object);
#endif

    object = PyFloat_FromDouble(apr_time_sec((double)wsgi_restart_time));
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(restart_time), object);
    Py_DECREF(object);

    current_time = apr_time_now();

    object = PyFloat_FromDouble(apr_time_sec((double)current_time));
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(current_time), object);
    Py_DECREF(object);

    running_time = apr_time_sec((double)current_time - wsgi_restart_time);

    object = PyLong_FromLongLong(running_time);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(running_time), object);
    Py_DECREF(object);

    object = PyLong_FromLong(wsgi_request_threads);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(request_threads), object);
    Py_DECREF(object);

    object = PyLong_FromLong(wsgi_active_requests);
    PyDict_SetItem(result,
                   WSGI_INTERNED_STRING(active_requests), object);
    Py_DECREF(object);

    thread_list = PyList_New(0);

    PyDict_SetItem(result, WSGI_INTERNED_STRING(threads), thread_list);

    thread_info = (WSGIThreadInfo **)wsgi_thread_details->elts;

    for (i = 0; i < wsgi_thread_details->nelts; i++)
    {
        PyObject *entry = NULL;

        if (thread_info[i]->request_thread)
        {
            entry = PyDict_New();

            object = PyLong_FromLong(thread_info[i]->thread_id);
            PyDict_SetItem(entry, WSGI_INTERNED_STRING(thread_id), object);
            Py_DECREF(object);

            object = PyLong_FromLongLong(thread_info[i]->request_count);
            PyDict_SetItem(entry, WSGI_INTERNED_STRING(request_count), object);
            Py_DECREF(object);

            PyList_Append(thread_list, entry);

            Py_DECREF(entry);
        }
    }

    Py_DECREF(thread_list);

    return result;
}

PyMethodDef wsgi_process_metrics_method[] = {
    {"process_metrics", (PyCFunction)wsgi_process_metrics,
     METH_NOARGS, 0},
    {NULL},
};

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_server_metrics(void)
{
    PyObject *scoreboard_dict = NULL;

    PyObject *process_list = NULL;

    PyObject *object = NULL;

    apr_time_t current_time;
    apr_interval_time_t running_time;

    global_score *gs_record;
    worker_score *ws_record;
    process_score *ps_record;

    int j, i;

    if (!wsgi_interns_initialized)
        wsgi_initialize_interned_strings();

    /* Scoreboard needs to exist and server metrics enabled. */

    if (!ap_exists_scoreboard_image())
        Py_RETURN_NONE;

    if (!wsgi_daemon_pool)
    {
        if (!wsgi_server_config->server_metrics)
            Py_RETURN_NONE;
    }
#if defined(MOD_WSGI_WITH_DAEMONS)
    else
    {
        if (!wsgi_daemon_process->group->server_metrics)
            Py_RETURN_NONE;
    }
#endif

    gs_record = ap_get_scoreboard_global();

    if (!gs_record)
        Py_RETURN_NONE;

    /* Return everything in a dictionary. Start with global. */

    scoreboard_dict = PyDict_New();

    object = PyLong_FromLong(gs_record->server_limit);
    PyDict_SetItem(scoreboard_dict,
                   WSGI_INTERNED_STRING(server_limit), object);
    Py_DECREF(object);

    object = PyLong_FromLong(gs_record->thread_limit);
    PyDict_SetItem(scoreboard_dict,
                   WSGI_INTERNED_STRING(thread_limit), object);
    Py_DECREF(object);

    object = PyLong_FromLong(gs_record->running_generation);
    PyDict_SetItem(scoreboard_dict,
                   WSGI_INTERNED_STRING(running_generation), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(apr_time_sec((
                                                 double)gs_record->restart_time));
    PyDict_SetItem(scoreboard_dict,
                   WSGI_INTERNED_STRING(restart_time), object);
    Py_DECREF(object);

    current_time = apr_time_now();

    object = PyFloat_FromDouble(apr_time_sec((double)current_time));
    PyDict_SetItem(scoreboard_dict,
                   WSGI_INTERNED_STRING(current_time), object);
    Py_DECREF(object);

    running_time = apr_time_sec((double)current_time -
                                ap_scoreboard_image->global->restart_time);

    object = PyLong_FromLongLong(running_time);
    PyDict_SetItem(scoreboard_dict,
                   WSGI_INTERNED_STRING(running_time), object);
    Py_DECREF(object);

    /* Now add in the processes/workers. */

    process_list = PyList_New(0);

    for (i = 0; i < gs_record->server_limit; ++i)
    {
        PyObject *process_dict = NULL;
        PyObject *worker_list = NULL;

        ps_record = ap_get_scoreboard_process(i);

        process_dict = PyDict_New();
        PyList_Append(process_list, process_dict);

        object = PyLong_FromLong(i);
        PyDict_SetItem(process_dict,
                       WSGI_INTERNED_STRING(process_num), object);
        Py_DECREF(object);

        object = PyLong_FromLong(ps_record->pid);
        PyDict_SetItem(process_dict,
                       WSGI_INTERNED_STRING(pid), object);
        Py_DECREF(object);

        object = PyLong_FromLong(ps_record->generation);
        PyDict_SetItem(process_dict,
                       WSGI_INTERNED_STRING(generation), object);
        Py_DECREF(object);

        object = PyBool_FromLong(ps_record->quiescing);
        PyDict_SetItem(process_dict,
                       WSGI_INTERNED_STRING(quiescing), object);
        Py_DECREF(object);

        worker_list = PyList_New(0);
        PyDict_SetItem(process_dict,
                       WSGI_INTERNED_STRING(workers), worker_list);

        for (j = 0; j < gs_record->thread_limit; ++j)
        {
            PyObject *worker_dict = NULL;

            ws_record = ap_get_scoreboard_worker_from_indexes(i, j);

            worker_dict = PyDict_New();

            PyList_Append(worker_list, worker_dict);

            object = PyLong_FromLong(ws_record->thread_num);
            PyDict_SetItem(worker_dict,
                           WSGI_INTERNED_STRING(thread_num), object);
            Py_DECREF(object);

            object = PyLong_FromLong(ws_record->generation);
            PyDict_SetItem(worker_dict,
                           WSGI_INTERNED_STRING(generation), object);
            Py_DECREF(object);

            object = wsgi_status_flags[ws_record->status];
            PyDict_SetItem(worker_dict,
                           WSGI_INTERNED_STRING(status), object);

            object = PyLong_FromLong(ws_record->access_count);
            PyDict_SetItem(worker_dict,
                           WSGI_INTERNED_STRING(access_count), object);
            Py_DECREF(object);

            object = PyLong_FromUnsignedLongLong(ws_record->bytes_served);
            PyDict_SetItem(worker_dict,
                           WSGI_INTERNED_STRING(bytes_served), object);
            Py_DECREF(object);

            object = PyFloat_FromDouble(apr_time_sec(
                (double)ws_record->start_time));
            PyDict_SetItem(worker_dict,
                           WSGI_INTERNED_STRING(start_time), object);
            Py_DECREF(object);

            object = PyFloat_FromDouble(apr_time_sec(
                (double)ws_record->stop_time));
            PyDict_SetItem(worker_dict,
                           WSGI_INTERNED_STRING(stop_time), object);
            Py_DECREF(object);

            object = PyFloat_FromDouble(apr_time_sec(
                (double)ws_record->last_used));
            PyDict_SetItem(worker_dict,
                           WSGI_INTERNED_STRING(last_used), object);
            Py_DECREF(object);

            object = PyUnicode_DecodeLatin1(ws_record->client, strlen(ws_record->client), NULL);
            PyDict_SetItem(worker_dict,
                           WSGI_INTERNED_STRING(client), object);
            Py_DECREF(object);

            object = PyUnicode_DecodeLatin1(ws_record->request, strlen(ws_record->request), NULL);
            PyDict_SetItem(worker_dict,
                           WSGI_INTERNED_STRING(request), object);
            Py_DECREF(object);

            object = PyUnicode_DecodeLatin1(ws_record->vhost, strlen(ws_record->vhost), NULL);
            PyDict_SetItem(worker_dict,
                           WSGI_INTERNED_STRING(vhost), object);
            Py_DECREF(object);

            Py_DECREF(worker_dict);
        }

        Py_DECREF(worker_list);
        Py_DECREF(process_dict);
    }

    PyDict_SetItem(scoreboard_dict,
                   WSGI_INTERNED_STRING(processes), process_list);
    Py_DECREF(process_list);

    return scoreboard_dict;
}

/* ------------------------------------------------------------------------- */

PyMethodDef wsgi_server_metrics_method[] = {
    {"server_metrics", (PyCFunction)wsgi_server_metrics,
     METH_NOARGS, 0},
    {NULL},
};

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_subscribe_events(PyObject *Py_UNUSED(self), PyObject *args)
{
    PyObject *callback = NULL;

    PyObject *module = NULL;

    if (!PyArg_ParseTuple(args, "O", &callback))
        return NULL;

    module = PyImport_ImportModule("mod_wsgi");

    if (module)
    {
        PyObject *dict = NULL;
        PyObject *list = NULL;

        dict = PyModule_GetDict(module);
        list = PyDict_GetItemString(dict, "event_callbacks");

        if (list)
            PyList_Append(list, callback);
        else
        {
            Py_DECREF(module);
            PyErr_SetString(PyExc_RuntimeError,
                            "mod_wsgi event_callbacks not initialised");
            return NULL;
        }

        Py_DECREF(module);
    }
    else
        return NULL;

    Py_RETURN_NONE;
}

static PyObject *wsgi_subscribe_shutdown(PyObject *Py_UNUSED(self), PyObject *args)
{
    PyObject *callback = NULL;

    PyObject *module = NULL;

    if (!PyArg_ParseTuple(args, "O", &callback))
        return NULL;

    module = PyImport_ImportModule("mod_wsgi");

    if (module)
    {
        PyObject *dict = NULL;
        PyObject *list = NULL;

        dict = PyModule_GetDict(module);
        list = PyDict_GetItemString(dict, "shutdown_callbacks");

        if (list)
            PyList_Append(list, callback);
        else
        {
            Py_DECREF(module);
            PyErr_SetString(PyExc_RuntimeError,
                            "mod_wsgi shutdown_callbacks not initialised");
            return NULL;
        }

        Py_DECREF(module);
    }
    else
        return NULL;

    Py_RETURN_NONE;
}

long wsgi_event_subscribers(void)
{
    PyObject *module = NULL;

    module = PyImport_ImportModule("mod_wsgi");

    if (module)
    {
        PyObject *dict = NULL;
        PyObject *list = NULL;

        long result = 0;

        dict = PyModule_GetDict(module);
        list = PyDict_GetItemString(dict, "event_callbacks");

        if (list)
            result = PyList_Size(list);

        Py_DECREF(module);

        return result;
    }
    else
        return 0;
}

void wsgi_call_callbacks(const char *name, PyObject *callbacks,
                         PyObject *event)
{
    int i;

    for (i = 0; i < PyList_Size(callbacks); i++)
    {
        PyObject *callback = NULL;

        PyObject *res = NULL;
        PyObject *args = NULL;

        callback = PyList_GetItem(callbacks, i);

        Py_INCREF(callback);

        args = Py_BuildValue("(s)", name);

        res = PyObject_Call(callback, args, event);

        if (!res)
        {
            PyObject *m = NULL;
            PyObject *result = NULL;

            PyObject *type = NULL;
            PyObject *value = NULL;
            PyObject *traceback = NULL;

            Py_BEGIN_ALLOW_THREADS
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                             "mod_wsgi (pid=%d): Exception occurred within "
                             "event callback.",
                             getpid());
            Py_END_ALLOW_THREADS

                PyErr_Fetch(&type, &value, &traceback);
            PyErr_NormalizeException(&type, &value, &traceback);

            if (!value)
            {
                value = Py_None;
                Py_INCREF(value);
            }

            if (!traceback)
            {
                traceback = Py_None;
                Py_INCREF(traceback);
            }

            m = PyImport_ImportModule("traceback");

            if (m)
            {
                PyObject *d = NULL;
                PyObject *o = NULL;
                d = PyModule_GetDict(m);
                o = PyDict_GetItemString(d, "print_exception");
                if (o)
                {
                    PyObject *log = NULL;
                    PyObject *tb_args = NULL;
                    PyObject *tb_kwargs = NULL;
                    Py_INCREF(o);
                    log = newLogObject(NULL, APLOG_ERR, NULL, 0);
                    tb_args = Py_BuildValue("(O)", value);
                    tb_kwargs = Py_BuildValue("{s:O}", "file", log);
                    result = PyObject_Call(o, tb_args, tb_kwargs);
                    Py_DECREF(tb_kwargs);
                    Py_DECREF(tb_args);
                    Py_DECREF(log);
                    Py_DECREF(o);
                }
            }

            if (!result)
            {
                /*
                 * If can't output exception and traceback then
                 * use PyErr_Print to dump out details of the
                 * exception. For SystemExit though if we do
                 * that the process will actually be terminated
                 * so can only clear the exception information
                 * and keep going.
                 */

                PyErr_Restore(type, value, traceback);

                if (!PyErr_ExceptionMatches(PyExc_SystemExit))
                {
                    PyErr_Print();
                    PyErr_Clear();
                }
                else
                {
                    PyErr_Clear();
                }
            }
            else
            {
                Py_XDECREF(type);
                Py_XDECREF(value);
                Py_XDECREF(traceback);
            }

            Py_XDECREF(result);

            Py_XDECREF(m);
        }
        else if (PyDict_Check(res))
        {
            PyDict_Update(event, res);
        }

        Py_XDECREF(res);

        Py_DECREF(callback);
        Py_DECREF(args);
    }
}

void wsgi_publish_event(const char *name, PyObject *event)
{
    PyObject *module = NULL;

    PyObject *event_callbacks = NULL;
    PyObject *shutdown_callbacks = NULL;

    module = PyImport_ImportModule("mod_wsgi");

    if (module)
    {
        PyObject *dict = NULL;

        dict = PyModule_GetDict(module);

        event_callbacks = PyDict_GetItemString(dict, "event_callbacks");
        Py_XINCREF(event_callbacks);

        shutdown_callbacks = PyDict_GetItemString(dict, "shutdown_callbacks");
        Py_XINCREF(shutdown_callbacks);

        Py_DECREF(module);
    }
    else
    {
        Py_BEGIN_ALLOW_THREADS
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Unable to import mod_wsgi when "
                         "publishing events.",
                         getpid());
        Py_END_ALLOW_THREADS

        PyErr_Clear();

        return;
    }

    if (!event_callbacks || !shutdown_callbacks)
    {
        Py_BEGIN_ALLOW_THREADS
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Unable to find event subscribers.",
                         getpid());
        Py_END_ALLOW_THREADS

        PyErr_Clear();

        Py_XDECREF(event_callbacks);
        Py_XDECREF(shutdown_callbacks);

        return;
    }

    wsgi_call_callbacks(name, event_callbacks, event);

    if (strcmp(name, "process_stopping") == 0)
        wsgi_call_callbacks(name, shutdown_callbacks, event);

    Py_DECREF(event_callbacks);
    Py_DECREF(shutdown_callbacks);
}

/* ------------------------------------------------------------------------- */

PyMethodDef wsgi_subscribe_events_method[] = {
    {"subscribe_events", (PyCFunction)wsgi_subscribe_events,
     METH_VARARGS, 0},
    {NULL},
};

PyMethodDef wsgi_subscribe_shutdown_method[] = {
    {"subscribe_shutdown", (PyCFunction)wsgi_subscribe_shutdown,
     METH_VARARGS, 0},
    {NULL},
};

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_request_data(PyObject *Py_UNUSED(self), PyObject *Py_UNUSED(args))
{
    WSGIThreadInfo *thread_info;

    thread_info = wsgi_thread_info(0, 0);

    if (!thread_info)
    {
        PyErr_SetString(PyExc_RuntimeError, "no active request for thread");
        return NULL;
    }

    if (!thread_info->request_data)
    {
        PyErr_SetString(PyExc_RuntimeError, "no active request for thread");
        return NULL;
    }

    Py_INCREF(thread_info->request_data);

    return thread_info->request_data;
}

/* ------------------------------------------------------------------------- */

PyMethodDef wsgi_request_data_method[] = {
    {"request_data", (PyCFunction)wsgi_request_data,
     METH_NOARGS, 0},
    {NULL},
};

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
