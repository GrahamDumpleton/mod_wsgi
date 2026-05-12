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
#include "wsgi_module.h"
#include "wsgi_thread.h"
#include "wsgi_telemetry.h"

#include <math.h> /* ceil(): slow-ring sizing math */

/* ------------------------------------------------------------------------- */

WSGIProcessMetrics *wsgi_process_metrics = NULL;

static void wsgi_phase_aggregate_reset(WSGIPhaseAggregate *p);
static int wsgi_query_request_threads_maximum(void);

void wsgi_process_metrics_init(apr_pool_t *pool)
{
    WSGIProcessMetrics *m = apr_pcalloc(pool, sizeof(*m));

    apr_thread_mutex_create(&m->monitor_lock, APR_THREAD_MUTEX_UNNESTED, pool);

    /*
     * Phase aggregators need the UINT64_MAX sentinel on min_us so the
     * first sample's min comparison succeeds; pcalloc zeros leave them
     * at 0 which would freeze min at 0 forever.
     */

    wsgi_phase_aggregate_reset(&m->server_time);
    wsgi_phase_aggregate_reset(&m->queue_time);
    wsgi_phase_aggregate_reset(&m->daemon_time);
    wsgi_phase_aggregate_reset(&m->application_time);
    wsgi_phase_aggregate_reset(&m->request_time);
    wsgi_phase_aggregate_reset(&m->gil_wait_time);
    wsgi_phase_aggregate_reset(&m->input_read_time);
    wsgi_phase_aggregate_reset(&m->output_write_time);

    m->request_threads_maximum = wsgi_query_request_threads_maximum();

#ifdef HAVE_TIMES
#ifdef _SC_CLK_TCK
    m->tick_hz = (double)sysconf(_SC_CLK_TCK);
#else
    m->tick_hz = (double)HZ;
#endif
#endif

    wsgi_process_metrics = m;
}

/*
 * Thread utilisation. Accrues an ongoing utilisation-time value at
 * request start, request end, and when a reader asks for it, so the
 * busy-handling-requests integral stays current.
 *
 * Caller MUST hold the monitor lock. Touches thread_utilization,
 * utilization_last, active_requests and total_requests on
 * wsgi_process_metrics; all covered by that same lock.
 */

static double wsgi_utilization_time_locked(int adjustment,
                                           apr_uint64_t *request_count)
{
    WSGIProcessMetrics *m = wsgi_process_metrics;
    apr_time_t now;
    double utilization = m->thread_utilization;

    now = apr_time_now();

    if (m->utilization_last != 0)
    {
        utilization = (now - m->utilization_last) / 1000000.0;

        if (utilization < 0)
            utilization = 0;

        utilization = m->active_requests * utilization;
        m->thread_utilization += utilization;
        utilization = m->thread_utilization;
    }

    m->utilization_last = now;
    m->active_requests += adjustment;

    if (adjustment < 0)
        m->total_requests += -adjustment;

    if (request_count)
        *request_count = m->total_requests;

    return utilization;
}

/*
 * Completed-ring sizing. Floor gives a tiny embedded MPM (a few threads
 * at the default reporter interval) reasonable headroom. Cap prevents
 * pathological allocations when WSGISlowRequests is set very low (e.g.
 * 0.01 s for debugging). Safety factor covers inter-tick jitter and
 * bursts where many threads complete near-simultaneously: the formula
 * otherwise assumes uniform distribution which real workloads don't
 * follow.
 */

#define WSGI_SLOW_RING_FLOOR 32
#define WSGI_SLOW_RING_CAP 4096
#define WSGI_SLOW_RING_SAFETY 5

apr_time_t wsgi_slow_threshold_us = 0;
extern double wsgi_telemetry_interval;

/*
 * Forward declarations; implementations live after wsgi_metrics_snapshot.
 */

static void wsgi_slow_ring_ensure_locked(void);
static void wsgi_slow_snapshot_fields(wsgi_slow_request_t *rec, request_rec *r);
static void wsgi_slow_push_completed_locked(const wsgi_slow_request_t *rec);
static void wsgi_slow_fill_phase_durations(wsgi_slow_request_t *rec,
                                           const WSGIActiveSlot *slot,
                                           apr_time_t now_us);

void wsgi_gil_wait_reset(void)
{
    /*
     * Called at the top of wsgi_execute_script to clear any leftover
     * staged value from a prior request handled on this thread. The
     * slot is also cleared on slot release (wsgi_end_request), so this
     * is belt-and-braces but cheap.
     */

    WSGIThreadInfo *ti = wsgi_thread_info(0, 1);
    if (ti)
    {
        ti->staged_gil_wait_us = 0;
        ti->staged_gil_wait_count = 0;
    }
}

void wsgi_gil_wait_record(apr_uint64_t wait_us)
{
    /*
     * Hot path: runs on every Py_END_ALLOW_THREADS-equivalent in the
     * request handler. APR threadkey lookup plus one or two uint64
     * adds, no locking. Per-slot writes race with the reporter thread's
     * active-record reads but tearing on a uint64 is acceptable for an
     * indicator metric.
     *
     * Slot may not yet be claimed; the daemon-phase sites (initial
     * interp acquire, module-lock, "200 Continue" brigade) fire before
     * wsgi_start_request runs. In that window the staging accumulator
     * on WSGIThreadInfo holds the running total; wsgi_start_request
     * drains it into the slot at claim time.
     */

    WSGIThreadInfo *ti = wsgi_thread_info(0, 1);
    if (!ti || ti->thread_id < 1)
        return;

    if (ti->slot.in_use)
    {
        ti->slot.gil_wait_us += wait_us;
        ti->slot.gil_wait_count += 1;
        return;
    }

    ti->staged_gil_wait_us += wait_us;
    ti->staged_gil_wait_count += 1;
}

void wsgi_gil_wait_current(apr_uint64_t *wait_us, apr_uint64_t *count)
{
    /*
     * Read the calling thread's running per-request GIL-wait totals.
     * Mirrors wsgi_gil_wait_record's slot-vs-staging branch: the active
     * slot holds the running total once claimed; before that, the
     * per-thread staging accumulator does. Caller passes NULL for any
     * field they don't want.
     */

    apr_uint64_t local_us = 0;
    apr_uint64_t local_count = 0;

    WSGIThreadInfo *ti = wsgi_thread_info(0, 1);
    if (ti && ti->thread_id >= 1)
    {
        if (ti->slot.in_use)
        {
            local_us = ti->slot.gil_wait_us;
            local_count = ti->slot.gil_wait_count;
        }
        else
        {
            local_us = ti->staged_gil_wait_us;
            local_count = ti->staged_gil_wait_count;
        }
    }

    if (wait_us)
        *wait_us = local_us;
    if (count)
        *count = local_count;
}

void wsgi_record_time_in_buckets(int *buckets, double duration)
{
    /*
     * HDR-style index: 16 octaves (1 ms .. 65536 ms) by 4 linear
     * sub-buckets per octave, plus a single overflow bucket at index
     * 64. Total 65 entries per phase.
     *
     * frexp(ms) returns mantissa in [0.5, 1.0) such that
     *   ms = mantissa * 2^exp
     * so exp - 1 is the octave index for ms in [1, 65536). The four
     * sub-buckets are a linear split of [2*mantissa - 1, 1) across
     * [0, 4). Bucket boundaries are [lo, hi) on each sub-bucket: a
     * value equal to a boundary lands in the higher bucket.
     */

    double ms = duration * 1000.0;
    int exp;
    double mantissa;
    int octave;
    int sub;

    if (ms < 1.0)
    {
        buckets[0] += 1;
        return;
    }

    if (ms >= 65536.0)
    {
        buckets[WSGI_TELEMETRY_BUCKET_COUNT - 1] += 1;
        return;
    }

    mantissa = frexp(ms, &exp);
    octave = exp - 1;

    sub = (int)((2.0 * mantissa - 1.0) * 4.0);
    if (sub > 3)
        sub = 3;

    buckets[octave * 4 + sub] += 1;
}

/*
 * Reset a phase aggregator to its empty-interval state: zero total,
 * zero buckets, UINT64_MAX min sentinel, zero max. Caller controls
 * locking.
 */

static void wsgi_phase_aggregate_reset(WSGIPhaseAggregate *p)
{
    p->total = 0.0;
    memset(p->buckets, 0, sizeof(p->buckets));
    p->min_us = UINT64_MAX;
    p->max_us = 0;
}

/*
 * Record one sample into a phase aggregator: fold the seconds-domain
 * total, update the integer-microseconds min/max accumulators, and
 * bucket the seconds-domain duration. Caller controls locking.
 */

static void wsgi_phase_aggregate_record(WSGIPhaseAggregate *p,
                                        double seconds, apr_uint64_t us)
{
    p->total += seconds;
    if (us < p->min_us)
        p->min_us = us;
    if (us > p->max_us)
        p->max_us = us;

    wsgi_record_time_in_buckets(p->buckets, seconds);
}

void wsgi_record_request_times(apr_time_t request_start,
                               apr_time_t queue_start, apr_time_t daemon_start,
                               apr_time_t application_start, apr_time_t application_finish,
                               apr_off_t input_bytes, apr_off_t input_reads,
                               apr_off_t output_bytes, apr_off_t output_writes,
                               apr_time_t input_read_us,
                               apr_time_t output_write_us,
                               int status)
{

    double server_time = 0.0;
    double queue_time = 0.0;
    double daemon_time = 0.0;
    double application_time = 0.0;
    double request_time = 0.0;
    double input_read_time = 0.0;
    double output_write_time = 0.0;
    apr_uint64_t server_us = 0;
    apr_uint64_t queue_us = 0;
    apr_uint64_t daemon_us = 0;
    apr_uint64_t application_us = 0;
    apr_uint64_t request_us = 0;
    apr_uint64_t input_read_us_u = 0;
    apr_uint64_t output_write_us_u = 0;
    WSGIThreadInfo *thread_info = NULL;

    if (wsgi_process_metrics->request_metrics_enabled == 0)
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

    request_time = server_time + queue_time + daemon_time + application_time;

    /*
     * Per-phase microseconds for the min/max accumulators. The seconds
     * round-trip is exact for any realistic request duration.
     */

    server_us = (apr_uint64_t)(server_time * 1000000.0);
    queue_us = (apr_uint64_t)(queue_time * 1000000.0);
    daemon_us = (apr_uint64_t)(daemon_time * 1000000.0);
    application_us = (apr_uint64_t)(application_time * 1000000.0);
    request_us = (apr_uint64_t)(request_time * 1000000.0);

    /*
     * I/O timings arrive from the adapter as apr_time_t in microseconds.
     * Clamp negative deltas (the adapter's own clamp belt-and-braces) and
     * keep both the integer-us and seconds forms: the former drives the
     * exact min/max accumulators, the latter the per-tick mean and
     * histogram bucketing.
     */

    input_read_us_u = input_read_us > 0 ? (apr_uint64_t)input_read_us : 0;
    output_write_us_u =
        output_write_us > 0 ? (apr_uint64_t)output_write_us : 0;
    input_read_time = (double)input_read_us_u / 1.0e6;
    output_write_time = (double)output_write_us_u / 1.0e6;

    /*
     * Identify this thread's slot so I/O totals can be stashed where
     * wsgi_end_request will pick them up for a slow-record snapshot.
     * Looked up before taking the lock; wsgi_thread_info() touches
     * only the current thread's APR threadkey storage.
     */

    thread_info = wsgi_thread_info(0, 1);

    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);

    wsgi_process_metrics->sample_requests += 1;

    /*
     * Per-phase totals + min/max + histogram. Queue and daemon phases
     * only contribute in daemon mode; recorded below inside the
     * MOD_WSGI_WITH_DAEMONS block. gil_wait_time is recorded in the
     * slot-found block so it picks up the per-request GIL accumulator.
     */

    wsgi_phase_aggregate_record(&wsgi_process_metrics->server_time, server_time, server_us);
    wsgi_phase_aggregate_record(&wsgi_process_metrics->application_time, application_time,
                                application_us);
    wsgi_phase_aggregate_record(&wsgi_process_metrics->request_time, request_time, request_us);
    wsgi_phase_aggregate_record(&wsgi_process_metrics->input_read_time, input_read_time,
                                input_read_us_u);
    wsgi_phase_aggregate_record(&wsgi_process_metrics->output_write_time, output_write_time,
                                output_write_us_u);

    if (input_bytes > 0)
        wsgi_process_metrics->input_bytes_total += (apr_uint64_t)input_bytes;
    if (input_reads > 0)
        wsgi_process_metrics->input_reads_total += (apr_uint64_t)input_reads;
    if (output_bytes > 0)
        wsgi_process_metrics->output_bytes_total += (apr_uint64_t)output_bytes;
    if (output_writes > 0)
        wsgi_process_metrics->output_writes_total += (apr_uint64_t)output_writes;

    /*
     * Classify the response status into a per-class counter.
     * status == 0 means the WSGI app raised before calling
     * start_response: fold it into 5xx so the error rate reflects the
     * user-visible outcome (mod_wsgi serves a 500 in that case).
     */

    if (status == 0)
        wsgi_process_metrics->status_5xx_count += 1;
    else if (status >= 100 && status < 200)
        wsgi_process_metrics->status_1xx_count += 1;
    else if (status >= 200 && status < 300)
        wsgi_process_metrics->status_2xx_count += 1;
    else if (status >= 300 && status < 400)
        wsgi_process_metrics->status_3xx_count += 1;
    else if (status >= 400 && status < 500)
        wsgi_process_metrics->status_4xx_count += 1;
    else if (status >= 500 && status < 600)
        wsgi_process_metrics->status_5xx_count += 1;
    /* else: out-of-range, silently dropped */

    if (thread_info && thread_info->thread_id >= 1)
    {
        WSGIActiveSlot *slot = &thread_info->slot;
        apr_uint64_t gil_wait_us = 0;
        double gil_wait_time = 0.0;

        slot->io_input_bytes = input_bytes > 0 ? input_bytes : 0;
        slot->io_input_reads = input_reads > 0 ? input_reads : 0;
        slot->io_output_bytes = output_bytes > 0 ? output_bytes : 0;
        slot->io_output_writes = output_writes > 0 ? output_writes : 0;
        slot->io_input_read_us = input_read_us > 0 ? input_read_us : 0;
        slot->io_output_write_us = output_write_us > 0 ? output_write_us : 0;
        slot->last_status = status;

        /*
         * application_start was stashed earlier by
         * wsgi_record_application_start; record application_finish here
         * so the slow-record snapshot at wsgi_end_request can compute
         * the application phase duration without re-deriving it.
         */

        slot->application_finish_us = application_finish;

        /*
         * Fold the per-request GIL-wait total into the interval
         * accumulator. Read inside the lock alongside the slot writes
         * above; the slot stays alive until wsgi_end_request clears it.
         */

        gil_wait_us = slot->gil_wait_us;
        gil_wait_time = (double)gil_wait_us / 1.0e6;
        wsgi_phase_aggregate_record(&wsgi_process_metrics->gil_wait_time, gil_wait_time,
                                    gil_wait_us);
        wsgi_process_metrics->gil_wait_count_total += slot->gil_wait_count;
    }

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
    {
        wsgi_phase_aggregate_record(&wsgi_process_metrics->queue_time, queue_time, queue_us);
        wsgi_phase_aggregate_record(&wsgi_process_metrics->daemon_time, daemon_time, daemon_us);
    }
#endif

    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);
}

void wsgi_record_application_start(apr_time_t application_start)
{
    WSGIThreadInfo *thread_info;

    if (wsgi_process_metrics->request_metrics_enabled == 0)
        return;

    /*
     * Looked up before taking the lock; wsgi_thread_info() touches
     * only the current thread's APR threadkey storage.
     */

    thread_info = wsgi_thread_info(0, 1);

    if (!thread_info || thread_info->thread_id < 1)
        return;

    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);

    if (thread_info->slot.in_use)
        thread_info->slot.application_start_us = application_start;

    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);
}

WSGIThreadInfo *wsgi_start_request(request_rec *r)
{
    WSGIThreadInfo *thread_info;
    WSGIRequestConfig *config = NULL;

    PyObject *module = NULL;

    thread_info = wsgi_thread_info(1, 1);

    /*
     * Best-effort. A failure here must not tear down the request: the
     * downstream wsgi_request_data accessor handles a NULL request_data
     * by raising RuntimeError to the caller. Each failure path chains a
     * site-specific RuntimeError onto the underlying (likely MemoryError)
     * exception before logging so the log identifies the failing
     * operation as well as the allocation primitive.
     */

    Py_XDECREF(thread_info->request_data);
    thread_info->request_data = PyDict_New();
    if (!thread_info->request_data)
    {
        wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                             "Failed to allocate request_data dict for request %s",
                                             r->uri ? r->uri : "(unknown)");
        wsgi_log_python_error(r, NULL, NULL, 0);
    }

    Py_XDECREF(thread_info->request_id);
    thread_info->request_id = NULL;

    if (r->log_id)
    {
        thread_info->request_id = PyUnicode_DecodeLatin1(
            r->log_id, strlen(r->log_id), NULL);
        if (!thread_info->request_id)
        {
            wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                                 "Failed to decode request_id for request %s",
                                                 r->uri ? r->uri : "(unknown)");
            wsgi_log_python_error(r, NULL, NULL, 0);
        }
    }

    if (thread_info->request_data && thread_info->request_id)
    {
        module = PyImport_ImportModule("mod_wsgi");

        if (module)
        {
            PyObject *dict = NULL;
            PyObject *requests = NULL;

            dict = PyModule_GetDict(module);
            requests = PyDict_GetItemString(dict, "active_requests");

            if (requests)
            {
                if (PyDict_SetItem(requests, thread_info->request_id,
                                   thread_info->request_data) < 0)
                {
                    wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                                         "Failed to register request_id in "
                                                         "active_requests for request %s",
                                                         r->uri ? r->uri : "(unknown)");
                    wsgi_log_python_error(r, NULL, NULL, 0);
                }
            }

            Py_DECREF(module);
        }
        else
            PyErr_Clear();
    }

    /*
     * Capture per-thread CPU baselines before taking the lock: the
     * underlying thread_info()/getrusage() syscall only reads this
     * worker's own state and doesn't need synchronisation, and the
     * locked region is kept short.
     */

    WSGIThreadCPUUsage cpu_usage;
    int have_cpu = 0;

    if (thread_info->thread_id >= 1)
        have_cpu = wsgi_thread_cpu_usage(&cpu_usage);

    /*
     * Per-request phase-timing baselines come from the WSGIRequestConfig
     * cached on r at handler entry. request_start is set by mod_wsgi.c
     * from r->request_time; queue_start and daemon_start are non-zero
     * only in daemon mode (queue_start crosses the daemon socket from
     * the Apache child, daemon_start is captured by the daemon thread
     * just before invoking handler-level setup). Reading config outside
     * the lock is safe; it lives in r->pool which is alive until
     * wsgi_end_request clears the slot.
     */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    /*
     * Bump utilization, claim this thread's active-request slot, all
     * under one lock acquire. Holding the request_rec pointer (not a
     * copy) lets the telemetry reporter thread read URL / identity
     * fields on demand and keeps the hot path cheap. r->pool stays
     * alive until after wsgi_end_request clears the slot, so reads
     * under the monitor lock are always against a live request_rec.
     */

    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);

    wsgi_utilization_time_locked(1, NULL);

    if (thread_info->thread_id >= 1)
    {
        WSGIActiveSlot *slot = &thread_info->slot;
        apr_time_t now = apr_time_now();

        wsgi_slow_ring_ensure_locked();

        slot->in_use = 1;
        slot->r = r;
        slot->start_us = now;
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

        slot->request_start_us = config ? config->request_start : 0;
        slot->queue_start_us = config ? config->queue_start : 0;
        slot->daemon_start_us = config ? config->daemon_start : 0;
        slot->application_start_us = 0;
        slot->application_finish_us = 0;

        slot->server_pid = config ? config->server_pid : 0;

        /*
         * wsgi_utilization_time_locked(1, ...) above already
         * incremented active_requests, so this snapshot reflects
         * the in-flight count *including* this request.
         */

        slot->active_at_start =
            (uint64_t)wsgi_process_metrics->active_requests;

        /*
         * Drain any GIL-wait time accumulated during the daemon-phase
         * sites that fired before this slot was claimed (initial
         * interp acquire, module-lock, "200 Continue" brigade). After
         * this point the WSGI_END_ALLOW_THREADS macros write directly
         * into the slot.
         */

        slot->gil_wait_us = thread_info->staged_gil_wait_us;
        slot->gil_wait_count = thread_info->staged_gil_wait_count;
        thread_info->staged_gil_wait_us = 0;
        thread_info->staged_gil_wait_count = 0;
    }

    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);

    return thread_info;
}

void wsgi_end_request(void)
{
    WSGIThreadInfo *thread_info;

    PyObject *module = NULL;

    WSGIThreadCPUUsage cpu_usage;
    int have_cpu = 0;

    thread_info = wsgi_thread_info(0, 1);

    /*
     * Capture CPU baseline before the lock; getrusage / thread_info
     * only see the current worker's state.
     */

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

            /*
             * Either side may be NULL if start_request never reached
             * the registration step (request_id decode failure, missing
             * active_requests dict, etc). A KeyError here just means
             * registration was skipped or already failed; clear it so
             * it doesn't leak into the next Python C API call.
             */

            if (requests && thread_info->request_id)
            {
                if (PyDict_DelItem(requests,
                                   thread_info->request_id) < 0)
                    PyErr_Clear();
            }

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

    /*
     * Fold the slot's per-request metrics into the interval accumulator,
     * release the active slot, and decrement utilization, all under one
     * lock acquire. If the request exceeded the slow threshold, snapshot
     * a completion record into the finalize ring while r->pool is still
     * alive (Apache destroys it only after wsgi_end_request returns).
     * Clearing the slot under the same lock ensures the reporter never
     * sees a slot with a dangling r.
     */

    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);

    if (thread_info && thread_info->thread_id >= 1)
    {
        WSGIActiveSlot *slot = &thread_info->slot;
        WSGITickStats *stats = &thread_info->tick_stats;

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

            /*
             * CPU deltas computed once and reused: per-slot stats
             * accumulator gets the sum, slow-record snapshot below
             * gets user/system separately so the UI can show the
             * breakdown in drill-down.
             */

            double cpu_user_delta = 0.0;
            double cpu_system_delta = 0.0;
            if (have_cpu && slot->cpu_valid)
            {
                cpu_user_delta = cpu_usage.user_time -
                                 slot->cpu_user_at_start;
                cpu_system_delta = cpu_usage.system_time -
                                   slot->cpu_system_at_start;
                if (cpu_user_delta < 0.0)
                    cpu_user_delta = 0.0;
                if (cpu_system_delta < 0.0)
                    cpu_system_delta = 0.0;
                stats->cpu_time_us +=
                    (apr_time_t)((cpu_user_delta + cpu_system_delta) *
                                 1.0e6);
            }

            if (wsgi_slow_threshold_us > 0 &&
                elapsed >= wsgi_slow_threshold_us)
            {
                wsgi_slow_request_t rec;
                memset(&rec, 0, sizeof(rec));
                rec.state = 1; /* completed */
                rec.start_stamp_us = (uint64_t)slot->start_us;
                rec.duration_us = (uint64_t)elapsed;
                rec.thread_id = (uint32_t)thread_info->thread_id;
                rec.input_bytes = (uint64_t)slot->io_input_bytes;
                rec.input_reads = (uint64_t)slot->io_input_reads;
                rec.output_bytes = (uint64_t)slot->io_output_bytes;
                rec.output_writes = (uint64_t)slot->io_output_writes;
                rec.input_read_us = (uint64_t)slot->io_input_read_us;
                rec.output_write_us = (uint64_t)slot->io_output_write_us;
                rec.cpu_user_us = (uint64_t)(cpu_user_delta * 1.0e6);
                rec.cpu_system_us = (uint64_t)(cpu_system_delta * 1.0e6);
                rec.status = (uint16_t)slot->last_status;
                rec.active_at_start = slot->active_at_start;

                /*
                 * active_requests still includes this request at this
                 * point; the matching decrement happens below in
                 * wsgi_utilization_time_locked(-1, ...).
                 */

                rec.active_at_completion =
                    (uint64_t)wsgi_process_metrics->active_requests;
                rec.gil_wait_us = slot->gil_wait_us;
                rec.gil_wait_count = slot->gil_wait_count;
                wsgi_slow_fill_phase_durations(&rec, slot, now);
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
        slot->io_input_read_us = 0;
        slot->io_output_write_us = 0;
        slot->last_status = 0;
        slot->gil_wait_us = 0;
        slot->gil_wait_count = 0;
    }

    wsgi_utilization_time_locked(-1, NULL);

    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);
}

/* ------------------------------------------------------------------------- */

/*
 * C-native interval snapshot for the telemetry reporter thread. Reads
 * the same aggregation globals as wsgi_request_metrics() but builds no
 * Python objects, so it does not require the GIL. Shares the per-reader
 * baselines (start_*) on WSGIProcessMetrics with the Python accessor;
 * the two readers are mutually exclusive at runtime (when external
 * reporting is enabled the Python accessors return None) so the shared
 * baselines are only ever advanced by one of them.
 */

static int wsgi_query_request_threads_maximum(void)
{
    int max = 0;
    int is_threaded = 0;

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
    return max;
}

void wsgi_metrics_telemetry_init(void)
{
    /*
     * Seed the per-reader baselines on WSGIProcessMetrics and enable
     * per-request accounting from this point. Called from
     * wsgi_telemetry_start_reporter in the daemon main thread before
     * any worker thread has had a chance to serve a request, so
     * wsgi_record_request_times sees enabled=1 on its first call and
     * request data from t=0 onwards is captured.
     *
     * Idempotent: a second call is a no-op. The baseline set is shared
     * with the wsgi_request_metrics() Python accessor (the two readers
     * are mutually exclusive at runtime), so this initialiser and
     * wsgi_start_recording_metrics seed the same fields.
     */

    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);

    if (wsgi_process_metrics->start_time != 0.0)
    {
        apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);
        return;
    }

    wsgi_process_metrics->start_time = (double)apr_time_now();
    wsgi_process_metrics->start_request_busy_time =
        wsgi_utilization_time_locked(0,
                                     &wsgi_process_metrics->start_request_count);

    wsgi_process_metrics->request_metrics_enabled = 1;

    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);

#ifdef HAVE_TIMES
    {
        struct tms tmsbuf;
        times(&tmsbuf);
        wsgi_process_metrics->start_cpu_user_time =
            tmsbuf.tms_utime / wsgi_process_metrics->tick_hz;
        wsgi_process_metrics->start_cpu_system_time =
            tmsbuf.tms_stime / wsgi_process_metrics->tick_hz;
    }
#endif
}

/*
 * Python-API entry point: mod_wsgi.start_recording_metrics(). Enables
 * per-request metrics accounting for the wsgi_request_metrics() and
 * wsgi_process_metrics() Python accessors, and seeds the per-reader
 * baselines so the first wsgi_request_metrics() call returns data
 * covering the interval since this function ran.
 *
 * Idempotent. A no-op when external telemetry reporting is enabled
 * (the reporter has already turned recording on for itself, and the
 * Python accessors return None regardless when external reporting
 * holds the recording slot). Safe to call unconditionally at app init.
 */

static PyObject *wsgi_start_recording_metrics(void)
{
    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);

    if (wsgi_process_metrics->start_time != 0.0)
    {
        apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);
        Py_RETURN_NONE;
    }

    wsgi_process_metrics->start_time = (double)apr_time_now();
    wsgi_process_metrics->start_request_busy_time =
        wsgi_utilization_time_locked(0,
                                     &wsgi_process_metrics->start_request_count);

    wsgi_process_metrics->request_metrics_enabled = 1;

    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);

#ifdef HAVE_TIMES
    {
        struct tms tmsbuf;
        times(&tmsbuf);
        wsgi_process_metrics->start_cpu_user_time =
            (double)tmsbuf.tms_utime / wsgi_process_metrics->tick_hz;
        wsgi_process_metrics->start_cpu_system_time =
            (double)tmsbuf.tms_stime / wsgi_process_metrics->tick_hz;
    }
#endif

    Py_RETURN_NONE;
}

PyMethodDef wsgi_start_recording_metrics_method[] = {
    {"start_recording_metrics", (PyCFunction)wsgi_start_recording_metrics,
     METH_NOARGS, 0},
    {NULL},
};

int wsgi_metrics_snapshot(wsgi_telemetry_sample_t *out)
{
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
    double request_time_total = 0.0;
    double gil_wait_time_total = 0.0;
    double input_read_time_total = 0.0;
    double output_write_time_total = 0.0;

    int i;
    int emitted_slots = 0;
    int threads_active = 0;

#ifdef HAVE_TIMES
    struct tms tmsbuf;
#endif

    if (!out)
        return 0;

    memset(out, 0, sizeof(*out));

    stop_time = apr_time_now();

    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);

    stop_request_busy_time = wsgi_utilization_time_locked(0,
                                                          &stop_request_count);

    /*
     * Ensure slot arrays exist even before the first request so a tick
     * that fires on an idle worker can still emit a well-formed
     * (all-zero) slot payload. Idempotent.
     */

    wsgi_slow_ring_ensure_locked();

    /*
     * First call seeds counters and returns a not-yet-seeded sample.
     */

    if (!wsgi_process_metrics->start_time)
    {
        wsgi_process_metrics->sample_requests = 0;
        wsgi_phase_aggregate_reset(&wsgi_process_metrics->server_time);
        wsgi_phase_aggregate_reset(&wsgi_process_metrics->queue_time);
        wsgi_phase_aggregate_reset(&wsgi_process_metrics->daemon_time);
        wsgi_phase_aggregate_reset(&wsgi_process_metrics->application_time);
        wsgi_phase_aggregate_reset(&wsgi_process_metrics->request_time);
        wsgi_phase_aggregate_reset(&wsgi_process_metrics->gil_wait_time);
        wsgi_phase_aggregate_reset(&wsgi_process_metrics->input_read_time);
        wsgi_phase_aggregate_reset(&wsgi_process_metrics->output_write_time);
        wsgi_process_metrics->gil_wait_count_total = 0;

        wsgi_process_metrics->input_bytes_total = 0;
        wsgi_process_metrics->input_reads_total = 0;
        wsgi_process_metrics->output_bytes_total = 0;
        wsgi_process_metrics->output_writes_total = 0;

        wsgi_process_metrics->status_1xx_count = 0;
        wsgi_process_metrics->status_2xx_count = 0;
        wsgi_process_metrics->status_3xx_count = 0;
        wsgi_process_metrics->status_4xx_count = 0;
        wsgi_process_metrics->status_5xx_count = 0;

        wsgi_process_metrics->request_metrics_enabled = 1;

        apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);

        wsgi_process_metrics->start_time = stop_time;
        wsgi_process_metrics->start_request_busy_time = stop_request_busy_time;
        wsgi_process_metrics->start_request_count = stop_request_count;

#ifdef HAVE_TIMES
        times(&tmsbuf);
        wsgi_process_metrics->start_cpu_user_time =
            tmsbuf.tms_utime / wsgi_process_metrics->tick_hz;
        wsgi_process_metrics->start_cpu_system_time =
            tmsbuf.tms_stime / wsgi_process_metrics->tick_hz;
#endif

        out->seeded = 0;
        return 1;
    }

    interval_requests = wsgi_process_metrics->sample_requests;
    server_time_total = wsgi_process_metrics->server_time.total;
    queue_time_total = wsgi_process_metrics->queue_time.total;
    daemon_time_total = wsgi_process_metrics->daemon_time.total;
    application_time_total = wsgi_process_metrics->application_time.total;
    request_time_total = wsgi_process_metrics->request_time.total;
    gil_wait_time_total = wsgi_process_metrics->gil_wait_time.total;
    input_read_time_total = wsgi_process_metrics->input_read_time.total;
    output_write_time_total = wsgi_process_metrics->output_write_time.total;

    out->server_time_min_us = wsgi_process_metrics->server_time.min_us;
    out->server_time_max_us = wsgi_process_metrics->server_time.max_us;
    out->queue_time_min_us = wsgi_process_metrics->queue_time.min_us;
    out->queue_time_max_us = wsgi_process_metrics->queue_time.max_us;
    out->daemon_time_min_us = wsgi_process_metrics->daemon_time.min_us;
    out->daemon_time_max_us = wsgi_process_metrics->daemon_time.max_us;
    out->application_time_min_us = wsgi_process_metrics->application_time.min_us;
    out->application_time_max_us = wsgi_process_metrics->application_time.max_us;
    out->request_time_min_us = wsgi_process_metrics->request_time.min_us;
    out->request_time_max_us = wsgi_process_metrics->request_time.max_us;
    out->gil_wait_time_min_us = wsgi_process_metrics->gil_wait_time.min_us;
    out->gil_wait_time_max_us = wsgi_process_metrics->gil_wait_time.max_us;
    out->input_read_time_min_us = wsgi_process_metrics->input_read_time.min_us;
    out->input_read_time_max_us = wsgi_process_metrics->input_read_time.max_us;
    out->output_write_time_min_us = wsgi_process_metrics->output_write_time.min_us;
    out->output_write_time_max_us = wsgi_process_metrics->output_write_time.max_us;

    out->input_bytes_total = wsgi_process_metrics->input_bytes_total;
    out->input_reads_total = wsgi_process_metrics->input_reads_total;
    out->output_bytes_total = wsgi_process_metrics->output_bytes_total;
    out->output_writes_total = wsgi_process_metrics->output_writes_total;

    out->status_1xx_total = wsgi_process_metrics->status_1xx_count;
    out->status_2xx_total = wsgi_process_metrics->status_2xx_count;
    out->status_3xx_total = wsgi_process_metrics->status_3xx_count;
    out->status_4xx_total = wsgi_process_metrics->status_4xx_count;
    out->status_5xx_total = wsgi_process_metrics->status_5xx_count;

    for (i = 0; i < WSGI_TELEMETRY_BUCKET_COUNT; i++)
    {
        out->server_time_buckets[i] = wsgi_process_metrics->server_time.buckets[i];
        out->queue_time_buckets[i] = wsgi_process_metrics->queue_time.buckets[i];
        out->daemon_time_buckets[i] = wsgi_process_metrics->daemon_time.buckets[i];
        out->application_time_buckets[i] = wsgi_process_metrics->application_time.buckets[i];
        out->request_time_buckets[i] = wsgi_process_metrics->request_time.buckets[i];
        out->gil_wait_time_buckets[i] = wsgi_process_metrics->gil_wait_time.buckets[i];
        out->input_read_time_buckets[i] = wsgi_process_metrics->input_read_time.buckets[i];
        out->output_write_time_buckets[i] = wsgi_process_metrics->output_write_time.buckets[i];
    }

    /*
     * Per-slot capacity drain. Fold any in-flight busy-tail so a long
     * request contributes to every tick it spans, not just the tick it
     * completes in. CPU-time tails can't be folded here because
     * getrusage(RUSAGE_THREAD) / thread_info() only sees the current
     * thread; worker threads publish their CPU delta at request-end.
     */

    emitted_slots = wsgi_process_metrics->request_threads_maximum;
    if (emitted_slots > WSGI_TELEMETRY_MAX_SLOTS)
        emitted_slots = WSGI_TELEMETRY_MAX_SLOTS;

    if (emitted_slots > 0 && wsgi_process_metrics->thread_details)
    {
        apr_time_t now = apr_time_now();
        WSGIThreadInfo **threads = (WSGIThreadInfo **)
                                       wsgi_process_metrics->thread_details->elts;
        int nelts = wsgi_process_metrics->thread_details->nelts;

        for (i = 0; i < nelts; i++)
        {
            WSGIThreadInfo *ti = threads[i];
            WSGIActiveSlot *slot;
            WSGITickStats *stats;
            int idx;
            apr_time_t busy_tail = 0;
            apr_time_t current_elapsed = 0;

            if (!ti->request_thread)
                continue;
            idx = ti->thread_id - 1;
            if (idx < 0 || idx >= emitted_slots)
                continue;

            slot = &ti->slot;
            stats = &ti->tick_stats;

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

            out->slot_request_count[idx] = (int32_t)stats->completed;
            out->slot_busy_time_us[idx] =
                (int32_t)(stats->busy_time_us + busy_tail);
            out->slot_cpu_time_us[idx] = (int32_t)stats->cpu_time_us;
            out->slot_current_elapsed_ms[idx] =
                (int32_t)(current_elapsed / 1000);
            out->slot_max_duration_ms[idx] =
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

    wsgi_process_metrics->sample_requests = 0;
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->server_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->queue_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->daemon_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->application_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->request_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->gil_wait_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->input_read_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->output_write_time);
    wsgi_process_metrics->gil_wait_count_total = 0;

    wsgi_process_metrics->input_bytes_total = 0;
    wsgi_process_metrics->input_reads_total = 0;
    wsgi_process_metrics->output_bytes_total = 0;
    wsgi_process_metrics->output_writes_total = 0;

    wsgi_process_metrics->status_1xx_count = 0;
    wsgi_process_metrics->status_2xx_count = 0;
    wsgi_process_metrics->status_3xx_count = 0;
    wsgi_process_metrics->status_4xx_count = 0;
    wsgi_process_metrics->status_5xx_count = 0;

    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);

    out->seeded = 1;

    sample_period = apr_time_sec((double)stop_time) -
                    apr_time_sec((double)wsgi_process_metrics->start_time);
    if (sample_period <= 0.0)
        sample_period = 1e-9; /* avoid divide by zero */

    out->sample_period = sample_period;

#ifdef HAVE_TIMES
    times(&tmsbuf);
    {
        double stop_user = tmsbuf.tms_utime / wsgi_process_metrics->tick_hz;
        double stop_system = tmsbuf.tms_stime / wsgi_process_metrics->tick_hz;
        double user_rate =
            (stop_user - wsgi_process_metrics->start_cpu_user_time) /
            sample_period;
        double system_rate =
            (stop_system - wsgi_process_metrics->start_cpu_system_time) /
            sample_period;

        out->cpu_user_utilization = user_rate;
        out->cpu_system_utilization = system_rate;
        out->cpu_utilization = user_rate + system_rate;

        wsgi_process_metrics->start_cpu_user_time = stop_user;
        wsgi_process_metrics->start_cpu_system_time = stop_system;
    }
#endif

    out->memory_rss = (uint64_t)wsgi_get_current_memory_RSS();
    out->memory_max_rss = (uint64_t)wsgi_get_peak_memory_RSS();

    out->request_threads_maximum =
        (uint32_t)wsgi_process_metrics->request_threads_maximum;
    out->request_threads_started = (uint32_t)wsgi_process_metrics->request_threads;

    request_busy_time = stop_request_busy_time -
                        wsgi_process_metrics->start_request_busy_time;
    out->capacity_utilization = request_busy_time / sample_period /
                                wsgi_process_metrics->request_threads_maximum;

    out->request_count =
        stop_request_count - wsgi_process_metrics->start_request_count;
    out->request_throughput = (sample_period > 0) ? (double)out->request_count / sample_period : 0.0;

    wsgi_process_metrics->start_time = stop_time;
    wsgi_process_metrics->start_request_busy_time = stop_request_busy_time;
    wsgi_process_metrics->start_request_count = stop_request_count;

    out->request_threads_active = (uint32_t)threads_active;

    if (interval_requests)
    {
        out->server_time = server_time_total / interval_requests;
        out->application_time = application_time_total / interval_requests;
        out->request_time = request_time_total / interval_requests;
        out->gil_wait_time = gil_wait_time_total / interval_requests;
        out->input_read_time = input_read_time_total / interval_requests;
        out->output_write_time = output_write_time_total / interval_requests;
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

/*
 * Slow-request helpers. Lazy-allocate the completion ring on first
 * request so there is no cost when the feature is off. Copy strings
 * out of a live request_rec under the monitor lock, truncating each
 * field with an "..." suffix so the UI can show where the cut was
 * made.
 */

static void wsgi_slow_ring_ensure_locked(void)
{
    int max = 0;
    int is_threaded = 0;
    int ring = WSGI_SLOW_RING_FLOOR;

    if (wsgi_process_metrics->slow_completed_ring)
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

    /*
     * Size the slow-completion ring from N threads x max
     * completions-per-tick x safety. Each thread can complete at most
     * ceil(T / S) slow requests in a tick, so total per-tick worst case
     * is max * ceil(T / S); the safety factor absorbs inter-tick jitter
     * and burst clustering. Floor + cap keep tiny deployments at 32 and
     * prevent pathological sizing when WSGISlowRequests is set very low.
     */

    if (wsgi_slow_threshold_us > 0)
    {
        double tick_s = wsgi_telemetry_interval > 0
                            ? wsgi_telemetry_interval
                            : 1.0;
        double thresh_s = (double)wsgi_slow_threshold_us / 1.0e6;
        if (thresh_s > 0)
        {
            double per_thread = ceil(tick_s / thresh_s);
            if (per_thread < 1.0)
                per_thread = 1.0;
            double sized = (double)max * per_thread *
                           (double)WSGI_SLOW_RING_SAFETY;
            if (sized > (double)ring)
                ring = (int)sized;
            if (ring > WSGI_SLOW_RING_CAP)
                ring = WSGI_SLOW_RING_CAP;
        }
    }
    wsgi_process_metrics->slow_completed_ring = (wsgi_slow_request_t *)apr_pcalloc(
        wsgi_server_config->pool, ring * sizeof(*wsgi_process_metrics->slow_completed_ring));
    wsgi_process_metrics->slow_completed_ring_size = ring;
}

/*
 * Fills the four phase-duration fields on rec from the slot's stashed
 * timestamps. Mirrors the breakdown that wsgi_record_request_times
 * applies to the aggregate stream. now_us is used in place of the
 * unset application_finish for active records still inside the WSGI
 * callable; for completed records (where application_finish_us is
 * non-zero) it is unused. queue_start_us is non-zero only in daemon
 * mode; embedded mode collapses queue_time and daemon_time into 0 and
 * folds everything before application_start into server_time.
 */

static void wsgi_slow_fill_phase_durations(wsgi_slow_request_t *rec,
                                           const WSGIActiveSlot *slot,
                                           apr_time_t now_us)
{
    apr_time_t app_start;
    apr_time_t app_finish;

    app_start = slot->application_start_us;
    app_finish = slot->application_finish_us
                     ? slot->application_finish_us
                     : (app_start ? now_us : 0);

    if (slot->queue_start_us)
    {
        rec->server_time_us = (uint64_t)(slot->queue_start_us -
                                         slot->request_start_us);
        rec->queue_time_us = (uint64_t)(slot->daemon_start_us -
                                        slot->queue_start_us);
        if (app_start)
        {
            rec->daemon_time_us = (uint64_t)(app_start -
                                             slot->daemon_start_us);
            rec->application_time_us = app_finish
                                           ? (uint64_t)(app_finish - app_start)
                                           : 0;
        }
        else
        {
            /*
             * Pre-app phase is still in the daemon-side setup. Report
             * the elapsed-since-daemon-start as a partial daemon_time
             * so the user can see where time is going; application is
             * zero by definition.
             */

            rec->daemon_time_us = (uint64_t)(now_us -
                                             slot->daemon_start_us);
            rec->application_time_us = 0;
        }
    }
    else
    {
        /*
         * Embedded mode: no queue or daemon hand-off. Server covers
         * everything up to application_start; if the WSGI callable has
         * not yet been invoked, server is the partial elapsed-since-
         * request-start.
         */

        if (app_start)
        {
            rec->server_time_us = (uint64_t)(app_start -
                                             slot->request_start_us);
            rec->application_time_us = app_finish
                                           ? (uint64_t)(app_finish - app_start)
                                           : 0;
        }
        else
        {
            rec->server_time_us = slot->request_start_us
                                      ? (uint64_t)(now_us - slot->request_start_us)
                                      : 0;
            rec->application_time_us = 0;
        }
        rec->queue_time_us = 0;
        rec->daemon_time_us = 0;
    }
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

/*
 * Pull URL / identity out of a request_rec into a snapshot record. Does
 * no allocation and never touches r->pool; safe to call under lock.
 */

static void wsgi_slow_snapshot_fields(wsgi_slow_request_t *rec, request_rec *r)
{
    const char *script_name = NULL;
    const char *path_info = NULL;
    const char *scheme_env = NULL;
    const char *scheme = "http";
    const char *protocol = NULL;

    wsgi_slow_copy_str(rec->log_id, sizeof(rec->log_id),
                       r->log_id ? r->log_id : "");
    wsgi_slow_copy_str(rec->hostname, sizeof(rec->hostname),
                       r->hostname ? r->hostname : "");

    /*
     * r->useragent_ip reflects mod_wsgi's existing trusted-proxy /
     * X-Forwarded-For resolution (see wsgi_environ.c) when configured,
     * so this is the *real* client IP rather than the immediate-hop
     * proxy. Apache populates it natively in embedded mode and
     * wsgi_daemon.c assigns it from the inbound connection in daemon
     * mode.
     */

    wsgi_slow_copy_str(rec->peer_ip, sizeof(rec->peer_ip),
                       r->useragent_ip ? r->useragent_ip : "");

    /*
     * In daemon mode r->method is NULL: the daemon-side request_rec is
     * synthesised from the subprocess_env stream and wsgi_read_request
     * never fills r->method. REQUEST_METHOD in subprocess_env is the
     * canonical source (ap_add_cgi_vars sets it on the parent) and works
     * in both daemon and embedded modes.
     */

    const char *method = NULL;

    if (r->subprocess_env)
    {
        method = apr_table_get(r->subprocess_env, "REQUEST_METHOD");

        /*
         * HTTPS in subprocess_env is the authoritative scheme decision
         * after trusted-proxy handling + mod_ssl detection. mod_wsgi
         * strips it from the Python WSGI environ dict later, but the
         * apr_table value survives for the lifetime of the request.
         */

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

        /*
         * SERVER_PROTOCOL is the canonical "HTTP/1.1" / "HTTP/2.0"
         * string and crosses the daemon socket via subprocess_env, so
         * it works in both modes. r->protocol is the embedded-mode
         * fallback (in daemon mode r->protocol on the synthesised
         * request_rec is unreliable).
         */

        protocol = apr_table_get(r->subprocess_env, "SERVER_PROTOCOL");
    }

    if (!protocol)
        protocol = r->protocol;

    if (!method)
        method = r->method; /* embedded-mode fallback */

    wsgi_slow_copy_str(rec->method, sizeof(rec->method),
                       method ? method : "");

    wsgi_slow_copy_str(rec->scheme, sizeof(rec->scheme), scheme);
    wsgi_slow_copy_str(rec->script_name, sizeof(rec->script_name),
                       script_name ? script_name : "");

    /*
     * Fall back to r->uri (always query-stripped) when the env keys are
     * absent; never read r->unparsed_uri or r->args so query strings
     * can't leak into telemetry.
     */

    wsgi_slow_copy_str(rec->path_info, sizeof(rec->path_info),
                       path_info ? path_info : (r->uri ? r->uri : ""));

    wsgi_slow_copy_str(rec->protocol, sizeof(rec->protocol),
                       protocol ? protocol : "");

    /*
     * User-Agent is opt-in via WSGIMetricsOptions +CaptureUserAgent
     * because UA strings can be PII-adjacent (fingerprinting) and bots
     * sometimes ship multi-kilobyte values. HTTP_USER_AGENT is the
     * canonical CGI-style env var and works in both modes; in daemon
     * mode the synthesised request_rec only rebuilds Host / Content-
     * Length / Transfer-Encoding into headers_in, so the original UA
     * header is reachable only via subprocess_env.
     */

    if (wsgi_metrics_options & WSGI_METRICS_OPT_CAPTURE_USER_AGENT)
    {
        const char *ua = NULL;
        if (r->subprocess_env)
            ua = apr_table_get(r->subprocess_env, "HTTP_USER_AGENT");
        if (!ua && r->headers_in)
            ua = apr_table_get(r->headers_in, "User-Agent");
        wsgi_slow_copy_str(rec->user_agent, sizeof(rec->user_agent),
                           ua ? ua : "");
    }
}

/*
 * Caller must hold the monitor lock.
 */

static void wsgi_slow_push_completed_locked(const wsgi_slow_request_t *rec)
{
    int idx;

    if (!wsgi_process_metrics->slow_completed_ring || wsgi_process_metrics->slow_completed_ring_size <= 0)
        return;

    if (wsgi_process_metrics->slow_completed_ring_count < wsgi_process_metrics->slow_completed_ring_size)
    {
        idx = (wsgi_process_metrics->slow_completed_ring_head + wsgi_process_metrics->slow_completed_ring_count) %
              wsgi_process_metrics->slow_completed_ring_size;
        wsgi_process_metrics->slow_completed_ring_count++;
    }
    else
    {
        /*
         * Ring full: drop oldest so recent slow completions aren't lost.
         * With dynamic sizing this should be rare in practice; if it
         * fires consistently the safety factor needs bumping.
         */

        idx = wsgi_process_metrics->slow_completed_ring_head;
        wsgi_process_metrics->slow_completed_ring_head = (wsgi_process_metrics->slow_completed_ring_head + 1) %
                                                         wsgi_process_metrics->slow_completed_ring_size;
    }

    wsgi_process_metrics->slow_completed_ring[idx] = *rec;
}

int wsgi_metrics_pop_slow_completed(wsgi_slow_request_t *out)
{
    int got = 0;

    if (!out)
        return 0;

    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);

    if (wsgi_process_metrics->slow_completed_ring && wsgi_process_metrics->slow_completed_ring_count > 0)
    {
        *out = wsgi_process_metrics->slow_completed_ring[wsgi_process_metrics->slow_completed_ring_head];
        wsgi_process_metrics->slow_completed_ring_head = (wsgi_process_metrics->slow_completed_ring_head + 1) %
                                                         wsgi_process_metrics->slow_completed_ring_size;
        wsgi_process_metrics->slow_completed_ring_count--;
        got = 1;
    }

    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);

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

    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);

    if (!wsgi_process_metrics->thread_details)
    {
        apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);
        return 0;
    }

    {
        WSGIThreadInfo **threads = (WSGIThreadInfo **)
                                       wsgi_process_metrics->thread_details->elts;
        int nelts = wsgi_process_metrics->thread_details->nelts;

        for (i = 0; i < nelts && n < out_cap; i++)
        {
            WSGIThreadInfo *ti = threads[i];
            WSGIActiveSlot *slot;
            apr_time_t elapsed;
            wsgi_slow_request_t *rec;

            if (!ti->request_thread)
                continue;
            slot = &ti->slot;
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
            rec->thread_id = (uint32_t)ti->thread_id;
            rec->input_bytes = (uint64_t)slot->io_input_bytes;
            rec->input_reads = (uint64_t)slot->io_input_reads;
            rec->output_bytes = (uint64_t)slot->io_output_bytes;
            rec->output_writes = (uint64_t)slot->io_output_writes;
            rec->input_read_us = (uint64_t)slot->io_input_read_us;
            rec->output_write_us = (uint64_t)slot->io_output_write_us;
            rec->active_at_start = slot->active_at_start;

            /*
             * active_at_completion is unset for in-flight records by
             * definition (they haven't completed); leave at 0 from the
             * memset above.
             */

            rec->gil_wait_us = slot->gil_wait_us;
            rec->gil_wait_count = slot->gil_wait_count;
            wsgi_slow_fill_phase_durations(rec, slot, now_us);
            wsgi_slow_snapshot_fields(rec, slot->r);

            n++;
        }
    }

    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);

    return n;
}

/* ------------------------------------------------------------------------- */

#define WSGI_CREATE_STATUS_FLAG(name, val) \
    state->status_flags[name] = PyUnicode_InternFromString(val)

int wsgi_metrics_init_state(PyObject *module)
{
    WSGIModuleState *state = NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state)
        return -1;

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
    WSGI_CREATE_INTERNED_STRING_ID(request_time);
    WSGI_CREATE_INTERNED_STRING_ID(server_time_min_us);
    WSGI_CREATE_INTERNED_STRING_ID(queue_time_min_us);
    WSGI_CREATE_INTERNED_STRING_ID(daemon_time_min_us);
    WSGI_CREATE_INTERNED_STRING_ID(application_time_min_us);
    WSGI_CREATE_INTERNED_STRING_ID(request_time_min_us);
    WSGI_CREATE_INTERNED_STRING_ID(server_time_max_us);
    WSGI_CREATE_INTERNED_STRING_ID(queue_time_max_us);
    WSGI_CREATE_INTERNED_STRING_ID(daemon_time_max_us);
    WSGI_CREATE_INTERNED_STRING_ID(application_time_max_us);
    WSGI_CREATE_INTERNED_STRING_ID(request_time_max_us);
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

    WSGI_CREATE_INTERNED_STRING_ID(gil_wait_time);
    WSGI_CREATE_INTERNED_STRING_ID(gil_wait_time_min_us);
    WSGI_CREATE_INTERNED_STRING_ID(gil_wait_time_max_us);
    WSGI_CREATE_INTERNED_STRING_ID(gil_wait_time_buckets);
    WSGI_CREATE_INTERNED_STRING_ID(gil_wait_count);
    WSGI_CREATE_INTERNED_STRING_ID(input_read_time);
    WSGI_CREATE_INTERNED_STRING_ID(input_read_time_min_us);
    WSGI_CREATE_INTERNED_STRING_ID(input_read_time_max_us);
    WSGI_CREATE_INTERNED_STRING_ID(input_read_time_buckets);
    WSGI_CREATE_INTERNED_STRING_ID(output_write_time);
    WSGI_CREATE_INTERNED_STRING_ID(output_write_time_min_us);
    WSGI_CREATE_INTERNED_STRING_ID(output_write_time_max_us);
    WSGI_CREATE_INTERNED_STRING_ID(output_write_time_buckets);

    WSGI_CREATE_INTERNED_STRING_ID(input_bytes);
    WSGI_CREATE_INTERNED_STRING_ID(input_reads);
    WSGI_CREATE_INTERNED_STRING_ID(output_bytes);
    WSGI_CREATE_INTERNED_STRING_ID(output_writes);

    WSGI_CREATE_INTERNED_STRING_ID(status_1xx);
    WSGI_CREATE_INTERNED_STRING_ID(status_2xx);
    WSGI_CREATE_INTERNED_STRING_ID(status_3xx);
    WSGI_CREATE_INTERNED_STRING_ID(status_4xx);
    WSGI_CREATE_INTERNED_STRING_ID(status_5xx);

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

    return 0;
}

/* ------------------------------------------------------------------------- */

/*
 * Each helper sets a typed value on `dict` under `key` and returns 0 on
 * success, or -1 with a Python exception set on failure. The caller
 * pattern is `if (wsgi_dict_set_*(...) < 0) goto error;` paired with an
 * `error:` label that Py_XDECREFs partially-built containers and
 * returns NULL.
 */

static int wsgi_dict_set_steal(PyObject *dict, PyObject *key, PyObject *value)
{
    int rc;

    if (!value)
        return -1;
    rc = PyDict_SetItem(dict, key, value);
    Py_DECREF(value);
    return rc;
}

static int wsgi_dict_set_long(PyObject *dict, PyObject *key, long val)
{
    return wsgi_dict_set_steal(dict, key, PyLong_FromLong(val));
}

static int wsgi_dict_set_longlong(PyObject *dict, PyObject *key,
                                  long long val)
{
    return wsgi_dict_set_steal(dict, key, PyLong_FromLongLong(val));
}

static int wsgi_dict_set_ulonglong(PyObject *dict, PyObject *key,
                                   unsigned long long val)
{
    return wsgi_dict_set_steal(dict, key, PyLong_FromUnsignedLongLong(val));
}

static int wsgi_dict_set_double(PyObject *dict, PyObject *key, double val)
{
    return wsgi_dict_set_steal(dict, key, PyFloat_FromDouble(val));
}

static int wsgi_dict_set_bool(PyObject *dict, PyObject *key, int val)
{
    return wsgi_dict_set_steal(dict, key, PyBool_FromLong(val));
}

static int wsgi_dict_set_none(PyObject *dict, PyObject *key)
{
    return PyDict_SetItem(dict, key, Py_None);
}

static int wsgi_dict_set_latin1(PyObject *dict, PyObject *key,
                                const char *s)
{
    /*
     * NULL s is treated as an empty string to match scoreboard call
     * sites where Apache may hand back NULL for an empty field.
     */

    PyObject *value = PyUnicode_DecodeLatin1(s ? s : "",
                                             s ? strlen(s) : 0, NULL);
    return wsgi_dict_set_steal(dict, key, value);
}

static int wsgi_dict_set_borrowed(PyObject *dict, PyObject *key,
                                  PyObject *value)
{
    if (!value)
    {
        PyErr_SetString(PyExc_SystemError,
                        "wsgi_dict_set_borrowed called with NULL value");
        return -1;
    }
    return PyDict_SetItem(dict, key, value);
}

static int wsgi_dict_set_long_list(PyObject *dict, PyObject *key,
                                   const int *vals, Py_ssize_t n)
{
    PyObject *lst;
    Py_ssize_t i;

    lst = PyList_New(n);
    if (!lst)
        return -1;
    for (i = 0; i < n; i++)
    {
        PyObject *o = PyLong_FromLong(vals[i]);
        if (!o)
        {
            Py_DECREF(lst);
            return -1;
        }
        PyList_SET_ITEM(lst, i, o);
    }
    return wsgi_dict_set_steal(dict, key, lst);
}

static int wsgi_dict_set_minmax_or_none(PyObject *dict, PyObject *min_key,
                                        PyObject *max_key,
                                        apr_uint64_t min_us,
                                        apr_uint64_t max_us)
{
    /*
     * min_us == UINT64_MAX means the phase recorded no requests this
     * interval; publish None for both keys so consumers can tell the
     * "no data" case from a recorded zero.
     */

    if (min_us == UINT64_MAX)
    {
        if (wsgi_dict_set_none(dict, min_key) < 0)
            return -1;
        return wsgi_dict_set_none(dict, max_key);
    }
    if (wsgi_dict_set_ulonglong(dict, min_key,
                                (unsigned long long)min_us) < 0)
        return -1;
    return wsgi_dict_set_ulonglong(dict, max_key,
                                   (unsigned long long)max_us);
}

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_request_metrics(void)
{
    PyObject *module = NULL;
    WSGIModuleState *state = NULL;

    PyObject *result = NULL;

    /*
     * External telemetry reporter is the canonical metrics consumer
     * when enabled; suppress the Python API path so consumers can
     * detect the configured mode by checking for None.
     */

    if (wsgi_telemetry_is_enabled())
        Py_RETURN_NONE;

    /*
     * Per-request recording must be opted in via
     * mod_wsgi.start_recording_metrics() before this accessor returns
     * data. The opt-in seeds the shared per-reader baselines used
     * below; an uninitialised start_time means the caller has not yet
     * opted in, so signal that with None.
     */

    if (wsgi_process_metrics->start_time == 0.0)
        Py_RETURN_NONE;

    apr_time_t stop_time;
    double stop_request_busy_time = 0.0;
    apr_uint64_t stop_request_count = 0;

    double request_busy_time = 0.0;
    double capacity_utilization = 0.0;

    double sample_period = 0.0;
    apr_uint64_t request_count = 0;
    double request_throughput = 0.0;
    double stop_cpu_system_time = 0.0;
    double stop_cpu_user_time = 0.0;

    double cpu_system_time = 0.0;
    double cpu_user_time = 0.0;
    double total_cpu_time = 0.0;

    int request_threads_maximum = wsgi_process_metrics->request_threads_maximum;
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
    double request_time_total = 0;
    double request_time_avg = 0;

    apr_uint64_t server_time_min_snap_us = UINT64_MAX;
    apr_uint64_t server_time_max_snap_us = 0;
    apr_uint64_t queue_time_min_snap_us = UINT64_MAX;
    apr_uint64_t queue_time_max_snap_us = 0;
    apr_uint64_t daemon_time_min_snap_us = UINT64_MAX;
    apr_uint64_t daemon_time_max_snap_us = 0;
    apr_uint64_t application_time_min_snap_us = UINT64_MAX;
    apr_uint64_t application_time_max_snap_us = 0;
    apr_uint64_t request_time_min_snap_us = UINT64_MAX;
    apr_uint64_t request_time_max_snap_us = 0;
    apr_uint64_t gil_wait_time_min_snap_us = UINT64_MAX;
    apr_uint64_t gil_wait_time_max_snap_us = 0;
    apr_uint64_t input_read_time_min_snap_us = UINT64_MAX;
    apr_uint64_t input_read_time_max_snap_us = 0;
    apr_uint64_t output_write_time_min_snap_us = UINT64_MAX;
    apr_uint64_t output_write_time_max_snap_us = 0;

    double gil_wait_time_total = 0;
    double gil_wait_time_avg = 0;
    apr_uint64_t gil_wait_count_snap = 0;
    double input_read_time_total = 0;
    double input_read_time_avg = 0;
    double output_write_time_total = 0;
    double output_write_time_avg = 0;

    apr_uint64_t input_bytes_snap = 0;
    apr_uint64_t input_reads_snap = 0;
    apr_uint64_t output_bytes_snap = 0;
    apr_uint64_t output_writes_snap = 0;

    apr_uint64_t status_1xx_snap = 0;
    apr_uint64_t status_2xx_snap = 0;
    apr_uint64_t status_3xx_snap = 0;
    apr_uint64_t status_4xx_snap = 0;
    apr_uint64_t status_5xx_snap = 0;

    int server_time_buckets_snap[WSGI_TELEMETRY_BUCKET_COUNT];
    int queue_time_buckets_snap[WSGI_TELEMETRY_BUCKET_COUNT];
    int daemon_time_buckets_snap[WSGI_TELEMETRY_BUCKET_COUNT];
    int application_time_buckets_snap[WSGI_TELEMETRY_BUCKET_COUNT];
    int request_time_buckets_snap[WSGI_TELEMETRY_BUCKET_COUNT];
    int gil_wait_time_buckets_snap[WSGI_TELEMETRY_BUCKET_COUNT];
    int input_read_time_buckets_snap[WSGI_TELEMETRY_BUCKET_COUNT];
    int output_write_time_buckets_snap[WSGI_TELEMETRY_BUCKET_COUNT];

    int request_threads_active = 0;

    int i;

#ifdef HAVE_TIMES
    struct tms tmsbuf;
#endif

    module = PyImport_ImportModule("mod_wsgi");
    if (!module)
        return NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state)
    {
        Py_DECREF(module);
        return NULL;
    }

    if (!slot_completed_snap)
    {
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
    if (!result)
        return NULL;

    stop_time = apr_time_now();

#ifdef HAVE_TIMES
    times(&tmsbuf);
    stop_cpu_user_time = tmsbuf.tms_utime / wsgi_process_metrics->tick_hz;
    stop_cpu_system_time = tmsbuf.tms_stime / wsgi_process_metrics->tick_hz;
#endif

    /*
     * One locked region covers the utilization read AND the accumulator
     * drain so the emitted sample is internally consistent. Python
     * object construction happens afterwards, using the local snapshots.
     */

    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);

    stop_request_busy_time = wsgi_utilization_time_locked(0,
                                                          &stop_request_count);

    /*
     * Ensure slow-completion ring exists even if no request has been
     * served yet.
     */

    wsgi_slow_ring_ensure_locked();

    interval_requests = wsgi_process_metrics->sample_requests;
    server_time_total = wsgi_process_metrics->server_time.total;
    queue_time_total = wsgi_process_metrics->queue_time.total;
    daemon_time_total = wsgi_process_metrics->daemon_time.total;
    application_time_total = wsgi_process_metrics->application_time.total;
    request_time_total = wsgi_process_metrics->request_time.total;
    gil_wait_time_total = wsgi_process_metrics->gil_wait_time.total;
    gil_wait_count_snap = wsgi_process_metrics->gil_wait_count_total;
    input_read_time_total = wsgi_process_metrics->input_read_time.total;
    output_write_time_total = wsgi_process_metrics->output_write_time.total;

    server_time_min_snap_us = wsgi_process_metrics->server_time.min_us;
    server_time_max_snap_us = wsgi_process_metrics->server_time.max_us;
    queue_time_min_snap_us = wsgi_process_metrics->queue_time.min_us;
    queue_time_max_snap_us = wsgi_process_metrics->queue_time.max_us;
    daemon_time_min_snap_us = wsgi_process_metrics->daemon_time.min_us;
    daemon_time_max_snap_us = wsgi_process_metrics->daemon_time.max_us;
    application_time_min_snap_us = wsgi_process_metrics->application_time.min_us;
    application_time_max_snap_us = wsgi_process_metrics->application_time.max_us;
    request_time_min_snap_us = wsgi_process_metrics->request_time.min_us;
    request_time_max_snap_us = wsgi_process_metrics->request_time.max_us;
    gil_wait_time_min_snap_us = wsgi_process_metrics->gil_wait_time.min_us;
    gil_wait_time_max_snap_us = wsgi_process_metrics->gil_wait_time.max_us;
    input_read_time_min_snap_us = wsgi_process_metrics->input_read_time.min_us;
    input_read_time_max_snap_us = wsgi_process_metrics->input_read_time.max_us;
    output_write_time_min_snap_us = wsgi_process_metrics->output_write_time.min_us;
    output_write_time_max_snap_us = wsgi_process_metrics->output_write_time.max_us;

    input_bytes_snap = wsgi_process_metrics->input_bytes_total;
    input_reads_snap = wsgi_process_metrics->input_reads_total;
    output_bytes_snap = wsgi_process_metrics->output_bytes_total;
    output_writes_snap = wsgi_process_metrics->output_writes_total;

    status_1xx_snap = wsgi_process_metrics->status_1xx_count;
    status_2xx_snap = wsgi_process_metrics->status_2xx_count;
    status_3xx_snap = wsgi_process_metrics->status_3xx_count;
    status_4xx_snap = wsgi_process_metrics->status_4xx_count;
    status_5xx_snap = wsgi_process_metrics->status_5xx_count;

    memcpy(server_time_buckets_snap, wsgi_process_metrics->server_time.buckets,
           sizeof(server_time_buckets_snap));
    memcpy(queue_time_buckets_snap, wsgi_process_metrics->queue_time.buckets,
           sizeof(queue_time_buckets_snap));
    memcpy(daemon_time_buckets_snap, wsgi_process_metrics->daemon_time.buckets,
           sizeof(daemon_time_buckets_snap));
    memcpy(application_time_buckets_snap, wsgi_process_metrics->application_time.buckets,
           sizeof(application_time_buckets_snap));
    memcpy(request_time_buckets_snap, wsgi_process_metrics->request_time.buckets,
           sizeof(request_time_buckets_snap));
    memcpy(gil_wait_time_buckets_snap, wsgi_process_metrics->gil_wait_time.buckets,
           sizeof(gil_wait_time_buckets_snap));
    memcpy(input_read_time_buckets_snap, wsgi_process_metrics->input_read_time.buckets,
           sizeof(input_read_time_buckets_snap));
    memcpy(output_write_time_buckets_snap, wsgi_process_metrics->output_write_time.buckets,
           sizeof(output_write_time_buckets_snap));

    /*
     * Per-slot capacity drain. Fold in-flight busy-tail so a long
     * request contributes to every interval it spans. CPU tails can't
     * be folded here (cross-thread CPU time isn't available);
     * request-end publishes the final CPU delta.
     */

    for (i = 0; i < request_threads_maximum; i++)
    {
        slot_completed_snap[i] = 0;
        slot_busy_us_snap[i] = 0;
        slot_cpu_us_snap[i] = 0;
        slot_current_ms_snap[i] = 0;
        slot_max_ms_snap[i] = 0;
    }

    if (wsgi_process_metrics->thread_details)
    {
        apr_time_t now = apr_time_now();
        WSGIThreadInfo **threads = (WSGIThreadInfo **)
                                       wsgi_process_metrics->thread_details->elts;
        int nelts = wsgi_process_metrics->thread_details->nelts;

        for (i = 0; i < nelts; i++)
        {
            WSGIThreadInfo *ti = threads[i];
            WSGIActiveSlot *slot;
            WSGITickStats *stats;
            int idx;
            apr_time_t busy_tail = 0;
            apr_time_t current_elapsed = 0;

            if (!ti->request_thread)
                continue;
            idx = ti->thread_id - 1;
            if (idx < 0 || idx >= request_threads_maximum)
                continue;

            slot = &ti->slot;
            stats = &ti->tick_stats;

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

            slot_completed_snap[idx] = (int)stats->completed;
            slot_busy_us_snap[idx] =
                (int)(stats->busy_time_us + busy_tail);
            slot_cpu_us_snap[idx] = (int)stats->cpu_time_us;
            slot_current_ms_snap[idx] = (int)(current_elapsed / 1000);
            slot_max_ms_snap[idx] = (int)(stats->max_duration_us / 1000);

            stats->busy_time_us = 0;
            stats->cpu_time_us = 0;
            stats->completed = 0;
            stats->max_duration_us = 0;
        }
    }

    wsgi_process_metrics->sample_requests = 0;
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->server_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->queue_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->daemon_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->application_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->request_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->gil_wait_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->input_read_time);
    wsgi_phase_aggregate_reset(&wsgi_process_metrics->output_write_time);
    wsgi_process_metrics->gil_wait_count_total = 0;

    /*
     * Drain the I/O totals. Snapshots were taken above into
     * input_bytes_snap / input_reads_snap / output_bytes_snap /
     * output_writes_snap; zero the globals so the telemetry reporter
     * starts a fresh interval, matching the drain-clash semantics used
     * for the phase totals.
     */

    wsgi_process_metrics->input_bytes_total = 0;
    wsgi_process_metrics->input_reads_total = 0;
    wsgi_process_metrics->output_bytes_total = 0;
    wsgi_process_metrics->output_writes_total = 0;

    /*
     * Drain the response-class counters. Snapshots were already taken
     * above into status_Nxx_snap; zero the globals so the telemetry
     * reporter starts a fresh interval, matching the drain-clash
     * semantics used for the I/O totals.
     */

    wsgi_process_metrics->status_1xx_count = 0;
    wsgi_process_metrics->status_2xx_count = 0;
    wsgi_process_metrics->status_3xx_count = 0;
    wsgi_process_metrics->status_4xx_count = 0;
    wsgi_process_metrics->status_5xx_count = 0;

    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);

    /*
     * Compute derived values used as inputs to several publishes, plus
     * the per-slot active-thread count, before any Python construction
     * begins so the publish path is purely "encode + dict-set".
     */

    sample_period = (apr_time_sec((double)stop_time) -
                     apr_time_sec((double)wsgi_process_metrics->start_time));

#ifdef HAVE_TIMES
    cpu_user_time =
        ((stop_cpu_user_time - wsgi_process_metrics->start_cpu_user_time) /
         sample_period);
    cpu_system_time =
        ((stop_cpu_system_time - wsgi_process_metrics->start_cpu_system_time) /
         sample_period);
    total_cpu_time = cpu_user_time + cpu_system_time;
#endif

    request_busy_time = stop_request_busy_time -
                        wsgi_process_metrics->start_request_busy_time;
    capacity_utilization = (request_busy_time / sample_period /
                            request_threads_maximum);
    request_count = stop_request_count -
                    wsgi_process_metrics->start_request_count;
    request_throughput = sample_period ? request_count / sample_period : 0;

    /*
     * The locked region above drained the per-interval aggregates so
     * this interval is consumed; advancing the baselines here keeps
     * the next call's rate metrics consistent with its per-phase means
     * even if the publish phase below fails. Done after the rate
     * deltas have been computed against the prior baselines.
     */

    wsgi_process_metrics->start_time = stop_time;
    wsgi_process_metrics->start_request_busy_time = stop_request_busy_time;
    wsgi_process_metrics->start_request_count = stop_request_count;
    wsgi_process_metrics->start_cpu_user_time = stop_cpu_user_time;
    wsgi_process_metrics->start_cpu_system_time = stop_cpu_system_time;

    for (i = 0; i < request_threads_maximum; i++)
    {
        if (slot_completed_snap[i] || slot_current_ms_snap[i])
            request_threads_active++;
    }

    if (interval_requests)
    {
        server_time_avg = server_time_total / interval_requests;
        queue_time_avg = queue_time_total / interval_requests;
        daemon_time_avg = daemon_time_total / interval_requests;
        application_time_avg = application_time_total / interval_requests;
        request_time_avg = request_time_total / interval_requests;
        gil_wait_time_avg = gil_wait_time_total / interval_requests;
        input_read_time_avg = input_read_time_total / interval_requests;
        output_write_time_avg = output_write_time_total / interval_requests;
    }

    if (wsgi_dict_set_long(result, WSGI_INTERNED_STRING(pid), getpid()) < 0)
        goto error;
    if (wsgi_dict_set_double(result, WSGI_INTERNED_STRING(start_time),
                             apr_time_sec(
                                 (double)wsgi_process_metrics->start_time)) < 0)
        goto error;
    if (wsgi_dict_set_double(result, WSGI_INTERNED_STRING(stop_time),
                             apr_time_sec((double)stop_time)) < 0)
        goto error;
    if (wsgi_dict_set_double(result, WSGI_INTERNED_STRING(sample_period),
                             sample_period) < 0)
        goto error;

    if (wsgi_dict_set_double(result,
                             WSGI_INTERNED_STRING(cpu_user_utilization),
                             cpu_user_time) < 0 ||
        wsgi_dict_set_double(result, WSGI_INTERNED_STRING(cpu_user_time),
                             cpu_user_time) < 0 ||
        wsgi_dict_set_double(result,
                             WSGI_INTERNED_STRING(cpu_system_utilization),
                             cpu_system_time) < 0 ||
        wsgi_dict_set_double(result, WSGI_INTERNED_STRING(cpu_system_time),
                             cpu_system_time) < 0 ||
        wsgi_dict_set_double(result,
                             WSGI_INTERNED_STRING(cpu_utilization),
                             total_cpu_time) < 0 ||
        wsgi_dict_set_double(result, WSGI_INTERNED_STRING(cpu_time),
                             total_cpu_time) < 0)
        goto error;

    if (wsgi_dict_set_longlong(result, WSGI_INTERNED_STRING(memory_max_rss),
                               wsgi_get_peak_memory_RSS()) < 0 ||
        wsgi_dict_set_longlong(result, WSGI_INTERNED_STRING(memory_rss),
                               wsgi_get_current_memory_RSS()) < 0)
        goto error;

    if (wsgi_dict_set_long(result,
                           WSGI_INTERNED_STRING(request_threads_maximum),
                           request_threads_maximum) < 0 ||
        wsgi_dict_set_long(result,
                           WSGI_INTERNED_STRING(request_threads_started),
                           wsgi_process_metrics->request_threads) < 0 ||
        wsgi_dict_set_long(result,
                           WSGI_INTERNED_STRING(request_threads_active),
                           request_threads_active) < 0)
        goto error;

    if (wsgi_dict_set_double(result,
                             WSGI_INTERNED_STRING(capacity_utilization),
                             capacity_utilization) < 0 ||
        wsgi_dict_set_ulonglong(result, WSGI_INTERNED_STRING(request_count),
                                request_count) < 0 ||
        wsgi_dict_set_double(result,
                             WSGI_INTERNED_STRING(request_throughput),
                             request_throughput) < 0)
        goto error;

    /*
     * Per-interval HTTP response class totals. status==0 (no
     * start_response call) is folded into status_5xx; out-of-range
     * values are silently dropped, so status_1xx + status_2xx +
     * status_3xx + status_4xx + status_5xx == request_count for the
     * same interval.
     */

    if (wsgi_dict_set_ulonglong(result, WSGI_INTERNED_STRING(status_1xx),
                                status_1xx_snap) < 0 ||
        wsgi_dict_set_ulonglong(result, WSGI_INTERNED_STRING(status_2xx),
                                status_2xx_snap) < 0 ||
        wsgi_dict_set_ulonglong(result, WSGI_INTERNED_STRING(status_3xx),
                                status_3xx_snap) < 0 ||
        wsgi_dict_set_ulonglong(result, WSGI_INTERNED_STRING(status_4xx),
                                status_4xx_snap) < 0 ||
        wsgi_dict_set_ulonglong(result, WSGI_INTERNED_STRING(status_5xx),
                                status_5xx_snap) < 0)
        goto error;

    /*
     * Per-interval I/O byte and op totals across all completed requests
     * in the interval. Mirrors the status counters above; drained from
     * the same locked region.
     */

    if (wsgi_dict_set_ulonglong(result, WSGI_INTERNED_STRING(input_bytes),
                                input_bytes_snap) < 0 ||
        wsgi_dict_set_ulonglong(result, WSGI_INTERNED_STRING(input_reads),
                                input_reads_snap) < 0 ||
        wsgi_dict_set_ulonglong(result, WSGI_INTERNED_STRING(output_bytes),
                                output_bytes_snap) < 0 ||
        wsgi_dict_set_ulonglong(result, WSGI_INTERNED_STRING(output_writes),
                                output_writes_snap) < 0)
        goto error;

    if (wsgi_dict_set_long_list(result,
                                WSGI_INTERNED_STRING(server_time_buckets),
                                server_time_buckets_snap,
                                WSGI_TELEMETRY_BUCKET_COUNT) < 0 ||
        wsgi_dict_set_long_list(result,
                                WSGI_INTERNED_STRING(queue_time_buckets),
                                queue_time_buckets_snap,
                                WSGI_TELEMETRY_BUCKET_COUNT) < 0 ||
        wsgi_dict_set_long_list(result,
                                WSGI_INTERNED_STRING(daemon_time_buckets),
                                daemon_time_buckets_snap,
                                WSGI_TELEMETRY_BUCKET_COUNT) < 0 ||
        wsgi_dict_set_long_list(result,
                                WSGI_INTERNED_STRING(application_time_buckets),
                                application_time_buckets_snap,
                                WSGI_TELEMETRY_BUCKET_COUNT) < 0 ||
        wsgi_dict_set_long_list(result,
                                WSGI_INTERNED_STRING(request_time_buckets),
                                request_time_buckets_snap,
                                WSGI_TELEMETRY_BUCKET_COUNT) < 0 ||
        wsgi_dict_set_long_list(result,
                                WSGI_INTERNED_STRING(gil_wait_time_buckets),
                                gil_wait_time_buckets_snap,
                                WSGI_TELEMETRY_BUCKET_COUNT) < 0 ||
        wsgi_dict_set_long_list(result,
                                WSGI_INTERNED_STRING(input_read_time_buckets),
                                input_read_time_buckets_snap,
                                WSGI_TELEMETRY_BUCKET_COUNT) < 0 ||
        wsgi_dict_set_long_list(result,
                                WSGI_INTERNED_STRING(output_write_time_buckets),
                                output_write_time_buckets_snap,
                                WSGI_TELEMETRY_BUCKET_COUNT) < 0)
        goto error;

    if (wsgi_dict_set_long_list(result,
                                WSGI_INTERNED_STRING(request_threads_buckets),
                                slot_completed_snap,
                                request_threads_maximum) < 0 ||
        wsgi_dict_set_long_list(result,
                                WSGI_INTERNED_STRING(slot_busy_time_us),
                                slot_busy_us_snap,
                                request_threads_maximum) < 0 ||
        wsgi_dict_set_long_list(result,
                                WSGI_INTERNED_STRING(slot_cpu_time_us),
                                slot_cpu_us_snap,
                                request_threads_maximum) < 0 ||
        wsgi_dict_set_long_list(result,
                                WSGI_INTERNED_STRING(slot_current_elapsed_ms),
                                slot_current_ms_snap,
                                request_threads_maximum) < 0 ||
        wsgi_dict_set_long_list(result,
                                WSGI_INTERNED_STRING(slot_max_duration_ms),
                                slot_max_ms_snap,
                                request_threads_maximum) < 0)
        goto error;

    if (wsgi_dict_set_double(result, WSGI_INTERNED_STRING(server_time),
                             server_time_avg) < 0)
        goto error;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
    {
        if (wsgi_dict_set_double(result, WSGI_INTERNED_STRING(queue_time),
                                 queue_time_avg) < 0 ||
            wsgi_dict_set_double(result, WSGI_INTERNED_STRING(daemon_time),
                                 daemon_time_avg) < 0)
            goto error;
    }
    else
#endif
    {
        if (wsgi_dict_set_none(result, WSGI_INTERNED_STRING(queue_time)) < 0 ||
            wsgi_dict_set_none(result, WSGI_INTERNED_STRING(daemon_time)) < 0)
            goto error;
    }

    if (wsgi_dict_set_double(result, WSGI_INTERNED_STRING(application_time),
                             application_time_avg) < 0 ||
        wsgi_dict_set_double(result, WSGI_INTERNED_STRING(request_time),
                             request_time_avg) < 0)
        goto error;

    /*
     * Cross-cutting overlap means. Same per-tick mean shape as the
     * phase means above (total time across completions divided by
     * request count); not addends in the request_time invariant.
     * gil_wait_count is the interval count of recorded GIL re-acquire
     * events, useful for normalising gil_wait_time to a mean wait per
     * acquire.
     */

    if (wsgi_dict_set_double(result, WSGI_INTERNED_STRING(gil_wait_time),
                             gil_wait_time_avg) < 0 ||
        wsgi_dict_set_ulonglong(result, WSGI_INTERNED_STRING(gil_wait_count),
                                gil_wait_count_snap) < 0 ||
        wsgi_dict_set_double(result, WSGI_INTERNED_STRING(input_read_time),
                             input_read_time_avg) < 0 ||
        wsgi_dict_set_double(result, WSGI_INTERNED_STRING(output_write_time),
                             output_write_time_avg) < 0)
        goto error;

    /*
     * Per-phase exact min/max for the interval, in microseconds. None
     * for both keys if the phase did not record any requests this tick
     * (the min accumulator still holds its UINT64_MAX sentinel).
     * queue_time and daemon_time are also None for non-daemon
     * configurations, matching the corresponding mean entries above.
     */

    if (wsgi_dict_set_minmax_or_none(
            result, WSGI_INTERNED_STRING(server_time_min_us),
            WSGI_INTERNED_STRING(server_time_max_us),
            server_time_min_snap_us, server_time_max_snap_us) < 0 ||
        wsgi_dict_set_minmax_or_none(
            result, WSGI_INTERNED_STRING(application_time_min_us),
            WSGI_INTERNED_STRING(application_time_max_us),
            application_time_min_snap_us, application_time_max_snap_us) < 0 ||
        wsgi_dict_set_minmax_or_none(
            result, WSGI_INTERNED_STRING(request_time_min_us),
            WSGI_INTERNED_STRING(request_time_max_us),
            request_time_min_snap_us, request_time_max_snap_us) < 0 ||
        wsgi_dict_set_minmax_or_none(
            result, WSGI_INTERNED_STRING(gil_wait_time_min_us),
            WSGI_INTERNED_STRING(gil_wait_time_max_us),
            gil_wait_time_min_snap_us, gil_wait_time_max_snap_us) < 0 ||
        wsgi_dict_set_minmax_or_none(
            result, WSGI_INTERNED_STRING(input_read_time_min_us),
            WSGI_INTERNED_STRING(input_read_time_max_us),
            input_read_time_min_snap_us, input_read_time_max_snap_us) < 0 ||
        wsgi_dict_set_minmax_or_none(
            result, WSGI_INTERNED_STRING(output_write_time_min_us),
            WSGI_INTERNED_STRING(output_write_time_max_us),
            output_write_time_min_snap_us,
            output_write_time_max_snap_us) < 0)
        goto error;

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process)
    {
        if (wsgi_dict_set_minmax_or_none(
                result, WSGI_INTERNED_STRING(queue_time_min_us),
                WSGI_INTERNED_STRING(queue_time_max_us),
                queue_time_min_snap_us, queue_time_max_snap_us) < 0 ||
            wsgi_dict_set_minmax_or_none(
                result, WSGI_INTERNED_STRING(daemon_time_min_us),
                WSGI_INTERNED_STRING(daemon_time_max_us),
                daemon_time_min_snap_us, daemon_time_max_snap_us) < 0)
            goto error;
    }
    else
#endif
    {
        if (wsgi_dict_set_none(result,
                               WSGI_INTERNED_STRING(queue_time_min_us)) < 0 ||
            wsgi_dict_set_none(result,
                               WSGI_INTERNED_STRING(queue_time_max_us)) < 0 ||
            wsgi_dict_set_none(result,
                               WSGI_INTERNED_STRING(daemon_time_min_us)) < 0 ||
            wsgi_dict_set_none(result,
                               WSGI_INTERNED_STRING(daemon_time_max_us)) < 0)
            goto error;
    }

    Py_DECREF(module);
    return result;

error:
    Py_DECREF(module);
    Py_DECREF(result);
    return NULL;
}

PyMethodDef wsgi_request_metrics_method[] = {
    {"request_metrics", (PyCFunction)wsgi_request_metrics,
     METH_NOARGS, 0},
    {NULL},
};

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_process_metrics_dict(void)
{
    PyObject *module = NULL;
    WSGIModuleState *state = NULL;

    PyObject *result = NULL;
    PyObject *thread_list = NULL;
    WSGIThreadInfo **thread_info = NULL;

    /*
     * External telemetry reporter is the canonical metrics consumer
     * when enabled; suppress the Python API path so consumers can
     * detect the configured mode by checking for None.
     */

    if (wsgi_telemetry_is_enabled())
        Py_RETURN_NONE;

    /*
     * Per-request recording must be opted in via
     * mod_wsgi.start_recording_metrics() before this accessor returns
     * data. Both Python accessors share the same opt-in so an
     * application can branch on a single None check rather than
     * tracking which one happens to enable recording as a side effect.
     */

    if (!wsgi_process_metrics->request_metrics_enabled)
        Py_RETURN_NONE;

    apr_uint64_t request_count = 0;
    double busy_time = 0.0;

    int i;

#ifdef HAVE_TIMES
    struct tms tmsbuf;
#endif

    apr_time_t current_time;
    apr_interval_time_t running_time;

    module = PyImport_ImportModule("mod_wsgi");
    if (!module)
        return NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state)
    {
        Py_DECREF(module);
        return NULL;
    }

    result = PyDict_New();
    if (!result)
    {
        Py_DECREF(module);
        return NULL;
    }

    apr_thread_mutex_lock(wsgi_process_metrics->monitor_lock);
    busy_time = wsgi_utilization_time_locked(0, &request_count);
    apr_thread_mutex_unlock(wsgi_process_metrics->monitor_lock);

    if (wsgi_dict_set_long(result, WSGI_INTERNED_STRING(pid), getpid()) < 0)
        goto error;
    if (wsgi_dict_set_double(result,
                             WSGI_INTERNED_STRING(request_busy_time),
                             busy_time) < 0)
        goto error;
    if (wsgi_dict_set_longlong(result,
                               WSGI_INTERNED_STRING(request_count),
                               (long long)request_count) < 0)
        goto error;
    if (wsgi_dict_set_longlong(result,
                               WSGI_INTERNED_STRING(memory_max_rss),
                               wsgi_get_peak_memory_RSS()) < 0)
        goto error;
    if (wsgi_dict_set_longlong(result,
                               WSGI_INTERNED_STRING(memory_rss),
                               wsgi_get_current_memory_RSS()) < 0)
        goto error;

#ifdef HAVE_TIMES
    times(&tmsbuf);

    if (wsgi_dict_set_double(result, WSGI_INTERNED_STRING(cpu_user_time),
                             tmsbuf.tms_utime / wsgi_process_metrics->tick_hz) < 0)
        goto error;
    if (wsgi_dict_set_double(result, WSGI_INTERNED_STRING(cpu_system_time),
                             tmsbuf.tms_stime / wsgi_process_metrics->tick_hz) < 0)
        goto error;
    if (wsgi_dict_set_double(result, WSGI_INTERNED_STRING(cpu_time),
                             (tmsbuf.tms_utime + tmsbuf.tms_stime) /
                                 wsgi_process_metrics->tick_hz) < 0)
        goto error;
#endif

    if (wsgi_dict_set_double(result, WSGI_INTERNED_STRING(restart_time),
                             apr_time_sec(
                                 (double)wsgi_process_metrics->process_start_us)) < 0)
        goto error;

    current_time = apr_time_now();
    if (wsgi_dict_set_double(result, WSGI_INTERNED_STRING(current_time),
                             apr_time_sec((double)current_time)) < 0)
        goto error;

    running_time = apr_time_sec((double)current_time -
                                wsgi_process_metrics->process_start_us);
    if (wsgi_dict_set_longlong(result, WSGI_INTERNED_STRING(running_time),
                               (long long)running_time) < 0)
        goto error;

    if (wsgi_dict_set_long(result, WSGI_INTERNED_STRING(request_threads),
                           wsgi_process_metrics->request_threads) < 0)
        goto error;
    if (wsgi_dict_set_long(result, WSGI_INTERNED_STRING(active_requests),
                           wsgi_process_metrics->active_requests) < 0)
        goto error;

    thread_list = PyList_New(0);
    if (!thread_list)
        goto error;

    thread_info = (WSGIThreadInfo **)wsgi_process_metrics->thread_details->elts;

    for (i = 0; i < wsgi_process_metrics->thread_details->nelts; i++)
    {
        PyObject *entry;

        if (!thread_info[i]->request_thread)
            continue;

        entry = PyDict_New();
        if (!entry)
            goto error;

        if (wsgi_dict_set_long(entry, WSGI_INTERNED_STRING(thread_id),
                               thread_info[i]->thread_id) < 0 ||
            wsgi_dict_set_longlong(entry, WSGI_INTERNED_STRING(request_count),
                                   thread_info[i]->request_count) < 0)
        {
            Py_DECREF(entry);
            goto error;
        }

        if (PyList_Append(thread_list, entry) < 0)
        {
            Py_DECREF(entry);
            goto error;
        }
        Py_DECREF(entry);
    }

    if (PyDict_SetItem(result, WSGI_INTERNED_STRING(threads),
                       thread_list) < 0)
        goto error;
    Py_DECREF(thread_list);

    Py_DECREF(module);
    return result;

error:
    Py_DECREF(module);
    Py_XDECREF(thread_list);
    Py_DECREF(result);
    return NULL;
}

PyMethodDef wsgi_process_metrics_method[] = {
    {"process_metrics", (PyCFunction)wsgi_process_metrics_dict,
     METH_NOARGS, 0},
    {NULL},
};

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_server_metrics(void)
{
    PyObject *module = NULL;
    WSGIModuleState *state = NULL;

    PyObject *scoreboard_dict = NULL;
    PyObject *process_list = NULL;
    PyObject *process_dict = NULL;
    PyObject *worker_list = NULL;
    PyObject *worker_dict = NULL;

    apr_time_t current_time;
    apr_interval_time_t running_time;

    global_score *gs_record;
    worker_score *ws_record;
    process_score *ps_record;

    int j, i;

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

    module = PyImport_ImportModule("mod_wsgi");
    if (!module)
        return NULL;

    state = (WSGIModuleState *)PyModule_GetState(module);
    if (!state)
    {
        Py_DECREF(module);
        return NULL;
    }

    scoreboard_dict = PyDict_New();
    if (!scoreboard_dict)
    {
        Py_DECREF(module);
        return NULL;
    }

    current_time = apr_time_now();
    running_time = apr_time_sec((double)current_time -
                                ap_scoreboard_image->global->restart_time);

    if (wsgi_dict_set_long(scoreboard_dict,
                           WSGI_INTERNED_STRING(server_limit),
                           gs_record->server_limit) < 0 ||
        wsgi_dict_set_long(scoreboard_dict,
                           WSGI_INTERNED_STRING(thread_limit),
                           gs_record->thread_limit) < 0 ||
        wsgi_dict_set_long(scoreboard_dict,
                           WSGI_INTERNED_STRING(running_generation),
                           gs_record->running_generation) < 0 ||
        wsgi_dict_set_double(scoreboard_dict,
                             WSGI_INTERNED_STRING(restart_time),
                             apr_time_sec(
                                 (double)gs_record->restart_time)) < 0 ||
        wsgi_dict_set_double(scoreboard_dict,
                             WSGI_INTERNED_STRING(current_time),
                             apr_time_sec((double)current_time)) < 0 ||
        wsgi_dict_set_longlong(scoreboard_dict,
                               WSGI_INTERNED_STRING(running_time),
                               (long long)running_time) < 0)
        goto error;

    process_list = PyList_New(0);
    if (!process_list)
        goto error;

    for (i = 0; i < gs_record->server_limit; ++i)
    {
        ps_record = ap_get_scoreboard_process(i);

        process_dict = PyDict_New();
        if (!process_dict)
            goto error;

        if (wsgi_dict_set_long(process_dict,
                               WSGI_INTERNED_STRING(process_num), i) < 0 ||
            wsgi_dict_set_long(process_dict, WSGI_INTERNED_STRING(pid),
                               ps_record->pid) < 0 ||
            wsgi_dict_set_long(process_dict,
                               WSGI_INTERNED_STRING(generation),
                               ps_record->generation) < 0 ||
            wsgi_dict_set_bool(process_dict,
                               WSGI_INTERNED_STRING(quiescing),
                               ps_record->quiescing) < 0)
            goto error;

        worker_list = PyList_New(0);
        if (!worker_list)
            goto error;

        for (j = 0; j < gs_record->thread_limit; ++j)
        {
            ws_record = ap_get_scoreboard_worker_from_indexes(i, j);

            worker_dict = PyDict_New();
            if (!worker_dict)
                goto error;

            if (wsgi_dict_set_long(worker_dict,
                                   WSGI_INTERNED_STRING(thread_num),
                                   ws_record->thread_num) < 0 ||
                wsgi_dict_set_long(worker_dict,
                                   WSGI_INTERNED_STRING(generation),
                                   ws_record->generation) < 0 ||
                wsgi_dict_set_borrowed(worker_dict,
                                       WSGI_INTERNED_STRING(status),
                                       state->status_flags[ws_record->status]) < 0 ||
                wsgi_dict_set_long(worker_dict,
                                   WSGI_INTERNED_STRING(access_count),
                                   ws_record->access_count) < 0 ||
                wsgi_dict_set_ulonglong(worker_dict,
                                        WSGI_INTERNED_STRING(bytes_served),
                                        ws_record->bytes_served) < 0 ||
                wsgi_dict_set_double(worker_dict,
                                     WSGI_INTERNED_STRING(start_time),
                                     apr_time_sec(
                                         (double)ws_record->start_time)) < 0 ||
                wsgi_dict_set_double(worker_dict,
                                     WSGI_INTERNED_STRING(stop_time),
                                     apr_time_sec(
                                         (double)ws_record->stop_time)) < 0 ||
                wsgi_dict_set_double(worker_dict,
                                     WSGI_INTERNED_STRING(last_used),
                                     apr_time_sec(
                                         (double)ws_record->last_used)) < 0 ||
                wsgi_dict_set_latin1(worker_dict,
                                     WSGI_INTERNED_STRING(client),
                                     ws_record->client) < 0 ||
                wsgi_dict_set_latin1(worker_dict,
                                     WSGI_INTERNED_STRING(request),
                                     ws_record->request) < 0 ||
                wsgi_dict_set_latin1(worker_dict,
                                     WSGI_INTERNED_STRING(vhost),
                                     ws_record->vhost) < 0)
                goto error;

            if (PyList_Append(worker_list, worker_dict) < 0)
                goto error;
            Py_CLEAR(worker_dict);
        }

        if (PyDict_SetItem(process_dict, WSGI_INTERNED_STRING(workers),
                           worker_list) < 0)
            goto error;
        Py_CLEAR(worker_list);

        if (PyList_Append(process_list, process_dict) < 0)
            goto error;
        Py_CLEAR(process_dict);
    }

    if (PyDict_SetItem(scoreboard_dict, WSGI_INTERNED_STRING(processes),
                       process_list) < 0)
        goto error;
    Py_DECREF(process_list);

    Py_DECREF(module);
    return scoreboard_dict;

error:
    Py_DECREF(module);
    Py_XDECREF(worker_dict);
    Py_XDECREF(worker_list);
    Py_XDECREF(process_dict);
    Py_XDECREF(process_list);
    Py_DECREF(scoreboard_dict);
    return NULL;
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

        if (!list)
        {
            Py_DECREF(module);
            PyErr_SetString(PyExc_RuntimeError,
                            "mod_wsgi event_callbacks not initialised");
            return NULL;
        }

        if (PyList_Append(list, callback) < 0)
        {
            wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                                 "Failed to register event subscriber");
            Py_DECREF(module);
            return NULL;
        }

        Py_DECREF(module);
    }
    else
        return NULL;

    /* Return the callback so the function can be used as a decorator. */
    Py_INCREF(callback);
    return callback;
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

        if (!list)
        {
            Py_DECREF(module);
            PyErr_SetString(PyExc_RuntimeError,
                            "mod_wsgi shutdown_callbacks not initialised");
            return NULL;
        }

        if (PyList_Append(list, callback) < 0)
        {
            wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                                 "Failed to register shutdown subscriber");
            Py_DECREF(module);
            return NULL;
        }

        Py_DECREF(module);
    }
    else
        return NULL;

    /* Return the callback so the function can be used as a decorator. */
    Py_INCREF(callback);
    return callback;
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

        if (list && PyList_Check(list))
            result = PyList_Size(list);

        Py_DECREF(module);

        return result;
    }
    else
    {
        /*
         * Callers treat the return as a boolean. Clear the import
         * error so it doesn't leak into the next Python C API call.
         */

        PyErr_Clear();
        return 0;
    }
}

void wsgi_call_callbacks(const char *name, PyObject *callbacks,
                         PyObject *event)
{
    PyObject *snapshot = NULL;
    Py_ssize_t n;
    Py_ssize_t i;

    /*
     * Snapshot the callback list before dispatch so a callback that
     * subscribes or unsubscribes mid-event cannot perturb the
     * iteration. Without the snapshot, a callback that removes an
     * earlier entry would shift the tail down and the loop's index
     * stepping would skip the next pending callback; a callback that
     * appends would have the new entry invoked for the current event,
     * which most pub/sub contracts disallow. PyList_GetSlice produces
     * a new list with fresh strong refs, so the source list can be
     * freely mutated during dispatch.
     */

    snapshot = PyList_GetSlice(callbacks, 0, PyList_Size(callbacks));
    if (!snapshot)
    {
        wsgi_log_python_event_callback_error(name);
        return;
    }

    n = PyList_GET_SIZE(snapshot);

    for (i = 0; i < n; i++)
    {
        PyObject *callback = NULL;

        PyObject *res = NULL;
        PyObject *args = NULL;

        callback = PyList_GET_ITEM(snapshot, i);

        Py_INCREF(callback);

        args = Py_BuildValue("(s)", name);
        if (!args)
        {
            wsgi_set_python_exception_from_cause(PyExc_RuntimeError,
                                                 "Failed to build callback args tuple for event %s",
                                                 name);
            wsgi_log_python_event_callback_error(name);
            Py_DECREF(callback);
            continue;
        }

        /*
         * The event dict is passed as the kwargs argument, so
         * subscribers receive the event name positionally and the
         * event payload as keyword-only parameters. Subscribers should
         * declare keyword-only parameters for the keys they care about
         * and use **kwargs to absorb the rest, e.g.
         * def cb(name, *, status_code, **kwargs).
         */

        res = PyObject_Call(callback, args, event);

        if (!res)
            wsgi_log_python_event_callback_error(name);
        else if (PyDict_Check(res))
        {
            /*
             * A subscriber that returned a dict is asking us to merge
             * its keys into the shared event before the next callback
             * runs. Surface and clear any failure so it doesn't leak
             * into the next iteration's PyObject_Call.
             */

            if (PyDict_Update(event, res) < 0)
                wsgi_log_python_event_callback_error(name);
        }

        Py_XDECREF(res);

        Py_DECREF(callback);
        Py_DECREF(args);
    }

    Py_DECREF(snapshot);
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
        wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server, WSGI_APLOGNO(0113) "Unable to import mod_wsgi when publishing "
                                                                            "events.");

        PyErr_Clear();

        return;
    }

    if (!event_callbacks || !shutdown_callbacks)
    {
        wsgi_log_error_locked(APLOG_ERR, 0, wsgi_server, WSGI_APLOGNO(0114) "Unable to find event subscribers.");

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
