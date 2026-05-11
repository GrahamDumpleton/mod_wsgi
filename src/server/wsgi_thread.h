#ifndef WSGI_THREAD_H
#define WSGI_THREAD_H

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

/* ------------------------------------------------------------------------- */

/* Per-request transient state for the worker thread that is currently
 * (or most recently was) servicing a request. Lives as the `slot` field
 * of WSGIThreadInfo. in_use is set at wsgi_start_request and cleared at
 * wsgi_end_request; everything else is meaningful only while in_use is
 * non-zero. The reporter thread reads these fields under the monitor
 * lock to publish the per-thread snapshot wire arrays (slot_busy_time_us
 * etc.) and to populate slow-record snapshots without taking the GIL. */
typedef struct
{
    int in_use;
    request_rec *r; /* valid only while in_use; lives in r->pool */
    apr_time_t start_us;

    /* Per-request baselines captured at wsgi_start_request, consumed by
     * wsgi_end_request and the reporter to compute per-slot interval
     * accumulators. busy_since_us equals start_us at request start and
     * is reset to now() at each tick while the slot stays in use, so
     * long-running requests contribute to every tick they span (not
     * just the tick they complete in). cpu_valid is 0 if the start-time
     * CPU capture failed, so end_request knows not to fold a bogus
     * (thread-lifetime-long) delta. */
    apr_time_t busy_since_us;
    int cpu_valid;
    double cpu_user_at_start;
    double cpu_system_at_start;

    /* Per-phase timing baselines, used by the slow-record snapshot to
     * compute server / queue / daemon / application durations. Captured
     * at slot claim from WSGIRequestConfig (request_start_us,
     * queue_start_us, daemon_start_us; the latter two are 0 in embedded
     * mode), via wsgi_record_application_start (application_start_us,
     * set by the adapter once the WSGI callable is about to run), and
     * via wsgi_record_request_times (application_finish_us, set at end-
     * of-request). Active-record snapshots use these plus the snapshot's
     * `now` to compute partial phase durations. */
    apr_time_t request_start_us;
    apr_time_t queue_start_us;
    apr_time_t daemon_start_us;
    apr_time_t application_start_us;
    apr_time_t application_finish_us;

    /* In-flight request count (= active_requests including this one)
     * at slot claim. Snapshotted into the slow record at completion
     * alongside the live active_requests value to give the "saturation
     * when this request was running" picture. */
    uint64_t active_at_start;

    /* Per-request I/O counters, written by wsgi_record_request_times
     * once the adapter knows the final read/write totals and consumed
     * by wsgi_end_request when snapshotting a slow-completion record.
     * Zero while no request is in flight or the request hasn't yet
     * reached its end-of-request hook. Active-record snapshots in
     * wsgi_metrics_snapshot_slow_active() report these as the partial
     * I/O so far (zero until end-of-request). */
    apr_off_t io_input_bytes;
    apr_off_t io_input_reads;
    apr_off_t io_output_bytes;
    apr_off_t io_output_writes;

    /* Per-request I/O timing totals, in microseconds. Same end-of-
     * request write / wsgi_end_request read pattern as the byte/count
     * counters above, surfaced on slow records as the input/output
     * overlap measure. Active-record snapshots see zero until the
     * adapter publishes them at completion: same caveat as the byte
     * totals. */
    apr_time_t io_input_read_us;
    apr_time_t io_output_write_us;

    /* Final HTTP response status (e.g. 200, 404, 500), stashed by
     * wsgi_record_request_times from AdapterObject.status. Read by
     * wsgi_end_request when building a slow-completion record. Zero
     * while no request is in flight or the WSGI app hasn't yet called
     * start_response: active-record snapshots leave this at zero,
     * matching the "0 = not yet known" convention. */
    int last_status;

    /* Per-request GIL-wait pressure indicator. Sum of wait time across
     * every instrumented Py_END_ALLOW_THREADS-equivalent re-acquire
     * site reached during the request, plus the initial sub-interp GIL
     * acquire in wsgi_acquire_interpreter. Count is the number of such
     * events. The metric is partial: it cannot see waits inside the
     * application's own C extensions, so it surfaces as a pressure
     * indicator (trend over time) rather than a phase attribution. */
    apr_uint64_t gil_wait_us;
    apr_uint64_t gil_wait_count;
} WSGIActiveSlot;

/* Per-tick capacity accumulators. Lives as the `tick_stats` field of
 * WSGIThreadInfo. Drained and reset at each tick (by either the
 * telemetry reporter or the Python accessor; whichever fires first,
 * the remaining reader gets an empty interval). */
typedef struct
{
    apr_time_t busy_time_us;    /* folded busy time this interval */
    apr_time_t cpu_time_us;     /* folded CPU time this interval */
    uint32_t completed;         /* completed-request count this interval */
    apr_time_t max_duration_us; /* longest single request this interval */
} WSGITickStats;

typedef struct
{
    int thread_id;
    int request_thread;
    apr_int64_t request_count;
    PyObject *request_id;
    PyObject *request_data;
    PyObject *log_buffer;

    /* Application group name of the interpreter this thread is currently
     * servicing a request in. Set by wsgi_execute_script just after
     * wsgi_acquire_interpreter succeeds, cleared just before
     * wsgi_release_interpreter. NULL when the thread is not currently
     * inside a request handler. The string is owned by Apache config
     * memory and lives for process lifetime, so no copy is needed.
     *
     * In daemon mode this is read by the monitor thread (via the
     * back-pointer on WSGIDaemonThread) to discover which sub-interpreter
     * to acquire when injecting a RequestTimeout exception into the
     * worker. */
    const char *current_application_group;

    /* Staging accumulator for GIL wait time observed at instrumented
     * Py_BEGIN/END_ALLOW_THREADS sites that fire before the per-request
     * active slot has been claimed (initial wsgi_acquire_interpreter,
     * module-lock acquire, "200 Continue" brigade send). Drained into
     * the slot in wsgi_start_request and reset at the top of
     * wsgi_execute_script. After slot claim the macros write directly
     * into the slot, so this stays at zero for the rest of the request. */
    apr_uint64_t staged_gil_wait_us;
    apr_uint64_t staged_gil_wait_count;

    WSGIActiveSlot slot;
    WSGITickStats tick_stats;
} WSGIThreadInfo;

extern WSGIThreadInfo *wsgi_thread_info(int create, int request);

typedef struct
{
    double user_time;
    double system_time;
} WSGIThreadCPUUsage;

extern int wsgi_thread_cpu_usage(WSGIThreadCPUUsage *usage);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
