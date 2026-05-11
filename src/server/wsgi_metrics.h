#ifndef WSGI_METRICS_H
#define WSGI_METRICS_H

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
#include "wsgi_telemetry.h"

/* ------------------------------------------------------------------------- */

/* Per-phase aggregator: total time, log-spaced histogram, and exact
 * min/max for one interval. Eight instances drive the per-tick
 * aggregation in wsgi_metrics.c (server / queue / daemon / application
 * / request phase totals plus the cross-cutting gil_wait / input_read /
 * output_write totals). min_us == UINT64_MAX is the "no samples this
 * interval" sentinel; encoders skip emission when the sentinel is in
 * place. Caller controls locking. */
typedef struct
{
    double total;
    int buckets[WSGI_TELEMETRY_BUCKET_COUNT];
    apr_uint64_t min_us;
    apr_uint64_t max_us;
} WSGIPhaseAggregate;

/* Process-wide metrics state. One instance per Apache child process
 * (embedded mode) or per daemon process (daemon mode), allocated from
 * the process pool at child init by wsgi_process_metrics_init. Holds
 * the synchronisation primitive, process identity, lifetime aggregates,
 * per-tick interval aggregators, and the slow-request tracking ring.
 *
 * monitor_lock is the coarse mutex covering the per-tick aggregators,
 * lifetime counters, the per-thread slot arrays, and the slow-completion
 * ring. It is held across every recorder write and every snapshot read.
 *
 * total_requests, active_requests, thread_utilization and
 * utilization_last form the request-busy-time integral and the gauge
 * pair, all read-modify-write under monitor_lock by
 * wsgi_utilization_time_locked.
 *
 * The per-tick aggregators (sample_requests through status_5xx_count)
 * and the WSGIPhaseAggregate phase blocks are accumulated by
 * wsgi_record_request_times under monitor_lock and drained by either
 * wsgi_metrics_snapshot or the wsgi_request_metrics Python accessor.
 * request_metrics_enabled gates accumulation; flipped on at first
 * snapshot/accessor call.
 *
 * The slow_completed_ring* fields back the lazy ring buffer of
 * completed slow records that the reporter/accessor drains via
 * wsgi_metrics_pop_slow_completed. The matching slow-request
 * threshold and metrics-options bitmask live as config-time globals
 * (wsgi_slow_threshold_us, wsgi_metrics_options) since they are set
 * by directive handlers before this struct is allocated.
 *
 * total_threads, request_threads, thread_key and thread_details form
 * the per-process thread directory. wsgi_thread_info uses thread_key
 * to look up (or lazily create) the per-thread WSGIThreadInfo block,
 * pushing newly created entries onto thread_details under monitor_lock
 * so the snapshot/accessor paths can iterate the directory safely. */
typedef struct
{
    apr_time_t process_start_us;
    apr_thread_mutex_t *monitor_lock;

    apr_uint64_t total_requests;
    int active_requests;
    double thread_utilization;
    apr_time_t utilization_last;

    int request_metrics_enabled;
    apr_uint64_t sample_requests;

    WSGIPhaseAggregate server_time;
    WSGIPhaseAggregate queue_time;
    WSGIPhaseAggregate daemon_time;
    WSGIPhaseAggregate application_time;
    WSGIPhaseAggregate request_time;
    WSGIPhaseAggregate gil_wait_time;
    WSGIPhaseAggregate input_read_time;
    WSGIPhaseAggregate output_write_time;

    apr_uint64_t gil_wait_count_total;
    apr_uint64_t input_bytes_total;
    apr_uint64_t input_reads_total;
    apr_uint64_t output_bytes_total;
    apr_uint64_t output_writes_total;
    apr_uint64_t status_1xx_count;
    apr_uint64_t status_2xx_count;
    apr_uint64_t status_3xx_count;
    apr_uint64_t status_4xx_count;
    apr_uint64_t status_5xx_count;

    wsgi_slow_request_t *slow_completed_ring;
    int slow_completed_ring_size;
    int slow_completed_ring_head;
    int slow_completed_ring_count;

    int total_threads;
    int request_threads;
    apr_threadkey_t *thread_key;
    apr_array_header_t *thread_details;
} WSGIProcessMetrics;

extern WSGIProcessMetrics *wsgi_process_metrics;

/* Slow-request threshold (microseconds; 0 disables the feature). Set
 * once from the WSGISlowRequests directive at config time, before
 * wsgi_process_metrics_init runs at child init, which is why it lives
 * as a separate global rather than as a field on WSGIProcessMetrics. */
extern apr_time_t wsgi_slow_threshold_us;

/* Allocate the WSGIProcessMetrics instance and create its monitor lock
 * from the supplied pool. Called once per child / daemon process at
 * child init, before any other metrics-touching code runs. */
extern void wsgi_process_metrics_init(apr_pool_t *pool);

extern PyMethodDef wsgi_request_metrics_method[];

extern PyMethodDef wsgi_process_metrics_method[];

extern PyMethodDef wsgi_start_recording_metrics_method[];

/*
 * Populate the metrics-owned fields of `module`'s WSGIModuleState
 * (the wsgi_id_* interned key strings and the scoreboard
 * status_flags array). Called from the embedded mod_wsgi module's
 * exec slot. Returns 0 on success, -1 on failure with Python
 * exception set.
 */

extern int wsgi_metrics_init_state(PyObject *module);

extern WSGIThreadInfo *wsgi_start_request(request_rec *r);
extern void wsgi_end_request(void);

extern void wsgi_record_request_times(apr_time_t request_start,
                                      apr_time_t queue_start, apr_time_t daemon_start,
                                      apr_time_t application_start, apr_time_t application_finish,
                                      apr_off_t input_bytes, apr_off_t input_reads,
                                      apr_off_t output_bytes, apr_off_t output_writes,
                                      apr_time_t input_read_us,
                                      apr_time_t output_write_us,
                                      int status);

/* Records the wall-clock instant the WSGI callable began executing onto
 * the worker thread's active slot. Called from the adapter immediately
 * after self->start_time is captured, so the active-record snapshot can
 * compute server / queue / daemon / application phase durations even
 * while the callable is still running. The companion application_finish
 * value is captured by wsgi_record_request_times at end-of-request. */
extern void wsgi_record_application_start(apr_time_t application_start);

extern int wsgi_metrics_snapshot(wsgi_telemetry_sample_t *out);

/* Seed the C-native snapshot baselines and turn on per-request metric
 * accounting. Called from wsgi_telemetry_start_reporter in the daemon
 * main thread before any worker has had a chance to serve a request,
 * so wsgi_record_request_times sees enabled=1 on its first invocation
 * and request data is captured from t=0 onwards rather than only after
 * the reporter's first periodic tick fires (which under default 1s
 * interval would silently drop everything served in the startup
 * window). Idempotent. */
extern void wsgi_metrics_telemetry_init(void);

/* Pop one completed slow-request record from the finalize ring. Returns 1
 * if one was copied into *out, 0 if the ring was empty. Takes
 * the monitor lock internally. */
extern int wsgi_metrics_pop_slow_completed(wsgi_slow_request_t *out);

/* Snapshot up to out_cap currently-active slots whose elapsed time is at
 * least threshold_us. now_us is the caller's current timestamp (so a
 * consistent "elapsed" can be computed across all slots). Returns the
 * number of records copied. Takes the monitor lock internally. */
extern int wsgi_metrics_snapshot_slow_active(wsgi_slow_request_t *out,
                                             int out_cap,
                                             apr_time_t now_us,
                                             apr_time_t threshold_us);

extern void wsgi_telemetry_start_reporter(apr_pool_t *pool);
extern void wsgi_telemetry_stop_reporter(void);

/* Graceful shutdown sequence. emit_process_stopping fires the chart-
 * marker datagram at decision time (before drain); pause_reporter
 * joins the reporter thread without closing the socket; then
 * emit_final_tick flushes the partial-window accumulators, emits
 * STOPPED with the lifetime summary, and closes the socket. Pass NULL
 * for reason when no shutdown reason is available.
 *
 * emit_process_stopped is the idempotent STOPPED emitter that
 * emit_final_tick uses internally. It is also called directly from
 * the reaper thread before forced exit so STOPPED still arrives when
 * worker drain exceeds shutdown_timeout. The first caller (graceful
 * path or reaper path) wins; subsequent calls are no-ops. graceful
 * is non-zero if drain completed cleanly. */
extern void wsgi_telemetry_emit_process_stopping(const char *reason);
extern void wsgi_telemetry_pause_reporter(void);
extern void wsgi_telemetry_emit_final_tick(const char *reason);
extern void wsgi_telemetry_emit_process_stopped(const char *reason,
                                                int graceful);

extern PyMethodDef wsgi_server_metrics_method[];

extern long wsgi_event_subscribers(void);
extern void wsgi_publish_event(const char *name, PyObject *event);

extern PyMethodDef wsgi_subscribe_events_method[];
extern PyMethodDef wsgi_subscribe_shutdown_method[];

extern PyMethodDef wsgi_request_data_method[];

/* ------------------------------------------------------------------------- */

/* Reset the per-thread GIL-wait staging accumulator. Called at the top of
 * wsgi_execute_script so any previous request's leftover staged value is
 * discarded before the new request's daemon-phase contributions begin. */
extern void wsgi_gil_wait_reset(void);

/* Record one GIL re-acquire wait. Routed by WSGI_END_ALLOW_THREADS at every
 * instrumented release/acquire site. Writes into the per-request active
 * slot when one is in_use; otherwise stages on WSGIThreadInfo (drained at
 * slot claim). Cheap — APR threadkey lookup plus uint64 add, no locking. */
extern void wsgi_gil_wait_record(apr_uint64_t wait_us);

/* Read the calling thread's running per-request GIL-wait totals. Reads
 * from the active slot when one is in_use, otherwise from the per-thread
 * staging accumulator. Either pointer may be NULL. Intended for the
 * request_finished event publisher, which runs before the slot is
 * drained by wsgi_record_request_times. */
extern void wsgi_gil_wait_current(apr_uint64_t *wait_us,
                                  apr_uint64_t *count);

/* Drop-in replacements for Py_BEGIN_ALLOW_THREADS / Py_END_ALLOW_THREADS
 * that additionally measure the time spent waiting to re-acquire the GIL
 * in the END expansion. The user's released-region code between BEGIN and
 * END is unchanged. Use these at every site on the per-request hot path
 * — the initial interp acquire is timed inline rather than via these
 * macros because that path has no symmetric BEGIN/END pair. */
#define WSGI_BEGIN_ALLOW_THREADS \
    {                            \
        PyThreadState *_wsgi_save = PyEval_SaveThread();
#define WSGI_END_ALLOW_THREADS                                       \
    apr_time_t _wsgi_t1 = apr_time_now();                            \
    PyEval_RestoreThread(_wsgi_save);                                \
    wsgi_gil_wait_record((apr_uint64_t)(apr_time_now() - _wsgi_t1)); \
    }

#endif

/* vi: set sw=4 expandtab : */
