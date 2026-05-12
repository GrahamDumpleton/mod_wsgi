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

/*
 * Per-phase aggregator: total time, log-spaced histogram, and exact
 * min/max for one interval. Eight instances drive the per-tick
 * aggregation on WSGIProcessMetrics (server / queue / daemon /
 * application / request phase totals plus the cross-cutting gil_wait /
 * input_read / output_write totals). min_us == UINT64_MAX is the "no
 * samples this interval" sentinel; encoders skip emission when the
 * sentinel is in place. Caller controls locking.
 */

typedef struct
{
    double total;
    int buckets[WSGI_TELEMETRY_BUCKET_COUNT];
    apr_uint64_t min_us;
    apr_uint64_t max_us;
} WSGIPhaseAggregate;

/* ------------------------------------------------------------------------- */

/*
 * Process-wide metrics state. One instance per Apache child process
 * (embedded mode) or per daemon process (daemon mode), allocated from
 * the process pool at child init by wsgi_process_metrics_init.
 *
 * monitor_lock is the coarse mutex covering every mutable field below.
 * Recorder writes and reader drains alike acquire it; callers do not
 * take it themselves except via the *_locked helpers.
 */

typedef struct
{
    /*
     * Wall-clock instant the child / daemon process began serving
     * requests, stamped immediately after wsgi_process_metrics_init by
     * the child-init hook. Basis for running_time on the process_metrics
     * accessor and for the STARTED datagram timestamp / uptime on the
     * telemetry reporter.
     */

    apr_time_t process_start_us;

    /*
     * Per-process constants captured once at child init.
     * request_threads_maximum is the MaxRequestWorkers /
     * WSGIDaemonProcess threads= value (queried from the daemon group
     * or the active MPM); tick_hz is sysconf(_SC_CLK_TCK) for converting
     * times(2) tick counts to seconds.
     */

    int request_threads_maximum;
    double tick_hz;

    /*
     * Coarse mutex serialising every mutable field below; see the
     * struct lead-in for the acquisition contract.
     */

    apr_thread_mutex_t *monitor_lock;

    /*
     * Gates per-tick accumulation in wsgi_record_request_times. Flipped
     * on by wsgi_metrics_telemetry_init (external reporter) or
     * wsgi_start_recording_metrics (Python accessor opt-in).
     */

    int request_metrics_enabled;

    /*
     * Per-tick request count, incremented by wsgi_record_request_times
     * and reset to zero when the active reader drains. Logically part
     * of the per-tick aggregator block below.
     */

    apr_uint64_t sample_requests;

    /*
     * Per-reader baselines (last-observed snapshot of the lifetime
     * counters). Seeded by wsgi_metrics_telemetry_init or
     * wsgi_start_recording_metrics; advanced on each call to whichever
     * reader is live (wsgi_metrics_snapshot or wsgi_request_metrics).
     * The two readers are mutually exclusive at runtime (when external
     * reporting is enabled the Python accessors return None), so a
     * single shared baseline set serves both. start_time == 0.0 is the
     * not-yet-seeded sentinel.
     */

    double start_time;
    double start_cpu_user_time;
    double start_cpu_system_time;
    double start_request_busy_time;
    apr_uint64_t start_request_count;

    /*
     * Lifetime request totals plus the request-busy-time integral and
     * its gauge pair, maintained by wsgi_utilization_time_locked.
     */

    apr_uint64_t total_requests;
    int active_requests;
    double thread_utilization;
    apr_time_t utilization_last;

    /*
     * Per-tick phase aggregators and scalar totals. Accumulated by
     * wsgi_record_request_times and drained by either
     * wsgi_metrics_snapshot or the wsgi_request_metrics Python
     * accessor.
     */

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

    /*
     * Lazy ring buffer of completed slow records, drained by the
     * reporter or accessor via wsgi_metrics_pop_slow_completed. The
     * matching slow-request threshold and metrics-options bitmask live
     * as config-time globals (wsgi_slow_threshold_us, wsgi_metrics_options)
     * since they are set by directive handlers before this struct is
     * allocated.
     */

    wsgi_slow_request_t *slow_completed_ring;
    int slow_completed_ring_size;
    int slow_completed_ring_head;
    int slow_completed_ring_count;

    /*
     * Per-process thread directory. wsgi_thread_info uses thread_key to
     * look up (or lazily create) the per-thread WSGIThreadInfo block,
     * pushing newly created entries onto thread_details so the
     * snapshot/accessor paths can iterate the directory safely.
     */

    int total_threads;
    int request_threads;
    apr_threadkey_t *thread_key;
    apr_array_header_t *thread_details;
} WSGIProcessMetrics;

extern WSGIProcessMetrics *wsgi_process_metrics;

/*
 * Slow-request threshold (microseconds; 0 disables the feature). Set
 * once from the WSGISlowRequests directive at config time, before
 * wsgi_process_metrics_init runs at child init.
 */

extern apr_time_t wsgi_slow_threshold_us;

/*
 * Allocate the WSGIProcessMetrics instance and create its monitor lock
 * from the supplied pool. Called once per child / daemon process at
 * child init, before any other metrics-touching code runs.
 */

extern void wsgi_process_metrics_init(apr_pool_t *pool);

/* ------------------------------------------------------------------------- */

/*
 * Per-request hooks driven from the worker hot path in wsgi_execute.c.
 * wsgi_start_request initialises the per-thread WSGIThreadInfo block at
 * the top of a request and returns it; wsgi_end_request clears the
 * active slot at end of request, snapshotting a slow-completion record
 * into the ring if the request crossed wsgi_slow_threshold_us.
 *
 * wsgi_record_application_start stamps the WSGI-callable-began instant
 * onto the active slot from the adapter immediately after
 * self->start_time is captured, so active-record snapshots can compute
 * the application phase duration even while the callable is still
 * running. The companion application_finish value is captured by
 * wsgi_record_request_times at end of request along with the final
 * per-phase totals, I/O counters and HTTP status, all folded into the
 * per-tick aggregators.
 */

extern WSGIThreadInfo *wsgi_start_request(request_rec *r);
extern void wsgi_end_request(void);

extern void wsgi_record_application_start(apr_time_t application_start);

extern void wsgi_record_request_times(apr_time_t request_start,
                                      apr_time_t queue_start, apr_time_t daemon_start,
                                      apr_time_t application_start, apr_time_t application_finish,
                                      apr_off_t input_bytes, apr_off_t input_reads,
                                      apr_off_t output_bytes, apr_off_t output_writes,
                                      apr_time_t input_read_us,
                                      apr_time_t output_write_us,
                                      int status);

/* ------------------------------------------------------------------------- */

/*
 * External telemetry reader. wsgi_metrics_telemetry_init seeds the
 * snapshot baselines and turns on per-request accounting; called from
 * wsgi_telemetry_start_reporter in the daemon main thread before any
 * worker has had a chance to serve a request, so wsgi_record_request_times
 * sees enabled=1 on its first invocation and request data is captured
 * from t=0 onwards (otherwise everything served before the reporter's
 * first periodic tick would be silently dropped). Idempotent.
 *
 * wsgi_metrics_snapshot fills the plain-C snapshot struct that the
 * datagram encoder consumes.
 *
 * The two slow-request readers drain records that crossed the
 * WSGISlowRequests threshold. pop_slow_completed dequeues one already-
 * finished record from the ring; snapshot_slow_active scans the
 * per-thread active slots and copies records whose elapsed time
 * (computed against the caller-supplied now_us) is at least
 * threshold_us into out, returning the count copied (capped at
 * out_cap).
 */

extern void wsgi_metrics_telemetry_init(void);

extern int wsgi_metrics_snapshot(wsgi_telemetry_sample_t *out);

extern int wsgi_metrics_pop_slow_completed(wsgi_slow_request_t *out);

extern int wsgi_metrics_snapshot_slow_active(wsgi_slow_request_t *out,
                                             int out_cap,
                                             apr_time_t now_us,
                                             apr_time_t threshold_us);

/* ------------------------------------------------------------------------- */

/*
 * Reporter lifecycle and graceful shutdown sequence. start_reporter and
 * stop_reporter own the periodic-tick thread that serialises
 * wsgi_metrics_snapshot results into UDP datagrams.
 *
 * The shutdown sequence is split so the chart-marker datagram fires at
 * decision time, before drain: emit_process_stopping flushes that
 * marker; pause_reporter joins the reporter thread without closing the
 * socket; emit_final_tick then drains the partial-window accumulators,
 * emits STOPPED with the lifetime summary, and closes the socket. Pass
 * NULL for reason when no shutdown reason is available.
 *
 * emit_process_stopped is the idempotent STOPPED emitter that
 * emit_final_tick uses internally. It is also called directly from the
 * reaper thread before forced exit so STOPPED still arrives when worker
 * drain exceeds shutdown_timeout. The first caller (graceful path or
 * reaper path) wins; subsequent calls are no-ops. graceful is non-zero
 * if drain completed cleanly.
 */

extern void wsgi_telemetry_start_reporter(apr_pool_t *pool);
extern void wsgi_telemetry_stop_reporter(void);

extern void wsgi_telemetry_emit_process_stopping(const char *reason);
extern void wsgi_telemetry_pause_reporter(void);
extern void wsgi_telemetry_emit_final_tick(const char *reason);
extern void wsgi_telemetry_emit_process_stopped(const char *reason,
                                                int graceful);

/* ------------------------------------------------------------------------- */

/*
 * Method tables installed on the embedded mod_wsgi module.
 * request_metrics, process_metrics and server_metrics are the runtime
 * introspection accessors; request_data exposes the per-request dict
 * stashed on WSGIThreadInfo. start_recording_metrics is the explicit
 * opt-in that arms request_metrics / process_metrics: both return None
 * until it has been called, and unconditionally when the external
 * WSGIMetricsService reporter has the recording slot.
 *
 * wsgi_metrics_init_state populates the metrics-owned fields of the
 * module's WSGIModuleState (the wsgi_id_* interned key strings and the
 * scoreboard status_flags array). Called from the embedded mod_wsgi
 * module's exec slot. Returns 0 on success, -1 on failure with Python
 * exception set.
 */

extern int wsgi_metrics_init_state(PyObject *module);

extern PyMethodDef wsgi_request_metrics_method[];
extern PyMethodDef wsgi_process_metrics_method[];
extern PyMethodDef wsgi_start_recording_metrics_method[];
extern PyMethodDef wsgi_server_metrics_method[];
extern PyMethodDef wsgi_request_data_method[];

/* ------------------------------------------------------------------------- */

/*
 * In-process event publishing API. wsgi_publish_event invokes every
 * registered Python callback for the named event (the lists live as
 * event_callbacks / shutdown_callbacks attributes on the mod_wsgi
 * module). wsgi_event_subscribers returns the current count so callers
 * on the per-request hot path can skip event-payload construction
 * entirely when nobody is listening. The two subscribe_*_method tables
 * expose the registration entry points to Python.
 */

extern long wsgi_event_subscribers(void);
extern void wsgi_publish_event(const char *name, PyObject *event);

extern PyMethodDef wsgi_subscribe_events_method[];
extern PyMethodDef wsgi_subscribe_shutdown_method[];

/* ------------------------------------------------------------------------- */

/*
 * Per-thread GIL re-acquire wait timing. Routed by WSGI_END_ALLOW_THREADS
 * at every instrumented release/acquire site. wsgi_gil_wait_record writes
 * into the per-request active slot when one is in_use; otherwise stages
 * on WSGIThreadInfo (drained at slot claim). Cheap: APR threadkey lookup
 * plus uint64 add, no locking. wsgi_gil_wait_reset clears the staging
 * accumulator at the top of wsgi_execute_script so any previous request's
 * leftover staged value is discarded. wsgi_gil_wait_current reads the
 * calling thread's running per-request totals (active slot when in_use,
 * otherwise staging); either pointer may be NULL. Intended for the
 * request_finished event publisher, which runs before the slot is
 * drained by wsgi_record_request_times.
 *
 * The WSGI_BEGIN_ALLOW_THREADS / WSGI_END_ALLOW_THREADS macros are
 * drop-in replacements for Py_BEGIN_ALLOW_THREADS / Py_END_ALLOW_THREADS
 * that additionally measure the time spent waiting to re-acquire the
 * GIL in the END expansion. The user's released-region code between
 * BEGIN and END is unchanged. Use these at every site on the
 * per-request hot path: the initial interp acquire is timed inline
 * because that path has no symmetric BEGIN/END pair.
 */

extern void wsgi_gil_wait_reset(void);
extern void wsgi_gil_wait_record(apr_uint64_t wait_us);
extern void wsgi_gil_wait_current(apr_uint64_t *wait_us,
                                  apr_uint64_t *count);

#define WSGI_BEGIN_ALLOW_THREADS \
    {                            \
        PyThreadState *_wsgi_save = PyEval_SaveThread();

#define WSGI_END_ALLOW_THREADS                                       \
    apr_time_t _wsgi_t1 = apr_time_now();                            \
    PyEval_RestoreThread(_wsgi_save);                                \
    wsgi_gil_wait_record((apr_uint64_t)(apr_time_now() - _wsgi_t1)); \
    }

#endif

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
