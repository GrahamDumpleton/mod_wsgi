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

extern apr_uint64_t wsgi_total_requests;
extern int wsgi_active_requests;

extern apr_thread_mutex_t *wsgi_monitor_lock;

extern PyMethodDef wsgi_request_metrics_method[];

extern PyMethodDef wsgi_process_metrics_method[];

extern WSGIThreadInfo *wsgi_start_request(request_rec *r);
extern void wsgi_end_request(void);

extern void wsgi_record_request_times(apr_time_t request_start,
                                      apr_time_t queue_start, apr_time_t daemon_start,
                                      apr_time_t application_start, apr_time_t application_finish,
                                      apr_off_t input_bytes, apr_off_t input_reads,
                                      apr_off_t output_bytes, apr_off_t output_writes,
                                      int status);

/* Records the wall-clock instant the WSGI callable began executing onto
 * the worker thread's active slot. Called from the adapter immediately
 * after self->start_time is captured, so the active-record snapshot can
 * compute server / queue / daemon / application phase durations even
 * while the callable is still running. The companion application_finish
 * value is captured by wsgi_record_request_times at end-of-request. */
extern void wsgi_record_application_start(apr_time_t application_start);

extern int wsgi_metrics_snapshot(wsgi_telemetry_sample_t *out);

/* Slow-request tracking. threshold_us == 0 disables the feature; set
 * from the WSGISlowRequests directive at config time. Must be written
 * before the telemetry reporter thread starts. */
extern apr_time_t wsgi_slow_threshold_us;

/* Pop one completed slow-request record from the finalize ring. Returns 1
 * if one was copied into *out, 0 if the ring was empty. Takes
 * wsgi_monitor_lock internally. */
extern int wsgi_metrics_pop_slow_completed(wsgi_slow_request_t *out);

/* Snapshot up to out_cap currently-active slots whose elapsed time is at
 * least threshold_us. now_us is the caller's current timestamp (so a
 * consistent "elapsed" can be computed across all slots). Returns the
 * number of records copied. Takes wsgi_monitor_lock internally. */
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

#endif

/* vi: set sw=4 expandtab : */
