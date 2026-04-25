#ifndef WSGI_TELEMETRY_H
#define WSGI_TELEMETRY_H

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
 * Wire format for telemetry datagrams emitted by the mod_wsgi telemetry
 * reporter. Deliberately free of Apache / Python dependencies so that
 * standalone ingesters and debug tools can include this header without
 * needing the full mod_wsgi build toolchain.
 *
 * Layout of one datagram (all multi-byte fields little-endian):
 *
 *   fixed header (24 bytes):
 *     uint32 magic      'WSGI'
 *     uint8  version
 *     uint8  kind       WSGI_METRICS_KIND_*
 *     uint16 flags      reserved, zero
 *     uint32 pid
 *     uint32 seq        monotonic per process
 *     uint64 stamp_us   microseconds since unix epoch
 *
 *   then repeated TLV records until end of datagram:
 *     uint16 field_id   WSGI_METRICS_F_*
 *     uint8  type       WSGI_METRICS_T_*
 *     [uint16 length]   only for BYTES / I32_ARRAY
 *     value             fixed width per type
 */

#include <stdint.h>
#include <string.h>

#define WSGI_METRICS_MAGIC_0 'W'
#define WSGI_METRICS_MAGIC_1 'S'
#define WSGI_METRICS_MAGIC_2 'G'
#define WSGI_METRICS_MAGIC_3 'I'

#define WSGI_METRICS_VERSION 1

#define WSGI_METRICS_KIND_PROCESS      1
#define WSGI_METRICS_KIND_REQUEST      2
#define WSGI_METRICS_KIND_SERVER       3
#define WSGI_METRICS_KIND_SLOW_REQUEST 4

#define WSGI_METRICS_T_U64       0x01
#define WSGI_METRICS_T_F64       0x02
#define WSGI_METRICS_T_I64       0x03
#define WSGI_METRICS_T_BYTES     0x04
#define WSGI_METRICS_T_I32_ARRAY 0x05

/* Field IDs. Grouped in blocks of 10 by concept. Must stay in lockstep
 * with the Python decoder table in telemetry/src/mod_wsgi_telemetry/wire.py.
 * IDs are kept stable while the wire format is in development; once a
 * release is cut, IDs become append-only and renumbering is no longer
 * permitted. */

/* 1-9: Identity. Build/runtime versions come first so a consumer that
 * wants to print a "who is this" banner can reach them without scanning
 * the whole TLV record. All six fields are static for the life of a
 * process and only need to be emitted on the first sample after start. */
#define WSGI_METRICS_F_MOD_WSGI_VERSION             1   /* bytes — e.g. "6.0.0" */
#define WSGI_METRICS_F_PYTHON_VERSION               2   /* bytes — e.g. "3.14.0" */
#define WSGI_METRICS_F_APACHE_VERSION               3   /* bytes — e.g. "Apache/2.4.62" */
#define WSGI_METRICS_F_MPM_NAME                     4   /* bytes — e.g. "event", "prefork" */
#define WSGI_METRICS_F_HOSTNAME                     5   /* bytes */
#define WSGI_METRICS_F_PROCESS_GROUP                6   /* bytes */

/* 10-19: Sampling and reporter configuration. sample_period is the
 * measured wall-clock interval between two snapshot calls (drifts with
 * scheduling jitter); telemetry_interval is the configured WSGITelemetry
 * directive value (constant for the life of the process). They normally
 * agree to within a few ms but can diverge under load.
 * slow_requests_threshold is the configured WSGISlowRequests value in
 * seconds (0 when the directive is not configured, in which case slow-
 * request datagrams never fire). */
#define WSGI_METRICS_F_SAMPLE_PERIOD               10   /* f64 */
#define WSGI_METRICS_F_TELEMETRY_INTERVAL          11   /* f64 */
#define WSGI_METRICS_F_SLOW_REQUESTS_THRESHOLD     12   /* f64 */

/* 20-29: Request rates and capacity for the interval. */
#define WSGI_METRICS_F_REQUEST_COUNT               20   /* u64 */
#define WSGI_METRICS_F_REQUEST_THROUGHPUT          21   /* f64 */
#define WSGI_METRICS_F_CAPACITY_UTILIZATION        22   /* f64 */

/* 30-39: CPU. *_utilization are interval rates from wsgi_request_metrics;
 * *_time are cumulative seconds reserved for wsgi_process_metrics (not
 * yet emitted on the wire). */
#define WSGI_METRICS_F_CPU_USER_UTILIZATION        30   /* f64 */
#define WSGI_METRICS_F_CPU_SYSTEM_UTILIZATION      31   /* f64 */
#define WSGI_METRICS_F_CPU_UTILIZATION             32   /* f64 */
#define WSGI_METRICS_F_CPU_USER_TIME               35   /* f64 */
#define WSGI_METRICS_F_CPU_SYSTEM_TIME             36   /* f64 */
#define WSGI_METRICS_F_CPU_TIME                    37   /* f64 */

/* 40-49: Memory. */
#define WSGI_METRICS_F_MEMORY_RSS                  40   /* u64 */
#define WSGI_METRICS_F_MEMORY_MAX_RSS              41   /* u64 */

/* 50-59: Worker-thread counts. */
#define WSGI_METRICS_F_REQUEST_THREADS_MAXIMUM     50   /* u64 */
#define WSGI_METRICS_F_REQUEST_THREADS_STARTED     51   /* u64 */
#define WSGI_METRICS_F_REQUEST_THREADS_ACTIVE      52   /* u64 */

/* 60-69: Per-phase mean times for the interval (seconds).
 * request_time is the per-request total (server + queue + daemon +
 * application) — what the caller actually experienced. */
#define WSGI_METRICS_F_SERVER_TIME                 60   /* f64 */
#define WSGI_METRICS_F_QUEUE_TIME                  61   /* f64 */
#define WSGI_METRICS_F_DAEMON_TIME                 62   /* f64 */
#define WSGI_METRICS_F_APPLICATION_TIME            63   /* f64 */
#define WSGI_METRICS_F_REQUEST_TIME                64   /* f64 */

/* 70-79: Per-phase exact min times for the interval (microseconds).
 * Only emitted on ticks where at least one request completed; the
 * encoder skips the field when the per-tick min sentinel
 * (UINT64_MAX) is still in place.
 *
 * Aggregate cleanly across processes and across time windows by
 * (min of mins) — exact, no histogram approximation. */
#define WSGI_METRICS_F_SERVER_TIME_MIN_US          70   /* u64 */
#define WSGI_METRICS_F_QUEUE_TIME_MIN_US           71   /* u64 */
#define WSGI_METRICS_F_DAEMON_TIME_MIN_US          72   /* u64 */
#define WSGI_METRICS_F_APPLICATION_TIME_MIN_US     73   /* u64 */
#define WSGI_METRICS_F_REQUEST_TIME_MIN_US         74   /* u64 */

/* 80-89: Per-phase exact max times for the interval (microseconds).
 * Same emission rule and aggregation semantics as the min block —
 * (max of maxes) is exact. Pairs with the histograms below to give a
 * true worst-case alongside the bucket-bounded percentiles. */
#define WSGI_METRICS_F_SERVER_TIME_MAX_US          80   /* u64 */
#define WSGI_METRICS_F_QUEUE_TIME_MAX_US           81   /* u64 */
#define WSGI_METRICS_F_DAEMON_TIME_MAX_US          82   /* u64 */
#define WSGI_METRICS_F_APPLICATION_TIME_MAX_US     83   /* u64 */
#define WSGI_METRICS_F_REQUEST_TIME_MAX_US         84   /* u64 */

/* 90-99: Per-phase histograms. HDR-style: 16 octaves from 1 ms to
 * 65.5 s, each octave linearly split into 4 sub-buckets, plus one
 * overflow bucket for >65536 ms = 65 entries per phase. Max relative
 * error inside any sub-bucket is ≤25%. See wsgi_record_time_in_buckets
 * for the mantissa-based O(1) index. */
#define WSGI_METRICS_F_SERVER_TIME_BUCKETS         90   /* i32 array */
#define WSGI_METRICS_F_QUEUE_TIME_BUCKETS          91   /* i32 array */
#define WSGI_METRICS_F_DAEMON_TIME_BUCKETS         92   /* i32 array */
#define WSGI_METRICS_F_APPLICATION_TIME_BUCKETS    93   /* i32 array */
#define WSGI_METRICS_F_REQUEST_TIME_BUCKETS        94   /* i32 array */

/* 100-109: Per-interval request I/O totals. Drained from the same
 * accumulator that wsgi_record_request_times() updates at end-of-
 * request, so the counts cover requests that completed during this
 * tick (in-flight requests do not contribute until they finish). */
#define WSGI_METRICS_F_INPUT_BYTES_TOTAL          100   /* u64 */
#define WSGI_METRICS_F_INPUT_READS_TOTAL          101   /* u64 */
#define WSGI_METRICS_F_OUTPUT_BYTES_TOTAL         102   /* u64 */
#define WSGI_METRICS_F_OUTPUT_WRITES_TOTAL        103   /* u64 */

/* 110-119: Per-slot capacity signals. One entry per worker thread;
 * array length matches the emitting process's live
 * request_threads_maximum. */
#define WSGI_METRICS_F_SLOT_REQUEST_COUNT         110   /* i32 array */
#define WSGI_METRICS_F_SLOT_BUSY_TIME_US          111   /* i32 array */
#define WSGI_METRICS_F_SLOT_CPU_TIME_US           112   /* i32 array */
#define WSGI_METRICS_F_SLOT_CURRENT_ELAPSED_MS    113   /* i32 array */
#define WSGI_METRICS_F_SLOT_MAX_DURATION_MS       114   /* i32 array */

/* 120-139: Slow-request fields. Only present in
 * WSGI_METRICS_KIND_SLOW_REQUEST datagrams; identity (hostname,
 * process_group) is looked up via the accompanying KIND_REQUEST stream
 * on the ingester.
 *
 * 120-129: identification and timing.
 * 130-133: per-request I/O — final at completion, partial snapshot for
 *          active records (the adapter may yet read or write more).
 * 134-135: per-request CPU time (microseconds), computed at end-of-
 *          request from the worker thread's getrusage delta. Active
 *          records carry zero — getrusage(RUSAGE_THREAD) only works
 *          from the request's own thread, but the active-record
 *          snapshot runs from the telemetry reporter thread.
 * 136:     final HTTP response status (e.g. 200, 404, 500). Active
 *          records carry zero — start_response may not have been
 *          called yet. Same "0 = not yet known" convention as the
 *          CPU-time fields above. */
#define WSGI_METRICS_F_SLOW_STATE                 120   /* u64: 0=active, 1=completed */
#define WSGI_METRICS_F_SLOW_START_STAMP_US        121   /* u64 */
#define WSGI_METRICS_F_SLOW_DURATION_US           122   /* u64 */
#define WSGI_METRICS_F_SLOW_THREAD_ID             123   /* u64 */
#define WSGI_METRICS_F_SLOW_LOG_ID                124   /* bytes */
#define WSGI_METRICS_F_SLOW_METHOD                125   /* bytes */
#define WSGI_METRICS_F_SLOW_SCHEME                126   /* bytes */
#define WSGI_METRICS_F_SLOW_HOSTNAME              127   /* bytes */
#define WSGI_METRICS_F_SLOW_SCRIPT_NAME           128   /* bytes */
#define WSGI_METRICS_F_SLOW_PATH_INFO             129   /* bytes */
#define WSGI_METRICS_F_SLOW_INPUT_BYTES           130   /* u64 */
#define WSGI_METRICS_F_SLOW_INPUT_READS           131   /* u64 */
#define WSGI_METRICS_F_SLOW_OUTPUT_BYTES          132   /* u64 */
#define WSGI_METRICS_F_SLOW_OUTPUT_WRITES         133   /* u64 */
#define WSGI_METRICS_F_SLOW_CPU_USER_US           134   /* u64 */
#define WSGI_METRICS_F_SLOW_CPU_SYSTEM_US         135   /* u64 */
#define WSGI_METRICS_F_SLOW_STATUS                136   /* u64: 0=not yet known */

/* 140-149: Per-interval HTTP response status class totals. Drained
 * from the same accumulators that wsgi_record_request_times() updates
 * at end-of-request, sharing drain-and-reset semantics with the
 * 100-109 I/O totals block. The five class counters partition every
 * request that reached end-of-request, with the convention that a
 * request whose WSGI app raised before calling start_response (status
 * value of 0) is folded into the 5xx counter — that matches the user-
 * visible outcome (mod_wsgi serves a 500). 1xx is included as a
 * tripwire: PEP 3333 forbids 1xx responses from a WSGI app, so a non-
 * zero count flags a protocol violation. Out-of-range values
 * (1..99 or 600+) are silently dropped by the recorder.
 *
 * Invariant: status_1xx_total + status_2xx_total + status_3xx_total +
 * status_4xx_total + status_5xx_total == request_count for the same
 * interval. Encoder always emits all five fields (even when zero) so
 * consumers can distinguish "zero of this class" from "older encoder
 * that didn't have the field". */
#define WSGI_METRICS_F_STATUS_1XX_TOTAL           140   /* u64 */
#define WSGI_METRICS_F_STATUS_2XX_TOTAL           141   /* u64 */
#define WSGI_METRICS_F_STATUS_3XX_TOTAL           142   /* u64 */
#define WSGI_METRICS_F_STATUS_4XX_TOTAL           143   /* u64 */
#define WSGI_METRICS_F_STATUS_5XX_TOTAL           144   /* u64 */

/* ------------------------------------------------------------------------- */

/*
 * Plain-C-only snapshot struct, produced by wsgi_metrics_snapshot() and
 * consumed by the telemetry encoder. Has no PyObject or Apache types so it
 * can be filled under wsgi_monitor_lock without taking the GIL.
 */

/* Per-phase histogram bucket count. HDR-style layout: 16 octaves
 * (1 ms → 65.5 s) × 4 linear sub-buckets per octave + 1 overflow
 * bucket for >65536 ms. See wsgi_record_time_in_buckets and the
 * BUCKET_UPPER_MS table on the UI side for the exact boundaries. */
#define WSGI_TELEMETRY_BUCKET_COUNT 65

/* Upper bound on per-slot array sizing. The encoder only emits
 * slot_count entries per tick, so oversizing the struct costs stack
 * memory but no wire bytes. 128 is generous for any realistic
 * WSGIDaemonProcess threads setting. */
#define WSGI_TELEMETRY_MAX_SLOTS    128

typedef struct {
    char     hostname[128];
    char     process_group[64];

    /* Build / runtime identity. Populated once at reporter thread
     * start and copied into the sample every tick; static for the
     * life of the process. Emitted as bytes fields 1-4. Empty strings
     * are skipped by the encoder so older ingesters tolerate a
     * mod_wsgi that couldn't resolve, say, the MPM name. */
    char     mod_wsgi_version[32];
    char     python_version[64];
    char     apache_version[64];
    char     mpm_name[32];

    double   sample_period;
    uint64_t request_count;
    double   request_throughput;
    double   capacity_utilization;

    double   cpu_user_utilization;
    double   cpu_system_utilization;
    double   cpu_utilization;

    uint64_t memory_rss;
    uint64_t memory_max_rss;

    uint32_t request_threads_maximum;
    uint32_t request_threads_started;
    uint32_t request_threads_active;

    double   server_time;
    double   queue_time;
    double   daemon_time;
    double   application_time;
    double   request_time;

    /* Per-phase exact min/max for the interval, in microseconds. The
     * encoder skips the corresponding wire field when min still holds
     * its UINT64_MAX sentinel — i.e. no requests completed during the
     * tick. Min-of-mins / max-of-maxes are exact under any cross-
     * process or cross-window aggregation. */
    uint64_t server_time_min_us;
    uint64_t queue_time_min_us;
    uint64_t daemon_time_min_us;
    uint64_t application_time_min_us;
    uint64_t request_time_min_us;
    uint64_t server_time_max_us;
    uint64_t queue_time_max_us;
    uint64_t daemon_time_max_us;
    uint64_t application_time_max_us;
    uint64_t request_time_max_us;

    int32_t  server_time_buckets[WSGI_TELEMETRY_BUCKET_COUNT];
    int32_t  queue_time_buckets[WSGI_TELEMETRY_BUCKET_COUNT];
    int32_t  daemon_time_buckets[WSGI_TELEMETRY_BUCKET_COUNT];
    int32_t  application_time_buckets[WSGI_TELEMETRY_BUCKET_COUNT];
    int32_t  request_time_buckets[WSGI_TELEMETRY_BUCKET_COUNT];

    /* Per-interval request I/O totals. Sum across requests that
     * completed in this interval; in-flight requests contribute on
     * the tick they finish. */
    uint64_t input_bytes_total;
    uint64_t input_reads_total;
    uint64_t output_bytes_total;
    uint64_t output_writes_total;

    /* Per-interval HTTP response class totals. Same drain-and-reset
     * semantics as the I/O totals above. status==0 (no start_response
     * call) is folded into status_5xx_total. Sum equals request_count
     * for the interval. */
    uint64_t status_1xx_total;
    uint64_t status_2xx_total;
    uint64_t status_3xx_total;
    uint64_t status_4xx_total;
    uint64_t status_5xx_total;

    /* Reporter / slow-request configuration. Constant over the life
     * of the process; populated once per snapshot so the UI sees the
     * same values as the C side. slow_requests_threshold is 0 when
     * the WSGISlowRequests directive is not configured. */
    double   telemetry_interval;
    double   slow_requests_threshold;

    /* Per-slot capacity signals. slot_count is the live length of each
     * array — normally the WSGI process's request_threads_maximum, or
     * WSGI_TELEMETRY_MAX_SLOTS if that is exceeded. */
    uint32_t slot_count;
    int32_t  slot_request_count      [WSGI_TELEMETRY_MAX_SLOTS];
    int32_t  slot_busy_time_us       [WSGI_TELEMETRY_MAX_SLOTS];
    int32_t  slot_cpu_time_us        [WSGI_TELEMETRY_MAX_SLOTS];
    int32_t  slot_current_elapsed_ms [WSGI_TELEMETRY_MAX_SLOTS];
    int32_t  slot_max_duration_ms    [WSGI_TELEMETRY_MAX_SLOTS];

    int      has_daemon_timing;  /* queue_time / daemon_time valid? */
    int      seeded;             /* false on first call; telemetry skips send */
} wsgi_telemetry_sample_t;

/* ------------------------------------------------------------------------- */

/*
 * Plain-C snapshot of a slow-request record. Filled by
 * wsgi_metrics_snapshot_slow_active() (for still-running requests scanned
 * out of the per-thread active-slot array) or popped from the completed
 * ring with wsgi_metrics_pop_slow_completed(). Strings are always
 * null-terminated; the encoder writes up to strlen() bytes on the wire.
 */

#define WSGI_SLOW_LOG_ID_MAX      64
#define WSGI_SLOW_METHOD_MAX      16
#define WSGI_SLOW_SCHEME_MAX      16
#define WSGI_SLOW_HOSTNAME_MAX    256
#define WSGI_SLOW_SCRIPT_NAME_MAX 256
#define WSGI_SLOW_PATH_INFO_MAX   512

typedef struct {
    uint64_t start_stamp_us;     /* wall-clock when request started */
    uint64_t duration_us;        /* elapsed (active) or final (completed) */
    uint32_t thread_id;
    uint8_t  state;              /* 0=active, 1=completed */

    /* Per-request I/O counters. Final at completion; partial snapshot
     * for an active record (adapter may read/write more before end). */
    uint64_t input_bytes;
    uint64_t input_reads;
    uint64_t output_bytes;
    uint64_t output_writes;

    /* Per-request CPU time (microseconds). Final at completion;
     * zero for active records — getrusage on this thread can only be
     * called from the request's own worker, not from the reporter
     * snapshot path that produces active records. */
    uint64_t cpu_user_us;
    uint64_t cpu_system_us;

    /* Final HTTP response status (e.g. 200, 404, 500). Zero for active
     * records — start_response may not have been called yet. */
    uint16_t status;

    char     log_id[WSGI_SLOW_LOG_ID_MAX];
    char     method[WSGI_SLOW_METHOD_MAX];
    char     scheme[WSGI_SLOW_SCHEME_MAX];
    char     hostname[WSGI_SLOW_HOSTNAME_MAX];
    char     script_name[WSGI_SLOW_SCRIPT_NAME_MAX];
    char     path_info[WSGI_SLOW_PATH_INFO_MAX];
} wsgi_slow_request_t;

/* ------------------------------------------------------------------------- */

/*
 * Inline little-endian encoder helpers. Each writes to *p and advances *p
 * past the written bytes. Callers are responsible for sizing the buffer;
 * see WSGI_METRICS_MAX_DATAGRAM for a safe upper bound on a full request_metrics
 * sample.
 */

#define WSGI_METRICS_MAX_DATAGRAM 8192

static inline void wsgi_metrics_put_u16le(uint8_t **p, uint16_t v)
{
    (*p)[0] = (uint8_t)(v & 0xff);
    (*p)[1] = (uint8_t)((v >> 8) & 0xff);
    *p += 2;
}

static inline void wsgi_metrics_put_u32le(uint8_t **p, uint32_t v)
{
    (*p)[0] = (uint8_t)(v & 0xff);
    (*p)[1] = (uint8_t)((v >> 8) & 0xff);
    (*p)[2] = (uint8_t)((v >> 16) & 0xff);
    (*p)[3] = (uint8_t)((v >> 24) & 0xff);
    *p += 4;
}

static inline void wsgi_metrics_put_u64le(uint8_t **p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++)
        (*p)[i] = (uint8_t)((v >> (i * 8)) & 0xff);
    *p += 8;
}

static inline void wsgi_metrics_put_header(uint8_t **p, uint8_t kind, uint32_t pid,
                                   uint32_t seq, uint64_t stamp_us)
{
    (*p)[0] = WSGI_METRICS_MAGIC_0;
    (*p)[1] = WSGI_METRICS_MAGIC_1;
    (*p)[2] = WSGI_METRICS_MAGIC_2;
    (*p)[3] = WSGI_METRICS_MAGIC_3;
    *p += 4;
    (*p)[0] = WSGI_METRICS_VERSION;
    (*p)[1] = kind;
    *p += 2;
    wsgi_metrics_put_u16le(p, 0);       /* flags */
    wsgi_metrics_put_u32le(p, pid);
    wsgi_metrics_put_u32le(p, seq);
    wsgi_metrics_put_u64le(p, stamp_us);
}

static inline void wsgi_metrics_put_u64(uint8_t **p, uint16_t id, uint64_t v)
{
    wsgi_metrics_put_u16le(p, id);
    (*p)[0] = WSGI_METRICS_T_U64; *p += 1;
    wsgi_metrics_put_u64le(p, v);
}

static inline void wsgi_metrics_put_f64(uint8_t **p, uint16_t id, double v)
{
    uint64_t bits;
    memcpy(&bits, &v, sizeof(bits));
    wsgi_metrics_put_u16le(p, id);
    (*p)[0] = WSGI_METRICS_T_F64; *p += 1;
    wsgi_metrics_put_u64le(p, bits);
}

static inline void wsgi_metrics_put_bytes(uint8_t **p, uint16_t id,
                                  const char *data, uint16_t len)
{
    wsgi_metrics_put_u16le(p, id);
    (*p)[0] = WSGI_METRICS_T_BYTES; *p += 1;
    wsgi_metrics_put_u16le(p, len);
    memcpy(*p, data, len);
    *p += len;
}

static inline void wsgi_metrics_put_i32_array(uint8_t **p, uint16_t id,
                                      const int32_t *arr, uint16_t count)
{
    uint16_t i;
    wsgi_metrics_put_u16le(p, id);
    (*p)[0] = WSGI_METRICS_T_I32_ARRAY; *p += 1;
    wsgi_metrics_put_u16le(p, count);
    for (i = 0; i < count; i++) {
        uint32_t v = (uint32_t)arr[i];
        wsgi_metrics_put_u32le(p, v);
    }
}

/* ------------------------------------------------------------------------- */

#endif /* WSGI_TELEMETRY_H */

/* vi: set sw=4 expandtab : */
