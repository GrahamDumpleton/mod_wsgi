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

#define WSGI_METRICS_KIND_PROCESS 1
#define WSGI_METRICS_KIND_REQUEST 2
#define WSGI_METRICS_KIND_SERVER  3

#define WSGI_METRICS_T_U64       0x01
#define WSGI_METRICS_T_F64       0x02
#define WSGI_METRICS_T_I64       0x03
#define WSGI_METRICS_T_BYTES     0x04
#define WSGI_METRICS_T_I32_ARRAY 0x05

/* Field IDs. Append-only; never reuse. Must stay in lockstep with the
 * Python decoder table in telemetry/src/mod_wsgi_telemetry/wire.py. */

#define WSGI_METRICS_F_HOSTNAME                     1
#define WSGI_METRICS_F_DAEMON_GROUP                 2

#define WSGI_METRICS_F_SAMPLE_PERIOD               10
#define WSGI_METRICS_F_REQUEST_COUNT               11
#define WSGI_METRICS_F_REQUEST_THROUGHPUT          12
#define WSGI_METRICS_F_CAPACITY_UTILIZATION        13

#define WSGI_METRICS_F_CPU_USER_UTILIZATION        20
#define WSGI_METRICS_F_CPU_SYSTEM_UTILIZATION      21
#define WSGI_METRICS_F_CPU_UTILIZATION             22

#define WSGI_METRICS_F_CPU_USER_TIME               25
#define WSGI_METRICS_F_CPU_SYSTEM_TIME             26
#define WSGI_METRICS_F_CPU_TIME                    27

#define WSGI_METRICS_F_MEMORY_RSS                  30
#define WSGI_METRICS_F_MEMORY_MAX_RSS              31

#define WSGI_METRICS_F_REQUEST_THREADS_MAXIMUM     40
#define WSGI_METRICS_F_REQUEST_THREADS_STARTED     41
#define WSGI_METRICS_F_REQUEST_THREADS_ACTIVE      42

#define WSGI_METRICS_F_SERVER_TIME                 50
#define WSGI_METRICS_F_QUEUE_TIME                  51
#define WSGI_METRICS_F_DAEMON_TIME                 52
#define WSGI_METRICS_F_APPLICATION_TIME            53

#define WSGI_METRICS_F_SERVER_TIME_BUCKETS         60
#define WSGI_METRICS_F_QUEUE_TIME_BUCKETS          61
#define WSGI_METRICS_F_DAEMON_TIME_BUCKETS         62
#define WSGI_METRICS_F_APPLICATION_TIME_BUCKETS    63
#define WSGI_METRICS_F_REQUEST_THREADS_BUCKETS     64

/* ------------------------------------------------------------------------- */

/*
 * Plain-C-only snapshot struct, produced by wsgi_metrics_snapshot() and
 * consumed by the telemetry encoder. Has no PyObject or Apache types so it
 * can be filled under wsgi_monitor_lock without taking the GIL.
 */

#define WSGI_TELEMETRY_BUCKET_COUNT 16

typedef struct {
    char     hostname[128];
    char     daemon_group[64];

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

    int32_t  server_time_buckets[WSGI_TELEMETRY_BUCKET_COUNT];
    int32_t  queue_time_buckets[WSGI_TELEMETRY_BUCKET_COUNT];
    int32_t  daemon_time_buckets[WSGI_TELEMETRY_BUCKET_COUNT];
    int32_t  application_time_buckets[WSGI_TELEMETRY_BUCKET_COUNT];

    int      has_daemon_timing;  /* queue_time / daemon_time valid? */
    int      seeded;             /* false on first call; telemetry skips send */
} wsgi_telemetry_sample_t;

/* ------------------------------------------------------------------------- */

/*
 * Inline little-endian encoder helpers. Each writes to *p and advances *p
 * past the written bytes. Callers are responsible for sizing the buffer;
 * see WSGI_METRICS_MAX_DATAGRAM for a safe upper bound on a full request_metrics
 * sample.
 */

#define WSGI_METRICS_MAX_DATAGRAM 4096

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
