#ifndef WSGI_GC_H
#define WSGI_GC_H

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

#include <stdint.h>

/* ------------------------------------------------------------------------- */

/*
 * Per-collection event record produced by the gc.callbacks
 * callback on each "stop" phase. start_us is captured on the
 * paired "start" phase so duration_us is exact for the GC pause,
 * inclusive of any other gc.callbacks entries that ran inside the
 * same collection.
 */

typedef struct
{
    uint64_t start_us;
    uint64_t duration_us;
    uint64_t collected;
    uint64_t uncollectable;
    uint8_t generation;
} wsgi_gc_event_t;

/*
 * Per-snapshot read of the cheap tier-1 GC counters. Populated by
 * wsgi_gc_read_counters under the target interpreter's GIL /
 * attach state and emitted on every telemetry tick.
 *
 * count[]:         gc.get_count() allocation pressure counters.
 * threshold[]:     gc.get_threshold() configured thresholds.
 * collections[]:   cumulative gc.get_stats()['collections'] per gen.
 * collected[]:     cumulative gc.get_stats()['collected'] per gen.
 * uncollectable[]: cumulative gc.get_stats()['uncollectable'] per gen.
 * is_enabled:      gc.isenabled() as 0 / 1.
 * freeze_count:    gc.get_freeze_count() current frozen-object count.
 */

typedef struct
{
    uint64_t count[3];
    uint64_t threshold[3];
    uint64_t collections[3];
    uint64_t collected[3];
    uint64_t uncollectable[3];
    uint8_t is_enabled;
    uint64_t freeze_count;
} wsgi_gc_counters_t;

/*
 * Opaque per-interpreter GC telemetry state. Allocated by
 * wsgi_gc_init_state from the server process pool and reachable
 * through WSGIModuleState->gc. Internals are private to wsgi_gc.c.
 */

typedef struct WSGIGcState WSGIGcState;

/* ------------------------------------------------------------------------- */

/*
 * Initialise the per-interpreter GC telemetry state and register
 * the gc.callbacks callback. Called from the embedded mod_wsgi
 * module's exec slot, after the per-type init helpers, with the
 * target interpreter's GIL / attach state already held. Sets the
 * gc field on WSGIModuleState. Returns 0 on success, -1 on
 * failure with Python exception set.
 *
 * Has no effect if WSGITelemetryService is not configured: the
 * tier-1 counters and tier-2 events are only meaningful when an
 * external reporter is consuming them, and skipping registration
 * avoids the gc.callbacks invocation cost on every collection in
 * the no-telemetry configuration.
 */

extern int wsgi_gc_init_state(PyObject *module);

/*
 * Drain queued tier-2 GC pause events from this interpreter's
 * ring buffer into the caller-supplied array. Takes the ring
 * lock briefly; the caller does not need the GIL for this. The
 * dropped counter accumulates events lost to ring overflow since
 * the previous drain; out_dropped receives the delta and the
 * counter resets. Returns the number of events copied (always
 * <= out_cap).
 */

extern int wsgi_gc_drain_events(WSGIGcState *state, wsgi_gc_event_t *out,
                                int out_cap, uint64_t *out_dropped);

/*
 * Read the tier-1 GC counters for the interpreter associated
 * with the given mod_wsgi module instance. Caller must hold the
 * target interpreter's GIL / attach state. On any Python-level
 * failure the function clears the exception and returns 0
 * with out zeroed, so the caller never propagates a GC-side
 * error into the telemetry stream.
 */

extern void wsgi_gc_read_counters(PyObject *module, wsgi_gc_counters_t *out);

/* ------------------------------------------------------------------------- */

#endif
