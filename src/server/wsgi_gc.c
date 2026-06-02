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

#include "wsgi_gc.h"

#include "wsgi_module.h"
#include "wsgi_telemetry.h"
#include "wsgi_server.h"

#include "apr_thread_mutex.h"
#include "apr_time.h"

/* ------------------------------------------------------------------------- */

/*
 * Ring capacity per interpreter. Sized to absorb a burst of
 * collections between two telemetry ticks without dropping. With
 * tier-2 events firing roughly one per cyclic GC pass and tick
 * intervals down to the 0.5s configured floor, 256 slots covers
 * pathological allocation pressure well beyond any realistic
 * sustained rate.
 */

#define WSGI_GC_RING_CAPACITY 256

/* ------------------------------------------------------------------------- */

/*
 * Private layout for the opaque WSGIGcState typedef. The lock
 * guards every read or write of ring_head / ring_count / dropped
 * and the slot at the about-to-be-written index. pending_start_us
 * is touched only from the gc.callbacks callback and is paired
 * with the next stop within the same collection, so it is
 * implicitly serialised by Python's stop-the-world GC and does
 * not need the ring lock.
 */

struct WSGIGcState
{
    apr_thread_mutex_t *lock;
    wsgi_gc_event_t *ring;
    uint32_t ring_capacity;
    uint32_t ring_head;
    uint32_t ring_count;
    uint64_t dropped;
    apr_time_t pending_start_us;
};

/* ------------------------------------------------------------------------- */

/*
 * Append one event to the ring, evicting the oldest slot when
 * full and bumping the dropped counter. Called from the
 * gc.callbacks callback under whichever serialisation Python
 * provides (GIL or stop-the-world). The mutex protects against
 * concurrent drain from the sampler thread.
 */

static void wsgi_gc_ring_push(WSGIGcState *state, const wsgi_gc_event_t *ev)
{
    uint32_t idx = 0;

    apr_thread_mutex_lock(state->lock);

    if (state->ring_count < state->ring_capacity)
    {
        idx = (state->ring_head + state->ring_count) % state->ring_capacity;
        state->ring_count++;
    }
    else
    {
        idx = state->ring_head;
        state->ring_head = (state->ring_head + 1) % state->ring_capacity;
        state->dropped++;
    }

    state->ring[idx] = *ev;

    apr_thread_mutex_unlock(state->lock);
}

/* ------------------------------------------------------------------------- */

/*
 * gc.callbacks callback implementation. Bound to a per-interpreter
 * PyCFunction whose self is the mod_wsgi module instance, so the
 * matching WSGIGcState is reachable via PyModule_GetState without
 * any global lookup. Receives (phase, info) per the Python gc
 * module contract: phase is "start" or "stop", info is a dict
 * carrying generation / collected / uncollectable keys.
 *
 * On "start" the wall-clock instant is stashed on pending_start_us
 * so the matching "stop" can compute an exact pause duration.
 * On "stop" a complete event record is pushed into the ring.
 * Anything else (unrecognised phase string, missing keys, the
 * info object not being a dict) is treated as a no-op rather than
 * propagated, since raising out of a gc.callbacks entry would
 * surface as a Python warning on every collection.
 */

static PyObject *wsgi_gc_callback_impl(PyObject *self, PyObject *args)
{
    WSGIModuleState *mstate = NULL;
    WSGIGcState *state = NULL;
    PyObject *phase_obj = NULL;
    PyObject *info_obj = NULL;
    const char *phase = NULL;

    mstate = (WSGIModuleState *)PyModule_GetState(self);
    if (!mstate || !mstate->gc)
        Py_RETURN_NONE;

    state = mstate->gc;

    if (!PyArg_ParseTuple(args, "OO", &phase_obj, &info_obj))
    {
        PyErr_Clear();
        Py_RETURN_NONE;
    }

    if (!PyUnicode_Check(phase_obj))
        Py_RETURN_NONE;

    phase = PyUnicode_AsUTF8(phase_obj);
    if (!phase)
    {
        PyErr_Clear();
        Py_RETURN_NONE;
    }

    if (strcmp(phase, "start") == 0)
    {
        state->pending_start_us = apr_time_now();
        Py_RETURN_NONE;
    }

    if (strcmp(phase, "stop") != 0)
        Py_RETURN_NONE;

    if (!PyDict_Check(info_obj))
        Py_RETURN_NONE;

    {
        apr_time_t now_us = apr_time_now();
        wsgi_gc_event_t ev;
        PyObject *v = NULL;
        long gen = -1;
        long long collected = 0;
        long long uncollectable = 0;

        v = PyDict_GetItemString(info_obj, "generation");
        if (v && PyLong_Check(v))
            gen = PyLong_AsLong(v);
        if (PyErr_Occurred() || gen < 0 || gen > 255)
        {
            PyErr_Clear();
            Py_RETURN_NONE;
        }

        v = PyDict_GetItemString(info_obj, "collected");
        if (v && PyLong_Check(v))
            collected = PyLong_AsLongLong(v);
        if (PyErr_Occurred() || collected < 0)
        {
            PyErr_Clear();
            collected = 0;
        }

        v = PyDict_GetItemString(info_obj, "uncollectable");
        if (v && PyLong_Check(v))
            uncollectable = PyLong_AsLongLong(v);
        if (PyErr_Occurred() || uncollectable < 0)
        {
            PyErr_Clear();
            uncollectable = 0;
        }

        ev.start_us = (uint64_t)state->pending_start_us;
        if (now_us > state->pending_start_us)
            ev.duration_us = (uint64_t)(now_us - state->pending_start_us);
        else
            ev.duration_us = 0;
        ev.collected = (uint64_t)collected;
        ev.uncollectable = (uint64_t)uncollectable;
        ev.generation = (uint8_t)gen;

        wsgi_gc_ring_push(state, &ev);
    }

    Py_RETURN_NONE;
}

static PyMethodDef wsgi_gc_callback_def = {
    "_gc_callback", wsgi_gc_callback_impl, METH_VARARGS,
    "Internal mod_wsgi gc.callbacks entry; do not call directly."};

/* ------------------------------------------------------------------------- */

/*
 * Register the per-interpreter PyCFunction on gc.callbacks. Bound
 * to the supplied module instance so the callback can recover its
 * WSGIGcState from PyModule_GetState(self). Returns 0 on success,
 * -1 on failure with Python exception set.
 */

static int wsgi_gc_register_callback(PyObject *module)
{
    PyObject *gc_module = NULL;
    PyObject *callbacks = NULL;
    PyObject *callable = NULL;
    int rc = -1;

    gc_module = PyImport_ImportModule("gc");
    if (!gc_module)
        return -1;

    callbacks = PyObject_GetAttrString(gc_module, "callbacks");
    if (!callbacks)
        goto cleanup;
    if (!PyList_Check(callbacks))
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "gc.callbacks is not a list");
        goto cleanup;
    }

    callable = PyCFunction_NewEx(&wsgi_gc_callback_def, module, NULL);
    if (!callable)
        goto cleanup;

    if (PyList_Append(callbacks, callable) < 0)
        goto cleanup;

    rc = 0;

cleanup:
    Py_XDECREF(callable);
    Py_XDECREF(callbacks);
    Py_XDECREF(gc_module);
    return rc;
}

/* ------------------------------------------------------------------------- */

int wsgi_gc_init_state(PyObject *module)
{
    WSGIModuleState *mstate = NULL;
    WSGIGcState *state = NULL;
    apr_pool_t *pool = NULL;
    apr_status_t rv = APR_SUCCESS;

    mstate = (WSGIModuleState *)PyModule_GetState(module);
    if (!mstate)
        return -1;

    /*
     * Skip when telemetry is disabled. tier-1 reads and tier-2
     * events only feed the external reporter; without it the
     * gc.callbacks entry would run on every collection in every
     * interpreter for no consumer. When telemetry is not built at all
     * there is never a consumer, so the hooks are always skipped.
     */

#if defined(MOD_WSGI_WITH_TELEMETRY)
    if (!wsgi_telemetry_is_enabled())
#endif
    {
        mstate->gc = NULL;
        return 0;
    }

    pool = wsgi_server->process->pool;

    state = apr_pcalloc(pool, sizeof(*state));
    if (!state)
    {
        PyErr_NoMemory();
        return -1;
    }

    state->ring_capacity = WSGI_GC_RING_CAPACITY;
    state->ring = apr_pcalloc(pool,
                              state->ring_capacity * sizeof(*state->ring));
    if (!state->ring)
    {
        PyErr_NoMemory();
        return -1;
    }

    rv = apr_thread_mutex_create(&state->lock, APR_THREAD_MUTEX_UNNESTED,
                                 pool);
    if (rv != APR_SUCCESS)
    {
        PyErr_SetString(PyExc_RuntimeError,
                        "Failed to create GC telemetry ring lock");
        return -1;
    }

    mstate->gc = state;

    if (wsgi_gc_register_callback(module) < 0)
    {
        mstate->gc = NULL;
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------------- */

int wsgi_gc_drain_events(WSGIGcState *state, wsgi_gc_event_t *out,
                         int out_cap, uint64_t *out_dropped)
{
    int copied = 0;

    if (!state || !out || out_cap <= 0)
    {
        if (out_dropped)
            *out_dropped = 0;
        return 0;
    }

    apr_thread_mutex_lock(state->lock);

    while (copied < out_cap && state->ring_count > 0)
    {
        out[copied++] = state->ring[state->ring_head];
        state->ring_head = (state->ring_head + 1) % state->ring_capacity;
        state->ring_count--;
    }

    if (out_dropped)
    {
        *out_dropped = state->dropped;
        state->dropped = 0;
    }

    apr_thread_mutex_unlock(state->lock);

    return copied;
}

/* ------------------------------------------------------------------------- */

/*
 * Read one long-valued attribute on a dict and store into out
 * with a default of 0 on any failure. Used to scrape the per-
 * generation entries of gc.get_stats(). Clears any Python
 * exception before returning so the tier-1 read never propagates
 * a failure.
 */

static void wsgi_gc_dict_long(PyObject *dict, const char *key, uint64_t *out)
{
    PyObject *v = NULL;

    *out = 0;
    if (!dict || !PyDict_Check(dict))
        return;

    v = PyDict_GetItemString(dict, key);
    if (v && PyLong_Check(v))
    {
        long long val = PyLong_AsLongLong(v);
        if (!PyErr_Occurred() && val >= 0)
            *out = (uint64_t)val;
    }
    PyErr_Clear();
}

/* ------------------------------------------------------------------------- */

void wsgi_gc_read_counters(PyObject *module, wsgi_gc_counters_t *out)
{
    PyObject *gc_module = NULL;
    PyObject *tuple = NULL;
    PyObject *stats = NULL;
    PyObject *item = NULL;
    Py_ssize_t i = 0;
    int gen = 0;

    memset(out, 0, sizeof(*out));
    (void)module; /* parity with wsgi_gc_init_state; future use. */

    gc_module = PyImport_ImportModule("gc");
    if (!gc_module)
    {
        PyErr_Clear();
        return;
    }

    tuple = PyObject_CallMethod(gc_module, "get_count", NULL);
    if (tuple && PyTuple_Check(tuple))
    {
        for (i = 0; i < 3 && i < PyTuple_GET_SIZE(tuple); i++)
        {
            item = PyTuple_GET_ITEM(tuple, i);
            if (item && PyLong_Check(item))
            {
                long long v = PyLong_AsLongLong(item);
                if (!PyErr_Occurred() && v >= 0)
                    out->count[i] = (uint64_t)v;
            }
            PyErr_Clear();
        }
    }
    Py_XDECREF(tuple);

    tuple = PyObject_CallMethod(gc_module, "get_threshold", NULL);
    if (tuple && PyTuple_Check(tuple))
    {
        for (i = 0; i < 3 && i < PyTuple_GET_SIZE(tuple); i++)
        {
            item = PyTuple_GET_ITEM(tuple, i);
            if (item && PyLong_Check(item))
            {
                long long v = PyLong_AsLongLong(item);
                if (!PyErr_Occurred() && v >= 0)
                    out->threshold[i] = (uint64_t)v;
            }
            PyErr_Clear();
        }
    }
    Py_XDECREF(tuple);

    stats = PyObject_CallMethod(gc_module, "get_stats", NULL);
    if (stats && PyList_Check(stats))
    {
        Py_ssize_t n = PyList_GET_SIZE(stats);
        for (gen = 0; gen < 3 && gen < n; gen++)
        {
            PyObject *d = PyList_GET_ITEM(stats, gen);
            wsgi_gc_dict_long(d, "collections", &out->collections[gen]);
            wsgi_gc_dict_long(d, "collected", &out->collected[gen]);
            wsgi_gc_dict_long(d, "uncollectable", &out->uncollectable[gen]);
        }
    }
    Py_XDECREF(stats);

    {
        PyObject *r = PyObject_CallMethod(gc_module, "isenabled", NULL);
        if (r)
        {
            int b = PyObject_IsTrue(r);
            if (b >= 0)
                out->is_enabled = (uint8_t)(b ? 1 : 0);
            Py_DECREF(r);
        }
        PyErr_Clear();
    }

    {
        PyObject *r = PyObject_CallMethod(gc_module, "get_freeze_count",
                                          NULL);
        if (r && PyLong_Check(r))
        {
            long long v = PyLong_AsLongLong(r);
            if (!PyErr_Occurred() && v >= 0)
                out->freeze_count = (uint64_t)v;
            PyErr_Clear();
        }
        Py_XDECREF(r);
    }

    Py_DECREF(gc_module);
}

/* ------------------------------------------------------------------------- */
