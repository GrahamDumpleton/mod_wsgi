#ifndef WSGI_MODULE_H
#define WSGI_MODULE_H

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

/*
 * Per-interpreter state for the embedded 'mod_wsgi' Python module.
 * Each Python sub-interpreter created by mod_wsgi has its own
 * instance of this struct, addressable via PyModule_GetState() on
 * the module returned by PyImport_ImportModule("mod_wsgi"). The
 * heap PyTypeObject fields are populated by the per-type init
 * helpers (wsgi_restricted_init, wsgi_signal_init, ...) called
 * from the module's exec slot. The interned key strings used by
 * the metrics dict construction code, and the scoreboard status
 * flag strings, are populated by wsgi_metrics_init_state from the
 * same exec slot, so that each interpreter's metrics paths only
 * touch PyObjects allocated under its own GIL.
 *
 * Lookup from anywhere in the embedded code goes through
 * sys.modules:
 *
 *     PyObject *m = PyImport_ImportModule("mod_wsgi");
 *     WSGIModuleState *s = PyModule_GetState(m);
 *     ... use s->Restricted_Type ...
 *     Py_DECREF(m);
 */

typedef struct
{
    PyTypeObject *Restricted_Type;
    PyTypeObject *SignalIntercept_Type;
    PyTypeObject *ShutdownInterpreter_Type;
    PyTypeObject *Log_Type;
    PyTypeObject *Stream_Type;
    PyTypeObject *Dispatch_Type;
    PyTypeObject *Auth_Type;
    PyTypeObject *Input_Type;
    PyTypeObject *Adapter_Type;

    /*
     * Interned key strings used as dict keys when building the
     * mod_wsgi.request_metrics / process_metrics / server_metrics
     * result dicts. Populated by wsgi_metrics_init_state.
     */

    PyObject *wsgi_id_server_limit;
    PyObject *wsgi_id_thread_limit;
    PyObject *wsgi_id_running_generation;
    PyObject *wsgi_id_restart_time;
    PyObject *wsgi_id_current_time;
    PyObject *wsgi_id_running_time;
    PyObject *wsgi_id_process_num;
    PyObject *wsgi_id_pid;
    PyObject *wsgi_id_generation;
    PyObject *wsgi_id_quiescing;
    PyObject *wsgi_id_workers;
    PyObject *wsgi_id_thread_num;
    PyObject *wsgi_id_status;
    PyObject *wsgi_id_access_count;
    PyObject *wsgi_id_bytes_served;
    PyObject *wsgi_id_start_time;
    PyObject *wsgi_id_stop_time;
    PyObject *wsgi_id_last_used;
    PyObject *wsgi_id_client;
    PyObject *wsgi_id_request;
    PyObject *wsgi_id_vhost;
    PyObject *wsgi_id_processes;

    PyObject *wsgi_id_request_count;
    PyObject *wsgi_id_request_busy_time;
    PyObject *wsgi_id_memory_max_rss;
    PyObject *wsgi_id_memory_rss;
    PyObject *wsgi_id_cpu_user_time;
    PyObject *wsgi_id_cpu_system_time;
    PyObject *wsgi_id_cpu_time;
    PyObject *wsgi_id_cpu_user_utilization;
    PyObject *wsgi_id_cpu_system_utilization;
    PyObject *wsgi_id_cpu_utilization;
    PyObject *wsgi_id_request_threads;
    PyObject *wsgi_id_active_requests;
    PyObject *wsgi_id_threads;
    PyObject *wsgi_id_thread_id;

    PyObject *wsgi_id_sample_period;
    PyObject *wsgi_id_request_threads_maximum;
    PyObject *wsgi_id_request_threads_started;
    PyObject *wsgi_id_request_threads_active;
    PyObject *wsgi_id_capacity_utilization;
    PyObject *wsgi_id_request_throughput;
    PyObject *wsgi_id_server_time;
    PyObject *wsgi_id_queue_time;
    PyObject *wsgi_id_daemon_time;
    PyObject *wsgi_id_application_time;
    PyObject *wsgi_id_request_time;
    PyObject *wsgi_id_server_time_min_us;
    PyObject *wsgi_id_queue_time_min_us;
    PyObject *wsgi_id_daemon_time_min_us;
    PyObject *wsgi_id_application_time_min_us;
    PyObject *wsgi_id_request_time_min_us;
    PyObject *wsgi_id_server_time_max_us;
    PyObject *wsgi_id_queue_time_max_us;
    PyObject *wsgi_id_daemon_time_max_us;
    PyObject *wsgi_id_application_time_max_us;
    PyObject *wsgi_id_request_time_max_us;
    PyObject *wsgi_id_server_time_buckets;
    PyObject *wsgi_id_queue_time_buckets;
    PyObject *wsgi_id_daemon_time_buckets;
    PyObject *wsgi_id_application_time_buckets;
    PyObject *wsgi_id_request_time_buckets;
    PyObject *wsgi_id_request_threads_buckets;
    PyObject *wsgi_id_slot_busy_time_us;
    PyObject *wsgi_id_slot_cpu_time_us;
    PyObject *wsgi_id_slot_current_elapsed_ms;
    PyObject *wsgi_id_slot_max_duration_ms;

    PyObject *wsgi_id_gil_wait_time;
    PyObject *wsgi_id_gil_wait_time_min_us;
    PyObject *wsgi_id_gil_wait_time_max_us;
    PyObject *wsgi_id_gil_wait_time_buckets;
    PyObject *wsgi_id_gil_wait_count;
    PyObject *wsgi_id_input_read_time;
    PyObject *wsgi_id_input_read_time_min_us;
    PyObject *wsgi_id_input_read_time_max_us;
    PyObject *wsgi_id_input_read_time_buckets;
    PyObject *wsgi_id_output_write_time;
    PyObject *wsgi_id_output_write_time_min_us;
    PyObject *wsgi_id_output_write_time_max_us;
    PyObject *wsgi_id_output_write_time_buckets;

    PyObject *wsgi_id_input_bytes;
    PyObject *wsgi_id_input_reads;
    PyObject *wsgi_id_output_bytes;
    PyObject *wsgi_id_output_writes;

    PyObject *wsgi_id_status_1xx;
    PyObject *wsgi_id_status_2xx;
    PyObject *wsgi_id_status_3xx;
    PyObject *wsgi_id_status_4xx;
    PyObject *wsgi_id_status_5xx;

    /*
     * Interned single-character flag strings indexed by Apache
     * scoreboard worker status code (SERVER_DEAD, SERVER_READY,
     * etc.). Slots not assigned by wsgi_metrics_init_state remain
     * NULL and must not be accessed.
     */

    PyObject *status_flags[SERVER_NUM_STATUS];
} WSGIModuleState;

/* ------------------------------------------------------------------------- */

extern struct PyModuleDef wsgi_module_def;

extern PyMODINIT_FUNC PyInit_mod_wsgi(void);

/*
 * Helper to add an object to a module. Properly handles the case
 * where the value is NULL (i.e. the allocator that produced it
 * failed) and where PyModule_AddObject() itself fails. The latter
 * does not steal the reference on failure, so the value must be
 * decremented in that case. Returns 0 on success, -1 on failure.
 */

extern int wsgi_module_add_object(PyObject *module, const char *name,
                                  PyObject *value);

/*
 * Build the embedded mod_wsgi module for the current Python
 * sub-interpreter and install it as sys.modules['mod_wsgi']. The
 * module is built via PEP 489 multi-phase init; its exec slot
 * populates WSGIModuleState with the heap-allocated PyTypeObjects
 * needed by the rest of interp setup. If the upstream mod_wsgi
 * PyPi companion package is on the import path, its __path__ is
 * copied across first so subpackage imports continue to resolve.
 *
 * Called early in interpreter setup, before any code that
 * constructs an instance of one of the heap types (Restricted,
 * SignalIntercept, etc.) so the type pointers are reachable via
 * PyImport_ImportModule + PyModule_GetState.
 *
 * `name` is the application group of the interpreter being set
 * up (the empty string for the main interpreter). It is used
 * only for log header context if the import of the upstream
 * Python companion package raises an exception other than
 * ModuleNotFoundError.
 *
 * Returns 0 on success, -1 on failure with Python exception set.
 */

extern int wsgi_module_init_state(const char *name);

/*
 * Populate the embedded mod_wsgi module with all its attributes:
 * the common ones (version, FileWrapper, RequestTimeout,
 * methods, empty containers) and the per-interpreter runtime
 * ones (process_group, application_group, maximum_processes,
 * threads_per_process). Looks the module up from sys.modules;
 * wsgi_module_init_state must have been called earlier in the
 * same interpreter.
 *
 * Returns an owned reference to the module, or NULL on failure
 * with Python exception set.
 */

extern PyObject *wsgi_module_populate(const char *name);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
