/* ------------------------------------------------------------------------- */

/*
 * Copyright 2007-2015 GRAHAM DUMPLETON
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

/* ------------------------------------------------------------------------- */

/*
 * Thread utilisation. On start and end of requests,
 * and when utilisation is requested, we acrue an
 * ongoing utilisation time value so can monitor how
 * busy we are handling requests.
 */

apr_uint64_t wsgi_total_requests = 0;
int wsgi_active_requests = 0;
static double wsgi_thread_utilization = 0.0;
static apr_time_t wsgi_utilization_last = 0;
int wsgi_dump_stack_traces = 0;

/* Request tracking and timing. */

apr_thread_mutex_t* wsgi_monitor_lock = NULL;

static double wsgi_utilization_time(int adjustment)
{
    apr_time_t now;
    double utilization = wsgi_thread_utilization;
    
    apr_thread_mutex_lock(wsgi_monitor_lock);

    now = apr_time_now();

    if (wsgi_utilization_last != 0.0) {
        utilization = (now - wsgi_utilization_last) / 1000000.0;

        if (utilization < 0)
            utilization = 0;

        utilization = wsgi_active_requests * utilization;
        wsgi_thread_utilization += utilization;
        utilization = wsgi_thread_utilization;
    }

    wsgi_utilization_last = now;
    wsgi_active_requests += adjustment;

    if (adjustment < 0)
        wsgi_total_requests += -adjustment;

    apr_thread_mutex_unlock(wsgi_monitor_lock);

    return utilization;
}

double wsgi_start_request(void)
{
    return wsgi_utilization_time(1);
}

double wsgi_end_request(void)
{
    return wsgi_utilization_time(-1);
}

/* ------------------------------------------------------------------------- */

static int wsgi_interns_initialized = 0;

WSGI_STATIC_INTERNED_STRING(server_limit);
WSGI_STATIC_INTERNED_STRING(thread_limit);
WSGI_STATIC_INTERNED_STRING(running_generation);
WSGI_STATIC_INTERNED_STRING(restart_time);
WSGI_STATIC_INTERNED_STRING(current_time);
WSGI_STATIC_INTERNED_STRING(running_time);
WSGI_STATIC_INTERNED_STRING(process_num);
WSGI_STATIC_INTERNED_STRING(pid);
WSGI_STATIC_INTERNED_STRING(generation);
WSGI_STATIC_INTERNED_STRING(quiescing);
WSGI_STATIC_INTERNED_STRING(workers);
WSGI_STATIC_INTERNED_STRING(thread_num);
WSGI_STATIC_INTERNED_STRING(status);
WSGI_STATIC_INTERNED_STRING(access_count);
WSGI_STATIC_INTERNED_STRING(bytes_served);
WSGI_STATIC_INTERNED_STRING(start_time);
WSGI_STATIC_INTERNED_STRING(stop_time);
WSGI_STATIC_INTERNED_STRING(last_used);
WSGI_STATIC_INTERNED_STRING(client);
WSGI_STATIC_INTERNED_STRING(request);
WSGI_STATIC_INTERNED_STRING(vhost);
WSGI_STATIC_INTERNED_STRING(processes);

WSGI_STATIC_INTERNED_STRING(request_count);
WSGI_STATIC_INTERNED_STRING(request_busy_time);
WSGI_STATIC_INTERNED_STRING(memory_max_rss);
WSGI_STATIC_INTERNED_STRING(memory_rss);
WSGI_STATIC_INTERNED_STRING(cpu_user_time);
WSGI_STATIC_INTERNED_STRING(cpu_system_time);

static PyObject *wsgi_status_flags[SERVER_NUM_STATUS];

#define WSGI_CREATE_STATUS_FLAG(name, val) \
    wsgi_status_flags[name] = wsgi_PyString_InternFromString(val)

static void wsgi_initialize_interned_strings(void)
{
    /* Initialise interned strings the first time. */

    if (!wsgi_interns_initialized) {
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

        wsgi_interns_initialized = 1;
    }
}

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_process_metrics(void)
{
    PyObject *result = NULL;

    PyObject *object = NULL;

#ifdef HAVE_TIMES
    struct tms tmsbuf; 
    static float tick = 0.0;
#endif

    apr_time_t current_time;
    apr_interval_time_t running_time;

    if (!wsgi_interns_initialized)
        wsgi_initialize_interned_strings();

#if 0
    if (!wsgi_daemon_pool) {
        if (!wsgi_server_config->server_metrics) {
            Py_INCREF(Py_None);

            return Py_None;
        }
    }
#if defined(MOD_WSGI_WITH_DAEMONS)
    else {
        if (!wsgi_daemon_process->group->server_metrics) {
            Py_INCREF(Py_None);

            return Py_None;
        }
    }
#endif
#endif

    result = PyDict_New();

        object = wsgi_PyInt_FromLong(getpid());
        PyDict_SetItem(result,
                WSGI_INTERNED_STRING(pid), object);
        Py_DECREF(object);

    object = wsgi_PyInt_FromLongLong(wsgi_total_requests);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(request_count), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(wsgi_utilization_time(0));
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(request_busy_time), object);
    Py_DECREF(object);

    object = wsgi_PyInt_FromLongLong(wsgi_get_peak_memory_RSS());
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(memory_max_rss), object);
    Py_DECREF(object);

    object = wsgi_PyInt_FromLongLong(wsgi_get_current_memory_RSS());
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(memory_rss), object);
    Py_DECREF(object);

#ifdef HAVE_TIMES
    if (!tick) {
#ifdef _SC_CLK_TCK
        tick = sysconf(_SC_CLK_TCK);
#else
        tick = HZ;
#endif
    }

    times(&tmsbuf);

    object = PyFloat_FromDouble(tmsbuf.tms_utime / tick);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(cpu_user_time), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(tmsbuf.tms_stime / tick);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(cpu_system_time), object);
    Py_DECREF(object);
#endif

    object = PyFloat_FromDouble(apr_time_sec((double)wsgi_restart_time));
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(restart_time), object);
    Py_DECREF(object);

    current_time = apr_time_now();

    object = PyFloat_FromDouble(apr_time_sec((double)current_time));
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(current_time), object);
    Py_DECREF(object);

    running_time = (apr_uint32_t)apr_time_sec((double)
            current_time - wsgi_restart_time);

    object = wsgi_PyInt_FromLongLong(running_time);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(running_time), object);
    Py_DECREF(object);

    return result;
}

PyMethodDef wsgi_process_metrics_method[] = {
    { "process_metrics",    (PyCFunction)wsgi_process_metrics,
                            METH_NOARGS, 0 },
    { NULL },
};

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_server_metrics(void)
{
    PyObject *scoreboard_dict = NULL;

    PyObject *process_list = NULL;

    PyObject *object = NULL;

    apr_time_t current_time;
    apr_interval_time_t running_time;

    global_score *gs_record;
    worker_score *ws_record;
    process_score *ps_record;

    int j, i;

    if (!wsgi_interns_initialized)
        wsgi_initialize_interned_strings();

    /* Scoreboard needs to exist and server metrics enabled. */

    if (!ap_exists_scoreboard_image()) {
        Py_INCREF(Py_None);

        return Py_None;
    }

    if (!wsgi_daemon_pool) {
        if (!wsgi_server_config->server_metrics) {
            Py_INCREF(Py_None);

            return Py_None;
        }
    }
#if defined(MOD_WSGI_WITH_DAEMONS)
    else {
        if (!wsgi_daemon_process->group->server_metrics) {
            Py_INCREF(Py_None);

            return Py_None;
        }
    }
#endif

    gs_record = ap_get_scoreboard_global();

    if (!gs_record) {
        Py_INCREF(Py_None);

        return Py_None;
    }

    /* Return everything in a dictionary. Start with global. */

    scoreboard_dict = PyDict_New();

    object = wsgi_PyInt_FromLong(gs_record->server_limit);
    PyDict_SetItem(scoreboard_dict,
            WSGI_INTERNED_STRING(server_limit), object);
    Py_DECREF(object);

    object = wsgi_PyInt_FromLong(gs_record->thread_limit);
    PyDict_SetItem(scoreboard_dict,
            WSGI_INTERNED_STRING(thread_limit), object);
    Py_DECREF(object);

    object = wsgi_PyInt_FromLong(gs_record->running_generation);
    PyDict_SetItem(scoreboard_dict,
            WSGI_INTERNED_STRING(running_generation), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(apr_time_sec((
            double)gs_record->restart_time));
    PyDict_SetItem(scoreboard_dict,
            WSGI_INTERNED_STRING(restart_time), object);
    Py_DECREF(object);

    current_time = apr_time_now();

    object = PyFloat_FromDouble(apr_time_sec((double)current_time));
    PyDict_SetItem(scoreboard_dict,
            WSGI_INTERNED_STRING(current_time), object);
    Py_DECREF(object);

    running_time = (apr_uint32_t)apr_time_sec((double)
            current_time - ap_scoreboard_image->global->restart_time);

    object = wsgi_PyInt_FromLongLong(running_time);
    PyDict_SetItem(scoreboard_dict,
            WSGI_INTERNED_STRING(running_time), object);
    Py_DECREF(object);

    /* Now add in the processes/workers. */

    process_list = PyList_New(0);

    for (i = 0; i < gs_record->server_limit; ++i) {
        PyObject *process_dict = NULL;
        PyObject *worker_list = NULL;

        ps_record = ap_get_scoreboard_process(i);

        process_dict = PyDict_New();
        PyList_Append(process_list, process_dict);

        object = wsgi_PyInt_FromLong(i);
        PyDict_SetItem(process_dict,
                WSGI_INTERNED_STRING(process_num), object);
        Py_DECREF(object);

        object = wsgi_PyInt_FromLong(ps_record->pid);
        PyDict_SetItem(process_dict,
                WSGI_INTERNED_STRING(pid), object);
        Py_DECREF(object);

        object = wsgi_PyInt_FromLong(ps_record->generation);
        PyDict_SetItem(process_dict,
                WSGI_INTERNED_STRING(generation), object);
        Py_DECREF(object);

        object = PyBool_FromLong(ps_record->quiescing);
        PyDict_SetItem(process_dict,
                WSGI_INTERNED_STRING(quiescing), object);
        Py_DECREF(object);

        worker_list = PyList_New(0);
        PyDict_SetItem(process_dict,
                WSGI_INTERNED_STRING(workers), worker_list);

        for (j = 0; j < gs_record->thread_limit; ++j) {
            PyObject *worker_dict = NULL;

#if AP_MODULE_MAGIC_AT_LEAST(20071023,0)
            ws_record = ap_get_scoreboard_worker_from_indexes(i, j);
#else
            ws_record = ap_get_scoreboard_worker(i, j);
#endif

            worker_dict = PyDict_New();

            PyList_Append(worker_list, worker_dict);

            object = wsgi_PyInt_FromLong(ws_record->thread_num);
            PyDict_SetItem(worker_dict,
                    WSGI_INTERNED_STRING(thread_num), object);
            Py_DECREF(object);

            object = wsgi_PyInt_FromLong(ws_record->generation);
            PyDict_SetItem(worker_dict,
                    WSGI_INTERNED_STRING(generation), object);
            Py_DECREF(object);

            object = wsgi_status_flags[ws_record->status];
            PyDict_SetItem(worker_dict,
                    WSGI_INTERNED_STRING(status), object);

            object = wsgi_PyInt_FromLong(ws_record->access_count);
            PyDict_SetItem(worker_dict,
                    WSGI_INTERNED_STRING(access_count), object);
            Py_DECREF(object);

            object = wsgi_PyInt_FromUnsignedLongLong(ws_record->bytes_served);
            PyDict_SetItem(worker_dict,
                    WSGI_INTERNED_STRING(bytes_served), object);
            Py_DECREF(object);

            object = PyFloat_FromDouble(apr_time_sec(
                    (double)ws_record->start_time));
            PyDict_SetItem(worker_dict,
                    WSGI_INTERNED_STRING(start_time), object);
            Py_DECREF(object);

            object = PyFloat_FromDouble(apr_time_sec(
                    (double)ws_record->stop_time));
            PyDict_SetItem(worker_dict,
                    WSGI_INTERNED_STRING(stop_time), object);
            Py_DECREF(object);

            object = PyFloat_FromDouble(apr_time_sec(
                    (double)ws_record->last_used));
            PyDict_SetItem(worker_dict,
                    WSGI_INTERNED_STRING(last_used), object);
            Py_DECREF(object);

            object = wsgi_PyString_FromString(ws_record->client);
            PyDict_SetItem(worker_dict,
                    WSGI_INTERNED_STRING(client), object);
            Py_DECREF(object);

            object = wsgi_PyString_FromString(ws_record->request);
            PyDict_SetItem(worker_dict,
                    WSGI_INTERNED_STRING(request), object);
            Py_DECREF(object);

            object = wsgi_PyString_FromString(ws_record->vhost);
            PyDict_SetItem(worker_dict,
                    WSGI_INTERNED_STRING(vhost), object);
            Py_DECREF(object);

            Py_DECREF(worker_dict);
        }

        Py_DECREF(worker_list);
        Py_DECREF(process_dict);
    }

    PyDict_SetItem(scoreboard_dict,
            WSGI_INTERNED_STRING(processes), process_list);
    Py_DECREF(process_list);

    return scoreboard_dict;
}

/* ------------------------------------------------------------------------- */

PyMethodDef wsgi_server_metrics_method[] = {
    { "server_metrics",     (PyCFunction)wsgi_server_metrics,
                            METH_NOARGS, 0 },
    { NULL },
};

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
