/* ------------------------------------------------------------------------- */

/*
 * Copyright 2007-2021 GRAHAM DUMPLETON
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
#include "wsgi_logger.h"
#include "wsgi_thread.h"

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

/* Request tracking and timing. */

apr_thread_mutex_t* wsgi_monitor_lock = NULL;

static double wsgi_utilization_time(int adjustment,
        apr_uint64_t* request_count)
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

    if (request_count)
        *request_count = wsgi_total_requests;

    apr_thread_mutex_unlock(wsgi_monitor_lock);

    return utilization;
}

static int wsgi_request_metrics_enabled = 0;
static apr_uint64_t wsgi_sample_requests = 0;
static double wsgi_server_time_total = 0;
static int wsgi_server_time_buckets[16];
static double wsgi_queue_time_total = 0;
static int wsgi_queue_time_buckets[16];
static double wsgi_daemon_time_total = 0;
static int wsgi_daemon_time_buckets[16];
static double wsgi_application_time_total = 0;
static int wsgi_application_time_buckets[16];
static int* wsgi_request_threads_buckets = NULL; 

void wsgi_record_time_in_buckets(int* buckets, double duration) {
    int index = 0;
    double threshold = 0.005;

    while (index < 14) {
        if (duration <= threshold)
        {
            buckets[index] += 1;
            return;
        }

        threshold *= 2;
        index += 1;
    }

    buckets[index] += 1;
}

void wsgi_record_request_times(apr_time_t request_start,
        apr_time_t queue_start, apr_time_t daemon_start,
        apr_time_t application_start, apr_time_t application_finish) {

    double server_time = 0.0;
    double queue_time = 0.0;
    double daemon_time = 0.0;
    double application_time = 0.0;

    if (wsgi_request_metrics_enabled == 0)
        return;

    if (queue_start) {
        server_time = apr_time_sec((double)(queue_start-request_start));
        queue_time = apr_time_sec((double)(daemon_start-queue_start));
        daemon_time = apr_time_sec((double)(application_start-daemon_start));
    }
    else {
        server_time = apr_time_sec((double)(application_start-request_start));
        daemon_time = 0;
        queue_time = 0;
    }

    application_time = (apr_time_sec((double)(application_finish-
            application_start)));

    apr_thread_mutex_lock(wsgi_monitor_lock);

    wsgi_sample_requests += 1;
    wsgi_server_time_total += server_time;
    wsgi_queue_time_total += queue_time;
    wsgi_daemon_time_total += daemon_time;
    wsgi_application_time_total += application_time;

    wsgi_record_time_in_buckets(&wsgi_server_time_buckets[0],
            server_time);

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process) {
        wsgi_record_time_in_buckets(&wsgi_queue_time_buckets[0],
                queue_time);
        wsgi_record_time_in_buckets(&wsgi_daemon_time_buckets[0],
                daemon_time);
    }
#endif

    wsgi_record_time_in_buckets(&wsgi_application_time_buckets[0],
            application_time);

    apr_thread_mutex_unlock(wsgi_monitor_lock);
}

WSGIThreadInfo *wsgi_start_request(request_rec *r)
{
    WSGIThreadInfo *thread_info;

    PyObject *module = NULL;

    thread_info = wsgi_thread_info(1, 1);

    thread_info->request_data = PyDict_New();

#if AP_MODULE_MAGIC_AT_LEAST(20100923,2)
#if PY_MAJOR_VERSION >= 3
    thread_info->request_id = PyUnicode_DecodeLatin1(r->log_id,
                                                strlen(r->log_id), NULL);
#else
    thread_info->request_id = PyString_FromString(r->log_id);
#endif

    module = PyImport_ImportModule("mod_wsgi");

    if (module) {
        PyObject *dict = NULL;
        PyObject *requests = NULL;

        dict = PyModule_GetDict(module);
        requests = PyDict_GetItemString(dict, "active_requests");

        if (requests)
            PyDict_SetItem(requests, thread_info->request_id,
                           thread_info->request_data);

        Py_DECREF(module);
    }
    else
        PyErr_Clear();
#endif

    wsgi_utilization_time(1, NULL);

    return thread_info;
}

void wsgi_end_request(void)
{
    WSGIThreadInfo *thread_info;

    PyObject *module = NULL;

    thread_info = wsgi_thread_info(0, 1);

    if (thread_info) {
        if (wsgi_request_threads_buckets)
            wsgi_request_threads_buckets[thread_info->thread_id-1] += 1;

#if AP_MODULE_MAGIC_AT_LEAST(20100923,2)
        module = PyImport_ImportModule("mod_wsgi");

        if (module) {
            PyObject *dict = NULL;
            PyObject *requests = NULL;

            dict = PyModule_GetDict(module);
            requests = PyDict_GetItemString(dict, "active_requests");

            PyDict_DelItem(requests, thread_info->request_id);

            Py_DECREF(module);
        }
        else
            PyErr_Clear();
#endif

        if (thread_info->log_buffer)
            Py_CLEAR(thread_info->log_buffer);

        if (thread_info->request_id)
            Py_CLEAR(thread_info->request_id);

        if (thread_info->request_data)
            Py_CLEAR(thread_info->request_data);
    }

    wsgi_utilization_time(-1, NULL);
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
WSGI_STATIC_INTERNED_STRING(request_threads);
WSGI_STATIC_INTERNED_STRING(active_requests);
WSGI_STATIC_INTERNED_STRING(threads);
WSGI_STATIC_INTERNED_STRING(thread_id);

WSGI_STATIC_INTERNED_STRING(sample_period);
WSGI_STATIC_INTERNED_STRING(request_threads_maximum);
WSGI_STATIC_INTERNED_STRING(request_threads_started);
WSGI_STATIC_INTERNED_STRING(request_threads_active);
WSGI_STATIC_INTERNED_STRING(capacity_utilization);
WSGI_STATIC_INTERNED_STRING(request_throughput);
WSGI_STATIC_INTERNED_STRING(server_time);
WSGI_STATIC_INTERNED_STRING(queue_time);
WSGI_STATIC_INTERNED_STRING(daemon_time);
WSGI_STATIC_INTERNED_STRING(application_time);
WSGI_STATIC_INTERNED_STRING(server_time_buckets);
WSGI_STATIC_INTERNED_STRING(queue_time_buckets);
WSGI_STATIC_INTERNED_STRING(daemon_time_buckets);
WSGI_STATIC_INTERNED_STRING(application_time_buckets);
WSGI_STATIC_INTERNED_STRING(request_threads_buckets);

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
        WSGI_CREATE_INTERNED_STRING_ID(request_threads);
        WSGI_CREATE_INTERNED_STRING_ID(active_requests);
        WSGI_CREATE_INTERNED_STRING_ID(threads);
        WSGI_CREATE_INTERNED_STRING_ID(thread_id);

        WSGI_CREATE_INTERNED_STRING_ID(sample_period);
        WSGI_CREATE_INTERNED_STRING_ID(request_threads_maximum);
        WSGI_CREATE_INTERNED_STRING_ID(request_threads_started);
        WSGI_CREATE_INTERNED_STRING_ID(request_threads_active);
        WSGI_CREATE_INTERNED_STRING_ID(capacity_utilization);
        WSGI_CREATE_INTERNED_STRING_ID(request_throughput);
        WSGI_CREATE_INTERNED_STRING_ID(server_time);
        WSGI_CREATE_INTERNED_STRING_ID(queue_time);
        WSGI_CREATE_INTERNED_STRING_ID(daemon_time);
        WSGI_CREATE_INTERNED_STRING_ID(application_time);
        WSGI_CREATE_INTERNED_STRING_ID(server_time_buckets);
        WSGI_CREATE_INTERNED_STRING_ID(daemon_time_buckets);
        WSGI_CREATE_INTERNED_STRING_ID(queue_time_buckets);
        WSGI_CREATE_INTERNED_STRING_ID(application_time_buckets);
        WSGI_CREATE_INTERNED_STRING_ID(request_threads_buckets);

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

static PyObject *wsgi_request_metrics(void)
{
    PyObject *result = NULL;

    PyObject *object = NULL;

    apr_time_t stop_time;
    double stop_request_busy_time = 0.0;
    apr_uint64_t stop_request_count = 0.0;

    double request_busy_time = 0.0;
    double capacity_utilization = 0.0;

    static double start_time = 0.0;
    static double start_cpu_system_time = 0.0;
    static double start_cpu_user_time = 0.0;
    static double start_request_busy_time = 0.0;
    static apr_uint64_t start_request_count = 0;

    double sample_period = 0.0;
    apr_uint64_t request_count = 0;
    double request_throughput = 0.0;
    double stop_cpu_system_time = 0.0;
    double stop_cpu_user_time = 0.0;

    double cpu_system_time = 0.0;
    double cpu_user_time = 0.0;
    double total_cpu_time = 0.0;

    static int request_threads_maximum = 0;

    apr_uint64_t interval_requests = 0;
    double server_time_total = 0;
    double server_time_avg = 0;
    double queue_time_total = 0;
    double queue_time_avg = 0;
    double daemon_time_total = 0;
    double daemon_time_avg = 0;
    double application_time_total = 0;
    double application_time_avg = 0;

    int request_threads_active = 0;

    int i;

#ifdef HAVE_TIMES
    struct tms tmsbuf; 
    static float tick = 0.0;

    if (!tick) {
#ifdef _SC_CLK_TCK
        tick = sysconf(_SC_CLK_TCK);
#else
        tick = HZ;
#endif
    }
#endif

    if (!wsgi_interns_initialized)
        wsgi_initialize_interned_strings();

    if (!request_threads_maximum) {
        int is_threaded = 0;

#if defined(MOD_WSGI_WITH_DAEMONS)
        if (wsgi_daemon_process) {
            request_threads_maximum = wsgi_daemon_process->group->threads;
        }
        else {
            ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded);
            if (is_threaded != AP_MPMQ_NOT_SUPPORTED) {
                ap_mpm_query(AP_MPMQ_MAX_THREADS, &request_threads_maximum);
            }
        }
#else
        ap_mpm_query(AP_MPMQ_IS_THREADED, &is_threaded);
        if (is_threaded != AP_MPMQ_NOT_SUPPORTED) {
            ap_mpm_query(AP_MPMQ_MAX_THREADS, &request_threads_maximum);
        }
#endif

        request_threads_maximum = ((request_threads_maximum <= 0) ? 1 :
                request_threads_maximum);

        wsgi_request_threads_buckets = (int *)apr_pcalloc(
                wsgi_server_config->pool, request_threads_maximum*sizeof(
                wsgi_request_threads_buckets[0]));
    }


    result = PyDict_New();

    stop_time = apr_time_now();
    stop_request_busy_time = wsgi_utilization_time(0, &stop_request_count);

    if (!start_time) {
        start_time = stop_time;
        start_request_busy_time = stop_request_busy_time;
        start_request_count = stop_request_count;

#ifdef HAVE_TIMES
        times(&tmsbuf);

        start_cpu_user_time = tmsbuf.tms_utime / tick;
        start_cpu_system_time = tmsbuf.tms_stime / tick;
#else
        start_cpu_user_time = 0.0;
        start_cpu_system_time = 0.0;
#endif

        apr_thread_mutex_lock(wsgi_monitor_lock);

        wsgi_sample_requests = 0;
        wsgi_server_time_total = 0.0;
        wsgi_queue_time_total = 0.0;
        wsgi_daemon_time_total = 0.0;
        wsgi_application_time_total = 0.0;

        wsgi_request_metrics_enabled = 1;

        apr_thread_mutex_unlock(wsgi_monitor_lock);

        return result;
    }

    object = wsgi_PyInt_FromLong(getpid());
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(pid), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(apr_time_sec((double)start_time));
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(start_time), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(apr_time_sec((double)stop_time));
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(stop_time), object);
    Py_DECREF(object);

    sample_period = (apr_time_sec((double)stop_time) -
            apr_time_sec((double)start_time));

    object = PyFloat_FromDouble(sample_period);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(sample_period), object);
    Py_DECREF(object);

#ifdef HAVE_TIMES
    times(&tmsbuf);

    stop_cpu_user_time = tmsbuf.tms_utime / tick;
    stop_cpu_system_time = tmsbuf.tms_stime / tick;

    cpu_user_time = ((stop_cpu_user_time - start_cpu_user_time) /
            sample_period);
    cpu_system_time = ((stop_cpu_system_time - start_cpu_system_time) /
            sample_period);

    total_cpu_time += cpu_user_time;
    total_cpu_time += cpu_system_time;

    object = PyFloat_FromDouble(cpu_user_time);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(cpu_user_time), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(cpu_system_time);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(cpu_system_time), object);
    Py_DECREF(object);
#else
    object = PyFloat_FromDouble(0.0);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(cpu_user_time), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(0.0);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(cpu_system_time), object);
    Py_DECREF(object);
#endif

    object = wsgi_PyInt_FromLongLong(wsgi_get_peak_memory_RSS());
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(memory_max_rss), object);
    Py_DECREF(object);

    object = wsgi_PyInt_FromLongLong(wsgi_get_current_memory_RSS());
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(memory_rss), object);
    Py_DECREF(object);

    object = wsgi_PyInt_FromLong(request_threads_maximum);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(request_threads_maximum), object);
    Py_DECREF(object);

    object = wsgi_PyInt_FromLong(wsgi_request_threads);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(request_threads_started), object);
    Py_DECREF(object);

    request_busy_time = stop_request_busy_time - start_request_busy_time;

    capacity_utilization = (request_busy_time / sample_period /
            request_threads_maximum);

    object = PyFloat_FromDouble(capacity_utilization);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(capacity_utilization), object);
    Py_DECREF(object);

    request_count = stop_request_count - start_request_count;

    object = wsgi_PyInt_FromLongLong(request_count);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(request_count), object);
    Py_DECREF(object);

    request_throughput = sample_period ? request_count / sample_period : 0;

    object = PyFloat_FromDouble(request_throughput);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(request_throughput), object);
    Py_DECREF(object);

    start_time = stop_time;
    start_request_busy_time = stop_request_busy_time;
    start_request_count = stop_request_count;
    start_cpu_user_time = stop_cpu_user_time;
    start_cpu_system_time = stop_cpu_system_time;

    apr_thread_mutex_lock(wsgi_monitor_lock);

    interval_requests = wsgi_sample_requests;
    server_time_total = wsgi_server_time_total;
    queue_time_total = wsgi_queue_time_total;
    daemon_time_total = wsgi_daemon_time_total;
    application_time_total = wsgi_application_time_total;

    object = PyList_New(16);
    for (i=0; i<16; i++) {
        PyList_SET_ITEM(object, i, wsgi_PyInt_FromLong(
                    wsgi_server_time_buckets[i]));
    }
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(server_time_buckets), object);
    Py_DECREF(object);

    object = PyList_New(16);
    for (i=0; i<16; i++) {
        PyList_SET_ITEM(object, i, wsgi_PyInt_FromLong(
                    wsgi_queue_time_buckets[i]));
    }
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(queue_time_buckets), object);
    Py_DECREF(object);

    object = PyList_New(16);
    for (i=0; i<16; i++) {
        PyList_SET_ITEM(object, i, wsgi_PyInt_FromLong(
                    wsgi_daemon_time_buckets[i]));
    }
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(daemon_time_buckets), object);
    Py_DECREF(object);

    object = PyList_New(16);
    for (i=0; i<16; i++) {
        PyList_SET_ITEM(object, i, wsgi_PyInt_FromLong(
                    wsgi_application_time_buckets[i]));
    }
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(application_time_buckets), object);
    Py_DECREF(object);

    object = PyList_New(request_threads_maximum);
    for (i=0; i<request_threads_maximum; i++) {
        PyList_SET_ITEM(object, i, wsgi_PyInt_FromLong(
                    wsgi_request_threads_buckets[i]));
        if (wsgi_request_threads_buckets[i])
            request_threads_active++;
    }
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(request_threads_buckets), object);
    Py_DECREF(object);

    object = wsgi_PyInt_FromLong(request_threads_active);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(request_threads_active), object);
    Py_DECREF(object);

    wsgi_sample_requests = 0;
    wsgi_server_time_total = 0.0;
    wsgi_queue_time_total = 0.0;
    wsgi_daemon_time_total = 0.0;
    wsgi_application_time_total = 0.0;

    memset(&wsgi_server_time_buckets, 0,
            sizeof(wsgi_server_time_buckets));
    memset(&wsgi_queue_time_buckets, 0,
            sizeof(wsgi_queue_time_buckets));
    memset(&wsgi_daemon_time_buckets, 0,
            sizeof(wsgi_daemon_time_buckets));
    memset(&wsgi_application_time_buckets, 0,
            sizeof(wsgi_application_time_buckets));

    memset(wsgi_request_threads_buckets, 0, request_threads_maximum*
            sizeof(wsgi_request_threads_buckets[0]));

    apr_thread_mutex_unlock(wsgi_monitor_lock);

    server_time_avg = 0;
    queue_time_avg = 0;
    daemon_time_avg = 0;
    application_time_avg = 0;

    if (interval_requests) {
        server_time_avg = server_time_total / interval_requests;
        queue_time_avg = queue_time_total / interval_requests;
        daemon_time_avg = daemon_time_total / interval_requests;
        application_time_avg = application_time_total / interval_requests;
    }

    object = PyFloat_FromDouble(server_time_avg);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(server_time), object);
    Py_DECREF(object);

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (wsgi_daemon_process) {
        object = PyFloat_FromDouble(queue_time_avg);
        PyDict_SetItem(result,
                WSGI_INTERNED_STRING(queue_time), object);
        Py_DECREF(object);

        object = PyFloat_FromDouble(daemon_time_avg);
        PyDict_SetItem(result,
                WSGI_INTERNED_STRING(daemon_time), object);
        Py_DECREF(object);
    }
    else {
        PyDict_SetItem(result,
                WSGI_INTERNED_STRING(queue_time), Py_None);
        PyDict_SetItem(result,
                WSGI_INTERNED_STRING(daemon_time), Py_None);
    }
#else
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(queue_time), Py_None);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(daemon_time), Py_None);
#endif

    object = PyFloat_FromDouble(application_time_avg);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(application_time), object);
    Py_DECREF(object);

    return result;
}

PyMethodDef wsgi_request_metrics_method[] = {
    { "request_metrics",    (PyCFunction)wsgi_request_metrics,
                            METH_NOARGS, 0 },
    { NULL },
};

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_process_metrics(void)
{
    PyObject *result = NULL;

    PyObject *object = NULL;

    PyObject *thread_list = NULL;
    WSGIThreadInfo **thread_info = NULL;

    apr_uint64_t request_count = 0;

    int i;

#ifdef HAVE_TIMES
    struct tms tmsbuf; 
    static float tick = 0.0;
#endif

    apr_time_t current_time;
    apr_interval_time_t running_time;

    if (!wsgi_interns_initialized)
        wsgi_initialize_interned_strings();

    result = PyDict_New();

    object = wsgi_PyInt_FromLong(getpid());
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(pid), object);
    Py_DECREF(object);

    object = PyFloat_FromDouble(wsgi_utilization_time(0, &request_count));
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(request_busy_time), object);
    Py_DECREF(object);

    object = wsgi_PyInt_FromLongLong(request_count);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(request_count), object);
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

    object = wsgi_PyInt_FromLong(wsgi_request_threads);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(request_threads), object);
    Py_DECREF(object);

    object = wsgi_PyInt_FromLong(wsgi_active_requests);
    PyDict_SetItem(result,
            WSGI_INTERNED_STRING(active_requests), object);
    Py_DECREF(object);

    thread_list = PyList_New(0);

    PyDict_SetItem(result, WSGI_INTERNED_STRING(threads), thread_list);

    thread_info = (WSGIThreadInfo **)wsgi_thread_details->elts;

    for (i=0; i<wsgi_thread_details->nelts; i++) {
        PyObject *entry = NULL;

        if (thread_info[i]->request_thread) {
            entry = PyDict_New();

            object = wsgi_PyInt_FromLong(thread_info[i]->thread_id);
            PyDict_SetItem(entry, WSGI_INTERNED_STRING(thread_id), object);
            Py_DECREF(object);

            object = wsgi_PyInt_FromLongLong(thread_info[i]->request_count);
            PyDict_SetItem(entry, WSGI_INTERNED_STRING(request_count), object);
            Py_DECREF(object);

            PyList_Append(thread_list, entry);

            Py_DECREF(entry);
        }
    }

    Py_DECREF(thread_list);

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

static PyObject *wsgi_subscribe_events(PyObject *self, PyObject *args)
{
    PyObject *callback = NULL;

    PyObject *module = NULL;

    if (!PyArg_ParseTuple(args, "O", &callback))
        return NULL;

    module = PyImport_ImportModule("mod_wsgi");

    if (module) {
        PyObject *dict = NULL;
        PyObject *list = NULL;

        dict = PyModule_GetDict(module);
        list = PyDict_GetItemString(dict, "event_callbacks");

        if (list)
            PyList_Append(list, callback);
        else
            return NULL;

        Py_DECREF(module);
    }
    else
        return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *wsgi_subscribe_shutdown(PyObject *self, PyObject *args)
{
    PyObject *callback = NULL;

    PyObject *module = NULL;

    if (!PyArg_ParseTuple(args, "O", &callback))
        return NULL;

    module = PyImport_ImportModule("mod_wsgi");

    if (module) {
        PyObject *dict = NULL;
        PyObject *list = NULL;

        dict = PyModule_GetDict(module);
        list = PyDict_GetItemString(dict, "shutdown_callbacks");

        if (list)
            PyList_Append(list, callback);
        else
            return NULL;

        Py_DECREF(module);
    }
    else
        return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

long wsgi_event_subscribers(void)
{
    PyObject *module = NULL;

    module = PyImport_ImportModule("mod_wsgi");

    if (module) {
        PyObject *dict = NULL;
        PyObject *list = NULL;

        long result = 0;

        dict = PyModule_GetDict(module);
        list = PyDict_GetItemString(dict, "event_callbacks");

        if (list)
            result = PyList_Size(list);

        Py_DECREF(module);

        return result;
    }
    else
        return 0;
}

void wsgi_call_callbacks(const char *name, PyObject *callbacks,
        PyObject *event)
{
    int i;

    for (i=0; i<PyList_Size(callbacks); i++) {
        PyObject *callback = NULL;

        PyObject *res = NULL;
        PyObject *args = NULL;

        callback = PyList_GetItem(callbacks, i);

        Py_INCREF(callback);

        args = Py_BuildValue("(s)", name);

        res = PyObject_Call(callback, args, event);

        if (!res) {
            PyObject *m = NULL;
            PyObject *result = NULL;

            PyObject *type = NULL;
            PyObject *value = NULL;
            PyObject *traceback = NULL;

            Py_BEGIN_ALLOW_THREADS
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                         "mod_wsgi (pid=%d): Exception occurred within "
                         "event callback.", getpid());
            Py_END_ALLOW_THREADS

            PyErr_Fetch(&type, &value, &traceback);
            PyErr_NormalizeException(&type, &value, &traceback);

            if (!value) {
                value = Py_None;
                Py_INCREF(value);
            }

            if (!traceback) {
                traceback = Py_None;
                Py_INCREF(traceback);
            }

            m = PyImport_ImportModule("traceback");

            if (m) {
                PyObject *d = NULL;
                PyObject *o = NULL;
                d = PyModule_GetDict(m);
                o = PyDict_GetItemString(d, "print_exception");
                if (o) {
                    PyObject *log = NULL;
                    PyObject *args = NULL;
                    Py_INCREF(o);
                    log = newLogObject(NULL, APLOG_ERR, NULL, 0);
                    args = Py_BuildValue("(OOOOO)", type, value,
                                         traceback, Py_None, log);
                    result = PyObject_CallObject(o, args);
                    Py_DECREF(args);
                    Py_DECREF(log);
                    Py_DECREF(o);
                }
            }

            if (!result) {
                /*
                 * If can't output exception and traceback then
                 * use PyErr_Print to dump out details of the
                 * exception. For SystemExit though if we do
                 * that the process will actually be terminated
                 * so can only clear the exception information
                 * and keep going.
                 */

                PyErr_Restore(type, value, traceback);

                if (!PyErr_ExceptionMatches(PyExc_SystemExit)) {
                    PyErr_Print();
                    PyErr_Clear();
                }
                else {
                    PyErr_Clear();
                }
            }
            else {
                Py_XDECREF(type);
                Py_XDECREF(value);
                Py_XDECREF(traceback);
            }

            Py_XDECREF(result);

            Py_XDECREF(m);
        }
        else if (PyDict_Check(res)) {
            PyDict_Update(event, res);
        }

        Py_XDECREF(res);

        Py_DECREF(callback);
        Py_DECREF(args);
    }
}

void wsgi_publish_event(const char *name, PyObject *event)
{
    PyObject *module = NULL;

    PyObject *event_callbacks = NULL;
    PyObject *shutdown_callbacks = NULL;

    module = PyImport_ImportModule("mod_wsgi");

    if (module) {
        PyObject *dict = NULL;

        dict = PyModule_GetDict(module);

        event_callbacks = PyDict_GetItemString(dict, "event_callbacks");
        Py_XINCREF(event_callbacks);

        shutdown_callbacks = PyDict_GetItemString(dict, "shutdown_callbacks");
        Py_XINCREF(shutdown_callbacks);

        Py_DECREF(module);
    }
    else {
        Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Unable to import mod_wsgi when "
                     "publishing events.", getpid());
        Py_END_ALLOW_THREADS

        PyErr_Clear();

        return;
    }

    if (!event_callbacks || !shutdown_callbacks) {
        Py_BEGIN_ALLOW_THREADS
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, wsgi_server,
                     "mod_wsgi (pid=%d): Unable to find event subscribers.",
                     getpid());
        Py_END_ALLOW_THREADS

        PyErr_Clear();

        Py_XDECREF(event_callbacks);
        Py_XDECREF(shutdown_callbacks);

        return;
    }

    wsgi_call_callbacks(name, event_callbacks, event);

    if (strcmp(name, "process_stopping") == 0)
        wsgi_call_callbacks(name, shutdown_callbacks, event);

    Py_DECREF(event_callbacks);
    Py_DECREF(shutdown_callbacks);
}

/* ------------------------------------------------------------------------- */

PyMethodDef wsgi_subscribe_events_method[] = {
    { "subscribe_events",   (PyCFunction)wsgi_subscribe_events,
                            METH_VARARGS, 0 },
    { NULL },
};

PyMethodDef wsgi_subscribe_shutdown_method[] = {
    { "subscribe_shutdown", (PyCFunction)wsgi_subscribe_shutdown,
                            METH_VARARGS, 0 },
    { NULL },
};

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_request_data(PyObject *self, PyObject *args)
{
    WSGIThreadInfo *thread_info;

    thread_info = wsgi_thread_info(0, 0);

    if (!thread_info) {
        PyErr_SetString(PyExc_RuntimeError, "no active request for thread");
        return NULL;
    }

    if (!thread_info->request_data) {
        PyErr_SetString(PyExc_RuntimeError, "no active request for thread");
        return NULL;
    }

    Py_INCREF(thread_info->request_data);

    return thread_info->request_data;
}

/* ------------------------------------------------------------------------- */

PyMethodDef wsgi_request_data_method[] = {
    { "request_data",       (PyCFunction)wsgi_request_data,
                            METH_NOARGS, 0 },
    { NULL },
};

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
