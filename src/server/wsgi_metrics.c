/* ------------------------------------------------------------------------- */

/*
 * Copyright 2007-2014 GRAHAM DUMPLETON
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

/* ------------------------------------------------------------------------- */

/*
 * Thread utilisation. On start and end of requests,
 * and when utilisation is requested, we acrue an
 * ongoing utilisation time value so can monitor how
 * busy we are handling requests.
 */

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

static PyObject *wsgi_process_status(void)
{
    PyObject *result = NULL;

    PyObject *object = NULL;

    result = PyDict_New();

    object = PyFloat_FromDouble(wsgi_utilization_time(0));
    PyDict_SetItemString(result, "thread_utilization", object);
    Py_DECREF(object);

    return result;
}

PyMethodDef wsgi_process_status_method[] = {
    { "process_status", (PyCFunction)wsgi_process_status,
                            METH_NOARGS, 0 },
    { NULL },
};

/* ------------------------------------------------------------------------- */

static PyObject *wsgi_apache_server_status(void)
{
    PyObject *result = NULL;

    PyObject *object = NULL;

    apr_time_t now_time;
    apr_interval_time_t up_time;

    ap_generation_t mpm_generation;

    int j, i, res;
    int ready;
    int busy;
    unsigned long count;
    unsigned long lres;
    apr_off_t bytes;
    apr_off_t bcount, kbcount;
    worker_score *ws_record;
    process_score *ps_record;

    int server_limit = 0;
    int thread_limit = 0;

    /* Scoreboard is not available in inetd mode. Give up now. */

    if (!ap_exists_scoreboard_image())
        return PyDict_New();

    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);

    now_time = apr_time_now();
    up_time = (apr_uint32_t)apr_time_sec(
            now_time - ap_scoreboard_image->global->restart_time);

#if defined(AP_MPMQ_GENERATION)
    ap_mpm_query(AP_MPMQ_GENERATION, &mpm_generation);
#else
    mpm_generation = ap_my_generation;
#endif

    ready = 0;
    busy = 0;
    count = 0;
    bcount = 0;
    kbcount = 0;

    for (i = 0; i < server_limit; ++i) {
        ps_record = ap_get_scoreboard_process(i);
        for (j = 0; j < thread_limit; ++j) {
            int indx = (i * thread_limit) + j;

#if AP_MODULE_MAGIC_AT_LEAST(20071023,0)
            ws_record = ap_get_scoreboard_worker_from_indexes(i, j);
#else
            ws_record = ap_get_scoreboard_worker(i, j);
#endif
            res = ws_record->status;

            if (!ps_record->quiescing
                && ps_record->pid) {
                if (res == SERVER_READY) {
                    if (ps_record->generation == mpm_generation)
                        ready++;
                }
                else if (res != SERVER_DEAD &&
                         res != SERVER_STARTING &&
                         res != SERVER_IDLE_KILL) {
                    busy++;
                }
            }

            lres = ws_record->access_count;
            bytes = ws_record->bytes_served;

            if (lres != 0 || (res != SERVER_READY && res != SERVER_DEAD)) {
                count += lres;
                bcount += bytes;

                if (bcount >= 1024) {
                    kbcount += (bcount >> 10);
                    bcount = bcount & 0x3ff;
                }
            }
        }
    }

    /*
     * Generate the dictionary for the server status from the
     * calculated values.
     */

    result = PyDict_New();

    object = PyInt_FromLong(now_time);
    PyDict_SetItemString(result, "time", object);
    Py_DECREF(object);

    object = PyInt_FromLong(up_time);
    PyDict_SetItemString(result, "uptime", object);
    Py_DECREF(object);

    object = PyInt_FromLong(mpm_generation);
    PyDict_SetItemString(result, "generation", object);
    Py_DECREF(object);

    object = PyInt_FromLong(count);
    PyDict_SetItemString(result, "total_accesses", object);
    Py_DECREF(object);

    object = PyInt_FromLong(kbcount);
    PyDict_SetItemString(result, "total_kbytes", object);
    Py_DECREF(object);

    object = PyInt_FromLong(busy);
    PyDict_SetItemString(result, "busy_workers", object);
    Py_DECREF(object);

    object = PyInt_FromLong(ready);
    PyDict_SetItemString(result, "idle_workers", object);
    Py_DECREF(object);

    return result;
}

PyMethodDef wsgi_apache_server_status_method[] = {
    { "server_status",      (PyCFunction)wsgi_apache_server_status,
                            METH_NOARGS, 0 },
    { NULL },
};

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
