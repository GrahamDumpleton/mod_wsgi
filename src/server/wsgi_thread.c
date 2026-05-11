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

#include "wsgi_thread.h"

#include "wsgi_server.h"
#include "wsgi_metrics.h"

#if defined(__APPLE__)
#include <mach/mach_init.h>
#include <mach/thread_act.h>
#include <mach/mach_port.h>
#endif

#if defined(linux)
#include <unistd.h>
#include <sys/syscall.h>
#endif

/* ------------------------------------------------------------------------- */

/*
 * Look up (or lazily create) the per-thread WSGIThreadInfo block.
 *
 * With create=0 the function returns NULL when no entry has been
 * stashed in the threadkey for the calling thread.
 *
 * With create=1 the function does not return NULL: APR pools abort
 * the process on allocation failure (apr_pcalloc / apr_array_push
 * never come back NULL under Apache's default abort handler), so
 * callers passing create=1 may dereference the result unconditionally.
 *
 * The lazy-create path takes the monitor lock around the directory
 * allocation, the directory push, and the total_threads counter
 * increment so two threads first-touching simultaneously cannot race
 * the apr_array_make / apr_array_push or read a torn counter. The
 * request_thread promotion takes the same lock around the
 * request_threads counter increment.
 */
WSGIThreadInfo *wsgi_thread_info(int create, int request)
{
    WSGIProcessMetrics *m = wsgi_process_metrics;
    WSGIThreadInfo *thread_handle = NULL;

    apr_threadkey_private_get((void **)&thread_handle, m->thread_key);

    if (!thread_handle && create)
    {
        WSGIThreadInfo **entry = NULL;

        thread_handle = (WSGIThreadInfo *)apr_pcalloc(
            wsgi_server->process->pool, sizeof(WSGIThreadInfo));

        thread_handle->log_buffer = NULL;

        apr_thread_mutex_lock(m->monitor_lock);

        if (!m->thread_details)
        {
            m->thread_details = apr_array_make(
                wsgi_server->process->pool, 3, sizeof(WSGIThreadInfo *));
        }

        thread_handle->thread_id = m->total_threads++;

        entry = (WSGIThreadInfo **)apr_array_push(m->thread_details);
        *entry = thread_handle;

        apr_thread_mutex_unlock(m->monitor_lock);

        apr_threadkey_private_set(thread_handle, m->thread_key);
    }

    if (thread_handle && request && !thread_handle->request_thread)
    {
        apr_thread_mutex_lock(m->monitor_lock);
        thread_handle->request_thread = 1;
        m->request_threads++;
        apr_thread_mutex_unlock(m->monitor_lock);
    }

    return thread_handle;
}

/* ------------------------------------------------------------------------- */

int wsgi_thread_cpu_usage(WSGIThreadCPUUsage *usage)
{
#if defined(__APPLE__)
    mach_port_t thread;
    kern_return_t kr;
    mach_msg_type_number_t count;
    thread_basic_info_data_t info;

    usage->user_time = 0.0;
    usage->system_time = 0.0;

    thread = mach_thread_self();

    count = THREAD_BASIC_INFO_COUNT;
    kr = thread_info(thread, THREAD_BASIC_INFO, (thread_info_t)&info, &count);

    mach_port_deallocate(mach_task_self(), thread);

    if (kr == KERN_SUCCESS && (info.flags & TH_FLAGS_IDLE) == 0)
    {
        usage->user_time = info.user_time.seconds;
        usage->user_time += info.user_time.microseconds / 1000000.0;
        usage->system_time = info.system_time.seconds;
        usage->system_time += info.system_time.microseconds / 1000000.0;

        return 1;
    }
#elif defined(linux) && defined(RUSAGE_THREAD)
    struct rusage info;

    usage->user_time = 0.0;
    usage->system_time = 0.0;

    if (getrusage(RUSAGE_THREAD, &info) == 0)
    {
        usage->user_time = info.ru_utime.tv_sec;
        usage->user_time += info.ru_utime.tv_usec / 1000000.0;
        usage->system_time = info.ru_stime.tv_sec;
        usage->system_time += info.ru_stime.tv_usec / 1000000.0;

        return 1;
    }
#elif defined(linux)
    FILE *fp;
    char filename[256];
    char content[1024];
    long tid;

    /* Field 14. Numbering start at 1. */

    int offset = 13;
    char *p;

    unsigned long user_time = 0;
    unsigned long system_time = 0;

    int ticks;

    usage->user_time = 0.0;
    usage->system_time = 0.0;

    memset(content, '\0', sizeof(content));

    tid = (long)syscall(SYS_gettid);

    ticks = sysconf(_SC_CLK_TCK);

    snprintf(filename, sizeof(filename), "/proc/%ld/stat", tid);

    fp = fopen(filename, "r");

    if (fp)
    {
        if (fread(content, 1, sizeof(content) - 1, fp))
        {
            p = content;

            while (*p && offset)
            {
                if (*p++ == ' ')
                {
                    offset--;
                    while (*p == ' ')
                        p++;
                }
            }

            user_time = strtoul(p, &p, 10);

            while (*p == ' ')
                p++;

            system_time = strtoul(p, &p, 10);

            fclose(fp);

            usage->user_time = (double)user_time / ticks;
            usage->system_time = (double)system_time / ticks;

            return 1;
        }

        fclose(fp);
    }
#endif

    return 0;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
