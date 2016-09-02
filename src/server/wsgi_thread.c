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

#include "wsgi_thread.h"

#include "wsgi_server.h"

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

int wsgi_total_threads;
int wsgi_request_threads;
apr_threadkey_t *wsgi_thread_key;
apr_array_header_t *wsgi_thread_details;

WSGIThreadInfo *wsgi_thread_info(int create, int request)
{
    WSGIThreadInfo *thread_handle = NULL;

    apr_threadkey_private_get((void**)&thread_handle, wsgi_thread_key);

    if (!thread_handle && create) {
        WSGIThreadInfo **entry = NULL;

        if (!wsgi_thread_details) {
            wsgi_thread_details = apr_array_make(
                    wsgi_server->process->pool, 3, sizeof(char*));
        }

        thread_handle = (WSGIThreadInfo *)apr_pcalloc(
                wsgi_server->process->pool, sizeof(WSGIThreadInfo));

        thread_handle->log_buffer = NULL;

        thread_handle->thread_id = wsgi_total_threads++;

        entry = (WSGIThreadInfo **)apr_array_push(wsgi_thread_details);
        *entry = thread_handle;

        apr_threadkey_private_set(thread_handle, wsgi_thread_key);
    }

    if (thread_handle && request && !thread_handle->request_thread) {
        thread_handle->request_thread = 1;
        wsgi_request_threads++;
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

    if (kr == KERN_SUCCESS && (info.flags & TH_FLAGS_IDLE) == 0) {
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

    if (getrusage(RUSAGE_THREAD, &info) == 0) {
        usage->user_time = info.ru_utime.tv_sec;
        usage->user_time += info.ru_utime.tv_usec / 1000000.0;
        usage->system_time = info.ru_stime.tv_sec;
        usage->system_time += info.ru_stime.tv_usec / 1000000.0;

        return 1;
    }
#elif defined(linux)
    FILE* fp;
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

    sprintf(filename, "/proc/%ld/stat", tid);

    fp = fopen(filename, "r");

    if (fp) {
        if (fread(content, 1, sizeof(content)-1, fp)) {
            p = content;

            while (*p && offset) {
                if (*p++ == ' ') {
                    offset--;
                    while (*p == ' ')
                        p++;
                }
            }

            user_time = strtoul(p, &p, 10);

            while (*p == ' ')
                p++;

            system_time = strtoul(p, &p, 10);
        }

        fclose(fp);

        usage->user_time = (float)user_time / ticks;
        usage->system_time = (float)system_time / ticks;

        return 1;
    }
#endif

    return 0;
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
