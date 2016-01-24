/* ------------------------------------------------------------------------- */

/*
 * Copyright 2007-2016 GRAHAM DUMPLETON
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

#include "wsgi_apache.h"

#include "wsgi_daemon.h"

/* ------------------------------------------------------------------------- */

/*
 * This is to shut up ranlib when run on empty object files as it confuses
 * users sometimes who then think it is an error and something is wrong.
 */


int wsgi_apache_dummy = 1;

/* ------------------------------------------------------------------------- */

#if defined(MOD_WSGI_WITH_DAEMONS)

#if !AP_MODULE_MAGIC_AT_LEAST(20051115,0)

void wsgi_ap_close_listeners(void)
{
    ap_listen_rec *lr;

    for (lr = ap_listeners; lr; lr = lr->next) {
        apr_socket_close(lr->sd);
        lr->active = 0;
    }
}

#endif

/* ------------------------------------------------------------------------- */

#if (APR_MAJOR_VERSION == 0) && \
    (APR_MINOR_VERSION == 9) && \
    (APR_PATCH_VERSION < 5)

#define apr_unix_file_cleanup wsgi_apr_unix_file_cleanup

apr_status_t wsgi_apr_unix_file_cleanup(void *thefile)
{
    apr_file_t *file = thefile;

    return apr_file_close(file);
}

#endif

/* ------------------------------------------------------------------------- */

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)

apr_status_t wsgi_apr_os_pipe_put_ex(apr_file_t **file,
                                     apr_os_file_t *thefile,
                                     int register_cleanup,
                                     apr_pool_t *pool)
{
    apr_status_t rv;

    rv = apr_os_pipe_put(file, thefile, pool);

    if (register_cleanup) {
        apr_pool_cleanup_register(pool, (void *)(*file),
                                  apr_unix_file_cleanup,
                                  apr_pool_cleanup_null);
    }

    return rv;
}

#endif

#endif

/* ------------------------------------------------------------------------- */

#if defined(WIN32) && defined(APR_HAS_UNICODE_FS)
APR_DECLARE(apr_status_t) apr_conv_utf8_to_ucs2(const char *in,
                                                apr_size_t *inbytes,
                                                apr_wchar_t *out,
                                                apr_size_t *outwords);

apr_status_t wsgi_utf8_to_unicode_path(apr_wchar_t* retstr,
                                       apr_size_t retlen, 
                                       const char* srcstr)
{
    /* TODO: The computations could preconvert the string to determine
     * the true size of the retstr, but that's a memory over speed
     * tradeoff that isn't appropriate this early in development.
     *
     * Allocate the maximum string length based on leading 4 
     * characters of \\?\ (allowing nearly unlimited path lengths) 
     * plus the trailing null, then transform /'s into \\'s since
     * the \\?\ form doesn't allow '/' path seperators.
     *
     * Note that the \\?\ form only works for local drive paths, and
     * \\?\UNC\ is needed UNC paths.
     */
    apr_size_t srcremains = strlen(srcstr) + 1;
    apr_wchar_t *t = retstr;
    apr_status_t rv;

    /* This is correct, we don't twist the filename if it is will
     * definately be shorter than 248 characters.  It merits some 
     * performance testing to see if this has any effect, but there
     * seem to be applications that get confused by the resulting
     * Unicode \\?\ style file names, especially if they use argv[0]
     * or call the Win32 API functions such as GetModuleName, etc.
     * Not every application is prepared to handle such names.
     * 
     * Note also this is shorter than MAX_PATH, as directory paths 
     * are actually limited to 248 characters. 
     *
     * Note that a utf-8 name can never result in more wide chars
     * than the original number of utf-8 narrow chars.
     */
    if (srcremains > 248) {
        if (srcstr[1] == ':' && (srcstr[2] == '/' || srcstr[2] == '\\')) {
            wcscpy (retstr, L"\\\\?\\");
            retlen -= 4;
            t += 4;
        }
        else if ((srcstr[0] == '/' || srcstr[0] == '\\')
              && (srcstr[1] == '/' || srcstr[1] == '\\')
              && (srcstr[2] != '?')) {
            /* Skip the slashes */
            srcstr += 2;
            srcremains -= 2;
            wcscpy (retstr, L"\\\\?\\UNC\\");
            retlen -= 8;
            t += 8;
        }
    }

    if (rv = apr_conv_utf8_to_ucs2(srcstr, &srcremains, t, &retlen)) {
        return (rv == APR_INCOMPLETE) ? APR_EINVAL : rv;
    }
    if (srcremains) {
        return APR_ENAMETOOLONG;
    }
    for (; *t; ++t)
        if (*t == L'/')
            *t = L'\\';
    return APR_SUCCESS;
}
#endif

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
