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

#include "wsgi_remote.h"

#include "wsgi_logger.h"
#include "wsgi_server.h"

#if defined(MOD_WSGI_WITH_DAEMONS)

static apr_status_t wsgi_socket_connect_un(apr_socket_t *sock,
                                           struct sockaddr_un *sa)
{
    apr_status_t rv;
    apr_os_sock_t rawsock;
    apr_interval_time_t t;

    rv = apr_os_sock_get(&rawsock, sock);
    if (rv != APR_SUCCESS)
    {
        return rv;
    }

    rv = apr_socket_timeout_get(sock, &t);
    if (rv != APR_SUCCESS)
    {
        return rv;
    }

    do
    {
        rv = connect(rawsock, (struct sockaddr *)sa,
                     APR_OFFSETOF(struct sockaddr_un, sun_path) + strlen(sa->sun_path) + 1);
    } while (rv == -1 && errno == EINTR);

    if ((rv == -1) && (errno == EINPROGRESS || errno == EALREADY) && (t > 0))
    {
#if APR_MAJOR_VERSION < 2
        rv = apr_wait_for_io_or_timeout(NULL, sock, 0);
#else
        rv = apr_socket_wait(sock, APR_WAIT_WRITE);
#endif

        if (rv != APR_SUCCESS)
        {
            return rv;
        }
    }

    if (rv == -1 && errno != EISCONN)
    {
        return APR_FROM_OS_ERROR(errno);
    }

    return APR_SUCCESS;
}

static int wsgi_connect_daemon(request_rec *r, WSGIDaemonSocket *daemon)
{
    WSGIRequestConfig *config = NULL;

    apr_status_t rv;

    struct sockaddr_un addr;

    int retries = 0;
    apr_interval_time_t timer = 0;
    apr_interval_time_t total_time = 0;

    apr_time_t start_time = 0;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    apr_cpystrn(addr.sun_path, daemon->socket_path, sizeof(addr.sun_path));

    start_time = apr_time_now();

    while (1)
    {
        retries++;

        config->daemon_connects++;

        rv = apr_socket_create(&daemon->socket, AF_UNIX, SOCK_STREAM,
                               0, r->pool);

        if (rv != APR_SUCCESS)
        {
            wsgi_log_rerror(APLOG_ERR, rv, r, WSGI_APLOGNO(0115)
                            "Unable to create socket to connect to WSGI "
                            "daemon process '%s' on '%s'.",
                            daemon->name, daemon->socket_path);

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /*
         * Apply timeout before issuing the socket connection in
         * case this hangs for some reason. Would have to be an extreme
         * event for a UNIX socket connect to hang, but have had some
         * unexplained situations which look exactly like that.
         */

        if (daemon->socket_timeout)
            apr_socket_timeout_set(daemon->socket, daemon->socket_timeout);
        else
            apr_socket_timeout_set(daemon->socket, r->server->timeout);

        rv = wsgi_socket_connect_un(daemon->socket, &addr);

        if (rv != APR_SUCCESS)
        {
            /*
             * We need to check for both connection refused and
             * connection unavailable as Linux systems when
             * connecting to a UNIX listener socket in non
             * blocking mode, where the listener backlog is full
             * will return the error EAGAIN rather than returning
             * ECONNREFUSED as is supposedly dictated by POSIX.
             */

            if (APR_STATUS_IS_ECONNREFUSED(rv) || APR_STATUS_IS_EAGAIN(rv))
            {
                if ((apr_time_now() - start_time) < daemon->connect_timeout)
                {
                    wsgi_log_rerror(APLOG_TRACE1, rv, r,
                                    "Connection attempt #%d to WSGI "
                                    "daemon process '%s' on '%s' failed, "
                                    "sleeping before retrying again.",
                                    retries, daemon->name,
                                    daemon->socket_path);

                    apr_socket_close(daemon->socket);

                    /*
                     * Progressively increase time we wait between
                     * connection attempts. Start at 0.125 second, but
                     * back off to 1 second interval after 2 seconds.
                     */

                    if (total_time < apr_time_make(2, 0))
                        timer = apr_time_make(0, 125000);
                    else
                        timer = apr_time_make(1, 0);

                    apr_sleep(timer);

                    total_time += timer;
                }
                else
                {
                    wsgi_log_rerror(APLOG_ERR, rv, r, WSGI_APLOGNO(0116)
                                    "Unable to connect to WSGI daemon "
                                    "process '%s' on '%s' after multiple "
                                    "attempts as listener backlog limit was "
                                    "exceeded or the socket does not exist.",
                                    daemon->name, daemon->socket_path);

                    apr_socket_close(daemon->socket);

                    return HTTP_SERVICE_UNAVAILABLE;
                }
            }
            else
            {
                wsgi_log_rerror(APLOG_ERR, rv, r, WSGI_APLOGNO(0117)
                                "Unable to connect to WSGI daemon process "
                                "'%s' on '%s' as user with uid=%ld.",
                                daemon->name, daemon->socket_path,
                                (long)geteuid());

                apr_socket_close(daemon->socket);

                return HTTP_SERVICE_UNAVAILABLE;
            }
        }
        else
            break;
    }

    return OK;
}

static apr_status_t wsgi_socket_send(apr_socket_t *sock, const char *buf,
                                     size_t buf_size)
{
    apr_status_t rv;
    apr_size_t len;

    while (buf_size > 0)
    {
        len = buf_size;

        rv = apr_socket_send(sock, buf, &len);

        if (rv != APR_SUCCESS)
            return rv;

        buf += len;
        buf_size -= len;
    }

    return APR_SUCCESS;
}

static apr_status_t wsgi_socket_sendv_limit(apr_socket_t *sock,
                                            struct iovec *vec, size_t nvec)
{
    apr_status_t rv;
    apr_size_t written = 0;
    apr_size_t to_write = 0;
    size_t i, offset;

    /* Calculate how much has to be sent. */

    for (i = 0; i < nvec; i++)
    {
        to_write += vec[i].iov_len;
    }

    /* Loop until all data has been sent. */

    offset = 0;

    while (to_write)
    {
        apr_size_t n = 0;

        rv = apr_socket_sendv(sock, vec + offset, nvec - offset, &n);

        if (rv != APR_SUCCESS)
            return rv;

        if (n > 0)
        {
            /* Bail out if all data has been sent. */

            written += n;

            if (written >= to_write)
                break;

            /*
             * Not all data was sent, so we need to try
             * again with the remainder of the data. We
             * first need to work out where to start from.
             */

            while (offset < nvec)
            {
                if (n >= vec[offset].iov_len)
                {
                    n -= vec[offset].iov_len;
                    offset++;
                }
                else
                {
                    vec[offset].iov_len -= n;
                    vec[offset].iov_base = (char *)vec[offset].iov_base + n;
                    break;
                }
            }
        }
    }

    return APR_SUCCESS;
}

static apr_status_t wsgi_socket_sendv(apr_socket_t *sock, struct iovec *vec,
                                      size_t nvec)
{
#if defined(_SC_IOV_MAX)
    static size_t iov_max = 0;

    if (iov_max == 0)
        iov_max = sysconf(_SC_IOV_MAX);
#else
    static size_t iov_max = APR_MAX_IOVEC_SIZE;
#endif

    if (nvec > iov_max)
    {
        size_t offset = 0;

        while (nvec != 0)
        {
            apr_status_t rv;

            rv = wsgi_socket_sendv_limit(sock, &vec[offset],
                                         (nvec < iov_max ? nvec : iov_max));

            if (rv != APR_SUCCESS)
                return rv;

            if (nvec > iov_max)
            {
                nvec -= iov_max;
                offset += iov_max;
            }
            else
            {
                break;
            }
        }

        return APR_SUCCESS;
    }
    else
        return wsgi_socket_sendv_limit(sock, vec, nvec);
}

static apr_status_t wsgi_send_request(request_rec *r,
                                      WSGIRequestConfig *config,
                                      WSGIDaemonSocket *daemon)
{
    const apr_array_header_t *env_arr;
    const apr_table_entry_t *elts;
    int i;

    struct iovec *vec;
    struct iovec *vec_start;
    struct iovec *vec_next;

    apr_size_t total = 0;
    apr_size_t count = 0;

    apr_table_setn(r->subprocess_env, "mod_wsgi.daemon_connects",
                   apr_psprintf(r->pool, "%d", config->daemon_connects));
    apr_table_setn(r->subprocess_env, "mod_wsgi.daemon_restarts",
                   apr_psprintf(r->pool, "%d", config->daemon_restarts));

    /* Send subprocess environment from request object. */

    env_arr = apr_table_elts(r->subprocess_env);
    elts = (const apr_table_entry_t *)env_arr->elts;

    /*
     * Sending total amount of data, followed by count of separate
     * strings and then each null terminated string. The total is
     * inclusive of the bytes used for the count of the strings.
     */

    vec = (struct iovec *)apr_palloc(r->pool, (2 + (2 * env_arr->nelts)) *
                                                  sizeof(struct iovec));

    vec_start = &vec[2];
    vec_next = vec_start;

    for (i = 0; i < env_arr->nelts; ++i)
    {
        if (!elts[i].key)
            continue;

        vec_next->iov_base = (void *)elts[i].key;
        vec_next->iov_len = strlen(elts[i].key) + 1;

        total += vec_next->iov_len;

        vec_next++;

        if (elts[i].val)
        {
            vec_next->iov_base = (void *)elts[i].val;
            vec_next->iov_len = strlen(elts[i].val) + 1;
        }
        else
        {
            vec_next->iov_base = (void *)"";
            vec_next->iov_len = 1;
        }

        total += vec_next->iov_len;

        vec_next++;
    }

    count = vec_next - vec_start;

    vec[1].iov_base = (void *)&count;
    vec[1].iov_len = sizeof(count);

    total += vec[1].iov_len;

    vec[0].iov_base = (void *)&total;
    vec[0].iov_len = sizeof(total);

    return wsgi_socket_sendv(daemon->socket, vec, vec_next - vec);
}

static void wsgi_discard_output(apr_bucket_brigade *bb)
{
    apr_bucket *e;
    const char *buf;
    apr_size_t len;
    apr_status_t rv;

    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e))
    {
        if (APR_BUCKET_IS_EOS(e))
        {
            break;
        }
        rv = apr_bucket_read(e, &buf, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS)
        {
            break;
        }
    }
}

static int wsgi_copy_header(void *v, const char *key, const char *val)
{
    apr_table_addn(v, key, val);
    return 1;
}

#define HTTP_UNSET (-HTTP_OK)

/*
 * Classification of outcomes from wsgi_read_header_line. LINE means a
 * terminated line (stripped of CR/LF) is available in the buffer. The
 * remaining values indicate why no line was produced.
 */

#define WSGI_HEADER_LINE       1
#define WSGI_HEADER_TRUNCATED  0
#define WSGI_HEADER_TIMEOUT   -1
#define WSGI_HEADER_CLOSED    -2
#define WSGI_HEADER_ERROR     -3

static int wsgi_read_header_line(char *buf, apr_size_t len,
                                 apr_bucket_brigade *bb,
                                 apr_status_t *status_out)
{
    char *dst_end;
    char *dst;
    apr_bucket *e;
    apr_status_t rv;
    int done = 0;

    *status_out = APR_SUCCESS;

    if (len == 0)
        return WSGI_HEADER_TRUNCATED;

    dst = buf;
    dst_end = buf + len - 1;

    e = APR_BRIGADE_FIRST(bb);

    while ((dst < dst_end) && !done &&
           e != APR_BRIGADE_SENTINEL(bb) && !APR_BUCKET_IS_EOS(e))
    {
        const char *bucket_data;
        apr_size_t bucket_data_len;
        const char *src;
        const char *src_end;
        apr_bucket *next;

        rv = apr_bucket_read(e, &bucket_data, &bucket_data_len,
                             APR_BLOCK_READ);

        if (rv != APR_SUCCESS)
        {
            *dst = '\0';
            *status_out = rv;

            if (APR_STATUS_IS_TIMEUP(rv))
                return WSGI_HEADER_TIMEOUT;
            if (APR_STATUS_IS_EOF(rv))
                return WSGI_HEADER_CLOSED;

            return WSGI_HEADER_ERROR;
        }

        if (bucket_data_len == 0)
        {
            next = APR_BUCKET_NEXT(e);
            APR_BUCKET_REMOVE(e);
            apr_bucket_destroy(e);
            e = next;
            continue;
        }

        src = bucket_data;
        src_end = bucket_data + bucket_data_len;

        while ((src < src_end) && (dst < dst_end) && !done)
        {
            if (*src == '\n')
                done = 1;
            else if (*src != '\r')
                *dst++ = *src;
            src++;
        }

        if (src < src_end)
            apr_bucket_split(e, src - bucket_data);

        next = APR_BUCKET_NEXT(e);
        APR_BUCKET_REMOVE(e);
        apr_bucket_destroy(e);
        e = next;
    }

    *dst = '\0';

    if (done)
        return WSGI_HEADER_LINE;

    if (dst >= dst_end)
        return WSGI_HEADER_TRUNCATED;

    return WSGI_HEADER_CLOSED;
}

static int wsgi_scan_headers_brigade(request_rec *r, apr_bucket_brigade *bb,
                                     char *buffer, int buflen)
{
    char x[32768];
    char *w, *l;
    apr_size_t w_size;

    int cgi_status = HTTP_UNSET;

    apr_table_t *merge;
    apr_table_t *cookie_table;
    apr_table_t *authen_table;

    WSGIRequestConfig *config = NULL;

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    /*
     * Default to internal fixed size buffer for reading headers if one
     * is not supplied explicitly with the call.
     */

    if (buffer)
        *buffer = '\0';

    w = buffer ? buffer : x;
    w_size = buffer ? (apr_size_t)buflen : sizeof(x);

    /* Temporary place to hold headers as we read them. */

    merge = apr_table_make(r->pool, 10);

    /*
     * The HTTP specification says that it is legal to merge duplicate
     * headers into one. Some browsers don't like certain headers being
     * merged however. These headers are Set-Cookie and WWW-Authenticate.
     * We will therefore keep these separate and merge them back in
     * independently at the end. Before we start though, we need to make
     * sure we save away any instances of these headers which may already
     * be listed in the request structure for some reason.
     */

    cookie_table = apr_table_make(r->pool, 2);
    apr_table_do(wsgi_copy_header, cookie_table, r->headers_out,
                 "Set-Cookie", NULL);

    authen_table = apr_table_make(r->pool, 2);
    apr_table_do(wsgi_copy_header, authen_table, r->err_headers_out,
                 "WWW-Authenticate", NULL);

    while (1)
    {
        apr_status_t read_status = APR_SUCCESS;
        char apr_error[512];
        int rv;

        rv = wsgi_read_header_line(w, w_size, bb, &read_status);

        if (rv == WSGI_HEADER_TRUNCATED)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool,
                "Response header line too long from daemon process '%s'",
                config->process_group), r->filename);

            r->status_line = NULL;

            return HTTP_INTERNAL_SERVER_ERROR;
        }
        else if (rv == WSGI_HEADER_TIMEOUT)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool,
                "Timeout when reading response headers from daemon "
                "process '%s'", config->process_group), r->filename);

            r->status_line = NULL;

            return HTTP_GATEWAY_TIME_OUT;
        }
        else if (rv == WSGI_HEADER_CLOSED)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool,
                "Daemon process '%s' closed connection before sending "
                "complete response headers", config->process_group),
                r->filename);

            r->status_line = NULL;

            return HTTP_BAD_GATEWAY;
        }
        else if (rv == WSGI_HEADER_ERROR)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool,
                "Error reading response headers from daemon process "
                "'%s': %s", config->process_group,
                apr_strerror(read_status, apr_error,
                             sizeof(apr_error) - 1)),
                r->filename);

            r->status_line = NULL;

            return HTTP_BAD_GATEWAY;
        }

        /*
         * If we've finished reading the headers, check to make sure
         * any HTTP/1.1 conditions are met. If so, we're done; normal
         * processing will handle the script's output. If not, just
         * return the error.
         */

        if (w[0] == '\0')
        {
            int cond_status = OK;

            /*
             * This fails because it gets confused when a CGI Status
             * header overrides ap_meets_conditions.
             *
             * We can fix that by dropping ap_meets_conditions when
             * Status has been set.  Since this is the only place
             * cgi_status gets used, let's test it explicitly.
             *
             * The alternative would be to ignore CGI Status when
             * ap_meets_conditions returns anything interesting. That
             * would be safer wrt HTTP, but would break CGI.
             */

            if ((cgi_status == HTTP_UNSET) && (r->method_number == M_GET))
            {
                cond_status = ap_meets_conditions(r);
            }

            /*
             * Merge the headers received back into the request
             * structure. There should only be one per header with
             * values combined for these.
             */

            apr_table_overlap(r->headers_out, merge,
                              APR_OVERLAP_TABLES_MERGE);

            /*
             * Now add in the special headers which we can't merge
             * because it gives certain browsers problems.
             */

            if (!apr_is_empty_table(cookie_table))
            {
                apr_table_unset(r->headers_out, "Set-Cookie");
                r->headers_out = apr_table_overlay(r->pool,
                                                   r->headers_out, cookie_table);
            }

            if (!apr_is_empty_table(authen_table))
            {
                apr_table_unset(r->err_headers_out, "WWW-Authenticate");
                r->err_headers_out = apr_table_overlay(r->pool,
                                                       r->err_headers_out, authen_table);
            }

            return cond_status;
        }

        /* If we see a bogus header don't ignore it. Shout and scream. */

        if (!(l = strchr(w, ':')))
        {
            char malformed[32];

            apr_cpystrn(malformed, w, sizeof(malformed));

            if (!buffer)
            {
                /* Soak up all the script output. */

                while (wsgi_read_header_line(w, w_size, bb,
                                             &read_status) == WSGI_HEADER_LINE)
                {
                    continue;
                }
            }

            wsgi_log_script_error(r, apr_psprintf(r->pool, "Malformed "
                                                           "header '%s' found when reading script "
                                                           "headers from daemon process '%s'",
                                                  malformed, config->process_group),
                                  r->filename);

            r->status_line = NULL;

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Strip leading white space from header value. */

        *l++ = '\0';
        while (*l && apr_isspace(*l))
        {
            ++l;
        }

        if (!strcasecmp(w, "Content-type"))
        {
            char *tmp;

            /* Nuke trailing whitespace. */

            char *endp = l + strlen(l) - 1;
            while (endp > l && apr_isspace(*endp))
            {
                *endp-- = '\0';
            }

            tmp = apr_pstrdup(r->pool, l);
            ap_content_type_tolower(tmp);
            ap_set_content_type(r, tmp);
        }
        else if (!strcasecmp(w, "Status"))
        {
            /*
             * If the script returned a specific status, that's what
             * we'll use, otherwise we assume 200 OK.
             */

            r->status = cgi_status = atoi(l);
            r->status_line = apr_pstrdup(r->pool, l);
        }
        else if (!strcasecmp(w, "Location"))
        {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Content-Length"))
        {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Content-Range"))
        {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Transfer-Encoding"))
        {
            apr_table_set(r->headers_out, w, l);
        }
        else if (!strcasecmp(w, "Last-Modified"))
        {
            /*
             * If the script gave us a Last-Modified header, we can't just
             * pass it on blindly because of restrictions on future values.
             */

            ap_update_mtime(r, apr_date_parse_http(l));
            ap_set_last_modified(r);
        }
        else if (!strcasecmp(w, "Set-Cookie"))
        {
            apr_table_add(cookie_table, w, l);
        }
        else if (!strcasecmp(w, "WWW-Authenticate"))
        {
            apr_table_add(authen_table, w, l);
        }
        else
        {
            apr_table_add(merge, w, l);
        }
    }

    return OK;
}

static int wsgi_transfer_response(request_rec *r, apr_bucket_brigade *bb,
                                  apr_size_t buffer_size, apr_time_t timeout)
{
    apr_bucket *e;
    apr_read_type_e mode = APR_NONBLOCK_READ;

    apr_bucket_brigade *tmpbb;

    const char *data = NULL;
    apr_size_t length = 0;

    apr_size_t bytes_transfered = 0;

    int bucket_count = 0;

    apr_status_t rv;

    apr_socket_t *sock;
    apr_interval_time_t existing_timeout = 0;

    if (buffer_size == 0)
        buffer_size = 65536;

    /*
     * Override the socket timeout for writing back data to the
     * client. If that wasn't defined this will be the same as
     * the timeout for the socket used in communicating with the
     * daemon, or left as the overall server timeout if that
     * isn't specified. Just to be safe we remember the existing
     * timeout and restore it at the end of a successful request
     * in case the same connection if kept alive and used for a
     * subsequent request with a different handler.
     */

    sock = ap_get_conn_socket(r->connection);

    rv = apr_socket_timeout_get(sock, &existing_timeout);

    if (rv != APR_SUCCESS)
    {
        existing_timeout = 0;
    }
    else
    {
        if (timeout)
            apr_socket_timeout_set(sock, timeout);
    }

    /*
     * Transfer any response content. We want to avoid the
     * problem where the core output filter has no flow control
     * to deal with slow HTTP clients and can actually buffer up
     * excessive amounts of response content in memory. A fix
     * for this was only introduced in Apache 2.3.3, with
     * possible further tweaks in Apache 2.4.1. To avoid issue of
     * what version it was implemented in, just employ a
     * strategy of forcing a flush every time we pass through
     * more than a certain amount of data.
     */

    tmpbb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    while ((e = APR_BRIGADE_FIRST(bb)) != APR_BRIGADE_SENTINEL(bb))
    {
        /* If we have reached end of stream, we need to pass it on */

        if (APR_BUCKET_IS_EOS(e))
        {
            /*
             * Probably do not need to force a flush as EOS should
             * do that, but do it just in case when we potentially
             * have pending data to be written out.
             */

            if (bytes_transfered != 0)
            {
                APR_BRIGADE_INSERT_TAIL(tmpbb, apr_bucket_flush_create(
                                                   r->connection->bucket_alloc));
            }

            APR_BRIGADE_INSERT_TAIL(tmpbb, apr_bucket_eos_create(
                                               r->connection->bucket_alloc));

            rv = ap_pass_brigade(r->output_filters, tmpbb);

            apr_brigade_cleanup(tmpbb);

            if (rv != APR_SUCCESS)
            {
                apr_brigade_destroy(bb);

                /*
                 * Don't flag error if client connection was aborted
                 * so that access log still records the original HTTP
                 * response code returned by the WSGI application.
                 */

                if (r->connection->aborted)
                    return OK;

                return HTTP_INTERNAL_SERVER_ERROR;
            }

            break;
        }

        /*
         * Force the reading in of next block of data to be
         * transfered if necessary. If the bucket is a heap
         * bucket, then it will be whatever data is in it. If it
         * is a socket bucket, this will result in the bucket
         * being converted to a heap bucket with some amount of
         * data and the socket bucket added back in after it. Any
         * non data buckets should be skipped and discarded. The
         * result should always be that the first bucket is a
         * heap bucket.
         */

        rv = apr_bucket_read(e, &data, &length, mode);

        /*
         * If we would have blocked if not in non blocking mode
         * we send a flush bucket to ensure that all buffered
         * data is sent out before we block waiting for more.
         */

        if (rv == APR_EAGAIN && mode == APR_NONBLOCK_READ)
        {
            APR_BRIGADE_INSERT_TAIL(tmpbb, apr_bucket_flush_create(
                                               r->connection->bucket_alloc));

            rv = ap_pass_brigade(r->output_filters, tmpbb);

            apr_brigade_cleanup(tmpbb);

            if (rv == APR_TIMEUP)
            {
                wsgi_log_rerror(APLOG_ERR, rv, r, WSGI_APLOGNO(0118)
                                "Unable to proxy response to client "
                                "(read timeout).");
            }

            if (rv != APR_SUCCESS)
            {
                apr_brigade_destroy(bb);

                /*
                 * Don't flag error if client connection was aborted
                 * so that access log still records the original HTTP
                 * response code returned by the WSGI application.
                 */

                if (r->connection->aborted)
                    return OK;

                return HTTP_INTERNAL_SERVER_ERROR;
            }

            bytes_transfered = 0;

            bucket_count = 0;

            /*
             * Retry read from daemon using a blocking read. We do
             * not delete the bucket as we want to operate on the
             * same one as we would have blocked.
             */

            mode = APR_BLOCK_READ;

            continue;
        }
        else if (rv != APR_SUCCESS)
        {
            apr_brigade_destroy(bb);

            wsgi_log_rerror(APLOG_ERR, rv, r, WSGI_APLOGNO(0119)
                            "Unable to proxy response from daemon to "
                            "client.");

            /*
             * Don't flag error if couldn't read from daemon
             * so that access log still records the original HTTP
             * response code returned by the WSGI application.
             */

            return OK;
        }

        /*
         * We had some data to transfer. Next time round we need to
         * always be try a non-blocking read first.
         */

        mode = APR_NONBLOCK_READ;

        /*
         * Now we don't actually work with the data which was
         * read direct and instead simply remove what should be a
         * heap bucket from the start of the bucket brigade and
         * then place in a new bucket brigade to be pushed out to
         * the client. By passing down the bucket, it avoids the
         * need to create a transient bucket holding a reference
         * to the data from the first bucket.
         */

        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(tmpbb, e);

        /*
         * If we have reached the buffer size threshold, we want
         * to flush the data so that we aren't buffering too much
         * in memory and blowing out memory size. We also have a
         * check on the number of buckets we have accumulated as
         * a large number of buckets with very small amounts of
         * data will also accumulate a lot of memory. Apache's
         * own flow control doesn't cope with such a situation.
         * Right now hard wire the max number of buckets at 16
         * which equates to worst case number of separate data
         * blocks can be written by a writev() call on systems
         * such as Solaris.
         */

        bytes_transfered += length;

        bucket_count += 1;

        if (bytes_transfered > buffer_size || bucket_count >= 16)
        {
            APR_BRIGADE_INSERT_TAIL(tmpbb, apr_bucket_flush_create(
                                               r->connection->bucket_alloc));

            bytes_transfered = 0;

            bucket_count = 0;

            /*
             * Since we flushed the data out to the client, it is
             * okay to go back and do a blocking read the next time.
             */

            mode = APR_BLOCK_READ;
        }

        /* Pass the heap bucket and any flush bucket on. */

        rv = ap_pass_brigade(r->output_filters, tmpbb);

        apr_brigade_cleanup(tmpbb);

        if (rv == APR_TIMEUP)
        {
            wsgi_log_rerror(APLOG_ERR, rv, r, WSGI_APLOGNO(0120)
                            "Unable to proxy response to client "
                            "(write timeout).");
        }

        if (rv != APR_SUCCESS)
        {
            apr_brigade_destroy(bb);

            /*
             * Don't flag error if client connection was aborted
             * so that access log still records the original HTTP
             * response code returned by the WSGI application.
             */

            if (r->connection->aborted)
                return OK;

            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (existing_timeout)
        apr_socket_timeout_set(sock, existing_timeout);

    apr_brigade_destroy(bb);

    return OK;
}

#define ASCII_CRLF "\015\012"
#define ASCII_ZERO "\060"

int wsgi_execute_remote(request_rec *r)
{
    WSGIRequestConfig *config = NULL;
    WSGIDaemonSocket *daemon = NULL;
    WSGIProcessGroup *group = NULL;

    char *key = NULL;
    const char *hash = NULL;

    int status;
    apr_status_t rv;

    int seen_eos;
    int child_stopped_reading;
    apr_bucket_brigade *bbout;
    apr_bucket_brigade *bbin;
    apr_bucket *b;

    const char *location = NULL;

    char *header_buffer = NULL;
    int header_buflen = 0;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    /*
     * Only allow the process group to match against a restricted
     * set of processes if such a restricted set has been defined.
     */

    if (config->restrict_process)
    {
        if (!apr_table_get(config->restrict_process,
                           config->process_group))
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Daemon "
                                                           "process called '%s' cannot be "
                                                           "accessed by this WSGI application "
                                                           "as not a member of allowed groups",
                                                  config->process_group),
                                  r->filename);

            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /*
     * Do not process request as remote if actually targeted at
     * the main Apache processes.
     */

    if (!*config->process_group)
        return DECLINED;

    /* Grab details of matching process group. */

    if (!wsgi_daemon_index)
    {
        wsgi_log_script_error(r, apr_psprintf(r->pool, "No WSGI daemon "
                                                       "process called '%s' has been configured",
                                              config->process_group),
                              r->filename);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    group = (WSGIProcessGroup *)apr_hash_get(wsgi_daemon_index,
                                             config->process_group,
                                             APR_HASH_KEY_STRING);

    if (!group)
    {
        wsgi_log_script_error(r, apr_psprintf(r->pool, "No WSGI daemon "
                                                       "process called '%s' has been configured",
                                              config->process_group),
                              r->filename);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Only allow the process group to match against a daemon
     * process defined within a virtual host with the same
     * server name or a daemon process defined at global server
     * scope.
     */

    if (group->server != r->server && group->server != wsgi_server)
    {
        if (strcmp(group->server->server_hostname,
                   r->server->server_hostname) != 0)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Daemon "
                                                           "process called '%s' cannot be "
                                                           "accessed by this WSGI application",
                                                  config->process_group),
                                  r->filename);

            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /*
     * Check restrictions related to the group of the WSGI
     * script file and who has write access to the directory it
     * is contained in. If not satisfied forbid access.
     */

    if (group->script_group)
    {
        apr_uid_t gid;
        struct group *grent = NULL;
        const char *grname = NULL;
        apr_finfo_t finfo;
        const char *path = NULL;

        if (!(r->finfo.valid & APR_FINFO_GROUP))
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Group "
                                                           "information not available for WSGI "
                                                           "script file"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        gid = r->finfo.group;

        if ((grent = getgrgid(gid)) == NULL)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Couldn't "
                                                           "determine group of WSGI script file, "
                                                           "gid=%ld",
                                                  (long)gid),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        grname = grent->gr_name;

        if (strcmp(group->script_group, grname))
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Group of WSGI "
                                                           "script file does not match required group "
                                                           "for daemon process, group=%s",
                                                  grname),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        if (!(r->finfo.valid & APR_FINFO_WPROT))
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "World "
                                                           "permissions not available for WSGI "
                                                           "script file"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        if (r->finfo.protection & APR_FPROT_WWRITE)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "WSGI script "
                                                           "file is writable to world"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        path = ap_make_dirstr_parent(r->pool, r->filename);

        if (apr_stat(&finfo, path, APR_FINFO_NORM, r->pool) != APR_SUCCESS)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Unable to stat "
                                                           "parent directory of WSGI script"),
                                  path);
            return HTTP_FORBIDDEN;
        }

        gid = finfo.group;

        if ((grent = getgrgid(gid)) == NULL)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Couldn't "
                                                           "determine group of parent directory of "
                                                           "WSGI script file, gid=%ld",
                                                  (long)gid),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        grname = grent->gr_name;

        if (strcmp(group->script_group, grname))
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Group of parent "
                                                           "directory of WSGI script file does not "
                                                           "match required group for daemon process, "
                                                           "group=%s",
                                                  grname),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        if (finfo.protection & APR_FPROT_WWRITE)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Parent directory "
                                                           "of WSGI script file is writable to world"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }
    }

    /*
     * Check restrictions related to who can be the owner of
     * the WSGI script file and who has write access to the
     * directory it is contained in. If not satisfied forbid
     * access.
     */

    if (group->script_user)
    {
        apr_uid_t uid;
        struct passwd *pwent = NULL;
        const char *pwname = NULL;
        apr_finfo_t finfo;
        const char *path = NULL;

        if (!(r->finfo.valid & APR_FINFO_USER))
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "User "
                                                           "information not available for WSGI "
                                                           "script file"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        uid = r->finfo.user;

        if ((pwent = getpwuid(uid)) == NULL)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Couldn't "
                                                           "determine owner of WSGI script file, "
                                                           "uid=%ld",
                                                  (long)uid),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        pwname = pwent->pw_name;

        if (strcmp(group->script_user, pwname))
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Owner of WSGI "
                                                           "script file does not match required user "
                                                           "for daemon process, user=%s",
                                                  pwname),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        if (!(r->finfo.valid & APR_FINFO_GPROT))
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Group "
                                                           "permissions not available for WSGI "
                                                           "script file"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        if (r->finfo.protection & APR_FPROT_GWRITE)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "WSGI script "
                                                           "file is writable to group"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        if (!(r->finfo.valid & APR_FINFO_WPROT))
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "World "
                                                           "permissions not available for WSGI "
                                                           "script file"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        if (r->finfo.protection & APR_FPROT_WWRITE)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "WSGI script "
                                                           "file is writable to world"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        path = ap_make_dirstr_parent(r->pool, r->filename);

        if (apr_stat(&finfo, path, APR_FINFO_NORM, r->pool) != APR_SUCCESS)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Unable to stat "
                                                           "parent directory of WSGI script"),
                                  path);
            return HTTP_FORBIDDEN;
        }

        uid = finfo.user;

        if ((pwent = getpwuid(uid)) == NULL)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Couldn't "
                                                           "determine owner of parent directory of "
                                                           "WSGI script file, uid=%ld",
                                                  (long)uid),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        pwname = pwent->pw_name;

        if (strcmp(group->script_user, pwname))
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Owner of parent "
                                                           "directory of WSGI script file does not "
                                                           "match required user for daemon process, "
                                                           "user=%s",
                                                  pwname),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        if (finfo.protection & APR_FPROT_WWRITE)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Parent directory "
                                                           "of WSGI script file is writable to world"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }

        if (finfo.protection & APR_FPROT_GWRITE)
        {
            wsgi_log_script_error(r, apr_psprintf(r->pool, "Parent directory "
                                                           "of WSGI script file is writable to group"),
                                  r->filename);
            return HTTP_FORBIDDEN;
        }
    }

    /*
     * Add magic marker into request environment so that daemon
     * process can verify that request is from a sender that can
     * be trusted. Wipe out original key to make it a bit harder
     * for rogue code in Apache child processes to trawl through
     * memory looking for unhashed string.
     */

    key = apr_psprintf(r->pool, "%ld|%s|%s|%s", group->random,
                       group->socket_path, r->filename,
                       config->handler_script);
    hash = ap_md5(r->pool, (const unsigned char *)key);
    memset(key, '\0', strlen(key));

    apr_table_setn(r->subprocess_env, "mod_wsgi.magic", hash);

    /* Create connection to the daemon process. */

    apr_table_setn(r->subprocess_env, "mod_wsgi.queue_start",
                   apr_psprintf(r->pool, "%" APR_TIME_T_FMT, apr_time_now()));

    daemon = (WSGIDaemonSocket *)apr_pcalloc(r->pool,
                                             sizeof(WSGIDaemonSocket));

    daemon->name = config->process_group;
    daemon->socket_path = group->socket_path;
    daemon->connect_timeout = group->connect_timeout;
    daemon->socket_timeout = group->socket_timeout;

    if ((status = wsgi_connect_daemon(r, daemon)) != OK)
        return status;

    /* Send request details and subprocess environment. */

    wsgi_log_error(APLOG_TRACE1, 0, wsgi_server,
                   "Request server was '%s|%d'.",
                   r->server->server_hostname, r->server->port);

    if ((rv = wsgi_send_request(r, config, daemon)) != APR_SUCCESS)
    {
        wsgi_log_rerror(APLOG_ERR, rv, r, WSGI_APLOGNO(0121)
                        "Unable to send request details to WSGI daemon "
                        "process '%s' on '%s'.",
                        daemon->name, daemon->socket_path);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Setup bucket brigade for reading response from daemon. */

    bbin = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    b = apr_bucket_socket_create(daemon->socket, r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bbin, b);
    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bbin, b);

    /* Create alternate buffer for reading in response header values. */

    if (group->header_buffer_size != 0)
    {
        header_buflen = group->header_buffer_size;
        header_buffer = apr_pcalloc(r->pool, header_buflen);
    }

    /*
     * If process reload mechanism enabled, or a queue timeout is
     * specified, then we need to look for marker indicating it
     * is okay to transfer content, or whether process is being
     * restarted and that we should therefore create a
     * connection to daemon process again.
     */

    if (*config->process_group && (config->script_reloading ||
                                   group->queue_timeout != 0))
    {

        int retries = 0;
        int maximum = (2 * group->processes) + 1;

        /*
         * While special header indicates a restart is being
         * done, then keep trying to reconnect. Cap the number
         * of retries to at most about 2 times the number of
         * daemon processes in the process group. If still being
         * told things are being restarted, then we will error
         * indicating service is unavailable.
         */

        while (retries < maximum)
        {
            /* Scan the CGI script like headers from daemon. */

            status = wsgi_scan_headers_brigade(r, bbin, header_buffer,
                                               header_buflen);

            if (status != OK)
                return status;

            /*
             * Status must be 200 for our special headers. Ideally
             * we would use 0 as did in the past but Apache 2.4
             * complains if use 0 as not a valid status value.
             */

            if (r->status != 200)
            {
                wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0122)
                                "Unexpected status from WSGI daemon "
                                "process: %d.", r->status);

                r->status_line = NULL;

                return HTTP_INTERNAL_SERVER_ERROR;
            }

            if (!strcmp(r->status_line, "200 Continue"))
            {
                r->status_line = NULL;

                break;
            }

            if (!strcmp(r->status_line, "200 Timeout"))
            {
                r->status_line = NULL;

                return HTTP_GATEWAY_TIME_OUT;
            }

            if (strcmp(r->status_line, "200 Rejected"))
            {
                wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0123)
                                "Unexpected status from WSGI daemon "
                                "process: %d.", r->status);

                r->status_line = NULL;

                return HTTP_INTERNAL_SERVER_ERROR;
            }

            r->status_line = NULL;

            /* Need to close previous socket connection first. */

            apr_socket_close(daemon->socket);

            retries++;

            config->daemon_restarts++;

            /* Has maximum number of attempts been reached. */

            if (retries >= maximum)
            {
                wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0124)
                                "Maximum number of WSGI daemon process "
                                "'%s' restart attempts reached: %d.",
                                daemon->name, maximum);
                return HTTP_SERVICE_UNAVAILABLE;
            }

            wsgi_log_rerror(APLOG_INFO, 0, r,
                            "Reconnecting after WSGI daemon process '%s' "
                            "restart, attempt #%d.",
                            daemon->name, retries);

            /* Connect and setup connection just like before. */

            if ((status = wsgi_connect_daemon(r, daemon)) != OK)
                return status;

            if ((rv = wsgi_send_request(r, config, daemon)) != APR_SUCCESS)
            {
                wsgi_log_rerror(APLOG_ERR, rv, r, WSGI_APLOGNO(0125)
                                "Unable to send request details to WSGI "
                                "daemon process '%s' on '%s'.",
                                daemon->name, daemon->socket_path);

                return HTTP_INTERNAL_SERVER_ERROR;
            }

            apr_brigade_destroy(bbin);

            bbin = apr_brigade_create(r->pool, r->connection->bucket_alloc);
            b = apr_bucket_socket_create(daemon->socket,
                                         r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bbin, b);
            b = apr_bucket_eos_create(r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bbin, b);
        }
    }

    /*
     * Need to reset request status value to HTTP_OK else it
     * screws up HTTP input filter when processing a POST
     * request with 100-continue requirement.
     */

    r->status = HTTP_OK;

    /*
     * Transfer any request content which was provided. Note that we
     * actually frame each data block sent with same format as is used
     * for chunked transfer encoding. This will be decoded in the
     * daemon process. This is done so that the EOS can be properly
     * identified by the daemon process in the absence of a value for
     * CONTENT_LENGTH that can be relied on. The CONTENT_LENGTH is
     * dodgy when have mutating input filters and none will be present
     * at all if chunked request content was used.
     */

    seen_eos = 0;
    child_stopped_reading = 0;

    bbout = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    do
    {
        apr_bucket *bucket;

        rv = ap_get_brigade(r->input_filters, bbout, AP_MODE_READBYTES,
                            APR_BLOCK_READ, HUGE_STRING_LEN);

        if (rv != APR_SUCCESS)
        {
            char status_buffer[512];
            const char *error_message;

            error_message = apr_psprintf(r->pool, "Request data read "
                                                  "error when proxying data to daemon process: %s",
                                         apr_strerror(rv, status_buffer, sizeof(status_buffer) - 1));

            wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0126) "%s.", error_message);

            if (APR_STATUS_IS_TIMEUP(rv))
                return HTTP_REQUEST_TIME_OUT;

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        for (bucket = APR_BRIGADE_FIRST(bbout);
             bucket != APR_BRIGADE_SENTINEL(bbout);
             bucket = APR_BUCKET_NEXT(bucket))
        {
            const char *data;
            apr_size_t len;

            char chunk_hdr[20];
            apr_size_t hdr_len;

            struct iovec vec[3];

            if (APR_BUCKET_IS_EOS(bucket))
            {
                /* Send closing frame for chunked content. */

                rv = wsgi_socket_send(daemon->socket,
                                      ASCII_ZERO ASCII_CRLF ASCII_CRLF, 5);

                if (rv != APR_SUCCESS)
                {
                    char status_buffer[512];
                    const char *error_message;

                    error_message = apr_psprintf(r->pool, "Request data write "
                                                          "error when proxying data to daemon process: %s",
                                                 apr_strerror(rv, status_buffer, sizeof(status_buffer) - 1));

                    wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0127) "%s.", error_message);
                }

                seen_eos = 1;
                break;
            }

            /* We can't do much with this. */

            if (APR_BUCKET_IS_FLUSH(bucket))
            {
                continue;
            }

            /* If the child stopped, we still must read to EOS. */

            if (child_stopped_reading)
            {
                continue;
            }

            /* Read block. */

            rv = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);

            if (rv != APR_SUCCESS)
            {
                char status_buffer[512];
                const char *error_message;

                error_message = apr_psprintf(r->pool, "Request data read "
                                                      "error when proxying data to daemon process: %s",
                                             apr_strerror(rv, status_buffer, sizeof(status_buffer) - 1));

                wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0128) "%s.", error_message);

                break;
            }

            /*
             * Keep writing data to the child until done or too
             * much time elapses with no progress or an error
             * occurs. Frame the data being sent with format used
             * for chunked transfer encoding.
             */

            hdr_len = apr_snprintf(chunk_hdr, sizeof(chunk_hdr),
                                   "%" APR_UINT64_T_HEX_FMT ASCII_CRLF, (apr_uint64_t)len);

            vec[0].iov_base = (void *)chunk_hdr;
            vec[0].iov_len = hdr_len;
            vec[1].iov_base = (void *)data;
            vec[1].iov_len = len;
            vec[2].iov_base = (void *)ASCII_CRLF;
            vec[2].iov_len = 2;

            rv = wsgi_socket_sendv(daemon->socket, vec, 3);

            if (rv != APR_SUCCESS)
            {
                char status_buffer[512];
                const char *error_message;

                error_message = apr_psprintf(r->pool, "Request data write "
                                                      "error when proxying data to daemon process: %s",
                                             apr_strerror(rv, status_buffer, sizeof(status_buffer) - 1));

                wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0129) "%s.", error_message);

                /* Daemon stopped reading, discard remainder. */

                child_stopped_reading = 1;
            }
        }
        apr_brigade_cleanup(bbout);
    } while (!seen_eos);

    /*
     * Close socket for writing so that daemon detects end of
     * request content.
     */

    apr_socket_shutdown(daemon->socket, APR_SHUTDOWN_WRITE);

    /* Scan the CGI script like headers from daemon. */

    status = wsgi_scan_headers_brigade(r, bbin, header_buffer,
                                       header_buflen);

    if (status != OK)
        return status;

    /*
     * Look for the special case of status being 200 but the
     * status line indicating an error and translate it into a
     * 500 error so that error document processing will occur
     * for those cases where WSGI application wouldn't have
     * supplied their own error document. We used to use 0
     * here for status but Apache 2.4 prohibits it now.
     */

    if (r->status == 200 && !strcmp(r->status_line, "200 Error"))
    {
        r->status_line = NULL;

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Look for 'Location' header and if an internal
     * redirect, execute the redirect. This behaviour is
     * consistent with how mod_cgi and mod_cgid work and
     * what is permitted by the CGI specification.
     */

    location = apr_table_get(r->headers_out, "Location");

    if (location && location[0] == '/' && r->status == 200)
    {
        /*
         * Discard all response content returned from
         * the daemon process.
         */

        wsgi_discard_output(bbin);
        apr_brigade_destroy(bbin);

        /*
         * The internal redirect needs to be a GET no
         * matter what the original method was.
         */

        r->method = apr_pstrdup(r->pool, "GET");
        r->method_number = M_GET;

        /*
         * We already read the message body (if any), so
         * don't allow the redirected request to think
         * it has one. Not sure if we need to worry
         * about removing 'Transfer-Encoding' header.
         */

        apr_table_unset(r->headers_in, "Content-Length");

        ap_internal_redirect_handler(location, r);

        return OK;
    }

    /*
     * Allow the web server to override any error
     * page produced by the WSGI application.
     */

    if (config->error_override && ap_is_HTTP_ERROR(r->status))
    {
        status = r->status;

        r->status = HTTP_OK;
        r->status_line = NULL;

        /*
         * Discard all response content returned from
         * the daemon process if any expected.
         */

        if (!r->header_only &&             /* not HEAD request */
            (status != HTTP_NO_CONTENT) && /* not 204 */
            (status != HTTP_NOT_MODIFIED))
        { /* not 304 */
            wsgi_discard_output(bbin);
            apr_brigade_destroy(bbin);
        }

        return status;
    }

    /* Transfer any response content. */

    return wsgi_transfer_response(r, bbin, group->response_buffer_size,
                                  group->response_socket_timeout);
}

static apr_status_t wsgi_socket_read(apr_socket_t *sock, void *vbuf,
                                     apr_size_t size)
{
    char *buf = vbuf;
    apr_status_t rv;
    apr_size_t count = 0;
    apr_size_t len = 0;

    do
    {
        len = size - count;
        if ((rv = apr_socket_recv(sock, buf + count, &len)) != APR_SUCCESS)
            return rv;
        count += len;
    } while (count < size);

    return APR_SUCCESS;
}

/*
 * Upper bound on the size of a serialised request-environment frame
 * received from the Apache child. Sufficient to cover any realistic CGI
 * environment (including generous headers and cookies) while still
 * rejecting implausibly large or corrupted frames that would otherwise
 * drive unbounded memory allocation.
 */

#define WSGI_MAX_REQUEST_FRAME (16 * 1024 * 1024)

/*
 * Size of the stack-resident preread buffer. Realistic CGI-style
 * environments easily fit inside this, so in the common case the
 * length prefix and the entire payload arrive in a single recv()
 * and no second syscall is needed.
 */

#define WSGI_REQUEST_FRAME_PREREAD 4096

static apr_status_t wsgi_read_strings(apr_socket_t *sock, char ***s,
                                      apr_pool_t *p)
{
    apr_status_t rv;

    char preread[WSGI_REQUEST_FRAME_PREREAD];
    apr_size_t got;
    apr_size_t len;
    apr_size_t payload_have;

    apr_size_t total;

    apr_size_t n;
    apr_size_t i;

    char *buffer;
    char *offset;
    char *end;
    char *nul;

    /*
     * Opportunistic first read into a stack buffer. Each daemon
     * connection is per-request, so there is no risk of
     * over-reading into a following request.
     */

    len = sizeof(preread);
    if ((rv = apr_socket_recv(sock, preread, &len)) != APR_SUCCESS)
        return rv;
    got = len;

    /*
     * Top up until we have at least the length prefix. In practice
     * the first recv() already covers this, but stream sockets can
     * deliver short reads so handle the case explicitly.
     */

    while (got < sizeof(total))
    {
        len = sizeof(preread) - got;
        if ((rv = apr_socket_recv(sock, preread + got, &len)) != APR_SUCCESS)
            return rv;
        got += len;
    }

    memcpy(&total, preread, sizeof(total));

    /*
     * Reject frames too small to hold the string count or larger than
     * the configured sanity cap to guard against corrupted peers.
     */

    if (total < sizeof(n) || total > WSGI_MAX_REQUEST_FRAME)
        return APR_EINVAL;

    buffer = apr_palloc(p, total);
    offset = buffer;
    end = buffer + total;

    /*
     * Copy whatever payload arrived with the length prefix, clamped
     * at total defensively. Fall back to a blocking read for any
     * remainder that did not fit in the preread buffer.
     */

    payload_have = got - sizeof(total);
    if (payload_have > total)
        payload_have = total;
    memcpy(buffer, preread + sizeof(total), payload_have);

    if (payload_have < total)
    {
        if ((rv = wsgi_socket_read(sock, buffer + payload_have,
                                   total - payload_have)) != APR_SUCCESS)
            return rv;
    }

    memcpy(&n, offset, sizeof(n));
    offset += sizeof(n);

    /* Guard against (n + 1) * sizeof(**s) overflow before allocating. */

    if (n > (APR_SIZE_MAX / sizeof(**s)) - 1)
        return APR_EINVAL;

    *s = apr_pcalloc(p, (n + 1) * sizeof(**s));

    for (i = 0; i < n; i++)
    {
        /*
         * Bounded search for the string terminator so a malformed frame
         * missing a trailing NUL cannot walk off the end of the buffer.
         */

        nul = memchr(offset, '\0', end - offset);
        if (nul == NULL)
            return APR_EINVAL;
        (*s)[i] = offset;
        offset = nul + 1;
    }

    return APR_SUCCESS;
}

apr_status_t wsgi_read_request(apr_socket_t *sock, request_rec *r)
{
    int rv;

    char **vars;

    /* Read subprocess environment from request object. */

    rv = wsgi_read_strings(sock, &vars, r->pool);

    if (rv != APR_SUCCESS)
        return rv;

    while (*vars)
    {
        char *key = *vars++;

        apr_table_setn(r->subprocess_env, key, *vars++);
    }

    return APR_SUCCESS;
}

ap_filter_rec_t *wsgi_header_filter_handle;

apr_status_t wsgi_header_filter(ap_filter_t *f, apr_bucket_brigade *b)
{
    request_rec *r = f->r;

    struct iovec vec1[4];
    apr_bucket_brigade *b2;
    char crlf[] = CRLF;
    apr_size_t buflen;

    const apr_array_header_t *elts;
    const apr_table_entry_t *t_elt;
    const apr_table_entry_t *t_end;
    struct iovec *vec2;
    struct iovec *vec2_next;

    /* Output status line. */

    if (!r->status_line)
        r->status_line = ap_get_status_line(r->status);

    vec1[0].iov_base = (void *)"Status:";
    vec1[0].iov_len = strlen("Status:");
    vec1[1].iov_base = (void *)" ";
    vec1[1].iov_len = sizeof(" ") - 1;
    vec1[2].iov_base = (void *)(r->status_line);
    vec1[2].iov_len = strlen(r->status_line);
    vec1[3].iov_base = (void *)CRLF;
    vec1[3].iov_len = sizeof(CRLF) - 1;

    b2 = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    apr_brigade_writev(b2, NULL, NULL, vec1, 4);

    /* Merge response header tables together. */

    if (!apr_is_empty_table(r->err_headers_out))
    {
        r->headers_out = apr_table_overlay(r->pool, r->err_headers_out,
                                           r->headers_out);
    }

    /* Override the content type for response. */

    if (r->content_type)
        apr_table_setn(r->headers_out, "Content-Type", r->content_type);

    /* Formt the response headers for output. */

    elts = apr_table_elts(r->headers_out);
    if (elts->nelts != 0)
    {
        t_elt = (const apr_table_entry_t *)(elts->elts);
        t_end = t_elt + elts->nelts;
        vec2 = (struct iovec *)apr_palloc(r->pool, 4 * elts->nelts *
                                                       sizeof(struct iovec));
        vec2_next = vec2;

        do
        {
            vec2_next->iov_base = (void *)(t_elt->key);
            vec2_next->iov_len = strlen(t_elt->key);
            vec2_next++;
            vec2_next->iov_base = ": ";
            vec2_next->iov_len = sizeof(": ") - 1;
            vec2_next++;
            vec2_next->iov_base = (void *)(t_elt->val);
            vec2_next->iov_len = strlen(t_elt->val);
            vec2_next++;
            vec2_next->iov_base = CRLF;
            vec2_next->iov_len = sizeof(CRLF) - 1;
            vec2_next++;
            t_elt++;
        } while (t_elt < t_end);

        apr_brigade_writev(b2, NULL, NULL, vec2, vec2_next - vec2);
    }

    /* Format terminating blank line for response headers. */

    buflen = strlen(crlf);
    apr_brigade_write(b2, NULL, NULL, crlf, buflen);

    /* Output the response headers. */

    ap_pass_brigade(f->next, b2);

    /* Remove ourselves from filter chain so we aren't called again. */

    ap_remove_output_filter(f);

    /* Output the partial response content. */

    return ap_pass_brigade(f->next, b);
}

#endif

/* vi: set sw=4 expandtab : */
