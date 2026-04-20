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

#include "wsgi_environ.h"

#include "wsgi_server.h"

static int wsgi_http_invalid_header(const char *w)
{
    char c;

    while ((c = *w++) != 0)
    {
        if (!apr_isalnum(c) && c != '-')
            return 1;
    }

    return 0;
}

static void wsgi_drop_invalid_headers(request_rec *r)
{
    /*
     * Apache 2.2 when converting headers for CGI variables, doesn't
     * ignore headers with invalid names. That is, any which use any
     * characters besides alphanumerics and the '-' character. This
     * opens us up to header spoofing whereby something can inject
     * multiple headers which differ by using non alphanumeric
     * characters in the same position, which would then encode to same
     * value. Since not easy to cleanup after the fact, as a workaround,
     * is easier to simply remove the invalid headers. This will make
     * things end up being the same as Apache 2.4. Doing this could
     * annoy some users of Apache 2.2 who were using invalid headers,
     * but things will break for them under Apache 2.4 anyway.
     */

    apr_array_header_t *to_delete = NULL;

    const apr_array_header_t *hdrs_arr;
    const apr_table_entry_t *hdrs;

    int i;

    hdrs_arr = apr_table_elts(r->headers_in);
    hdrs = (const apr_table_entry_t *)hdrs_arr->elts;

    for (i = 0; i < hdrs_arr->nelts; ++i)
    {
        if (!hdrs[i].key)
        {
            continue;
        }

        if (wsgi_http_invalid_header(hdrs[i].key))
        {
            char **new;

            if (!to_delete)
                to_delete = apr_array_make(r->pool, 1, sizeof(char *));

            new = (char **)apr_array_push(to_delete);
            *new = hdrs[i].key;
        }
    }

    if (to_delete)
    {
        char *key;

        for (i = 0; i < to_delete->nelts; i++)
        {
            key = ((char **)to_delete->elts)[i];

            apr_table_unset(r->headers_in, key);
        }
    }
}

static const char *wsgi_proxy_client_headers[] = {
    "HTTP_X_FORWARDED_FOR",
    "HTTP_X_CLIENT_IP",
    "HTTP_X_REAL_IP",
    NULL,
};

static const char *wsgi_proxy_scheme_headers[] = {
    "HTTP_X_FORWARDED_HTTPS",
    "HTTP_X_FORWARDED_PROTO",
    "HTTP_X_FORWARDED_SCHEME",
    "HTTP_X_FORWARDED_SSL",
    "HTTP_X_HTTPS",
    "HTTP_X_SCHEME",
    NULL,
};

static const char *wsgi_proxy_host_headers[] = {
    "HTTP_X_FORWARDED_HOST",
    "HTTP_X_HOST",
    NULL,
};

static const char *wsgi_proxy_script_name_headers[] = {
    "HTTP_X_SCRIPT_NAME",
    "HTTP_X_FORWARDED_SCRIPT_NAME",
    NULL,
};

static int wsgi_ip_is_in_array(apr_sockaddr_t *client_ip,
                               apr_array_header_t *proxy_ips)
{
    int i;
    apr_ipsubnet_t **subs = (apr_ipsubnet_t **)proxy_ips->elts;

    for (i = 0; i < proxy_ips->nelts; i++)
    {
        if (apr_ipsubnet_test(subs[i], client_ip))
        {
            return 1;
        }
    }

    return 0;
}

static void wsgi_process_forwarded_for(request_rec *r,
                                       WSGIRequestConfig *config,
                                       const char *value)
{
    if (config->trusted_proxies)
    {
        /*
         * A potentially comma separated list where client we are
         * interested in will be that immediately before the last
         * trusted proxy working from the end forwards. If there
         * are no trusted proxies then we use the last.
         */

        apr_array_header_t *arr;

        arr = apr_array_make(r->pool, 3, sizeof(char *));

        while (*value != '\0')
        {
            /* Skip leading whitespace for item. */

            while (*value != '\0' && apr_isspace(*value))
                value++;

            if (*value != '\0')
            {
                const char *end = NULL;
                const char *next = NULL;

                char **entry = NULL;

                end = value;

                while (*end != '\0' && *end != ',')
                    end++;

                if (*end == '\0')
                    next = end;
                else if (*end == ',')
                    next = end + 1;

                /* Need deal with trailing whitespace. */

                while (end != value)
                {
                    if (!apr_isspace(*(end - 1)))
                        break;

                    end--;
                }

                /*
                 * Skip empty list elements per RFC 9110 §5.6.1, which
                 * requires recipients to parse and ignore them.
                 */

                if (end != value)
                {
                    entry = (char **)apr_array_push(arr);
                    *entry = apr_pstrndup(r->pool, value, (end - value));
                }

                value = next;
            }
        }

        if (arr->nelts != 0)
        {
            /* HTTP_X_FORWARDED_FOR wasn't just an empty string. */

            char **items;
            int first = -1;
            int i;

            items = (char **)arr->elts;

            /*
             * Work out the position of the IP closest to the start
             * that we actually trusted.
             */

            for (i = arr->nelts; i > 0;)
            {
                apr_sockaddr_t *sa;
                apr_status_t rv;

                i--;

                rv = apr_sockaddr_info_get(&sa, items[i], APR_UNSPEC,
                                           0, 0, r->pool);

                if (rv == APR_SUCCESS)
                {
                    if (!wsgi_ip_is_in_array(sa, config->trusted_proxies))
                        break;

                    first = i;
                }
                else
                {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                  "mod_wsgi (pid=%d): Forwarded IP of \"%s\" is "
                                  "not a valid IP address.",
                                  getpid(), items[i]);
                    break;
                }
            }

            if (first >= 0)
            {
                /*
                 * We found at least one trusted IP. We use the
                 * IP that may have appeared before that as
                 * REMOTE_ADDR. We rewrite HTTP_X_FORWARDED_FOR
                 * to record only from REMOTE_ADDR onwards.
                 */

                char *list;

                i = first - 1;
                if (i < 0)
                    i = 0;

                apr_table_setn(r->subprocess_env, "REMOTE_ADDR", items[i]);

                list = items[i];

                i++;

                while (arr->nelts != i)
                {
                    list = apr_pstrcat(r->pool, list, ", ", items[i], NULL);
                    i++;
                }

                apr_table_setn(r->subprocess_env, "HTTP_X_FORWARDED_FOR",
                               list);
            }
            else
            {
                /*
                 * No trusted IP. Use the last for REMOTE_ADDR.
                 * We rewrite HTTP_X_FORWARDED_FOR to record only
                 * the last.
                 */

                apr_table_setn(r->subprocess_env, "REMOTE_ADDR",
                               items[arr->nelts - 1]);
                apr_table_setn(r->subprocess_env, "HTTP_X_FORWARDED_FOR",
                               items[arr->nelts - 1]);
            }
        }
    }
    else
    {
        /*
         * We do not need to validate the proxies. We will have a
         * potentially comma separated list where the client we
         * are interested in will be listed first.
         */

        const char *end = NULL;

        /*
         * Loop until we find the first non-empty list element. Empty
         * elements are skipped per RFC 9110 §5.6.1.
         */

        while (*value != '\0')
        {
            const char *next = NULL;

            /* Skip leading whitespace for item. */

            while (*value != '\0' && apr_isspace(*value))
                value++;

            if (*value == '\0')
                break;

            end = value;

            while (*end != '\0' && *end != ',')
                end++;

            next = (*end == ',') ? end + 1 : end;

            /* Need deal with trailing whitespace. */

            while (end != value)
            {
                if (!apr_isspace(*(end - 1)))
                    break;

                end--;
            }

            if (end != value)
            {
                /* Override REMOTE_ADDR. Leave HTTP_X_FORWARDED_FOR. */

                apr_table_setn(r->subprocess_env, "REMOTE_ADDR",
                               apr_pstrndup(r->pool, value, (end - value)));
                break;
            }

            value = next;
        }
    }
}

static void wsgi_process_proxy_headers(request_rec *r)
{
    WSGIRequestConfig *config = NULL;

    apr_array_header_t *trusted_proxy_headers = NULL;

    int match_client_header = 0;
    int match_host_header = 0;
    int match_script_name_header = 0;
    int match_scheme_header = 0;

    const char *trusted_client_header = NULL;
    const char *trusted_host_header = NULL;
    const char *trusted_script_name_header = NULL;
    const char *trusted_scheme_header = NULL;

    int i = 0;

    int trusted_proxy = 1;

    const char *client_ip = NULL;

    apr_status_t rv;

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    trusted_proxy_headers = config->trusted_proxy_headers;

    /* Nothing to do if no trusted headers have been specified. */

    if (!trusted_proxy_headers)
        return;

    /*
     * Check for any special processing required for each trusted
     * header which has been specified. We should only do this if
     * there was no list of trusted proxies, or if the client IP
     * was that of a trusted proxy.
     */

    if (config->trusted_proxies)
    {
        client_ip = apr_table_get(r->subprocess_env, "REMOTE_ADDR");

        if (client_ip)
        {
            apr_sockaddr_t *sa;

            rv = apr_sockaddr_info_get(&sa, client_ip, APR_UNSPEC,
                                       0, 0, r->pool);

            if (rv == APR_SUCCESS)
            {
                if (!wsgi_ip_is_in_array(sa, config->trusted_proxies))
                    trusted_proxy = 0;
            }
            else
            {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "mod_wsgi (pid=%d): REMOTE_ADDR of \"%s\" is "
                              "not a valid IP address.",
                              getpid(), client_ip);

                trusted_proxy = 0;
            }
        }
        else
            trusted_proxy = 0;
    }

    if (trusted_proxy)
    {
        for (i = 0; i < trusted_proxy_headers->nelts; i++)
        {
            const char *name;
            const char *value;

            name = ((const char **)trusted_proxy_headers->elts)[i];
            value = apr_table_get(r->subprocess_env, name);

            if (!strcmp(name, "HTTP_X_FORWARDED_FOR"))
            {
                match_client_header = 1;

                if (value)
                {
                    wsgi_process_forwarded_for(r, config, value);

                    trusted_client_header = name;
                }
            }
            else if (!strcmp(name, "HTTP_X_CLIENT_IP") ||
                     !strcmp(name, "HTTP_X_REAL_IP"))
            {

                match_client_header = 1;

                if (value)
                {
                    /* Use the value as is. */

                    apr_table_setn(r->subprocess_env, "REMOTE_ADDR", value);

                    trusted_client_header = name;
                }
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_HOST") ||
                     !strcmp(name, "HTTP_X_HOST"))
            {

                match_host_header = 1;

                if (value)
                {
                    /* Use the value as is. May include a port. */

                    trusted_host_header = name;

                    apr_table_setn(r->subprocess_env, "HTTP_HOST", value);
                }
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_SERVER"))
            {
                if (value)
                {
                    /* Use the value as is. */

                    apr_table_setn(r->subprocess_env, "SERVER_NAME", value);
                }
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_PORT"))
            {
                if (value)
                {
                    /* Use the value as is. */

                    apr_table_setn(r->subprocess_env, "SERVER_PORT", value);
                }
            }
            else if (!strcmp(name, "HTTP_X_SCRIPT_NAME") ||
                     !strcmp(name, "HTTP_X_FORWARDED_SCRIPT_NAME"))
            {

                match_script_name_header = 1;

                if (value)
                {
                    /*
                     * Use the value as is. We want to remember what the
                     * original value for SCRIPT_NAME was though.
                     */

                    apr_table_setn(r->subprocess_env, "mod_wsgi.mount_point",
                                   value);

                    trusted_script_name_header = name;

                    apr_table_setn(r->subprocess_env, "SCRIPT_NAME", value);
                }
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_PROTO") ||
                     !strcmp(name, "HTTP_X_FORWARDED_SCHEME") ||
                     !strcmp(name, "HTTP_X_SCHEME"))
            {

                match_scheme_header = 1;

                if (value)
                {
                    trusted_scheme_header = name;

                    /* Value can be either 'http' or 'https'. */

                    if (!strcasecmp(value, "https"))
                        apr_table_setn(r->subprocess_env, "HTTPS", "1");
                    else if (!strcasecmp(value, "http"))
                        apr_table_unset(r->subprocess_env, "HTTPS");
                }
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_HTTPS") ||
                     !strcmp(name, "HTTP_X_FORWARDED_SSL") ||
                     !strcmp(name, "HTTP_X_HTTPS"))
            {

                match_scheme_header = 1;

                if (value)
                {
                    trusted_scheme_header = name;

                    /*
                     * Value can be a boolean like flag such as 'On',
                     * 'Off', 'true', 'false', '1' or '0'.
                     */

                    if (!strcasecmp(value, "On") ||
                        !strcasecmp(value, "true") ||
                        !strcasecmp(value, "1"))
                    {

                        apr_table_setn(r->subprocess_env, "HTTPS", "1");
                    }
                    else if (!strcasecmp(value, "Off") ||
                             !strcasecmp(value, "false") ||
                             !strcasecmp(value, "0"))
                    {

                        apr_table_unset(r->subprocess_env, "HTTPS");
                    }
                }
            }
        }
    }
    else
    {
        /*
         * If it isn't a trusted proxy, we still need to knock
         * out any headers for categories we were interested in.
         */

        for (i = 0; i < trusted_proxy_headers->nelts; i++)
        {
            const char *name;

            name = ((const char **)trusted_proxy_headers->elts)[i];

            if (!strcmp(name, "HTTP_X_FORWARDED_FOR") ||
                !strcmp(name, "HTTP_X_CLIENT_IP") ||
                !strcmp(name, "HTTP_X_REAL_IP"))
            {

                match_client_header = 1;
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_HOST") ||
                     !strcmp(name, "HTTP_X_HOST"))
            {

                match_host_header = 1;
            }
            else if (!strcmp(name, "HTTP_X_SCRIPT_NAME") ||
                     !strcmp(name, "HTTP_X_FORWARDED_SCRIPT_NAME"))
            {

                match_script_name_header = 1;
            }
            else if (!strcmp(name, "HTTP_X_FORWARDED_PROTO") ||
                     !strcmp(name, "HTTP_X_FORWARDED_SCHEME") ||
                     !strcmp(name, "HTTP_X_SCHEME") ||
                     !strcmp(name, "HTTP_X_FORWARDED_HTTPS") ||
                     !strcmp(name, "HTTP_X_FORWARDED_SSL") ||
                     !strcmp(name, "HTTP_X_HTTPS"))
            {

                match_scheme_header = 1;
            }
        }
    }

    /*
     * Remove all client IP headers from request environment which
     * weren't matched as being trusted.
     */

    if (match_client_header)
    {
        const char *name = NULL;

        for (i = 0; (name = wsgi_proxy_client_headers[i]); i++)
        {
            if (!trusted_client_header || strcmp(name, trusted_client_header))
            {
                apr_table_unset(r->subprocess_env, name);
            }
        }
    }

    /*
     * Remove all proxy scheme headers from request environment
     * which weren't matched as being trusted.
     */

    if (match_scheme_header)
    {
        const char *name = NULL;

        for (i = 0; (name = wsgi_proxy_scheme_headers[i]); i++)
        {
            if (!trusted_scheme_header || strcmp(name, trusted_scheme_header))
            {
                apr_table_unset(r->subprocess_env, name);
            }
        }
    }

    /*
     * Remove all proxy host headers from request environment which
     * weren't matched as being trusted.
     */

    if (match_host_header)
    {
        const char *name = NULL;

        for (i = 0; (name = wsgi_proxy_host_headers[i]); i++)
        {
            if (!trusted_host_header || strcmp(name, trusted_host_header))
                apr_table_unset(r->subprocess_env, name);
        }
    }

    /*
     * Remove all proxy script name headers from request environment
     * which weren't matched as being trusted.
     */

    if (match_script_name_header)
    {
        const char *name = NULL;

        for (i = 0; (name = wsgi_proxy_script_name_headers[i]); i++)
        {
            if (!trusted_script_name_header ||
                strcmp(name, trusted_script_name_header))
            {
                apr_table_unset(r->subprocess_env, name);
            }
        }
    }
}

static APR_OPTIONAL_FN_TYPE(ssl_is_https) *wsgi_is_https = NULL;

void wsgi_environ_child_init(void)
{
    /*
     * Retrieve mod_ssl's optional function once per child process
     * after post-config has completed but before any requests are
     * served. Doing it here rather than lazily in wsgi_build_environment
     * avoids a benign but avoidable race across worker threads. If
     * mod_ssl is not loaded the pointer remains NULL and the HTTPS
     * check in wsgi_build_environment short circuits.
     */

    wsgi_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
}

void wsgi_build_environment(request_rec *r)
{
    WSGIRequestConfig *config = NULL;

    const char *value = NULL;
    const char *script_name = NULL;
    const char *path_info = NULL;

    conn_rec *c = r->connection;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    /*
     * Remove any invalid headers which use invalid characters.
     * This is necessary to ensure that someone doesn't try and
     * take advantage of header spoofing. This can come about
     * where characters other than alphanumerics or '-' are used
     * as the conversion of non alphanumerics to '_' means one
     * can get collisions. This is technically only an issue
     * with Apache 2.2 as Apache 2.4 addresses the problem and
     * drops them anyway. Still go through and drop them even
     * for Apache 2.4 as not sure which version of Apache 2.4
     * introduces the change.
     */

    wsgi_drop_invalid_headers(r);

    /* Populate environment with standard CGI variables. */

    ap_add_cgi_vars(r);
    ap_add_common_vars(r);

    /*
     * Mutate a HEAD request into a GET request. This is
     * required because WSGI specification doesn't lay out
     * clearly how WSGI applications should treat a HEAD
     * request. Generally authors of WSGI applications or
     * frameworks take it that they do not need to return any
     * content, but this screws up any Apache output filters
     * which need to see all the response content in order to
     * correctly set up response headers for a HEAD request such
     * that they are the same as a GET request. Thus change a
     * HEAD request into a GET request to ensure that request
     * content is generated. If using Apache 2.X we can skip
     * doing this if we know there is no output filter that
     * might change the content and/or headers.
     *
     * The default behaviour here of changing it if an output
     * filter is detected can be overridden using the directive
     * WSGIMapHEADToGet. The default value is 'Auto'. If set to
     * 'On' then it remapped regardless of whether an output
     * filter is present. If 'Off' then it will be left alone
     * and the original value used.
     */

    if (config->map_head_to_get == 2)
    {
        if (r->method_number == M_GET && r->header_only &&
            r->output_filters && r->output_filters->frec &&
            r->output_filters->frec->ftype < AP_FTYPE_PROTOCOL)
            apr_table_setn(r->subprocess_env, "REQUEST_METHOD", "GET");
    }
    else if (config->map_head_to_get == 1)
    {
        if (r->method_number == M_GET)
            apr_table_setn(r->subprocess_env, "REQUEST_METHOD", "GET");
    }

    /*
     * If enabled, pass along authorisation headers which Apache
     * leaves out of CGI environment. WSGI still needs to see
     * these if it needs to implement any of the standard
     * authentication schemes such as Basic and Digest. We do
     * not pass these through by default though as it can result
     * in passwords being leaked though to a WSGI application
     * when it shouldn't. This would be a problem where there is
     * some sort of site wide authorisation scheme in place
     * which has got nothing to do with specific applications.
     */

    if (config->pass_authorization)
    {
        value = apr_table_get(r->headers_in, "Authorization");
        if (value)
            apr_table_setn(r->subprocess_env, "HTTP_AUTHORIZATION", value);
    }

    /* If PATH_INFO not set, set it to an empty string. */

    value = apr_table_get(r->subprocess_env, "PATH_INFO");
    if (!value)
        apr_table_setn(r->subprocess_env, "PATH_INFO", "");

    /* If SCRIPT_NAME not set, set it to an empty string. */

    value = apr_table_get(r->subprocess_env, "SCRIPT_NAME");
    if (!value)
        apr_table_setn(r->subprocess_env, "SCRIPT_NAME", "");

    /*
     * Multiple slashes are not always collapsed into a single
     * slash in SCRIPT_NAME and PATH_INFO with Apache 1.3 and
     * Apache 2.X behaving a bit differently. Because some WSGI
     * applications don't deal with multiple slashes properly we
     * collapse any duplicate slashes to a single slash so
     * Apache behaviour is consistent across all versions. We
     * don't care that PATH_TRANSLATED can on Apache 1.3 still
     * contain multiple slashes as that should not be getting
     * used from a WSGI application anyway.
     */

    script_name = apr_table_get(r->subprocess_env, "SCRIPT_NAME");

    if (strstr(script_name, "//"))
    {
        script_name = apr_pstrdup(r->pool, script_name);
        ap_no2slash((char *)script_name);
        apr_table_setn(r->subprocess_env, "SCRIPT_NAME", script_name);
    }

    path_info = apr_table_get(r->subprocess_env, "PATH_INFO");

    if (strstr(path_info, "//"))
    {
        path_info = apr_pstrdup(r->pool, path_info);
        ap_no2slash((char *)path_info);
        apr_table_setn(r->subprocess_env, "PATH_INFO", path_info);
    }

    /*
     * Save away the SCRIPT_NAME and PATH_INFO values at this point
     * so we have a way of determining if they are rewritten somehow.
     * This can be important when dealing with rewrite rules and
     * a trusted header was being handled for SCRIPT_NAME.
     */

    apr_table_setn(r->subprocess_env, "mod_wsgi.script_name", script_name);
    apr_table_setn(r->subprocess_env, "mod_wsgi.path_info", path_info);

    /*
     * Perform fixups on environment based on trusted proxy headers
     * sent through from a front end proxy.
     */

    wsgi_process_proxy_headers(r);

    /*
     * Determine whether connection uses HTTPS protocol. This has
     * to be done after and fixups due to trusted proxy headers.
     * wsgi_is_https is populated once per child process in
     * wsgi_environ_child_init and will be NULL if mod_ssl is not
     * loaded.
     */

    if (wsgi_is_https && wsgi_is_https(r->connection))
        apr_table_set(r->subprocess_env, "HTTPS", "1");

    /*
     * Set values specific to mod_wsgi configuration. These control
     * aspects of how a request is managed but don't strictly need
     * to be passed through to the application itself. It is though
     * easier to set them here as then they are carried across to
     * the daemon process as part of the environment where they can
     * be extracted and used.
     */

    apr_table_setn(r->subprocess_env, "mod_wsgi.process_group",
                   config->process_group);
    apr_table_setn(r->subprocess_env, "mod_wsgi.application_group",
                   config->application_group);
    apr_table_setn(r->subprocess_env, "mod_wsgi.callable_object",
                   config->callable_object);

    apr_table_setn(r->subprocess_env, "mod_wsgi.request_handler", r->handler);
    apr_table_setn(r->subprocess_env, "mod_wsgi.handler_script",
                   config->handler_script);

    apr_table_setn(r->subprocess_env, "mod_wsgi.script_reloading",
                   apr_psprintf(r->pool, "%d", config->script_reloading));

#if defined(MOD_WSGI_WITH_DAEMONS)
    apr_table_setn(r->subprocess_env, "mod_wsgi.listener_host",
                   c->local_addr->hostname ? c->local_addr->hostname : "");
    apr_table_setn(r->subprocess_env, "mod_wsgi.listener_port",
                   apr_psprintf(r->pool, "%d", c->local_addr->port));
#endif

    apr_table_setn(r->subprocess_env, "mod_wsgi.enable_sendfile",
                   apr_psprintf(r->pool, "%d", config->enable_sendfile));
    apr_table_setn(r->subprocess_env, "mod_wsgi.ignore_activity",
                   apr_psprintf(r->pool, "%d", config->ignore_activity));

    apr_table_setn(r->subprocess_env, "mod_wsgi.request_start",
                   apr_psprintf(r->pool, "%" APR_TIME_T_FMT, r->request_time));

    if (!r->log_id)
    {
        const char **id;

        /* Need to cast const away. */

        id = &((request_rec *)r)->log_id;

        ap_run_generate_log_id(c, r, id);
    }

    if (r->log_id)
        apr_table_setn(r->subprocess_env, "mod_wsgi.request_id", r->log_id);
    if (r->connection->log_id)
        apr_table_setn(r->subprocess_env, "mod_wsgi.connection_id",
                       r->connection->log_id);
}

/* vi: set sw=4 expandtab : */
