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

#include "wsgi_logger.h"
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

/*
 * Proxy header registry. This is the single source of truth for the set
 * of trusted-proxy-related headers mod_wsgi understands, the category
 * each belongs to (used both for deriving the match flag and for the
 * post-rewrite trim pass that strips non-winning synonyms), and the
 * rewrite handler invoked when the peer is trusted and the header is
 * present. Adding a new synonym is a one-line registry entry.
 */

typedef enum
{
    WSGI_PROXY_CATEGORY_NONE = 0,
    WSGI_PROXY_CATEGORY_CLIENT,
    WSGI_PROXY_CATEGORY_HOST,
    WSGI_PROXY_CATEGORY_SERVER,
    WSGI_PROXY_CATEGORY_PORT,
    WSGI_PROXY_CATEGORY_SCRIPT_NAME,
    WSGI_PROXY_CATEGORY_SCHEME,
    WSGI_PROXY_CATEGORY_MAX,
} wsgi_proxy_category_t;

typedef struct
{
    const char *name;
    wsgi_proxy_category_t category;
    void (*apply)(request_rec *, WSGIRequestConfig *, const char *);
} wsgi_proxy_header_entry_t;

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
                    wsgi_log_rerror(APLOG_TRACE1, 0, r,
                                    "Forwarded IP of \"%s\" is not a valid "
                                    "IP address.",
                                    items[i]);
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

static void wsgi_apply_forwarded_for(request_rec *r,
                                     WSGIRequestConfig *config,
                                     const char *value)
{
    wsgi_process_forwarded_for(r, config, value);
}

static void wsgi_apply_client_ip_verbatim(request_rec *r,
                                          WSGIRequestConfig *config,
                                          const char *value)
{
    (void)config;

    /* Use the value as is. */

    apr_table_setn(r->subprocess_env, "REMOTE_ADDR", value);
}

static void wsgi_apply_forwarded_host(request_rec *r,
                                      WSGIRequestConfig *config,
                                      const char *value)
{
    (void)config;

    /* Use the value as is. May include a port. */

    apr_table_setn(r->subprocess_env, "HTTP_HOST", value);
}

static void wsgi_apply_forwarded_server(request_rec *r,
                                        WSGIRequestConfig *config,
                                        const char *value)
{
    (void)config;

    /* Use the value as is. */

    apr_table_setn(r->subprocess_env, "SERVER_NAME", value);
}

static void wsgi_apply_forwarded_port(request_rec *r,
                                      WSGIRequestConfig *config,
                                      const char *value)
{
    (void)config;

    /* Use the value as is. */

    apr_table_setn(r->subprocess_env, "SERVER_PORT", value);
}

static void wsgi_apply_script_name(request_rec *r,
                                   WSGIRequestConfig *config,
                                   const char *value)
{
    (void)config;

    /*
     * Use the value as is. We want to remember what the
     * original value for SCRIPT_NAME was though.
     */

    apr_table_setn(r->subprocess_env, "mod_wsgi.mount_point", value);
    apr_table_setn(r->subprocess_env, "SCRIPT_NAME", value);
}

static void wsgi_apply_scheme_string(request_rec *r,
                                     WSGIRequestConfig *config,
                                     const char *value)
{
    (void)config;

    /* Value can be either 'http' or 'https'. */

    if (!strcasecmp(value, "https"))
        apr_table_setn(r->subprocess_env, "HTTPS", "1");
    else if (!strcasecmp(value, "http"))
        apr_table_unset(r->subprocess_env, "HTTPS");
}

static void wsgi_apply_scheme_bool(request_rec *r,
                                   WSGIRequestConfig *config,
                                   const char *value)
{
    (void)config;

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

static const wsgi_proxy_header_entry_t wsgi_proxy_header_registry[] = {
    {"HTTP_X_FORWARDED_FOR", WSGI_PROXY_CATEGORY_CLIENT, wsgi_apply_forwarded_for},
    {"HTTP_X_CLIENT_IP", WSGI_PROXY_CATEGORY_CLIENT, wsgi_apply_client_ip_verbatim},
    {"HTTP_X_REAL_IP", WSGI_PROXY_CATEGORY_CLIENT, wsgi_apply_client_ip_verbatim},
    {"HTTP_X_FORWARDED_HOST", WSGI_PROXY_CATEGORY_HOST, wsgi_apply_forwarded_host},
    {"HTTP_X_HOST", WSGI_PROXY_CATEGORY_HOST, wsgi_apply_forwarded_host},
    {"HTTP_X_FORWARDED_SERVER", WSGI_PROXY_CATEGORY_SERVER, wsgi_apply_forwarded_server},
    {"HTTP_X_FORWARDED_PORT", WSGI_PROXY_CATEGORY_PORT, wsgi_apply_forwarded_port},
    {"HTTP_X_SCRIPT_NAME", WSGI_PROXY_CATEGORY_SCRIPT_NAME, wsgi_apply_script_name},
    {"HTTP_X_FORWARDED_SCRIPT_NAME", WSGI_PROXY_CATEGORY_SCRIPT_NAME, wsgi_apply_script_name},
    {"HTTP_X_FORWARDED_PROTO", WSGI_PROXY_CATEGORY_SCHEME, wsgi_apply_scheme_string},
    {"HTTP_X_FORWARDED_SCHEME", WSGI_PROXY_CATEGORY_SCHEME, wsgi_apply_scheme_string},
    {"HTTP_X_SCHEME", WSGI_PROXY_CATEGORY_SCHEME, wsgi_apply_scheme_string},
    {"HTTP_X_FORWARDED_HTTPS", WSGI_PROXY_CATEGORY_SCHEME, wsgi_apply_scheme_bool},
    {"HTTP_X_FORWARDED_SSL", WSGI_PROXY_CATEGORY_SCHEME, wsgi_apply_scheme_bool},
    {"HTTP_X_HTTPS", WSGI_PROXY_CATEGORY_SCHEME, wsgi_apply_scheme_bool},
    {NULL, WSGI_PROXY_CATEGORY_NONE, NULL},
};

static const wsgi_proxy_header_entry_t *
wsgi_lookup_proxy_header(const char *name)
{
    const wsgi_proxy_header_entry_t *entry;

    for (entry = wsgi_proxy_header_registry; entry->name; entry++)
    {
        if (!strcmp(entry->name, name))
            return entry;
    }

    return NULL;
}

typedef struct
{
    int matched;
    const char *trusted_header;
} wsgi_proxy_category_state_t;

static unsigned int wsgi_process_proxy_headers(request_rec *r)
{
    WSGIRequestConfig *config = NULL;

    apr_array_header_t *trusted_proxy_headers = NULL;

    wsgi_proxy_category_state_t category_state[WSGI_PROXY_CATEGORY_MAX];

    unsigned int applied = 0;

    int i = 0;
    int category = 0;

    int trusted_proxy = 1;

    const char *client_ip = NULL;

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    trusted_proxy_headers = config->trusted_proxy_headers;

    /* Nothing to do if no trusted headers have been specified. */

    if (!trusted_proxy_headers)
        return 0;

    memset(category_state, 0, sizeof(category_state));

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
            apr_status_t rv;

            rv = apr_sockaddr_info_get(&sa, client_ip, APR_UNSPEC,
                                       0, 0, r->pool);

            if (rv == APR_SUCCESS)
            {
                if (!wsgi_ip_is_in_array(sa, config->trusted_proxies))
                    trusted_proxy = 0;
            }
            else
            {
                wsgi_log_rerror(APLOG_TRACE1, 0, r,
                                "REMOTE_ADDR of \"%s\" is not a valid IP "
                                "address.",
                                client_ip);

                trusted_proxy = 0;
            }
        }
        else
            trusted_proxy = 0;
    }

    /*
     * Walk every header the admin declared as trusted. For each
     * recognised entry, unconditionally record its category as matched
     * (this drives the trim loop below so untrusted spoofed values of
     * synonyms are stripped regardless of peer trust). When the peer is
     * trusted and the header carries a value, invoke the registered
     * apply handler to rewrite derived environment variables, and
     * remember which synonym "won" so the trim loop preserves it.
     */

    for (i = 0; i < trusted_proxy_headers->nelts; i++)
    {
        const char *name;
        const char *value;
        const wsgi_proxy_header_entry_t *entry;

        name = ((const char **)trusted_proxy_headers->elts)[i];
        entry = wsgi_lookup_proxy_header(name);

        if (!entry)
            continue;

        if (entry->category != WSGI_PROXY_CATEGORY_NONE)
            category_state[entry->category].matched = 1;

        if (!trusted_proxy || !entry->apply)
            continue;

        value = apr_table_get(r->subprocess_env, name);
        if (!value)
            continue;

        entry->apply(r, config, value);

        if (entry->category != WSGI_PROXY_CATEGORY_NONE)
            category_state[entry->category].trusted_header = name;
    }

    /*
     * Remove all synonym headers for each matched category from the
     * request environment except the one that won (if any). This
     * protects categories which the admin declared trusted from being
     * polluted by spoofed values of other synonyms in the same
     * category.
     */

    for (category = WSGI_PROXY_CATEGORY_NONE + 1;
         category < WSGI_PROXY_CATEGORY_MAX;
         category++)
    {
        const wsgi_proxy_header_entry_t *entry;
        const char *kept = category_state[category].trusted_header;

        if (kept)
            applied |= (1u << category);

        if (!category_state[category].matched)
            continue;

        for (entry = wsgi_proxy_header_registry; entry->name; entry++)
        {
            if (entry->category != (wsgi_proxy_category_t)category)
                continue;
            if (kept && !strcmp(entry->name, kept))
                continue;
            apr_table_unset(r->subprocess_env, entry->name);
        }
    }

    return applied;
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

/*
 * Replicates the work of Apache's ap_add_cgi_vars() and ap_add_common_vars()
 * but skips:
 *
 *   - PATH_TRANSLATED. ap_add_cgi_vars() computes this by issuing an Apache
 *     subrequest via ap_sub_req_lookup_uri() against the request's PATH_INFO.
 *     The subrequest can have surprising side effects (rerunning translation
 *     hooks, walking the full request_rec lifecycle, touching the filesystem)
 *     and PATH_TRANSLATED is not used by WSGI applications.
 *
 *   - REMOTE_HOST. ap_add_common_vars() calls ap_get_useragent_host() which
 *     can trigger a reverse-DNS lookup when HostnameLookups is enabled.
 *
 *   - REMOTE_IDENT. ap_add_common_vars() calls ap_get_remote_logname() which
 *     can issue an RFC 1413 ident protocol lookup when IdentityCheck is on.
 *
 *   - PATH and platform library-path variables (LD_LIBRARY_PATH,
 *     DYLD_LIBRARY_PATH, SHLIB_PATH, LIBPATH, LIBRARY_PATH, PERLLIB_PREFIX,
 *     SystemRoot, COMSPEC, PATHEXT, WINDIR, ETC, DPATH). These are inherited
 *     by forked CGI children and have no role for an in-process WSGI
 *     interpreter.
 *
 *   - SERVER_SIGNATURE. An HTML blob with no use to a WSGI application.
 *
 * Everything else from the two upstream functions is preserved, including
 * the cgi_pass_auth gating on Authorization/Proxy-Authorization, the strip
 * of the Proxy request header (CVE-2016-5388), the cgi_var_rules override
 * for REQUEST_URI, and the REDIRECT_* walk over r->prev.
 */

static void wsgi_add_vars_to_environment(request_rec *r)
{
    apr_table_t *e;
    server_rec *s = r->server;
    conn_rec *c = r->connection;
    core_dir_config *conf =
        (core_dir_config *)ap_get_core_module_config(r->per_dir_config);

    const apr_array_header_t *hdrs_arr = apr_table_elts(r->headers_in);
    const apr_table_entry_t *hdrs = (const apr_table_entry_t *)hdrs_arr->elts;

    int request_uri_from_original = 1;
    const char *request_uri_rule = NULL;

    char *q = NULL;
    int i;

    /*
     * Build into a temp table when r->subprocess_env already has entries
     * (e.g. set by mod_setenvif) so the final overlap-with-set replaces
     * any pre-existing values cleanly. Mirrors ap_add_common_vars().
     */

    if (apr_is_empty_table(r->subprocess_env))
        e = r->subprocess_env;
    else
        e = apr_table_make(r->pool, 25 + hdrs_arr->nelts);

    /*
     * Header copy loop, transcribed from ap_add_common_vars(). The
     * cgi_pass_auth gating on Authorization/Proxy-Authorization and the
     * Proxy header strip (CVE-2016-5388) match upstream verbatim.
     * wsgi_drop_invalid_headers() runs before this so wsgi_http2env()
     * should not return NULL, but we keep the guard for safety.
     */

    for (i = 0; i < hdrs_arr->nelts; ++i)
    {
        char *name;

        if (!hdrs[i].key)
            continue;

        if (!strcasecmp(hdrs[i].key, "Content-type"))
        {
            apr_table_addn(e, "CONTENT_TYPE", hdrs[i].val);
        }
        else if (!strcasecmp(hdrs[i].key, "Content-length"))
        {
            apr_table_addn(e, "CONTENT_LENGTH", hdrs[i].val);
        }
        else if (!strcasecmp(hdrs[i].key, "Proxy"))
        {
            /* Never expose Proxy as HTTP_PROXY (httpoxy / CVE-2016-5388). */
            continue;
        }
        else if (!strcasecmp(hdrs[i].key, "Authorization") ||
                 !strcasecmp(hdrs[i].key, "Proxy-Authorization"))
        {
            if (conf->cgi_pass_auth == AP_CGI_PASS_AUTH_ON)
            {
                name = wsgi_http2env(r->pool, hdrs[i].key);
                if (name && hdrs[i].val)
                    apr_table_addn(e, name, hdrs[i].val);
            }
        }
        else
        {
            name = wsgi_http2env(r->pool, hdrs[i].key);
            if (name && hdrs[i].val)
                apr_table_addn(e, name, hdrs[i].val);
        }
    }

    /*
     * Server identity and connection details. Match ap_add_common_vars()
     * except for the deliberate omissions described in the file-level
     * comment above (REMOTE_HOST, REMOTE_IDENT, SERVER_SIGNATURE,
     * PATH/library-path variables).
     */

    apr_table_addn(e, "SERVER_SOFTWARE", ap_get_server_banner());
    apr_table_addn(e, "SERVER_NAME",
                   ap_escape_html(r->pool, ap_get_server_name_for_url(r)));
    apr_table_addn(e, "SERVER_ADDR", c->local_ip);
    apr_table_addn(e, "SERVER_PORT",
                   apr_psprintf(r->pool, "%u", ap_get_server_port(r)));
    apr_table_addn(e, "REMOTE_ADDR", r->useragent_ip);
    apr_table_addn(e, "DOCUMENT_ROOT", ap_document_root(r));
    apr_table_setn(e, "REQUEST_SCHEME", ap_http_scheme(r));
    apr_table_addn(e, "CONTEXT_PREFIX", ap_context_prefix(r));
    apr_table_addn(e, "CONTEXT_DOCUMENT_ROOT", ap_context_document_root(r));

    if (s->server_admin)
        apr_table_addn(e, "SERVER_ADMIN", s->server_admin);

    if (apr_table_get(r->notes, "proxy-noquery") &&
        (q = ap_strchr(r->filename, '?')))
    {
        apr_table_addn(e, "SCRIPT_FILENAME",
                       apr_pstrmemdup(r->pool, r->filename,
                                      q - r->filename));
    }
    else
    {
        apr_table_addn(e, "SCRIPT_FILENAME", r->filename);
    }

    apr_table_addn(e, "REMOTE_PORT",
                   apr_itoa(r->pool, c->client_addr->port));

    if (r->user)
    {
        apr_table_addn(e, "REMOTE_USER", r->user);
    }
    else if (r->prev)
    {
        request_rec *back = r->prev;

        while (back)
        {
            if (back->user)
            {
                apr_table_addn(e, "REDIRECT_REMOTE_USER", back->user);
                break;
            }
            back = back->prev;
        }
    }

    if (r->ap_auth_type)
        apr_table_addn(e, "AUTH_TYPE", r->ap_auth_type);

    if (r->prev)
    {
        if (conf->qualify_redirect_url != AP_CORE_CONFIG_ON)
        {
            if (r->prev->uri)
                apr_table_addn(e, "REDIRECT_URL", r->prev->uri);
        }
        else
        {
            apr_uri_t *uri = &r->prev->parsed_uri;

            if (!uri->scheme)
                uri->scheme = (char *)ap_http_scheme(r->prev);
            if (!uri->port)
            {
                uri->port = ap_get_server_port(r->prev);
                uri->port_str = apr_psprintf(r->pool, "%u", uri->port);
            }
            if (!uri->hostname)
                uri->hostname = (char *)ap_get_server_name_for_url(r->prev);

            apr_table_addn(e, "REDIRECT_URL",
                           apr_uri_unparse(r->pool, uri, 0));
        }

        if (r->prev->args)
            apr_table_addn(e, "REDIRECT_QUERY_STRING", r->prev->args);
    }

    /*
     * CGI request-line variables, transcribed from ap_add_cgi_vars().
     * Use setn so these win over any pre-existing entries inherited
     * via the temp table. The PATH_TRANSLATED block is deliberately
     * omitted — that is the subrequest we are avoiding. GATEWAY_INTERFACE
     * is also omitted: it is not required by PEP 3333 and the "CGI/1.1"
     * value upstream sets is misleading for a WSGI environment.
     */

    apr_table_setn(e, "SERVER_PROTOCOL", r->protocol);
    apr_table_setn(e, "REQUEST_METHOD", r->method);
    apr_table_setn(e, "QUERY_STRING", r->args ? r->args : "");

    if (conf->cgi_var_rules)
    {
        request_uri_rule = apr_hash_get(conf->cgi_var_rules, "REQUEST_URI",
                                        APR_HASH_KEY_STRING);
        if (request_uri_rule && !strcmp(request_uri_rule, "current-uri"))
            request_uri_from_original = 0;
    }
    apr_table_setn(e, "REQUEST_URI",
                   request_uri_from_original ? wsgi_original_uri(r) : r->uri);

    if (!strcmp(r->protocol, "INCLUDED"))
    {
        apr_table_setn(e, "SCRIPT_NAME", r->uri);
        if (r->path_info && *r->path_info)
            apr_table_setn(e, "PATH_INFO", r->path_info);
    }
    else if (!r->path_info || !*r->path_info)
    {
        apr_table_setn(e, "SCRIPT_NAME", r->uri);
    }
    else
    {
        int path_info_start = ap_find_path_info(r->uri, r->path_info);

        apr_table_setn(e, "SCRIPT_NAME",
                       apr_pstrndup(r->pool, r->uri, path_info_start));
        apr_table_setn(e, "PATH_INFO", r->path_info);
    }

    /* PATH_TRANSLATED deliberately omitted (would require subrequest). */

    if (e != r->subprocess_env)
        apr_table_overlap(r->subprocess_env, e, APR_OVERLAP_TABLES_SET);
}

void wsgi_build_environment(request_rec *r)
{
    WSGIRequestConfig *config = NULL;

    const char *value = NULL;
    const char *script_name = NULL;
    const char *path_info = NULL;

    unsigned int proxy_applied = 0;

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

    /*
     * Replaced by wsgi_add_vars_to_environment() below to avoid the
     * subrequest that ap_add_cgi_vars() issues when computing
     * PATH_TRANSLATED, and to skip variables irrelevant to WSGI
     * (REMOTE_HOST, REMOTE_IDENT, PATH, library-path vars, etc.).
     * See the comment above wsgi_add_vars_to_environment() for details.
     */

    /* ap_add_cgi_vars(r); */
    /* ap_add_common_vars(r); */

    wsgi_add_vars_to_environment(r);

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
     * sent through from a front end proxy. Returns a bitmask of
     * categories whose trusted apply handler fired so the scheme
     * detection below can defer to the proxy when it authoritatively
     * declared the original client scheme.
     */

    proxy_applied = wsgi_process_proxy_headers(r);

    /*
     * Determine whether the connection uses HTTPS. This only runs if a
     * trusted X-Forwarded-Proto style header did not already settle the
     * question above, otherwise mod_ssl's view of the immediate Apache
     * hop could overwrite a "http" scheme that the proxy correctly
     * reported for the original client connection. wsgi_is_https is
     * populated once per child process in wsgi_environ_child_init and
     * will be NULL if mod_ssl is not loaded.
     */

    if (!(proxy_applied & (1u << WSGI_PROXY_CATEGORY_SCHEME)) &&
        wsgi_is_https && wsgi_is_https(r->connection))
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
