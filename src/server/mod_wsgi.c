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

#include "wsgi_apache.h"
#include "wsgi_python.h"

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifndef WIN32
#include <pwd.h>
#endif

/* Local project header files. */

#include "wsgi_version.h"
#include "wsgi_convert.h"
#include "wsgi_validate.h"
#include "wsgi_interp.h"
#include "wsgi_server.h"
#include "wsgi_logger.h"
#include "wsgi_restrict.h"
#include "wsgi_stream.h"
#include "wsgi_metrics.h"
#include "wsgi_daemon.h"
#include "wsgi_buckets.h"
#include "wsgi_thread.h"
#include "wsgi_signal.h"
#include "wsgi_shutdown.h"
#include "wsgi_adapter.h"
#include "wsgi_dispatch.h"
#include "wsgi_config.h"
#include "wsgi_auth.h"
#include "wsgi_remote.h"
#include "wsgi_environ.h"
#include "wsgi_execute.h"

/* Module information. */

module AP_MODULE_DECLARE_DATA wsgi_module;

/* Process information. */

int wsgi_multiprocess = 1;
int wsgi_multithread = 1;

static void *wsgi_create_server_config(apr_pool_t *p, server_rec *s)
{
    WSGIServerConfig *config = NULL;

    config = newWSGIServerConfig(p);

    return config;
}

static void *wsgi_merge_server_config(apr_pool_t *p, void *base_conf,
                                      void *new_conf)
{
    WSGIServerConfig *config = NULL;
    WSGIServerConfig *parent = NULL;
    WSGIServerConfig *child = NULL;

    config = newWSGIServerConfig(p);

    parent = (WSGIServerConfig *)base_conf;
    child = (WSGIServerConfig *)new_conf;

    if (child->alias_list && parent->alias_list)
    {
        config->alias_list = apr_array_append(p, child->alias_list,
                                              parent->alias_list);
    }
    else if (child->alias_list)
    {
        config->alias_list = apr_array_make(p, 20, sizeof(WSGIAliasEntry));
        apr_array_cat(config->alias_list, child->alias_list);
    }
    else if (parent->alias_list)
    {
        config->alias_list = apr_array_make(p, 20, sizeof(WSGIAliasEntry));
        apr_array_cat(config->alias_list, parent->alias_list);
    }

    if (child->restrict_process)
        config->restrict_process = child->restrict_process;
    else
        config->restrict_process = parent->restrict_process;

    if (child->process_group)
        config->process_group = child->process_group;
    else
        config->process_group = parent->process_group;

    if (child->application_group)
        config->application_group = child->application_group;
    else
        config->application_group = parent->application_group;

    if (child->callable_object)
        config->callable_object = child->callable_object;
    else
        config->callable_object = parent->callable_object;

    if (child->dispatch_script)
        config->dispatch_script = child->dispatch_script;
    else
        config->dispatch_script = parent->dispatch_script;

    if (child->pass_apache_request != -1)
        config->pass_apache_request = child->pass_apache_request;
    else
        config->pass_apache_request = parent->pass_apache_request;

    if (child->pass_authorization != -1)
        config->pass_authorization = child->pass_authorization;
    else
        config->pass_authorization = parent->pass_authorization;

    if (child->script_reloading != -1)
        config->script_reloading = child->script_reloading;
    else
        config->script_reloading = parent->script_reloading;

    if (child->error_override != -1)
        config->error_override = child->error_override;
    else
        config->error_override = parent->error_override;

    if (child->chunked_request != -1)
        config->chunked_request = child->chunked_request;
    else
        config->chunked_request = parent->chunked_request;

    if (child->map_head_to_get != -1)
        config->map_head_to_get = child->map_head_to_get;
    else
        config->map_head_to_get = parent->map_head_to_get;

    if (child->ignore_activity != -1)
        config->ignore_activity = child->ignore_activity;
    else
        config->ignore_activity = parent->ignore_activity;

    if (child->trusted_proxy_headers)
        config->trusted_proxy_headers = child->trusted_proxy_headers;
    else
        config->trusted_proxy_headers = parent->trusted_proxy_headers;

    if (child->trusted_proxies)
        config->trusted_proxies = child->trusted_proxies;
    else
        config->trusted_proxies = parent->trusted_proxies;

    if (child->enable_sendfile != -1)
        config->enable_sendfile = child->enable_sendfile;
    else
        config->enable_sendfile = parent->enable_sendfile;

    if (!child->handler_scripts)
        config->handler_scripts = parent->handler_scripts;
    else if (!parent->handler_scripts)
        config->handler_scripts = child->handler_scripts;
    else
    {
        config->handler_scripts = apr_hash_overlay(p, child->handler_scripts,
                                                   parent->handler_scripts);
    }

    return config;
}

static WSGIDirectoryConfig *newWSGIDirectoryConfig(apr_pool_t *p)
{
    WSGIDirectoryConfig *object = NULL;

    object = (WSGIDirectoryConfig *)apr_pcalloc(p, sizeof(WSGIDirectoryConfig));

    object->pool = p;

    object->process_group = NULL;
    object->application_group = NULL;
    object->callable_object = NULL;

    object->dispatch_script = NULL;

    object->pass_apache_request = -1;
    object->pass_authorization = -1;
    object->script_reloading = -1;
    object->error_override = -1;
    object->chunked_request = -1;
    object->map_head_to_get = -1;
    object->ignore_activity = -1;

    object->trusted_proxy_headers = NULL;
    object->trusted_proxies = NULL;

    object->enable_sendfile = -1;

    object->access_script = NULL;
    object->auth_user_script = NULL;
    object->auth_group_script = NULL;
    object->user_authoritative = -1;
    object->group_authoritative = -1;

    return object;
}

static void *wsgi_create_dir_config(apr_pool_t *p, char *dir)
{
    WSGIDirectoryConfig *config = NULL;

    config = newWSGIDirectoryConfig(p);

    return config;
}

static void *wsgi_merge_dir_config(apr_pool_t *p, void *base_conf,
                                   void *new_conf)
{
    WSGIDirectoryConfig *config = NULL;
    WSGIDirectoryConfig *parent = NULL;
    WSGIDirectoryConfig *child = NULL;

    config = newWSGIDirectoryConfig(p);

    parent = (WSGIDirectoryConfig *)base_conf;
    child = (WSGIDirectoryConfig *)new_conf;

    if (child->restrict_process)
        config->restrict_process = child->restrict_process;
    else
        config->restrict_process = parent->restrict_process;

    if (child->process_group)
        config->process_group = child->process_group;
    else
        config->process_group = parent->process_group;

    if (child->application_group)
        config->application_group = child->application_group;
    else
        config->application_group = parent->application_group;

    if (child->callable_object)
        config->callable_object = child->callable_object;
    else
        config->callable_object = parent->callable_object;

    if (child->dispatch_script)
        config->dispatch_script = child->dispatch_script;
    else
        config->dispatch_script = parent->dispatch_script;

    if (child->pass_apache_request != -1)
        config->pass_apache_request = child->pass_apache_request;
    else
        config->pass_apache_request = parent->pass_apache_request;

    if (child->pass_authorization != -1)
        config->pass_authorization = child->pass_authorization;
    else
        config->pass_authorization = parent->pass_authorization;

    if (child->script_reloading != -1)
        config->script_reloading = child->script_reloading;
    else
        config->script_reloading = parent->script_reloading;

    if (child->error_override != -1)
        config->error_override = child->error_override;
    else
        config->error_override = parent->error_override;

    if (child->chunked_request != -1)
        config->chunked_request = child->chunked_request;
    else
        config->chunked_request = parent->chunked_request;

    if (child->map_head_to_get != -1)
        config->map_head_to_get = child->map_head_to_get;
    else
        config->map_head_to_get = parent->map_head_to_get;

    if (child->ignore_activity != -1)
        config->ignore_activity = child->ignore_activity;
    else
        config->ignore_activity = parent->ignore_activity;

    if (child->trusted_proxy_headers)
        config->trusted_proxy_headers = child->trusted_proxy_headers;
    else
        config->trusted_proxy_headers = parent->trusted_proxy_headers;

    if (child->trusted_proxies)
        config->trusted_proxies = child->trusted_proxies;
    else
        config->trusted_proxies = parent->trusted_proxies;

    if (child->enable_sendfile != -1)
        config->enable_sendfile = child->enable_sendfile;
    else
        config->enable_sendfile = parent->enable_sendfile;

    if (child->access_script)
        config->access_script = child->access_script;
    else
        config->access_script = parent->access_script;

    if (child->auth_user_script)
        config->auth_user_script = child->auth_user_script;
    else
        config->auth_user_script = parent->auth_user_script;

    if (child->auth_group_script)
        config->auth_group_script = child->auth_group_script;
    else
        config->auth_group_script = parent->auth_group_script;

    if (child->user_authoritative != -1)
        config->user_authoritative = child->user_authoritative;
    else
        config->user_authoritative = parent->user_authoritative;

    if (child->group_authoritative != -1)
        config->group_authoritative = child->group_authoritative;
    else
        config->group_authoritative = parent->group_authoritative;

    if (!child->handler_scripts)
        config->handler_scripts = parent->handler_scripts;
    else if (!parent->handler_scripts)
        config->handler_scripts = child->handler_scripts;
    else
    {
        config->handler_scripts = apr_hash_overlay(p, child->handler_scripts,
                                                   parent->handler_scripts);
    }

    return config;
}

/* Handler for the translate name phase. */

static long wsgi_alias_matches(const char *uri, const char *alias_fakename)
{
    /* Code for this function from Apache mod_alias module. */

    const char *aliasp = alias_fakename, *urip = uri;

    while (*aliasp)
    {
        if (*aliasp == '/')
        {
            /* any number of '/' in the alias matches any number in
             * the supplied URI, but there must be at least one...
             */
            if (*urip != '/')
                return 0;

            do
            {
                ++aliasp;
            } while (*aliasp == '/');
            do
            {
                ++urip;
            } while (*urip == '/');
        }
        else
        {
            /* Other characters are compared literally */
            if (*urip++ != *aliasp++)
                return 0;
        }
    }

    /* Check last alias path component matched all the way */

    if (aliasp[-1] != '/' && *urip != '\0' && *urip != '/')
        return 0;

    /* Return number of characters from URI which matched (may be
     * greater than length of alias, since we may have matched
     * doubled slashes)
     */

    return urip - uri;
}

static int wsgi_hook_intercept(request_rec *r)
{
    WSGIServerConfig *config = NULL;

    apr_array_header_t *aliases = NULL;

    WSGIAliasEntry *entries = NULL;
    WSGIAliasEntry *entry = NULL;

    ap_regmatch_t matches[AP_MAX_REG_MATCH];

    const char *location = NULL;
    const char *application = NULL;

    int i = 0;

    config = ap_get_module_config(r->server->module_config, &wsgi_module);

    if (!config->alias_list)
        return DECLINED;

    if (r->uri[0] != '/' && r->uri[0])
        return DECLINED;

    aliases = config->alias_list;
    entries = (WSGIAliasEntry *)aliases->elts;

    for (i = 0; i < aliases->nelts; ++i)
    {
        long l = 0;

        entry = &entries[i];

        if (entry->regexp)
        {
            if (!ap_regexec(entry->regexp, r->uri, AP_MAX_REG_MATCH,
                            matches, 0))
            {
                if (entry->application)
                {
                    l = matches[0].rm_eo;

                    location = apr_pstrndup(r->pool, r->uri, l);
                    application = ap_pregsub(r->pool, entry->application,
                                             r->uri, AP_MAX_REG_MATCH,
                                             matches);
                }
            }
        }
        else if (entry->location)
        {
            l = wsgi_alias_matches(r->uri, entry->location);

            location = entry->location;
            application = entry->application;
        }

        if (l > 0)
        {
            if (!strcmp(location, "/"))
            {
                r->filename = apr_pstrcat(r->pool, application,
                                          r->uri, NULL);
            }
            else
            {
                r->filename = apr_pstrcat(r->pool, application,
                                          r->uri + l, NULL);
            }

            r->handler = "wsgi-script";
            apr_table_setn(r->notes, "alias-forced-type", r->handler);

            if (entry->process_group)
            {
                apr_table_setn(r->notes, "mod_wsgi.process_group",
                               entry->process_group);
            }
            if (entry->application_group)
            {
                apr_table_setn(r->notes, "mod_wsgi.application_group",
                               entry->application_group);
            }
            if (entry->callable_object)
            {
                apr_table_setn(r->notes, "mod_wsgi.callable_object",
                               entry->callable_object);
            }

            if (entry->pass_authorization == 0)
                apr_table_setn(r->notes, "mod_wsgi.pass_authorization", "0");
            else if (entry->pass_authorization == 1)
                apr_table_setn(r->notes, "mod_wsgi.pass_authorization", "1");

            return OK;
        }
    }

    return DECLINED;
}

/* Handler for the response handler phase. */

static int wsgi_is_script_aliased(request_rec *r)
{
    const char *t = NULL;

    t = apr_table_get(r->notes, "alias-forced-type");
    return t && (!strcasecmp(t, "wsgi-script"));
}

static int wsgi_hook_handler(request_rec *r)
{
    int status;
    apr_off_t limit = 0;

    WSGIRequestConfig *config = NULL;

    const char *value = NULL;

    const char *tenc = NULL;
    const char *lenp = NULL;

    /* Filter out the obvious case of no handler defined. */

    if (!r->handler)
        return DECLINED;

    /*
     * Construct request configuration and cache it in the
     * request object against this module so can access it later
     * from handler code.
     */

    config = wsgi_create_req_config(r->pool, r);

    ap_set_module_config(r->request_config, &wsgi_module, config);

    /*
     * Only process requests for this module. First check for
     * where target is the actual WSGI script. Then need to
     * check for the case where handler name mapped to a handler
     * script definition.
     */

    if (!strcmp(r->handler, "wsgi-script") ||
        !strcmp(r->handler, "application/x-httpd-wsgi"))
    {

        /*
         * Ensure that have adequate privileges to run the WSGI
         * script. Require ExecCGI to be specified in Options for
         * this. In doing this, using the wider interpretation that
         * ExecCGI refers to any executable like script even though
         * not a separate process execution.
         */

        if (!(ap_allow_options(r) & OPT_EXECCGI) &&
            !wsgi_is_script_aliased(r))
        {
            wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0134) "Options ExecCGI is off in this directory.");
            return HTTP_FORBIDDEN;
        }

        /* Ensure target script exists and is a file. */

        if (r->finfo.filetype == 0)
        {
            wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0135) "Target WSGI script not found or unable to "
                                                                "stat.");
            return HTTP_NOT_FOUND;
        }

        if (r->finfo.filetype == APR_DIR)
        {
            wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0136) "Attempt to invoke directory as WSGI "
                                                                "application.");
            return HTTP_FORBIDDEN;
        }

        if (wsgi_is_script_aliased(r))
        {
            /*
             * Allow any configuration supplied through request notes to
             * override respective values. Request notes are used when
             * configuration supplied with WSGIScriptAlias directives.
             */

            if ((value = apr_table_get(r->notes, "mod_wsgi.process_group")))
                config->process_group = wsgi_process_group(r, value);
            if ((value = apr_table_get(r->notes, "mod_wsgi.application_group")))
                config->application_group = wsgi_application_group(r, value);
            if ((value = apr_table_get(r->notes, "mod_wsgi.callable_object")))
                config->callable_object = value;

            if ((value = apr_table_get(r->notes,
                                       "mod_wsgi.pass_authorization")))
            {
                if (!strcmp(value, "1"))
                    config->pass_authorization = 1;
                else
                    config->pass_authorization = 0;
            }
        }
    }
#if 0
    else if (strstr(r->handler, "wsgi-handler=") == r->handler) {
        config->handler_script = apr_pstrcat(r->pool, r->handler+13, NULL);
        config->callable_object = "handle_request";
    }
#endif
    else if (config->handler_scripts)
    {
        WSGIScriptFile *entry;

        entry = (WSGIScriptFile *)apr_hash_get(config->handler_scripts,
                                               r->handler,
                                               APR_HASH_KEY_STRING);

        if (entry)
        {
            config->handler_script = entry->handler_script;
            config->callable_object = "handle_request";

            if ((value = entry->process_group))
                config->process_group = wsgi_process_group(r, value);
            if ((value = entry->application_group))
                config->application_group = wsgi_application_group(r, value);

            if ((value = entry->pass_authorization))
            {
                if (!strcmp(value, "1"))
                    config->pass_authorization = 1;
                else
                    config->pass_authorization = 0;
            }
        }
        else
            return DECLINED;
    }
    else
        return DECLINED;

    /*
     * Honour AcceptPathInfo directive. Default behaviour is
     * accept additional path information.
     */

    if ((r->used_path_info == AP_REQ_REJECT_PATH_INFO) &&
        r->path_info && *r->path_info)
    {
        wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0137) "AcceptPathInfo off disallows user's path.");
        return HTTP_NOT_FOUND;
    }

    /*
     * Setup policy to apply if request contains a body. Note that the
     * WSGI specification doesn't strictly allow for chunked request
     * content as CONTENT_LENGTH is required when reading input and
     * an application isn't meant to read more than what is defined by
     * CONTENT_LENGTH. We still optionally allow chunked request content.
     * For an application to use the content, it has to ignore the WSGI
     * specification and use read() with no arguments to read all
     * available input, or call read() with specific block size until
     * read() returns an empty string.
     */

    tenc = apr_table_get(r->headers_in, "Transfer-Encoding");

    if (tenc)
    {
        /* Only chunked transfer encoding is supported. */

        if (strcasecmp(tenc, "chunked"))
        {
            wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0138) "Unexpected value for Transfer-Encoding of "
                                                                "'%s' supplied. Only 'chunked' supported.",
                            tenc);
            return HTTP_NOT_IMPLEMENTED;
        }

        /* Only allow chunked requests when explicitly enabled. */

        if (!config->chunked_request)
        {
            wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0139) "Request requires chunked transfer encoding, "
                                                                "but support for chunked transfer encoding "
                                                                "has not been enabled.");
            return HTTP_LENGTH_REQUIRED;
        }

        /*
         * When chunked transfer encoding is specified, there should
         * not be any content length specified.
         */

        if (lenp)
        {
            wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0140) "Unexpected Content-Length header supplied "
                                                                "where Transfer-Encoding was specified as "
                                                                "'chunked'.");
            return HTTP_BAD_REQUEST;
        }
    }

    /*
     * Check to see if the request content is too large if the
     * Content-Length header is defined then end the request here. We do
     * this as otherwise it will not be done until first time input data
     * is read in by the application. Problem is that underlying HTTP
     * output filter will also generate a 413 response and the error
     * raised from the application will be appended to that. The call to
     * ap_discard_request_body() is hopefully enough to trigger sending
     * of the 413 response by the HTTP filter.
     */

    lenp = apr_table_get(r->headers_in, "Content-Length");

    if (lenp)
    {
        char *endstr;
        apr_off_t length;

        if (wsgi_strtoff(&length, lenp, &endstr, 10) || *endstr || length < 0)
        {

            wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0141) "Invalid Content-Length header value of '%s' "
                                                                "was supplied.",
                            lenp);

            return HTTP_BAD_REQUEST;
        }

        limit = ap_get_limit_req_body(r);

        if (limit && limit < length)
        {
            ap_discard_request_body(r);
            return OK;
        }
    }

    /* Build the sub process environment. */

    config->request_start = r->request_time;

    wsgi_build_environment(r);

    /*
     * If a dispatch script has been provided, as appropriate
     * allow it to override any of the configuration related
     * to what context the script will be executed in and what
     * the target callable object for the application is.
     */

    if (config->dispatch_script)
    {
        status = wsgi_execute_dispatch(r);

        if (status != OK)
            return status;
    }

    /*
     * Execute the target WSGI application script or proxy
     * request to one of the daemon processes as appropriate.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    status = wsgi_execute_remote(r);

    if (status != DECLINED)
        return status;
#endif

#if defined(MOD_WSGI_DISABLE_EMBEDDED)
    wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0142) "Embedded mode of mod_wsgi disabled at compile time.");
    return HTTP_INTERNAL_SERVER_ERROR;
#endif

    if (wsgi_server_config->restrict_embedded == 1)
    {
        wsgi_log_rerror(APLOG_ERR, 0, r, WSGI_APLOGNO(0143) "Embedded mode of mod_wsgi disabled by runtime "
                                                            "configuration.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return wsgi_execute_script(r);
}

/*
 * Apache 2.X module initialisation functions.
 */

static int wsgi_hook_init(apr_pool_t *pconf, apr_pool_t *ptemp,
                          apr_pool_t *plog, server_rec *s)
{
    void *data = NULL;
    const char *userdata_key;
    char package[128];
    char interpreter[256];

    int status = OK;

    /*
     * Init function gets called twice during startup, we only
     * need to actually do anything on the second time it is
     * called. This avoids unecessarily initialising and then
     * destroying Python for no reason. We also though have to
     * deal with a special case when a graceful restart is done.
     * For that we are only called once, which is generally okay
     * as the 'wsgi_init' key will be set from initial start up
     * of the server. The exception to this is where the module
     * is only loaded into Apache when the server is already
     * running. In this case we have to detect that it is not
     * the initial startup, but a subsequent restart. We can do
     * this by looking at whether the scoreboard has been
     * initialised yet. That is probably enough, but to be safe,
     * also check what generation it is.
     */

    userdata_key = "wsgi_init";

    apr_pool_userdata_get(&data, userdata_key, s->process->pool);

    if (!data)
    {
        apr_pool_userdata_set((const void *)1, userdata_key,
                              apr_pool_cleanup_null, s->process->pool);

        /*
         * Check for the special case of a graceful restart and
         * the module being loaded for the first time. In this
         * case we still go onto perform initialisation as the
         * initialisation routine for the module will not be
         * called a second time.
         */

        if (!ap_scoreboard_image ||
            ap_get_scoreboard_global()->running_generation == 0)
        {

            return OK;
        }
    }

    /* Setup module version information. */

    sprintf(package, "mod_wsgi/%s", MOD_WSGI_VERSION_STRING);

    ap_add_version_component(pconf, package);

    /* Record Python version string with Apache. */

    sprintf(interpreter, "Python/%d.%d", PY_MAJOR_VERSION, PY_MINOR_VERSION);
    ap_add_version_component(pconf, interpreter);

    /* Retain reference to base server. */

    wsgi_server = s;

    /* Retain record of parent process ID. */

    wsgi_parent_pid = getpid();

    /* Determine whether multiprocess and/or multithread. */

    ap_mpm_query(AP_MPMQ_IS_THREADED, &wsgi_multithread);
    if (wsgi_multithread != AP_MPMQ_NOT_SUPPORTED)
    {
        ap_mpm_query(AP_MPMQ_MAX_THREADS, &wsgi_multithread);
        wsgi_multithread = (wsgi_multithread != 1);
    }

    ap_mpm_query(AP_MPMQ_IS_FORKED, &wsgi_multiprocess);
    if (wsgi_multiprocess != AP_MPMQ_NOT_SUPPORTED)
    {
        ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &wsgi_multiprocess);
        wsgi_multiprocess = (wsgi_multiprocess != 1);
    }

    /* Retain reference to main server config. */

    wsgi_server_config = ap_get_module_config(s->module_config, &wsgi_module);

    /*
     * Check that the version of Python found at
     * runtime is what was used at compilation.
     *
     * XXX Can't do this as will cause Anaconda
     * Python to fail as not safe to call the
     * Py_GetVersion() function before one calls
     * the Py_Initialize() function when using
     * Anaconda Python.
     */

#if 0
    wsgi_python_version();
#endif

    if (wsgi_python_required == -1)
        wsgi_python_required = 1;

    /*
     * Startup separate named daemon processes. This is
     * a bit tricky as we only want to do this after the
     * scoreboard has been created. On the initial server
     * startup though, this hook function is called prior
     * to the MPM being run, which means the scoreboard
     * hasn't been created yet. In that case we need to
     * defer process creation until after that, which we
     * can only do by hooking into the pre_mpm hook after
     * scoreboard creation has been done. On a server
     * restart, the scoreboard will be preserved, so we
     * can do it here, which is just as well as the pre_mpm
     * hook isn't run on a restart.
     */

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (!ap_scoreboard_image)
    {
        /*
         * Need to remember the pool we were given here as
         * the pre_mpm hook functions get given a different
         * pool which isn't the one we want and if we use
         * that then Apache will crash when it is being
         * shutdown. So our pre_mpm hook will use the pool
         * we have remembered here.
         */

        wsgi_pconf_pool = pconf;

        ap_hook_pre_mpm(wsgi_deferred_start_daemons, NULL, NULL,
                        APR_HOOK_REALLY_LAST);
    }
    else
        status = wsgi_start_daemons(pconf);
#endif

    return status;
}

static void wsgi_hook_child_init(apr_pool_t *p, server_rec *s)
{
#if defined(MOD_WSGI_WITH_DAEMONS)
    WSGIProcessGroup *entries = NULL;
    WSGIProcessGroup *entry = NULL;

    int i;

    /* Close listener sockets for daemon processes. */

    if (wsgi_daemon_list)
    {
        entries = (WSGIProcessGroup *)wsgi_daemon_list->elts;

        for (i = 0; i < wsgi_daemon_list->nelts; ++i)
        {
            entry = &entries[i];

            if (entry->listener_fd != -1)
            {
                close(entry->listener_fd);
                entry->listener_fd = -1;
            }
        }
    }
#endif

    /* Remember worker process ID. */

    wsgi_worker_pid = getpid();

    /* Time child process started waiting for requests. */

    wsgi_restart_time = apr_time_now();

    /* Create lock for request monitoring. */

    apr_thread_mutex_create(&wsgi_monitor_lock,
                            APR_THREAD_MUTEX_UNNESTED, p);

    /* Retrieve optional functions from peer modules. */

    wsgi_environ_child_init();

    if (wsgi_python_required)
    {
        /*
         * Initialise Python if required to be done in
         * the child process. If initialisation fails,
         * skip subsequent Python setup so that we don't
         * crash trying to use a broken interpreter. The
         * wsgi_python_initialized flag will remain 0 so
         * code paths gated on it will short circuit.
         */

        if (wsgi_python_init(p) != APR_SUCCESS)
        {
            wsgi_log_error(APLOG_CRIT, 0, wsgi_server, WSGI_APLOGNO(0001) "Python initialisation failed in Apache child "
                                                                          "process; Python based handlers will not be "
                                                                          "available.");
        }
        else
        {
            /*
             * Now perform additional initialisation steps
             * always done in child process.
             */

            if (wsgi_python_child_init(p) != APR_SUCCESS)
            {
                wsgi_log_error(APLOG_CRIT, 0, wsgi_server, WSGI_APLOGNO(0002) "Python child initialisation failed in "
                                                                              "Apache child process; Python based "
                                                                              "handlers will not be available.");
            }
        }
    }

    /*
     * Start the telemetry reporter in this MPM child only if embedded
     * mode is permitted and Python is available. WSGIRestrictEmbedded On
     * disables WSGI request handling in embedded mode entirely, so even
     * if a Python interpreter is initialised here for auth scripts
     * there are no request metrics to report. The reporter thread also
     * acquires the GIL to read sys.getswitchinterval(), so it must not
     * start until Python has been initialised in this child.
     */

    if (wsgi_server_config->restrict_embedded != 1 &&
        wsgi_python_initialized)
        wsgi_telemetry_start_reporter(p);
}

APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_out) * wsgi_logio_add_bytes_out;

static void ap_logio_add_bytes_out(conn_rec *c, apr_off_t bytes)
{
    if (!wsgi_daemon_pool && wsgi_logio_add_bytes_out)
        wsgi_logio_add_bytes_out(c, bytes);
}

static int wsgi_hook_logio(apr_pool_t *pconf, apr_pool_t *ptemp,
                           apr_pool_t *plog, server_rec *s)
{
    /*
     * This horrible fiddle is to insert a proxy function before
     * the normal ap_logio_add_bytes_out() function so that the
     * call to it can be disabled when mod_wsgi running in daemon
     * mode. If this is not done, then daemon process will crash
     * when mod_logio has been loaded.
     */

    wsgi_logio_add_bytes_out = APR_RETRIEVE_OPTIONAL_FN(ap_logio_add_bytes_out);

    APR_REGISTER_OPTIONAL_FN(ap_logio_add_bytes_out);

    return OK;
}

static void wsgi_register_hooks(apr_pool_t *p)
{
    static const char *const p1[] = {"mod_alias.c", NULL};
    static const char *const n1[] = {"mod_userdir.c",
                                     "mod_vhost_alias.c", NULL};

    static const char *const n2[] = {"core.c", NULL};

    static const char *const n5[] = {"mod_authz_host.c", NULL};

    static const char *const p7[] = {"mod_ssl.c", NULL};

    ap_hook_post_config(wsgi_hook_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(wsgi_hook_child_init, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_translate_name(wsgi_hook_intercept, p1, n1, APR_HOOK_MIDDLE);
    ap_hook_handler(wsgi_hook_handler, NULL, NULL, APR_HOOK_MIDDLE);

#if defined(MOD_WSGI_WITH_DAEMONS)
    ap_hook_post_config(wsgi_hook_logio, NULL, n2, APR_HOOK_REALLY_FIRST);

    wsgi_header_filter_handle =
        ap_register_output_filter("WSGI_HEADER", wsgi_header_filter,
                                  NULL, AP_FTYPE_PROTOCOL);
#endif

    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "wsgi",
                         AUTHN_PROVIDER_VERSION, &wsgi_authn_provider);
    ap_register_provider(p, AUTHZ_PROVIDER_GROUP, "wsgi-group",
                         AUTHZ_PROVIDER_VERSION, &wsgi_authz_provider);
    ap_hook_access_checker(wsgi_hook_access_checker, p7, n5, APR_HOOK_MIDDLE);
}

static const command_rec wsgi_commands[] =
    {
        AP_INIT_RAW_ARGS("WSGIScriptAlias", wsgi_add_script_alias,
                         NULL, RSRC_CONF, "Map location to target WSGI script file."),
        AP_INIT_RAW_ARGS("WSGIScriptAliasMatch", wsgi_add_script_alias,
                         "*", RSRC_CONF, "Map location pattern to target WSGI script file."),

#if defined(MOD_WSGI_WITH_DAEMONS)
        AP_INIT_RAW_ARGS("WSGIDaemonProcess", wsgi_add_daemon_process,
                         NULL, RSRC_CONF, "Specify details of daemon processes to start."),
        AP_INIT_TAKE1("WSGISocketPrefix", wsgi_set_socket_prefix,
                      NULL, RSRC_CONF, "Path prefix for the daemon process sockets."),
        AP_INIT_TAKE1("WSGISocketRotation", wsgi_set_socket_rotation,
                      NULL, RSRC_CONF, "Enable/Disable rotation of daemon process sockets."),
        AP_INIT_TAKE1("WSGIAcceptMutex", wsgi_set_accept_mutex,
                      NULL, RSRC_CONF, "Set accept mutex type for daemon processes."),

#endif

        AP_INIT_TAKE1("WSGIVerboseDebugging", wsgi_set_verbose_debugging,
                      NULL, RSRC_CONF, "Enable/Disable verbose debugging messages."),

        AP_INIT_TAKE1("WSGIDontWriteBytecode", wsgi_set_dont_write_bytecode,
                      NULL, RSRC_CONF, "Enable/Disable writing of byte code."),

        AP_INIT_TAKE1("WSGIPythonWarnings", wsgi_add_python_warnings,
                      NULL, RSRC_CONF, "Control Python warning messages."),
        AP_INIT_TAKE1("WSGIPythonOptimize", wsgi_set_python_optimize,
                      NULL, RSRC_CONF, "Set level of Python compiler optimisations."),
        AP_INIT_TAKE1("WSGIPythonHome", wsgi_set_python_home,
                      NULL, RSRC_CONF, "Python prefix/exec_prefix absolute path names."),
        AP_INIT_TAKE1("WSGIPythonPath", wsgi_set_python_path,
                      NULL, RSRC_CONF, "Python module search path."),
        AP_INIT_TAKE1("WSGIPythonEggs", wsgi_set_python_eggs,
                      NULL, RSRC_CONF, "Python eggs cache directory."),
        AP_INIT_TAKE1("WSGIPythonHashSeed", wsgi_set_python_hash_seed,
                      NULL, RSRC_CONF, "Python hash seed."),
        AP_INIT_TAKE1("WSGISwitchInterval", wsgi_set_switch_interval,
                      NULL, RSRC_CONF,
                      "Override Python GIL switch interval (seconds)."),

        AP_INIT_TAKE1("WSGIDestroyInterpreter", wsgi_set_destroy_interpreter,
                      NULL, RSRC_CONF, "Enable/Disable destruction of Python interpreter."),

        AP_INIT_TAKE1("WSGIPerInterpreterGIL", wsgi_set_per_interpreter_gil,
                      NULL, RSRC_CONF, "Enable/Disable per-interpreter GIL "
                                       "for sub-interpreters (Python 3.12+)."),

#if defined(MOD_WSGI_WITH_DAEMONS)
        AP_INIT_TAKE1("WSGIRestrictEmbedded", wsgi_set_restrict_embedded,
                      NULL, RSRC_CONF, "Enable/Disable use of embedded mode."),
#endif
        AP_INIT_TAKE1("WSGIRestrictStdin", wsgi_set_restrict_stdin,
                      NULL, RSRC_CONF, "Enable/Disable restrictions on use of STDIN."),
        AP_INIT_TAKE1("WSGIRestrictStdout", wsgi_set_restrict_stdout,
                      NULL, RSRC_CONF, "Enable/Disable restrictions on use of STDOUT."),
        AP_INIT_TAKE1("WSGIRestrictSignal", wsgi_set_restrict_signal,
                      NULL, RSRC_CONF, "Enable/Disable restrictions on use of signal()."),

        AP_INIT_TAKE1("WSGICaseSensitivity", wsgi_set_case_sensitivity,
                      NULL, RSRC_CONF, "Define whether file system is case sensitive."),

#if defined(MOD_WSGI_WITH_DAEMONS)
        AP_INIT_RAW_ARGS("WSGIRestrictProcess", wsgi_set_restrict_process,
                         NULL, ACCESS_CONF | RSRC_CONF, "Limit selectable WSGI process groups."),
        AP_INIT_TAKE1("WSGIProcessGroup", wsgi_set_process_group,
                      NULL, ACCESS_CONF | RSRC_CONF, "Name of the WSGI process group."),
#endif

        AP_INIT_TAKE1("WSGIApplicationGroup", wsgi_set_application_group,
                      NULL, ACCESS_CONF | RSRC_CONF, "Application interpreter group."),
        AP_INIT_TAKE1("WSGICallableObject", wsgi_set_callable_object,
                      NULL, OR_FILEINFO, "Name of entry point in WSGI script file."),

        AP_INIT_RAW_ARGS("WSGIImportScript", wsgi_add_import_script,
                         NULL, RSRC_CONF, "Location of WSGI import script."),
        AP_INIT_RAW_ARGS("WSGIDispatchScript", wsgi_set_dispatch_script,
                         NULL, ACCESS_CONF | RSRC_CONF, "Location of WSGI dispatch script."),

        AP_INIT_TAKE1("WSGIPassApacheRequest", wsgi_set_pass_apache_request,
                      NULL, ACCESS_CONF | RSRC_CONF, "Enable/Disable Apache request object."),
        AP_INIT_TAKE1("WSGIPassAuthorization", wsgi_set_pass_authorization,
                      NULL, OR_FILEINFO, "Enable/Disable WSGI authorization."),
        AP_INIT_TAKE1("WSGIScriptReloading", wsgi_set_script_reloading,
                      NULL, OR_FILEINFO, "Enable/Disable script reloading mechanism."),
        AP_INIT_TAKE1("WSGIErrorOverride", wsgi_set_error_override,
                      NULL, OR_FILEINFO, "Enable/Disable overriding of error pages."),
        AP_INIT_TAKE1("WSGIChunkedRequest", wsgi_set_chunked_request,
                      NULL, OR_FILEINFO, "Enable/Disable support for chunked requests."),
        AP_INIT_TAKE1("WSGIMapHEADToGET", wsgi_set_map_head_to_get,
                      NULL, OR_FILEINFO, "Enable/Disable mapping of HEAD to GET."),
        AP_INIT_TAKE1("WSGIIgnoreActivity", wsgi_set_ignore_activity,
                      NULL, OR_FILEINFO, "Enable/Disable reset of inactvity timeout."),

        AP_INIT_RAW_ARGS("WSGITrustedProxyHeaders", wsgi_set_trusted_proxy_headers,
                         NULL, OR_FILEINFO, "Specify a list of trusted proxy headers."),
        AP_INIT_RAW_ARGS("WSGITrustedProxies", wsgi_set_trusted_proxies,
                         NULL, OR_FILEINFO, "Specify a list of trusted proxies."),

#ifndef WIN32
        AP_INIT_TAKE1("WSGIEnableSendfile", wsgi_set_enable_sendfile,
                      NULL, OR_FILEINFO, "Enable/Disable support for kernel sendfile."),
#endif

        AP_INIT_RAW_ARGS("WSGIAccessScript", wsgi_set_access_script,
                         NULL, OR_AUTHCFG, "Location of WSGI host access script file."),
        AP_INIT_RAW_ARGS("WSGIAuthUserScript", wsgi_set_auth_user_script,
                         NULL, OR_AUTHCFG, "Location of WSGI user auth script file."),
        AP_INIT_RAW_ARGS("WSGIAuthGroupScript", wsgi_set_auth_group_script,
                         NULL, OR_AUTHCFG, "Location of WSGI group auth script file."),
        AP_INIT_TAKE1("WSGIGroupAuthoritative", wsgi_set_group_authoritative,
                      NULL, OR_AUTHCFG, "Enable/Disable as being authoritative on groups."),

        AP_INIT_RAW_ARGS("WSGIHandlerScript", wsgi_add_handler_script,
                         NULL, ACCESS_CONF | RSRC_CONF, "Location of WSGI handler script file."),

        AP_INIT_TAKE1("WSGIServerMetrics", wsgi_set_server_metrics,
                      NULL, RSRC_CONF, "Enabled/Disable access to server metrics."),

        AP_INIT_TAKE12("WSGIMetricsService", wsgi_set_metrics_service,
                       NULL, RSRC_CONF, "Push telemetry to a metrics service. "
                                        "Args: unix:/path [interval=N]"),
        AP_INIT_TAKE1("WSGISlowRequests", wsgi_set_slow_requests,
                      NULL, RSRC_CONF, "Enable slow-request reporting. "
                                       "Arg: threshold in seconds."),
        AP_INIT_RAW_ARGS("WSGIMetricsOptions", wsgi_set_metrics_options,
                         NULL, RSRC_CONF,
                         "Toggle metrics capture options. "
                         "Args: [+|-]Flag... | None | All. "
                         "Flags: CaptureUserAgent."),

        {NULL}};

/* Dispatch list for API hooks */

module AP_MODULE_DECLARE_DATA wsgi_module = {
    STANDARD20_MODULE_STUFF,
    wsgi_create_dir_config,    /* create per-dir    config structures */
    wsgi_merge_dir_config,     /* merge  per-dir    config structures */
    wsgi_create_server_config, /* create per-server config structures */
    wsgi_merge_server_config,  /* merge  per-server config structures */
    wsgi_commands,             /* table of config file commands       */
    wsgi_register_hooks        /* register hooks                      */
};

/* ------------------------------------------------------------------------- */

#if defined(_WIN32)
PyMODINIT_FUNC PyInit_mod_wsgi(void)
{
    /* The 'mod_wsgi' Python module is created at runtime by the Apache
     * module when it sets up each interpreter; it is not a regular
     * Python extension and cannot be imported from a standalone Python
     * process. This stub exists only to satisfy the Windows linker and
     * is not expected to be reached. Set an explicit ImportError so the
     * importer reports the actual situation instead of the generic
     * "initialization of mod_wsgi failed without raising an exception"
     * SystemError. */

    PyErr_SetString(PyExc_ImportError,
                    "mod_wsgi cannot be imported as a regular Python "
                    "module; it is provided by the Apache mod_wsgi "
                    "module and is only available inside an Apache "
                    "process running mod_wsgi.");
    return NULL;
}
#endif

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
