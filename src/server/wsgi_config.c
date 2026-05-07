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

#include "wsgi_config.h"

#include "wsgi_daemon.h"
#include "wsgi_interp.h"
#include "wsgi_logger.h"

#include <errno.h>
#include <limits.h>

/* ------------------------------------------------------------------------- */

apr_array_header_t *wsgi_import_list = NULL;

/* ------------------------------------------------------------------------- */

int wsgi_parse_option(apr_pool_t *p, const char **line,
                      const char **name, const char **value)
{
    const char *str = *line, *strend;

    while (*str && apr_isspace(*str))
        ++str;

    if (!*str || *str == '=')
    {
        *line = str;
        return APR_EINVAL;
    }

    /* Option must be of form name=value. Extract the name. */

    strend = str;
    while (*strend && *strend != '=' && !apr_isspace(*strend))
        ++strend;

    if (*strend != '=')
    {
        *line = str;
        return APR_EINVAL;
    }

    *name = apr_pstrndup(p, str, strend - str);

    *line = strend + 1;

    /* Now extract the value. Note that value can be quoted. */

    *value = ap_getword_conf(p, line);

    return APR_SUCCESS;
}

const char *wsgi_add_script_alias(cmd_parms *cmd, void *mconfig,
                                  const char *args)
{
    const char *l = NULL;
    const char *a = NULL;

    WSGIServerConfig *sconfig = NULL;
    WSGIAliasEntry *entry = NULL;

    const char *option = NULL;
    const char *value = NULL;

#if defined(MOD_WSGI_WITH_DAEMONS)
    const char *process_group = NULL;
#else
    const char *process_group = "";
#endif

    const char *application_group = NULL;
    const char *callable_object = NULL;

    int pass_authorization = -1;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (!sconfig->alias_list)
    {
        sconfig->alias_list = apr_array_make(sconfig->pool, 20,
                                             sizeof(WSGIAliasEntry));
    }

    l = ap_getword_conf(cmd->pool, &args);

    if (*l == '\0' || *args == 0)
    {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " requires at least two arguments",
                           cmd->cmd->errmsg ? ", " : NULL,
                           cmd->cmd->errmsg, NULL);
    }

    a = ap_getword_conf(cmd->pool, &args);

    if (*a == '\0')
    {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " requires at least two arguments",
                           cmd->cmd->errmsg ? ", " : NULL,
                           cmd->cmd->errmsg, NULL);
    }

    while (*args)
    {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS)
        {
            return "Invalid option to WSGI script alias definition.";
        }

        if (!strcmp(option, "application-group"))
        {
            if (!*value)
                return "Invalid name for WSGI application group.";

            if (!strcmp(value, "%{GLOBAL}"))
                value = "";

            application_group = value;
        }
#if defined(MOD_WSGI_WITH_DAEMONS)
        else if (!strcmp(option, "process-group"))
        {
            if (!*value)
                return "Invalid name for WSGI process group.";

            if (!strcmp(value, "%{GLOBAL}"))
                value = "";

            process_group = value;
        }
#endif
        else if (!strcmp(option, "callable-object"))
        {
            if (!*value)
                return "Invalid name for WSGI callable object.";

            callable_object = value;
        }
        else if (!strcmp(option, "pass-authorization"))
        {
            if (!*value)
                return "Invalid value for authorization flag.";

            if (strcasecmp(value, "Off") == 0)
                pass_authorization = 0;
            else if (strcasecmp(value, "On") == 0)
                pass_authorization = 1;
            else
                return "Invalid value for authorization flag.";
        }
        else
            return "Invalid option to WSGI script alias definition.";
    }

    ap_regex_t *regexp = NULL;

    if (cmd->info)
    {
        regexp = ap_pregcomp(cmd->pool, l, AP_REG_EXTENDED);
        if (!regexp)
            return "Regular expression could not be compiled.";
    }

    entry = (WSGIAliasEntry *)apr_array_push(sconfig->alias_list);

    entry->regexp = regexp;
    entry->location = l;
    entry->application = a;

    entry->process_group = process_group;
    entry->application_group = application_group;
    entry->callable_object = callable_object;
    entry->pass_authorization = pass_authorization;

    /*
     * Only add to import list if both process group and application
     * group are specified, that they don't include substitution values,
     * and in the case of WSGIScriptAliasMatch, that the WSGI script
     * target path doesn't include substitutions from URL pattern.
     */

    if (process_group && application_group &&
        !strstr(process_group, "%{") &&
        !strstr(application_group, "%{") &&
        (!cmd->info || !strstr(a, "$")))
    {

        WSGIScriptFile *object = NULL;

        if (!wsgi_import_list)
        {
            wsgi_import_list = apr_array_make(cmd->pool, 20,
                                              sizeof(WSGIScriptFile));
            apr_pool_cleanup_register(cmd->pool, &wsgi_import_list,
                                      ap_pool_cleanup_set_null,
                                      apr_pool_cleanup_null);
        }

        object = (WSGIScriptFile *)apr_array_push(wsgi_import_list);

        object->handler_script = a;
        object->process_group = process_group;
        object->application_group = application_group;

#if defined(MOD_WSGI_WITH_DAEMONS)
        if (*object->process_group &&
            strcmp(object->process_group, "%{RESOURCE}") != 0 &&
            strcmp(object->process_group, "%{SERVER}") != 0 &&
            strcmp(object->process_group, "%{HOST}") != 0)
        {

            WSGIProcessGroup *group = NULL;
            WSGIProcessGroup *entries = NULL;
            WSGIProcessGroup *candidate = NULL;
            int i;

            if (!wsgi_daemon_list)
                return "WSGI process group not yet configured.";

            entries = (WSGIProcessGroup *)wsgi_daemon_list->elts;

            for (i = 0; i < wsgi_daemon_list->nelts; ++i)
            {
                candidate = &entries[i];

                if (!strcmp(candidate->name, object->process_group))
                {
                    group = candidate;
                    break;
                }
            }

            if (!group)
                return "WSGI process group not yet configured.";

            if (cmd->server->server_hostname &&
                group->server->server_hostname &&
                strcmp(cmd->server->server_hostname,
                       group->server->server_hostname) &&
                group->server->is_virtual)
            {

                return "WSGI process group not accessible.";
            }

            if (!cmd->server->server_hostname &&
                group->server->server_hostname &&
                group->server->is_virtual)
            {

                return "WSGI process group not matchable.";
            }

            if (cmd->server->server_hostname &&
                !group->server->server_hostname &&
                group->server->is_virtual)
            {

                return "WSGI process group not matchable.";
            }
        }
#endif
    }

    return NULL;
}

const char *wsgi_set_verbose_debugging(cmd_parms *cmd, void *mconfig,
                                       const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->verbose_debugging = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->verbose_debugging = 1;
    else
        return "WSGIVerboseDebugging must be one of: Off | On";

    wsgi_log_error(APLOG_INFO, 0, cmd->server,
                   "WSGIVerboseDebugging is deprecated and has no effect. "
                   "Use 'LogLevel info wsgi_module:debug' for lifecycle "
                   "messages and 'LogLevel info wsgi_module:trace1' for "
                   "per-request and per-thread-binding messages.");

    return NULL;
}

const char *wsgi_add_python_warnings(cmd_parms *cmd, void *mconfig,
                                     const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    char **entry = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (!sconfig->python_warnings)
    {
        sconfig->python_warnings = apr_array_make(sconfig->pool, 5,
                                                  sizeof(char *));
    }

    entry = (char **)apr_array_push(sconfig->python_warnings);
    *entry = apr_pstrdup(sconfig->pool, f);

    return NULL;
}

const char *wsgi_set_dont_write_bytecode(cmd_parms *cmd, void *mconfig,
                                         const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->dont_write_bytecode = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->dont_write_bytecode = 1;
    else
        return "WSGIDontWriteBytecode must be one of: Off | On";

    return NULL;
}

const char *wsgi_set_python_optimize(cmd_parms *cmd, void *mconfig,
                                     const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->python_optimize = atoi(f);

    return NULL;
}

const char *wsgi_set_python_home(cmd_parms *cmd, void *mconfig,
                                 const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->python_home = f;

    return NULL;
}

/*
 * Identify whether the directive currently being processed is nested
 * inside a <WSGIInterpreterOptions> section. The section handler
 * stashes a pointer to the active block in cmd->directive->parent->data,
 * so any contained directive that wants to scope its value to that
 * block looks for it there.
 */

static WSGIInterpreterOptionsBlock *wsgi_active_options_block(
    cmd_parms *cmd)
{
    if (cmd->directive && cmd->directive->parent &&
        cmd->directive->parent->data)
    {
        return (WSGIInterpreterOptionsBlock *)cmd->directive->parent->data;
    }

    return NULL;
}

static int wsgi_parse_on_off(const char *value, int *out)
{
    if (strcasecmp(value, "Off") == 0)
    {
        *out = 0;
        return 0;
    }

    if (strcasecmp(value, "On") == 0)
    {
        *out = 1;
        return 0;
    }

    return -1;
}

const char *wsgi_set_python_path(cmd_parms *cmd, void *mconfig,
                                 const char *f)
{
    WSGIServerConfig *sconfig = NULL;
    WSGIInterpreterOptionsBlock *block = NULL;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    block = wsgi_active_options_block(cmd);

    if (!block)
    {
        const char *error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
        if (error != NULL)
            return error;
    }

    if (block)
        block->python_path = apr_pstrdup(cmd->pool, f);
    else
        sconfig->python_path = f;

    return NULL;
}

const char *wsgi_set_python_eggs(cmd_parms *cmd, void *mconfig,
                                 const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->python_eggs = f;

    return NULL;
}

const char *wsgi_set_python_hash_seed(cmd_parms *cmd, void *mconfig,
                                      const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    /*
     * Must check this here because if we don't and is wrong, then
     * Python interpreter will check later and may kill the process.
     */

    if (f && *f != '\0' && strcmp(f, "random") != 0)
    {
        const char *endptr = f;
        unsigned long seed;

        errno = 0;
        seed = PyOS_strtoul((char *)f, (char **)&endptr, 10);

        if (*endptr != '\0' || seed > 4294967295UL || (errno == ERANGE && seed == ULONG_MAX))
        {
            return "WSGIPythonHashSeed must be \"random\" or an integer "
                   "in range [0; 4294967295]";
        }
    }

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->python_hash_seed = f;

    return NULL;
}

const char *wsgi_set_switch_interval(cmd_parms *cmd, void *mconfig,
                                     const char *f)
{
    WSGIServerConfig *sconfig = NULL;
    WSGIInterpreterOptionsBlock *block = NULL;
    char *endp = NULL;
    double v;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    block = wsgi_active_options_block(cmd);

    if (!block)
    {
        const char *error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
        if (error != NULL)
            return error;
    }

    v = strtod(f, &endp);
    if (endp == f || *endp != '\0' || v <= 0.0)
        return "WSGISwitchInterval must be a positive number of seconds.";

    if (block)
        block->switch_interval = v;
    else
        sconfig->switch_interval = v;

    return NULL;
}

const char *wsgi_set_destroy_interpreter(cmd_parms *cmd, void *mconfig,
                                         const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->destroy_interpreter = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->destroy_interpreter = 1;
    else
        return "WSGIDestroyInterpreter must be one of: Off | On";

    return NULL;
}

const char *wsgi_set_per_interpreter_gil(cmd_parms *cmd, void *mconfig,
                                         const char *f)
{
    WSGIServerConfig *sconfig = NULL;
    WSGIInterpreterOptionsBlock *block = NULL;
    int value = 0;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    block = wsgi_active_options_block(cmd);

    if (!block)
    {
        const char *error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
        if (error != NULL)
            return error;
    }

    if (wsgi_parse_on_off(f, &value) < 0)
        return "WSGIPerInterpreterGIL must be one of: Off | On";

    if (block)
        block->per_interpreter_gil = value;
    else
        sconfig->per_interpreter_gil = value;

#if PY_VERSION_HEX < 0x030c0000
    if (value > 0)
    {
        wsgi_log_error(APLOG_WARNING, 0, cmd->server,
                       WSGI_APLOGNO(0198) "WSGIPerInterpreterGIL requires "
                                          "Python 3.12 or later; directive has no effect on "
                                          "this build.");
    }
#endif

    return NULL;
}

const char *wsgi_set_free_threading(cmd_parms *cmd, void *mconfig,
                                    const char *f)
{
    WSGIServerConfig *sconfig = NULL;
    WSGIInterpreterOptionsBlock *block = NULL;
    int value = 0;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    block = wsgi_active_options_block(cmd);

    if (!block)
    {
        const char *error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
        if (error != NULL)
            return error;
    }

    if (wsgi_parse_on_off(f, &value) < 0)
        return "WSGIFreeThreading must be one of: Off | On";

    if (block && block->application_group)
    {
        wsgi_log_error(APLOG_WARNING, 0, cmd->server,
                       WSGI_APLOGNO(0201) "WSGIFreeThreading inside "
                                          "<WSGIInterpreterOptions> with application-group= "
                                          "set is ignored: free-threading is a process-wide "
                                          "setting and cannot be scoped per application "
                                          "group.");
    }

    if (block)
        block->free_threading = value;
    else
        sconfig->free_threading = value;

#if !defined(Py_GIL_DISABLED)
    if (value > 0)
    {
        wsgi_log_error(APLOG_WARNING, 0, cmd->server,
                       WSGI_APLOGNO(0200) "WSGIFreeThreading On has no "
                                          "effect: this Python build does not support "
                                          "free-threading (PEP 703). Rebuild Python with "
                                          "--disable-gil to use it.");
    }
#endif

    return NULL;
}

/*
 * Section handler for <WSGIInterpreterOptions>. Parses the opening-
 * tag arguments (process-group=NAME and/or application-group=NAME),
 * appends a new options block to the server config, and stashes a
 * pointer to it on the directive's data field so that contained
 * directive setters can find it via cmd->directive->parent->data.
 *
 * Apache walks the inner directives automatically as part of the
 * standard config walk; we don't call ap_walk_config ourselves.
 */

const char *wsgi_interpreter_options_section(cmd_parms *cmd, void *mconfig,
                                             const char *arg)
{
    WSGIServerConfig *sconfig = NULL;
    WSGIInterpreterOptionsBlock *block = NULL;
    const char *endp = NULL;
    char *args_copy = NULL;
    char *word = NULL;
    const char *error = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    endp = ap_strrchr_c(arg, '>');
    if (endp == NULL)
        return "<WSGIInterpreterOptions> directive missing closing '>'";

    args_copy = apr_pstrndup(cmd->pool, arg, endp - arg);

    block = apr_pcalloc(cmd->pool, sizeof(*block));
    block->per_interpreter_gil = -1;
    block->free_threading = -1;
    block->switch_interval = 0.0;
    block->restrict_stdin = -1;
    block->restrict_stdout = -1;
    block->restrict_signal = -1;
    block->python_path = NULL;

    while ((word = ap_getword_conf(cmd->pool, (const char **)&args_copy)) &&
           *word)
    {
        char *eq = strchr(word, '=');
        const char *key = NULL;
        const char *val = NULL;

        if (!eq)
            return apr_pstrcat(cmd->pool,
                               "<WSGIInterpreterOptions>: argument '", word,
                               "' is not of the form key=value", NULL);

        *eq = '\0';
        key = word;
        val = eq + 1;

        if (strcasecmp(key, "process-group") == 0)
        {
            if (block->process_group)
                return "<WSGIInterpreterOptions>: process-group given more "
                       "than once";
            if (!strcmp(val, "%{GLOBAL}"))
                block->process_group = "";
            else
                block->process_group = apr_pstrdup(cmd->pool, val);
        }
        else if (strcasecmp(key, "application-group") == 0)
        {
            if (block->application_group)
                return "<WSGIInterpreterOptions>: application-group given "
                       "more than once";
            if (!strcmp(val, "%{GLOBAL}"))
                block->application_group = "";
            else
                block->application_group = apr_pstrdup(cmd->pool, val);
        }
        else
        {
            return apr_pstrcat(cmd->pool,
                               "<WSGIInterpreterOptions>: unknown selector '",
                               key, "', expected process-group or "
                                    "application-group",
                               NULL);
        }
    }

    if (!sconfig->interpreter_option_blocks)
    {
        sconfig->interpreter_option_blocks = apr_array_make(cmd->pool, 4,
                                                            sizeof(WSGIInterpreterOptionsBlock *));
    }

    *(WSGIInterpreterOptionsBlock **)apr_array_push(
        sconfig->interpreter_option_blocks) = block;

    cmd->directive->data = block;

    return ap_walk_config(cmd->directive->first_child, cmd,
                          cmd->server->lookup_defaults);
}

const char *wsgi_set_restrict_embedded(cmd_parms *cmd, void *mconfig,
                                       const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->restrict_embedded = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->restrict_embedded = 1;
    else
        return "WSGIRestrictEmbedded must be one of: Off | On";

    if (sconfig->restrict_embedded)
    {
        if (wsgi_python_required == -1)
            wsgi_python_required = 0;
    }

    return NULL;
}

const char *wsgi_set_restrict_stdin(cmd_parms *cmd, void *mconfig,
                                    const char *f)
{
    WSGIServerConfig *sconfig = NULL;
    WSGIInterpreterOptionsBlock *block = NULL;
    int value = 0;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    block = wsgi_active_options_block(cmd);

    if (!block)
    {
        const char *error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
        if (error != NULL)
            return error;
    }

    if (wsgi_parse_on_off(f, &value) < 0)
        return "WSGIRestrictStdin must be one of: Off | On";

    if (block)
        block->restrict_stdin = value;
    else
        sconfig->restrict_stdin = value;

    return NULL;
}

const char *wsgi_set_restrict_stdout(cmd_parms *cmd, void *mconfig,
                                     const char *f)
{
    WSGIServerConfig *sconfig = NULL;
    WSGIInterpreterOptionsBlock *block = NULL;
    int value = 0;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    block = wsgi_active_options_block(cmd);

    if (!block)
    {
        const char *error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
        if (error != NULL)
            return error;
    }

    if (wsgi_parse_on_off(f, &value) < 0)
        return "WSGIRestrictStdout must be one of: Off | On";

    if (block)
        block->restrict_stdout = value;
    else
        sconfig->restrict_stdout = value;

    return NULL;
}

const char *wsgi_set_restrict_signal(cmd_parms *cmd, void *mconfig,
                                     const char *f)
{
    WSGIServerConfig *sconfig = NULL;
    WSGIInterpreterOptionsBlock *block = NULL;
    int value = 0;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    block = wsgi_active_options_block(cmd);

    if (!block)
    {
        const char *error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
        if (error != NULL)
            return error;
    }

    if (wsgi_parse_on_off(f, &value) < 0)
        return "WSGIRestrictSignal must be one of: Off | On";

    if (block)
        block->restrict_signal = value;
    else
        sconfig->restrict_signal = value;

    return NULL;
}

const char *wsgi_set_case_sensitivity(cmd_parms *cmd, void *mconfig,
                                      const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->case_sensitivity = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->case_sensitivity = 1;
    else
        return "WSGICaseSensitivity must be one of: Off | On";

    return NULL;
}

const char *wsgi_set_restrict_process(cmd_parms *cmd, void *mconfig,
                                      const char *args)
{
    apr_table_t *index = apr_table_make(cmd->pool, 5);

    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        dconfig->restrict_process = index;
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        sconfig->restrict_process = index;
    }

    while (*args)
    {
        const char *option;

        option = ap_getword_conf(cmd->pool, &args);

        if (!strcmp(option, "%{GLOBAL}"))
            option = "";

        apr_table_setn(index, option, option);
    }

    return NULL;
}

const char *wsgi_set_process_group(cmd_parms *cmd, void *mconfig,
                                   const char *n)
{
    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->process_group = n;
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->process_group = n;
    }

    return NULL;
}

const char *wsgi_set_application_group(cmd_parms *cmd, void *mconfig,
                                       const char *n)
{
    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->application_group = n;
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->application_group = n;
    }

    return NULL;
}

const char *wsgi_set_callable_object(cmd_parms *cmd, void *mconfig,
                                     const char *n)
{
    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->callable_object = n;
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->callable_object = n;
    }

    return NULL;
}

const char *wsgi_add_import_script(cmd_parms *cmd, void *mconfig,
                                   const char *args)
{
    WSGIScriptFile *object = NULL;

    const char *handler_script = NULL;
    const char *option = NULL;
    const char *value = NULL;

    handler_script = ap_getword_conf(cmd->pool, &args);

    if (!handler_script || !*handler_script)
        return "Location of import script not supplied.";

    if (!wsgi_import_list)
    {
        wsgi_import_list = apr_array_make(cmd->pool, 20,
                                          sizeof(WSGIScriptFile));
        apr_pool_cleanup_register(cmd->pool, &wsgi_import_list,
                                  ap_pool_cleanup_set_null,
                                  apr_pool_cleanup_null);
    }

    object = (WSGIScriptFile *)apr_array_push(wsgi_import_list);

    object->handler_script = handler_script;
    object->process_group = NULL;
    object->application_group = NULL;

    while (*args)
    {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS)
        {
            return "Invalid option to WSGI import script definition.";
        }

        if (!strcmp(option, "application-group"))
        {
            if (!*value)
                return "Invalid name for WSGI application group.";

            object->application_group = value;
        }
#if defined(MOD_WSGI_WITH_DAEMONS)
        else if (!strcmp(option, "process-group"))
        {
            if (!*value)
                return "Invalid name for WSGI process group.";

            object->process_group = value;
        }
#endif
        else
            return "Invalid option to WSGI import script definition.";
    }

    if (!object->application_group)
        return "Name of WSGI application group required.";

    if (!strcmp(object->application_group, "%{GLOBAL}"))
        object->application_group = "";

#if defined(MOD_WSGI_WITH_DAEMONS)
    if (!object->process_group)
        return "Name of WSGI process group required.";

    if (!strcmp(object->process_group, "%{GLOBAL}"))
        object->process_group = "";

    if (*object->process_group)
    {
        WSGIProcessGroup *group = NULL;
        WSGIProcessGroup *entries = NULL;
        WSGIProcessGroup *entry = NULL;
        int i;

        if (!wsgi_daemon_list)
            return "WSGI process group not yet configured.";

        entries = (WSGIProcessGroup *)wsgi_daemon_list->elts;

        for (i = 0; i < wsgi_daemon_list->nelts; ++i)
        {
            entry = &entries[i];

            if (!strcmp(entry->name, object->process_group))
            {
                group = entry;
                break;
            }
        }

        if (!group)
            return "WSGI process group not yet configured.";

        if (cmd->server->server_hostname &&
            group->server->server_hostname &&
            strcmp(cmd->server->server_hostname,
                   group->server->server_hostname) &&
            group->server->is_virtual)
        {

            return "WSGI process group not accessible.";
        }

        if (!cmd->server->server_hostname &&
            group->server->server_hostname &&
            group->server->is_virtual)
        {

            return "WSGI process group not matchable.";
        }

        if (cmd->server->server_hostname &&
            !group->server->server_hostname &&
            group->server->is_virtual)
        {

            return "WSGI process group not matchable.";
        }
    }
#else
    object->process_group = "";
#endif

    if (!*object->process_group)
        wsgi_python_required = 1;

    return NULL;
}

const char *wsgi_set_dispatch_script(cmd_parms *cmd, void *mconfig,
                                     const char *args)
{
    WSGIScriptFile *object = NULL;

    const char *option = NULL;
    const char *value = NULL;

    object = newWSGIScriptFile(cmd->pool);

    object->handler_script = ap_getword_conf(cmd->pool, &args);

    if (!object->handler_script || !*object->handler_script)
        return "Location of dispatch script not supplied.";

    while (*args)
    {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS)
        {
            return "Invalid option to WSGI dispatch script definition.";
        }

        if (!strcmp(option, "application-group"))
        {
            if (!*value)
                return "Invalid name for WSGI application group.";

            object->application_group = value;
        }
        else
            return "Invalid option to WSGI dispatch script definition.";
    }

    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->dispatch_script = object;
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->dispatch_script = object;
    }

    wsgi_python_required = 1;

    return NULL;
}

const char *wsgi_set_pass_apache_request(cmd_parms *cmd, void *mconfig,
                                         const char *f)
{
    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->pass_apache_request = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->pass_apache_request = 1;
        else
            return "WSGIPassApacheRequest must be one of: Off | On";
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->pass_apache_request = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->pass_apache_request = 1;
        else
            return "WSGIPassApacheRequest must be one of: Off | On";
    }

    return NULL;
}

const char *wsgi_set_pass_authorization(cmd_parms *cmd, void *mconfig,
                                        const char *f)
{
    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->pass_authorization = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->pass_authorization = 1;
        else
            return "WSGIPassAuthorization must be one of: Off | On";
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->pass_authorization = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->pass_authorization = 1;
        else
            return "WSGIPassAuthorization must be one of: Off | On";
    }

    return NULL;
}

const char *wsgi_set_script_reloading(cmd_parms *cmd, void *mconfig,
                                      const char *f)
{
    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->script_reloading = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->script_reloading = 1;
        else
            return "WSGIScriptReloading must be one of: Off | On";
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->script_reloading = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->script_reloading = 1;
        else
            return "WSGIScriptReloading must be one of: Off | On";
    }

    return NULL;
}

const char *wsgi_set_error_override(cmd_parms *cmd, void *mconfig,
                                    const char *f)
{
    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->error_override = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->error_override = 1;
        else
            return "WSGIErrorOverride must be one of: Off | On";
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->error_override = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->error_override = 1;
        else
            return "WSGIErrorOverride must be one of: Off | On";
    }

    return NULL;
}

const char *wsgi_set_chunked_request(cmd_parms *cmd, void *mconfig,
                                     const char *f)
{
    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->chunked_request = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->chunked_request = 1;
        else
            return "WSGIChunkedRequest must be one of: Off | On";
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->chunked_request = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->chunked_request = 1;
        else
            return "WSGIChunkedRequest must be one of: Off | On";
    }

    return NULL;
}

const char *wsgi_set_map_head_to_get(cmd_parms *cmd, void *mconfig,
                                     const char *f)
{
    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->map_head_to_get = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->map_head_to_get = 1;
        else if (strcasecmp(f, "Auto") == 0)
            dconfig->map_head_to_get = 2;
        else
            return "WSGIMapHEADToGET must be one of: Off | On | Auto";
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->map_head_to_get = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->map_head_to_get = 1;
        else if (strcasecmp(f, "Auto") == 0)
            sconfig->map_head_to_get = 2;
        else
            return "WSGIMapHEADToGET must be one of: Off | On | Auto";
    }

    return NULL;
}

const char *wsgi_set_ignore_activity(cmd_parms *cmd, void *mconfig,
                                     const char *f)
{
    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->ignore_activity = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->ignore_activity = 1;
        else
            return "WSGIIgnoreActivity must be one of: Off | On";
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->ignore_activity = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->ignore_activity = 1;
        else
            return "WSGIIgnoreActivity must be one of: Off | On";
    }

    return NULL;
}

const char *wsgi_set_trusted_proxy_headers(cmd_parms *cmd,
                                           void *mconfig,
                                           const char *args)
{
    apr_array_header_t *headers = NULL;

    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (!dconfig->trusted_proxy_headers)
        {
            headers = apr_array_make(cmd->pool, 3, sizeof(char *));
            dconfig->trusted_proxy_headers = headers;
        }
        else
            headers = dconfig->trusted_proxy_headers;
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (!sconfig->trusted_proxy_headers)
        {
            headers = apr_array_make(cmd->pool, 3, sizeof(char *));
            sconfig->trusted_proxy_headers = headers;
        }
        else
            headers = sconfig->trusted_proxy_headers;
    }

    while (*args)
    {
        const char **entry = NULL;

        entry = (const char **)apr_array_push(headers);
        *entry = wsgi_http2env(cmd->pool, ap_getword_conf(cmd->pool, &args));
    }

    return NULL;
}

static int wsgi_looks_like_ip(const char *ip)
{
    static const char ipv4_set[] = "0123456789./";
    static const char ipv6_set[] = "0123456789abcdef:/";

    const char *ptr;

    /* Zero length value is not valid. */

    if (!*ip)
        return 0;

    /* Determine if this could be a IPv6 or IPv4 address. */

    ptr = ip;

    if (strchr(ip, ':'))
    {
        while (*ptr && strchr(ipv6_set, *ptr) != NULL)
            ++ptr;
    }
    else
    {
        while (*ptr && strchr(ipv4_set, *ptr) != NULL)
            ++ptr;
    }

    return (*ptr == '\0');
}

const char *wsgi_set_trusted_proxies(cmd_parms *cmd,
                                     void *mconfig, const char *args)
{
    apr_array_header_t *proxy_ips = NULL;

    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (!dconfig->trusted_proxies)
        {
            proxy_ips = apr_array_make(cmd->pool, 3, sizeof(char *));
            dconfig->trusted_proxies = proxy_ips;
        }
        else
            proxy_ips = dconfig->trusted_proxies;
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (!sconfig->trusted_proxies)
        {
            proxy_ips = apr_array_make(cmd->pool, 3, sizeof(char *));
            sconfig->trusted_proxies = proxy_ips;
        }
        else
            proxy_ips = sconfig->trusted_proxies;
    }

    while (*args)
    {
        const char *proxy_ip;

        proxy_ip = ap_getword_conf(cmd->pool, &args);

        if (wsgi_looks_like_ip(proxy_ip))
        {
            char *ip;
            char *mask;
            apr_ipsubnet_t **sub;
            apr_status_t rv;

            ip = apr_pstrdup(cmd->temp_pool, proxy_ip);

            if ((mask = ap_strchr(ip, '/')))
                *mask++ = '\0';

            sub = (apr_ipsubnet_t **)apr_array_push(proxy_ips);

            rv = apr_ipsubnet_create(sub, ip, mask, cmd->pool);

            if (rv != APR_SUCCESS)
            {
                char msgbuf[128];
                apr_strerror(rv, msgbuf, sizeof(msgbuf));

                return apr_pstrcat(cmd->pool, "Unable to parse trusted "
                                              "proxy IP address/subnet of \"",
                                   proxy_ip,
                                   "\". ", msgbuf, NULL);
            }
        }
        else
        {
            return apr_pstrcat(cmd->pool, "Unable to parse trusted proxy "
                                          "IP address/subnet of \"",
                               proxy_ip, "\".",
                               NULL);
        }
    }

    return NULL;
}

const char *wsgi_set_enable_sendfile(cmd_parms *cmd, void *mconfig,
                                     const char *f)
{
    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (strcasecmp(f, "Off") == 0)
            dconfig->enable_sendfile = 0;
        else if (strcasecmp(f, "On") == 0)
            dconfig->enable_sendfile = 1;
        else
            return "WSGIEnableSendfile must be one of: Off | On";
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (strcasecmp(f, "Off") == 0)
            sconfig->enable_sendfile = 0;
        else if (strcasecmp(f, "On") == 0)
            sconfig->enable_sendfile = 1;
        else
            return "WSGIEnableSendfile must be one of: Off | On";
    }

    return NULL;
}

const char *wsgi_set_access_script(cmd_parms *cmd, void *mconfig,
                                   const char *args)
{
    WSGIDirectoryConfig *dconfig = NULL;
    WSGIScriptFile *object = NULL;

    const char *option = NULL;
    const char *value = NULL;

    object = newWSGIScriptFile(cmd->pool);

    object->handler_script = ap_getword_conf(cmd->pool, &args);

    if (!object->handler_script || !*object->handler_script)
        return "Location of access script not supplied.";

    while (*args)
    {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS)
        {
            return "Invalid option to WSGI access script definition.";
        }

        if (!strcmp(option, "application-group"))
        {
            if (!*value)
                return "Invalid name for WSGI application group.";

            object->application_group = value;
        }
        else
            return "Invalid option to WSGI access script definition.";
    }

    dconfig = (WSGIDirectoryConfig *)mconfig;
    dconfig->access_script = object;

    wsgi_python_required = 1;

    return NULL;
}

const char *wsgi_set_auth_user_script(cmd_parms *cmd, void *mconfig,
                                      const char *args)
{
    WSGIDirectoryConfig *dconfig = NULL;
    WSGIScriptFile *object = NULL;

    const char *option = NULL;
    const char *value = NULL;

    object = newWSGIScriptFile(cmd->pool);

    object->handler_script = ap_getword_conf(cmd->pool, &args);

    if (!object->handler_script || !*object->handler_script)
        return "Location of auth user script not supplied.";

    while (*args)
    {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS)
        {
            return "Invalid option to WSGI auth user script definition.";
        }

        if (!strcmp(option, "application-group"))
        {
            if (!*value)
                return "Invalid name for WSGI application group.";

            object->application_group = value;
        }
        else
            return "Invalid option to WSGI auth user script definition.";
    }

    dconfig = (WSGIDirectoryConfig *)mconfig;
    dconfig->auth_user_script = object;

    wsgi_python_required = 1;

    return NULL;
}

const char *wsgi_set_auth_group_script(cmd_parms *cmd, void *mconfig,
                                       const char *args)
{
    WSGIDirectoryConfig *dconfig = NULL;
    WSGIScriptFile *object = NULL;

    const char *option = NULL;
    const char *value = NULL;

    object = newWSGIScriptFile(cmd->pool);

    object->handler_script = ap_getword_conf(cmd->pool, &args);

    if (!object->handler_script || !*object->handler_script)
        return "Location of auth group script not supplied.";

    while (*args)
    {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS)
        {
            return "Invalid option to WSGI auth group script definition.";
        }

        if (!strcmp(option, "application-group"))
        {
            if (!*value)
                return "Invalid name for WSGI application group.";

            object->application_group = value;
        }
        else
            return "Invalid option to WSGI auth group script definition.";
    }

    dconfig = (WSGIDirectoryConfig *)mconfig;
    dconfig->auth_group_script = object;

    wsgi_python_required = 1;

    return NULL;
}

const char *wsgi_set_group_authoritative(cmd_parms *cmd, void *mconfig,
                                         const char *f)
{
    WSGIDirectoryConfig *dconfig = NULL;
    dconfig = (WSGIDirectoryConfig *)mconfig;

    if (strcasecmp(f, "Off") == 0)
        dconfig->group_authoritative = 0;
    else if (strcasecmp(f, "On") == 0)
        dconfig->group_authoritative = 1;
    else
        return "WSGIGroupAuthoritative must be one of: Off | On";

    return NULL;
}

const char *wsgi_add_handler_script(cmd_parms *cmd, void *mconfig,
                                    const char *args)
{
    WSGIScriptFile *object = NULL;

    const char *name = NULL;
    const char *option = NULL;
    const char *value = NULL;

    name = ap_getword_conf(cmd->pool, &args);

    if (!name || !*name)
        return "Name for handler script not supplied.";

    object = newWSGIScriptFile(cmd->pool);

    object->handler_script = ap_getword_conf(cmd->pool, &args);

    if (!object->handler_script || !*object->handler_script)
        return "Location of handler script not supplied.";

    while (*args)
    {
        if (wsgi_parse_option(cmd->pool, &args, &option,
                              &value) != APR_SUCCESS)
        {
            return "Invalid option to WSGI handler script definition.";
        }

        if (!strcmp(option, "process-group"))
        {
            if (!*value)
                return "Invalid name for WSGI process group.";

            object->process_group = value;
        }
        else if (!strcmp(option, "application-group"))
        {
            if (!*value)
                return "Invalid name for WSGI application group.";

            object->application_group = value;
        }
        else if (!strcmp(option, "pass-authorization"))
        {
            if (!*value)
                return "Invalid value for authorization flag.";

            if (strcasecmp(value, "Off") == 0)
                object->pass_authorization = "0";
            else if (strcasecmp(value, "On") == 0)
                object->pass_authorization = "1";
            else
                return "Invalid value for authorization flag.";
        }
        else
            return "Invalid option to WSGI handler script definition.";
    }

    if (cmd->path)
    {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;

        if (!dconfig->handler_scripts)
            dconfig->handler_scripts = apr_hash_make(cmd->pool);

        apr_hash_set(dconfig->handler_scripts, name, APR_HASH_KEY_STRING,
                     object);
    }
    else
    {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);

        if (!sconfig->handler_scripts)
            sconfig->handler_scripts = apr_hash_make(cmd->pool);

        apr_hash_set(sconfig->handler_scripts, name, APR_HASH_KEY_STRING,
                     object);
    }

    return NULL;
}

const char *wsgi_set_server_metrics(cmd_parms *cmd, void *mconfig,
                                    const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (strcasecmp(f, "Off") == 0)
        sconfig->server_metrics = 0;
    else if (strcasecmp(f, "On") == 0)
        sconfig->server_metrics = 1;
    else
        return "WSGIServerMetrics must be one of: Off | On";

    return NULL;
}

static long wsgi_find_path_info(const char *uri, const char *path_info)
{
    long lu = strlen(uri);
    long lp = strlen(path_info);

    while (lu-- && lp-- && uri[lu] == path_info[lp])
    {
        if (path_info[lp] == '/')
        {
            while (lu && uri[lu - 1] == '/')
                lu--;
        }
    }

    if (lu == -1)
    {
        lu = 0;
    }

    while (uri[lu] != '\0' && uri[lu] != '/')
    {
        lu++;
    }
    return lu;
}

static const char *wsgi_script_name(request_rec *r)
{
    char *script_name = NULL;
    long path_info_start = 0;

    if (!r->path_info || !*r->path_info)
    {
        script_name = apr_pstrdup(r->pool, r->uri);
    }
    else
    {
        path_info_start = wsgi_find_path_info(r->uri, r->path_info);

        script_name = apr_pstrndup(r->pool, r->uri, path_info_start);
    }

    if (strstr(script_name, "//"))
        ap_no2slash(script_name);

    if (!wsgi_server_config->case_sensitivity)
        ap_str_tolower(script_name);

    return script_name;
}

const char *wsgi_process_group(request_rec *r, const char *s)
{
    const char *name = NULL;
    const char *value = NULL;

    const char *h = NULL;
    apr_port_t p = 0;
    const char *n = NULL;

    if (!s)
        return "";

    if (*s != '%')
        return s;

    name = s + 1;

    if (*name)
    {
        if (!strcmp(name, "{GLOBAL}"))
            return "";

        if (!strcmp(name, "{RESOURCE}"))
        {
            h = r->server->server_hostname;
            p = ap_get_server_port(r);
            n = wsgi_script_name(r);

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u|%s", h, p, n);
            else
                return apr_psprintf(r->pool, "%s|%s", h, n);
        }

        if (!strcmp(name, "{SERVER}"))
        {
            h = r->server->server_hostname;
            p = ap_get_server_port(r);

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u", h, p);
            else
                return h;
        }

        if (!strcmp(name, "{HOST}"))
        {
            h = r->hostname;
            p = ap_get_server_port(r);

            /*
             * The Host header could be empty or absent for HTTP/1.0
             * or older. In that case fallback to ServerName.
             */

            if (h == NULL || *h == 0)
                h = r->server->server_hostname;

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u", h, p);
            else
                return h;
        }

        if (strstr(name, "{ENV:") == name)
        {
            long len = 0;

            name = name + 5;
            len = strlen(name);

            if (len && name[len - 1] == '}')
            {
                name = apr_pstrndup(r->pool, name, len - 1);

                value = apr_table_get(r->notes, name);

                if (!value)
                    value = apr_table_get(r->subprocess_env, name);

                if (!value)
                    value = getenv(name);

                if (value)
                {
                    if (*value == '%' && strstr(value, "%{ENV:") != value)
                        return wsgi_process_group(r, value);

                    return value;
                }
            }
        }
    }

    return s;
}

const char *wsgi_server_group(request_rec *r, const char *s)
{
    const char *name = NULL;

    const char *h = NULL;
    apr_port_t p = 0;

    if (!s)
        return "";

    if (*s != '%')
        return s;

    name = s + 1;

    if (*name)
    {
        if (!strcmp(name, "{GLOBAL}"))
            return "";

        if (!strcmp(name, "{SERVER}"))
        {
            h = r->server->server_hostname;
            p = ap_get_server_port(r);

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u", h, p);
            else
                return h;
        }

        if (!strcmp(name, "{HOST}"))
        {
            h = r->hostname;
            p = ap_get_server_port(r);

            /*
             * The Host header could be empty or absent for HTTP/1.0
             * or older. In that case fallback to ServerName.
             */

            if (h == NULL || *h == 0)
                h = r->server->server_hostname;

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u", h, p);
            else
                return h;
        }
    }

    return s;
}

const char *wsgi_application_group(request_rec *r, const char *s)
{
    const char *name = NULL;
    const char *value = NULL;

    const char *h = NULL;
    apr_port_t p = 0;
    const char *n = NULL;

    if (!s)
    {
        h = r->server->server_hostname;
        p = ap_get_server_port(r);
        n = wsgi_script_name(r);

        if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
            return apr_psprintf(r->pool, "%s:%u|%s", h, p, n);
        else
            return apr_psprintf(r->pool, "%s|%s", h, n);
    }

    if (*s != '%')
        return s;

    name = s + 1;

    if (*name)
    {
        if (!strcmp(name, "{GLOBAL}"))
            return "";

        if (!strcmp(name, "{RESOURCE}"))
        {
            h = r->server->server_hostname;
            p = ap_get_server_port(r);
            n = wsgi_script_name(r);

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u|%s", h, p, n);
            else
                return apr_psprintf(r->pool, "%s|%s", h, n);
        }

        if (!strcmp(name, "{SERVER}"))
        {
            h = r->server->server_hostname;
            p = ap_get_server_port(r);

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u", h, p);
            else
                return h;
        }

        if (!strcmp(name, "{HOST}"))
        {
            h = r->hostname;
            p = ap_get_server_port(r);

            /*
             * The Host header could be empty or absent for HTTP/1.0
             * or older. In that case fallback to ServerName.
             */

            if (h == NULL || *h == 0)
                h = r->server->server_hostname;

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u", h, p);
            else
                return h;
        }

        if (strstr(name, "{ENV:") == name)
        {
            long len = 0;

            name = name + 5;
            len = strlen(name);

            if (len && name[len - 1] == '}')
            {
                name = apr_pstrndup(r->pool, name, len - 1);

                value = apr_table_get(r->notes, name);

                if (!value)
                    value = apr_table_get(r->subprocess_env, name);

                if (!value)
                    value = getenv(name);

                if (value)
                {
                    if (*value == '%' && strstr(value, "%{ENV:") != value)
                        return wsgi_application_group(r, value);

                    return value;
                }
            }
        }
    }

    return s;
}

const char *wsgi_callable_object(request_rec *r, const char *s)
{
    const char *name = NULL;
    const char *value = NULL;

    if (!s)
        return "application";

    if (*s != '%')
        return s;

    name = s + 1;

    if (!*name)
        return "application";

    if (strstr(name, "{ENV:") == name)
    {
        long len = 0;

        name = name + 5;
        len = strlen(name);

        if (len && name[len - 1] == '}')
        {
            name = apr_pstrndup(r->pool, name, len - 1);

            value = apr_table_get(r->notes, name);

            if (!value)
                value = apr_table_get(r->subprocess_env, name);

            if (!value)
                value = getenv(name);

            if (value)
                return value;
        }
    }

    return "application";
}

WSGIRequestConfig *wsgi_create_req_config(apr_pool_t *p, request_rec *r)
{
    WSGIRequestConfig *config = NULL;
    WSGIServerConfig *sconfig = NULL;
    WSGIDirectoryConfig *dconfig = NULL;

    config = (WSGIRequestConfig *)apr_pcalloc(p, sizeof(WSGIRequestConfig));

    dconfig = ap_get_module_config(r->per_dir_config, &wsgi_module);
    sconfig = ap_get_module_config(r->server->module_config, &wsgi_module);

    config->pool = p;

    config->restrict_process = dconfig->restrict_process;

    if (!config->restrict_process)
        config->restrict_process = sconfig->restrict_process;

    config->process_group = dconfig->process_group;

    if (!config->process_group)
        config->process_group = sconfig->process_group;

    config->process_group = wsgi_process_group(r, config->process_group);

    config->application_group = dconfig->application_group;

    if (!config->application_group)
        config->application_group = sconfig->application_group;

    config->application_group = wsgi_application_group(r,
                                                       config->application_group);

    config->callable_object = dconfig->callable_object;

    if (!config->callable_object)
        config->callable_object = sconfig->callable_object;

    config->callable_object = wsgi_callable_object(r, config->callable_object);

    config->dispatch_script = dconfig->dispatch_script;

    if (!config->dispatch_script)
        config->dispatch_script = sconfig->dispatch_script;

    config->pass_apache_request = dconfig->pass_apache_request;

    if (config->pass_apache_request < 0)
    {
        config->pass_apache_request = sconfig->pass_apache_request;
        if (config->pass_apache_request < 0)
            config->pass_apache_request = 0;
    }

    config->pass_authorization = dconfig->pass_authorization;

    if (config->pass_authorization < 0)
    {
        config->pass_authorization = sconfig->pass_authorization;
        if (config->pass_authorization < 0)
            config->pass_authorization = 0;
    }

    config->script_reloading = dconfig->script_reloading;

    if (config->script_reloading < 0)
    {
        config->script_reloading = sconfig->script_reloading;
        if (config->script_reloading < 0)
            config->script_reloading = 1;
    }

    config->error_override = dconfig->error_override;

    if (config->error_override < 0)
    {
        config->error_override = sconfig->error_override;
        if (config->error_override < 0)
            config->error_override = 0;
    }

    config->chunked_request = dconfig->chunked_request;

    if (config->chunked_request < 0)
    {
        config->chunked_request = sconfig->chunked_request;
        if (config->chunked_request < 0)
            config->chunked_request = 0;
    }

    config->map_head_to_get = dconfig->map_head_to_get;

    if (config->map_head_to_get < 0)
    {
        config->map_head_to_get = sconfig->map_head_to_get;
        if (config->map_head_to_get < 0)
            config->map_head_to_get = 2;
    }

    config->ignore_activity = dconfig->ignore_activity;

    if (config->ignore_activity < 0)
    {
        config->ignore_activity = sconfig->ignore_activity;
        if (config->ignore_activity < 0)
            config->ignore_activity = 0;
    }

    config->trusted_proxy_headers = dconfig->trusted_proxy_headers;

    if (!config->trusted_proxy_headers)
        config->trusted_proxy_headers = sconfig->trusted_proxy_headers;

    config->trusted_proxies = dconfig->trusted_proxies;

    if (!config->trusted_proxies)
        config->trusted_proxies = sconfig->trusted_proxies;

    config->enable_sendfile = dconfig->enable_sendfile;

    if (config->enable_sendfile < 0)
    {
        config->enable_sendfile = sconfig->enable_sendfile;
        if (config->enable_sendfile < 0)
            config->enable_sendfile = 0;
    }

    config->access_script = dconfig->access_script;

    config->auth_user_script = dconfig->auth_user_script;

    config->auth_group_script = dconfig->auth_group_script;

    config->user_authoritative = dconfig->user_authoritative;

    if (config->user_authoritative == -1)
        config->user_authoritative = 1;

    config->group_authoritative = dconfig->group_authoritative;

    if (config->group_authoritative == -1)
        config->group_authoritative = 1;

    if (!dconfig->handler_scripts)
        config->handler_scripts = sconfig->handler_scripts;
    else if (!sconfig->handler_scripts)
        config->handler_scripts = dconfig->handler_scripts;
    else
    {
        config->handler_scripts = apr_hash_overlay(p, dconfig->handler_scripts,
                                                   sconfig->handler_scripts);
    }

    config->handler_script = "";

    config->daemon_connects = 0;
    config->daemon_restarts = 0;

    config->request_start = 0;
    config->queue_start = 0;
    config->daemon_start = 0;

    return config;
}

char *wsgi_original_uri(request_rec *r)
{
    char *first, *last;

    if (r->the_request == NULL)
    {
        return apr_pcalloc(r->pool, 1);
    }

    first = r->the_request; /* use the request-line */

    while (*first && !apr_isspace(*first))
    {
        ++first; /* skip over the method */
    }
    while (apr_isspace(*first))
    {
        ++first; /*   and the space(s)   */
    }

    last = first;
    while (*last && !apr_isspace(*last))
    {
        ++last; /* end at next whitespace */
    }

    return apr_pstrmemdup(r->pool, first, last - first);
}

/* ------------------------------------------------------------------------- */

/* vi: set sw=4 expandtab : */
