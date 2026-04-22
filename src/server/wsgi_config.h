#ifndef WSGI_CONFIG_H
#define WSGI_CONFIG_H

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

#include "wsgi_python.h"
#include "wsgi_apache.h"
#include "wsgi_server.h"

/* ------------------------------------------------------------------------- */

extern apr_array_header_t *wsgi_import_list;

extern int wsgi_parse_option(apr_pool_t *p, const char **line,
                             const char **name, const char **value);

extern const char *wsgi_add_script_alias(cmd_parms *cmd, void *mconfig,
                                         const char *args);
extern const char *wsgi_set_metrics_service(cmd_parms *cmd, void *mconfig,
                                            const char *arg1,
                                            const char *arg2);
extern const char *wsgi_set_slow_requests(cmd_parms *cmd, void *mconfig,
                                          const char *arg);

extern const char *wsgi_set_verbose_debugging(cmd_parms *cmd, void *mconfig,
                                              const char *f);
extern const char *wsgi_add_python_warnings(cmd_parms *cmd, void *mconfig,
                                            const char *f);
extern const char *wsgi_set_dont_write_bytecode(cmd_parms *cmd, void *mconfig,
                                                const char *f);
extern const char *wsgi_set_python_optimize(cmd_parms *cmd, void *mconfig,
                                            const char *f);
extern const char *wsgi_set_python_home(cmd_parms *cmd, void *mconfig,
                                        const char *f);
extern const char *wsgi_set_python_path(cmd_parms *cmd, void *mconfig,
                                        const char *f);
extern const char *wsgi_set_python_eggs(cmd_parms *cmd, void *mconfig,
                                        const char *f);
extern const char *wsgi_set_python_hash_seed(cmd_parms *cmd, void *mconfig,
                                             const char *f);
extern const char *wsgi_set_destroy_interpreter(cmd_parms *cmd, void *mconfig,
                                                const char *f);
extern const char *wsgi_set_restrict_embedded(cmd_parms *cmd, void *mconfig,
                                              const char *f);
extern const char *wsgi_set_restrict_stdin(cmd_parms *cmd, void *mconfig,
                                           const char *f);
extern const char *wsgi_set_restrict_stdout(cmd_parms *cmd, void *mconfig,
                                            const char *f);
extern const char *wsgi_set_restrict_signal(cmd_parms *cmd, void *mconfig,
                                            const char *f);
extern const char *wsgi_set_case_sensitivity(cmd_parms *cmd, void *mconfig,
                                             const char *f);
extern const char *wsgi_set_restrict_process(cmd_parms *cmd, void *mconfig,
                                             const char *args);
extern const char *wsgi_set_process_group(cmd_parms *cmd, void *mconfig,
                                          const char *n);
extern const char *wsgi_set_application_group(cmd_parms *cmd, void *mconfig,
                                              const char *n);
extern const char *wsgi_set_callable_object(cmd_parms *cmd, void *mconfig,
                                            const char *n);
extern const char *wsgi_add_import_script(cmd_parms *cmd, void *mconfig,
                                          const char *args);
extern const char *wsgi_set_dispatch_script(cmd_parms *cmd, void *mconfig,
                                            const char *args);
extern const char *wsgi_set_pass_apache_request(cmd_parms *cmd, void *mconfig,
                                                const char *f);
extern const char *wsgi_set_pass_authorization(cmd_parms *cmd, void *mconfig,
                                               const char *f);
extern const char *wsgi_set_script_reloading(cmd_parms *cmd, void *mconfig,
                                             const char *f);
extern const char *wsgi_set_error_override(cmd_parms *cmd, void *mconfig,
                                           const char *f);
extern const char *wsgi_set_chunked_request(cmd_parms *cmd, void *mconfig,
                                            const char *f);
extern const char *wsgi_set_map_head_to_get(cmd_parms *cmd, void *mconfig,
                                            const char *f);
extern const char *wsgi_set_ignore_activity(cmd_parms *cmd, void *mconfig,
                                            const char *f);
extern const char *wsgi_set_trusted_proxy_headers(cmd_parms *cmd,
                                                  void *mconfig,
                                                  const char *args);
extern const char *wsgi_set_trusted_proxies(cmd_parms *cmd,
                                            void *mconfig, const char *args);
extern const char *wsgi_set_enable_sendfile(cmd_parms *cmd, void *mconfig,
                                            const char *f);
extern const char *wsgi_set_access_script(cmd_parms *cmd, void *mconfig,
                                          const char *args);
extern const char *wsgi_set_auth_user_script(cmd_parms *cmd, void *mconfig,
                                             const char *args);
extern const char *wsgi_set_auth_group_script(cmd_parms *cmd, void *mconfig,
                                              const char *args);
extern const char *wsgi_set_group_authoritative(cmd_parms *cmd, void *mconfig,
                                                const char *f);
extern const char *wsgi_add_handler_script(cmd_parms *cmd, void *mconfig,
                                           const char *args);
extern const char *wsgi_set_server_metrics(cmd_parms *cmd, void *mconfig,
                                           const char *f);

/* ------------------------------------------------------------------------- */

#endif

/* vi: set sw=4 expandtab : */
