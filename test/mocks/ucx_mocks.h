/*
 * ParaStation
 *
 * Copyright (C) 2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stddef.h>
#include <ucp/api/ucp.h>
#include <ucp/api/ucp_def.h>

ucs_status_t __wrap_ucp_init_version(unsigned api_major_version,
                                     unsigned api_minor_version,
                                     const ucp_params_t *params,
                                     const ucp_config_t *config,
                                     ucp_context_h *context_p);
ucs_status_t __wrap_ucp_config_read(const char *env_prefix,
                                    const char *filename,
                                    ucp_config_t **config_p);
void __wrap_ucp_config_release(ucp_config_t *config);
ucs_status_t __wrap_ucp_worker_create(ucp_context_h context,
                                      const ucp_worker_params_t *params,
                                      ucp_worker_h *worker_p);
ucs_status_t __wrap_ucp_worker_get_address(ucp_worker_h worker,
                                           ucp_address_t **address_p,
                                           size_t *address_length_p);
void __wrap_ucp_worker_release_address(ucp_worker_h worker,
                                       ucp_address_t *address_p);
void __wrap_ucp_worker_destroy(ucp_worker_h worker);
void __wrap_ucp_cleanup(ucp_context_h context_p);


char *__wrap_ucs_status_string(ucs_status_t status);
