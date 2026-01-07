/*
 * ParaStation
 *
 * Copyright (C) 2021      ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdarg.h> /* IWYU pragma: keep */
#include <stddef.h> /* IWYU pragma: keep */
#include <stdint.h> /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <cmocka.h>

#include "ucx_mocks.h"
#include <ucp/api/ucp.h>
#include <ucp/api/ucp_def.h>

////////////////////////////////////////////////////////////////////////////////
/// Mocking funktions for UCP
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Mocking function for ucp_init_version()
 */
ucs_status_t __wrap_ucp_init_version(unsigned api_major_version,
                                     unsigned api_minor_version,
                                     const ucp_params_t *params,
                                     const ucp_config_t *config,
                                     ucp_context_h *context_p)
{
    function_called();

    return UCS_OK;
}


/**
 * \brief Mocking function for ucp_config_read()
 */
ucs_status_t __wrap_ucp_config_read(const char *env_prefix,
                                    const char *filename,
                                    ucp_config_t **config_p)
{
    return UCS_OK;
}

/**
 * \brief Mocking function for ucp_config_release()
 */
void __wrap_ucp_config_release(ucp_config_t *config)
{
}

/**
 * \brief Mocking function for ucp_worker_create()
 */
ucs_status_t __wrap_ucp_worker_create(ucp_context_h context,
                                      const ucp_worker_params_t *params,
                                      ucp_worker_h *worker_p)
{
    *worker_p = mock_type(ucp_worker_h);
    return UCS_OK;
}


/**
 * \brief Mocking function for ucp_worker_get_address()
 */
ucs_status_t __wrap_ucp_worker_get_address(ucp_worker_h worker,
                                           ucp_address_t **address_p,
                                           size_t *address_length_p)
{
    return UCS_OK;
}


/**
 * \brief Mocking function for ucp_worker_release_address()
 */
void __wrap_ucp_worker_release_address(ucp_worker_h worker,
                                       ucp_address_t *address_p)
{
}


/**
 * \brief Mocking function for ucp_worker_destroy()
 */
void __wrap_ucp_worker_destroy(ucp_worker_h worker)
{
    function_called();
    check_expected(worker);
}


/**
 * \brief Mocking function for ucp_cleanup()
 */
void __wrap_ucp_cleanup(ucp_context_h context_p)
{
}


////////////////////////////////////////////////////////////////////////////////
/// Mocking funktions for UCS
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Mocking function for ucs_status_string()
 */
char *__wrap_ucs_status_string(ucs_status_t status)
{
    return NULL;
}
