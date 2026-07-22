/*
 * ParaStation
 *
 * Copyright (C) 2025-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "pscom_priv.h"
#include "pscom_ufd.h"
#include "pscom_utest.h"
#include "test_utils_common.h"
#include "test_utils_provider.h"

static test_utils_common_envvar_backup_t env_precon_type_backup_provider = {
    .name = "PSP_PRECON_TYPE"};

void setup_dummy_provider(const char *type)
{
    if (!type) {
        /* no type given means use the default (if not already set) */
        env_precon_type_backup_provider.value =
            pscom_utest.default_values.precon_type;
        env_precon_type_backup_provider.overwrite = 0;
    } else {
        /* save the old envvar value and overwrite it with the given type */
        env_precon_type_backup_provider.value     = type;
        env_precon_type_backup_provider.overwrite = 1;
    }
    test_utils_common_envvar_backup_capture(&env_precon_type_backup_provider);

    /* init/reset ufd so the precon provider can add its FD to an empty list */
    ufd_init(&pscom.ufd);

    pscom_precon_provider_init();
}

void teardown_dummy_provider(void)
{
    pscom_precon_provider_destroy();

    /* restore or unset envvar as it was before the test */
    test_utils_common_envvar_backup_restore(&env_precon_type_backup_provider);

    /* cleanup ufd (i.e., remove the precon provider's FD from the ufd list) */
    ufd_cleanup(&pscom.ufd);
}
