/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "test_utils_provider.h"

#include <stdlib.h>


void setup_dummy_provider(const char *type)
{
    /* init provider*/
    setenv("PSP_PRECON_TYPE", type, 1);
    pscom_precon_provider_init();
}

void teardown_dummy_provider(void)
{
    pscom_precon_provider_destroy();
}
