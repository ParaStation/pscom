/*
 * ParaStation
 *
 * Copyright (C) 2025-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
#include "pscom_version.h"

pscom_err_t pscom_version_check(int pscom_version_required, int pscom_version)
{
    int cuda_req, major_req, minor_req, cuda, major, minor;
    pscom_err_t ret = PSCOM_SUCCESS;

    PSCOM_VERSION_SPLIT(pscom_version_required, cuda_req, major_req, minor_req);
    PSCOM_VERSION_SPLIT(pscom_version, cuda, major, minor);

    if (!cuda && cuda_req) { ret = PSCOM_ERR_UNSUPPORTED_VERSION; }

    /*
     * different major number, or minor number bigger
     * (new libs support old api, if major number is equal)
     */
    if ((major_req != major) || (minor_req > minor)) {
        ret = PSCOM_ERR_UNSUPPORTED_VERSION;
    }

    return ret;
}
