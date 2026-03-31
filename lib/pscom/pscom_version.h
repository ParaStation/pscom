/*
 * ParaStation
 *
 * Copyright (C) 2025-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
#ifndef _PSCOM_VERSION_H_
#define _PSCOM_VERSION_H_

#include "pscom.h"

/**
 * @brief Check if ABI version pscom_version fulfills the required
 *        ABI version pscom_version_required.
 *
 * @param pscom_version_required Required ABI version
 * @param pscom_version          Available ABI version
 * @return pscom_err_t Returns PSCOM_ERR_UNSUPPORTED_VERSION if CUDA
 *                     support differs in both ABI versions, if major
 *                     ABI versions differ, or (in case major versions
 *                     are identical) if minor required ABI version is
 *                     larger than minor available ABI version.
 *                     Returns PSCOM_SUCCESS otherwise.
 */
pscom_err_t pscom_abi_version_check_internal(int pscom_version_required,
                                             int pscom_version);

#endif /* _PSCOM_VERSION_H_ */
