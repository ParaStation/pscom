/*
 * ParaStation
 *
 * Copyright (C) 2011-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * pscom_psm.h: Header for PSM communication
 */

#ifndef _PSCOM_PSM_H_
#define _PSCOM_PSM_H_

#include "pscom_priv.h"


/*
 * Methods
 */

static int pscom_psm_post_recv(pscom_con_t *con);
static void pscom_psm_init(void);
static void pscom_psm_finalize();


#endif /* _PSCOM_PSM_H_ */
