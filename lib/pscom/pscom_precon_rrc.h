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
#ifndef _PSCOM_PRECON_RRCOMM_H_
#define _PSCOM_PRECON_RRCOMM_H_

#include "pscom_precon.h"
#include "pscom_types.h"
#include "pstaskid.h"

/**
 * @struct PSCOM_precon_rrc
 * @brief Parameters used only by RRcomm precons.
 */
typedef struct PSCOM_precon_rrc {
    pscom_precon_t *precon;  /**< Pointer to connection precon (one by
                                connection). */
    pscom_con_t *con;        /**< Pointer to connection. */
    pscom_con_t *remote_con; /**< Pointer to remote connection. */
    int recv_done; /**< Handshaking for connection establishment done. */
    int type;      /**< Type of the message before creating the precon. */
    PStask_ID_t local_jobid;  /**< Jobid of this current precon. */
    PStask_ID_t remote_jobid; /**< Remote jobid of this current precon. */
    int info_sent;            /**< con_info already sent with backconnect */
} pscom_precon_rrc_t;

#endif /* _PSCOM_RRCOMM_H_ */
