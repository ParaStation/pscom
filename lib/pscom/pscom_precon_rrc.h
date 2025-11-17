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
#include <sys/time.h>
#include <stdint.h>
#include "list.h"


/**
 * @struct pscom_resend_request
 * @brief Information about an instant error.
 */
typedef struct pscom_resend_request {
    struct list_head next;     /**< Pointer to the next resend request. */
    pscom_precon_t *precon;    /**< Precon used to resend the message. */
    int dest;                  /**< Destination rank of the resend message. */
    uint64_t jobid;            /**< Destination jobid of the resend message. */
    int msg_type;              /**< Type of the the resend message. */
    struct timeval start_time; /**< Start time stamp when the resend is
                                  triggered. */
} pscom_resend_request_t;


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
    int msg_type;  /**< Type of the last message sent from this precon. */
    PStask_ID_t local_jobid;  /**< Jobid of this current precon. */
    PStask_ID_t remote_jobid; /**< Remote jobid of this current precon. */
    int info_sent;            /**< con_info already sent with backconnect */
    int resend_times; /**< Maximum number of retry to resend a packet. */
} pscom_precon_rrc_t;

#endif /* _PSCOM_RRCOMM_H_ */
