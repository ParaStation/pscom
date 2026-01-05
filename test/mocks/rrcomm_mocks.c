/*
 * ParaStation
 *
 * Copyright (C) 2025-2026 ParTec AG, Munich
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
#include <string.h>
#include <sys/types.h>

#include "rrcomm_mocks.h"
#include "pscom.h"
#include "pstaskid.h"
#include "pscom_precon.h"

typedef struct {
    pscom_info_rrc_t header;
    pscom_info_con_info_version_t info;
} rrc_msg_t;

////////////////////////////////////////////////////////////////////////////////
/// Mocking funktions for RRComm
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Mocking function for RRC_init()
 */
int __wrap_RRC_init(void)
{
    return 1;
}


/**
 * \brief Mocking function for ucp_config_release()
 */
void __wrap_RRC_finalize(void)
{
}


/**
 * \brief Mocking function for RRC_getJobID()
 */
PStask_ID_t __wrap_RRC_getJobID(void)
{
    return 88;
}


/**
 * \brief Mocking function for RRC_sendX()
 */
ssize_t __wrap_RRC_sendX(PStask_ID_t jobid, uint32_t dest, char *buf,
                         int buf_size)
{
    return (ssize_t)mock();
}


/**
 * \brief Mocking function for RRC_recvX()
 */
ssize_t __wrap_RRC_recvX(PStask_ID_t *jobid, uint32_t *src, char *buf,
                         int buf_size)
{
    rrc_msg_t msg;
    msg.header.type                        = 0; // default
    msg.header.size                        = sizeof(int);
    msg.header.remote_con                  = NULL;
    msg.header.source_con                  = NULL;
    msg.info.version.ver_from              = VER_FROM;
    msg.info.version.ver_to                = VER_TO;
    msg.info.source_sockid                 = 0;
    msg.info.con_info.rrcomm.remote_sockid = 0;

    ssize_t msg_size = sizeof(rrc_msg_t);
    *jobid           = 1;
    *src             = 1;

    if (buf_size < msg_size) { return msg_size; }

    memcpy(buf, &msg, msg_size);
    return (ssize_t)mock();
}
