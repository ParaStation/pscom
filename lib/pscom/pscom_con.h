/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_CON_H_
#define _PSCOM_CON_H_

#include <assert.h>

#include "list.h"
#include "pscom.h"
#include "pscom_env.h"
#include "pscom_priv.h"

pscom_err_t pscom_con_connect_loopback(pscom_con_t *con);
/* start send and receive queue */
void pscom_con_setup(pscom_con_t *con);
void pscom_con_setup_ok(pscom_con_t *con);
void pscom_con_setup_failed(pscom_con_t *con, pscom_err_t err);

pscom_con_t *pscom_con_create(pscom_sock_t *sock);

/* clear all recvq's of this connection. finish all recv requests of this
 * connection with error. (keep recv any!) */
void pscom_con_terminate_recvq(pscom_con_t *con);
void pscom_con_close(pscom_con_t *con);
void pscom_con_closing(pscom_con_t *con);

void pscom_con_info_set(pscom_con_t *con, const char *path, const char *val);

/* {read,write}_{start,stop} default hook. */
void pscom_no_rw_start_stop(pscom_con_t *con);

pscom_con_t *pscom_ondemand_find_con(pscom_sock_t *sock, const char name[8]);
pscom_con_t *pscom_ondemand_get_con(pscom_sock_t *sock, const char name[8]);

/* Start the connection guard on con.
   - con must have an active con->precon
   - precon->closefd_on_cleanup will be set to false
   - precon's fd will be monitored for EOF
*/
void pscom_con_guard_start(pscom_con_t *con);
void pscom_con_guard_stop(pscom_con_t *con);

/**
 * @brief Checks whether a connection should be reading
 *
 * @param [in] con The connection to be tested
 *
 * @return 1 if the connection should be open for reading; 0 otherwise
 */
static inline int pscom_con_should_read(pscom_con_t *con)
{
    return (con->recv_req_cnt || con->in.req);
}


static inline void pscom_con_check_read_stop(pscom_con_t *con)
{
    if (!pscom_con_should_read(con) && !pscom.env.unexpected_receives) {
        con->read_stop(con);
    }
}


static inline
    // void _pscom_recv_req_cnt_check_start(pscom_con_t *con)
    void
    pscom_con_check_read_start(pscom_con_t *con)
{
    if (pscom_con_should_read(con)) { con->read_start(con); }
}


/**
 * @brief Checks whether a connection should be writing
 *
 * Send requests can be of two different kinds: either they are synchronously
 * processed and remain in the connection's send queue, or the respective plugin
 * is capable of asynchronous processing resulting in pending I/O on this
 * request. As long as a send request has pending I/O this is reflected by the
 * connections pending I/O counter.
 *
 * @param [in] con The connection to be tested
 *
 * @return 1 if the connection should be open for writing; 0 otherwise
 */
static inline int pscom_con_should_write(pscom_con_t *con)
{
    return (!list_empty(&con->sendq) || con->write_pending_io_cnt);
}


static inline void pscom_con_check_write_start(pscom_con_t *con)
{
    if (pscom_con_should_write(con)) { con->write_start(con); }
}


static inline void pscom_con_check_write_stop(pscom_con_t *con)
{
    if (!pscom_con_should_write(con)) {
        assert(list_empty(&con->sendq));
        con->write_stop(con);
    }
}
#endif /* _PSCOM_CON_H_ */
