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
#ifndef _PSCOM_PRECON_TCP_H_
#define _PSCOM_PRECON_TCP_H_

#include <stddef.h>
#include <stdint.h>

#include "pscom.h"
#include "pscom_poll.h"
#include "pscom_types.h"
#include "pscom_ufd.h"
#include "pscom_precon.h"

typedef struct PSCOM_precon_tcp {
    unsigned long magic;
    pscom_con_t *con;
    pscom_sock_t *sock;
    pscom_precon_t *precon;
    ufd_info_t ufd_info;
    unsigned send_len; // Length of send
    unsigned recv_len; // Length of recv
    char *send;        // Send buffer
    char *recv;        // Receive buffer

    unsigned recv_done : 1;
    unsigned closefd_on_cleanup : 1; // Call close(fd) on cleanup?
    unsigned back_connect : 1;       // Is this a back connect precon?
    unsigned connect : 1;            // Bool: fd used with connect()?
    unsigned stalled_cnt : 8;        // Stalled connection counter

    unsigned reconnect_cnt;
    unsigned long last_reconnect; // usec of last reconnect

    size_t stat_send; // bytes send
    size_t stat_recv; // bytes received

    int nodeid, portno; // Retry connect to nodeid:portno on ECONNREFUSED

    unsigned long last_print_stat; // usec of last print_stat

    pscom_poll_t poll_read; // timeout handling

    unsigned stat_poll_cnt; // loops in poll
} pscom_precon_tcp_t;


/* init a precon object with tcp */
void pscom_precon_provider_init_tcp();

/* Connect a precon via tcp to nodeid:portno. Return 0 on sucess, -1 on error
 * with errno set. */
int pscom_precon_direct_connect_tcp(pscom_precon_t *precon, int nodeid,
                                    int portno);
pscom_err_t pscom_precon_connect_tcp(pscom_con_t *con);

void pscom_con_accept_tcp(ufd_t *ufd, ufd_funcinfo_t *ufd_info);

/* Assign the fd to precon. fd is typically from a previous fd =
 * accept(listen_fd). */
void pscom_precon_assign_fd_tcp(pscom_precon_tcp_t *pre_tcp, int fd);

void pscom_precon_handshake_tcp(pscom_precon_t *precon);

void pscom_precon_handle_receive_tcp(pscom_precon_tcp_t *pre_tcp, uint32_t type,
                                     void *data, unsigned size);

/* Send a con_info message of type CON_INFO, CON_INFO_DEMAND or BACK_CONNECT via
 * tcp*/
void pscom_precon_send_PSCOM_INFO_CON_INFO_tcp(pscom_precon_tcp_t *pre_tcp,
                                               int type);

/* send a message via tcp */
pscom_err_t pscom_precon_send_tcp(pscom_precon_t *precon, unsigned type,
                                  void *data, unsigned size);

void pscom_precon_check_connect_tcp(pscom_precon_tcp_t *pre_tcp);

pscom_precon_t *pscom_precon_create_tcp(pscom_con_t *con);

void pscom_precon_destroy_tcp(pscom_precon_t *precon);

void pscom_precon_recv_start_tcp(pscom_precon_t *precon);

void pscom_precon_recv_stop_tcp(pscom_precon_t *precon);

int pscom_precon_isconnected_tcp(pscom_precon_tcp_t *pre_tcp);

void pscom_precon_check_end_tcp(pscom_precon_tcp_t *pre_tcp);

void pscom_precon_abort_plugin_tcp(pscom_precon_tcp_t *pre_tcp);

void pscom_precon_terminate_tcp(pscom_precon_tcp_t *pre_tcp);

const char *pscom_precon_str_tcp(pscom_precon_tcp_t *pre_tcp);

void pscom_precon_ondemand_backconnect_tcp(pscom_con_t *con);

int pscom_precon_guard_setup_tcp(pscom_precon_t *precon);

#endif /* _PSCOM_PRECON_H_ */
