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

#include "pscom_precon_rrc.h"
#include <assert.h>       // for assert
#include <errno.h>        // for errno, ENOPROTOOPT, EPROTO
#include <poll.h>         // for POLLIN, pollfd, POLLOUT
#include <stdint.h>       // for uint32_t
#include <stdio.h>        // for snprintf, sprintf
#include <string.h>       // for memset, strtok, memcpy, strcpy, strdup
#include <sys/types.h>    // for u_int32_t
#include <unistd.h>       // for _exit
#include "list.h"         // for list_empty, list_add_tail, list_entry, lis...
#include "pscom.h"        // for PSCOM_con_info::(anonymous union)::(anonym...
#include "pscom_con.h"    // for pscom_con_setup_failed, pscom_con_create
#include "pscom_env.h"    // for PSCOM_env
#include "pscom_plugin.h" // for pscom_plugin_by_archid, pscom_plugin_t
#include "pscom_precon.h" // for pscom_global_rrc_t, pscom_precon_provider
#include "pscom_priv.h"   // for pscom, get_sock, pscom_sock_t, pscom_con_t
#include "pscom_ufd.h"    // for ufd_event_clr, ufd_event_set, ufd_add, ufd...
#include <stdlib.h>       // for malloc, free, atoi, atoll
#include "pscom_debug.h"  // for DPRINT, D_PRECON_TRACE, D_ERR, D_DBG_V
#include "rrcomm.h"       // for RRC_getJobID, RRC_finalize, RRC_init, RRC_...

/**< Maximum packet size */
#define MAX_SIZE 1000

/**< Maximum endpoint information size */
#define MAX_EP_STR_SIZE 50

/**
 * @brief Creates a new RRComm precon
 *
 * This function creates and initialize a RRComm precon for the connection.
 *
 * @param [in] con  connection pointer
 *
 * @return connection pointer
 */
static pscom_precon_t *pscom_precon_create_rrc(pscom_con_t *con)
{
    size_t precon_size = sizeof(pscom_precon_t) + sizeof(pscom_precon_rrc_t);
    pscom_precon_t *precon;

    precon = (pscom_precon_t *)malloc(precon_size);

    assert(precon);
    memset(precon, 0, sizeof(*precon));

    pscom_precon_rrc_t *pre_rrc = (pscom_precon_rrc_t *)&precon->precon_data;
    precon->magic               = MAGIC_PRECON;
    pre_rrc->remote_con         = NULL;

    pre_rrc->con         = con;
    pre_rrc->recv_done   = 0;
    pre_rrc->precon      = precon;
    pre_rrc->local_jobid = RRC_getJobID();
    pre_rrc->info_sent   = 0;

    return precon;
}


/**
 * @brief Print pollfd statistics for this precon
 *
 * This function will print statistics about the given precon
 * providing information about pollfd events.
 *
 * @param [in]  pre_rrc     rrcomm plugin pointer
 */
static void pscom_precon_print_stat_rrc(pscom_precon_rrc_t *pre_rrc)
{
    pscom_global_rrc_t *global_rrc =
        (pscom_global_rrc_t *)pscom_precon_provider.precon_provider_data;

    int fd         = global_rrc->ufd_info.fd;
    char state[10] = "no fd";
    assert(pre_rrc->precon->magic == MAGIC_PRECON);

    if (fd != -1) {
        struct pollfd *pollfd = ufd_get_pollfd(&pscom.ufd,
                                               &global_rrc->ufd_info);
        if (pollfd) {
            state[0] = pollfd->events & POLLIN ? 'R' : '_';
            state[1] = pollfd->events & POLLOUT ? 'W' : '_';
            state[3] = 0;
        } else {
            strcpy(state, "no poll");
        }
    }
    DPRINT(D_PRECON_TRACE,
           "precon(%p): user_cnt:%d active_cnt:%d recv done?:%s precon "
           "count:%u "
           "state:%s\n",
           pre_rrc, global_rrc->user_cnt, global_rrc->active,
           pre_rrc->recv_done ? "yes" : "no",
           pscom_precon_provider.precon_count, state);
}


/**
 * @brief Check whether the handshake is done
 *
 * This function checks whether the handshake has finished by checking
 * `pre_rrc->recv_done`. If yes, the precon for this connection will be closed.
 *
 * @param [in] pre_rrc     rrcomm plugin pointer
 * @param [in] con         connection pointer
 */
static void pscom_precon_check_end_rrc(pscom_precon_rrc_t *pre_rrc,
                                       pscom_con_t *con)
{
    if (pre_rrc->recv_done) {
        /* print precon information */
        pscom_precon_print_stat_rrc(pre_rrc);

        pre_rrc->recv_done = 0;
        pscom_plugin_t *p  = con->precon->plugin;

        if (pre_rrc->con) {
            pre_rrc->con->precon = NULL; // disallow precon usage in
                                         // handshake
        }

        if (p) { p->con_handshake(pre_rrc->con, PSCOM_INFO_EOF, NULL, 0); }

        /* Destroy precon_rrcomm plugin for RRcomm connections */
        pscom_precon_destroy(pre_rrc->precon);
    }
}


/**
 * @brief Send a messsage via RRComm
 *
 * This function sends a message directly using `RRC_sendX()` to the destination
 * (jobID and rank). The sent message contains a header with the information on
 * rank, connection, and remote connection as well as the payload.
 *
 * @param [in] precon     precon pointer
 * @param [in] type       type of the message
 * @param [in] data       data of the message
 * @param [in] size       size of the message
 *
 * @return  PSCOM_SUCCESS if message is sent
 * @return  PSCOM_ERR_STDERROR if message cannot be sent
 */
static pscom_err_t pscom_precon_send_rrc(pscom_precon_t *precon, uint32_t type,
                                         void *data, uint32_t size)
{
    uint32_t dest;
    pscom_precon_rrc_t *pre_rrc = (pscom_precon_rrc_t *)&precon->precon_data;
    pscom_con_t *con            = pre_rrc->con;
    assert(con);

    pscom_info_rrc_t rrcomm;
    rrcomm.source_con = con;
    rrcomm.remote_con = pre_rrc->remote_con;
    rrcomm.type       = type;
    rrcomm.size       = size;

    pscom_precon_info_dump(precon, "send", type, data, size);

    /* allocate a `send` buffer of `msg_size` bytes */
    unsigned msg_size = size + sizeof(pscom_info_rrc_t);
    char *msg, *send = (char *)malloc(msg_size);
    assert(send);
    msg = send;

    /* copy the message header to the send buffer */
    memcpy(msg, &rrcomm, sizeof(pscom_info_rrc_t));
    msg += sizeof(pscom_info_rrc_t);
    /* append the message to the send buffer */
    memcpy(msg, data, size);

    /* Send RRcomm message to destination */
    dest = con->pub.remote_con_info.rank;

    int len = (int)RRC_sendX(pre_rrc->remote_jobid, dest, send, msg_size);

    free(send);

    /* Error when sending the message? */
    if (len < 0) {
        /* Message could not be sent */
        goto err_send;
    }

    return PSCOM_SUCCESS;

err_send:
    /* Print and return error */
    DPRINT(D_ERR, "RRC_sendX(%d) failed with error: %m\n", dest);
    return PSCOM_ERR_STDERROR;
}


/**
 * @brief Abort plugin and look for the next one
 *
 * This function will abort the current plugin and
 * will check for the next one.
 *
 * @param [in]  pre_rrc   rrcomm plugin pointer
 */
static void pscom_precon_rrcomm_abort_plugin(pscom_precon_rrc_t *pre_rrc)
{
    pscom_con_t *con = pre_rrc->con;
    if (pre_rrc->precon->plugin && con) {
        DPRINT(D_PRECON_TRACE, "pre_rrc(%p):abort %s", pre_rrc,
               pre_rrc->precon->plugin->name);
        pre_rrc->precon->plugin->con_handshake(con, PSCOM_INFO_ARCH_NEXT, NULL,
                                               0);
    }
    pre_rrc->precon->plugin = NULL; // Do not use plugin anymore after
                                    // PSCOM_INFO_ARCH_NEXT
}


/**
 * @brief Check version during handshake
 *
 * Compare the version received from the remote with the local version.
 *
 * @param [in]  version   version pointer
 * @param [in]  con       connection pointer
 */
static void pscom_check_VERSION(pscom_info_version_t *version, pscom_con_t *con)
{
    if ((VER_TO < version->ver_from) || (version->ver_to < VER_FROM)) {
        DPRINT(D_ERR,
               "Unsupported protocol version "
               "(mine:[%04x..%04x] remote:[%04x..%04x])",
               VER_FROM, VER_TO, version->ver_from, version->ver_to);
        errno = EPROTO;
        if (con) { pscom_con_setup_failed(con, PSCOM_ERR_STDERROR); }
    }
}


/**
 * @brief Send VERSION and CON_INFO
 *
 * Send VERSION and CON_INFO in one message (PSCOM_INFO_CON_INFO_VERSION) to the
 * destination and the remote peert will check them in `handle_receive`.
 *
 * @param [in]  con       connection pointer
 * @param [in]  type      message type
 * @param [in]  sockid    socket ID
 */
static void pscom_precon_send_PSCOM_INFO_CON_INFO_VERSION_rrc(
    pscom_con_t *con, int type, uint32_t local_sockid, uint32_t remote_sockid)
{
    pscom_precon_t *precon = con->precon;
    pscom_info_con_info_version_t msg_con_info_version;
    assert(precon->magic == MAGIC_PRECON);
    assert(con);
    assert(con->magic == MAGIC_CONNECTION);

    /* Send supported versions */
    msg_con_info_version.version.ver_from = VER_FROM;
    msg_con_info_version.version.ver_to   = VER_TO;

    /* Send connection information */
    pscom_con_info(con, &msg_con_info_version.con_info);
    msg_con_info_version.local_sockid                  = local_sockid;
    msg_con_info_version.con_info.rrcomm.remote_sockid = remote_sockid;

    DPRINT(D_PRECON_TRACE, "precon(%p): con:%s", precon,
           pscom_con_str(&con->pub));
    pscom_precon_send(precon, type, &msg_con_info_version,
                      sizeof(msg_con_info_version));
}


/**
 * @brief Handles the received message via RRcomm
 *
 * This function handles the received message and takes
 * the required action depending on what is received.
 *
 * @param [in] type    type of the message
 * @param [in] data    data of the message
 * @param [in] size    size of the message
 * @param [in] rrcomm  rrcomm structure
 */
static void pscom_precon_handle_receive_rrc(uint32_t type, PStask_ID_t jobid,
                                            void *data, unsigned size,
                                            pscom_info_rrc_t *rrcomm)
{
    pscom_precon_rrc_t *pre_rrc = NULL;
    pscom_con_t *con            = rrcomm->remote_con;
    pscom_sock_t *sock          = NULL;
    pscom_con_info_t *con_info  = NULL;
    uint32_t remote_sockid;
    pscom_info_con_info_version_t *msg = NULL;

    // Obtain socket when there is no connection yet
    if (!con) {
        msg = data;
        assert(msg);
        con_info      = &msg->con_info;
        remote_sockid = msg->con_info.rrcomm.remote_sockid;

        struct list_head *pos;
        list_for_each (pos, &pscom.sockets) {
            pscom_sock_t *temp_sock = list_entry(pos, pscom_sock_t, next);
            if (temp_sock->id == remote_sockid) {
                sock = temp_sock;
                break;
            }
        }
    }
    // Obtain socket from con
    else {
        sock = get_sock(con->pub.socket);
    }
    /* ensure that we have found one sock */
    assert(sock);

    assert(!con || con->magic == MAGIC_CONNECTION);
    switch (type) {
    case PSCOM_INFO_CON_INFO_VERSION: {
        msg                           = data;
        pscom_info_version_t *version = &msg->version;
        uint32_t local_sockid         = msg->local_sockid;
        remote_sockid                 = msg->con_info.rrcomm.remote_sockid;

        assert(size == sizeof(*msg));
        pscom_check_VERSION(version, con);

        if (!con) { // Accepting side of the connection
            con                            = pscom_con_create(sock);
            con->state.internal_connection = 1; // until the user gets a handle
                                                // to con (via con->on_accept)
            con->pub.state                 = PSCOM_CON_STATE_ACCEPTING;
            con->pub.remote_con_info       = msg->con_info;

            pscom_precon_t *precon = pscom_precon_create(con);
            con->precon            = precon;
            pre_rrc                = (pscom_precon_rrc_t *)&precon->precon_data;

            pre_rrc->remote_con   = rrcomm->source_con;
            pre_rrc->remote_jobid = jobid;

            pscom_precon_recv_start(pre_rrc->precon);

            pscom_precon_send_PSCOM_INFO_CON_INFO_VERSION_rrc(
                con, PSCOM_INFO_CON_INFO_VERSION, remote_sockid, local_sockid);
            /* this should only happen for direct connection;
             * for ONDEMAND, it should not be possible */
            if (pre_rrc->con->pub.type != PSCOM_CON_TYPE_ONDEMAND) {
                pre_rrc->precon->plugin = NULL;
                plugin_connect_first(con);
            }

        } else {
            con->pub.remote_con_info = msg->con_info;
            pre_rrc = (pscom_precon_rrc_t *)&con->precon->precon_data;
            pre_rrc->remote_con   = rrcomm->source_con;
            pre_rrc->remote_jobid = jobid;
        }

        break;
    }
    case PSCOM_INFO_BACK_CONNECT: {
        assert(!con);
        pscom_info_version_t *version = &msg->version;

        // Search for an existing matching connection
        con = pscom_ondemand_find_con(sock, con_info->name);

        if (con && con->pub.type == PSCOM_CON_TYPE_ONDEMAND) {
            /* Trigger the back connect */
            DPRINT(D_DBG_V, "RACCEPT %s", pscom_con_str(&con->pub));
            con->write_start(con);

            /* Handle VERSION and CON_INFO during backconnect */
            assert(size == sizeof(*msg));
            pscom_check_VERSION(version, con);
            pre_rrc = (pscom_precon_rrc_t *)&con->precon->precon_data;
            pre_rrc->remote_con = rrcomm->source_con;

            /* Set con */
            assert(con->pub.type == PSCOM_CON_TYPE_ONDEMAND);
            con->pub.remote_con_info = msg->con_info;

            DPRINT(D_PRECON_TRACE, "pre_rrc(%p): recv backcon %.8s to %.8s",
                   pre_rrc, con_info->name, sock->pub.local_con_info.name);
        } else {
            DPRINT(D_DBG_V, "RACCEPT from %s skipped",
                   pscom_con_info_str(con_info));
        }
        break;
    }
    case PSCOM_INFO_CON_INFO_VERSION_DEMAND: {
        msg                           = data;
        pscom_info_version_t *version = &msg->version;
        uint32_t local_sockid         = msg->local_sockid;
        remote_sockid                 = msg->con_info.rrcomm.remote_sockid;

        assert(size == sizeof(*msg));
        pscom_check_VERSION(version, con);

        // Search for the existing matching connection
        con = pscom_ondemand_get_con(sock, msg->con_info.name);
        if (con) {

            if (!con->precon) {
                pscom_precon_t *precon = pscom_precon_create(con);
                con->precon            = precon;
                pre_rrc = (pscom_precon_rrc_t *)&precon->precon_data;

                pre_rrc->remote_con   = rrcomm->source_con;
                pre_rrc->remote_jobid = jobid;
                pscom_precon_recv_start(pre_rrc->precon);
            }

            pre_rrc = (pscom_precon_rrc_t *)&con->precon->precon_data;

            /* Set con */
            assert(con->pub.type == PSCOM_CON_TYPE_ONDEMAND);
            con->pub.remote_con_info = msg->con_info;

            con->pub.state = PSCOM_CON_STATE_ACCEPTING_ONDEMAND;

            con->precon         = pre_rrc->precon;
            pre_rrc->remote_con = rrcomm->source_con;

            /* Send INFO_CON_INFO_VERSION if not provided by backconnect yet */
            if (!pre_rrc->info_sent) {
                pscom_precon_send_PSCOM_INFO_CON_INFO_VERSION_rrc(
                    con, PSCOM_INFO_CON_INFO_VERSION, remote_sockid,
                    local_sockid);
            }

            pre_rrc->precon->plugin = NULL;
            plugin_connect_first(con);

        } else {
            /* No con found.
               Reject this connection! */
            DPRINT(D_WARN, "Reject %s : unknown ondemand connection",
                   pscom_con_info_str(&msg->con_info));
        }

        break;
    }
    case PSCOM_INFO_ARCH_REQ: {
        assert(size == sizeof(int));
        assert(con);
        int arch          = *(int *)data;
        pscom_plugin_t *p = NULL;
        pre_rrc           = (pscom_precon_rrc_t *)&con->precon->precon_data;

        if (_pscom_con_type_mask_is_set(sock, PSCOM_ARCH2CON_TYPE(arch))) {
            p = pscom_plugin_by_archid(arch);
        }

        if (p && !p->con_init(con)) {
            con->precon->plugin = p;
            assert(con->precon);
            /* Use asynchronous handshake */
            con->precon->plugin->con_handshake(con, type, data, size);
        } else {
            // Unknown or disabled arch or con_init fail. Try next arch.
            pscom_precon_send_PSCOM_INFO_ARCH_NEXT(con->precon);
        }
        break;
    }
    case PSCOM_INFO_ARCH_OK:
    case PSCOM_INFO_ARCH_STEP1:
    case PSCOM_INFO_ARCH_STEP2:
    case PSCOM_INFO_ARCH_STEP3:
    case PSCOM_INFO_ARCH_STEP4: {
        /* Handled by the current plugin. precon->plugin might be
         * null, in the case of an initialization error. */
        if (con) {
            pre_rrc = (pscom_precon_rrc_t *)&con->precon->precon_data;
            if (con->precon->plugin) {
                con->precon->plugin->con_handshake(con, type, data, size);
                if (type == PSCOM_INFO_ARCH_OK) {
                    pscom_precon_recv_stop(pre_rrc->precon);
                }
            } else {
                // Failed locally before. Handle OK like an ARCH_NEXT
                if (type == PSCOM_INFO_ARCH_OK) {
                    plugin_connect_next(pre_rrc->con);
                }
            }
        }
        break;
    }
    case PSCOM_INFO_ARCH_NEXT: {
        pre_rrc = (pscom_precon_rrc_t *)&con->precon->precon_data;
        pscom_precon_rrcomm_abort_plugin(pre_rrc);
        plugin_connect_next(con);
        break;
    }
    case PSCOM_INFO_EOF: {
        if (con->precon->plugin && con) {
            con->precon->plugin->con_handshake(con, type, data, size);
        }
        con->precon->plugin = NULL;
    }
    default: /* ignore all unknown info messages */
        ;
    }

    if (con) {
        pscom_precon_info_dump(con->precon, "recv", type, data, size);
        pre_rrc = (pscom_precon_rrc_t *)&con->precon->precon_data;
        pscom_precon_check_end_rrc(pre_rrc, con);
    }
}


/**
 * @brief Receive message via RRComm.
 *
 * This function receives a message and handles it
 * depending on the type of the message.
 * In case of failure, the corresponding error will be
 * printed and the current process will abort.
 *
 * @param [in] ufd       ufd pointer
 * @param [in] ufd_info  ufd_info pointer
 */
static void pscom_precon_do_read_rrc(ufd_t *ufd, ufd_funcinfo_t *ufd_info)
{
    int rank;
    PStask_ID_t jobid;
    char *recv = (char *)malloc(MAX_SIZE);
    assert(recv);

    /* Read the package and store it in recv buffer */
    int len = (int)RRC_recvX(&jobid, &rank, recv, MAX_SIZE);

    /* Handle a possible error */
    if (len < 0) {
        /* Print error and exit */
        DPRINT(D_ERR, "RRC_recvX(%d) failed with error: %m\n", rank);
        _exit(112); // terminate
    }

    pscom_info_rrc_t *rrcomm = (pscom_info_rrc_t *)recv;

    /* Handle the received message depending on the type. */
    pscom_precon_handle_receive_rrc(rrcomm->type, jobid,
                                    recv + sizeof(pscom_info_rrc_t),
                                    rrcomm->size, rrcomm);

    free(recv);
    recv = NULL;

    return;
}


/**
 * @brief Assign a file descriptor to global_rrc->ufd_info
 *
 * This function assigns RRcomm file descriptor to the
 * `global_rrc->ufd_info`. It adds the `global_rrc->ufd_info`
 * to the list and sets up different function pointers.
 */
static void pscom_precon_assign_fd_rrc(void)
{
    pscom_global_rrc_t *global_rrc =
        (pscom_global_rrc_t *)pscom_precon_provider.precon_provider_data;

    global_rrc->ufd_info.fd       = global_rrc->rrcomm_fd;
    global_rrc->ufd_info.can_read = pscom_precon_do_read_rrc;

    ufd_add(&pscom.ufd, &global_rrc->ufd_info);
}


/**
 * @brief Start the handshake
 *
 * This function exchanges the version and connection
 * information between two endpoints.
 * For the plugin version exchange, this is done
 * after exchanging `con_info` when running RRcomm.
 *
 * @param [in] precon     precon pointer
 * @param [in] sockid     socket ID
 * @param [in] jobid      job ID
 */
static void pscom_precon_handshake_rrc(pscom_precon_t *precon,
                                       uint32_t remote_sockid,
                                       PStask_ID_t jobid)
{
    pscom_precon_rrc_t *pre_rrc = (pscom_precon_rrc_t *)&precon->precon_data;
    pscom_sock_t *sock          = get_sock(pre_rrc->con->pub.socket);
    u_int32_t local_sockid      = sock->id;

    if (pre_rrc->con && (pre_rrc->con->pub.state & PSCOM_CON_STATE_CONNECTING)) {
        int on_demand = (pre_rrc->con->pub.type == PSCOM_CON_TYPE_ONDEMAND);
        if (on_demand) {
            pre_rrc->type           = PSCOM_INFO_CON_INFO_VERSION_DEMAND;
            pre_rrc->con->pub.state = PSCOM_CON_STATE_CONNECTING_ONDEMAND;
        } else {
            pre_rrc->type           = PSCOM_INFO_CON_INFO_VERSION;
            pre_rrc->con->pub.state = PSCOM_CON_STATE_CONNECTING;
        }

        pre_rrc->remote_jobid = jobid;
        pre_rrc->remote_con   = NULL;
        pscom_precon_send_PSCOM_INFO_CON_INFO_VERSION_rrc(pre_rrc->con,
                                                          pre_rrc->type,
                                                          local_sockid,
                                                          remote_sockid);
    }
}


/**
 * @brief Send a backconnect request
 *
 * This function will send a backconnect message.
 *
 * @param [in] precon  precon pointer
 * @param [in] con     connection pointer
 * @param [in] type    type of the message
 */
static void pscom_precon_send_PSCOM_INFO_CON_INFO_rrc(pscom_precon_t *precon,
                                                      pscom_con_t *con,
                                                      int type)
{
    pscom_info_con_info_version_t msg_con_info_version;
    pscom_sock_t *sock = get_sock(con->pub.socket);
    assert(precon->magic == MAGIC_PRECON);
    assert(con);
    assert(con->magic == MAGIC_CONNECTION);

    /* Send supported versions */
    msg_con_info_version.version.ver_from = VER_FROM;
    msg_con_info_version.version.ver_to   = VER_TO;

    /* Send connection information */
    pscom_con_info(con, &msg_con_info_version.con_info);
    msg_con_info_version.local_sockid = sock->id;
    msg_con_info_version.con_info.rrcomm.remote_sockid =
        con->pub.remote_con_info.rrcomm.remote_sockid;

    DPRINT(D_PRECON_TRACE, "precon(%p): con:%s", precon,
           pscom_con_str(&con->pub));
    pscom_precon_send(precon, type, &msg_con_info_version,
                      sizeof(msg_con_info_version));
}


/**
 * @brief Prepare a backconnect request
 *
 * This function will prepare a backconnect when
 * remote process name is lower than the local one.
 *
 * @param [in] con     connection pointer
 */
static void pscom_precon_ondemand_backconnect_rrc(pscom_con_t *con)
{
    int start_receiver     = 0;
    pscom_precon_t *precon = NULL;
    if (!con->precon) {
        precon         = pscom_precon_create(con);
        con->precon    = precon;
        start_receiver = 1;
    } else {
        precon = con->precon;
    }
    pscom_precon_rrc_t *pre_rrc = (pscom_precon_rrc_t *)&precon->precon_data;
    if (start_receiver) { pscom_precon_recv_start(precon); }

    pre_rrc->type         = PSCOM_INFO_BACK_CONNECT;
    pre_rrc->remote_con   = NULL;
    pre_rrc->con          = con;
    pre_rrc->remote_jobid = con->pub.remote_con_info.rrcomm.jobid;
    pre_rrc->info_sent    = 1;
    pscom_precon_send_PSCOM_INFO_CON_INFO_rrc(con->precon, con,
                                              PSCOM_INFO_BACK_CONNECT);
}


/**
 * @brief This function starts connecting to the peer via precon RRComm
 *
 * This function will create a new preconnection for connecting the remote
 * endpoint. The precon used for handshaking is initialized with RRcomm
 * protocol for this connection.
 *
 * @param [in] con     con pointer
 *
 * @return  PSCOM_SUCCESS if connected
 * @return  PSCOM_ERR_STDERROR if connection states is closed
 */
static pscom_err_t pscom_precon_connect_rrc(pscom_con_t *con)
{
    pscom_sock_t *sock     = get_sock(con->pub.socket);
    pscom_precon_t *precon = pscom_precon_create(con);
    con->precon            = precon;

    pscom_precon_recv_start(precon);

    if (list_empty(&con->next)) {
        list_add_tail(&con->next, &sock->connections);
    }

    con->pub.state = PSCOM_CON_STATE_CONNECTING;
    pscom_precon_handshake_rrc(con->precon,
                               con->pub.remote_con_info.rrcomm.remote_sockid,
                               con->pub.remote_con_info.rrcomm.jobid);

    if (con->pub.state == PSCOM_CON_STATE_CLOSED) { goto err_connect; }

    return PSCOM_SUCCESS;
    /* --- */
// err_init_failed:
err_connect:
    if (errno != ENOPROTOOPT) {
        // if (errno == ENOPROTOOPT) _plugin_connect_next() already called
        // pscom_con_setup_failed().
        pscom_con_setup_failed(con, PSCOM_ERR_STDERROR);
    }
    return PSCOM_ERR_STDERROR;
}


/**
 * @brief Initializes RRComm.
 *
 * This function initializes RRComm and the RRComm related variables in precon
 * provider. Besides, it sets the global RRcomm `ufd_info` and assigns the
 * `fd`.
 */
static void pscom_precon_provider_init_rrc(void)
{
    pscom_global_rrc_t *global_rrc;

    /* Initialize RRcomm */
    int fd = RRC_init();

    if (fd < 0) {
        DPRINT(D_ERR, "RRcomm file descriptor could not be initialized! %s\n",
               strerror(errno));
        _exit(112);
    }

    if (pscom.env.guard == 1) {
        DPRINT(D_ERR, "The connection guards have to be disabled when RRComm "
                      "is used as the precon protocol! PSP_GUARD must be set "
                      "to 0 when PSP_PRECON_TYPE=rrcomm!\n");
        _exit(1);
    }

    // Assign memory for RRcomm sock variables
    pscom_precon_provider.precon_provider_data = (void *)malloc(
        sizeof(pscom_global_rrc_t));
    assert(pscom_precon_provider.precon_provider_data);
    global_rrc = (pscom_global_rrc_t *)
                     pscom_precon_provider.precon_provider_data;
    memset(global_rrc, 0, sizeof(pscom_global_rrc_t));

    // Assign RRcomm file descriptor
    global_rrc->rrcomm_fd = fd;
    // Initialize user counter of listener
    global_rrc->user_cnt  = 0;
    // Initialize listener counter
    global_rrc->active    = 0;
    // Assign RRcomm file descriptor
    pscom_precon_assign_fd_rrc();
}


/**
 * @brief Finalizes RRcomm.
 *
 * This function will destroy RRcomm and ensures that
 * there are not precons pending and counters are 0.
 * Besides, deletes RRcomm `ufd_info` and frees sock rrcomm.
 */
static void pscom_precon_provider_destroy_rrc(void)
{
    pscom_global_rrc_t *global_rrc =
        (pscom_global_rrc_t *)pscom_precon_provider.precon_provider_data;

    // Ensure that precon_list is empty
    assert(list_empty(&pscom_precon_provider.precon_list));
    assert(!pscom_precon_provider.precon_count);

    // Ensure that connection and listener counters are 0
    assert(!global_rrc->user_cnt);

    // Delete RRcomm ufd_info
    ufd_del(&pscom.ufd, &global_rrc->ufd_info);
    // Destroy sock rrcomm struct
    free(global_rrc);

    // finalize RRcomm for this socket
    RRC_finalize();
}


/**
 * @brief Destroys a RRcomm precon
 *
 * This function is called by `pscom_precon_destroy()`
 * and sets the `pre_rrc` variables to NULL/0. All the rest
 * is done in `pscom_precon_destroy()` for both TCP and RRcomm.
 *
 * @param [in] precon  precon pointer
 *
 */
static void pscom_precon_cleanup_rrc(pscom_precon_t *precon)
{
    pscom_precon_rrc_t *pre_rrc = (pscom_precon_rrc_t *)&precon->precon_data;

    pre_rrc->precon     = NULL;
    pre_rrc->con        = NULL;
    pre_rrc->remote_con = NULL;
    pre_rrc->recv_done  = 0;
}


/**
 * @brief Set a POLLIN event
 *
 * This function sets a POLLIN event to be able to
 * receive new messages. It also increases precon counter.
 * All of this is for ondemand connections only.
 *
 * @param [in] precon     precon pointer
 */
static void pscom_precon_recv_start_rrc(pscom_precon_t *precon)
{
    pscom_global_rrc_t *global_rrc =
        (pscom_global_rrc_t *)pscom_precon_provider.precon_provider_data;

    if (!global_rrc->user_cnt && !global_rrc->active) {
        ufd_event_set(&pscom.ufd, &global_rrc->ufd_info, POLLIN);
    }

    global_rrc->user_cnt++;
}


/**
 * @brief Clear POLLIN event
 *
 * Clear POLLIN event to avoid latency
 * issues in ondemand connections. Also clears POLLIN
 * when counters are 0. Additionally, sets
 * `con->recv_done` to 1 in all type of connections.
 * Also precon counter is decreased in ondemand connections.
 *
 * @param [in] precon     precon     pointer
 */
static void pscom_precon_recv_stop_rrc(pscom_precon_t *precon)
{
    pscom_global_rrc_t *global_rrc =
        (pscom_global_rrc_t *)pscom_precon_provider.precon_provider_data;
    pscom_precon_rrc_t *pre_rrc = (pscom_precon_rrc_t *)&precon->precon_data;

    /* Check to clear POLLIN event only if there are pending connections */
    assert(global_rrc->user_cnt > 0);
    global_rrc->user_cnt--;

    /* Clear POLLIN event if counters are 0 */
    if (!global_rrc->user_cnt && !global_rrc->active) {
        ufd_event_clr(&pscom.ufd, &global_rrc->ufd_info, POLLIN);
    }

    pre_rrc->recv_done = 1;
}


/**
 * @brief Add the listener when read and precon counters are 0
 *
 * When the counters are 0, the corresponding listener will be added.
 * This function will increment the read counter.
 *
 * @param [in]  listener   pscom listener
 */
static void pscom_listener_active_inc_rrc(struct pscom_listener *listener)
{
    pscom_global_rrc_t *global_rrc =
        (pscom_global_rrc_t *)pscom_precon_provider.precon_provider_data;

    if (!global_rrc->user_cnt && !global_rrc->active) {
        ufd_event_set(&pscom.ufd, &global_rrc->ufd_info, POLLIN);
    }
    global_rrc->user_cnt++;
}


/**
 * @brief Remove the listener when counters are 0
 *
 * This function will decrement the read counter for the given precon.
 * When counters are 0, the corresponding listener will be deleted.
 * The read counter is decreased in any case.
 *
 * @param [in]  listener   pscom listener
 */
static void pscom_listener_active_dec_rrc(struct pscom_listener *listener)
{
    pscom_global_rrc_t *global_rrc =
        (pscom_global_rrc_t *)pscom_precon_provider.precon_provider_data;

    assert(global_rrc->user_cnt > 0);
    global_rrc->user_cnt--;
    if (!global_rrc->user_cnt && !global_rrc->active) {
        ufd_event_clr(&pscom.ufd, &global_rrc->ufd_info, POLLIN);
    }
}


/**
 * @brief Start receiver
 *
 * Start receiver for direct connections.
 * `portno` is not used here, however
 * it is provided for consistency with TCP.
 * Also, a default sock is assigned to rrcomm.
 *
 * @param [in]  sock    sock pointer
 * @param [in]  portno  port number
 */
static pscom_err_t pscom_sock_start_listen_rrc(pscom_sock_t *sock, int portno)
{
    pscom_global_rrc_t *global_rrc =
        (pscom_global_rrc_t *)pscom_precon_provider.precon_provider_data;

    // Avoid error in `_pscom_con_connect_ondemand`
    sock->pub.listen_portno                       = 0;
    sock->pub.local_con_info.rrcomm.jobid         = RRC_getJobID();
    sock->pub.local_con_info.rrcomm.remote_sockid = 0;

    // Start receiver
    if (global_rrc->active == 0 && !global_rrc->user_cnt) {
        ufd_event_set(&pscom.ufd, &global_rrc->ufd_info, POLLIN);
    }
    global_rrc->active++;

    return PSCOM_SUCCESS;
}


/**
 * @brief Stop receiver
 *
 * Stop receiver for direct connections.
 *
 * @param [in]  sock    sock pointer
 */
static void pscom_sock_stop_listen_rrc(pscom_sock_t *sock)
{
    pscom_global_rrc_t *global_rrc =
        (pscom_global_rrc_t *)pscom_precon_provider.precon_provider_data;

    // this will be called when sock is closed, active may already be 0
    if (global_rrc->active == 0) { return; }

    assert(global_rrc->active > 0);
    global_rrc->active--;
    if (global_rrc->active == 0 && !global_rrc->user_cnt) {
        ufd_event_clr(&pscom.ufd, &global_rrc->ufd_info, POLLIN);
    }
}

/**
 * @brief Resume listener
 *
 * Add `ufd_info` back to the pscom ufd list and
 * start listening again. It must be used
 * in pair with `pscom_listener_suspend()`.
 *
 * @param [in]  listener   pscom listener
 */
static void pscom_listener_resume_rrc(struct pscom_listener *listener)
{
    pscom_global_rrc_t *global_rrc =
        (pscom_global_rrc_t *)pscom_precon_provider.precon_provider_data;

    // todo: for now suspend/resume only controls `active` counter, more tests
    // are needed
    if (global_rrc->active == 0 && !global_rrc->user_cnt) {
        ufd_event_set(&pscom.ufd, &global_rrc->ufd_info, POLLIN);
    }
    global_rrc->active++;
}


/**
 * @brief Resume listener
 *
 * Remove `ufd_info` from the pscom ufd list
 * and stop listening. The fd is not closed!
 * Use `pscom_listener_resume()` to start listening again.
 *
 * @param [in]  listener   pscom listener
 */
static void pscom_listener_suspend_rrc(struct pscom_listener *listener)
{
    pscom_global_rrc_t *global_rrc =
        (pscom_global_rrc_t *)pscom_precon_provider.precon_provider_data;

    // todo: for now suspend/resume only controls `active` counter, more tests
    // are needed
    assert(global_rrc->active > 0);
    global_rrc->active--;
    if (global_rrc->active == 0 && !global_rrc->user_cnt) {
        ufd_event_clr(&pscom.ufd, &global_rrc->ufd_info, POLLIN);
    }
}


/**
 * @brief Obtain information from a socket
 *
 * In case of a INTRA-JOB, it sets NULL in `ep_str`.
 * For INTER-JOB socket, `ep_str` will be
 * "rank:jobid:sockID:sockName".
 *
 * @param [in] socket  socket pointer
 * @param [in] ep_str  string to pass the socket information
 *
 * @return PSCOM_SUCCESS
 */
static pscom_err_t pscom_get_ep_info_from_socket_rrc(pscom_socket_t *socket,
                                                     char **ep_str)
{
    char *ep_str_rrc = (char *)malloc(MAX_EP_STR_SIZE);
    assert(ep_str_rrc);
    pscom_sock_t *sock = get_sock(socket);

    if (sock->sock_flags & PSCOM_SOCK_FLAG_INTRA_JOB) {
        *ep_str = NULL;
    } else {
        snprintf(ep_str_rrc, MAX_EP_STR_SIZE, "%d:%ld:%d@%s",
                 sock->pub.local_con_info.rank, RRC_getJobID(), sock->id,
                 socket->local_con_info.name);
        *ep_str = ep_str_rrc;
    }

    return PSCOM_SUCCESS;
}


/**
 * @brief Set con_info values
 *
 * Set the `con_info` parameters depending on the socket type,
 * for intra-job socket (NULL), we sets the `name` with `rank` and
 * `remote_sockid` as 0, while for inter-job socket
 * ("rank:jobid:sockID:sockName"), we will set the rank, job ID, socket ID, and
 * socket name using `ep_str`
 *
 * @param [in] ep_str   string with socket information
 * @param [in] con_info connection information
 *
 * @return PSCOM_SUCCESS
 */
static pscom_err_t pscom_parse_ep_info_rrc(const char *ep_str,
                                           pscom_con_info_t *con_info)
{
    char dest_name[9];
    char *name = NULL;
    char *jobid;
    char *rank;
    char *sockid;
    char *token;

    if (!ep_str) {
        con_info->rrcomm.jobid = RRC_getJobID();
        memset(con_info->name, 0, sizeof(con_info->name));
        sprintf(dest_name, "r%07d", con_info->rank);
        memcpy(con_info->name, dest_name, sizeof(dest_name));
        con_info->rrcomm.remote_sockid = 0;
    } else {
        token                          = strdup(ep_str);
        rank                           = strtok(token, ":");
        jobid                          = strtok(NULL, ":");
        con_info->rank                 = atoi(rank);
        con_info->rrcomm.jobid         = atoll(jobid);
        sockid                         = strtok(NULL, ":@");
        con_info->rrcomm.remote_sockid = atoi(sockid);
        name                           = strtok(NULL, "@");
        memset(con_info->name, 0, sizeof(con_info->name));
        strncpy(con_info->name, name, sizeof(con_info->name));
    }

    return PSCOM_SUCCESS;
}


/**
 * @brief Check whether this is a loopback connection
 *
 * Local and destination job ID must be the same as well as
 * local and destination rank to be a loopback connection.
 * Otherwise, it will be a connection between two different pairs.
 *
 * @param [in] socket     socket pointer
 * @param [in] connection connection pointer
 *
 * @return 1 if the connection is loopback
 * @return 0 if the connection is not loopback
 */
static int pscom_is_connect_loopback_rrc(pscom_socket_t *socket,
                                         pscom_connection_t *connection)
{
    pscom_sock_t *sock      = get_sock(socket);
    int local_rank          = sock->pub.local_con_info.rank;
    int dest_rank           = connection->remote_con_info.rank;
    PStask_ID_t local_jobid = RRC_getJobID();
    PStask_ID_t dest_jobid  = connection->remote_con_info.rrcomm.jobid;
    return ((local_jobid == dest_jobid) && (local_rank == dest_rank));
}


static int pscom_precon_guard_setup_rrc(pscom_precon_t *precon)
{
    return 0;
}


static void pscom_listener_user_inc_rrc(struct pscom_listener *listener)
{
}


static void pscom_listener_user_dec_rrc(struct pscom_listener *listener)
{
}


pscom_precon_provider_t pscom_provider_rrc = {
    .precon_type             = PSCOM_PRECON_TYPE_RRCOMM,
    .init                    = pscom_precon_provider_init_rrc,
    .destroy                 = pscom_precon_provider_destroy_rrc,
    .send                    = pscom_precon_send_rrc,
    .create                  = pscom_precon_create_rrc,
    .cleanup                 = pscom_precon_cleanup_rrc,
    .recv_start              = pscom_precon_recv_start_rrc,
    .recv_stop               = pscom_precon_recv_stop_rrc,
    .connect                 = pscom_precon_connect_rrc,
    .guard_setup             = pscom_precon_guard_setup_rrc,
    .get_ep_info_from_socket = pscom_get_ep_info_from_socket_rrc,
    .parse_ep_info           = pscom_parse_ep_info_rrc,
    .is_connect_loopback     = pscom_is_connect_loopback_rrc,
    .start_listen            = pscom_sock_start_listen_rrc,
    .stop_listen             = pscom_sock_stop_listen_rrc,
    .ondemand_backconnect    = pscom_precon_ondemand_backconnect_rrc,
    .listener_suspend        = pscom_listener_suspend_rrc,
    .listener_resume         = pscom_listener_resume_rrc,
    .listener_active_inc     = pscom_listener_active_inc_rrc,
    .listener_active_dec     = pscom_listener_active_dec_rrc,
    .listener_user_inc       = pscom_listener_user_inc_rrc,
    .listener_user_dec       = pscom_listener_user_dec_rrc,
};
