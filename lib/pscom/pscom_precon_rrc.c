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
#include <assert.h>         // for assert
#include <errno.h>          // for errno, ENOPROTOOPT, EPROTO
#include <poll.h>           // for POLLIN, pollfd, POLLOUT
#include <stdint.h>         // for uint32_t
#include <stdio.h>          // for snprintf, sprintf
#include <string.h>         // for memset, strtok, memcpy, strcpy, strdup
#include <sys/types.h>      // for u_int32_t
#include <unistd.h>         // for _exit
#include "list.h"           // for list_empty, list_add_tail, list_entry, lis...
#include "pscom.h"          // for PSCOM_con_info::(anonymous union)::(anonym...
#include "pscom_con.h"      // for pscom_con_setup_failed, pscom_con_create
#include "pscom_env.h"      // for PSCOM_env
#include "pscom_plugin.h"   // for pscom_plugin_by_archid, pscom_plugin_t
#include "pscom_precon.h"   // for pscom_global_rrc_t, pscom_precon_provider
#include "pscom_priv.h"     // for pscom, get_sock, pscom_sock_t, pscom_con_t
#include "pscom_str_util.h" // for INET_ADDR_FORMAT
#include "pscom_ufd.h"      // for ufd_event_clr, ufd_event_set, ufd_add, ufd...
#include <stdlib.h>         // for malloc, free, atoi, atoll
#include "pscom_debug.h"    // for DPRINT, D_PRECON_TRACE, D_ERR, D_DBG_V
#include "rrcomm.h"         // for RRC_getJobID, RRC_finalize, RRC_init, RRC_...
#include <limits.h>

/**< Maximum endpoint information size */
#define MAX_EP_STR_SIZE 50

/**< Number of pending resend requests */
int resend_count;
/**< list  of pending resend requests */
struct list_head resend_requests;

/**< Maximum packet size (gets increased automatically if necessary) */
static ssize_t max_buf_size = 1000;


pscom_env_table_entry_t pscom_env_table_precon_rrc[] = {
    {"RESEND_TIMES", "10000",
     "Maximum number of resend retries after receiving a resend signal from "
     "RRComm. 0 means infinite times of retries.",
     &pscom.env.rrc_resend_times, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_ENV_PARSER_UINT},

    {"RESEND_DELAY", "100000",
     "Delay time before the first resend retry in microseconds after receiving "
     "a resend signal from RRComm. Default is 100000 us (0.1 s).",
     &pscom.env.rrc_resend_delay, PSCOM_ENV_ENTRY_FLAGS_EMPTY,
     PSCOM_ENV_PARSER_UINT},

    {0},
};


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
    memset(precon, 0, precon_size);

    pscom_precon_rrc_t *pre_rrc = (pscom_precon_rrc_t *)&precon->precon_data;
    precon->magic               = MAGIC_PRECON;
    pre_rrc->remote_con         = NULL;

    pre_rrc->con          = con;
    pre_rrc->recv_done    = 0;
    pre_rrc->precon       = precon;
    pre_rrc->local_jobid  = RRC_getJobID();
    pre_rrc->info_sent    = 0;
    pre_rrc->resend_times = pscom.env.rrc_resend_times;

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
        (pscom_global_rrc_t *)pscom_precon_provider->precon_provider_data;

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
           pscom_precon_provider->precon_count, state);
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
            /* recv is done, disallow precon usage in handshake */
            pre_rrc->con->precon = NULL;
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
static pscom_err_t pscom_precon_send_rrc(pscom_precon_t *precon, unsigned type,
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
    ssize_t msg_size = (ssize_t)(size + sizeof(pscom_info_rrc_t));
    /* all sent messages should be smaller than the max recv buffer size */
    if (msg_size > max_buf_size) { max_buf_size = msg_size + 1; }

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

    ssize_t len = RRC_sendX(pre_rrc->remote_jobid, dest, send, msg_size);

    free(send);

    /* Error when sending the message? */
    if (len < 0) {
        /* Message could not be sent when len <0 */
        DPRINT(D_ERR,
               "RRC_sendX returns with %zd and sends msg with length %zd to "
               "%ld, %d (jobid, dest).\n",
               len, msg_size, pre_rrc->remote_jobid, dest);
        goto err_send;
    }

    /* On success, all bytes must have been sent. */
    assert(len == msg_size);

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

    /* Do not use plugin anymore after PSCOM_INFO_ARCH_NEXT */
    pre_rrc->precon->plugin = NULL;
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
    assert(con);
    assert(con->magic == MAGIC_CONNECTION);
    pscom_precon_t *precon = con->precon;
    assert(precon->magic == MAGIC_PRECON);
    pscom_info_con_info_version_t msg_con_info_version;

    /* Send supported versions */
    msg_con_info_version.version.ver_from = VER_FROM;
    msg_con_info_version.version.ver_to   = VER_TO;

    /* Send connection information */
    pscom_con_info(con, &msg_con_info_version.con_info);
    msg_con_info_version.source_sockid                 = local_sockid;
    msg_con_info_version.con_info.rrcomm.remote_sockid = remote_sockid;

    DPRINT(D_PRECON_TRACE, "precon(%p): con:%s", precon,
           pscom_con_str(&con->pub));
    pscom_err_t ret = pscom_precon_send(precon, type, &msg_con_info_version,
                                        sizeof(msg_con_info_version));
    assert(ret == PSCOM_SUCCESS);
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
    assert(con);
    assert(con->magic == MAGIC_CONNECTION);
    pscom_sock_t *sock = get_sock(con->pub.socket);
    assert(precon->magic == MAGIC_PRECON);

    /* Send supported versions */
    msg_con_info_version.version.ver_from = VER_FROM;
    msg_con_info_version.version.ver_to   = VER_TO;

    /* Send connection information */
    pscom_con_info(con, &msg_con_info_version.con_info);
    msg_con_info_version.source_sockid = sock->id;
    msg_con_info_version.con_info.rrcomm.remote_sockid =
        con->pub.remote_con_info.rrcomm.remote_sockid;

    DPRINT(D_PRECON_TRACE, "precon(%p): con:%s", precon,
           pscom_con_str(&con->pub));
    pscom_err_t ret = pscom_precon_send(precon, type, &msg_con_info_version,
                                        sizeof(msg_con_info_version));
    assert(ret == PSCOM_SUCCESS);
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
    uint32_t local_sockid;
    pscom_info_con_info_version_t *msg = NULL;

    /* Obtain socket when there is no connection yet */
    if (!con) {
        msg = data;
        assert(msg);
        con_info     = &msg->con_info;
        /* the received remote sockid is the sockid at the recv side. */
        local_sockid = msg->con_info.rrcomm.remote_sockid;

        struct list_head *pos;
        list_for_each (pos, &pscom.sockets) {
            pscom_sock_t *temp_sock = list_entry(pos, pscom_sock_t, next);
            if (temp_sock->id == local_sockid) {
                sock = temp_sock;
                break;
            }
        }
    } else {
        /* get socket from con */
        sock = get_sock(con->pub.socket);
    }
    /* ensure that we have found one sock */
    assert(sock);

    assert(!con || con->magic == MAGIC_CONNECTION);
    switch (type) {
    case PSCOM_INFO_CON_INFO_VERSION: {
        msg                           = data;
        pscom_info_version_t *version = &msg->version;
        remote_sockid                 = msg->source_sockid;
        local_sockid                  = msg->con_info.rrcomm.remote_sockid;

        assert(size == sizeof(*msg));
        pscom_check_VERSION(version, con);

        if (!con) { /* Accepting side of the connection */
            con                            = pscom_con_create(sock);
            /* until the user gets a handle to con (via con->on_accept) */
            con->state.internal_connection = 1;
            con->pub.state                 = PSCOM_CON_STATE_ACCEPTING;
            con->pub.remote_con_info       = msg->con_info;

            pscom_precon_t *precon = pscom_precon_create(con);
            con->precon            = precon;
            pre_rrc                = (pscom_precon_rrc_t *)&precon->precon_data;

            pre_rrc->remote_con   = rrcomm->source_con;
            pre_rrc->remote_jobid = jobid;

            pscom_precon_recv_start(pre_rrc->precon);

            pscom_precon_send_PSCOM_INFO_CON_INFO_VERSION_rrc(
                con, PSCOM_INFO_CON_INFO_VERSION, local_sockid, remote_sockid);
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

        /* Search for an existing matching connection */
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
        remote_sockid                 = msg->source_sockid;
        local_sockid                  = msg->con_info.rrcomm.remote_sockid;

        assert(size == sizeof(*msg));
        pscom_check_VERSION(version, con);

        /* Search for the existing matching connection */
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
                    con, PSCOM_INFO_CON_INFO_VERSION, local_sockid,
                    remote_sockid);
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
            /* Unknown or disabled arch or con_init fail. Try next arch. */
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
                /* Failed locally before. Handle OK like an ARCH_NEXT */
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
 * @brief Enqueue a resend request when sending fails
 *
 * This function will enqueue a resend request when a resend signal is
 * obtained due to the destination is not ready yet. If so the message will be
 * resent in `do_write` after the specified delay.
 *
 * @param [in] jobid   current job ID of the process
 * @param [in] dest    destination to resend the message
 */
static int pscom_enqueue_message(int dest, PStask_ID_t jobid)
{
    pscom_global_rrc_t *global_rrc =
        (pscom_global_rrc_t *)pscom_precon_provider->precon_provider_data;

    struct list_head *pos;
    /* Obtain the precon associated to this resend signal */
    list_for_each (pos, &pscom_precon_provider->precon_list) {
        pscom_precon_t *precon = list_entry(pos, pscom_precon_t, next);
        pscom_precon_rrc_t *pre_rrc = (pscom_precon_rrc_t *)&precon->precon_data;
        pscom_con_t *con = pre_rrc->con;
        assert(con);

        if (con->pub.remote_con_info.rank == dest &&
            con->pub.remote_con_info.rrcomm.jobid == (uint64_t)jobid) {
            /* Still more retries? */
            if (!pscom.env.rrc_resend_times || pre_rrc->resend_times) {
                /* create a resend req for this precon */
                pscom_resend_request_t *resend = (pscom_resend_request_t *)
                    malloc(sizeof(pscom_resend_request_t));
                assert(resend);
                /* get the start time stamp */
                gettimeofday(&resend->start_time, NULL);
                resend->jobid    = jobid;
                resend->dest     = dest;
                resend->msg_type = pre_rrc->msg_type;
                resend->precon   = precon;

                /* Append it to the list of resends */
                INIT_LIST_HEAD(&resend->next);
                assert(list_empty(&resend->next));

                list_add_tail(&resend->next, &resend_requests);
                resend_count++;

                /* Set POLLOUT event until all resends have been finished */
                ufd_event_set(&pscom.ufd, &global_rrc->ufd_info, POLLOUT);
                return PSCOM_SUCCESS;
            } else {
                DPRINT(D_ERR, "RRC resend (%ld,%d): maximum retries reached\n",
                       jobid, dest);
                return PSCOM_ERR_STDERROR;
            }
        }
    }
    DPRINT(D_ERR, "RRC resend (%ld,%d): precon is not found for the resend \n",
           jobid, dest);
    return PSCOM_ERR_STDERROR;
}


/**
 * @brief Resend a message when obtaining a resend signal
 *
 * This function will resend a message when we obtain a
 * resend signal after the specified delay.
 *
 * @param [in] ufd       ufd pointer
 * @param [in] ufd_info  ufd_info pointer
 */
static void pscom_precon_do_write_rrc(ufd_t *ufd, ufd_funcinfo_t *ufd_info)
{
    pscom_global_rrc_t *global_rrc =
        (pscom_global_rrc_t *)pscom_precon_provider->precon_provider_data;

    struct list_head *pos, *next;

    /* only one thread is allowed to do the resend */
    list_for_each_safe (pos, next, &resend_requests) {
        pscom_resend_request_t *resend = list_entry(pos, pscom_resend_request_t,
                                                    next);

        /* get current timestamp */
        struct timeval time;
        gettimeofday(&time, NULL);

        /* resend signal timestamp */
        double st = (double)resend->start_time.tv_sec +
                    (double)resend->start_time.tv_usec / 1e6;
        /* Current timestamp */
        double ct = (double)time.tv_sec + (double)time.tv_usec / 1e6;

        /* Delay threshold reached? */
        if (ct - st > (double)(pscom.env.rrc_resend_delay / 1e6)) {
            pscom_precon_t *precon = resend->precon;
            assert(precon->magic == MAGIC_PRECON);

            pscom_precon_rrc_t *pre_rrc = (pscom_precon_rrc_t *)
                                              resend->precon->precon_data;


            if (pre_rrc->msg_type == PSCOM_INFO_CON_INFO_VERSION ||
                pre_rrc->msg_type == PSCOM_INFO_CON_INFO_VERSION_DEMAND) {
                /* Resend the INFO_VERSION message */
                assert(pre_rrc->resend_times || !pscom.env.rrc_resend_times);
                pre_rrc->resend_times--;
                pscom_con_t *con = pre_rrc->con;
                assert(con);
                pscom_sock_t *sock = get_sock(con->pub.socket);

                DPRINT(D_ERR, "resend message to %d, %ld, type %s\n",
                       resend->dest, resend->jobid,
                       pscom_info_type_str(resend->msg_type));

                pscom_precon_send_PSCOM_INFO_CON_INFO_VERSION_rrc(
                    con, pre_rrc->msg_type, sock->id,
                    con->pub.remote_con_info.rrcomm.remote_sockid);

            } else if (pre_rrc->msg_type == PSCOM_INFO_BACK_CONNECT) {
                /* Resend the BACK_CONNECT message */
                assert(pre_rrc->resend_times || !pscom.env.rrc_resend_times);
                pre_rrc->resend_times--;

                DPRINT(D_ERR,
                       "resend message to %d, %ld, type %s, send done %d\n",
                       resend->dest, resend->jobid,
                       pscom_info_type_str(resend->msg_type),
                       pre_rrc->info_sent);

                /* due to the delay, the con_info may be already sent to the
                 * target, then the sending back_connect and con_info is not
                 * needed. */
                if (!pre_rrc->info_sent) {
                    pscom_precon_send_PSCOM_INFO_CON_INFO_rrc(
                        precon, pre_rrc->con, PSCOM_INFO_BACK_CONNECT);
                }
            }

            /* Remove this resend from the list as it has been already resent */
            list_del(&resend->next);
            resend_count--;
            free(resend);
        }
    }

    /* Stop POLLOUT once there are no more pending resends */
    if (list_empty(&resend_requests)) {
        assert(resend_count == 0);
        ufd_event_clr(&pscom.ufd, &global_rrc->ufd_info, POLLOUT);
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
    /* the messages sent and received should not be larger than max_buf_size.
     * The payload information (libverbs, ucx, portals4) may excceed this limit
     */
    char *recv = (char *)malloc(max_buf_size);
    assert(recv);

    /* Read the package and store it in recv buffer */
    ssize_t len = RRC_recvX(&jobid, &rank, recv, max_buf_size);

    /* the buffer is smaller than the message, len is the actual message size
     * and RRComm will keep the message*/
    while (len > max_buf_size) {
        /* change the max_buf_size */
        max_buf_size = len + 1;
        recv         = (char *)realloc(recv, max_buf_size);
        assert(recv);
        /* RRC_recvX() shall be called again with an adapted buffer size to
         * actually receive the message. */
        len = RRC_recvX(&jobid, &rank, recv, max_buf_size);
    }

    /* Handle a resend signal or a possible error */
    if (len < 0) {
        /* This is a resend signal with errno=0, then resend the message */
        if (!errno) {
            /* enqueue resend request and start resending with a delay */
            DPRINT(D_ERR, "RRC_sendX(%d) with job %ld failed. Resending it!\n",
                   rank, (int64_t)jobid);
            int ret = pscom_enqueue_message(rank, jobid);
            if (ret == PSCOM_SUCCESS) {
                return;
            } else {
                DPRINT(D_ERR, "RRC_recvX(%ld, %d): resend failed!\n", jobid,
                       rank);
                _exit(-1);
            }
        } else {
            /* Print error and exit */
            DPRINT(D_ERR, "RRC_recvX(%ld,%d) failed with error: %s\n", jobid,
                   rank, strerror(errno));
            _exit(112);
        }
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
        (pscom_global_rrc_t *)pscom_precon_provider->precon_provider_data;

    global_rrc->ufd_info.fd        = global_rrc->rrcomm_fd;
    global_rrc->ufd_info.can_read  = pscom_precon_do_read_rrc;
    global_rrc->ufd_info.can_write = pscom_precon_do_write_rrc;

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
            pre_rrc->msg_type       = PSCOM_INFO_CON_INFO_VERSION_DEMAND;
            pre_rrc->con->pub.state = PSCOM_CON_STATE_CONNECTING_ONDEMAND;
        } else {
            pre_rrc->msg_type       = PSCOM_INFO_CON_INFO_VERSION;
            pre_rrc->con->pub.state = PSCOM_CON_STATE_CONNECTING;
        }

        pre_rrc->remote_jobid = jobid;
        pre_rrc->remote_con   = NULL;
        pscom_precon_send_PSCOM_INFO_CON_INFO_VERSION_rrc(pre_rrc->con,
                                                          pre_rrc->msg_type,
                                                          local_sockid,
                                                          remote_sockid);
    }
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

    pre_rrc->msg_type     = PSCOM_INFO_BACK_CONNECT;
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

err_connect:
    if (errno != ENOPROTOOPT) {
        /* if (errno == ENOPROTOOPT) _plugin_connect_next() already called
         * pscom_con_setup_failed(). */
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

    pscom_env_table_register_and_parse("pscom PRECON_RRCOMM", "PRECON_RRCOMM_",
                                       pscom_env_table_precon_rrc);

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

    /* Init resend */
    resend_count = 0;
    INIT_LIST_HEAD(&resend_requests);

    /* Assign memory for RRcomm sock variables */
    pscom_precon_provider->precon_provider_data = (void *)malloc(
        sizeof(pscom_global_rrc_t));
    assert(pscom_precon_provider->precon_provider_data);
    global_rrc = (pscom_global_rrc_t *)
                     pscom_precon_provider->precon_provider_data;
    memset(global_rrc, 0, sizeof(pscom_global_rrc_t));

    /* Assign RRcomm file descriptor */
    global_rrc->rrcomm_fd = fd;
    /* Initialize user counter of listener */
    global_rrc->user_cnt  = 0;
    /* Initialize listener counter */
    global_rrc->active    = 0;
    /* Assign RRcomm file descriptor */
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
        (pscom_global_rrc_t *)pscom_precon_provider->precon_provider_data;

    /* check if precon_list is empty */
    if (!list_empty(&pscom_precon_provider->precon_list)) {
        struct list_head *pos, *next;
        /* Obtain the precon associated to this resend signal */
        list_for_each_safe (pos, next, &pscom_precon_provider->precon_list) {
            pscom_precon_t *precon = list_entry(pos, pscom_precon_t, next);
            pscom_precon_rrc_t *pre_rrc =
                (pscom_precon_rrc_t *)&precon->precon_data;
            DPRINT(D_ERR,
                   "precon(%p): local jobid %ld, remote jobid %ld, user_cnt:%d "
                   "active_cnt:%d recv done?:%s precon "
                   "count:%u \n",
                   pre_rrc, pre_rrc->local_jobid, pre_rrc->remote_jobid,
                   global_rrc->user_cnt, global_rrc->active,
                   pre_rrc->recv_done ? "yes" : "no",
                   pscom_precon_provider->precon_count);
            /* Remove precon from the list */
            assert(precon->magic == MAGIC_PRECON);
            pscom_precon_provider->cleanup(precon);
            list_del_init(&precon->next);
            pscom_precon_provider->precon_count--;
            // free space
            free(precon);
        }
    }
    assert(list_empty(&pscom_precon_provider->precon_list));
    assert(!pscom_precon_provider->precon_count);

    /* Ensure that connection and listener counters are 0 */
    assert(!global_rrc->user_cnt);

    /* Delete RRcomm ufd_info */
    ufd_del(&pscom.ufd, &global_rrc->ufd_info);
    /* Destroy sock rrcomm struct */
    free(global_rrc);

    /* finalize RRcomm for this socket */
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
        (pscom_global_rrc_t *)pscom_precon_provider->precon_provider_data;

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
        (pscom_global_rrc_t *)pscom_precon_provider->precon_provider_data;
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
        (pscom_global_rrc_t *)pscom_precon_provider->precon_provider_data;

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
        (pscom_global_rrc_t *)pscom_precon_provider->precon_provider_data;

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
        (pscom_global_rrc_t *)pscom_precon_provider->precon_provider_data;

    /* Avoid error in `_pscom_con_connect_ondemand` to check portno */
    sock->pub.listen_portno                       = 0;
    sock->pub.local_con_info.rrcomm.jobid         = RRC_getJobID();
    sock->pub.local_con_info.rrcomm.remote_sockid = 0;

    /* Start receiver */
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
        (pscom_global_rrc_t *)pscom_precon_provider->precon_provider_data;

    /* this will be called when sock is closed, active may already be 0 */
    if (global_rrc->active == 0) { return; }

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
        snprintf(ep_str_rrc, MAX_EP_STR_SIZE, "%d:%ld:%d:%s",
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
    char dup_ep_str[MAX_EP_STR_SIZE + 1];
    char *endptr;
    long val;

    if (!ep_str) {
        con_info->rrcomm.jobid = RRC_getJobID();
        memset(con_info->name, 0, sizeof(con_info->name));
        sprintf(dest_name, "r%07d", con_info->rank);
        memcpy(con_info->name, dest_name, sizeof(dest_name));
        con_info->rrcomm.remote_sockid = 0;
    } else {
        strncpy(dup_ep_str, ep_str, sizeof(dup_ep_str));
        dup_ep_str[sizeof(dup_ep_str) - 1] = '\0';

        char *p     = dup_ep_str;
        /* rank */
        char *colon = strchr(p, ':');
        if (!colon) {
            DPRINT(D_ERR, "ep_str format error, missing rank.");
            goto err_invalid_ep_str;
        }
        if (colon == p) {
            DPRINT(D_ERR, "ep_str format error, rank information empty.");
            goto err_invalid_ep_str;
        }
        /* temp cut*/
        *colon = '\0';

        errno = 0;
        val   = strtol(p, &endptr, 10);
        if (errno != 0 || *endptr != '\0') {
            DPRINT(D_ERR, "rank information error:%d, %s", (int)val, p);
            goto err_invalid_ep_str;
        }
        if (val < 0 || val > INT_MAX) {
            DPRINT(D_ERR, "rank invalid value:%d, %s", (int)val, p);
            goto err_invalid_ep_str;
        }
        con_info->rank = (int)val;

        /* move to next segment */
        p = colon + 1;

        /* jobid */
        colon = strchr(p, ':');
        if (!colon) {
            DPRINT(D_ERR, "ep_str format error, missing jobid.");
            goto err_invalid_ep_str;
        }
        if (colon == p) {
            DPRINT(D_ERR, "ep_str format error, jobid information empty.");
            goto err_invalid_ep_str;
        }
        /* temp cut*/
        *colon = '\0';

        errno = 0;
        val   = strtol(p, &endptr, 10);
        if (errno != 0 || *endptr != '\0') {
            DPRINT(D_ERR, "jobid information error:%d, %s", (int)val, p);
            goto err_invalid_ep_str;
        }
        con_info->rrcomm.jobid = (uint64_t)val;

        /* move to next segment */
        p = colon + 1;

        /* sockid */
        colon = strchr(p, ':');
        if (!colon) {
            DPRINT(D_ERR, "ep_str format error, missing sockid.");
            goto err_invalid_ep_str;
        }
        if (colon == p) {
            DPRINT(D_ERR, "ep_str format error, sockid information empty.");
            goto err_invalid_ep_str;
        }
        /* temp cut*/
        *colon = '\0';
        errno  = 0;
        val    = strtol(p, &endptr, 10);
        if (errno != 0 || *endptr != '\0') {
            DPRINT(D_ERR, "sockid error:%d, %s", (int)val, p);
            goto err_invalid_ep_str;
        }
        if (val < 0 || val > INT_MAX) {
            DPRINT(D_ERR, "sockid invalid value:%d, %s", (int)val, p);
            goto err_invalid_ep_str;
        }
        con_info->rrcomm.remote_sockid = (uint32_t)val;

        /* move to next segment */
        p = colon + 1;

        /* name */
        char *name = p;
        if (*name == '\0') {
            DPRINT(D_ERR, "ep_str format error, missing name.");
            goto err_invalid_ep_str;
        }

        memset(con_info->name, 0, sizeof(con_info->name));
        strncpy(con_info->name, name, sizeof(con_info->name));
    }

    return PSCOM_SUCCESS;

err_invalid_ep_str:
    errno = EINVAL;
    return PSCOM_ERR_STDERROR;
}


static char *pscom_get_con_info_str_rrc(pscom_con_info_t *con_info)
{
    static char buf[sizeof("(xxx.xxx.xxx.xxx, jobid xxxxxxxxxxxxxxxxxxxx, "
                           "rxxxxxxxxxx, sockid xxxxxxxxxx,0xxxxxxxxxxxxxxxxx,"
                           "xxxxxxxx____)")];

    snprintf(buf, sizeof(buf),
             "(" INET_ADDR_FORMAT ",jobid %lu, r%d, "
             "sockid %u,%p,%.8s)",
             INET_ADDR_SPLIT(con_info->node_id), con_info->rrcomm.jobid,
             con_info->rank, con_info->rrcomm.remote_sockid, con_info->id,
             con_info->name);

    return buf;
}


static char *pscom_get_con_info_str2_rrc(pscom_con_info_t *con_info1,
                                         pscom_con_info_t *con_info2)
{
    static char buf[sizeof("(xxx.xxx.xxx.xxx, jobid xxxxxxxxxxxxxxxxxxxx, "
                           "rxxxxxxxxxx, sockid xxxxxxxxxx,0xxxxxxxxxxxxxxxxx,"
                           "xxxxxxxx_____) to "
                           "(xxx.xxx.xxx.xxx, jobid xxxxxxxxxxxxxxxxxxxx, "
                           "rxxxxxxxxxx, sockid xxxxxxxxxx,0xxxxxxxxxxxxxxxxx,"
                           "xxxxxxxx_____)")];

    snprintf(buf, sizeof(buf),
             "(" INET_ADDR_FORMAT ",jobid %lu, r%d, sockid %u,%p,%.8s) to "
             "(" INET_ADDR_FORMAT ",jobid %lu, r%d, "
             "sockid %u,%p,"
             "%.8s)",
             INET_ADDR_SPLIT(con_info1->node_id), con_info1->rrcomm.jobid,
             con_info1->rank, con_info1->rrcomm.remote_sockid, con_info1->id,
             con_info1->name, INET_ADDR_SPLIT(con_info2->node_id),
             con_info2->rrcomm.jobid, con_info2->rank,
             con_info2->rrcomm.remote_sockid, con_info2->id, con_info2->name);

    return buf;
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


static void pscom_precon_sock_init_rrc(pscom_sock_t *sock)
{
    /* TODO: Currently, TCP is not supported as payload when RRComm is used. */
    pscom_con_type_mask_del(&sock->pub, PSCOM_CON_TYPE_TCP);
}


/*
 * In RRComm, the plugin handshake is started by the accepting side.
 * It has to wait for the connection information from the connecting side and
 * then decides whether `shm` will be used and starts the handshaking of plugin
 * information.
 */
int pscom_precon_is_starting_peer_rrc(pscom_con_t *con)
{
    return !precon_con_is_connecting_peer(con);
}


pscom_precon_provider_t pscom_provider_rrc = {
    .init                    = pscom_precon_provider_init_rrc,
    .destroy                 = pscom_precon_provider_destroy_rrc,
    .send                    = pscom_precon_send_rrc,
    .create                  = pscom_precon_create_rrc,
    .cleanup                 = pscom_precon_cleanup_rrc,
    .recv_start              = pscom_precon_recv_start_rrc,
    .recv_stop               = pscom_precon_recv_stop_rrc,
    .connect                 = pscom_precon_connect_rrc,
    .sock_init               = pscom_precon_sock_init_rrc,
    .guard_setup             = pscom_precon_guard_setup_rrc,
    .is_starting_peer        = pscom_precon_is_starting_peer_rrc,
    .get_ep_info_from_socket = pscom_get_ep_info_from_socket_rrc,
    .parse_ep_info           = pscom_parse_ep_info_rrc,
    .get_con_info_str        = pscom_get_con_info_str_rrc,
    .get_con_info_str2       = pscom_get_con_info_str2_rrc,
    .is_connect_loopback     = pscom_is_connect_loopback_rrc,
    .start_listen            = pscom_sock_start_listen_rrc,
    .stop_listen             = pscom_sock_stop_listen_rrc,
    .ondemand_backconnect    = pscom_precon_ondemand_backconnect_rrc,
    .suspend_listen          = pscom_sock_stop_listen_rrc,
    .resume_listen           = pscom_sock_start_listen_rrc,
    .listener_active_inc     = pscom_listener_active_inc_rrc,
    .listener_active_dec     = pscom_listener_active_dec_rrc,
};
