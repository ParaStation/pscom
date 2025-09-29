/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "pscom_sock.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "list.h"
#include "pscom.h"
#include "pscom_con.h"
#include "pscom_debug.h"
#include "pscom_env.h"
#include "pscom_io.h"
#include "pscom_plugin.h"
#include "pscom_priv.h"
#include "pscom_util.h"
#include "pslib.h"
#include "pscom_precon.h"
#include "pscom_precon_tcp.h"

static int32_t inter_sockid = 1;
static int32_t intra_sockid = 0;


static void _pscom_sock_terminate_all_recvs(pscom_sock_t *sock)
{
    struct list_head *pos;

    assert(sock->magic == MAGIC_SOCKET);

    // Recvq's of all connections
    list_for_each (pos, &sock->connections) {
        pscom_con_t *con = list_entry(pos, pscom_con_t, next);

        pscom_con_terminate_recvq(con);
    }


    // Socket RecvAny Queue: (the global any-source queue is terminated in
    // pscom_cleanup())
    while (!list_empty(&sock->recvq_any)) {
        pscom_req_t *req = list_entry(sock->recvq_any.next, pscom_req_t, next);

        list_del(&req->next);
        req->pub.state |= PSCOM_REQ_STATE_ERROR;
        _pscom_recv_req_done(req); // done
    }
}


void pscom_sock_close(pscom_sock_t *sock)
{
    struct list_head *pos, *next;
    int retry_cnt                      = 0;
    unsigned long last_progress_time   = pscom_wtime_sec();
    unsigned long last_stalled_con_cnt = (unsigned long)-1;

    sock->state.close_called = 1;

retry:
    assert(sock->magic == MAGIC_SOCKET);

    // Call close on every connections
    list_for_each_safe (pos, next, &sock->connections) {
        pscom_con_t *con = list_entry(pos, pscom_con_t, next);
        pscom_con_close(con);
    }

    pscom_precon_provider.stop_listen(sock);
    // todo: listen_portno is forced to set to 1, if not, for rrcomm there will
    // be a retry dead loop.
    sock->pub.listen_portno = -1;

    // Wait until all connections are closed. If there is no progress made
    // on any conncetion within the given timeout of PSP_SHUTDOWN_TIMEOUT
    // seconds (e.g., because one or more of the other sides do not react)
    // while loop and function are aborted.
    while (1) {
        unsigned long stalled_con_cnt = 0;
        list_for_each_safe (pos, next, &sock->connections) {
            pscom_con_t *con = list_entry(pos, pscom_con_t, next);
            assert(con->magic == MAGIC_CONNECTION);
            if (con->pub.state != PSCOM_CON_STATE_CLOSED) { stalled_con_cnt++; }
        }

        if (!stalled_con_cnt) { break; }

        // Proceed
        pscom_call_io_done();
        pscom_progress(0);

        if (stalled_con_cnt < last_stalled_con_cnt) {
            // Progress! Reset timer and continue:
            last_stalled_con_cnt = stalled_con_cnt;
            last_progress_time   = pscom_wtime_sec();
            continue;
        }

        if (pscom.env.shutdown_timeout &&
            (pscom_wtime_sec() - last_progress_time >
             pscom.env.shutdown_timeout)) {
            goto fn_timeout;
        }
    }

    _pscom_sock_terminate_all_recvs(sock);

    pscom_call_io_done();

    if (!list_empty(&sock->connections) || !list_empty(&sock->recvq_any) ||
        sock->pub.listen_portno != -1) {
        retry_cnt++;

        DPRINT(D_DBG, "pscom_sock_close() retry loop (cnt=%u)!", retry_cnt);

        if (retry_cnt >= 10) { sleep(1); }

        if (pscom.env.shutdown_timeout &&
            (pscom_wtime_sec() - last_progress_time >
             pscom.env.shutdown_timeout)) {
            goto fn_timeout;
        }

        goto retry; // in the case the io_doneq callbacks post more work
    }

fn_exit:
    if (!list_empty(&sock->next)) { list_del_init(&sock->next); }

    return;

fn_timeout:
    DPRINT(D_ERR, "pscom_sock_close() forced closing of all connections "
                  "failed.");
    sock->state.close_timeout = 1;
    goto fn_exit;
}


PSCOM_PLUGIN_API_EXPORT
void pscom_sock_set_name(pscom_sock_t *sock, const char *name)
{
    memset(sock->pub.local_con_info.name, 0,
           sizeof(sock->pub.local_con_info.name));
    strncpy(sock->pub.local_con_info.name, name,
            sizeof(sock->pub.local_con_info.name));
    pscom_info_set("socket", pscom_con_info_str(&sock->pub.local_con_info));
}


static void pscom_sock_init_con_info(pscom_sock_t *sock, int local_rank)
{
    pscom_con_info_t *con_info = &sock->pub.local_con_info;
    char name[sizeof(con_info->name) + 1];

    con_info->node_id = pscom_get_nodeid();
    /* use the rank from process manager, rank could be -1
     * (PSCOM_RANK_UNDEFINED). The valid rank should be equal to the rank from
     * rrcomm when rrcomm is used as the precon protocol */
    con_info->rank    = local_rank;
    con_info->id      = NULL;

    /* set the name with pid, format "p+pid", name will be overwritten if user
     * calls pscom_socket_set_name */
    snprintf(name, sizeof(name), "p%d", getpid());
    pscom_sock_set_name(sock, name);
}


/**
 * @brief Thread safe sock ID increase
 *
 * Safely increase sock->id with unique ID.
 *
 * For now, we allow one intra socket only
 * because in the RRcomm implementation multiple
 * intra-job sockets might cause issues due to the
 * local connection not knowing which socket the
 * remote connection belongs to at the peer side.
 *
 * @param [in]  sock   sock pointer
 */
static int pscom_sock_set_id(pscom_sock_t *sock)
{
    pscom_lock();

    /* sock type is exclusive, either INTER_JOB or INTRA_JOB */
    int intra_job = sock->sock_flags & PSCOM_SOCK_FLAG_INTRA_JOB;
    int inter_job = sock->sock_flags & PSCOM_SOCK_FLAG_INTER_JOB;
    int ret       = PSCOM_SUCCESS;

    if (inter_job && !intra_job) {
        // Allow multiple inter-sockets
        sock->id = inter_sockid++;
    } else if (intra_job && !inter_job) {
        sock->id = intra_sockid++;
        // Allow only one intra-socket, and its id will be 0
        if (sock->id) {
            ret = PSCOM_ERR_STDERROR;
            DPRINT(D_BUG, "More than one intra job has been created. %s",
                   pscom_err_str(ret));
        }
    } else {
        ret = PSCOM_ERR_INVALID;
        DPRINT(D_BUG, "the flag for socket type is not set correctly. %s",
               pscom_err_str(ret));
    }

    pscom_unlock();

    return ret;
}


void pscom_sock_unset_id(pscom_sock_t *sock)
{
    /* release the only intra job socket, reset intra_sockid to 0 */
    if (sock->sock_flags & PSCOM_SOCK_FLAG_INTRA_JOB) {
        intra_sockid--;
        assert(intra_sockid == 0);
    }
}


PSCOM_PLUGIN_API_EXPORT
pscom_sock_t *pscom_sock_create(size_t userdata_size,
                                size_t connection_userdata_size, int local_rank,
                                uint64_t socket_flags)
{
    int ret = PSCOM_SUCCESS;
    pscom_sock_t *sock;
    sock = malloc(sizeof(*sock) + userdata_size);
    if (!sock) { goto err_out; }

    sock->magic                = MAGIC_SOCKET;
    sock->pub.ops.con_accept   = NULL;
    sock->pub.ops.con_error    = NULL;
    sock->pub.ops.default_recv = NULL;

    sock->pub.listen_portno = -1;
    pscom_listener_init(&sock->listen, pscom_con_accept_tcp, sock);

    sock->con_type_mask                = ~0ULL;
    sock->pub.userdata_size            = userdata_size;
    sock->pub.connection_userdata_size = connection_userdata_size;

    INIT_LIST_HEAD(&sock->archs);
    INIT_LIST_HEAD(&sock->connections);
    INIT_LIST_HEAD(&sock->genrecvq_any);
    INIT_LIST_HEAD(&sock->recvq_any);
    INIT_LIST_HEAD(&sock->groups);
    INIT_LIST_HEAD(&sock->group_req_unknown);
    INIT_LIST_HEAD(&sock->sendq_suspending);

    sock->recv_req_cnt_any = 0;

    pscom_sock_init_con_info(sock, local_rank);

    sock->state.close_called  = 0;
    sock->state.close_timeout = 0;
    sock->state.destroyed     = 0;

    sock->sock_flags = socket_flags;
    sock->id         = -1;

    /* set sock ID for this socket */
    ret = pscom_sock_set_id(sock);
    if (ret) { goto err_out; }

    /* call the precon provider init hook */
    pscom_precon_provider.sock_init(sock);

    pscom_plugins_sock_init(sock);

    pscom_lock();
    {
        list_add_tail(&sock->next, &pscom.sockets);
    }
    pscom_unlock();

    return sock;

err_out:
    return NULL; // error
}


static void pscom_sock_destroy(pscom_sock_t *sock)
{
    assert(sock->magic == MAGIC_SOCKET);

    if (sock->state.destroyed) {
        return; // Already destroyed (why?)
    }
    sock->state.destroyed = 1;

    if (!sock->state.close_timeout) {
        // In a timeout case, these lists may still not be empty!
        assert(list_empty(&sock->next));
        assert(list_empty(&sock->connections));
        assert(list_empty(&sock->genrecvq_any));
        assert(list_empty(&sock->recvq_any));

        assert(sock->pub.listen_portno == -1);
    }

    pscom_plugins_sock_destroy(sock);

    /* ensure all plugins performed a proper cleanup */
    assert(list_empty(&sock->archs));

    sock->magic = 0;

    /* only intra-job socket releases its id */
    pscom_sock_unset_id(sock);

    free(sock);
}


PSCOM_PLUGIN_API_EXPORT
int _pscom_con_type_mask_is_set(pscom_sock_t *sock, pscom_con_type_t con_type)
{
    return !!(sock->con_type_mask & (1ULL << con_type));
}


PSCOM_PLUGIN_API_EXPORT
void _pscom_con_type_mask_del(pscom_sock_t *sock, pscom_con_type_t con_type)
{
    assert(sock->magic == MAGIC_SOCKET);
    assert(con_type < 64);

    sock->con_type_mask &= ~(1ULL << con_type);
}


/*
******************************************************************************
*/

PSCOM_API_EXPORT
pscom_socket_t *pscom_open_socket(size_t userdata_size,
                                  size_t connection_userdata_size,
                                  int local_rank, uint64_t socket_flags)
{
    pscom_sock_t *sock;

    sock = pscom_sock_create(userdata_size, connection_userdata_size,
                             local_rank, socket_flags);
    if (!sock) {
        return NULL; // error
    }

    return &sock->pub;
}


PSCOM_API_EXPORT
void pscom_socket_set_name(pscom_socket_t *socket, const char *name)
{
    pscom_lock();
    {
        pscom_sock_t *sock = get_sock(socket);
        assert(sock->magic == MAGIC_SOCKET);
        /* todo: set a clear rule of the name, for now name format is "r+rank,
         * rXXXXXX" and set with local_rank from psmpi. The name in
         * `local_con_info` pack by `pscom_con_info` will be sent to the remote
         * side. The sent name will be used to find the correct connection at
         * the remote. In case of ondemand connection, the name will be compared
         * with the remote name set by the destation rank. */
        pscom_sock_set_name(sock, name);
        DPRINT(D_INFO, "Socket name: %s", name);
        pscom_debug_set_prefix(name);
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
pscom_err_t pscom_listen(pscom_socket_t *socket, int portno)
{
    pscom_sock_t *sock = get_sock(socket);
    pscom_err_t ret;

    assert(sock->magic == MAGIC_SOCKET);

    pscom_lock();
    {
        ret = pscom_precon_provider.start_listen(sock, portno);
    }
    pscom_unlock();

    return ret;
}


static inline void _pscom_close_and_destroy_sock(pscom_sock_t *sock)
{
    assert(sock->magic == MAGIC_SOCKET);
    pscom_sock_close(sock);
    pscom_sock_destroy(sock);
}


PSCOM_API_EXPORT
void pscom_close_socket(pscom_socket_t *socket)
{
    pscom_lock();
    {
        if (!socket) { // Close _all_ sockets:
            while (!list_empty(&pscom.sockets)) {
                pscom_sock_t *sock = list_entry(pscom.sockets.next,
                                                pscom_sock_t, next);
                _pscom_close_and_destroy_sock(sock);
            }
        } else {
            _pscom_close_and_destroy_sock(get_sock(socket));
        }
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
void pscom_stop_listen(pscom_socket_t *socket)
{
    pscom_lock();
    {
        pscom_sock_t *sock = get_sock(socket);
        assert(sock->magic == MAGIC_SOCKET);
        pscom_precon_provider.stop_listen(sock);
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
void pscom_con_type_mask_all(pscom_socket_t *socket)
{
    pscom_lock();
    {
        pscom_sock_t *sock = get_sock(socket);
        assert(sock->magic == MAGIC_SOCKET);
        sock->con_type_mask = ~0ULL;
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
void pscom_con_type_mask_only(pscom_socket_t *socket, pscom_con_type_t con_type)
{
    pscom_lock();
    {
        pscom_sock_t *sock = get_sock(socket);
        assert(sock->magic == MAGIC_SOCKET);
        assert(con_type < 64);
        sock->con_type_mask = 1ULL << con_type;
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
void pscom_con_type_mask_add(pscom_socket_t *socket, pscom_con_type_t con_type)
{
    pscom_lock();
    {
        pscom_sock_t *sock = get_sock(socket);
        assert(sock->magic == MAGIC_SOCKET);
        assert(con_type < 64);
        sock->con_type_mask |= 1ULL << con_type;
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
void pscom_con_type_mask_del(pscom_socket_t *socket, pscom_con_type_t con_type)
{
    pscom_lock();
    {
        _pscom_con_type_mask_del(get_sock(socket), con_type);
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
int pscom_con_type_mask_is_set(pscom_socket_t *socket, pscom_con_type_t con_type)
{
    int res;
    pscom_lock();
    {
        pscom_sock_t *sock = get_sock(socket);
        assert(sock->magic == MAGIC_SOCKET);
        assert(con_type < 64);

        res = _pscom_con_type_mask_is_set(sock, con_type);
    }
    pscom_unlock();
    return res;
}


#define PSCOM_CON_TYPE_MASK_MAGIC 0x6522feab23
typedef struct {
    unsigned long magic;
    uint64_t con_type_mask;
} pscom_con_type_mask_backup_t;


PSCOM_API_EXPORT
void *pscom_con_type_mask_backup(pscom_socket_t *socket)
{
    pscom_con_type_mask_backup_t *mask = malloc(sizeof(*mask));
    mask->magic                        = PSCOM_CON_TYPE_MASK_MAGIC;

    pscom_lock();
    {
        pscom_sock_t *sock  = get_sock(socket);
        mask->con_type_mask = sock->con_type_mask;
    }
    pscom_unlock();

    return mask;
}


PSCOM_API_EXPORT
void pscom_con_type_mask_restore(pscom_socket_t *socket,
                                 void *con_type_mask_backup)
{
    pscom_con_type_mask_backup_t *mask = (pscom_con_type_mask_backup_t *)
        con_type_mask_backup;
    assert(mask->magic == PSCOM_CON_TYPE_MASK_MAGIC);

    pscom_lock();
    {
        pscom_sock_t *sock  = get_sock(socket);
        sock->con_type_mask = mask->con_type_mask;
    }
    pscom_unlock();

    mask->magic = 0;
    free(mask);
}


PSCOM_API_EXPORT
void pscom_suspend_listen(pscom_socket_t *socket)
{
    pscom_lock();
    {
        pscom_sock_t *sock = get_sock(socket);
        assert(sock->magic == MAGIC_SOCKET);
        pscom_precon_provider.listener_suspend(&sock->listen);
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
void pscom_resume_listen(pscom_socket_t *socket)
{
    pscom_lock();
    {
        pscom_sock_t *sock = get_sock(socket);
        assert(sock->magic == MAGIC_SOCKET);
        pscom_precon_provider.listener_resume(&sock->listen);
    }
    pscom_unlock();
}


PSCOM_API_EXPORT
pscom_err_t pscom_socket_get_ep_str(pscom_socket_t *socket, char **ep_str)
{
    return pscom_precon_get_ep_info_from_socket(socket, ep_str);
}


PSCOM_API_EXPORT
void pscom_socket_free_ep_str(char *ep_str)
{
    free(ep_str);
}
