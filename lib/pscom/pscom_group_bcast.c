/*
 * ParaStation
 *
 * Copyright (C) 2008-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdlib.h>
#include "pscom_group.h"

// #define USE_ASYNCHRONOUS_BCAST 1

/***********************
 * rank iterator
 */
static const unsigned bcast_devide = 3; // ToDo: make it configurable/
                                        // messagelen dependant


typedef struct bcast_rank_iter {
    unsigned group_size;
    unsigned delta;
    unsigned med;
} bcast_rank_iter_t;


static inline unsigned bcast_rank_iter_begin(bcast_rank_iter_t *iter,
                                             unsigned group_size,
                                             unsigned devide)
{
    unsigned delta = (group_size) / devide;

    unsigned g1  = group_size - delta * devide;
    unsigned med = g1 * (delta + 1);

    iter->group_size = group_size;
    iter->delta      = delta;
    iter->med        = med;

    return 0;
}


static inline unsigned bcast_rank_iter_end(bcast_rank_iter_t *iter)
{
    return iter->group_size;
}


static inline unsigned bcast_rank_iter_next(bcast_rank_iter_t *iter,
                                            unsigned rank)
{
    return rank + iter->delta + (rank < iter->med);
}


static void _gcompat_init(unsigned recvs[], unsigned my_rank,
                          unsigned group_size, unsigned devide)
{
    unsigned urank, urank_next;
    bcast_rank_iter_t iter;

    for (urank = bcast_rank_iter_begin(&iter, group_size - 1, devide);
         urank != bcast_rank_iter_end(&iter); urank = urank_next) {
        urank_next = bcast_rank_iter_next(&iter, urank);

        unsigned dest      = urank + my_rank + 1;
        unsigned dest_size = urank_next - urank;

        recvs[dest] = my_rank;

        _gcompat_init(recvs, dest, dest_size, devide);
    }
}


void pscom_group_gcompat_init(pscom_group_t *group)
{
    group->compat = malloc(sizeof(*group->compat) * group->group_size);

    group->compat[0] = RANK_NONE;
    _gcompat_init(group->compat, 0, group->group_size, bcast_devide);
}

/***************************************************/

static pscom_con_t *_pscom_get_bcast_recv_con(pscom_group_t *group,
                                              unsigned bcast_root)
{
    unsigned my_urank = (group->my_grank + group->group_size - bcast_root) %
                        group->group_size;
    unsigned urank_recv_from = group->compat[my_urank];
    unsigned rank_recv_from  = (urank_recv_from + bcast_root) %
                              group->group_size;
    pscom_group_mem_t *mem_recv_from = &group->member[rank_recv_from];
    pscom_con_t *con                 = mem_recv_from->con;

    return con;
}

#ifdef USE_ASYNCHRONOUS_BCAST

static void _replay_bcast_req(pscom_req_t *req_bcast)
{
    pscom_req_t *req_master = _pscom_get_bcast_receiver(
        get_con(req_bcast->pub.connection), &req_bcast->pub.header);
    if (!req_master) {
        return; // error
    }

    pscom_req_prepare_recv(req_master, &req_bcast->pub.header,
                           req_bcast->pub.connection);
    pscom_req_write(req_master, req_bcast->pub.data, req_bcast->pub.data_len);

    _pscom_update_recv_req(req_master); // io_done will call
                                        // _bcast_req_master_step()
}


static void io_done_replay_bcast_req(pscom_request_t *request)
{
    pscom_req_t *req = get_req(request);

    pscom_lock();
    {
        _replay_bcast_req(req);
    }
    pscom_unlock();

    pscom_req_free(req);
}


void pscom_group_replay_bcasts(pscom_sock_t *sock, unsigned group_id)
{
    struct list_head *pos, *n;

    list_for_each_safe (pos, n, &sock->group_req_unknown) {
        pscom_req_t *req = list_entry(pos, pscom_req_t, next);

        if (req->pub.xheader.bcast.group_id == group_id) {

            list_del(&req->next);

            if (req->pub.state & PSCOM_REQ_STATE_DONE) {
                _replay_bcast_req(req);
                pscom_req_free(req);
            } else {
                // copy message in io_done
                assert(req->pub.ops.io_done == NULL);
                req->pub.ops.io_done = io_done_replay_bcast_req;
                /* io_done will use req->next !!! */
            }
        }
    }
}


typedef struct pscom_bcast_req {
    struct list_head fw_send_requests; /* list of sendrequests->next */
    pscom_req_t *req_recv_user;
    pscom_req_t *req_send_user;

    int fw_posted : 1; // send requests posted?
    int req_recv_user_done : 1;

    char data[0];
} pscom_bcast_req_t;


/*
static
int _bcast_receive_accept(pscom_request_t *request,
                          pscom_connection_t *connection,
                          pscom_header_net_t *header_net)
{
        //pscom_req_t *req = get_req(request);
        //pscom_req_t *user_req = req->partner_req;


        // ToDo: call user accept? (request->partner_req->pub.recv_accept)

        return header_net->msg_type == PSCOM_MSGTYPE_BCAST;
}
*/


static void _pscom_req_send_continue(pscom_req_t *req)
{
    pscom_con_t *con = get_con(req->pub.connection);
    con->write_start(con);
}


static void _bcast_req_master_step(pscom_req_t *req_master)
{
    assert(req_master->magic == MAGIC_REQUEST);
    pscom_bcast_req_t *bc_master = (pscom_bcast_req_t *)req_master->pub.user;

    // fw sends in progress?
    if (!list_empty(&bc_master->fw_send_requests)) { return; }

    // req_recv_user done? (check after fw sends in progress (maybe shared data
    // pointer!!!))
    if (bc_master->req_recv_user) {
        assert(list_empty(&bc_master->fw_send_requests) ||
               req_master->pub.data != bc_master->req_recv_user->pub.data);
        int done = _pscom_update_recv_req(bc_master->req_recv_user);
        if (!done) { return; }

        bc_master->req_recv_user      = NULL;
        bc_master->req_recv_user_done = 1;
    }

    // generated request and still waiting for req_recv_user?
    if (!bc_master->req_recv_user_done) { return; }

    // still receiving? io_done called?
    if (!(req_master->pub.state &
          PSCOM_REQ_STATE_DONE /*PSCOM_REQ_STATE_IO_DONE*/)) {
        return;
    }

    if (bc_master->req_send_user) {
        _pscom_send_req_done(bc_master->req_send_user); // done
        bc_master->req_send_user = NULL;
    }

    // No references to req_master left -> last step.
    pscom_req_free(req_master);
}


static void _bcast_req_master_write(pscom_req_t *req_master, char *buf,
                                    unsigned len)
{
    pscom_bcast_req_t *bc_master = (pscom_bcast_req_t *)req_master->pub.user;
    struct list_head *pos;

    int fw_posted        = bc_master->fw_posted;
    bc_master->fw_posted = 1;

    list_for_each (pos, &bc_master->fw_send_requests) {
        pscom_req_t *req_send = list_entry(pos, pscom_req_t, next_alt);

        // printf("%s:%d Forward send request: ->con %p\n", __func__, __LINE__,
        // req_send->pub.connection); // ToDo:

        pscom_req_append(req_send, buf, len);

        if (!fw_posted) {
            // First data fragment
            _pscom_sendq_enq(get_con(req_send->pub.connection), req_send);
        } else {
            // More data fragments
            _pscom_req_send_continue(req_send);
        }
    }

    if (bc_master->req_recv_user) {
        pscom_req_write(bc_master->req_recv_user, buf, len);
    }

    _bcast_req_master_step(req_master);
    // dont use req_master behind me - it may be freed
}


static void io_done_bcast_req_master(pscom_request_t *request)
{
    pscom_req_t *req_master      = get_req(request);
    pscom_bcast_req_t *bc_master = (pscom_bcast_req_t *)req_master->pub.user;

    assert(req_master->magic == MAGIC_REQUEST);

    pscom_lock();
    {
        if (bc_master->fw_posted) {
            _bcast_req_master_step(req_master);
            // dont use req_master behind me - it may be freed
        } else {
            // maybe fw_posted == 0, if data_len == 0.
            _bcast_req_master_write(req_master, NULL, 0);
            // dont use req_master behind me - it may be freed
        }
    }
    pscom_unlock();
}


static void check_recv_accept(pscom_req_t *req)
{
    static int warned = 0;
    if (req->pub.ops.recv_accept && !warned) {
        DPRINT(D_WARNONCE, "Warning: Bcast: request->ops.recv_accept not "
                           "implemented!");
        warned = 1;
    }
}


static void _recvq_enq(pscom_con_t *con, pscom_group_mem_t *mem,
                       pscom_req_t *req)
{
    req->pub.connection = &con->pub;

    list_add_tail(&req->next_alt, &mem->recvq);
    _pscom_recv_req_cnt_inc(con);
}


static void _recvq_deq(pscom_req_t *req)
{
    list_del(&req->next_alt);
    _pscom_recv_req_cnt_dec(get_con(req->pub.connection));
}


static pscom_req_t *_recvq_find_and_deq(pscom_group_t *group,
                                        pscom_group_mem_t *mem,
                                        pscom_header_net_t *nh)
{
    if (!list_empty(&mem->recvq)) {
        // return first list entry
        pscom_req_t *req = list_entry(mem->recvq.next, pscom_req_t, next_alt);

        // ToDo: call req->pub.recv_accept?
        check_recv_accept(req);

        _recvq_deq(mem, req);

        return req;
    }
    return NULL;
}


static pscom_req_t *_find_genrecv_req(pscom_group_t *group,
                                      pscom_group_mem_t *mem, pscom_req_t *req)
{
    check_recv_accept(req);

    if (!list_empty(&mem->genrecvq)) {
        // ToDo: call req->pub.recv_accept?

        // return first list entry
        pscom_req_t *req_master = list_entry(mem->genrecvq.next, pscom_req_t,
                                             next_alt);
        return req_master;
    }
    return NULL;
}


static pscom_req_t *generate_fwrecv_req(pscom_group_t *group,
                                        unsigned xheader_len, unsigned data_len,
                                        pscom_req_t *req_recv_user,
                                        pscom_req_t *req_send_user)
{
    pscom_req_t *req_master;
    char *data;
    pscom_bcast_req_t *bc_master;

    if (req_recv_user) {
        assert(!req_send_user);
        req_master = pscom_req_create(xheader_len, sizeof(pscom_bcast_req_t));
        bc_master  = (pscom_bcast_req_t *)req_master->pub.user;
        data       = req_recv_user->pub.data;
    } else if (req_send_user) {
        assert(!req_recv_user);
        req_master = pscom_req_create(xheader_len, sizeof(pscom_bcast_req_t));
        bc_master  = (pscom_bcast_req_t *)req_master->pub.user;
        data       = req_send_user->pub.data;
    } else {
        req_master = pscom_req_create(xheader_len,
                                      sizeof(pscom_bcast_req_t) + data_len);
        bc_master  = (pscom_bcast_req_t *)req_master->pub.user;
        data       = bc_master->data;
        pscom.stat.gen_reqs++;
    }

    req_master->pub.state = PSCOM_REQ_STATE_GRECV_REQUEST;
    /* freed inside genreq_merge() */

    req_master->pub.data        = data;
    req_master->pub.data_len    = data_len;
    req_master->pub.xheader_len = xheader_len;
    req_master->partner_req     = NULL;

    req_master->write_hook      = _bcast_req_master_write;
    req_master->pub.ops.io_done = io_done_bcast_req_master;

    bc_master->req_recv_user = req_recv_user;
    bc_master->req_send_user = req_send_user;

    bc_master->req_recv_user_done = !!req_send_user; // in send mode fake a
                                                     // recv_user_done

    return req_master;
}


static void _pscom_post_bcast_receive(pscom_req_t *req_user,
                                      pscom_group_t *group, unsigned bcast_root)
{
    assert(req_user->pub.xheader_len >= sizeof(pscom_xheader_bcast_t));
    pscom_group_mem_t *mem_root = &group->member[bcast_root];

    pscom_req_t *req_master = _find_genrecv_req(group, mem_root, req_user);

    req_user->pub.state = PSCOM_REQ_STATE_RECV_REQUEST | PSCOM_REQ_STATE_POSTED;

    if (!req_master) {
        req_master = generate_fwrecv_req(group, req_user->pub.xheader_len,
                                         req_user->pub.data_len, req_user,
                                         NULL);

        pscom_con_t *con = _pscom_get_bcast_recv_con(group, bcast_root);
        _recvq_enq(con, mem_root, req_master);
    } else {
        /* matching generated receive available */
        assert(req_master->magic == MAGIC_REQUEST);

        list_del(&req_master->next_alt); // dequeue from &mem->genrecvq

        pscom_bcast_req_t *bc_master = (pscom_bcast_req_t *)req_master->pub.user;
        assert(!bc_master->req_recv_user);
        assert(!bc_master->req_recv_user_done);
        bc_master->req_recv_user = req_user;

        // Copy header
        pscom_req_prepare_recv(req_user, &req_master->pub.header,
                               req_master->pub.connection);

        // Copy data
        pscom_req_write(req_user, req_master->pub.data,
                        (char *)req_master->cur_data.iov_base -
                            (char *)req_master->pub.data);

        _bcast_req_master_step(req_master);
    }
}


static void io_done_bcast_fw_send(pscom_request_t *request)
{
    pscom_req_t *req_send   = get_req(request);
    pscom_req_t *req_master = req_send->partner_req;

    pscom_lock();
    {
        // remove from bc_master->fw_send_requests
        list_del(&req_send->next_alt);

        _bcast_req_master_step(req_master);
    }
    pscom_unlock();
    pscom_request_free(request);
}


static pscom_req_t *fw_send_create(char *data_master, pscom_header_net_t *nh)
{
    pscom_req_t *req_send = pscom_req_create(nh->xheader_len, 0);

    // copy xheader
    memcpy(&req_send->pub.xheader, nh->xheader, nh->xheader_len);
    req_send->pub.xheader_len = nh->xheader_len;

    // prepare data
    req_send->pub.data_len = nh->data_len;
    req_send->pub.data     = data_master;

    return req_send;
}
static void init_send_forwards(pscom_group_t *group, pscom_req_t *req_master,
                               pscom_header_net_t *nh)
{
    pscom_bcast_req_t *bc_master = (pscom_bcast_req_t *)req_master->pub.user;

    INIT_LIST_HEAD(&bc_master->fw_send_requests);
    bc_master->fw_posted = 0;

    // unsigned root_rank = nh->xheader->bcast.bcast_root;
    unsigned subg_size = nh->xheader->bcast.bcast_arg1;

    bcast_rank_iter_t iter;
    unsigned urank;
    unsigned urank_next;

    unsigned my_rank = group->my_grank;


    for (urank = bcast_rank_iter_begin(&iter, subg_size - 1, bcast_devide);
         urank != bcast_rank_iter_end(&iter); urank = urank_next) {
        urank_next = bcast_rank_iter_next(&iter, urank);

        unsigned dest      = (urank + my_rank + 1) % group->group_size;
        unsigned dest_size = urank_next - urank;

        pscom_req_t *req_send = fw_send_create(req_master->pub.data, nh);

        req_send->pub.xheader.bcast.bcast_arg1 = dest_size;

        req_send->pub.connection  = group_rank2connection(group,
                                                          dest); // destination
        req_send->pub.ops.io_done = io_done_bcast_fw_send;

#if 0
		printf("%s:%d Forward send request: ->con %p rank %2d -> %2d\n",
		       __func__, __LINE__, req_send->pub.connection, my_rank, dest);
#endif

        list_add_tail(&req_send->next_alt, &bc_master->fw_send_requests);

        req_send->partner_req = req_master;

        pscom_req_prepare_send_pending(req_send, PSCOM_MSGTYPE_BCAST,
                                       nh->data_len);
        // ToDo: Use pscom_post_send_rendezvous() for long messages?
        // called in _bcast_req_master_write(): pscom_post_send_direct(req,
        // PSCOM_MSGTYPE_BCAST);
    }
}


/* provide a receive request for the network layer */
pscom_req_t *_pscom_get_bcast_receiver(pscom_con_t *con, pscom_header_net_t *nh)
{
    pscom_xheader_bcast_t *bh = &nh->xheader->bcast;
    unsigned group_id         = bh->group_id;
    unsigned bcast_root       = bh->bcast_root;
    pscom_group_t *group      = _pscom_group_find(get_sock(con->pub.socket),
                                                  group_id);

    if (!group) { goto unknown_group; }
    if (bcast_root >= group->group_size) { goto err_illegal_root; }

    pscom_group_mem_t *mem_root = &group->member[bcast_root];

    // ToDo: disable assert (check if we receive from the expected group
    // member):
    assert(con == _pscom_get_bcast_recv_con(group, bcast_root));

    pscom_req_t *req_master = _recvq_find_and_deq(group, mem_root, nh);
    if (req_master) {
        /* matching receive available */

        pscom_bcast_req_t *bc_master = (pscom_bcast_req_t *)req_master->pub.user;
        pscom_req_t *req_user = bc_master->req_recv_user;
        assert(req_user);

        // Copy header
        pscom_req_prepare_recv(req_user, nh, &con->pub);
    } else {
        /* no matching receive available. */
        req_master = generate_fwrecv_req(group, nh->xheader_len, nh->data_len,
                                         NULL, NULL);
        list_add_tail(&req_master->next_alt, &mem_root->genrecvq);
    }

    init_send_forwards(group, req_master, nh);

    return req_master;
unknown_group:;
    pscom_req_t *req_gen = _pscom_generate_recv_req(con, nh);

    list_add_tail(&req_gen->next,
                  &(get_sock(con->pub.socket)->group_req_unknown));

    return req_gen;
err_illegal_root:
    DPRINT(D_FATAL,
           "receive broadcast with illegal root_rank group_id:%d from:'%s' "
           "grank:%d.",
           group_id, pscom_con_info_str(&con->pub.remote_con_info), bcast_root);
    return NULL;
}


static void _pscom_post_bcast_send(pscom_req_t *req_user, pscom_group_t *group)
{
    assert(req_user->pub.xheader_len >= sizeof(pscom_xheader_bcast_t));

    pscom_req_t *req_master = generate_fwrecv_req(group,
                                                  req_user->pub.xheader_len,
                                                  req_user->pub.data_len, NULL,
                                                  req_user);

    req_user->pub.state = PSCOM_REQ_STATE_SEND_REQUEST |
                          PSCOM_REQ_STATE_POSTED | PSCOM_REQ_STATE_IO_STARTED;

    // Init bcast xheader (arg1)
    assert(req_user->pub.xheader.bcast.bcast_root == group->my_grank);
    req_user->pub.xheader.bcast.bcast_arg1 = group->group_size;

    req_user->pub.header.xheader_len = req_user->pub.xheader_len;
    req_user->pub.header.data_len    = req_user->pub.data_len;

    init_send_forwards(group, req_master, &req_user->pub.header);

    req_master->pub.state = PSCOM_REQ_STATE_SEND_REQUEST |
                            PSCOM_REQ_STATE_POSTED | PSCOM_REQ_STATE_DONE;
    _bcast_req_master_write(req_master, req_user->pub.data,
                            req_user->pub.data_len);
}


PSCOM_API_EXPORT
void pscom_post_bcast(pscom_request_t *request)
{
    pscom_req_t *req = get_req(request);
    assert(req->magic == MAGIC_REQUEST);
    assert(request->state & PSCOM_REQ_STATE_DONE);

    uint32_t group_id   = request->xheader.bcast.group_id;
    uint32_t bcast_root = request->xheader.bcast.bcast_root;
    pscom_sock_t *sock  = get_sock(request->socket);

    assert(sock->magic == MAGIC_SOCKET);

    pscom_lock();
    {
        pscom_group_t *group = _pscom_group_find(sock, group_id);

        assert(group);
        assert(group->magic == MAGIC_GROUP);
        assert(bcast_root < group->group_size);

        if (bcast_root != group->my_grank) {
            _pscom_post_bcast_receive(req, group, bcast_root);
        } else {
            _pscom_post_bcast_send(req, group);
        }
    }
    pscom_unlock();

    return;
}


/* Blocking version of bcast */
PSCOM_API_EXPORT
void pscom_bcast(pscom_group_t *group, unsigned bcast_root, void *xheader,
                 unsigned int xheader_len, void *data, unsigned int data_len)
{
    pscom_request_t *request;
    unsigned xlen = xheader_len + sizeof(request->xheader.bcast);
    int iam_root;

    assert(group->magic == MAGIC_GROUP);

    request = pscom_request_create(xlen, 0);

    request->xheader_len = xlen;
    request->data_len    = data_len;
    request->data        = data;


    request->xheader.bcast.group_id   = group->group_id;
    request->xheader.bcast.bcast_root = bcast_root;
    request->socket                   = &group->sock->pub;

    pscom_req_t *req = get_req(request);

    pscom_lock();
    {
        assert(bcast_root < group->group_size);

        iam_root = bcast_root == group->my_grank;
        if (!iam_root) {
            _pscom_post_bcast_receive(req, group, bcast_root);
        } else {
            memcpy(&request->xheader.bcast.user, xheader, xheader_len);
            _pscom_post_bcast_send(req, group);
        }
    }
    pscom_unlock();

    pscom_wait(request);

    if (!iam_root) {
        memcpy(xheader, &request->xheader.bcast.user, xheader_len);
    }

    pscom_request_free(request);
}

#else /* !USE_ASYNCHRONOUS_BCAST */

void pscom_group_replay_bcasts(pscom_sock_t *sock, unsigned group_id)
{
}


/* provide a receive request for the network layer */
pscom_req_t *_pscom_get_bcast_receiver(pscom_con_t *con, pscom_header_net_t *nh)
{
    return _pscom_get_ctrl_receiver(con, nh);
}


static inline pscom_req_t *pscom_bcast_create_req(pscom_group_t *group,
                                                  void *xheader,
                                                  size_t xheader_len,
                                                  void *data, size_t data_len)
{
    pscom_req_t *req;
    size_t xlen = sizeof(req->pub.xheader.bcast) + xheader_len;

    req = pscom_req_create(xlen, 0);

    req->pub.xheader_len            = xlen;
    req->pub.xheader.bcast.group_id = group->group_id;
    req->pub.data                   = data;
    req->pub.data_len               = data_len;
    req->pub.header.msg_type        = PSCOM_MSGTYPE_BCAST;

    if (xheader) { memcpy(req->pub.xheader.bcast.user, xheader, xheader_len); }

    return req;
}


static int recv_accept_bcast(pscom_request_t *request,
                             pscom_connection_t *connection,
                             pscom_header_net_t *header_net)
{
    return request->xheader.bcast.group_id ==
           header_net->xheader->bcast.group_id;
}


/* Blocking version of bcast */
PSCOM_API_EXPORT
void pscom_bcast(pscom_group_t *group, unsigned bcast_root, void *xheader,
                 size_t xheader_len, void *data, size_t data_len)
{
    pscom_req_t *req = NULL;
    unsigned subg_size;

    assert(group->magic == MAGIC_GROUP);
    assert(bcast_root < group->group_size);

    if (bcast_root != group->my_grank) {
        /* I am not root. First receive data. */

        req = pscom_bcast_create_req(group, NULL, xheader_len, data, data_len);
        req->pub.ops.recv_accept = recv_accept_bcast;
        req->pub.connection = &_pscom_get_bcast_recv_con(group, bcast_root)->pub;

        pscom_post_recv_ctrl(req);
        pscom_wait(&req->pub);

        assert(pscom_req_successful(&req->pub));

        if (xheader_len) {
            memcpy(xheader, req->pub.xheader.bcast.user, xheader_len);
        }

        /* request to forward this message to subgroub of size subg_size: */
        subg_size = req->pub.xheader.bcast.bcast_arg1;
    } else {
        /* I am the root. Subgroup is the whole group. */
        subg_size = group->group_size;
    }

    /* Forward xheader and data */

    pscom_req_t *reqs[bcast_devide + 1];
    unsigned idx_send = 0;
    unsigned urank, urank_next;
    bcast_rank_iter_t iter;

    for (urank = bcast_rank_iter_begin(&iter, subg_size - 1, bcast_devide);
         urank != bcast_rank_iter_end(&iter); urank = urank_next) {
        urank_next = bcast_rank_iter_next(&iter, urank);

        unsigned dest      = (urank + group->my_grank + 1) % group->group_size;
        unsigned dest_size = urank_next - urank;

        if (!req) {
            req = pscom_bcast_create_req(group, xheader, xheader_len, data,
                                         data_len);
        }
        req->pub.connection               = group_rank2connection(group, dest);
        req->pub.xheader.bcast.bcast_arg1 = dest_size;

        pscom_post_send_direct(req, PSCOM_MSGTYPE_BCAST);

        if (!pscom_req_is_done(&req->pub)) {
            /* schedule the wait */
            reqs[idx_send++] = req;
            req              = NULL;
        } /* else reuse request */
    }

    if (req) {
        pscom_req_free(req);
        req = NULL;
    }

    reqs[idx_send++] = NULL;

    pscom_req_t **r;
    for (r = reqs; *r; r++) {
        pscom_wait(&(*r)->pub);
        pscom_req_free(*r);
    }
}


/* ToDo: this communication is not asynchronous and
   pscom_post_bcast will block in this implementation! */
PSCOM_API_EXPORT
void pscom_post_bcast(pscom_request_t *request)
{
    pscom_req_t *req = get_req(request);
    assert(req->magic == MAGIC_REQUEST);
    assert(request->state & PSCOM_REQ_STATE_DONE);
    assert(request->xheader_len >= sizeof(request->xheader.bcast));

    uint32_t group_id   = request->xheader.bcast.group_id;
    uint32_t bcast_root = request->xheader.bcast.bcast_root;

    pscom_group_t *group = pscom_group_find(request->socket, group_id);

    assert(group);
    assert(group->magic == MAGIC_GROUP);

    /* fake receive request */
    req->pub.state = PSCOM_REQ_STATE_RECV_REQUEST | PSCOM_REQ_STATE_POSTED;

    pscom_bcast(group, bcast_root, request->xheader.bcast.user,
                request->xheader_len - sizeof(req->pub.xheader.bcast),
                request->data, request->data_len);

    /* fake receive request done */
    pscom_req_done(req);
}

#endif /* !USE_ASYNCHRONOUS_BCAST */
