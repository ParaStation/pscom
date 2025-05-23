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

#ifndef _PSCOM_IO_H_
#define _PSCOM_IO_H_

#include "list.h"
#include "pscom.h"
#include "pscom_cuda.h"
#include "pscom_debug.h"
#include "pscom_priv.h"

static inline void _pscom_step(void)
{
    pscom.stat.progresscounter++;
}


/* move to state done and call io_done. unlocked version */
static inline void pscom_req_done(pscom_req_t *req)
{
    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));

    req->pub.state |= PSCOM_REQ_STATE_IO_DONE | PSCOM_REQ_STATE_DONE;
    _pscom_step(); // ToDo: Need lock!

    if (req->pub.ops.io_done) { req->pub.ops.io_done(&req->pub); }
}


static inline void _pscom_req_done(pscom_req_t *req)
{
    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));

    if (req->pub.ops.io_done) {
        req->pub.state |= PSCOM_REQ_STATE_IO_DONE;
        D_TR(printf("%s:%u:%s req:%s add to pscom.io_doneq\n", __FILE__,
                    __LINE__, __func__, pscom_debug_req_str(req)));
        list_add_tail(&req->next, &pscom.io_doneq);
    } else {
        req->pub.state |= PSCOM_REQ_STATE_IO_DONE | PSCOM_REQ_STATE_DONE;
    }

    _pscom_step();
}


/* unlocked version */
static inline void pscom_recv_req_done(pscom_req_t *req)
{
    _pscom_unstage_buffer(req, 1);
    pscom_req_done(req);
}


/* locked version */
static inline void _pscom_recv_req_done(pscom_req_t *req)
{
    _pscom_unstage_buffer(req, 1);
    _pscom_req_done(req);
}


static inline void _pscom_send_req_done(pscom_req_t *req)
{
    _pscom_unstage_buffer(req, 0);
    _pscom_req_done(req);
}


static inline void _pscom_grecv_req_done(pscom_req_t *req)
{
    D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
                pscom_debug_req_str(req)));
    // assert(!genreq->rendezvous_req);
    req->pub.state |= PSCOM_REQ_STATE_GRECV_MERGED;
    _pscom_req_done(req);
}


#if 0
static inline
void _pscom_req_bcast_done(pscom_req_t *req)
{
	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
		    pscom_debug_req_str(req)));

	req->pub.state |= PSCOM_REQ_STATE_DONE;
	_pscom_step();
	pscom_req_free(req);
}
#endif


void pscom_greq_check_free(pscom_con_t *con, pscom_req_t *greq);

/* call _pscom_recv_req_done() and return 1 if req received all data. return 0
   else. Do not use req, after a return of 1!  */
int _pscom_update_recv_req(pscom_req_t *req);

void pscom_post_send_direct(pscom_req_t *req, pscom_msgtype_t msg_type);
void _pscom_post_rma_read(pscom_req_t *rma_read_req);

pscom_req_t *_pscom_get_ctrl_receiver(pscom_con_t *con, pscom_header_net_t *nh);
pscom_req_t *_pscom_get_bcast_receiver(pscom_con_t *con, pscom_header_net_t *nh);
void pscom_req_prepare_recv(pscom_req_t *req, const pscom_header_net_t *nh,
                            pscom_connection_t *connection);

void pscom_req_prepare_send_pending(pscom_req_t *req, pscom_msgtype_t msg_type,
                                    unsigned data_pending);

pscom_req_t *_pscom_generate_recv_req(pscom_con_t *con, pscom_header_net_t *nh);

void _pscom_genreq_abort_rendezvous_rma_reads(pscom_con_t *con);

/* post the receive request req.
   Receiving up to req->xheader_len bytes to req->xheader and
   up to req->data_len bytes to req->data from connection
   req->connection with message type req->header.msg_type.

   req->xheader_len
   req->xheader
   req->data_len
   req->data
   req->connection (no "ANY" allowed!)
   req->header.msg_type

   optional:
   req->ops.recv_accept
   req->ops.io_done
*/
void _pscom_post_recv_ctrl(pscom_req_t *req); /* must hold pscom_lock() */
void pscom_post_recv_ctrl(pscom_req_t *req);  /* must not hold pscom_lock() */

void _pscom_recvq_rma_terminate(pscom_con_t *con);

// receiver for PSCOM_MSGTYPE_GW_ENVELOPE, set by pscom4gateway.
extern pscom_req_t *(*_pscom_get_gw_envelope_receiver)(pscom_con_t *con,
                                                       pscom_header_net_t *nh);

void pscom_rma_request_free_send_buffer(pscom_request_t *request);
#endif /* _PSCOM_IO_H_ */
