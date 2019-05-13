/*
 * ParaStation
 *
 * Copyright (C) 2007,2010 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include "pscom_priv.h"
#include "pscom_io.h"
#include "pscom_queues.h"
#include "pscom_req.h"
#include <stdlib.h>
#include <stdio.h>
#include "pscom_str_util.h"
#include "pscom_util.h"
#include "pscom_cuda.h"

static inline size_t       header_length(pscom_header_net_t *header);
static inline int          header_complete(void *buf, size_t size);
static inline int          is_recv_req_done(pscom_req_t *req);
static        void         _pscom_rendezvous_read_data(pscom_req_t *user_recv_req,
						       pscom_req_t *rendezvous_req);
static        void _pscom_rendezvous_read_data_abort_arch(pscom_req_t *rendezvous_req);
static        void         pscom_req_prepare_send(pscom_req_t *req, pscom_msgtype_t msg_type);
static        void         pscom_req_prepare_rma_write(pscom_req_t *req);
static        void         _check_readahead(pscom_con_t *con, size_t len);
static        void         _pscom_update_in_recv_req(pscom_con_t *con);
static inline void         _pscom_req_bcast_done(pscom_req_t *req);
static        void         genreq_merge_header(pscom_req_t *newreq, pscom_req_t *genreq);
static        void         _genreq_merge(pscom_req_t *newreq, pscom_req_t *genreq);
static        pscom_req_t *pscom_get_default_recv_req(pscom_con_t *con, pscom_header_net_t *nh);
static inline pscom_req_t *_pscom_get_user_receiver(pscom_con_t *con, pscom_header_net_t *nh);
static        pscom_req_t *pscom_get_rma_write_receiver(pscom_con_t *con, pscom_header_net_t *nh);
static        pscom_req_t *_pscom_get_rma_read_receiver(pscom_con_t *con, pscom_header_net_t *nh);
static        pscom_req_t *_pscom_get_rma_read_answer_receiver(pscom_con_t *con, pscom_header_net_t *nh);
static        pscom_req_t *_pscom_get_eof_receiver(pscom_con_t *con, pscom_header_net_t *nh);
static        pscom_req_t *_pscom_get_suspend_receiver(pscom_con_t *con, pscom_header_net_t *nh);
static        void         pscom_rendezvous_read_data_io_done(pscom_request_t *request);
static        void         pscom_rendezvous_receiver_io_done(pscom_request_t *req);
static        pscom_req_t *pscom_get_rendezvous_receiver(pscom_con_t *con, pscom_header_net_t *nh);
static        pscom_req_t *_pscom_get_rendezvous_fin_receiver(pscom_con_t *con, pscom_header_net_t *nh);
static        pscom_req_t *_pscom_get_recv_req(pscom_con_t *con, pscom_header_net_t *nh);
// return true at the end of each message
static        void         _pscom_send(pscom_con_t *con, pscom_msgtype_t msg_type,
				       void *xheader, size_t xheader_len,
				       void *data, size_t data_len);
static        void         pscom_send_inplace_io_done(pscom_request_t *req);
static        int          _pscom_cancel_send(pscom_req_t *req);
static        int          _pscom_cancel_recv(pscom_req_t *req);
static inline void         pscom_post_send_direct_inline(pscom_req_t *req, pscom_msgtype_t msg_type);
static inline void         _pscom_post_send_direct_inline(pscom_con_t *con, pscom_req_t *req, pscom_msgtype_t msg_type);
static inline void         pscom_post_send_rendezvous(pscom_req_t *user_req);
static inline void         _pscom_post_rma_read(pscom_req_t *req);

int                        pscom_read_is_at_message_start(pscom_con_t *con);
void                       pscom_read_get_buf(pscom_con_t *con, char **buf, size_t *len);
void                       pscom_read_done(pscom_con_t *con, char *buf, size_t len);


pscom_req_t *(*_pscom_get_gw_envelope_receiver)(pscom_con_t *con, pscom_header_net_t *nh);
pscom_req_t *(*_pscom_get_gw_ctrl_receiver)(pscom_con_t *con, pscom_header_net_t *nh);

void pscom_req_prepare_recv(pscom_req_t *req, const pscom_header_net_t *nh, pscom_connection_t *connection)
{
	size_t copy_header = sizeof(req->pub.header) +
		pscom_min(req->pub.xheader_len, nh->xheader_len);

	memcpy(&req->pub.header, nh, copy_header);

	req->cur_data.iov_base = req->pub.data;

	if (nh->data_len <= req->pub.data_len) {
		req->cur_data.iov_len = nh->data_len;
		req->skip = 0;
	} else {
		assert(req->magic == MAGIC_REQUEST);
		req->cur_data.iov_len = req->pub.data_len;
		req->skip = nh->data_len - req->pub.data_len;
		req->pub.state |= PSCOM_REQ_STATE_TRUNCATED;
	}

	D_TR(printf("%s:%u:%s(%s) hlen=%u dlen=%zu dlen_req=%u dlen_net=%u skip=%u\n",
		    __FILE__, __LINE__, __func__,
		    pscom_debug_req_str(req), copy_header, req->cur_data.iov_len,
		    req->pub.data_len, nh->data_len, req->skip));

	assert(connection);
	req->pub.connection = connection;
}


static inline
size_t header_length(pscom_header_net_t *header)
{
	return sizeof(pscom_header_net_t) + header->xheader_len;
}


static inline
int header_complete(void *buf, size_t size)
{
	pscom_header_net_t *nhead = (pscom_header_net_t *)buf;

	return (size >= sizeof(pscom_header_net_t)) &&
		(size >= header_length(nhead));
}


static inline
int is_recv_req_done(pscom_req_t *req)
{
	return (req->cur_data.iov_len == 0);
}


static inline
void pscom_req_prepare_send_pending_inline(pscom_req_t *req, pscom_msgtype_t msg_type, unsigned data_pending)
{
	req->pub.header.msg_type = msg_type;
	req->pub.header.xheader_len = (uint16_t)req->pub.xheader_len;
	req->pub.header.data_len = PSCOM_DATA_LEN_MASK & req->pub.data_len;

	req->cur_header.iov_base = &req->pub.header;
	req->cur_header.iov_len = sizeof(pscom_header_net_t) + req->pub.header.xheader_len;
	req->cur_data.iov_base = req->pub.data;
	req->cur_data.iov_len = req->pub.data_len - data_pending;

	req->skip = data_pending;
	req->pending_io = 0;
}


void pscom_req_prepare_send_pending(pscom_req_t *req, pscom_msgtype_t msg_type, unsigned data_pending)
{
	pscom_req_prepare_send_pending_inline(req, msg_type, data_pending);
}


static
void pscom_req_prepare_send(pscom_req_t *req, pscom_msgtype_t msg_type)
{
	pscom_req_prepare_send_pending_inline(req, msg_type, 0);
}


static
void pscom_req_prepare_rma_write(pscom_req_t *req)
{
	req->pub.xheader_len = sizeof(req->pub.xheader.rma_write);
}


/*
 * Request queueing network side
 */

static
void _check_readahead(pscom_con_t *con, size_t len)
{
	if (con->in.readahead_size < len) {
		con->in.readahead.iov_base = realloc(con->in.readahead.iov_base, len);
		con->in.readahead_size = len;
		if (!con->in.readahead.iov_base) {
			perror("allocate mem");
			exit(1);
		}
	}
}


int _pscom_update_recv_req(pscom_req_t *req)
{
	if (is_recv_req_done(req)) {
		_pscom_recv_req_done(req);
		return 1;
	}
	return 0;
}


static
void _pscom_update_in_recv_req(pscom_con_t *con)
{
	pscom_req_t *req = con->in.req;
	if (req && is_recv_req_done(req)) {
		con->in.skip = req->skip;
		con->in.req = NULL;

		_pscom_recv_req_done(req);
		_pscom_recv_req_cnt_check_stop(con);
	}
}


static inline
void _pscom_req_bcast_done(pscom_req_t *req)
{
	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
		    pscom_debug_req_str(req)));

	req->pub.state |= PSCOM_REQ_STATE_DONE;
	_pscom_step();
	pscom_req_free(req);
}


pscom_req_t *_pscom_generate_recv_req(pscom_con_t *con, pscom_header_net_t *nh)
{
	pscom_req_t *req;

	pscom.stat.gen_reqs++;

	req = pscom_req_create(nh->xheader_len, nh->data_len);
	req->pub.state = PSCOM_REQ_STATE_GRECV_REQUEST;
	/* freed inside genreq_merge() */

	req->pub.data = req->pub.user;
	req->pub.data_len = nh->data_len;
	req->pub.xheader_len = nh->xheader_len;
	req->partner_req = NULL;

	D_TR(printf("%s:%u:%s(). %s xheaderlen=%d\n", __FILE__, __LINE__, __func__,
		    pscom_debug_req_str(req), req->pub.xheader_len));

	return req;
}


static
void genreq_merge_header(pscom_req_t *newreq, pscom_req_t *genreq)
{
	pscom_req_prepare_recv(newreq, &genreq->pub.header, genreq->pub.connection);
}


void pscom_greq_check_free(pscom_con_t *con, pscom_req_t *greq)
{
	assert(greq->pub.state & PSCOM_REQ_STATE_GRECV_REQUEST);
	if (greq == con->in.req_locked) return; // greq locked by plugin
	if (!(greq->pub.state & PSCOM_REQ_STATE_GRECV_MERGED)) return; // greq not merged yet

	pscom_req_free(greq);
}


static
void _genreq_merge(pscom_req_t *newreq, pscom_req_t *genreq)
{
	pscom_con_t *con = get_con(genreq->pub.connection);

//	printf("GHeader: " RED "%s" NORM "\n", pscom_dumpstr(&genreq->pub.header, genreq->pub.xheader_len + sizeof(genreq->pub.header)));
	D_TR(printf("%s:%u:%s(gen: %s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(genreq)));
	assert(genreq->magic == MAGIC_REQUEST);

	genreq_merge_header(newreq, genreq);

	/* copy already received data: */

	pscom_req_write(newreq, genreq->pub.data, (char*)genreq->cur_data.iov_base - (char *)genreq->pub.data);

	newreq->pub.state |= genreq->pub.state;

	if (con->in.req == genreq) {
		// replace existing genreq by newreq;
		// Receiving started, but not done.
		assert((genreq->pub.state & (PSCOM_REQ_STATE_IO_STARTED | PSCOM_REQ_STATE_IO_DONE))
			== PSCOM_REQ_STATE_IO_STARTED);

		// further receives to newreq
		con->in.req = newreq;

		// Continue receive on this connection (Maybe duplicate start)
		_pscom_recv_req_cnt_check_start(con);
	} else if (genreq->partner_req) {
		assert(genreq->partner_req->magic == MAGIC_REQUEST);

		/* genreq from rendezvous. Now request the data: */
		// ToDo: check: will _pscom_rendezvous_read_data() be called, in case of con->in.req == genreq?

		_pscom_rendezvous_read_data(newreq, genreq->partner_req);
		genreq->partner_req = NULL;
	} else {
		/* request done. */
		assert(genreq->pub.state & (PSCOM_REQ_STATE_IO_DONE));
		_pscom_recv_req_done(newreq);
	}

	pscom.stat.gen_reqs_used++;

	_pscom_grecv_req_done(genreq);
	pscom_greq_check_free(con, genreq);
}


void _pscom_genreq_abort_rendezvous_rma_reads(pscom_con_t *con)
{
	struct list_head *pos;

	list_for_each(pos, &con->net_recvq_user) {
		pscom_req_t *genreq = list_entry(pos, pscom_req_t, next);
		if (genreq->partner_req) {
			assert(genreq->partner_req->magic == MAGIC_REQUEST);
			_pscom_rendezvous_read_data_abort_arch(genreq->partner_req);
		}
	}
}


static
pscom_req_t *pscom_get_default_recv_req(pscom_con_t *con, pscom_header_net_t *nh)
{
	pscom_request_t *(*default_recv)(pscom_connection_t *connection,
					 pscom_header_net_t *header_net)
		= get_sock(con->pub.socket)->pub.ops.default_recv;
	if (default_recv) {
		pscom_request_t *ureq;
		pscom_req_t *req;

		ureq = default_recv(&con->pub, nh);
		if (ureq) {
			assert(ureq->state & PSCOM_REQ_STATE_DONE);
			ureq->state = PSCOM_REQ_STATE_RECV_REQUEST;
			ureq->connection = &con->pub;
			ureq->socket = con->pub.socket;
			req = get_req(ureq);
			assert(req->magic == MAGIC_REQUEST);
		} else {
			req = NULL;
		}

		return req;
	} else {
		return NULL;
	}
}


static inline
pscom_req_t *_pscom_get_user_receiver(pscom_con_t *con, pscom_header_net_t *nh)
{
	pscom_req_t *req;
	req = pscom_get_default_recv_req(con, nh);
	if (!req) {
		req = _pscom_recvq_user_find_and_deq(con, nh);

		if (!req) {
			/* generate a request */
			req = _pscom_generate_recv_req(con, nh);

			assert(req);
			_pscom_net_recvq_user_enq(con, req);
		}
	}

	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req)));
	return req;
}


pscom_req_t *_pscom_get_ctrl_receiver(pscom_con_t *con, pscom_header_net_t *nh)
{
	pscom_req_t *req;

	req = _pscom_recvq_ctrl_find_and_deq(con, nh);
	if (!req) {
		/* generate a request */
		req = _pscom_generate_recv_req(con, nh);

		assert(req);
		_pscom_net_recvq_ctrl_enq(con, req);
	}

	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req)));
	return req;
}


static
pscom_req_t *pscom_get_rma_write_receiver(pscom_con_t *con, pscom_header_net_t *nh)
{
	pscom_req_t *req;
	pscom_xheader_rma_write_t *rma_header = &nh->xheader->rma_write;

	req = pscom_req_create(0, 0);
	req->pub.state = PSCOM_REQ_STATE_RMA_WRITE_REQUEST | PSCOM_REQ_STATE_PASSIVE_SIDE;

	/* freed in io_done() */
	req->pub.data = rma_header->dest;
	req->pub.data_len = nh->data_len;
	req->pub.xheader_len = 0;
	req->pub.ops.io_done = pscom_request_free;

	D_TR(printf("%s:%u:%s() %s dest=%p, len=%d\n", __FILE__, __LINE__, __func__,
		    pscom_debug_req_str(req), req->pub.data, req->pub.data_len));

	return req;
}


static
void _send_rma_read_answer(pscom_req_t *req_answer)
{
	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req_answer)));
	assert(req_answer->magic == MAGIC_REQUEST);
	pscom_mverify(req_answer);

	req_answer->pub.ops.io_done = pscom_request_free;

	_pscom_post_send_direct_inline(get_con(req_answer->pub.connection), req_answer, PSCOM_MSGTYPE_RMA_READ_ANSWER);
}


static
void send_rma_read_answer(pscom_request_t *request_answer)
{
	pscom_req_t *req_answer = get_req(request_answer);

	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req_answer)));
	assert(req_answer->magic == MAGIC_REQUEST);
	pscom_mverify(req_answer);

	req_answer->pub.ops.io_done = pscom_request_free;

	pscom_post_send_direct(req_answer, PSCOM_MSGTYPE_RMA_READ_ANSWER);
}


static
void _rma_write_done(void *priv)
{
	pscom_req_t *req_answer = (pscom_req_t *)priv;
	/* rma_write_done() could be called anytime by the lower level
	 * protocol driver. The pscom.io_doneq queue is used to
	 * postpone the pscom_post_send_direct(PSCOM_MSGTYPE_RMA_READ_ANSWER)
	 * call until it is safe to call.
	 */
	req_answer->pub.ops.io_done = send_rma_read_answer;
	_pscom_req_done(req_answer);
}


static
pscom_req_t *_pscom_get_rma_read_receiver(pscom_con_t *con, pscom_header_net_t *nh)
{
	pscom_rendezvous_msg_t *rd_msg = (pscom_rendezvous_msg_t *)nh->xheader;
	pscom_req_t *req_answer = pscom_req_create(sizeof(pscom_xheader_rma_read_answer_t), 0);

	req_answer->pub.xheader.rma_read_answer.id = rd_msg->id;
	req_answer->pub.connection = &con->pub;

	if (nh->xheader_len == pscom_rendezvous_msg_size(0)) {
	fallback_to_sw_rndv:
		req_answer->pub.data_len = rd_msg->data_len;
		req_answer->pub.data = rd_msg->data;

		D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req_answer)));

		_send_rma_read_answer(req_answer);
	} else {
		assert(con->rma_write);

		req_answer->pub.data_len = 0;
		req_answer->pub.data = NULL;

		D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req_answer)));

		pscom_mverify(req_answer);
		if(con->rma_write(con, rd_msg->data, rd_msg, _rma_write_done, req_answer)) {
			pscom.stat.fallback_to_sw_rndv++;
			goto fallback_to_sw_rndv;
		}
	}
	return NULL;
}


static
pscom_req_t *_pscom_get_rma_read_answer_receiver(pscom_con_t *con, pscom_header_net_t *nh)
{
	pscom_req_t *req;
	pscom_xheader_rma_read_answer_t *rma_answer;

	assert(!list_empty(con->recvq_rma.next));

	req = nh->xheader->rma_read_answer.id;

	assert(_pscom_recvq_rma_contains(con, req));

	if (con->rma_mem_deregister && req->rndv_data) {
		pscom_rendezvous_data_t *rd = (pscom_rendezvous_data_t *) req->rndv_data;

		assert(req->pub.data_len > pscom_rendezvous_msg_size(0));

		con->rma_mem_deregister(con, rd);
		pscom_free(rd);
		req->rndv_data = NULL;
	}

	_pscom_recvq_rma_deq(con, req);

	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req)));
	return req;
}


static
void pscom_rendezvous_read_data_io_done(pscom_request_t *request)
{
	pscom_req_t *req = get_req(request);
	pscom_req_t *user_req = req->partner_req;

	pscom_rendezvous_data_t *rd =
		(pscom_rendezvous_data_t *) req->pub.user;

	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req)));
	assert(req->magic == MAGIC_REQUEST);
	assert(user_req->magic == MAGIC_REQUEST);
	pscom_recv_req_done(user_req);

	/* rewrite rendezvous_req for rendezvous fin message */
	req->pub.xheader.ren_fin.id = rd->msg.id;
	req->pub.xheader_len = sizeof(req->pub.xheader.ren_fin);

	req->pub.data = NULL;
	req->pub.data_len = 0;

	/* rendezvous_req->pub.connection already set */
	req->pub.ops.io_done = pscom_request_free;

	pscom_post_send_direct(req, PSCOM_MSGTYPE_RENDEZVOUS_FIN);
}


static inline
void _pscom_post_rma_read(pscom_req_t *req);


static
void _pscom_rendezvous_read_data(pscom_req_t *user_recv_req, pscom_req_t *rendezvous_req)
{
	pscom_rendezvous_data_t *rd =
		(pscom_rendezvous_data_t *) rendezvous_req->pub.user;

	size_t to_read = pscom_min(rd->msg.data_len, user_recv_req->pub.data_len);
	pscom_con_t *con = get_con(rendezvous_req->pub.connection);
	assert(rendezvous_req->magic == MAGIC_REQUEST);
	assert(user_recv_req->magic == MAGIC_REQUEST);

	D_TR(printf("%s:%u:%s(user: %s", __FILE__, __LINE__, __func__, pscom_debug_req_str(user_recv_req)));
	D_TR(printf(", rndv: %s)\n", pscom_debug_req_str(rendezvous_req)));

	/* rewrite the rendezvous_req for read rma (read data) */
	rendezvous_req->pub.data_len = to_read;
	rendezvous_req->pub.data = user_recv_req->pub.data;

	/* rendezvous_req->pub.connection already set */
	rendezvous_req->pub.xheader.rma_read.src = rd->msg.data;
	rendezvous_req->pub.xheader.rma_read.src_len = to_read;
	rendezvous_req->pub.xheader.rma_read.id = rd->msg.id;

	rendezvous_req->pub.ops.io_done = pscom_rendezvous_read_data_io_done;
	rendezvous_req->partner_req = user_recv_req;

	if (rd->use_arch_read && con->rma_read) {
//#define RMA_CNT
#ifdef RMA_CNT
		static unsigned work_cnt = 0;
		static unsigned fail_cnt = 0;
#endif
		perf_add("rndv_con_rma_read");
		if (con->rma_read(rendezvous_req, rd))  {
#ifdef RMA_CNT
			fail_cnt++;
			if (fail_cnt % 1000 == 0) {
				printf("WorkCnt:%u, FailCnt: %u\n", work_cnt, fail_cnt);
			}
#endif
			pscom.stat.fallback_to_sw_rndv++;
			goto rma_read_fallback;
		}
#ifdef RMA_CNT
		work_cnt++;
		if (work_cnt % 1000 == 0) {
			printf("WorkCnt:%u, FailCnt: %u\n", work_cnt, fail_cnt);
		}
#endif
	} else {
	rma_read_fallback:
		perf_add("rndv_fallback_rma_read");
		_pscom_post_rma_read(rendezvous_req);
	}
}


static
void _pscom_rendezvous_read_data_abort_arch(pscom_req_t *rendezvous_req)
{
	pscom_rendezvous_data_t *rd =
		(pscom_rendezvous_data_t *) rendezvous_req->pub.user;

	assert(rendezvous_req->magic == MAGIC_REQUEST);

	// Do not use any remote memory information for rma_read anymore:
	rd->use_arch_read = 0;
}


static
void pscom_rendezvous_receiver_io_done(pscom_request_t *req)
{
	pscom_rendezvous_data_t *rd =
		(pscom_rendezvous_data_t *) req->user;

	perf_add("rndv_receiver_io_done");
	assert(get_req(req)->magic == MAGIC_REQUEST);

	/* rewrite the header */
	req->header.msg_type = PSCOM_MSGTYPE_USER;
	/* req->header.xheader_len already set */
	req->header.data_len = PSCOM_DATA_LEN_MASK & rd->msg.data_len;

	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(get_req(req))));

	pscom_lock(); {
		/* Use the rewritten header to search for a recv request: */
		pscom_req_t *user_req = _pscom_get_user_receiver(get_con(req->connection),
								 &req->header);
		assert(user_req);
		pscom_req_prepare_recv(user_req, &req->header, req->connection);

		if (!(user_req->pub.state & PSCOM_REQ_STATE_GRECV_REQUEST)) {
			/* found user receive request. Initiate a
			   rma_read. */
			_pscom_rendezvous_read_data(user_req, get_req(req));
		} else {
			/* found generated request.
			   Continue after user post a recv. */
			user_req->partner_req = get_req(req);
			user_req->pub.state |= PSCOM_REQ_STATE_RENDEZVOUS_REQUEST;
		}
	} pscom_unlock();
}


static
pscom_req_t *pscom_get_rendezvous_receiver(pscom_con_t *con, pscom_header_net_t *nh)
{
	pscom_req_t *req;

	perf_add("rndv_receiver");
	req = pscom_req_create(nh->xheader_len, sizeof(pscom_rendezvous_data_t));
	pscom_rendezvous_data_t *rd = (pscom_rendezvous_data_t *) req->pub.user;

	req->pub.state = PSCOM_REQ_STATE_RENDEZVOUS_REQUEST | PSCOM_REQ_STATE_PASSIVE_SIDE;
	assert(nh->data_len <= sizeof(rd->msg));

	req->pub.data = &rd->msg;
	req->pub.data_len = nh->data_len;
	req->pub.xheader_len = nh->xheader_len;

	req->pub.ops.io_done = pscom_rendezvous_receiver_io_done;

	// Received additional rendezvous data from network arch? Yes: use arch read.
	rd->use_arch_read = nh->data_len > pscom_rendezvous_msg_size(0);

	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req)));
	return req;
}


static
pscom_req_t *_pscom_get_rendezvous_fin_receiver(pscom_con_t *con, pscom_header_net_t *nh)
{
	pscom_req_t *user_req = nh->xheader->ren_fin.id;
	pscom_req_t *req = user_req->partner_req;
	pscom_rendezvous_data_t *rd = (pscom_rendezvous_data_t *)req->pub.user;

	assert (req->magic == MAGIC_REQUEST);
	assert (user_req->magic == MAGIC_REQUEST);

	if (con->rma_mem_deregister && (req->pub.data_len > pscom_rendezvous_msg_size(0))) {
		con->rma_mem_deregister(con, rd);
	}

	_pscom_recv_req_cnt_dec(con); // inc in pscom_post_send_rendezvous()
	pscom_request_free(&req->pub);

	perf_add("rndv_send_done");
	_pscom_send_req_done(user_req); // done

	return NULL;
}


static
pscom_req_t *_pscom_get_eof_receiver(pscom_con_t *con, pscom_header_net_t *nh)
{
	DPRINT(D_DBG_V, "EOF recv   %s via %s",
	       pscom_con_str(&con->pub),
	       pscom_con_type_str(con->pub.type));

	con->state.eof_received = 1;
	pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_EOF);
	return NULL;
}


static
void _pscom_req_suspend_io_done(pscom_request_t *request)
{
	pscom_req_t *req = get_req(request);
	pscom_con_t *con = get_con(req->pub.connection);
	pscom_lock(); {
		_pscom_con_suspend_received(con, &req->pub.xheader.user, req->pub.xheader_len);
	} pscom_unlock();

	pscom_req_free(req);
}


static
pscom_req_t *_pscom_get_suspend_receiver(pscom_con_t *con, pscom_header_net_t *nh)
{
	pscom_req_t *req;

	if (!nh->xheader_len) return NULL; // Ignore message sent to resume the connection.

	req = pscom_req_create(nh->xheader_len, 0);

	req->pub.state = PSCOM_REQ_STATE_RECV_REQUEST;
	assert(nh->data_len == 0);

	req->pub.data = NULL;
	req->pub.data_len = 0;
	req->pub.xheader_len = nh->xheader_len;

	req->pub.ops.io_done = _pscom_req_suspend_io_done;

	return req;
}


/* return a request, which will receive this message.
   return NULL if this message should be discarded */
static
pscom_req_t *_pscom_get_recv_req(pscom_con_t *con, pscom_header_net_t *nh)
{
	pscom_req_t *req;
	D_TR(printf("%s:%u:%s(con:%p, nh->msg_type:%s)\n", __FILE__, __LINE__, __func__,
		    con, pscom_msgtype_str(nh->msg_type)));

	if (nh->msg_type == PSCOM_MSGTYPE_USER) {
		req = _pscom_get_user_receiver(con, nh);
		pscom_req_prepare_recv(req, nh, &con->pub);
	} else {
		switch (nh->msg_type) {
		case PSCOM_MSGTYPE_RMA_WRITE:
			req = pscom_get_rma_write_receiver(con, nh);
			break;
		case PSCOM_MSGTYPE_RMA_READ:
			req = _pscom_get_rma_read_receiver(con, nh);
			break;
		case PSCOM_MSGTYPE_RMA_READ_ANSWER:
			req = _pscom_get_rma_read_answer_receiver(con, nh);
			break;
		case PSCOM_MSGTYPE_RENDEZVOUS_REQ:
			req = pscom_get_rendezvous_receiver(con, nh);
			break;
		case PSCOM_MSGTYPE_RENDEZVOUS_FIN:
			req = _pscom_get_rendezvous_fin_receiver(con, nh);
			break;
		case PSCOM_MSGTYPE_BCAST:
			req = _pscom_get_bcast_receiver(con, nh);
			break;
		case PSCOM_MSGTYPE_BARRIER:
			req = _pscom_get_ctrl_receiver(con, nh);
			break;
		case PSCOM_MSGTYPE_EOF:
			req = _pscom_get_eof_receiver(con, nh);
			break;
		case PSCOM_MSGTYPE_SUSPEND:
			req = _pscom_get_suspend_receiver(con, nh);
			break;
		case PSCOM_MSGTYPE_GW_ENVELOPE:
			req = _pscom_get_gw_envelope_receiver ? _pscom_get_gw_envelope_receiver(con, nh) : NULL;
			break;
		case PSCOM_MSGTYPE_GW_CTRL:
			req = _pscom_get_gw_ctrl_receiver ? _pscom_get_gw_ctrl_receiver(con, nh) : NULL;
			break;
		default:
			DPRINT(D_BUG, "Receive unknown msg_type %u", nh->msg_type);
			req = NULL;
		}
		if (req) pscom_req_prepare_recv(req, nh, &con->pub);
	}

	D_TR(printf("%s:%u:%s(con:%p) : %s\n", __FILE__, __LINE__, __func__,
		    con, pscom_debug_req_str(req)));
	return req;
}


// return true at the end of each message
int pscom_read_is_at_message_start(pscom_con_t *con)
{
	return !con->in.req && !con->in.skip;
}


void
pscom_read_get_buf(pscom_con_t *con, char **buf, size_t *len)
{
	if (con->in.req) {
		pscom_req_t *req = con->in.req;
		*buf = req->cur_data.iov_base;
		*len = req->cur_data.iov_len;
		assert(req->cur_data.iov_len > 0);
	} else if (!con->in.skip) {
		size_t readlen = pscom.env.readahead;

		if (con->in.readahead.iov_len >= sizeof(pscom_header_net_t)) {
			readlen = header_length((pscom_header_net_t *)con->in.readahead.iov_base);
		}
		_check_readahead(con, readlen);

		*buf = con->in.readahead.iov_base + con->in.readahead.iov_len;
		*len = readlen - con->in.readahead.iov_len;
	} else {
		size_t rlen = pscom_min(pscom.env.skipblocksize, con->in.skip);
		_check_readahead(con, rlen);
		*buf = con->in.readahead.iov_base;
		*len = rlen;
	}

	D_TR(printf("%s:%u:%s(con, *buf=%p, *len=%zu)\n", __FILE__, __LINE__, __func__,
		    *buf, *len));
}


void
pscom_read_get_buf_locked(pscom_con_t *con, char **buf, size_t *len)
{
	pscom_read_get_buf(con, buf, len);

	if (con->in.req && (con->in.req->pub.state & PSCOM_REQ_STATE_GRECV_REQUEST)) {
		/* Only generated requests should be locked. Only
		   _genreq_merge() check for req->in.req_lock. All
		   other requests are already locked, until they are done
		   (pscom_req_is_done() == true) */
		assert(!con->in.req_locked);
		con->in.req_locked = con->in.req;
	}
}


void
pscom_read_done_unlock(pscom_con_t *con, char *buf, size_t len)
{
	pscom_read_done(con, buf, len);

	if (con->in.req_locked) {
		pscom_req_t *req = con->in.req_locked;
		con->in.req_locked = NULL;
		pscom_greq_check_free(con, req);
	}
}


void
pscom_read_done(pscom_con_t *con, char *buf, size_t len)
{
	pscom_req_t *req = con->in.req;

	D_TR(printf("%s:%u:%s(con, buf=%p, len=%zu, %s)\n", __FILE__, __LINE__, __func__,
		    buf, len, pscom_dumpstr(buf, pscom_min(len, 32))));

	if (!len) goto err_eof;

	if (req) {
		size_t _len;

		_len = pscom_req_write(req, buf, len);
		len -= _len;
		buf += _len;

		_pscom_update_in_recv_req(con);

		assert(!con->in.readahead.iov_len);

		if (!len) return;

		assert(!con->in.req);
	}

	if (con->in.readahead.iov_len) {
		char *dest;
		// append buf,len to readahead buffer
		assert(!con->in.skip);

		_check_readahead(con, con->in.readahead.iov_len + len);
		dest = ((char *)con->in.readahead.iov_base) + con->in.readahead.iov_len;
		if (buf != dest) {
			memcpy(dest, buf, len);
		}

		con->in.readahead.iov_len += len;

		buf = con->in.readahead.iov_base;
		len = con->in.readahead.iov_len;
	} else if (con->in.skip) {
		if (con->in.skip < len) {
			buf += con->in.skip;
			len -= con->in.skip;
			con->in.skip = 0;
		} else {
			con->in.skip -= len;
			return;
		}
	}


	while (header_complete(buf, len)) {
		// consume data
		pscom_header_net_t *header = (pscom_header_net_t *)buf;
		size_t hlen = header_length(header);
		size_t l;

		con->in.req = _pscom_get_recv_req(con, header);
		req = con->in.req;

		buf += hlen;
		len -= hlen;

		if (req) {
			req->pub.state |= PSCOM_REQ_STATE_IO_STARTED;
			l = pscom_req_write(req, buf, len);
			buf += l;
			len -= l;
		} else if (len) {
			/* Skip message */
			size_t skip = pscom_min(header->data_len, len);

			buf += skip;
			len -= skip;
			con->in.skip = header->data_len - skip;
		}

		_pscom_update_in_recv_req(con);
		assert(!con->in.skip || !len);
	}


	if (len && (con->in.readahead.iov_base != buf)) {
		// save unused data
		_check_readahead(con, len);
		memmove(con->in.readahead.iov_base, buf, len);
	}

	con->in.readahead.iov_len = len;

	return;
	/* --- */
err_eof:
	if (!con->state.eof_received && !con->state.close_called) {
		/* Received an transport layer eof, without
		   a previous received PSCOM_MSGTYPE_EOF or call to close. -> Throw an IOERROR: */
		pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_IOERROR);
	}
	return;
}


pscom_req_t *pscom_write_get_iov(pscom_con_t *con, struct iovec iov[2])
{
	if (!list_empty(&con->sendq)) {
		pscom_req_t *req = list_entry(con->sendq.next, pscom_req_t, next);

		iov[0] = req->cur_header;
		iov[1] = req->cur_data;

		if (req->cur_data.iov_len || req->cur_header.iov_len) {
			req->pub.state |= PSCOM_REQ_STATE_IO_STARTED;
			return req;
		} else {
			/* Nothing to send. Wait for more data (up
			   to req->skip bytes) */
			con->write_stop(con);
			return 0;
		}
	} else {
		con->write_stop(con);
		return 0;
	}
}


void pscom_write_done(pscom_con_t *con, pscom_req_t *req, size_t len)
{
	pscom_forward_iov(&req->cur_header, len);

	if (!req->cur_data.iov_len && !req->cur_header.iov_len && !req->skip) {
		_pscom_sendq_deq(con, req);
		if (!req->pending_io) _pscom_send_req_done(req); // done
	}
}


void pscom_write_pending(pscom_con_t *con, pscom_req_t *req, size_t len)
{
	pscom_forward_iov(&req->cur_header, len);

	req->pending_io++;
	if (!req->cur_data.iov_len && !req->cur_header.iov_len && !req->skip) {
		_pscom_sendq_deq(con, req);
		_pscom_pendingio_enq(con, req);
	}
}


void pscom_write_pending_done(pscom_con_t *con, pscom_req_t *req)
{
	req->pending_io--;
	if (!req->pending_io && !req->cur_data.iov_len && !req->cur_header.iov_len && !req->skip &&
	    !(req->pub.state & PSCOM_REQ_STATE_IO_DONE)) {
		_pscom_pendingio_deq(con, req);
		_pscom_send_req_done(req); // done
	}
}


void pscom_write_pending_error(pscom_con_t *con, pscom_req_t *req)
{
	req->pub.state |= PSCOM_REQ_STATE_ERROR;
	pscom_write_pending_done(con, req);
}


/* Use con to send req with msg_type. pscom_lock must be held. */
static inline
void _pscom_post_send_direct_inline(pscom_con_t *con, pscom_req_t *req, pscom_msgtype_t msg_type)
{
	pscom_req_prepare_send(req, msg_type); // build header and iovec
	req->pub.connection = &con->pub;

	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
		    pscom_debug_req_str(req)));

	_pscom_sendq_enq(con, req);
}


/* Use con to send req with msg_type. pscom_lock must be held. */
void _pscom_post_send_direct(pscom_con_t *con, pscom_req_t *req, pscom_msgtype_t msg_type)
{
	_pscom_post_send_direct_inline(con, req, msg_type);
}


/* inline version of pscom_post_send_direct */
static inline
void pscom_post_send_direct_inline(pscom_req_t *req, pscom_msgtype_t msg_type)
{
	pscom_req_prepare_send(req, msg_type); // build header and iovec

	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__,
		    pscom_debug_req_str(req)));

	pscom_lock(); {
		_pscom_sendq_enq(get_con(req->pub.connection), req);
	} pscom_unlock();
}


/* _pscom_post_send_direct version, but pscom_lock NOT held. */
void pscom_post_send_direct(pscom_req_t *req, pscom_msgtype_t msg_type)
{
	pscom_post_send_direct_inline(req, msg_type);
}


static
void _pscom_send(pscom_con_t *con, pscom_msgtype_t msg_type,
		 void *xheader, size_t xheader_len,
		 void *data, size_t data_len)
{
	pscom_req_t *req;

	req = pscom_req_create(xheader_len, data_len);

	req->pub.xheader_len = xheader_len;
	req->pub.data_len = data_len;
	req->pub.data = req->pub.user;

	memcpy(&req->pub.xheader, xheader, xheader_len);
	_pscom_memcpy_from_user(req->pub.data, data, data_len);

	req->pub.ops.io_done = pscom_request_free;

	_pscom_post_send_direct_inline(con, req, msg_type);
}


struct pscom_req_send_inplace_rdata
{
	void (*io_done)(pscom_req_state_t state, void *priv);
	void *priv;
	char data[0];
};


static
void pscom_send_inplace_io_done(pscom_request_t *req)
{
	struct pscom_req_send_inplace_rdata *rdata =
		(struct pscom_req_send_inplace_rdata *)req->user;

	if (rdata->io_done) {
		rdata->io_done(req->state, rdata->priv);
	}

	pscom_request_free(req);
}


void _pscom_send_inplace(pscom_con_t *con, pscom_msgtype_t msg_type,
			 void *xheader, size_t xheader_len,
			 void *data, size_t data_len,
			 void (*io_done)(pscom_req_state_t state, void *priv), void *priv)
{
	pscom_req_t *req;

	struct pscom_req_send_inplace_rdata *rdata;

	req = pscom_req_create(xheader_len, sizeof(*rdata));

	req->pub.xheader_len = xheader_len;
	req->pub.data_len = data_len;
	req->pub.data = data;
	rdata = (struct pscom_req_send_inplace_rdata *)req->pub.user;

	rdata->io_done = io_done;
	rdata->priv = priv;

	memcpy(&req->pub.xheader, xheader, xheader_len);

	req->pub.ops.io_done = pscom_send_inplace_io_done;

	_pscom_post_send_direct_inline(con, req, msg_type);
}


static
int _pscom_cancel_send(pscom_req_t *req)
{
	if (req->pub.state & PSCOM_REQ_STATE_IO_DONE) {
		return 0;
	}
	if (req->pub.state & PSCOM_REQ_STATE_IO_STARTED) {
		return 0;
	}

	_pscom_sendq_deq(get_con(req->pub.connection), req);

	req->pub.state |= PSCOM_REQ_STATE_CANCELED;
	_pscom_send_req_done(req); // done

	return 1;
}


static
int _pscom_cancel_recv(pscom_req_t *req)
{
	if (req->pub.state & PSCOM_REQ_STATE_IO_DONE) {
		return 0;
	}
	if (req->pub.state & PSCOM_REQ_STATE_IO_STARTED) {
		return 0;
	}

	assert(_pscom_recvq_user_is_inside(req));

	_pscom_recvq_user_deq(req);
	_pscom_recvq_any_cleanup(get_sock(req->pub.socket));

	req->pub.state |= PSCOM_REQ_STATE_CANCELED;
	_pscom_recv_req_done(req); // done

	return 1;
}


static inline
void pscom_post_send_rendezvous(pscom_req_t *user_req)
{

	pscom_req_t *req;
	pscom_rendezvous_data_t *rd;
	pscom_con_t *con = get_con(user_req->pub.connection);

	req = pscom_req_create(user_req->pub.xheader_len,
			       sizeof(pscom_rendezvous_data_t));

	pscom.stat.rendezvous_reqs++;

	req->pub.xheader_len = user_req->pub.xheader_len;
	req->pub.data_len = pscom_rendezvous_msg_size(0);
	req->pub.data = req->pub.user;

	D_TR(printf("%s:%u:%s(user:%s) ", __FILE__, __LINE__, __func__, pscom_debug_req_str(user_req)));
	D_TR(printf("rndv:%s\n", pscom_debug_req_str(req)));


	rd = (pscom_rendezvous_data_t *)req->pub.data;

	rd->msg.id = user_req;
	rd->msg.data = user_req->pub.data;
	rd->msg.data_len = user_req->pub.data_len;

	if (con->rma_mem_register && con->rma_mem_register_check && !con->rma_mem_register_check(con, rd)) {
		goto fallback_to_eager;
	}

	if (con->rma_read && con->rma_mem_register) {
		int len_arch = con->rma_mem_register(con, rd);
		if(!len_arch) goto fallback_to_eager;
		req->pub.data_len += len_arch;
	}

	memcpy(&req->pub.xheader, &user_req->pub.xheader, user_req->pub.xheader_len);

	req->pub.ops.io_done = NULL;

	user_req->partner_req = req;
	user_req->pub.state = PSCOM_REQ_STATE_RENDEZVOUS_REQUEST |
		PSCOM_REQ_STATE_SEND_REQUEST | PSCOM_REQ_STATE_POSTED;

	pscom_lock(); {
		_pscom_post_send_direct_inline(con, req, PSCOM_MSGTYPE_RENDEZVOUS_REQ);
		_pscom_recv_req_cnt_inc(con); // dec in _pscom_get_rendezvous_fin_receiver()
	} pscom_unlock();

	return;

fallback_to_eager:
	pscom_req_free(req);
	pscom.stat.fallback_to_eager++;
	pscom_post_send_direct_inline(user_req, PSCOM_MSGTYPE_USER);
}


static inline
void _pscom_post_rma_read(pscom_req_t *req)
{
	pscom_con_t *con = get_con(req->pub.connection);
	pscom_req_t *req_rma = pscom_req_create(sizeof(pscom_rendezvous_data_t), 0);
	pscom_rendezvous_data_t *rd = (pscom_rendezvous_data_t *)&req_rma->pub.xheader.user;
	unsigned len_arch = 0;

	req->pub.state = PSCOM_REQ_STATE_RMA_READ_REQUEST | PSCOM_REQ_STATE_POSTED;
	_pscom_recvq_rma_enq(con, req);

	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req)));

	rd->msg.id = req;
	req->rndv_data = NULL;

	if (con->rma_write && con->rma_mem_register) {

		rd->msg.data = req->pub.data;
		rd->msg.data_len = req->pub.data_len;

		if(!con->rma_mem_register_check || (con->rma_mem_register_check && con->rma_mem_register_check(con, rd))) {

			len_arch = con->rma_mem_register(con, rd);

			if(len_arch && con->rma_mem_deregister) {
				req->rndv_data = pscom_malloc(sizeof(pscom_rendezvous_data_t));
				memcpy(req->rndv_data, rd, sizeof(pscom_rendezvous_data_t)); // ToDo: _pscom_memcpy?
			}
		}

		if(!len_arch) {
			pscom.stat.fallback_to_sw_rndv++;
		}
	}

	rd->msg.data = req->pub.xheader.rma_read.src;
	rd->msg.data_len = req->pub.xheader.rma_read.src_len;

	req_rma->pub.xheader_len = pscom_rendezvous_msg_size(len_arch);
	req_rma->pub.ops.io_done = pscom_request_free;
	_pscom_post_send_direct(con, req_rma, PSCOM_MSGTYPE_RMA_READ);
}


/* post the receive request req.
   Receiving up to req->xheader_len bytes to req->xheader and
   up to req->data_len bytes to req->data from connection
   req->connection with message type req->header.msg_type.

   req->xheader_len
   req->xheader
   req->data_len
   req->data
   req->connection or req->connection==NULL and req->socket
   req->header.msg_type

   optional:
   req->ops.recv_accept
   req->ops.io_done
*/
void _pscom_post_recv_ctrl(pscom_req_t *req)
{
	pscom_req_t *genreq;

	assert(req->magic == MAGIC_REQUEST);
	assert(req->pub.state & PSCOM_REQ_STATE_DONE);
	assert(req->pub.connection != NULL);

	req->pub.state = PSCOM_REQ_STATE_RECV_REQUEST | PSCOM_REQ_STATE_POSTED;

	genreq = _pscom_net_recvq_ctrl_find(req);
	if (!genreq) {
		// Nothing received so far. Enqueue to recvq_ctrl.
		pscom_con_t *con = get_con(req->pub.connection);
		_pscom_recvq_ctrl_enq(con, req);
	} else {
		// Matching message already partial or in whole received.
		_pscom_net_recvq_ctrl_deq(genreq);
		_genreq_merge(req, genreq);
	}
}


void pscom_post_recv_ctrl(pscom_req_t *req)
{
	pscom_lock(); {
		_pscom_post_recv_ctrl(req);
	} pscom_unlock();
}


static
void _pscom_wait_any(void)
{
	if (pscom.stat.progresscounter ==
	    pscom.stat.progresscounter_check) {
		pscom_progress(-1);
	} else {
		pscom_progress(0);
		pscom.stat.progresscounter_check = pscom.stat.progresscounter;
	}
}

/*
******************************************************************************
*/

pscom_request_t *pscom_request_create(size_t max_xheader_len, size_t user_size)
{
	pscom_req_t *req;

	req = pscom_req_create(max_xheader_len, user_size);

	return req ? &req->pub : NULL;
}


__attribute__((visibility("default")))
void pscom_request_free(pscom_request_t *request)
{
	pscom_req_free(get_req(request));
}


void pscom_post_recv(pscom_request_t *request)
{
	pscom_req_t *req = get_req(request);
	assert(req->magic == MAGIC_REQUEST);
	assert(request->state & PSCOM_REQ_STATE_DONE);

	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req)));

	_pscom_stage_buffer(req, 0);

	pscom_lock(); {
		pscom_req_t *genreq;
		perf_add("pscom_post_recv");

		req->pub.state = PSCOM_REQ_STATE_RECV_REQUEST | PSCOM_REQ_STATE_POSTED;

		genreq = _pscom_net_recvq_user_find(req);

		if (!genreq) {
			// Nothing received so far. Enqueue receive reques.
			_pscom_recvq_user_enq(req);
		} else {
			// Matching message already partial or in whole received.
			_pscom_net_recvq_user_deq(genreq);
			_genreq_merge(req, genreq);
		}
	} pscom_unlock();
}


/* return 1, if there is a matching receive. 0 otherwise.
 * in case 1: copy also the message header
 * caller have to call _pscom_recv_req_cnt_{inc,dec}()! */
static
int _pscom_iprobe(pscom_req_t *req)
{
	int res;
	pscom_req_t *genreq;

	req->pub.state = PSCOM_REQ_STATE_RECV_REQUEST | PSCOM_REQ_STATE_POSTED;

	genreq = _pscom_net_recvq_user_find(req);

	if (!genreq) {
		/* not found: */
		res = 0;
	} else {
		res = 1;
		genreq_merge_header(req, genreq);
	}
	req->pub.state |= PSCOM_REQ_STATE_DONE;

	return res;
}


static
void _pscom_probe(pscom_req_t *req)
{
	while (!_pscom_iprobe(req)) {
		_pscom_wait_any();

		// short release of the lock to call done callbacks:
		pscom_lock_yield();
	}
}


static
unsigned int pscom_iprobe_progresscounter = ~0;
static
unsigned int pscom_iprobe_count = 0;

static inline int pscom_iprobe_make_progress(void)
{
	if (pscom_iprobe_progresscounter != pscom.stat.progresscounter) {
		pscom_iprobe_count = 0;
		pscom_iprobe_progresscounter = pscom.stat.progresscounter;
		return 1;
	} else {
		pscom_iprobe_count++;
		if (pscom_iprobe_count >= pscom.env.iprobe_count) {
			pscom_iprobe_count = 0;
			return 1;
		}
	}
	return 0;
}


/* return 1, if there is a matching receive. 0 otherwise. */
/* in case 1: copy also the message header */
int pscom_iprobe(pscom_request_t *request)
{
	pscom_req_t *req = get_req(request);
	int res;
	int make_progress;

	assert(req->magic == MAGIC_REQUEST);
	assert(request->state & PSCOM_REQ_STATE_DONE);

	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req)));

	if (request->connection) {
		/* probe on one connection */
		pscom_con_t *con = get_con(request->connection);

		pscom_lock(); {
			pscom.stat.probes++;
			make_progress = pscom_iprobe_make_progress();

			if (make_progress) {
				_pscom_recv_req_cnt_inc(con);
				pscom_progress(0);
			}

			res = _pscom_iprobe(req);

			if (make_progress) {
				_pscom_recv_req_cnt_dec(con);
			}

			pscom.stat.iprobes_ok += res;
		} pscom_unlock();
	} else {
		/* probe on all connections */
		if (request->socket) {

			pscom_sock_t *sock = get_sock(request->socket);

			pscom_lock(); {
				pscom.stat.probes++;
				pscom.stat.probes_any_source++;
				make_progress = pscom_iprobe_make_progress();

				if (make_progress) {
					_pscom_recv_req_cnt_any_inc(sock);
					pscom_progress(0);
				}

				res = _pscom_iprobe(req);
				if (make_progress) {
					_pscom_recv_req_cnt_any_dec(sock);
				}

				pscom.stat.iprobes_ok += res;
			} pscom_unlock();
		} else {
			pscom_lock(); {
				pscom.stat.probes++;
				pscom.stat.probes_any_source++;
				make_progress = pscom_iprobe_make_progress();

				if (make_progress) {
					_pscom_recv_req_cnt_any_global_inc();
					pscom_progress(0);
				}

				res = _pscom_iprobe(req);
				if (make_progress) {
					_pscom_recv_req_cnt_any_global_dec();
				}

				pscom.stat.iprobes_ok += res;
			} pscom_unlock();

		}
	}

	return res;
}


void pscom_probe(pscom_request_t *request)
{
	pscom_req_t *req = get_req(request);

	assert(req->magic == MAGIC_REQUEST);
	assert(request->state & PSCOM_REQ_STATE_DONE);

	while (!pscom_iprobe(request)) {
		pscom_lock(); {
			_pscom_wait_any();
		} pscom_unlock();
	}

	if (request->connection) {
		/* probe on one connection */
		pscom_con_t *con = get_con(request->connection);

		pscom_lock(); {
			pscom.stat.probes++;

			_pscom_recv_req_cnt_inc(con);
			_pscom_probe(req);
			_pscom_recv_req_cnt_dec(con);
		} pscom_unlock();
	} else {
		/* probe on all connections */
		if (request->socket) {

			pscom_sock_t *sock = get_sock(request->socket);

			pscom_lock(); {
				pscom.stat.probes++;
				pscom.stat.probes_any_source++;

				_pscom_recv_req_cnt_any_inc(sock);
				_pscom_probe(req);
				_pscom_recv_req_cnt_any_dec(sock);
			} pscom_unlock();
		} else {
			pscom_lock(); {
				pscom.stat.probes++;
				pscom.stat.probes_any_source++;

				_pscom_recv_req_cnt_any_global_inc();
				_pscom_probe(req);
				_pscom_recv_req_cnt_any_global_dec();
			} pscom_unlock();
		}
	}
}


void pscom_post_send(pscom_request_t *request)
{
	pscom_req_t *req = get_req(request);
	assert(req->magic == MAGIC_REQUEST);
	assert(request->state & PSCOM_REQ_STATE_DONE);
	assert(request->connection != NULL);

	_pscom_stage_buffer(req, 1);

	if (req->pub.data_len < get_con(request->connection)->rendezvous_size) {
		perf_add("reset_send_direct");
		pscom_post_send_direct_inline(req, PSCOM_MSGTYPE_USER);
	} else {
		perf_add("reset_send_rndv");
		pscom_post_send_rendezvous(req);
	}
}


void pscom_send(pscom_connection_t *connection,
		void *xheader, size_t xheader_len,
		void *data, size_t data_len)
{
	pscom_lock(); {
		_pscom_send(get_con(connection), PSCOM_MSGTYPE_USER,
			    xheader, xheader_len,
			    data, data_len);
	} pscom_unlock();
}


void pscom_send_inplace(pscom_connection_t *connection,
			void *xheader, size_t xheader_len,
			void *data, size_t data_len,
			void (*io_done)(pscom_req_state_t state, void *priv), void *priv)
{
	pscom_lock(); {
		_pscom_send_inplace(get_con(connection), PSCOM_MSGTYPE_USER,
				    xheader, xheader_len,
				    data, data_len,
				    io_done, priv);
	} pscom_unlock();
}


pscom_err_t pscom_recv(pscom_connection_t *connection, pscom_socket_t *socket,
		       void *xheader, size_t xheader_len,
		       void *data, size_t data_len)
{
	pscom_request_t *req = pscom_request_create(xheader_len, 0);
	pscom_err_t ret = PSCOM_ERR_IOERROR;

	if (!req) {
		return PSCOM_ERR_STDERROR;
	}

	req->xheader_len = xheader_len;
	// memcpy(req->xheader.user, xheader, xheader_len);
	req->data_len = data_len;
	req->data = data;
	req->connection = connection;
	req->socket = socket;

	pscom_post_recv(req);

	pscom_wait(req);

	if (pscom_req_successful(req)) {
		memcpy(xheader, &req->xheader.user, xheader_len);
		ret = PSCOM_SUCCESS;
	}

	pscom_request_free(req);

	return ret;
}


void pscom_flush(pscom_connection_t *connection)
{
	if (!connection) return;
	pscom_con_t *con = get_con(connection);
	pscom_lock(); {
		while (!list_empty(&con->sendq)) {
			_pscom_wait_any();

			// short release of the lock to call done callbacks:
			pscom_lock_yield();
		}
	} pscom_unlock();
}


void pscom_post_rma_write(pscom_request_t *request)
{
	pscom_req_t *req = get_req(request);
	assert(req->magic == MAGIC_REQUEST);
	assert(request->state & PSCOM_REQ_STATE_DONE);
	assert(request->connection != NULL);

	pscom_req_prepare_rma_write(req); // build header and iovec

	pscom_post_send_direct(req, PSCOM_MSGTYPE_RMA_WRITE);
}


void pscom_post_rma_read(pscom_request_t *request)
{
	pscom_req_t *req = get_req(request);
	assert(req->magic == MAGIC_REQUEST);
	assert(request->state & PSCOM_REQ_STATE_DONE);
	assert(request->connection != NULL);

	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req)));

	pscom_lock(); {
		_pscom_post_rma_read(req);
	} pscom_unlock();
}


void pscom_wait_any(void)
{
	pscom_lock(); {
		_pscom_wait_any();
	} pscom_unlock();
}


void pscom_wait(pscom_request_t *request)
{
	volatile pscom_req_state_t *state = &request->state;

	while (!(*state & PSCOM_REQ_STATE_DONE)) {
		pscom_wait_any();
	}
}


void pscom_wait_all(pscom_request_t **requests)
{
	while (*requests) {
		pscom_wait(*requests);
		requests++;
	}
}


int pscom_cancel_send(pscom_request_t *request)
{
	pscom_req_t *req = get_req(request);
	int res;
	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req)));
	assert(req->magic == MAGIC_REQUEST);
	assert(request->state & PSCOM_REQ_STATE_SEND_REQUEST);
	if (request->state & PSCOM_REQ_STATE_DONE) return 0;

	pscom_lock(); {
		res = _pscom_cancel_send(req);
	} pscom_unlock();

	return res;
}


int pscom_cancel_recv(pscom_request_t *request)
{
	pscom_req_t *req = get_req(request);
	int res;
	D_TR(printf("%s:%u:%s()\n", __FILE__, __LINE__, __func__));
	assert(req->magic == MAGIC_REQUEST);
	assert(request->state & PSCOM_REQ_STATE_RECV_REQUEST);
	if (request->state & PSCOM_REQ_STATE_DONE) return 0;

	pscom_lock(); {
		res = _pscom_cancel_recv(req);
	} pscom_unlock();

	return res;
}


int pscom_cancel(pscom_request_t *request)
{
	pscom_req_t *req = get_req(request);
	assert(req->magic == MAGIC_REQUEST);

	if (request->state & PSCOM_REQ_STATE_SEND_REQUEST) {
		return pscom_cancel_send(request);
	} else if (request->state & PSCOM_REQ_STATE_RECV_REQUEST) {
		return pscom_cancel_recv(request);
	}
	return 0;
}
