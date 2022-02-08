/*
 * ParaStation
 *
 * Copyright (C) 2014-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#define MXM_MSG_TAG  85


static int init_ctx(struct mxm_pp_context *ctx)
{
	mxm_context_opts_t *mxm_opts;
	mxm_ep_opts_t *ep_opts;
	mxm_error_t error;
	size_t mxm_ep_addr_len = sizeof(ctx->mxm_ep_addr);

	error = mxm_config_read_opts(&mxm_opts, &ep_opts, NULL, NULL, 0);
	if (error != MXM_OK) {
		fprintf(stderr, "Failed to parse options: %s\n", mxm_error_string(error));
		return -1;
	}

	if (!ctx->params.flag_no_optimization) {
		// Fast mode. Might be not portable.
		ep_opts->ud.ib.rx.queue_len = 1024;
		mxm_opts->async_mode     = MXM_ASYNC_MODE_SIGNAL;
	}

	error = mxm_init(mxm_opts, &ctx->mxm_mxmh);
	if (error != MXM_OK) {
		fprintf(stderr, "Failed to create MXM: %s\n", mxm_error_string(error));
		return -1;
	}

	error = mxm_ep_create(ctx->mxm_mxmh, ep_opts, &ctx->mxm_ep);
	if (error != MXM_OK) {
		fprintf(stderr, "Failed to create endpoint: %s\n", mxm_error_string(error));
		return -1;
	}

	error = mxm_ep_get_address(ctx->mxm_ep, ctx->mxm_ep_addr,
				   &mxm_ep_addr_len);
	if (error != MXM_OK) {
		fprintf(stderr, "Failed to get endpoint address : %s\n",
			mxm_error_string(error));
		return -1;
	}

	/* allocate memory for rdma */
	ctx->mem_access_buf = NULL;
	ctx->mem_access_buf_size = sizeof(msg_buf_t) * 2;
#if 1
	ctx->mem_access_buf = malloc(ctx->mem_access_buf_size);
	printf("Using unmapped memory\n");
#else
	error = mxm_mem_map(ctx->mxm_mxmh, &ctx->mem_access_buf, &ctx->mem_access_buf_size,
			    0, NULL, 0);
	if (error != MXM_OK) {
		fprintf(stderr, "Failed to allocate memory: %s\n", mxm_error_string(error));
		return -1;
	}

	error = mxm_mem_get_key(ctx->mxm_mxmh, ctx->mem_access_buf, &ctx->mem_access_buf_mkey);
	if (error != MXM_OK) {
		fprintf(stderr, "Failed to get memory key: %s.\n", mxm_error_string(error));
		return -1;
	}
#endif
	mxm_config_free_context_opts(mxm_opts);
	mxm_config_free_ep_opts(ep_opts);
	return 0;
}


static void cleanup_ctx(struct mxm_pp_context *ctx)
{
	mxm_mem_unmap(ctx->mxm_mxmh, ctx->mem_access_buf, ctx->mem_access_buf_size, 0);

	mxm_mq_destroy(ctx->mxm_mq);
	mxm_ep_disconnect(ctx->mxm_conn);
	mxm_ep_destroy(ctx->mxm_ep);
	mxm_cleanup(ctx->mxm_mxmh);
}


static int connect_eps(struct mxm_pp_context *ctx)
{
    mxm_error_t error;

    error = mxm_ep_connect(ctx->mxm_ep, ctx->mxm_remote_ep_addr, &ctx->mxm_conn);
    if (error != MXM_OK) {
	    fprintf(stderr, "mxm_ep_connect() failed : %s.\n",
		    mxm_error_string(error));
	    return -1;
    }

    error = mxm_mq_create(ctx->mxm_mxmh, 0x5115, &ctx->mxm_mq);
    if (error != MXM_OK) {
	    fprintf(stderr, "Failed to create MQ: %s.\n", mxm_error_string(error));
	    return -1;
    }

    error = mxm_ep_wireup(ctx->mxm_ep);
    if (error != MXM_OK) {
	fprintf(stderr, "Failed to wire-up all connections: %s.\n", mxm_error_string(error));
	return -1;
    }
    return 0;
}


static void init_req_buffer(struct mxm_pp_context *ctx, mxm_req_base_t *req,
			    void *data, unsigned data_len)
{
	size_t offset, iovsize, remainder;
	unsigned i;

	/* Initialize request fields */
	req->state        = MXM_REQ_NEW;
	req->mq           = ctx->mxm_mq;
	req->conn         = NULL; // Later replaced where relevant
	req->completed_cb = NULL;
	req->data_type    = MXM_REQ_DATA_BUFFER; /* or for pscom use MXM_REQ_DATA_IOV */
	req->error        = MXM_OK;
	req->data.buffer.ptr    = data;
	req->data.buffer.length = data_len;
}


static void init_recv_req(struct mxm_pp_context *ctx, mxm_recv_req_t *rreq,
			  void *data, unsigned data_len)
{
	init_req_buffer(ctx, &rreq->base, data, data_len);
	rreq->tag      = MXM_MSG_TAG;
	rreq->tag_mask = -1;
}


static void init_send_req(struct mxm_pp_context *ctx, mxm_send_req_t *sreq,
			  void *data, unsigned data_len)
{
	init_req_buffer(ctx, &sreq->base, data, data_len);
	sreq->flags   = 0;

	// sreq->flags |= MXM_REQ_SEND_FLAG_BLOCKING;
	// sreq->flags |= MXM_REQ_SEND_FLAG_LAZY;

	sreq->opcode = MXM_REQ_OP_SEND; // MXM_REQ_OP_SEND_SYNC
	sreq->op.send.tag = MXM_MSG_TAG;
}
