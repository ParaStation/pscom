/*
 * ParaStation
 *
 * Copyright (C) 2016-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "psucp.h"
#include "pscom_priv.h"
#include "pscom_util.h"

#include <ucp/api/ucp.h>
#include <ucp/api/ucp_def.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>



#define MIN(a,b)      (((a)<(b))?(a):(b))
#define MAX(a,b)      (((a)>(b))?(a):(b))

struct hca_info {
	ucp_worker_h	ucp_worker;
	ucp_context_h	ucp_context;

	ucp_address_t	*my_ucp_address;
	size_t		my_ucp_address_size;

	struct list_head pending_requests; // List of psucp_req_t.next
};


typedef struct psucp_req psucp_req_t;

/* UCP specific information about one connection */
struct psucp_con_info {
	ucp_ep_h	ucp_ep;

	/* low level */
	hca_info_t	*hca_info;

	uint64_t	remote_tag;
	size_t		small_msg_len;		// Remote psucp_small_msg_len

	/* misc */
	void		*con_priv;		/* priv data from psucp_con_init() */

	int con_broken;
};

#define PSUCP_COMPLETED_PENDING 0
#define PSUCP_COMPLETED_SEND 1
#define PSUCP_COMPLETED_RECV 2

struct psucp_req {
	struct list_head	next;		// list struct hca_info.pending_requests.
	int			completed;	// PSUCP_COMPLETED_*
	psucp_con_info_t	*con_info;
	union {
		struct {
			void	*req_priv;
			void	*sendbuf;	// for small_msg only
		} send;
		struct {
			void 	*req_priv;
		} recv;
	} type;
};


static hca_info_t  default_hca;

char *psucp_err_str = NULL; /* last error string */

int psucp_debug = 2;
FILE *psucp_debug_stream = NULL;
unsigned psucp_small_msg_len = 350; // will be overwritten by pscom.env.readahead (PSP_READAHEAD)
void *psucp_small_msg_sendbuf = NULL; // Prepared sendbuffer for small messages
size_t psucp_small_msg_sendbuf_len = 0;
unsigned int psucp_max_recv = ~0U;  // will be overwritten by pscom.env.ucp_max_recv (PSP_UCP_MAX_RECV)

static unsigned int psucp_recv_in_progress = 0; // count all receives currently in progress

#define psucp_dprint(level,fmt,arg... )					\
do {									\
	if ((level) <= psucp_debug) {					\
		fprintf(psucp_debug_stream ? psucp_debug_stream : stderr, \
			"ucp:" fmt "\n",##arg);				\
	}								\
} while(0);


static
void psucp_err(char *str)
{
	if (psucp_err_str) free(psucp_err_str);

	psucp_err_str = str ? strdup(str) : strdup("");
	return;
}


static
void psucp_err_status(char *str, ucs_status_t status)
{
	const char *err_str = ucs_status_string(status);
	size_t len = strlen(str) + strlen(err_str) + 10;
	char *msg = malloc(len);

	assert(msg);

	strcpy(msg, str);
	strcat(msg, " : ");
	strcat(msg, err_str);

	psucp_err(msg);
	free(msg);
}


static
void psucp_small_msg_sendbuf_check(size_t min_length)
{
	if (min_length > psucp_small_msg_sendbuf_len) {
		psucp_small_msg_sendbuf = realloc(psucp_small_msg_sendbuf, min_length);
		psucp_small_msg_sendbuf_len = min_length;
		assert(psucp_small_msg_sendbuf);
	}
}


static
void psucp_small_msg_sendbuf_free(void)
{
	free(psucp_small_msg_sendbuf);
	psucp_small_msg_sendbuf = NULL;
	psucp_small_msg_sendbuf_len = 0;
}


// Caller has to free() the old psucp_small_msg_sendbuf (= return value)!
static
void *psucp_small_msg_sendbuf_get_ownership(void)
{
	void *old = psucp_small_msg_sendbuf;
	psucp_small_msg_sendbuf = malloc(psucp_small_msg_sendbuf_len);
	assert(psucp_small_msg_sendbuf);
	return old;
}


static
void psucp_cleanup_hca(hca_info_t *hca_info)
{

	if (hca_info->ucp_worker) {
		if (hca_info->my_ucp_address) {
			ucp_worker_release_address(hca_info->ucp_worker, hca_info->my_ucp_address);
			hca_info->my_ucp_address = NULL;
		}

		ucp_worker_destroy(hca_info->ucp_worker);
		hca_info->ucp_worker = NULL;
	}

	if (hca_info->ucp_context) {
		ucp_cleanup(hca_info->ucp_context);
		hca_info->ucp_context = NULL;
	}

	psucp_small_msg_sendbuf_free();
}


static
void psucp_req_init(void *_req) {
	psucp_req_t *psucp_req = (psucp_req_t *)_req;
	memset(psucp_req, 0, sizeof(*psucp_req));
	INIT_LIST_HEAD(&psucp_req->next); // allow multiple dequeues
}


static
void psucp_req_release(psucp_req_t *psucp_req) {
	// Call psucp_req_init. ucp_request_free() move the request to
	// the request pool and do NOT call psucp_req_init() before reusing it!

	psucp_req_init(psucp_req);
	ucp_request_free(psucp_req);
}


static
void psucp_pending_req_enqueue(psucp_req_t *psucp_req) {
	hca_info_t *hca_info = &default_hca;

	list_add_tail(&psucp_req->next, &hca_info->pending_requests);
}


static
void psucp_pending_req_dequeue(psucp_req_t *psucp_req) {
//	hca_info_t *hca_info = &default_hca;
	list_del_init(&psucp_req->next);
}


static inline
void psucp_pending_req_attach(psucp_req_t *psucp_req, psucp_con_info_t *con_info) {
	if (!psucp_req) return;
	psucp_req->con_info = con_info;
	psucp_pending_req_enqueue(psucp_req);
}


static
void psucp_pending_req_dequeue_and_release(psucp_req_t *psucp_req) {
	psucp_pending_req_dequeue(psucp_req);
	psucp_req_release(psucp_req);
}


static
void psucp_req_send_done(void *request, ucs_status_t status) {
	psucp_req_t *psucp_req = (psucp_req_t *)request;
	psucp_req->completed = PSUCP_COMPLETED_SEND;

	if (psucp_req->type.send.req_priv) {
		pscom_psucp_sendv_done(psucp_req->type.send.req_priv);
	}

	psucp_pending_req_dequeue_and_release(psucp_req);
}


static
void psucp_req_send_small_done(void *request, ucs_status_t status) {
	psucp_req_t *psucp_req = (psucp_req_t *)request;

	free(psucp_req->type.send.sendbuf);

	psucp_req_send_done(request, status);
}


static
int psucp_init_hca(hca_info_t *hca_info)
{
	ucs_status_t status;
	ucp_config_t *config;
	ucp_params_t ucp_params;
	ucp_worker_params_t ucp_worker_params;

	memset(hca_info, 0, sizeof(*hca_info));

	/* UCP initialization */
	status = ucp_config_read(NULL, NULL, &config);
	assert(status == UCS_OK);

	memset(&ucp_params, 0, sizeof(ucp_params));
	ucp_params.field_mask      =
		UCP_PARAM_FIELD_FEATURES |
		UCP_PARAM_FIELD_REQUEST_SIZE |
		UCP_PARAM_FIELD_REQUEST_INIT;
	ucp_params.features        = UCP_FEATURE_TAG;
	ucp_params.request_size    = sizeof(psucp_req_t);
	ucp_params.request_init    = psucp_req_init;
	ucp_params.request_cleanup = NULL;

	INIT_LIST_HEAD(&hca_info->pending_requests);

	status = ucp_init(&ucp_params, config, &hca_info->ucp_context);
	if (status != UCS_OK) goto err_init;

	// ucp_config_print(config, stdout, NULL, UCS_CONFIG_PRINT_CONFIG);
	ucp_config_release(config);

	memset(&ucp_worker_params, 0, sizeof(ucp_worker_params));
	ucp_worker_params.field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
	ucp_worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;

	status = ucp_worker_create(hca_info->ucp_context, &ucp_worker_params,
				   &hca_info->ucp_worker);
	if (status != UCS_OK) goto err_worker_create;

	status = ucp_worker_get_address(hca_info->ucp_worker,
					&hca_info->my_ucp_address, &hca_info->my_ucp_address_size);
	if (status != UCS_OK) goto err_worker;

	return 0;
	/* --- */
err_worker_create:
	hca_info->ucp_worker = NULL;
err_worker:
	psucp_cleanup_hca(hca_info);
err_init:
	return -1;
}


static inline
void psucp_recv_req_inc(void)
{
    psucp_recv_in_progress++;
}


static inline
void psucp_recv_req_dec(void)
{
    psucp_recv_in_progress--;
}


int psucp_init(void)
{
	static int init_state = 1;
	if (init_state == 1) {
		if (psucp_init_hca(&default_hca)) goto err_hca;

		init_state = 0;
	}

	return init_state; /* 0 = success, -1 = error */
	/* --- */
err_hca:
	init_state = -1;
	psucp_dprint(D_INFO, "UCP disabled : %s", psucp_err_str);
	return -1;
}


void psucp_con_cleanup(psucp_con_info_t *con_info)
{
	ucs_status_ptr_t request;
	hca_info_t *hca_info = con_info->hca_info;
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, &hca_info->pending_requests) {
		psucp_req_t *psucp_req = list_entry(pos, psucp_req_t, next);
		// ucs_status_t status = ucp_request_check_status(psucp_req);
		// printf("%s:%u:%s pending: %p : %d\n", __FILE__, __LINE__, __func__, psucp_req, status);

		if (psucp_req->con_info == con_info) {
			// Cancel request and free
			ucp_request_cancel(hca_info->ucp_worker, psucp_req);
			psucp_pending_req_dequeue_and_release(psucp_req);
		}
	}


	if (con_info->ucp_ep) {
		request = ucp_ep_close_nb(con_info->ucp_ep,
					  UCP_EP_CLOSE_MODE_FLUSH);
//					  UCP_EP_CLOSE_MODE_FORCE);

		if (UCS_PTR_IS_ERR(request)) goto err_close;

		ucp_worker_progress(hca_info->ucp_worker);

		if (request) {
			// ToDo: Is it safe to free the request without waiting for completion?
			ucp_request_free(request);
		}
	}
	return;
err_close:
	{
		ucs_status_t status = UCS_PTR_STATUS(request);
		psucp_err_status("ucp_ep_close_nb()", status);
		psucp_dprint(D_WARN, "failed psucp_con_cleanup() : %s", psucp_err_str);
	}
}


int psucp_con_init(psucp_con_info_t *con_info, hca_info_t *hca_info, void *con_priv)
{
	if (!hca_info) hca_info = &default_hca;
	memset(con_info, 0, sizeof(*con_info));

	con_info->hca_info = hca_info;
	con_info->con_priv = con_priv;
	con_info->con_broken = 0;

	return 0;
}


int psucp_con_connect(psucp_con_info_t *con_info, psucp_info_msg_t *info_msg)
{
	hca_info_t *hca_info = con_info->hca_info;
	ucs_status_t status;
	ucp_ep_params_t ep_params;

	con_info->remote_tag = info_msg->tag;
	con_info->small_msg_len = info_msg->small_msg_len;

	psucp_small_msg_sendbuf_check(con_info->small_msg_len);

	memset(&ep_params, 0, sizeof(ep_params));
	ep_params.field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS;
	ep_params.address = (ucp_address_t *)info_msg->ucp_addr;

	status = ucp_ep_create(hca_info->ucp_worker, &ep_params, &con_info->ucp_ep);
	if (status != UCS_OK) goto err_ep_create;

	return 0;
	/* --- */
err_ep_create:
	con_info->ucp_ep = NULL;
	psucp_err_status("ucp_ep_create()", status);
	psucp_dprint(D_ERR, "psucp_con_connect() : %s", psucp_err_str);
	return -1;
}


psucp_con_info_t *psucp_con_create(void)
{
	psucp_con_info_t *con_info = malloc(sizeof(*con_info));
	memset(con_info, 0, sizeof(*con_info));
	return con_info;
}


void psucp_con_free(psucp_con_info_t *con_info)
{
	free(con_info);
}


psucp_info_msg_t *
psucp_con_get_info_msg(psucp_con_info_t *con_info, unsigned long tag)
{
	hca_info_t *hca_info = con_info->hca_info;
	psucp_info_msg_t *info_msg = malloc(sizeof(*info_msg) + hca_info->my_ucp_address_size);

	assert(info_msg);
	assert(hca_info->my_ucp_address_size <= 0xffff);

	info_msg->tag = tag;
	info_msg->small_msg_len = psucp_small_msg_len;

	info_msg->ucp_addr_size = (uint16_t)hca_info->my_ucp_address_size;
	memcpy(info_msg->ucp_addr, hca_info->my_ucp_address, info_msg->ucp_addr_size);

	return info_msg;
}


ssize_t psucp_sendv(psucp_con_info_t *con_info, struct iovec iov[2], void *req_priv)
{
	ucs_status_ptr_t request;
	psucp_req_t *psucp_req;
	size_t len;
#if 0	/* use UCP_DATATYPE_IOV ucp_tag_send_nb() */
	ucp_dt_iov_t *ucp_iov = (ucp_dt_iov_t *)iov;
	// assert ucp_dt_iov_t compatible to iovec:
	assert((sizeof(ucp_dt_iov_t) == sizeof(struct iovec)) &&
	       ( &(((ucp_dt_iov_t *)0)->length) == &(((struct iovec *)0)->iov_len)));

	// printf("%s:%u:%s send head %3u, data %3u\n",
	//        __FILE__, __LINE__, __func__, (unsigned)iov[0].iov_len, (unsigned)iov[1].iov_len);

	request = ucp_tag_send_nb(con_info->ucp_ep,
				  ucp_iov, 2,
				  ucp_dt_make_iov(),
				  con_info->remote_tag,
				  /*(ucp_send_callback_t)*/psucp_req_send_done);
	if (UCS_PTR_IS_ERR(request)) goto err_send;

	psucp_pending_req_attach(request);
#else	/* individual ucp_tag_send_nb() for each iov[] */
	assert(iov[0].iov_len > 0);

	len = iov[0].iov_len + iov[1].iov_len;
#if 1
	// Copy small messages into one continuous buffer.
	if (len <= con_info->small_msg_len &&
	    PSCOM_IF_CUDA(!pscom.env.cuda, 1) && /* do not copy if iov[1] could point to gpu mem */
	    iov[1].iov_len /* has two fragments? */) {
		pscom_memcpy_from_iov(psucp_small_msg_sendbuf, iov, len);

		request = ucp_tag_send_nb(con_info->ucp_ep,
					  psucp_small_msg_sendbuf, len,
					  ucp_dt_make_contig(1),
					  con_info->remote_tag,
					  /*(ucp_send_callback_t)*/psucp_req_send_small_done);
		if (UCS_PTR_IS_ERR(request)) goto err_send;
		if (!request) {
			// Common case. Sent inline. No request.
			pscom_psucp_sendv_done(req_priv);
		} else {
			psucp_req = (psucp_req_t *)request;
			// Free() the sendbuf when done (psucp_req_send_small_done()).
			psucp_req->type.send.sendbuf = psucp_small_msg_sendbuf_get_ownership();
			assert(!psucp_req->completed);
			psucp_req->type.send.req_priv = req_priv;

			psucp_pending_req_attach(request, con_info);
		}

		return len;
	}
#endif
	int i;
	size_t len_first = MIN(iov[0].iov_len, con_info->small_msg_len);
	struct iovec siov[3] = {
		{ .iov_base = iov[0].iov_base, .iov_len = len_first },
		{ .iov_base = iov[0].iov_base + len_first, .iov_len = iov[0].iov_len - len_first },
		iov[1]
	};
	request = NULL;

	// Send up to three messages:
	// 1st: iov[0], with up to con_info->small_msg_len bytes
	// 2nd: rest of iov[0], if iov[0] is longer than con_info->small_msg_len
	// 3rd: iov[1], if iov[1]->iov_len > 0
	for (i = 0; i < 3; i++) {
		size_t len = siov[i].iov_len;
		if (!len) continue;
		request = ucp_tag_send_nb(con_info->ucp_ep,
					  siov[i].iov_base, len,
					  ucp_dt_make_contig(1),
					  con_info->remote_tag,
					  /*(ucp_send_callback_t)*/psucp_req_send_done);
		if (UCS_PTR_IS_ERR(request)) goto err_send;

		psucp_pending_req_attach(request, con_info);
	}
#endif
	if (request) {
		psucp_req = (psucp_req_t *)request;
		assert(!psucp_req->completed);
		psucp_req->type.send.req_priv = req_priv;
	} else {
		pscom_psucp_sendv_done(req_priv);
	}


	return len;
err_send:
	{
		ucs_status_t status = UCS_PTR_STATUS(request);

		psucp_err_status("ucp_tag_send_nb()", status);
		psucp_dprint(D_ERR, "psucp_sendv() : %s", psucp_err_str);
	}
	return -EPIPE;;
}


void psucp_progress(void)
{
	hca_info_t *hca_info = &default_hca;
	ucp_worker_progress(hca_info->ucp_worker);
}


size_t psucp_probe(psucp_msg_t *msg)
{
	hca_info_t *hca_info = &default_hca;

	if (psucp_recv_in_progress < psucp_max_recv) {
		msg->msg_tag = ucp_tag_probe_nb(
			hca_info->ucp_worker,
			0 /* tag */, (ucp_tag_t)0 /* tag mask any */,
			1 /* remove */,
			&msg->info_tag);
	} else {
		msg->msg_tag = NULL;
	}

	if (msg->msg_tag == NULL) {
		// Progress with ucp_tag_probe_nb() alone didn't call the req callbacks.
		// psucp_progres calls ucp_worker_progress(hca_info->ucp_worker);
		ucp_worker_progress(hca_info->ucp_worker);
		return 0;
	}
	assert(msg->info_tag.length > 0);

	return msg->info_tag.length;
}


static
void psucp_req_recv_done(void *request, ucs_status_t status, ucp_tag_recv_info_t *info)
{
	psucp_req_t *psucp_req = (psucp_req_t *)request;
	psucp_con_info_t *con_info = psucp_req->con_info;

	psucp_req->completed = PSUCP_COMPLETED_RECV;

	if (con_info) {
		// On slow track. con_info set in psucp_irecv().
		// printf("%s:%u:%s PSUCP_COMPLETED_RECV slow\n", __FILE__, __LINE__, __func__);
		pscom_read_pending_done(con_info->con_priv, psucp_req->type.recv.req_priv);
		psucp_pending_req_dequeue_and_release(psucp_req);
		psucp_recv_req_dec();
	} /* else {
		// called from within ucp_tag_msg_recv_nb(). con_info is still unset.
		printf("%s:%u:%s PSUCP_COMPLETED_RECV fast\n", __FILE__, __LINE__, __func__);
	}
	  */
}


ssize_t psucp_irecv(psucp_con_info_t *con_info, psucp_msg_t *msg, void *buf, size_t size)
{
	hca_info_t *hca_info = &default_hca;
	ucs_status_ptr_t request;
	psucp_req_t *psucp_req;

	size_t len = size < msg->info_tag.length ? size : msg->info_tag.length;

	// printf("%s:%u:%s irecv msg length %3u, expected %3u\n",
	//        __FILE__, __LINE__, __func__, (unsigned)msg->info_tag.length, (unsigned)size);

	request = ucp_tag_msg_recv_nb(hca_info->ucp_worker,
				      buf, len,
				      ucp_dt_make_contig(1), msg->msg_tag,
				      psucp_req_recv_done);

	if (UCS_PTR_IS_ERR(request)) {
		goto err_recv;
	}

	psucp_req = (psucp_req_t *)request;

	if (psucp_req->completed) {
		// On fast track. Request already completed (probably small message).
		pscom_read_done(con_info->con_priv, buf, len);
		psucp_req_release(psucp_req);
	} else {
		psucp_recv_req_inc();

		// psucp_req not yet done. Poll for completion later:
		psucp_pending_req_attach(request, con_info);
		psucp_req->type.recv.req_priv = (void*)pscom_read_pending(con_info->con_priv, len);
	}

	//printf("%s:%u:%s recv %u : %s\n", __FILE__, __LINE__, __func__,
	//      (unsigned) len, pscom_dumpstr(buf, len));
	return len;

err_recv:
	{
		ucs_status_t status = UCS_PTR_STATUS(request);

		psucp_err_status("ucp_tag_msg_recv_nb()", status);
		psucp_dprint(D_ERR, "psucp_recv() : %s", psucp_err_str);
	}
	return -EPIPE;;
}
