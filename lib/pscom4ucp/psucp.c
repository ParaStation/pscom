/*
 * ParaStation
 *
 * Copyright (C) 2016 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include "psucp.h"
#include "pscom_priv.h"

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
	union {
		struct {
			void	*req_priv;
		} send;
		struct {
			psucp_con_info_t *con_info;
			char	*rbuf;		/* recv buffer of this receive */
			size_t	rbuf_len;
		} recv;
	} type;
};


static hca_info_t  default_hca;

char *psucp_err_str = NULL; /* last error string */

int psucp_debug = 2;
FILE *psucp_debug_stream = NULL;


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
void psucp_cleanup_hca(hca_info_t *hca_info)
{
	// ToDo: Implement cleanup
}


static
void psucp_req_init(void *_req) {
	psucp_req_t *psucp_req = (psucp_req_t *)_req;
	memset(psucp_req, 0, sizeof(*psucp_req));
	INIT_LIST_HEAD(&psucp_req->next); // allow multiple dequeues
}


static
void psucp_req_release(psucp_req_t *psucp_req) {
	// Call psucp_req_init. ucp_request_release() move the request to
	// the request pool and do NOT call psucp_req_init() before reusing it!
	psucp_req_init(psucp_req);
	ucp_request_release(psucp_req);
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


static
void psucp_pending_req_attach(psucp_req_t *psucp_req) {
	if (!psucp_req) return;
	psucp_pending_req_enqueue(psucp_req);
}


static
void psucp_pending_req_release(psucp_req_t *psucp_req) {
	psucp_pending_req_dequeue(psucp_req);
	psucp_req_release(psucp_req);
}


static
int psucp_pending_req_progress(psucp_req_t *psucp_req) {
	if (!psucp_req->completed) {
		return 0;
	}

	if (psucp_req->completed == PSUCP_COMPLETED_SEND) {
		if (psucp_req->type.send.req_priv) {
			pscom_psucp_sendv_done(psucp_req->type.send.req_priv);
		}
	} else {
		assert(psucp_req->completed == PSUCP_COMPLETED_RECV);
	}

	psucp_pending_req_release(psucp_req);
	return 1;
}


static
void psucp_req_send_done(void *request, ucs_status_t status) {
	psucp_req_t *psucp_req = (psucp_req_t *)request;
	psucp_req->completed = PSUCP_COMPLETED_SEND;
}


static
int psucp_init_hca(hca_info_t *hca_info)
{
	int rc;
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
	if (status != UCS_OK) goto err_worker;

	status = ucp_worker_get_address(hca_info->ucp_worker,
					&hca_info->my_ucp_address, &hca_info->my_ucp_address_size);
	if (status != UCS_OK) goto err_worker;

	return 0;
	/* --- */
err_worker:
	psucp_cleanup_hca(hca_info);
err_init:
	return -1;
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
	psucp_dprint(1, "UCP disabled : %s", psucp_err_str);
	return -1;
}


int psucp_progress(void) {
	hca_info_t *hca_info = &default_hca;
	struct list_head *pos, *next;
	int progress = 0;

	// ucp_worker_progress() will fire completed request callbacks.
	ucp_worker_progress(hca_info->ucp_worker);

	list_for_each_safe(pos, next, &hca_info->pending_requests) {
		psucp_req_t *psucp_req = list_entry(pos, psucp_req_t, next);

		progress |= psucp_pending_req_progress(psucp_req);
	}
	return progress;
}


void psucp_con_cleanup(psucp_con_info_t *con_info)
{
	hca_info_t *hca_info = con_info->hca_info;
}


int psucp_con_init(psucp_con_info_t *con_info, hca_info_t *hca_info, void *con_priv)
{
	unsigned int i;

	if (!hca_info) hca_info = &default_hca;
	memset(con_info, 0, sizeof(*con_info));

	con_info->hca_info = hca_info;
	con_info->con_priv = con_priv;
	con_info->con_broken = 0;

	return 0;
	/* --- */
err_alloc:
	psucp_con_cleanup(con_info);
	psucp_dprint(1, "psucp_con_init() : %s", psucp_err_str);
	return -1;
}


int psucp_con_connect(psucp_con_info_t *con_info, psucp_info_msg_t *info_msg)
{
	hca_info_t *hca_info = con_info->hca_info;
	int rc;
	ucs_status_t status;
	ucp_ep_params_t ep_params;

	con_info->remote_tag = info_msg->tag;

	memset(&ep_params, 0, sizeof(ep_params));
	ep_params.field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS;
	ep_params.address = (ucp_address_t *)info_msg->addr;

	status = ucp_ep_create(hca_info->ucp_worker, &ep_params, &con_info->ucp_ep);
	if (status != UCS_OK) goto err_ep_create;

	return 0;
	/* --- */
err_ep_create:
	psucp_err_status("ucp_ep_create()", status);
	psucp_dprint(1, "psucp_con_connect() : %s", psucp_err_str);
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


void psucp_con_get_info_msg(psucp_con_info_t *con_info /* in */,
			    unsigned long tag,
			    psucp_info_msg_t *info_msg /* out */)
{
	int rc;
	hca_info_t *hca_info = con_info->hca_info;

	if (hca_info->my_ucp_address_size > sizeof(info_msg->addr)) {
		printf("psucp_info_msg_t.addr to small! Should be at least %zu!\n", hca_info->my_ucp_address_size);
		// ToDo: Error recovery
	}
	info_msg->size = (uint16_t)hca_info->my_ucp_address_size;
	memcpy(info_msg->addr, hca_info->my_ucp_address, MIN(sizeof(info_msg->addr), info_msg->size));

	info_msg->tag = tag;
}


ssize_t psucp_sendv(psucp_con_info_t *con_info, struct iovec iov[2], void *req_priv)
{
	ucs_status_ptr_t request;
	psucp_req_t *psucp_req;
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

	// ToDo: Copy small messages into one continuous buffer.

	//printf("%s:%u:%s send head %3u of %3u : %s\n",
	//      __FILE__, __LINE__, __func__, (unsigned)iov[0].iov_len, size,
	//     pscom_dumpstr(iov[0].iov_base, iov[0].iov_len));
	request = ucp_tag_send_nb(con_info->ucp_ep,
				  iov[0].iov_base, iov[0].iov_len,
				  ucp_dt_make_contig(1),
				  con_info->remote_tag,
				  /*(ucp_send_callback_t)*/psucp_req_send_done);
	if (UCS_PTR_IS_ERR(request)) goto err_send_header;

	psucp_pending_req_attach(request);

	if (iov[1].iov_len) {
		//printf("%s:%u:%s send data %3u : %s\n",
		//      __FILE__, __LINE__, __func__, iov[1].iov_len,
		//     pscom_dumpstr(iov[1].iov_base, iov[1].iov_len));

		request = ucp_tag_send_nb(con_info->ucp_ep,
					  iov[1].iov_base, iov[1].iov_len,
					  ucp_dt_make_contig(1),
					  con_info->remote_tag,
					  /*(ucp_send_callback_t)*/psucp_req_send_done);
		if (UCS_PTR_IS_ERR(request)) goto err_send_data;

		psucp_pending_req_attach(request);
	}
#endif
	if (request) {
		psucp_req = (psucp_req_t *)request;
		assert(!psucp_req->completed);
		psucp_req->type.send.req_priv = req_priv;
	} else {
		pscom_psucp_sendv_done(req_priv);
	}


	return iov[0].iov_len + iov[1].iov_len;
err_send:
err_send_data:
err_send_header:
	{
		ucs_status_t status = UCS_PTR_STATUS(request);

		psucp_err_status("ucp_tag_send_nb()", status);
		psucp_dprint(2, "psucp_sendv() : %s", psucp_err_str);
	}
	return -EPIPE;;
}


size_t psucp_probe(psucp_msg_t *msg)
{
	hca_info_t *hca_info = &default_hca;

	msg->msg_tag = ucp_tag_probe_nb(
		hca_info->ucp_worker,
		0 /* tag */, (ucp_tag_t)0 /* tag mask any */,
		1 /* remove */,
		&msg->info_tag);

	if (msg->msg_tag == NULL) {
		// Progress with ucp_tag_probe_nb() alone didn't call the req callbacks.
		// psucp_progres calls ucp_worker_progress(hca_info->ucp_worker);
		psucp_progress();
		return 0;
	}
	assert(msg->info_tag.length > 0);

	return msg->info_tag.length;
}


static
void psucp_req_recv_done(void *request, ucs_status_t status, ucp_tag_recv_info_t *info)
{
	psucp_req_t *psucp_req = (psucp_req_t *)request;
	psucp_con_info_t *con_info = psucp_req->type.recv.con_info;

	psucp_req->completed = PSUCP_COMPLETED_RECV;

	if (con_info) {
		// On slow track. con_info set in psucp_irecv().
		// printf("%s:%u:%s PSUCP_COMPLETED_RECV slow\n", __FILE__, __LINE__, __func__);
		pscom_psucp_read_done(con_info->con_priv,
				      psucp_req->type.recv.rbuf, psucp_req->type.recv.rbuf_len);
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
		pscom_psucp_read_done(con_info->con_priv, buf, len);
		psucp_req_release(psucp_req);
	} else {
		// On slow track. Enqueue request into pending requests queue.
		psucp_req->type.recv.rbuf = buf;
		psucp_req->type.recv.rbuf_len = len;
		psucp_req->type.recv.con_info = con_info;

		// psucp_req not yet done. Poll for completion later:
		psucp_pending_req_attach(request);
	}

	//printf("%s:%u:%s recv %u : %s\n", __FILE__, __LINE__, __func__,
	//      (unsigned) len, pscom_dumpstr(buf, len));
	return len;

err_recv:
	{
		ucs_status_t status = UCS_PTR_STATUS(request);

		psucp_err_status("ucp_tag_msg_recv_nb()", status);
		psucp_dprint(2, "psucp_recv() : %s", psucp_err_str);
	}
	return -EPIPE;;
}
