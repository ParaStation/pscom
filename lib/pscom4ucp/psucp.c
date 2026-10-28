/*
 * ParaStation
 *
 * Copyright (C) 2016-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
#include "psucp.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include <ucp/api/ucp.h>
#include <ucp/api/ucp_def.h>
#include <ucp/api/ucp_compat.h> /* IWYU pragma: keep */

#include "list.h"
#include "pscom.h"
#include "pscom_env.h" /* IWYU pragma: keep */
#include "pscom_debug.h"
#include "pscom_priv.h"
#include "pscom_util.h"


#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

struct psucp_hca_info {
    ucp_worker_h ucp_worker;
    ucp_context_h ucp_context;

    ucp_address_t *my_ucp_address;
    size_t my_ucp_address_size;

    struct list_head pending_requests; // List of psucp_req_t.next
};


/* information on RMA accumulate operations
********************************************
MPI op :
1 MPI_MAX maximum                          not supported
2 MPI_MIN minimum                          not supported
3 MPI_SUM sum                              supported
4 MPI_PROD product                         not supported
5 MPI_LAND logical and                     not supported
6 MPI_BAND bit-wise and                    supported
7 MPI_LOR logical or                       not supported
8 MPI_BOR bit-wise or                      supported
9 MPI_LXOR logical exclusive or (xor)      not supported
10 MPI_BXOR bit-wise exclusive or (xor)    supported
11 MPI_MINLOC min value and location       not supported
12 MPI_MAXLOC max value and location       not supported
13 MPI_REPLACE                             supported
   MPI_NO_OP   (MPI_Op)(0x5800000e)
********************************************
initialized rma_op_mask  0b0001 0010 1010 0100
********************************************
ucx supported hardware-enabled RMA acc ops
enum ucp_atomic_op_t used for ucp_atomic_op_nbx
UCP_ATOMIC_OP_ADD Atomic add
UCP_ATOMIC_OP_SWAP Atomic swap
UCP_ATOMIC_OP_CSWAP Atomic conditional swap
UCP_ATOMIC_OP_AND Atomic and
UCP_ATOMIC_OP_OR Atomic or
UCP_ATOMIC_OP_XOR Atomic xor
*/

struct psucp_rma_module {
    /* specific plugin definitions go below */
    unsigned int rma_fetch_op_mask; /* which rma get accumulate operation is
                                       supported by the hardware */
    unsigned int rma_mask;        /* which rma communication is supported by the
                                     hardware */
    unsigned int rma_acc_op_mask; /* which rma accumulate operation is supported
                                     by the hardware */
};

static struct psucp_rma_module ucp_rma_module;


typedef struct psucp_req psucp_req_t;

/* UCP specific information about one connection */
struct psucp_con_info {
    ucp_ep_h ucp_ep;

    /* low level */
    psucp_hca_info_t *hca_info;

    uint64_t remote_tag;
    size_t small_msg_len; // Remote psucp_small_msg_len

    /* misc */
    void *con_priv; /* priv data from psucp_con_init() */

    int con_broken;
};

#define PSUCP_COMPLETED_PENDING 0
#define PSUCP_COMPLETED_SEND    1
#define PSUCP_COMPLETED_RECV    2

struct psucp_req {
    struct list_head next; // list struct psucp_hca_info.pending_requests.
    int completed;         // PSUCP_COMPLETED_*
    psucp_con_info_t *con_info;
    union {
        struct {
            void *req_priv;
            void *sendbuf; // for small_msg only
        } send;
        struct {
            void *req_priv;
        } recv;
    } type;
};

typedef struct {
    size_t remaining; // TODO: use atomic datatype
    void *req_priv;
} psucp_atomic_segment_ctx_t;


static psucp_hca_info_t psucp_default_hca;

static int init_state = 1; /* only initialized once */

char *psucp_err_str = NULL; /* last error string */

int psucp_debug               = 2;
FILE *psucp_debug_stream      = NULL;
unsigned psucp_small_msg_len  = 350;  // will be overwritten by
                                      // pscom.env.readahead (PSP_READAHEAD)
void *psucp_small_msg_sendbuf = NULL; // Prepared sendbuffer for small messages
size_t psucp_small_msg_sendbuf_len = 0;
unsigned int psucp_max_recv        = ~0U; // will be overwritten by
                                   // pscom.env.ucp_max_recv (PSP_UCP_MAX_RECV)

static unsigned int psucp_recv_in_progress = 0; // count all receives currently
                                                // in progress

#define psucp_dprint(level, fmt, arg...)                                       \
    do {                                                                       \
        if ((level) <= psucp_debug) {                                          \
            fprintf(psucp_debug_stream ? psucp_debug_stream : stderr,          \
                    "ucp:" fmt "\n", ##arg);                                   \
        }                                                                      \
    } while (0);


static void psucp_err(char *str)
{
    if (psucp_err_str) { free(psucp_err_str); }

    psucp_err_str = str ? strdup(str) : strdup("");
    return;
}


static void psucp_err_status(char *str, ucs_status_t status)
{
    const char *err_str = ucs_status_string(status);
    size_t len          = strlen(str) + strlen(err_str) + 10;
    char *msg           = malloc(len);

    assert(msg);

    strcpy(msg, str);
    strcat(msg, " : ");
    strcat(msg, err_str);

    psucp_err(msg);
    free(msg);
}


static void psucp_small_msg_sendbuf_check(size_t min_length)
{
    if (min_length > psucp_small_msg_sendbuf_len) {
        psucp_small_msg_sendbuf = realloc(psucp_small_msg_sendbuf, min_length);
        psucp_small_msg_sendbuf_len = min_length;
        assert(psucp_small_msg_sendbuf);
    }
}


static void psucp_small_msg_sendbuf_free(void)
{
    free(psucp_small_msg_sendbuf);
    psucp_small_msg_sendbuf     = NULL;
    psucp_small_msg_sendbuf_len = 0;
}


// Caller has to free() the old psucp_small_msg_sendbuf (= return value)!
static void *psucp_small_msg_sendbuf_get_ownership(void)
{
    void *old               = psucp_small_msg_sendbuf;
    psucp_small_msg_sendbuf = malloc(psucp_small_msg_sendbuf_len);
    assert(psucp_small_msg_sendbuf);
    return old;
}


static void psucp_cleanup_hca(psucp_hca_info_t *hca_info)
{

    if (hca_info->ucp_worker) {
        if (hca_info->my_ucp_address) {
            ucp_worker_release_address(hca_info->ucp_worker,
                                       hca_info->my_ucp_address);
            hca_info->my_ucp_address = NULL;
        }

        ucp_worker_destroy(hca_info->ucp_worker);
        hca_info->ucp_worker = NULL;
    }

    if (hca_info->ucp_context) {
        ucp_cleanup(hca_info->ucp_context);
        hca_info->ucp_context = NULL;
    }

    if (psucp_small_msg_sendbuf) { psucp_small_msg_sendbuf_free(); }
}


static void psucp_req_init(void *_req)
{
    psucp_req_t *psucp_req = (psucp_req_t *)_req;
    memset(psucp_req, 0, sizeof(*psucp_req));
    INIT_LIST_HEAD(&psucp_req->next); // allow multiple dequeues
}


static void psucp_req_release(psucp_req_t *psucp_req)
{
    // Call psucp_req_init. ucp_request_free() move the request to
    // the request pool and do NOT call psucp_req_init() before reusing it!

    psucp_req_init(psucp_req);
    ucp_request_free(psucp_req);
}


static void psucp_pending_req_enqueue(psucp_req_t *psucp_req)
{
    psucp_hca_info_t *hca_info = &psucp_default_hca;

    list_add_tail(&psucp_req->next, &hca_info->pending_requests);
}


static void psucp_pending_req_dequeue(psucp_req_t *psucp_req)
{
    //	psucp_hca_info_t *hca_info = &psucp_default_hca;
    list_del_init(&psucp_req->next);
}


static inline void psucp_pending_req_attach(psucp_req_t *psucp_req,
                                            psucp_con_info_t *con_info)
{
    if (!psucp_req) { return; }
    psucp_req->con_info = con_info;
    psucp_pending_req_enqueue(psucp_req);
}


static void psucp_pending_req_dequeue_and_release(psucp_req_t *psucp_req)
{
    psucp_pending_req_dequeue(psucp_req);
    psucp_req_release(psucp_req);
}


static void psucp_req_send_done(void *request, ucs_status_t status)
{
    psucp_req_t *psucp_req = (psucp_req_t *)request;
    psucp_req->completed   = PSUCP_COMPLETED_SEND;

    if (psucp_req->type.send.req_priv) {
        pscom_psucp_sendv_done(psucp_req->type.send.req_priv);
    }

    psucp_pending_req_dequeue_and_release(psucp_req);
}


static void psucp_req_send_small_done(void *request, ucs_status_t status)
{
    psucp_req_t *psucp_req = (psucp_req_t *)request;

    free(psucp_req->type.send.sendbuf);

    psucp_req_send_done(request, status);
}


static int psucp_init_hca(psucp_hca_info_t *hca_info)
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
    ucp_params.field_mask = UCP_PARAM_FIELD_FEATURES |
                            UCP_PARAM_FIELD_REQUEST_SIZE |
                            UCP_PARAM_FIELD_REQUEST_INIT;
    ucp_params.features = UCP_FEATURE_TAG | UCP_FEATURE_RMA |
                          UCP_FEATURE_AMO32 | UCP_FEATURE_AMO64;
    ucp_params.request_size    = sizeof(psucp_req_t);
    ucp_params.request_init    = psucp_req_init;
    ucp_params.request_cleanup = NULL;

    INIT_LIST_HEAD(&hca_info->pending_requests);

    status = ucp_init(&ucp_params, config, &hca_info->ucp_context);
    if (status != UCS_OK) { goto err_init; }

    // ucp_config_print(config, stdout, NULL, UCS_CONFIG_PRINT_CONFIG);
    ucp_config_release(config);

    memset(&ucp_worker_params, 0, sizeof(ucp_worker_params));
    ucp_worker_params.field_mask  = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    ucp_worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;

    status = ucp_worker_create(hca_info->ucp_context, &ucp_worker_params,
                               &hca_info->ucp_worker);
    if (status != UCS_OK) { goto err_worker_create; }

    status = ucp_worker_get_address(hca_info->ucp_worker,
                                    &hca_info->my_ucp_address,
                                    &hca_info->my_ucp_address_size);
    if (status != UCS_OK) { goto err_worker; }

    return 0;
    /* --- */
err_worker_create:
    hca_info->ucp_worker = NULL;
err_worker:
    psucp_cleanup_hca(hca_info);
err_init:
    return -1;
}


static inline void psucp_recv_req_inc(void)
{
    psucp_recv_in_progress++;
}


static inline void psucp_recv_req_dec(void)
{
    psucp_recv_in_progress--;
}


int psucp_init(void)
{
    if (init_state == 1) {
        if (psucp_init_hca(&psucp_default_hca)) { goto err_hca; }

        init_state = 0;
    }

    return init_state; /* 0 = success, -1 = error */
                       /* --- */
err_hca:
    init_state = -1;
    psucp_dprint(D_INFO, "UCP disabled : %s", psucp_err_str);
    return -1;
}


void psucp_finalize(void)
{
    if (init_state == 0) { psucp_cleanup_hca(&psucp_default_hca); }
}


void psucp_con_cleanup(psucp_con_info_t *con_info)
{
    ucs_status_ptr_t request;
    psucp_hca_info_t *hca_info = con_info->hca_info;
    struct list_head *pos, *next;

    list_for_each_safe (pos, next, &hca_info->pending_requests) {
        psucp_req_t *psucp_req = list_entry(pos, psucp_req_t, next);
        // ucs_status_t status = ucp_request_check_status(psucp_req);
        // printf("%s:%u:%s pending: %p : %d\n", __FILE__, __LINE__, __func__,
        // psucp_req, status);

        if (psucp_req->con_info == con_info) {
            // Cancel request and free
            ucp_request_cancel(hca_info->ucp_worker, psucp_req);
            psucp_pending_req_dequeue_and_release(psucp_req);
        }
    }


    if (con_info->ucp_ep) {
        request = ucp_ep_close_nb(con_info->ucp_ep, UCP_EP_CLOSE_MODE_FLUSH);
        //					  UCP_EP_CLOSE_MODE_FORCE);

        if (UCS_PTR_IS_ERR(request)) { goto err_close; }

        ucp_worker_progress(hca_info->ucp_worker);

        if (request) {
            // ToDo: Is it safe to free the request without waiting for
            // completion?
            ucp_request_free(request);
        }
    }
    return;
err_close: {
    ucs_status_t status = UCS_PTR_STATUS(request);
    psucp_err_status("ucp_ep_close_nb()", status);
    psucp_dprint(D_WARN, "failed psucp_con_cleanup() : %s", psucp_err_str);
}
}


int psucp_con_init(psucp_con_info_t *con_info, psucp_hca_info_t *hca_info,
                   void *con_priv)
{
    if (!hca_info) { hca_info = &psucp_default_hca; }
    memset(con_info, 0, sizeof(*con_info));

    con_info->hca_info   = hca_info;
    con_info->con_priv   = con_priv;
    con_info->con_broken = 0;

    return 0;
}


int psucp_con_connect(psucp_con_info_t *con_info, psucp_info_msg_t *info_msg)
{
    psucp_hca_info_t *hca_info = con_info->hca_info;
    ucs_status_t status;
    ucp_ep_params_t ep_params;

    con_info->remote_tag    = info_msg->tag;
    con_info->small_msg_len = info_msg->small_msg_len;

    psucp_small_msg_sendbuf_check(con_info->small_msg_len);

    memset(&ep_params, 0, sizeof(ep_params));
    ep_params.field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS;
    ep_params.address    = (ucp_address_t *)info_msg->ucp_addr;

    status = ucp_ep_create(hca_info->ucp_worker, &ep_params, &con_info->ucp_ep);
    if (status != UCS_OK) { goto err_ep_create; }

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


psucp_info_msg_t *psucp_con_get_info_msg(psucp_con_info_t *con_info,
                                         unsigned long tag)
{
    psucp_hca_info_t *hca_info = con_info->hca_info;
    psucp_info_msg_t *info_msg = malloc(sizeof(*info_msg) +
                                        hca_info->my_ucp_address_size);

    assert(info_msg);
    assert(hca_info->my_ucp_address_size <= 0xffff);

    info_msg->tag           = tag;
    info_msg->small_msg_len = psucp_small_msg_len;

    info_msg->ucp_addr_size = (uint16_t)hca_info->my_ucp_address_size;
    memcpy(info_msg->ucp_addr, hca_info->my_ucp_address,
           info_msg->ucp_addr_size);

    return info_msg;
}


ssize_t psucp_sendv(psucp_con_info_t *con_info, struct iovec iov[2],
                    void *req_priv)
{
    ucs_status_ptr_t request;
    psucp_req_t *psucp_req;
    size_t len;
    size_t len_first;
#if 0 /* use UCP_DATATYPE_IOV ucp_tag_send_nb() */
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
#else /* individual ucp_tag_send_nb() for each iov[] */
    assert(iov[0].iov_len > 0);

    len = iov[0].iov_len + iov[1].iov_len;
#if 1
    // Copy small messages into one continuous buffer.
    if (len <= con_info->small_msg_len &&
        PSCOM_IF_CUDA(!pscom.env.cuda, 1) && /* do not copy if iov[1] could
                                                point to gpu mem */
        iov[1].iov_len /* has two fragments? */) {
        pscom_memcpy_from_iov(psucp_small_msg_sendbuf, iov, len);

        request = ucp_tag_send_nb(
            con_info->ucp_ep, psucp_small_msg_sendbuf, len,
            ucp_dt_make_contig(1), con_info->remote_tag,
            /*(ucp_send_callback_t)*/ psucp_req_send_small_done);
        if (UCS_PTR_IS_ERR(request)) { goto err_send; }
        if (!request) {
            // Common case. Sent inline. No request.
            pscom_psucp_sendv_done(req_priv);
        } else {
            psucp_req = (psucp_req_t *)request;
            // Free() the sendbuf when done (psucp_req_send_small_done()).
            psucp_req->type.send.sendbuf =
                psucp_small_msg_sendbuf_get_ownership();
            assert(!psucp_req->completed);
            psucp_req->type.send.req_priv = req_priv;

            psucp_pending_req_attach(request, con_info);
        }

        return len;
    }
#endif
    int i;
    len_first            = MIN(iov[0].iov_len, con_info->small_msg_len);
    struct iovec siov[3] = {{.iov_base = iov[0].iov_base, .iov_len = len_first},
                            {.iov_base = (void *)((char *)iov[0].iov_base +
                                                  len_first),
                             .iov_len  = iov[0].iov_len - len_first},
                            iov[1]};
    request              = NULL;

    // Send up to three messages:
    // 1st: iov[0], with up to con_info->small_msg_len bytes
    // 2nd: rest of iov[0], if iov[0] is longer than con_info->small_msg_len
    // 3rd: iov[1], if iov[1]->iov_len > 0
    for (i = 0; i < 3; i++) {
        size_t iov_len = siov[i].iov_len;
        if (!iov_len) { continue; }
        request = ucp_tag_send_nb(con_info->ucp_ep, siov[i].iov_base, iov_len,
                                  ucp_dt_make_contig(1), con_info->remote_tag,
                                  /*(ucp_send_callback_t)*/ psucp_req_send_done);
        if (UCS_PTR_IS_ERR(request)) { goto err_send; }

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
err_send: {
    ucs_status_t status = UCS_PTR_STATUS(request);

    psucp_err_status("ucp_tag_send_nb()", status);
    psucp_dprint(D_ERR, "psucp_sendv() : %s", psucp_err_str);
}
    return -EPIPE;
    ;
}


void psucp_progress(void)
{
    psucp_hca_info_t *hca_info = &psucp_default_hca;
    ucp_worker_progress(hca_info->ucp_worker);
}


size_t psucp_probe(psucp_msg_t *msg)
{
    psucp_hca_info_t *hca_info = &psucp_default_hca;

    if (psucp_recv_in_progress < psucp_max_recv) {
        msg->msg_tag = ucp_tag_probe_nb(hca_info->ucp_worker, 0 /* tag */,
                                        (ucp_tag_t)0 /* tag mask any */,
                                        1 /* remove */, &msg->info_tag);
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


static void psucp_req_recv_done(void *request, ucs_status_t status,
                                ucp_tag_recv_info_t *info)
{
    psucp_req_t *psucp_req     = (psucp_req_t *)request;
    psucp_con_info_t *con_info = psucp_req->con_info;

    psucp_req->completed = PSUCP_COMPLETED_RECV;

    if (con_info) {
        // On slow track. con_info set in psucp_irecv().
        // printf("%s:%u:%s PSUCP_COMPLETED_RECV slow\n", __FILE__, __LINE__,
        // __func__);
        pscom_read_pending_done(con_info->con_priv,
                                psucp_req->type.recv.req_priv);
        psucp_pending_req_dequeue_and_release(psucp_req);
        psucp_recv_req_dec();
    } /* else {
            // called from within ucp_tag_msg_recv_nb(). con_info is still
    unset. printf("%s:%u:%s PSUCP_COMPLETED_RECV fast\n", __FILE__, __LINE__,
    __func__);
    }
      */
}


ssize_t psucp_irecv(psucp_con_info_t *con_info, psucp_msg_t *msg, void *buf,
                    size_t size)
{
    psucp_hca_info_t *hca_info = &psucp_default_hca;
    ucs_status_ptr_t request;
    psucp_req_t *psucp_req;

    size_t len = size < msg->info_tag.length ? size : msg->info_tag.length;

    // printf("%s:%u:%s irecv msg length %3u, expected %3u\n",
    //        __FILE__, __LINE__, __func__, (unsigned)msg->info_tag.length,
    //        (unsigned)size);

    request = ucp_tag_msg_recv_nb(hca_info->ucp_worker, buf, len,
                                  ucp_dt_make_contig(1), msg->msg_tag,
                                  psucp_req_recv_done);

    if (UCS_PTR_IS_ERR(request)) { goto err_recv; }

    psucp_req = (psucp_req_t *)request;

    if (psucp_req->completed) {
        // On fast track. Request already completed (probably small message).
        pscom_read_done(con_info->con_priv, buf, len);
        psucp_req_release(psucp_req);
    } else {
        psucp_recv_req_inc();

        // psucp_req not yet done. Poll for completion later:
        psucp_pending_req_attach(request, con_info);
        psucp_req->type.recv.req_priv = (void *)
            pscom_read_pending(con_info->con_priv, len);
    }

    // printf("%s:%u:%s recv %u : %s\n", __FILE__, __LINE__, __func__,
    //       (unsigned) len, pscom_dumpstr(buf, len));
    return len;

err_recv: {
    ucs_status_t status = UCS_PTR_STATUS(request);

    psucp_err_status("ucp_tag_msg_recv_nb()", status);
    psucp_dprint(D_ERR, "psucp_recv() : %s", psucp_err_str);
}
    return -EPIPE;
    ;
}


/* RMA functions */
int psucp_rma_mem_register(void *addr, size_t length, void **rkeybuf,
                           uint16_t *bufsize, ucp_mem_h *memh)
{
    ucp_context_h ucp_context = psucp_default_hca.ucp_context;
    ucp_mem_map_params_t mem_map_params;
    ucs_status_t status;

    mem_map_params.field_mask = UCP_MEM_MAP_PARAM_FIELD_ADDRESS |
                                UCP_MEM_MAP_PARAM_FIELD_LENGTH;
    mem_map_params.address = addr;
    mem_map_params.length  = length;

    status = ucp_mem_map(ucp_context, &mem_map_params, memh);

    if (status != UCS_OK) {
        psucp_err_status("ucp_mem_map()", status);
        psucp_dprint(D_ERR, "psucp_rma_mem_register() : %s", psucp_err_str);
        return PSCOM_ERR_STDERROR;
    }

    status = ucp_rkey_pack(ucp_context, *memh, rkeybuf, (size_t *)bufsize);
    if (status != UCS_OK) { goto err_rkey; }

    return PSCOM_SUCCESS;

err_rkey:
    psucp_err_status("ucp_rkey_pack()", status);
    psucp_dprint(D_ERR, "psucp_rma_mem_register() : %s", psucp_err_str);
    ucp_mem_unmap(ucp_context, *memh);
    return PSCOM_ERR_STDERROR;
}


int psucp_rma_mem_deregister(ucp_mem_h memh)
{
    ucs_status_t status;
    ucp_context_h ucp_context = psucp_default_hca.ucp_context;

    status = ucp_mem_unmap(ucp_context, memh);

    if (status != UCS_OK) { goto err_dereg; }

    return PSCOM_SUCCESS;
err_dereg:
    psucp_err_status("ucp_mem_unmap()", status);
    psucp_dprint(D_ERR, "psucp_rma_mem_deregister() : %s", psucp_err_str);
    return PSCOM_ERR_STDERROR;
}


int psucp_rma_rkey_generate(psucp_con_info_t *con_info, void *rkeybuf,
                            ucp_rkey_h *rkey)
{
    ucs_status_t status;
    ucp_ep_h ep = con_info->ucp_ep;

    status = ucp_ep_rkey_unpack(ep, rkeybuf, rkey);

    if (status != UCS_OK) { goto err_keygen; }

    return PSCOM_SUCCESS;
err_keygen:
    psucp_err_status("ucp_ep_rkey_unpack()", status);
    psucp_dprint(D_ERR, "psucp_rma_rkey_generate() : %s", psucp_err_str);
    return PSCOM_ERR_STDERROR;
}


int psucp_rma_rkey_destroy(ucp_rkey_h rkey)
{
    ucp_rkey_destroy(rkey);
    return PSCOM_SUCCESS;
}


void psucp_rma_rkey_buf_free(void *rkey_buf)
{
    ucp_rkey_buffer_release(rkey_buf);
    return;
}


static void psucp_rma_put_done(void *request, ucs_status_t status)
{
    psucp_req_t *psucp_req = (psucp_req_t *)request;
    psucp_req->completed   = PSUCP_COMPLETED_SEND; // use the same tag as send
    pscom_con_t *con       = psucp_req->con_info->con_priv;
    psucp_con_rma_stat_t *con_rma_stat = (psucp_con_rma_stat_t *)
                                             con->arch.ucp.rma_stat;
    con_rma_stat->local_complete++;

    pscom_psucp_rma_put_done(psucp_req->type.send.req_priv);
    psucp_pending_req_dequeue_and_release(psucp_req);
}


int psucp_rma_put(psucp_con_info_t *ci, void *buffer, size_t length,
                  void *remote_addr, ucp_rkey_h ucp_rkey, void *req_priv)
{
    ucs_status_ptr_t request = NULL;
    psucp_req_t *psucp_req;
    pscom_con_t *con                   = ci->con_priv;
    psucp_con_rma_stat_t *con_rma_stat = (psucp_con_rma_stat_t *)
                                             con->arch.ucp.rma_stat;
    pscom_sock_t *sock           = get_sock(con->pub.socket);
    pscom_arch_sock_t *arch_sock = get_arch_sock(sock, PSCOM_CON_TYPE_UCP);
    assert(arch_sock);
    pscom_ucp_sock_t *ucp_sock = arch_sock->arch.ucp;

    request = ucp_put_nb(ci->ucp_ep, buffer, length, (uint64_t)remote_addr,
                         ucp_rkey,
                         /*(ucp_send_callback_t)*/ psucp_rma_put_done);
    if (UCS_PTR_IS_ERR(request)) { goto err_rma_put; }

    if (request) {
        psucp_pending_req_attach(request, ci);
        psucp_req = (psucp_req_t *)request;
        assert(!psucp_req->completed);
        psucp_req->type.send.req_priv = req_priv;
        con_rma_stat->issued_op_count++; // issue op locally
        /* flush local and remote */
        con_rma_stat->flush_local  = 1;
        con_rma_stat->flush_remote = 1;
        ucp_sock->flush_required   = 1;
    } else {
        /* direct return, only flush remote, this is not explained clearly in
         * ucp document, we assume that local completion is guaranteed */
        con_rma_stat->flush_remote = 1;
        ucp_sock->flush_required   = 1;
        pscom_psucp_rma_put_done(req_priv);
    }


    return PSCOM_SUCCESS;
err_rma_put: {
    ucs_status_t status = UCS_PTR_STATUS(request);

    psucp_err_status("ucp_put_nb()", status);
    psucp_dprint(D_ERR, "psucp_rma_put() : %s", psucp_err_str);
}
    return PSCOM_ERR_STDERROR;
}


static void psucp_rma_get_done(void *request, ucs_status_t status)
{
    psucp_req_t *psucp_req = (psucp_req_t *)request;
    psucp_req->completed   = PSUCP_COMPLETED_SEND; // use the same tag as send

    pscom_con_t *con                   = psucp_req->con_info->con_priv;
    psucp_con_rma_stat_t *con_rma_stat = (psucp_con_rma_stat_t *)
                                             con->arch.ucp.rma_stat;
    con_rma_stat->local_complete++;
    /* use the same `done` function as put */
    pscom_psucp_rma_put_done(psucp_req->type.send.req_priv);
    psucp_pending_req_dequeue_and_release(psucp_req);
}

int psucp_rma_get(psucp_con_info_t *ci, void *buffer, size_t length,
                  void *remote_addr, ucp_rkey_h ucp_rkey, void *req_priv)
{
    ucs_status_ptr_t request = NULL;
    psucp_req_t *psucp_req;
    pscom_con_t *con                   = ci->con_priv;
    psucp_con_rma_stat_t *con_rma_stat = (psucp_con_rma_stat_t *)
                                             con->arch.ucp.rma_stat;
    pscom_sock_t *sock           = get_sock(con->pub.socket);
    pscom_arch_sock_t *arch_sock = get_arch_sock(sock, PSCOM_CON_TYPE_UCP);
    assert(arch_sock);
    pscom_ucp_sock_t *ucp_sock = arch_sock->arch.ucp;

    request = ucp_get_nb(ci->ucp_ep, buffer, length, (uint64_t)remote_addr,
                         ucp_rkey,
                         /*(ucp_send_callback_t)*/ psucp_rma_get_done);
    if (UCS_PTR_IS_ERR(request)) { goto err_rma_get; }

    if (request) {
        psucp_pending_req_attach(request, ci);
        psucp_req = (psucp_req_t *)request;
        assert(!psucp_req->completed);
        psucp_req->type.send.req_priv = req_priv;
        con_rma_stat->issued_op_count++; // issue op locally
        /* flush local and remote */
        con_rma_stat->flush_local  = 1;
        con_rma_stat->flush_remote = 1;
        ucp_sock->flush_required   = 1;
    } else {
        /* direct return, we assume a local completion, for rma_get, local
         * completion means total completion of this operation, no need to
         * flush??? */
        con_rma_stat->flush_remote = 1;
        ucp_sock->flush_required   = 1;
        /* use the same `done` function as put */
        pscom_psucp_rma_put_done(req_priv);
    }


    return PSCOM_SUCCESS;
err_rma_get: {
    ucs_status_t status = UCS_PTR_STATUS(request);

    psucp_err_status("ucp_get_nb()", status);
    psucp_dprint(D_ERR, "psucp_rma_get() : %s", psucp_err_str);
}
    return PSCOM_ERR_STDERROR;
}


static void psucp_rma_cs_done(void *request, ucs_status_t status,
                              void *user_data)
{
    psucp_req_t *psucp_req = (psucp_req_t *)request;
    psucp_req->completed   = PSUCP_COMPLETED_SEND; // use the same tag as send

    pscom_con_t *con                   = psucp_req->con_info->con_priv;
    psucp_con_rma_stat_t *con_rma_stat = (psucp_con_rma_stat_t *)
                                             con->arch.ucp.rma_stat;
    con_rma_stat->local_complete++;

    pscom_psucp_rma_cs_done(psucp_req->type.send.req_priv);
    psucp_pending_req_dequeue_and_release(psucp_req);
}

static void psucp_rma_acc_done(void *request, ucs_status_t status,
                               void *user_data)
{
    psucp_req_t *psucp_req = (psucp_req_t *)request;
    psucp_req->completed   = PSUCP_COMPLETED_SEND; // use the same tag as send

    pscom_con_t *con                   = psucp_req->con_info->con_priv;
    psucp_con_rma_stat_t *con_rma_stat = (psucp_con_rma_stat_t *)
                                             con->arch.ucp.rma_stat;
    con_rma_stat->local_complete++;

    psucp_atomic_segment_ctx_t *seg_ctx = (psucp_atomic_segment_ctx_t *)
        user_data;
    /* if segment context is set in userdata */
    if (seg_ctx != NULL) {
        seg_ctx->remaining--;
        if (seg_ctx->remaining == 0) {
            assert(psucp_req->type.send.req_priv == seg_ctx->req_priv);
            pscom_psucp_rma_put_done(seg_ctx->req_priv);
            free(seg_ctx);
        }
    } else {
        /* no segment context is set in userdata */
        if (psucp_req->type.send.req_priv) {
            pscom_psucp_rma_put_done(psucp_req->type.send.req_priv);
        }
    }
    psucp_pending_req_dequeue_and_release(psucp_req);
}

int psucp_rma_atomic_op(psucp_con_info_t *ci, void *buffer, size_t length,
                        void *remote_addr, void *result_addr,
                        ucp_atomic_op_t ucp_opcode, ucp_rkey_h ucp_rkey,
                        void *req_priv)
{
    ucs_status_ptr_t request = NULL;
    psucp_req_t *psucp_req;
    pscom_con_t *con                   = ci->con_priv;
    psucp_con_rma_stat_t *con_rma_stat = (psucp_con_rma_stat_t *)
                                             con->arch.ucp.rma_stat;
    pscom_sock_t *sock           = get_sock(con->pub.socket);
    pscom_arch_sock_t *arch_sock = get_arch_sock(sock, PSCOM_CON_TYPE_UCP);
    assert(arch_sock);
    pscom_ucp_sock_t *ucp_sock = arch_sock->arch.ucp;

    if (ucp_opcode == UCP_ATOMIC_OP_LAST) { goto err_rma_opcode; }

    assert(result_addr); /* fetch op and CAS need a valid result buffer */

    ucp_request_param_t param = {
        /* Only ucp_dt_make_contig(4) and
           ucp_dt_make_contig(8) are valid, which
           meansonly 4 or 8 bytes of data length is
           acceptable. */
        .datatype     = ucp_dt_make_contig(length),
        .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                        UCP_OP_ATTR_FIELD_DATATYPE |
                        UCP_OP_ATTR_FIELD_REPLY_BUFFER,
        .reply_buffer = result_addr,
    };

    if (ucp_opcode == UCP_ATOMIC_OP_CSWAP) {
        param.cb.send = (ucp_send_nbx_callback_t)psucp_rma_cs_done;
    } else {
        param.cb.send = (ucp_send_nbx_callback_t)psucp_rma_acc_done;
    }

    /* Currently atomic operations can handle one element only. Thus, count must
     * be set to 1. */
    request = ucp_atomic_op_nbx(ci->ucp_ep, (ucp_atomic_op_t)ucp_opcode, buffer,
                                1, (uint64_t)remote_addr, ucp_rkey, &param);
    if (UCS_PTR_IS_ERR(request)) { goto err_rma_atomic; }

    if (request) {
        psucp_pending_req_attach(request, ci);
        psucp_req = (psucp_req_t *)request;
        assert(!psucp_req->completed);
        psucp_req->type.send.req_priv = req_priv;
        con_rma_stat->issued_op_count++; // issue op locally
        /* flush local and remote */
        con_rma_stat->flush_local  = 1;
        con_rma_stat->flush_remote = 1;
        ucp_sock->flush_required   = 1;
    } else {
        /* direct return, only flush remote, this is not explained clearly in
         * ucp document, we assume that local completion is guaranteed*/
        con_rma_stat->flush_remote = 1;
        ucp_sock->flush_required   = 1;
        if (ucp_opcode == UCP_ATOMIC_OP_CSWAP) {
            pscom_psucp_rma_cs_done(req_priv);
        } else {
            pscom_psucp_rma_put_done(req_priv);
        }
    }


    return PSCOM_SUCCESS;
err_rma_atomic: {
    ucs_status_t status = UCS_PTR_STATUS(request);

    psucp_err_status("ucp_atomic_op_nbx()", status);
    psucp_dprint(D_ERR, "psucp_rma_atomic_op() : %s", psucp_err_str);
    return PSCOM_ERR_STDERROR;
}
err_rma_opcode: {
    printf("error: psucp_rma_atomic_op() opcode: UCP_ATOMIC_OP_LAST\n");
    return PSCOM_ERR_STDERROR;
}
}

int psucp_rma_atomic_op_segment(psucp_con_info_t *ci, void *buffer,
                                size_t length, pscom_datatype_t data_type,
                                void *remote_addr, void *result_addr,
                                ucp_atomic_op_t ucp_opcode, ucp_rkey_h ucp_rkey,
                                void *req_priv)
{
    ucs_status_ptr_t request = NULL;
    psucp_req_t *psucp_req;
    pscom_con_t *con                   = ci->con_priv;
    psucp_con_rma_stat_t *con_rma_stat = (psucp_con_rma_stat_t *)
                                             con->arch.ucp.rma_stat;
    pscom_sock_t *sock           = get_sock(con->pub.socket);
    pscom_arch_sock_t *arch_sock = get_arch_sock(sock, PSCOM_CON_TYPE_UCP);
    assert(arch_sock);
    pscom_ucp_sock_t *ucp_sock = arch_sock->arch.ucp;

    if (ucp_opcode == UCP_ATOMIC_OP_LAST) { goto err_rma_opcode; }

    int data_size      = pscom_datatype_get_size(data_type);
    size_t segment_num = length / data_size;

    if (segment_num == 0) {
        pscom_psucp_rma_put_done(req_priv);
        return PSCOM_SUCCESS;
    }

    psucp_atomic_segment_ctx_t *seg_ctx = malloc(
        sizeof(psucp_atomic_segment_ctx_t));
    seg_ctx->remaining = segment_num;
    seg_ctx->req_priv  = req_priv;

    ucp_request_param_t param = {
        /* Only ucp_dt_make_contig(4) and ucp_dt_make_contig(8) are valid, which
         * means only 4 or 8 bytes of data length is acceptable. */
        .datatype  = ucp_dt_make_contig(data_size),
        .cb.send   = (ucp_send_nbx_callback_t)psucp_rma_acc_done,
        .user_data = seg_ctx,
    };


    if (result_addr) /* get_acc */
    {
        param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                             UCP_OP_ATTR_FIELD_DATATYPE |
                             UCP_OP_ATTR_FIELD_USER_DATA |
                             UCP_OP_ATTR_FIELD_REPLY_BUFFER;

    } else /* acc, no reply is required */
    {
        param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                             UCP_OP_ATTR_FIELD_DATATYPE |
                             UCP_OP_ATTR_FIELD_USER_DATA;
    }

    /* pipelining the acc or get acc operations */
    for (size_t i = 0; i < segment_num; i++) {
        /* set offset for result buffer for get acc */
        if (result_addr) {
            param.reply_buffer = (void *)((char *)result_addr + i * data_size);
        }
        /* Currently atomic operations can handle one element only. Thus, count
         * must be set to 1. */
        request = ucp_atomic_op_nbx(ci->ucp_ep, (ucp_atomic_op_t)ucp_opcode,
                                    (void *)((char *)buffer + i * data_size), 1,
                                    (uint64_t)remote_addr + i * data_size,
                                    ucp_rkey, &param);
        if (UCS_PTR_IS_ERR(request)) { goto err_rma_atomic; }

        if (request) {
            psucp_pending_req_attach(request, ci);
            psucp_req = (psucp_req_t *)request;
            assert(!psucp_req->completed);
            psucp_req->type.send.req_priv = req_priv;
            con_rma_stat->issued_op_count++; // issue op locally
            /* flush local and remote */
            con_rma_stat->flush_local  = 1;
            con_rma_stat->flush_remote = 1;
            ucp_sock->flush_required   = 1;
        } else {
            /* direct return, only flush remote, this is not explained clearly
             * in ucp document, we assume that local completion is guaranteed*/
            con_rma_stat->flush_remote = 1;
            ucp_sock->flush_required   = 1;
            /* finish one segment */
            seg_ctx->remaining--;
            if (seg_ctx->remaining == 0) {
                pscom_psucp_rma_put_done(req_priv);
                free(seg_ctx);
            }
        }
    }

    return PSCOM_SUCCESS;
err_rma_atomic: {
    ucs_status_t status = UCS_PTR_STATUS(request);

    psucp_err_status("ucp_atomic_op_nbx()", status);
    psucp_dprint(D_ERR, "psucp_rma_atomic_op_segment() : %s", psucp_err_str);
    return PSCOM_ERR_STDERROR;
}
err_rma_opcode: {
    printf("error: psucp_rma_atomic_op_segment() opcode: UCP_ATOMIC_OP_LAST\n");
    return PSCOM_ERR_STDERROR;
}
}


static void psucp_rma_flush_cb(void *request, ucs_status_t status)
{
    // empty
}

/* Important comments:
 * If one ucp sock is used for multiple windows in MPI RMA implementation, when
 * fence is issued on one window, all the RMA communications issued on this
 * worker will be flushed. This means that the RMA communications issued by
 * another window which shares the same socket and worker will also be flushed.
 * In conclusion, worker(socket) rma flush operation is not exclusive for
 * certain MPI window when this worker(socket) is shared by multiple windows. */

/* Blocking flush implementation with non-blocking worker flush
 * This function flushes all RMA communication on the worker.
 * All the RMA communications issued on this worker prior to this call are
 * complete at the ORIGIN and TARGET side when this call returns.
 */
int psucp_rma_worker_flush(void)
{
    psucp_hca_info_t *hca_info = &psucp_default_hca;
    ucs_status_t status;

    /* non-blocking version */
    /* flag = 0, empty callback function is provided*/
    void *request = ucp_worker_flush_nb(hca_info->ucp_worker, 0,
                                        &psucp_rma_flush_cb);

    if (request == NULL) {
        return UCS_OK;
    } else if (UCS_PTR_IS_ERR(request)) {
        status = UCS_PTR_STATUS(request);
        psucp_err_status("ucp_worker_flush_nb()", status);
        psucp_dprint(D_ERR, "psucp_rma_worker_flush() : %s", psucp_err_str);
        return PSCOM_ERR_STDERROR;
    } else {
        do {
            ucp_worker_progress(hca_info->ucp_worker);
            status = ucp_request_check_status(request);
        } while (status == UCS_INPROGRESS);
        ucp_request_release(request);
        if (status == UCS_OK) {
            return PSCOM_SUCCESS;
        } else {
            psucp_err_status("ucp_worker_progress()", status);
            psucp_dprint(D_ERR, "psucp_rma_worker_flush() : %s", psucp_err_str);
            return PSCOM_ERR_STDERROR;
        }
    }
}


/* Important comments:
 * We have the same circumstance as worker flush. In conclusion, the
 * ep(connection) rma flush operation is not exclusive for certain pscom
 * connection when this connection is shared by multiple windows. */

/* Blocking flush implementation with non-blocking ep flush
 * This function flushes all RMA communication on the endpoint(connection).
 * All the RMA communications issued on this ep prior to this call are complete
 * at the ORIGIN and TARGET side when this call returns
 */
int psucp_rma_ep_flush(psucp_con_info_t *con_info)
{
    psucp_hca_info_t *hca_info = &psucp_default_hca;
    ucs_status_t status;
    void *request = ucp_ep_flush_nb(con_info->ucp_ep, 0, &psucp_rma_flush_cb);
    if (request == NULL) {
        return UCS_OK;
    } else if (UCS_PTR_IS_ERR(request)) {
        status = UCS_PTR_STATUS(request);
        psucp_err_status("ucp_ep_flush_nb()", status);
        psucp_dprint(D_ERR, "psucp_rma_ep_flush() : %s", psucp_err_str);
        return PSCOM_ERR_STDERROR;
    } else {
        do {
            ucp_worker_progress(hca_info->ucp_worker);
            status = ucp_request_check_status(request);
        } while (status == UCS_INPROGRESS);
        ucp_request_release(request);
        if (status == UCS_OK) {
            return PSCOM_SUCCESS;
        } else {
            psucp_err_status("ucp_worker_progress()", status);
            psucp_dprint(D_ERR, "psucp_rma_ep_flush() : %s", psucp_err_str);
            return PSCOM_ERR_STDERROR;
        }
    }
}


int psucp_rma_ep_flush_local(psucp_con_info_t *con_info)
{
    psucp_hca_info_t *hca_info         = &psucp_default_hca;
    pscom_con_t *con                   = con_info->con_priv;
    psucp_con_rma_stat_t *con_rma_stat = (psucp_con_rma_stat_t *)
                                             con->arch.ucp.rma_stat;
    /* Note: This implementation only guarantee local completion using the
     * counter but this may lead to endless cycle here. One alternative solution
     * is to flush the ep completely as above to guarantee completion at origin
     * and target side. */
    do {
        ucp_worker_progress(hca_info->ucp_worker);
    } while (con_rma_stat->issued_op_count > con_rma_stat->local_complete);

    return PSCOM_SUCCESS;
}


int psucp_rma_native_check(pscom_rma_op_t rma_op)
{
    psucp_rma_module_t *ucp_rma = &ucp_rma_module;

    /* check if rma comm api is available */
    if (ucp_rma->rma_mask & (1 << rma_op)) { return PSCOM_SUCCESS; }
    /* not supported */
    return PSCOM_ERR_INVALID;
}


int psucp_rma_atomics_check(pscom_rma_atomic_op_t atomic_op,
                            pscom_datatype_t data_type, size_t length,
                            pscom_rma_op_t rma_op)
{
    psucp_rma_module_t *ucp_rma = &ucp_rma_module;
    /* Note:
     * Many data types are defined in MPICH and pscom. Which should we enable
     * here? Only 4 or 8 bytes datatype is supported by UCP.
     * For now, we only allow integer with size of 4 or 8
     */
    switch (data_type) {
    case PSCOM_INT:
    case PSCOM_UNSIGNED:
    case PSCOM_LONG:
    case PSCOM_UNSIGNED_LONG:
    case PSCOM_LONG_LONG_INT: break;

    default: return PSCOM_ERR_INVALID; break;
    }

    /* if data length % size != 0, something is wrong with the data length and
     * we can not pipeline */
    int size = pscom_datatype_get_size(data_type);
    if (length % size != 0) { return PSCOM_ERR_INVALID; }

    if (rma_op == PSCOM_RMA_COMPARE_AND_SWAP) {
        if (((length == 4) || (length == 8)) && ((int)length == size)) {
            return PSCOM_SUCCESS;
        } else {
            return PSCOM_ERR_INVALID;
        }
    }

    int temp_op_type = (atomic_op & 0x0000000f) - 1;
    if (rma_op == PSCOM_RMA_GET_ACCUMULATE) {
        if (ucp_rma->rma_fetch_op_mask & (1 << temp_op_type)) {
            /* check if rma op is supported */
            return PSCOM_SUCCESS;
        } else {
            return PSCOM_ERR_INVALID;
        }
    }

    if (rma_op == PSCOM_RMA_FETCH_AND_OP) {
        if ((ucp_rma->rma_fetch_op_mask & (1 << temp_op_type)) &&
            ((int)length == size)) {
            /* check if rma op is supported, only one element is allowed for fop
             */
            return PSCOM_SUCCESS;
        } else {
            return PSCOM_ERR_INVALID;
        }
    }

    if (rma_op == PSCOM_RMA_ACCUMULATE) {
        if (ucp_rma->rma_acc_op_mask & (1 << temp_op_type)) {
            /* check if rma op is supported */
            return PSCOM_SUCCESS;
        } else {
            return PSCOM_ERR_INVALID;
        }
    }

    return PSCOM_ERR_INVALID;
}

/* information on RMA accumulate operations
********************************************
typedef int MPI_Op;
#define MPI_MAX     (MPI_Op)(0x58000001)
#define MPI_MIN     (MPI_Op)(0x58000002)
#define MPI_SUM     (MPI_Op)(0x58000003)
#define MPI_PROD    (MPI_Op)(0x58000004)
#define MPI_LAND    (MPI_Op)(0x58000005)
#define MPI_BAND    (MPI_Op)(0x58000006)
#define MPI_LOR     (MPI_Op)(0x58000007)
#define MPI_BOR     (MPI_Op)(0x58000008)
#define MPI_LXOR    (MPI_Op)(0x58000009)
#define MPI_BXOR    (MPI_Op)(0x5800000a)
#define MPI_MINLOC  (MPI_Op)(0x5800000b)
#define MPI_MAXLOC  (MPI_Op)(0x5800000c)
#define MPI_REPLACE (MPI_Op)(0x5800000d)
#define MPI_NO_OP   (MPI_Op)(0x5800000e)

MPI op :
1 MPI_MAX maximum                          not supported
2 MPI_MIN minimum                          not supported
3 MPI_SUM sum                              supported
4 MPI_PROD product                         not supported
5 MPI_LAND logical and                     not supported
6 MPI_BAND bit-wise and                    supported
7 MPI_LOR logical or                       not supported
8 MPI_BOR bit-wise or                      supported
9 MPI_LXOR logical exclusive or (xor)      not supported
10 MPI_BXOR bit-wise exclusive or (xor)    supported
11 MPI_MINLOC min value and location       not supported
12 MPI_MAXLOC max value and location       not supported
13 MPI_REPLACE                             supported
   MPI_NO_OP   (MPI_Op)(0x5800000e)
********************************************
initialized rma_op_mask  0b0001 0010 1010 0100
********************************************
ucx supported hardware-enabled RMA acc ops
enum ucp_atomic_op_t used for ucp_atomic_op_nbx
UCP_ATOMIC_OP_ADD Atomic add 0
UCP_ATOMIC_OP_SWAP Atomic swap 1
UCP_ATOMIC_OP_CSWAP Atomic conditional swap 2
UCP_ATOMIC_OP_AND Atomic and 3
UCP_ATOMIC_OP_OR Atomic or 4
UCP_ATOMIC_OP_XOR Atomic xor 5
*/
void psucp_init_rma_masks(void)
{
    psucp_rma_module_t *pscom_ucp_rma_module = &ucp_rma_module;

    /* init plugin rma masks, hardcoded for now */
    pscom_ucp_rma_module->rma_mask = 0;
    pscom_ucp_rma_module->rma_mask |= (1 << PSCOM_RMA_PUT);
    pscom_ucp_rma_module->rma_mask |= (1 << PSCOM_RMA_GET);
    pscom_ucp_rma_module->rma_mask |= (1 << PSCOM_RMA_ACCUMULATE);
    pscom_ucp_rma_module->rma_mask |= (1 << PSCOM_RMA_GET_ACCUMULATE);
    pscom_ucp_rma_module->rma_mask |= (1 << PSCOM_RMA_FETCH_AND_OP);
    pscom_ucp_rma_module->rma_mask |= (1 << PSCOM_RMA_COMPARE_AND_SWAP);

    /* determined by which atomic operation is supported by the hardware */
    /* mask used for get acc and fop */
    pscom_ucp_rma_module->rma_fetch_op_mask = 0b0001001010100100;
    /* mask used for acc */
    pscom_ucp_rma_module->rma_acc_op_mask   = 0b0000001010100100;

    return;
}


/**
 * @brief this converts pscom atomic op code (mpich op code) into ucp atomic op
 * code
 *
 * @param rma_opcode pscom op code (MPICH op code)
 * @return ucp_atomic_op_t
 *
 */
ucp_atomic_op_t psucp_rma_opcode_convert(pscom_rma_atomic_op_t rma_opcode)
{
    switch (rma_opcode) {
    case PSCOM_SUM: return UCP_ATOMIC_OP_ADD; break;
    case PSCOM_BAND: return UCP_ATOMIC_OP_AND; break;
    case PSCOM_BOR: return UCP_ATOMIC_OP_OR; break;
    case PSCOM_BXOR: return UCP_ATOMIC_OP_XOR; break;
    case PSCOM_REPLACE: return UCP_ATOMIC_OP_SWAP; break;
    default: break;
    }
    /* we use `UCP_ATOMIC_OP_LAST` as a placeholder for an invalid operation
     * here */
    return UCP_ATOMIC_OP_LAST;
}
