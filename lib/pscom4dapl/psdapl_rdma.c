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

#if 0
 ToDo:- flush_evd() !!! Polling auf letztem byte?

#endif


#include "list.h"

typedef struct psdapl_mregion {
    DAT_LMR_HANDLE lmr_handle;
    DAT_LMR_CONTEXT lmr_context;
    DAT_RMR_CONTEXT rmr_context;
} psdapl_mregion_t;


struct psdapl_mregion_cache {
    struct list_head next;
    psdapl_mregion_t mregion;
    void *buf;
    size_t size;

    psdapl_socket_t *socket;
    unsigned use_cnt;
};


#define psdapl_mregion_cache_size 6

static psdapl_mregion_cache_t _psdapl_mregion_cache[psdapl_mregion_cache_size];
static LIST_HEAD(psdapl_mregion_cache);


static unsigned psdapl_page_size = 0;


static void psdapl_page_size_init(void)
{
    if (!psdapl_page_size) { psdapl_page_size = getpagesize(); }
    assert(psdapl_page_size != 0);
    assert((psdapl_page_size & (psdapl_page_size - 1)) == 0); /* power of 2 */
}


static void psdapl_mregion_deregister(psdapl_mregion_t *mregion)
{
    if (mregion->lmr_handle) {
        dat_lmr_free(mregion->lmr_handle);
        mregion->lmr_handle = 0;
    }
}


static void psdapl_mregion_cache_clear(void)
{
    int i;
    for (i = 0; i < psdapl_mregion_cache_size; i++) {
        psdapl_mregion_cache_t *mreg = &_psdapl_mregion_cache[i];
        if (!mreg->use_cnt) {
            psdapl_mregion_deregister(&mreg->mregion);
            mreg->buf  = NULL;
            mreg->size = 0;
        }
    }
}


static void psdapl_mregion_cache_init(void)
{
    static int initialized = 0;
    if (initialized) { return; }
    initialized = 1;

    int i;
    memset(_psdapl_mregion_cache, 0, sizeof(_psdapl_mregion_cache));
    for (i = 0; i < psdapl_mregion_cache_size; i++) {
        psdapl_mregion_cache_t *mreg = &_psdapl_mregion_cache[i];
        mreg->buf                    = NULL;
        mreg->size                   = 0;
        mreg->use_cnt                = 0;
        list_add_tail(&mreg->next, &psdapl_mregion_cache);
    }
}


static inline int psdapl_mregion_is_inside(void *mreg_buf, size_t mreg_size,
                                           void *buf, size_t size)
{
    return (buf >= mreg_buf) &&
           ((char *)buf + size <= (char *)mreg_buf + mreg_size);
}


/* Find a the regin buf_size inside the cache */
static psdapl_mregion_cache_t *psdapl_mregion_find(void *buf, size_t size,
                                                   psdapl_socket_t *socket)
{
    struct list_head *pos;
    list_for_each (pos, &psdapl_mregion_cache) {
        psdapl_mregion_cache_t *mreg = list_entry(pos, psdapl_mregion_cache_t,
                                                  next);
        if (psdapl_mregion_is_inside(mreg->buf, mreg->size, buf, size) &&
            (mreg->socket == socket)) {
            return mreg;
        }
    }

    return NULL;
}


/* make mreg the first in the list */
static void psdapl_mregion_use(psdapl_mregion_cache_t *mreg)
{
    mreg->use_cnt++;
    if (&mreg->next == psdapl_mregion_cache.next) {
        /* already first entry */
        return;
    }
    list_del(&mreg->next);
    list_add(&mreg->next, &psdapl_mregion_cache);
}


static void psdapl_mregion_use_done(psdapl_mregion_cache_t *mreg)
{
    mreg->use_cnt--;
}


static psdapl_mregion_cache_t *psdapl_mregion_get_oldest(void)
{
    return list_entry(psdapl_mregion_cache.prev, psdapl_mregion_cache_t, next);
}


static DAT_RETURN psdapl_mregion_register(psdapl_mregion_t *mregion, void *buf,
                                          size_t size, psdapl_socket_t *socket)
{
    DAT_RETURN dat_rc;

    DAT_REGION_DESCRIPTION region;
    region.for_va = buf;

    DAT_VLEN registered_size     = 0;
    DAT_VADDR registered_address = 0;

    dat_rc = dat_lmr_create(socket->ia_handle, DAT_MEM_TYPE_VIRTUAL, region,
                            size, socket->pz_handle, DAT_MEM_PRIV_ALL_FLAG,
                            &mregion->lmr_handle, &mregion->lmr_context,
                            &mregion->rmr_context, &registered_size,
                            &registered_address);

    return dat_rc;
}


/* get lmr and rmr Handles from mem region buf:size. from cache.
 * call psdapl_put_mregion() after usage!
 * return NULL on error. */
psdapl_mregion_cache_t *psdapl_get_mregion(void *buf, size_t size,
                                           psdapl_con_info_t *ci)
{
    psdapl_mregion_cache_t *mreg;

    mreg = psdapl_mregion_find(buf, size, ci->socket);
    if (mreg) {
        psdapl_mregion_use(mreg);
        return mreg;
    }

    /* dec buf and inc size to page_size borders. */

    unsigned long page_mask = (psdapl_page_size - 1);
    size += ((unsigned long)buf) & page_mask;
    size = (size + page_mask) & ~page_mask;
    buf  = (void *)((unsigned long)buf & ~page_mask);

    /* Use oldest cache entry */
    mreg = psdapl_mregion_get_oldest();
    if (mreg->use_cnt) { goto err_in_use; }

    /* free oldest entry */
    psdapl_mregion_deregister(&mreg->mregion);
    mreg->buf  = NULL;
    mreg->size = 0;

    DAT_RETURN dat_rc;
    dat_rc = psdapl_mregion_register(&mreg->mregion, buf, size, ci->socket);
    if (dat_rc != DAT_SUCCESS) { goto err_register; }

    mreg->buf    = buf;
    mreg->size   = size;
    mreg->socket = ci->socket;

    psdapl_mregion_use(mreg);

    return mreg;
err_in_use:
    psdapl_dprint(3, "psdapl_get_mregion() failed : no free resources");
    return NULL;
err_register:
    psdapl_dprint_dat_err(3, dat_rc, "dat_lmr_create() failed");
    return NULL;
}


DAT_RMR_CONTEXT psdapl_get_rmr_context(psdapl_mregion_cache_t *mreg)
{
    return mreg->mregion.rmr_context;
}


void psdapl_put_mregion(psdapl_mregion_cache_t *mreg)
{
    psdapl_mregion_use_done(mreg);
}


/*
static
void psdapl_free_rdma_req(psdapl_rdma_req_t *req)
{
        free(req);
}


static
psdapl_rdma_req_t *psdapl_create_rdma_req(void)
{
        psdapl_rdma_req_t *req = calloc(sizeof(*req), 1);

        req->io_done = psdapl_free_rdma_req;

        return req;
}
*/

/* return -1 on error */
int psdapl_post_rdma_put(psdapl_rdma_req_t *req)
{
    psdapl_mregion_cache_t *mreg;
    psdapl_con_info_t *ci = req->ci;

    mreg = psdapl_get_mregion(req->lmr_buf, req->size, ci);
    if (!mreg) { goto err_get_mregion; }

    req->mreg = mreg;

    DAT_RETURN dat_rc;
    DAT_LMR_TRIPLET lmr;
    DAT_RMR_TRIPLET rmr;

    lmr.lmr_context     = mreg->mregion.lmr_context;
    lmr.pad             = 0;
    lmr.virtual_address = psdapl_mem2vaddr(req->lmr_buf);
    lmr.segment_length  = req->size;

    rmr.rmr_context    = req->rmr_context;
    rmr.pad            = 0;
    rmr.target_address = req->rmr_vaddr;
    rmr.segment_length = req->size;

    DAT_DTO_COOKIE cookie;
    cookie.as_ptr = req;

    dat_rc = dat_ep_post_rdma_write(ci->ep_handle, 1, &lmr, cookie, &rmr,
                                    0 /* DAT_COMPLETION_SUPPRESS_FLAG*/);
    if (dat_rc != DAT_SUCCESS) { goto err_rdma_write; }

    return 0;
err_get_mregion:
    return -1;
err_rdma_write:
    psdapl_dprint_dat_err(3, dat_rc, "dat_ep_post_rdma_write() failed");
    psdapl_put_mregion(mreg);
    return -1;
}


/* return -1 on error */
int psdapl_post_rdma_get(psdapl_rdma_req_t *req)
{
    psdapl_mregion_cache_t *mreg;
    psdapl_con_info_t *ci = req->ci;

    mreg = psdapl_get_mregion(req->lmr_buf, req->size, ci);
    if (!mreg) { goto err_get_mregion; }

    req->mreg = mreg;

    DAT_RETURN dat_rc;
    DAT_LMR_TRIPLET lmr;
    DAT_RMR_TRIPLET rmr;

    lmr.lmr_context     = mreg->mregion.lmr_context;
    lmr.pad             = 0;
    lmr.virtual_address = psdapl_mem2vaddr(req->lmr_buf);
    lmr.segment_length  = req->size;

    rmr.rmr_context    = req->rmr_context;
    rmr.pad            = 0;
    rmr.target_address = req->rmr_vaddr;
    rmr.segment_length = req->size;

    DAT_DTO_COOKIE cookie;
    cookie.as_ptr = req;

    dat_rc = dat_ep_post_rdma_read(ci->ep_handle, 1, &lmr, cookie, &rmr,
                                   0 /* DAT_COMPLETION_SUPPRESS_FLAG*/);
    if (dat_rc != DAT_SUCCESS) { goto err_rdma_read; }

    return 0;
err_get_mregion:
    return -1;
err_rdma_read:
    psdapl_dprint_dat_err(3, dat_rc, "dat_ep_post_rdma_read() failed");
    psdapl_put_mregion(mreg);
    return -1;
}


static void do_DTO_COMPLETION_EVENT(psdapl_con_info_t *ci,
                                    DAT_DTO_COMPLETION_EVENT_DATA *event)
{
    if (event->status != DAT_DTO_SUCCESS /* DAT_SUCCESS*/) {
        psdapl_dprint_dat_err(0, event->status,
                              "Warning: do_DTO_COMPLETION_EVENT() failed");
    }

    psdapl_rdma_req_t *req = (psdapl_rdma_req_t *)event->user_cookie.as_ptr;
    if (!req) { return; }

    assert(req->mreg);
    psdapl_put_mregion(req->mreg);
    req->mreg = NULL;

    void (*io_done)(psdapl_rdma_req_t *req) = req->io_done;

    if (io_done) { io_done(req); }
}
