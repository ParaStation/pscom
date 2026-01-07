/*
 * ParaStation
 *
 * Copyright (C) 2014-201 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdlib.h>
#include <malloc.h>
#include "list.h"
#include "psshmalloc.h"

typedef struct psoib_mregion_cache {
    struct list_head next;
    void *buf;
    size_t size;
    psoib_con_info_t *ci;
    psoib_rma_mreg_t mregion;
    unsigned use_cnt;
} psoib_mregion_cache_t;

int psoib_mregion_malloc_options         = 1;
unsigned psoib_mregion_cache_max_size    = PSOIB_MREGION_CACHE_MAX_SIZE_DEFAULT;
static unsigned psoib_mregion_cache_size = 0;
static LIST_HEAD(psoib_mregion_cache);

static unsigned psoib_page_size;
static void *psoib_safe_mreg_start = NULL;
static void *psoib_safe_mreg_end   = NULL;


static inline int psoib_mregion_is_inside(psoib_mregion_cache_t *mregc,
                                          void *buf, size_t size)
{
    return (buf >= mregc->buf) &&
           ((char *)buf + size <= (char *)mregc->buf + mregc->size);
}


/* Find a region buf[0:size] in the cache */
static psoib_mregion_cache_t *psoib_mregion_find(void *buf, size_t size)
{
    struct list_head *pos;
    list_for_each (pos, &psoib_mregion_cache) {
        psoib_mregion_cache_t *mregc = list_entry(pos, psoib_mregion_cache_t,
                                                  next);
        if (psoib_mregion_is_inside(mregc, buf, size)) { return mregc; }
    }

    return NULL;
}


static void psoib_mregion_enq(psoib_mregion_cache_t *mregc)
{
    list_add(&mregc->next, &psoib_mregion_cache);
    psoib_mregion_cache_size++;
}


static void psoib_mregion_deq(psoib_mregion_cache_t *mregc)
{
    list_del(&mregc->next);
    psoib_mregion_cache_size--;
}


/* increment the use count of mregc and move it to the head (LRU) */
static void psoib_mregion_use_inc(psoib_mregion_cache_t *mregc)
{
    mregc->use_cnt++;
    if (&mregc->next == psoib_mregion_cache.next) {
        /* already first entry */
        return;
    }
    list_del(&mregc->next);
    list_add(&mregc->next, &psoib_mregion_cache);
}


static void psoib_mregion_use_dec(psoib_mregion_cache_t *mregc)
{
    mregc->use_cnt--;
}


static psoib_mregion_cache_t *psoib_mregion_create(void *buf, size_t size,
                                                   psoib_con_info_t *ci)
{
    psoib_mregion_cache_t *mregc = (psoib_mregion_cache_t *)malloc(
        sizeof(psoib_mregion_cache_t));
    int err;

    mregc->use_cnt = 0;

    err = psoib_rma_mreg_register(&mregc->mregion, buf, size, ci);
    if (err) { goto err_register; }

#if 0 /* DON'T ALIGN FOR ibv_reg_mr()! */

	/* dec buf and inc size to page_size borders. */
	unsigned long page_mask = (psoib_page_size - 1);
	size += ((unsigned long) buf) & page_mask;
	size = (size + page_mask) & ~page_mask;
	buf = (void*)((unsigned long) buf & ~page_mask);
#endif

    mregc->buf  = buf;
    mregc->size = size;
    mregc->ci   = ci;

    return mregc;
err_register:
    free(mregc);
    return NULL;
}


static void psoib_mregion_destroy(psoib_mregion_cache_t *mregc)
{
    assert(!mregc->use_cnt);

    psoib_rma_mreg_deregister(&mregc->mregion);

    free(mregc);
}


static void psoib_mregion_gc(unsigned max_size)
{
    struct list_head *pos, *prev;

    list_for_each_prev_safe(pos, prev, &psoib_mregion_cache)
    {
        if (psoib_mregion_cache_size < max_size) { break; }

        psoib_mregion_cache_t *mregc = list_entry(pos, psoib_mregion_cache_t,
                                                  next);
        if (mregc->use_cnt) { continue; }

        psoib_mregion_deq(mregc);
        psoib_mregion_destroy(mregc);
    }
}


#if HAVE_GLIBC_MORECORE_HOOK
static void *psoib_morecore_hook(ptrdiff_t incr)
{
    /* Do not return memory back to the OS: (do not trim) */
    if (incr < 0) {
        return __default_morecore(0);
    } else {
        psoib_safe_mreg_end += incr;
        return __default_morecore(incr);
    }
}
#endif


static void psoib_mregion_malloc_init(void)
{
    if (is_psshm_enabled()) {
        /* direct shared mem is used. */
        /* In the psshmalloc case, we can assume the whole shared region as
         * being safe: */
        psoib_safe_mreg_start = psshm_info.base;
        psoib_safe_mreg_end   = psshm_info.end;
    } else if (psoib_mregion_cache_max_size) {
        /* Rendezvous and mregion cache is enabled! */

        if (psoib_mregion_malloc_options) {
            /* We have to prevent free() from returning memory back to the OS:
             */
            /* See 'man mallopt(3) / M_MMAP_MAX': Setting this parameter to 0
               disables the use of mmap(2) for servicing large allocation
               requests. */
            mallopt(M_MMAP_MAX, 0);

            /* See 'man mallopt(3) / M_TRIM_THRESHOLD': Setting M_TRIM_THRESHOLD
               to -1 disables trimming completely. */
            mallopt(M_TRIM_THRESHOLD, -1);
        }

#if HAVE_GLIBC_MORECORE_HOOK
        if (__morecore == __default_morecore) {
            psoib_safe_mreg_end = psoib_safe_mreg_start = __morecore(0);

            /* Switch to our own function pscom_openib_morecore() that does not
               trim and update psoib_safe_mreg_end: */
            __morecore = psoib_morecore_hook;
        } else if (__morecore == psoib_morecore_hook) {
            /* Already set to pscom_openib_morecore_hook */
        } else {
            /* Unknown __morecore hook. Disable mregion cache and rendezvous. */
            psoib_mregion_cache_max_size = 0;
            {
                static int warned = 0;
                if (!warned) {
                    warned = 1;
                    psoib_dprint(D_WARNONCE, "psoib: mregion cache disabled: "
                                             "Unknown __morecore hook");
                }
            }
        }
#else
        /* Fixme! For now, the workaround is disabling mregion cache and
         * rendezvous. */
        psoib_mregion_cache_max_size = 0;
        {
            static int warned = 0;
            if (!warned) {
                warned = 1;
                psoib_dprint(D_WARNONCE, "psoib: mregion cache disabled: "
                                         "__morecore hook not available with"
                                         " glibc >= 2.34");
            }
        }
#endif
    }
}


static int psoib_mregion_cache_initialized = 0;

void psoib_mregion_cache_cleanup(void)
{
    if (psoib_mregion_cache_initialized) {
        psoib_mregion_gc(0);
        assert(psoib_mregion_cache_size == 0);
    }
}


void psoib_mregion_cache_init(void)
{
    if (!psoib_mregion_cache_max_size || psoib_mregion_cache_initialized) {
        // Disabled cache or already initialized. Nothing to Initialize.
        return;
    }
    psoib_page_size = getpagesize();
    assert(psoib_page_size != 0);
    assert((psoib_page_size & (psoib_page_size - 1)) == 0); /* power of 2 */
    psoib_mregion_cache_initialized = 1;

    psoib_mregion_malloc_init();
}

int psoib_check_rma_mreg(psoib_rma_mreg_t *mreg, void *buf, size_t size,
                         psoib_con_info_t *ci)
{
    if (!psoib_mregion_cache_max_size ||
        /* buf < psoib_safe_mreg_start || */ buf > psoib_safe_mreg_end) {
        return 0;
    } else {
        return 1;
    }
}

int psoib_acquire_rma_mreg(psoib_rma_mreg_t *mreg, void *buf, size_t size,
                           psoib_con_info_t *ci)
{
    psoib_mregion_cache_t *mregc;
    if (!psoib_mregion_cache_max_size ||
        /* buf < psoib_safe_mreg_start || */ buf > psoib_safe_mreg_end) {
        // Disabled cache
        mreg->mreg_cache = NULL;
        return psoib_rma_mreg_register(mreg, buf, size, ci);
    }

    mregc = psoib_mregion_find(buf, size);
    if (mregc) {
        // cached mregion
        psoib_mregion_use_inc(mregc);
    } else {
        psoib_mregion_gc(psoib_mregion_cache_max_size);

        // create new mregion
        mregc = psoib_mregion_create(buf, size, ci);
        if (!mregc) { goto err_register; }

        psoib_mregion_enq(mregc);
        mregc->use_cnt = 1; /* shortcut for psoib_mregion_use_inc(mreg); */
    }

    mreg->mem_info.ptr = buf;
    mreg->size         = size;
    mreg->mem_info.mr  = mregc->mregion.mem_info.mr;
    mreg->mreg_cache   = mregc;

    return 0;
err_register:
    psoib_dprint(D_WARN, "psoib_get_mregion() failed");
    return -1;
}


int psoib_release_rma_mreg(psoib_rma_mreg_t *mreg)
{
    if (mreg->mreg_cache == NULL) {
        // Disabled cache
        return psoib_rma_mreg_deregister(mreg);
    }

    psoib_mregion_use_dec(mreg->mreg_cache);
    mreg->mreg_cache = NULL;

    return 0;
}
