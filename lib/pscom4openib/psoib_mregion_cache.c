/*
 * ParaStation
 *
 * Copyright (C) 2014 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include "list.h"

typedef
struct psoib_mregion_cache {
	struct list_head next;
	void		*buf;
	size_t		size;
	psoib_con_info_t *ci;
	psoib_rma_mreg_t mregion;
	unsigned	use_cnt;
} psoib_mregion_cache_t;


unsigned psoib_mregion_cache_max_size = IB_RNDV_MREG_CACHE_SIZE;
static unsigned psoib_mregion_cache_size = 0;
static LIST_HEAD(psoib_mregion_cache);

static unsigned psoib_page_size;


static inline
int psoib_mregion_is_inside(psoib_mregion_cache_t *mregc,
			   void *buf, size_t size)
{
	return (buf >= mregc->buf) &&
		((char*)buf + size <= (char*)mregc->buf + mregc->size);
}


/* Find a region buf[0:size] in the cache */
static
psoib_mregion_cache_t *psoib_mregion_find(void *buf, size_t size)
{
	struct list_head *pos;
	list_for_each(pos, &psoib_mregion_cache) {
		psoib_mregion_cache_t *mregc = list_entry(pos, psoib_mregion_cache_t, next);
		if (psoib_mregion_is_inside(mregc, buf, size)) {
			return mregc;
		}
	}

	return NULL;
}


static
void psoib_mregion_enq(psoib_mregion_cache_t *mregc)
{
	list_add(&mregc->next, &psoib_mregion_cache);
	psoib_mregion_cache_size++;
}


static
void psoib_mregion_deq(psoib_mregion_cache_t *mregc)
{
	list_del(&mregc->next);
	psoib_mregion_cache_size--;
}


/* increment the use count of mregc and move it to the head (LRU) */
static
void psoib_mregion_use_inc(psoib_mregion_cache_t *mregc)
{
	mregc->use_cnt++;
	if (&mregc->next == psoib_mregion_cache.next) {
		/* already first entry */
		return;
	}
	list_del(&mregc->next);
	list_add(&mregc->next, &psoib_mregion_cache);
}


static
void psoib_mregion_use_dec(psoib_mregion_cache_t *mregc)
{
	mregc->use_cnt--;
}


static
psoib_mregion_cache_t *psoib_mregion_get_oldest(void)
{
	return list_entry(psoib_mregion_cache.prev, psoib_mregion_cache_t, next);
}


static
psoib_mregion_cache_t *psoib_mregion_create(void *buf, size_t size, psoib_con_info_t *ci)
{
	psoib_mregion_cache_t *mregc =
		(psoib_mregion_cache_t *)malloc(sizeof(psoib_mregion_cache_t));
	int err;

	mregc->use_cnt = 0;

	err = psoib_rma_mreg_register(&mregc->mregion, buf, size, ci);
	if (err) goto err_register;

#if 0   /* DON'T ALIGN FOR ibv_reg_mr()! */

	/* dec buf and inc size to page_size borders. */
	unsigned long page_mask = (psoib_page_size - 1);
	size += ((unsigned long) buf) & page_mask;
	size = (size + page_mask) & ~page_mask;
	buf = (void*)((unsigned long) buf & ~page_mask);
#endif
	
	mregc->buf = buf;
	mregc->size = size;
	mregc->ci = ci;

	return mregc;
err_register:
	free(mregc);
	return NULL;
}


static
void psoib_mregion_destroy(psoib_mregion_cache_t *mregc)
{
	assert(!mregc->use_cnt);

	psoib_rma_mreg_deregister(&mregc->mregion);

	free(mregc);
}


static
void psoib_mregion_gc(unsigned max_size)
{
	psoib_mregion_cache_t *mregc;
	while (psoib_mregion_cache_size >= max_size) {
		mregc = psoib_mregion_get_oldest();
		if (mregc->use_cnt) break;

		psoib_mregion_deq(mregc);
		psoib_mregion_destroy(mregc);
	}
}

void psoib_mregion_cache_cleanup(void)
{
	psoib_mregion_gc(0);
	assert(psoib_mregion_cache_size == 0);
}

void psoib_mregion_cache_init(void)
{
	psoib_page_size = getpagesize();
	assert(psoib_page_size != 0);
	assert((psoib_page_size & (psoib_page_size - 1)) == 0); /* power of 2 */
}
