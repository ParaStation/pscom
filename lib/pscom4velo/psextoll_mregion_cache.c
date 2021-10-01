/*
 * ParaStation
 *
 * Copyright (C) 2014-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "list.h"

struct psex_mregion_cache {
	struct list_head next;
	RMA2_NLA	rma2_nla;
	RMA2_Region	rma2_region;
	RMA2_Port	rma2_port;
	void		*buf;
	size_t		size;
	unsigned	use_cnt;
};


unsigned psex_mregion_cache_max_size = 6;
static unsigned psex_mregion_cache_size = 0;
static LIST_HEAD(psex_mregion_cache);


static inline
int psex_mregion_is_inside(psex_mregion_cache_t *mregc,
			   void *buf, size_t size)
{
	return (buf >= mregc->buf) &&
		((char*)buf + size <= (char*)mregc->buf + mregc->size);
}


/* Find a region buf[0:size] in the cache */
static
psex_mregion_cache_t *psex_mregion_find(void *buf, size_t size)
{
	struct list_head *pos;
	list_for_each(pos, &psex_mregion_cache) {
		psex_mregion_cache_t *mregc = list_entry(pos, psex_mregion_cache_t, next);
		if (psex_mregion_is_inside(mregc, buf, size)) {
			return mregc;
		}
	}

	return NULL;
}


static
void psex_mregion_enq(psex_mregion_cache_t *mregc)
{
	list_add(&mregc->next, &psex_mregion_cache);
	psex_mregion_cache_size++;
}


static
void psex_mregion_deq(psex_mregion_cache_t *mregc)
{
	list_del(&mregc->next);
	psex_mregion_cache_size--;
}


/* increment the use count of mregc and move it to the head (LRU) */
static
void psex_mregion_use_inc(psex_mregion_cache_t *mregc)
{
	mregc->use_cnt++;
	if (&mregc->next == psex_mregion_cache.next) {
		/* already first entry */
		return;
	}
	list_del(&mregc->next);
	list_add(&mregc->next, &psex_mregion_cache);
}


static
void psex_mregion_use_dec(psex_mregion_cache_t *mregc)
{
	mregc->use_cnt--;
}


static
psex_mregion_cache_t *psex_mregion_create(void *buf, size_t size, RMA2_Port rma2_port)
{
	psex_mregion_cache_t *mregc =
		(psex_mregion_cache_t *)malloc(sizeof(psex_mregion_cache_t));
	int err;

	mregc->use_cnt = 0;

	err = psex_mregion_register(&mregc->rma2_region, rma2_port, buf, size);
	if (err) goto err_register;

	/* determine actual start address and size of the registered memory region */
	mregc->buf = mregc->rma2_region.start;
	mregc->size = mregc->rma2_region.size;
	assert(mregc->buf <= buf);
	assert((mregc->buf + mregc->size) >= (buf + size));

	mregc->rma2_port = rma2_port;

	return mregc;
err_register:
	free(mregc);
	return NULL;
}


static
void psex_mregion_destroy(psex_mregion_cache_t *mregc)
{
	assert(!mregc->use_cnt);
	psex_mregion_deregister(&mregc->rma2_region, mregc->rma2_port);
	free(mregc);
}


static
void psex_mregion_gc(unsigned max_size)
{
	struct list_head *pos, *prev;

	list_for_each_prev_safe(pos, prev, &psex_mregion_cache) {
		if (psex_mregion_cache_size < max_size) break;

		psex_mregion_cache_t *mregc = list_entry(pos, psex_mregion_cache_t, next);
		if (mregc->use_cnt) continue;

		psex_mregion_deq(mregc);
		psex_mregion_destroy(mregc);
	}
}


/* get lmr and rmr Handles from mem region buf:size. from cache.
 * call psex_put_mregion() after usage!
 * return error or 0. */
int psex_get_mregion(psex_mregion_t *mreg, void *buf, size_t size, psex_con_info_t *ci)
{
	psex_mregion_cache_t *mregc;

	mregc = psex_mregion_find(buf, size);
	if (mregc) {
		// cached mregion
		psex_mregion_use_inc(mregc);
	} else {
		psex_mregion_gc(psex_mregion_cache_max_size);

		// create new mregion
		mregc = psex_mregion_create(buf, size, ci->rma2_port);
		if (!mregc) goto err_register;

		psex_mregion_enq(mregc);
		mregc->use_cnt = 1; /* shortcut for psex_mregion_use_inc(mreg); */
	}

	mreg->mreg_cache = mregc;
	mreg->rma2_nla = psex_mregion_nla(&mregc->rma2_region, buf);

	return 0;
err_register:
	psex_dprint(3, "psex_get_mregion() failed");
	return -1;
}


void psex_put_mregion(psex_mregion_t *mreg, psex_con_info_t *ci)
{
	psex_mregion_use_dec(mreg->mreg_cache);
	mreg->mreg_cache = NULL;
	mreg->rma2_nla = 0;
}


static
void psex_mregion_cache_cleanup(void)
{
	psex_mregion_gc(0);
	assert(psex_mregion_cache_size == 0);
}
