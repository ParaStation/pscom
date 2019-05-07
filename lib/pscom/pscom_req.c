/*
 * ParaStation
 *
 * Copyright (C) 2008 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include "pscom_cuda.h"
#include "pscom_req.h"
#include "pscom_util.h"

#include <stdlib.h>


// ToDo: disable:
#define ENABLE_REQUEST_MONITORING 1

#ifdef ENABLE_REQUEST_MONITORING
static inline
void announce_new_req(pscom_req_t *req)
{
	if (!pscom.env.debug_req) return;
	pthread_mutex_lock(&pscom.lock_requests);
	list_add_tail(&req->all_req_next, &pscom.requests);
	pthread_mutex_unlock(&pscom.lock_requests);
}


static inline
void announce_free_req(pscom_req_t *req)
{
	if (!pscom.env.debug_req) return;
	pthread_mutex_lock(&pscom.lock_requests);
	list_del(&req->all_req_next);
	pthread_mutex_unlock(&pscom.lock_requests);
}
#else /* ENABLE_REQUEST_MONITORING */
static inline void announce_new_req(pscom_req_t *req) { }
static inline void announce_free_req(pscom_req_t *req) { }
#endif

static inline
size_t round_up8(size_t val)
{
	return (val + 7) & ~7;
}

#if USE_PSCOM_MALLOC
// Malloc cache for PSCOM_MALLOC_SIZE mallocs
#define PSCOM_MALLOC_SIZE (sizeof(pscom_req_t) + 50)

typedef struct PSCOM_malloc {
	union {
		struct list_head	next;
		unsigned		magic;
	}	u;
#if PSCOM_MALLOC_SAFE_SIZE
	char			safe_header[PSCOM_MALLOC_SAFE_SIZE]; // check for buf underruns
#endif
	char			data[0];
} pscom_malloc_t;

#define PSCOM_MALLOC_MAGIC_POOL		0x578ef12
#define PSCOM_MALLOC_MAGIC_MALLOC	0x14578ef

static
struct list_head mallocs = LIST_HEAD_INIT(mallocs);


void *pscom_malloc(unsigned int size)
{
	void *ptr;
	pscom_malloc_t *m;

	if (size <= PSCOM_MALLOC_SIZE) {
		// ToDo: listlock!
		if (!list_empty(&mallocs)) {
			m = list_entry(mallocs.next, pscom_malloc_t, u.next);
			list_del(&m->u.next);
			// printf("%s:%u use pool\n", __func__, __LINE__);
		} else {
			m = malloc(sizeof(pscom_malloc_t) + PSCOM_MALLOC_SIZE);
		}
		m->u.magic = PSCOM_MALLOC_MAGIC_POOL;
	} else {
		m = malloc(sizeof(pscom_malloc_t) + size);
		m->u.magic = PSCOM_MALLOC_MAGIC_MALLOC;
	}
#if PSCOM_MALLOC_SAFE_SIZE
	memset(m->safe_header, 32, sizeof(m->safe_header));
#endif

	ptr = m->data;
	return ptr;
}


inline
void pscom_mverify(void *ptr)
{
	pscom_malloc_t *m = list_entry(ptr, pscom_malloc_t, data);
	unsigned i;

#if PSCOM_MALLOC_SAFE_SIZE
	assert(m->u.magic == PSCOM_MALLOC_MAGIC_POOL ||
	       m->u.magic == PSCOM_MALLOC_MAGIC_MALLOC);
	for (i = 0; i < sizeof(m->safe_header); i++ ) {
		if (m->safe_header[i] != 32) {
			printf("Failing assert in pscom_free(%p) at %u of %zu\n",
			       ptr, i, sizeof(m->safe_header));
			assert(m->safe_header[i] == 32);
		}
	}
#endif
}


void pscom_free(void *ptr)
{
	pscom_malloc_t *m = list_entry(ptr, pscom_malloc_t, data);
	pscom_mverify(ptr);
	if (m->u.magic == PSCOM_MALLOC_MAGIC_POOL) {
		// ToDo: listlock!
		//printf("%s:%u add pool\n", __func__, __LINE__);
		list_add_tail(&m->u.next, &mallocs);
	} else {
		assert(m->u.magic == PSCOM_MALLOC_MAGIC_MALLOC);
		free(m);
	}
}

#endif

pscom_req_t *pscom_req_create(size_t max_xheader_len, size_t user_size)
{
	pscom_req_t *req;
	size_t max_xhl = pscom_max(round_up8(max_xheader_len), sizeof(req->pub.xheader));
	size_t extra_xh_size = max_xhl - sizeof(req->pub.xheader);

	req = pscom_malloc(sizeof(*req) + extra_xh_size + user_size);
	if (!req) return NULL;

	req->magic		= MAGIC_REQUEST;
	req->write_hook		= NULL;

	req->req_no = ++pscom.stat.reqs; // ToDo: disable debug?

	req->pub.state		= PSCOM_REQ_STATE_DONE;

	req->pub.xheader_len	= max_xheader_len;
	req->pub.data_len	= 0;
	req->pub.data		= NULL;

#ifdef PSCOM_CUDA_AWARENESS
	req->stage_buf	= NULL;
#endif

	req->pub.connection	= NULL;
	req->pub.socket		= NULL;

	req->pub.ops.recv_accept= NULL;
	req->pub.ops.io_done	= NULL;

	req->pub.user_size	= user_size;
	req->pub.user		= (void*)(((char *)&req->pub.xheader) + max_xhl);

	req->pub.max_xheader_len= max_xhl; // at least sizeof(req->pub.xheader)

	announce_new_req(req);
	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req)));

	return req;
}


void pscom_req_free(pscom_req_t *req)
{
	D_TR(printf("%s:%u:%s(%s)\n", __FILE__, __LINE__, __func__, pscom_debug_req_str(req)));

	assert(req->magic == MAGIC_REQUEST);
	assert(req->pub.state & PSCOM_REQ_STATE_DONE);

	req->magic = 0;
	announce_free_req(req);

	pscom_free(req);
}


size_t pscom_req_write(pscom_req_t *req, char *buf, size_t len)
{
	// printf("req_write() %s\n", pscom_dumpstr(buf, pscom_min(len, 32)));
	if (len <= req->cur_data.iov_len) {
		if (req->cur_data.iov_base != buf) {
			_pscom_memcpy_to_user(req->cur_data.iov_base, buf, len);
		}
		req->cur_data.iov_base += len;
		req->cur_data.iov_len -= len;
	} else {
		size_t clen = req->cur_data.iov_len;
		size_t left;
		if (req->cur_data.iov_base != buf) {
			_pscom_memcpy_to_user(req->cur_data.iov_base, buf, clen);
		}
		req->cur_data.iov_base += clen;
		req->cur_data.iov_len = 0;


		left = len - clen;

		if (req->skip >= left) {
			req->skip -= left;
		} else {
			len = clen + req->skip;
			req->skip = 0;
		}
	}

	if (req->write_hook) req->write_hook(req, buf, len);

	return len;
}


/* append data on req. used for partial send requests. */
void pscom_req_append(pscom_req_t *req, char *buf, size_t len)
{
	size_t send = (char*)req->cur_data.iov_base - (char *)req->pub.data;
	char *tail = (char*)req->cur_data.iov_base + req->cur_data.iov_len;

	size_t msg_len = send + req->cur_data.iov_len + len;
	assert(msg_len <= req->pub.data_len);
	assert(len <= req->skip);

	if (buf && buf != tail) {
		_pscom_memcpy_default(tail, buf, len);
	}
	req->cur_data.iov_len += len;
	req->skip -= len;
}
