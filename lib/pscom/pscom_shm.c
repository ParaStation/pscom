/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * psport_shm.c: Shared Mem communication
 */

#include "pscom_shm.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <errno.h>
#include "pscom_priv.h"
#include "pscom_util.h"
#include "pscom_precon.h"
#include "pscom_con.h"
#include "psshmalloc.h"

#if defined(__x86_64__) && !(defined(__KNC__) || defined(__MIC__))
/* We need memory barriers only for x86_64 (?) */
#define shm_mb()    asm volatile("mfence":::"memory")
#elif defined(__aarch64__)
#define shm_mb()    asm volatile("dsb sy" ::: "memory")
#elif defined(__ia64__)
#define shm_mb()    asm volatile ("mf" ::: "memory")
#else
/* Dont need it for ia32, alpha (?) */
#define shm_mb()    asm volatile ("" :::"memory")
#endif

#define SHM_DIRECT	400

#if !(defined(__KNC__) || defined(__MIC__))
#define SHM_INDIRECT	(SHM_DIRECT)
#else
/* On KNC fall back to buffered send, when direct send fails. */
#define SHM_INDIRECT	~0
#endif


static
unsigned shm_direct = SHM_DIRECT;
static
unsigned shm_indirect = SHM_INDIRECT;

static
struct {
	struct pscom_poll_reader poll_reader; // calling shm_poll_pending_io(). Used if !list_empty(shm_conn_head)
	struct list_head	shm_conn_head; // shm_conn_t.pending_io_next_conn.
} shm_pending_io;

typedef struct shm_info_msg_s {
	int shm_id;
	int direct_shm_id;	/* shm direct shared mem id */
	void *direct_base;	/* base pointer of the shared mem segment */
} shm_info_msg_t;

struct shm_direct_header {
	void	*base;
	size_t	len;
};

static
void shm_init_direct(shm_conn_t *shm, int shmid, void *remote_base)
{
	if (shmid == -1) {
		shm->direct_offset = 0;
		shm->direct_base = NULL;
		return;
	}
	void *buf = shmat(shmid, 0, SHM_RDONLY);
	assert(buf != (void *) -1 && buf);

	shm->direct_base = buf;
	shm->direct_offset = (char *)buf - (char *)remote_base;
}

static
int shm_initrecv(shm_conn_t *shm)
{
	int shmid;
	void *buf;

	shmid = shmget(/*key*/0, sizeof(shm_com_t), IPC_CREAT | 0777);
	if (shmid == -1) goto err;

	buf = shmat(shmid, 0, 0 /*SHM_RDONLY*/);
	shmctl(shmid, IPC_RMID, NULL); /* remove shmid after usage */

	if (((long)buf == -1) || !buf) goto err_shmat;

	memset(buf, 0, sizeof(shm_com_t)); /* init */

	shm->local_id = shmid;
	shm->local_com = (shm_com_t *)buf;
	shm->recv_cur = 0;
	return 0;
err_shmat:
	DPRINT(1, "shmat(%d, 0, 0) : %s", shmid, strerror(errno));
	return -1;
err:
	DPRINT(1, "shmget(0, sizeof(shm_com_t), IPC_CREAT | 0777) : %s", strerror(errno));
	return -1;
}


static
int shm_initsend(shm_conn_t *shm, shm_info_msg_t *msg)
{
	void *buf;
	int rem_shmid = msg->shm_id;
	buf = shmat(rem_shmid, 0, 0);
	if (((long)buf == -1) || !buf) goto err_shmat;

	shm_init_direct(shm, msg->direct_shm_id, msg->direct_base);

	shm->remote_id = rem_shmid;
	shm->remote_com = buf;
	shm->send_cur = 0;
	return 0;
err_shmat:
	DPRINT(1, "shmat(%d, 0, 0) : %s", rem_shmid, strerror(errno));
	return -1;
}


static inline
int shm_cansend(shm_conn_t *shm)
{
	int cur = shm->send_cur;
	shm_buf_t *shmbuf = &shm->remote_com->buf[cur];
	return shmbuf->header.msg_type == SHM_MSGTYPE_NONE;
}


/* send buf.
   Call only if shm_cansend() == true (no check inside)!
   len must be smaller or equal SHM_BUFLEN!
*/
static
void shm_send(shm_conn_t *shm, char *buf, int len)
{
	int cur = shm->send_cur;
	shm_buf_t *shmbuf = &shm->remote_com->buf[cur];

	/* copy to sharedmem */
	memcpy(SHM_DATA(shmbuf, len), buf, len);
	shmbuf->header.len = len;

	shm_mb();

	/* Notification about the new message */
	shmbuf->header.msg_type = SHM_MSGTYPE_STD;
	shm->send_cur = (shm->send_cur + 1) % SHM_BUFS;
}


/* send iov.
   Call only if shm_cansend() == true (no check inside)!
   len must be smaller or equal SHM_BUFLEN!
*/
static
void shm_iovsend(shm_conn_t *shm, struct iovec *iov, int len)
{
	int cur = shm->send_cur;
	shm_buf_t *shmbuf = &shm->remote_com->buf[cur];

	/* copy to sharedmem */
	pscom_memcpy_from_iov(SHM_DATA(shmbuf, len), iov, len);
	shmbuf->header.len = len;

	shm_mb();

	/* Notification about the new message */
	shmbuf->header.msg_type = SHM_MSGTYPE_STD;
	shm->send_cur = (shm->send_cur + 1) % SHM_BUFS;
}


/* send iov.
   Call only if shm_cansend() == true (no check inside)!
   iov[0].iov_len must be smaller or equal SHM_BUFLEN - sizeof(struct shm_direct_header)!
   is_psshm_ptr(iov[1].iov_base) must be true.
*/
static
shm_msg_t *shm_iovsend_direct(shm_conn_t *shm, struct iovec *iov)
{
	int cur = shm->send_cur;
	shm_buf_t *shmbuf = &shm->remote_com->buf[cur];
	size_t len0 = iov[0].iov_len;
	char *data = SHM_DATA(shmbuf, len0);

	/* reference to iov[1] before header */
	struct shm_direct_header *dh = (struct shm_direct_header *)(data - sizeof(*dh));
	dh->base = iov[1].iov_base;
	dh->len = iov[1].iov_len;

	/* copy header to sharedmem */
	memcpy(data, iov[0].iov_base, len0);
	shmbuf->header.len = len0;

	shm_mb();

	/* Notification about the new message */
	shmbuf->header.msg_type = SHM_MSGTYPE_DIRECT;
	shm->send_cur = (shm->send_cur + 1) % SHM_BUFS;

	return &shmbuf->header;
}


static inline
uint32_t shm_canrecv(shm_conn_t *shm)
{
	int cur = shm->recv_cur;
	shm_buf_t *shmbuf = &shm->local_com->buf[cur];
	return shmbuf->header.msg_type;
}


/* receive.
   Call only if shm_canrecv() == SHM_MSGTYPE_STD (no check inside)!
*/
static inline
void shm_recvstart(shm_conn_t *shm, char **buf, unsigned int *len)
{
	int cur = shm->recv_cur;
	shm_buf_t *shmbuf = &shm->local_com->buf[cur];

	*len = shmbuf->header.len;
	*buf = SHM_DATA(shmbuf, *len);
}


/* receive.
   Call only if shm_canrecv() == SHM_MSGTYPE_DIRECT (no check inside)!
*/
static inline
void shm_recvstart_direct(shm_conn_t *shm, struct iovec iov[2])
{
	int cur = shm->recv_cur;
	shm_buf_t *shmbuf = &shm->local_com->buf[cur];

	unsigned len = shmbuf->header.len;
	char *data = SHM_DATA(shmbuf, len);

	iov[0].iov_base = data;
	iov[0].iov_len = len;

	struct shm_direct_header *dh = (struct shm_direct_header *)(data - sizeof(*dh));

	iov[1].iov_base = dh->base + shm->direct_offset;
	iov[1].iov_len = dh->len;
}


static inline
void shm_recvdone(shm_conn_t *shm)
{
	int cur = shm->recv_cur;
	shm_buf_t *shmbuf = &shm->local_com->buf[cur];

	shm_mb();

	/* Notification: message is read */
	shmbuf->header.msg_type = SHM_MSGTYPE_NONE;

	/* free buffer */
	shm->recv_cur = (shm->recv_cur + 1) % SHM_BUFS;
}


static inline
void shm_recvdone_direct(shm_conn_t *shm)
{
	int cur = shm->recv_cur;
	shm_buf_t *shmbuf = &shm->local_com->buf[cur];

	shm_mb();

	/* Notification: message is read */
	shmbuf->header.msg_type = SHM_MSGTYPE_DIRECT_DONE;

	/* free buffer */
	shm->recv_cur = (shm->recv_cur + 1) % SHM_BUFS;
}

/****************************************************************/

static
int shm_do_read(pscom_poll_reader_t *reader)
{
	pscom_con_t *con = list_entry(reader, pscom_con_t, poll_reader);
	uint32_t ret;
	char *buf;
	unsigned int len;

	ret = shm_canrecv(&con->arch.shm);

	if (ret == SHM_MSGTYPE_STD) {
		shm_recvstart(&con->arch.shm, &buf, &len);
		pscom_read_done(con, buf, len);
		shm_recvdone(&con->arch.shm);
		return 1;
	} else if (ret == SHM_MSGTYPE_DIRECT) {
		struct iovec iov[2];
		shm_recvstart_direct(&con->arch.shm, iov);
		pscom_read_done(con, iov[0].iov_base, iov[0].iov_len);
		pscom_read_done(con, iov[1].iov_base, iov[1].iov_len);
		shm_recvdone_direct(&con->arch.shm);
		return 1;
	}

	// assert(ret == SHM_MSGTYPE_NONE || ret == SHM_MSGTYPE_DIRECT_DONE);
	return 0;
}


/*
 * Pending io requests
 */


static
void shm_pending_io_conn_enq(shm_conn_t *shm)
{
	if (list_empty(&shm_pending_io.shm_conn_head)) {
		// Start polling for pending_io
		list_add_tail(&shm_pending_io.poll_reader.next, &pscom.poll_reader);
	}
	list_add_tail(&shm->pending_io_next_conn, &shm_pending_io.shm_conn_head);
}


static
void shm_pending_io_conn_deq(shm_conn_t *shm)
{
	list_del(&shm->pending_io_next_conn);
	if (list_empty(&shm_pending_io.shm_conn_head)) {
		// No shm_conn_t with pending io requests left. Stop polling for pending_io.
		list_del(&shm_pending_io.poll_reader.next);
	}
}


struct shm_pending {
	struct shm_pending *next;
	pscom_con_t *con;
	shm_msg_t *msg;
	pscom_req_t *req;
	void *data;
};


static
void shm_check_pending_io(shm_conn_t *shm)
{
	struct shm_pending *sp;
	while (((sp = shm->shm_pending)) && (
		       (sp->msg->msg_type == SHM_MSGTYPE_DIRECT_DONE) ||
		       (sp->req && (sp->req->pub.state & PSCOM_REQ_STATE_ERROR))
	       )) {
		// finish request
		if (sp->req) pscom_write_pending_done(sp->con, sp->req); // direct send done
		if (sp->data) free(sp->data); // indirect send done

		// Free buffer for next send
		sp->msg->msg_type = SHM_MSGTYPE_NONE;

		// loop next sp
		shm->shm_pending = sp->next;
		free(sp);

		if (!shm->shm_pending) {
			// shm_conn_t is without pending io requests.
			shm_pending_io_conn_deq(shm);
			break;
		}
	}
}


static
int shm_poll_pending_io(pscom_poll_reader_t *poll_reader)
{
	struct list_head *pos, *next;
	// For each shm_conn_t shm
	list_for_each_safe(pos, next, &shm_pending_io.shm_conn_head) {
		shm_conn_t *shm = list_entry(pos, shm_conn_t, pending_io_next_conn);

		shm_check_pending_io(shm);
	}
	return 0;
}


/*
 * Enqueue a pending shared mem operation msg on connection con.
 *
 * After the io finishes call:
 *  - pscom_write_pending_done(con, req), if req != NULL
 *  - free(data), if data != NULL
 * see shm_check_pending_io().
 */
static
void shm_pending_io_enq(pscom_con_t *con, shm_msg_t *msg, pscom_req_t *req, void *data)
{
	shm_conn_t *shm = &con->arch.shm;
	struct shm_pending *sp = malloc(sizeof(*sp));
	struct shm_pending *old_sp;
	sp->next = NULL;
	sp->con = con;
	sp->msg = msg;
	sp->req = req;
	sp->data = data;

	if (!shm->shm_pending) {
		shm_pending_io_conn_enq(shm);
		shm->shm_pending = sp;
	} else {
		// Append at the end
		for (old_sp = shm->shm_pending; old_sp->next; old_sp = old_sp->next);
		old_sp->next = sp;
	}
}


static
void shm_do_write(pscom_con_t *con)
{
	unsigned int len;
	struct iovec iov[2];
	pscom_req_t *req;

	req = pscom_write_get_iov(con, iov);

	if (req && shm_cansend(&con->arch.shm)) {
		if (iov[1].iov_len < shm_direct ||
		    iov[0].iov_len > (SHM_BUFLEN - sizeof(struct shm_direct_header))) {
		do_buffered_send:

			/* Buffered send : Send through the send & receive buffers. */

			len = iov[0].iov_len + iov[1].iov_len;
			len = pscom_min(len, SHM_BUFLEN);

			shm_iovsend(&con->arch.shm, iov, len);

			pscom_write_done(con, req, len);
		} else if (is_psshm_ptr(iov[1].iov_base)) {
			/* Direct send : Send a reference to the data iov[1]. */

			shm_msg_t *msg = shm_iovsend_direct(&con->arch.shm, iov);

			pscom_write_pending(con, req, iov[0].iov_len + iov[1].iov_len);

			/* The shm_iovsend_direct is active as long as msg->msg_type == SHM_MSGTYPE_DIRECT.
			   We have to call pscom_write_pending_done(con, req) when we got the ack msg_type == SHM_MSGTYPE_DIRECT_DONE. */

			shm_pending_io_enq(con, msg, req, NULL);

			pscom.stat.shm_direct++;
		} else {
			/* Indirect send : Copy data iov[1] to a shared region and send a reference to it. */
			/* Size is good for direct send, but the data is not inside the shared mem region */

			void *data;
			shm_msg_t *msg;

			if (!is_psshm_enabled() ||		// Direct shm is disabled.
			    iov[1].iov_len <= shm_indirect) {	// or (disabled or len to small) for indirect shm
				goto do_buffered_send;
			}

			data = malloc(iov[1].iov_len); // try to get a buffer inside the shared mem region

			if (unlikely(!is_psshm_ptr(data))) {
				// Still a non shared buffer
				free(data);
				pscom.stat.shm_direct_failed++;
				goto do_buffered_send; // Giving up. Fallback to buffered send.
			}

			memcpy(data, iov[1].iov_base, iov[1].iov_len);
			iov[1].iov_base = data;

			msg = shm_iovsend_direct(&con->arch.shm, iov);

			pscom_write_done(con, req, iov[0].iov_len + iov[1].iov_len);

			shm_pending_io_enq(con, msg, NULL, data);


			/* Count messages which should but cant be send with direct_send.
			   Means iov_len >= shm_direct and false == is_psshm_ptr().
			*/
			pscom.stat.shm_direct_nonshmptr++;
		}


	}
}


static
void shm_init_shm_conn(shm_conn_t *shm)
{
	memset(shm, 0, sizeof(*shm));
	shm->local_com = NULL;
	shm->remote_com = NULL;
	shm->direct_base = NULL;
	shm->local_id = -1;
	shm->remote_id = -1;
}


static
void shm_cleanup_shm_conn(shm_conn_t *shm)
{
	if (shm->local_com) shmdt(shm->local_com);
	shm->local_com = NULL;

	if (shm->remote_com) shmdt(shm->remote_com);
	shm->remote_com = NULL;

	if (shm->direct_base) shmdt(shm->direct_base);
	shm->direct_base = NULL;
}


static
void shm_close(pscom_con_t *con)
{
	if (con->arch.shm.local_com) {
		int i;
		shm_conn_t *shm = &con->arch.shm;

		// ToDo: This must not be a blocking while loop!
		while (shm->shm_pending) {
			shm_check_pending_io(shm);
		}

		shm_cleanup_shm_conn(shm);

		assert(list_empty(&con->poll_next_send));
		assert(list_empty(&con->poll_reader.next));
	}
}


static
void shm_init_con(pscom_con_t *con)
{
	con->pub.type = PSCOM_CON_TYPE_SHM;

	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_poll_read_start;
	con->read_stop = pscom_poll_read_stop;

	con->poll_reader.do_read = shm_do_read;
	con->do_write = shm_do_write;
	con->close = shm_close;

	con->rendezvous_size = pscom.env.rendezvous_size_shm;

	pscom_con_setup_ok(con);
}


static
int shm_is_local(pscom_con_t *con)
{
	return con->pub.remote_con_info.node_id == pscom_get_nodeid();
}

/****************************************************************/
static
void pscom_shm_sock_init(pscom_sock_t *sock)
{
	if (psshm_info.size) {
		DPRINT(2, "PSP_MALLOC = 1 : size = %lu\n", psshm_info.size);
		pscom_env_get_uint(&shm_direct, ENV_SHM_DIRECT);
		pscom_env_get_uint(&shm_indirect, ENV_SHM_INDIRECT);
		if ((shm_indirect > 0) && (shm_indirect != ~0U)) {
			// compare with len > shm_indirect instead of len >= shm_indirect.
			// With this shm_indirect=~0 can disable indirect sends.
			shm_indirect--;
		}
	} else {
		DPRINT(2, "PSP_MALLOC disabled : %s\n", psshm_info.msg);
		shm_direct = (unsigned)~0;
		shm_indirect = (unsigned)~0;
	}

	shm_pending_io.poll_reader.do_read = shm_poll_pending_io;
	INIT_LIST_HEAD(&shm_pending_io.shm_conn_head);
}


static
void pscom_shm_info_msg(shm_conn_t *shm, shm_info_msg_t *msg)
{
	msg->shm_id = shm->local_id;
	msg->direct_shm_id = psshm_info.shmid;
	msg->direct_base = psshm_info.base;
}

static
int pscom_shm_con_init(pscom_con_t *con)
{
	return shm_is_local(con) ? 0 : -1;
}

#define PSCOM_INFO_SHM_SHMID PSCOM_INFO_ARCH_STEP1

static
void pscom_shm_handshake(pscom_con_t *con, int type, void *data, unsigned size)
{
	precon_t *pre = con->precon;
	shm_conn_t *shm = &con->arch.shm;

	switch (type) {
	case PSCOM_INFO_ARCH_REQ: {
		shm_init_shm_conn(shm);
		if (shm_initrecv(shm)) goto error_initsend;

		shm_info_msg_t msg;
		pscom_shm_info_msg(shm, &msg);
		pscom_precon_send(pre, PSCOM_INFO_SHM_SHMID, &msg, sizeof(msg));
		break;
	}
	case PSCOM_INFO_SHM_SHMID: {
		shm_info_msg_t *msg = data;
		assert(size == sizeof(*msg));
		if (shm_initsend(shm, msg)) goto error_initrecv;
		pscom_precon_send(pre, PSCOM_INFO_ARCH_OK, NULL, 0);
		break;

	}
	case PSCOM_INFO_ARCH_NEXT:
		/* Cleanup shm */
		shm_cleanup_shm_conn(shm);
		break;

	case PSCOM_INFO_ARCH_OK:
		pscom_con_guard_start(con);
		break;
	case PSCOM_INFO_EOF:
		shm_init_con(con);
		break;
	}

	return;
	/* --- */
error_initrecv:
error_initsend:
	shm_cleanup_shm_conn(shm);
	pscom_precon_send_PSCOM_INFO_ARCH_NEXT(pre);
}


pscom_plugin_t pscom_plugin_shm = {
	.name		= "shm",
	.version	= PSCOM_PLUGIN_VERSION,
	.arch_id	= PSCOM_ARCH_SHM,
	.priority	= PSCOM_SHM_PRIO,

	.init		= NULL,
	.destroy	= NULL,
	.sock_init	= pscom_shm_sock_init,
	.sock_destroy	= NULL,
	.con_init	= pscom_shm_con_init,
	.con_handshake	= pscom_shm_handshake,
};
