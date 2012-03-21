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
#include <sys/uio.h>
#include <errno.h>
#include "pscom_priv.h"
#include "pscom_util.h"

#ifdef __x86_64__
/* We need memory barriers only for x86_64 (?) */
#define shm_mb()    asm volatile("mfence":::"memory")
#elif defined(__ia64__)
#define shm_mb()    asm volatile ("mf" ::: "memory")
#else
/* Dont need it for ia32, alpha (?) */
#define shm_mb()    asm volatile ("" :::"memory")
#endif


static
int shm_initrecv(shm_conn_t *shm)
{
	int shmid;
	void *buf;

	shmid = shmget(/*key*/0, sizeof(shm_com_t), IPC_CREAT | 0777);
	if (shmid == -1) goto err;

	buf = shmat(shmid, 0, 0 /*SHM_RDONLY*/);
	if (((long)buf == -1) || !buf) goto err_shmat;

	shmctl(shmid, IPC_RMID, NULL); /* remove shmid after usage */

	memset(buf, 0, sizeof(shm_com_t)); /* init */

	shm->local_id = shmid;
	shm->local_com = (shm_com_t *)buf;
	shm->recv_cur = 0;
	return 0;
err_shmat:
	DPRINT(1, "shmat(%d, 0, 0) : %s", shmid, strerror(errno));
	shmctl(shmid, IPC_RMID, NULL);
	return -1;
err:
	DPRINT(1, "shmget(0, sizeof(shm_com_t), IPC_CREAT | 0777) : %s", strerror(errno));
	return -1;
}


static
int shm_initsend(shm_conn_t *shm, int rem_shmid)
{
	void *buf;
	buf = shmat(rem_shmid, 0, 0);
	if (((long)buf == -1) || !buf) goto err_shmat;

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


static inline
int shm_canrecv(shm_conn_t *shm)
{
	int cur = shm->recv_cur;
	shm_buf_t *shmbuf = &shm->local_com->buf[cur];

	return shmbuf->header.msg_type != SHM_MSGTYPE_NONE;
}


/* receive.
   Call only if shm_canrecv() == true (no check inside)!
*/
static
void shm_recvstart(shm_conn_t *shm, char **buf, unsigned int *len)
{
	int cur = shm->recv_cur;
	shm_buf_t *shmbuf = &shm->local_com->buf[cur];

	*len = shmbuf->header.len;
	*buf = SHM_DATA(shmbuf, *len);
}


static
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

/****************************************************************/

static
int shm_do_read(pscom_poll_reader_t *reader)
{
	pscom_con_t *con = list_entry(reader, pscom_con_t, poll_reader);
	int ret;
	char *buf;
	unsigned int len;

	ret = shm_canrecv(&con->arch.shm);
	if (ret) {
		shm_recvstart(&con->arch.shm, &buf, &len);
		pscom_read_done(con, buf, len);
		shm_recvdone(&con->arch.shm);
	}
	return ret;
}


static
void shm_do_write(pscom_con_t *con)
{
	unsigned int len;
	struct iovec iov[2];
	pscom_req_t *req;

	req = pscom_write_get_iov(con, iov);

	if (req && shm_cansend(&con->arch.shm)) {
		len = iov[0].iov_len + iov[1].iov_len;
		len = pscom_min(len, SHM_BUFLEN);

		shm_iovsend(&con->arch.shm, iov, len);

		pscom_write_done(con, req, len);
	}
}


static
void shm_close(pscom_con_t *con)
{
	if (con->arch.shm.local_com) {
		int i;
		shm_conn_t *shm = &con->arch.shm;

		for (i = 0; i < 5; i++) {
			// ToDo: Unreliable EOF
			if (shm_cansend(shm)) {
				shm_send(shm, NULL, 0);
				break;
			} else {
				usleep(5*1000);
				sched_yield();
			}
		}


		if (shm->local_com) shmdt(shm->local_com);
		shm->local_com = NULL;

		if (shm->remote_com) shmdt(shm->remote_com);
		shm->remote_com = NULL;

		assert(list_empty(&con->poll_next_send));
		assert(list_empty(&con->poll_reader.next));
	}
}


static
void shm_init_con(pscom_con_t *con,
		  int con_fd, shm_conn_t *shm)
{
	con->pub.state = PSCOM_CON_STATE_RW;
	con->pub.type = PSCOM_CON_TYPE_SHM;

	close(con_fd);

	memcpy(&con->arch.shm, shm, sizeof(*shm));

	con->write_start = pscom_poll_write_start;
	con->write_stop = pscom_poll_write_stop;
	con->read_start = pscom_poll_read_start;
	con->read_stop = pscom_poll_read_stop;

	con->poll_reader.do_read = shm_do_read;
	con->do_write = shm_do_write;
	con->close = shm_close;

	con->rendezvous_size = pscom.env.rendezvous_size_shm;
}


static
int shm_is_local(pscom_con_t *con)
{
	return con->pub.remote_con_info.node_id == pscom_get_nodeid();
}


typedef struct shm_info_msg_s {
	int shm_id;
} shm_info_msg_t;

/****************************************************************/
static
void pscom_shm_sock_init(pscom_sock_t *sock)
{
}


static
int pscom_shm_connect(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_SHM;
	shm_conn_t shm;
	shm_info_msg_t msg;
	int err;

	if (!shm_is_local(con))
		return 0; /* Dont use sharedmem */

	/* talk shm? */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 1 */
	if ((pscom_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	    (arch != PSCOM_ARCH_SHM))
		goto err_remote;

	/* step 2 : recv shm_id */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	    (msg.shm_id == -1))
		goto err_remote;

	err = shm_initrecv(&shm) || shm_initsend(&shm, msg.shm_id);

	/* step 3 : send shm_id or error */
	msg.shm_id = err ? -1 : shm.local_id;
	pscom_writeall(con_fd, &msg, sizeof(msg));
	if (err) goto err_local;

	/* step 4: Shared mem initialized. Recv final ACK. */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	    (msg.shm_id == -1)) goto err_ack;

	shm_init_con(con, con_fd, &shm);

	return 1;
	/* --- */
err_ack:
err_local:
	if (shm.local_com) shmdt(shm.local_com);
	if (shm.remote_com) shmdt(shm.remote_com);
err_remote:
	return 0;
}


static
int pscom_shm_accept(pscom_con_t *con, int con_fd)
{
	int arch = PSCOM_ARCH_SHM;
	shm_conn_t shm;
	shm_info_msg_t msg;

	if ((!shm_is_local(con)) || shm_initrecv(&shm)) {
		arch = PSCOM_ARCH_ERROR;
		pscom_writeall(con_fd, &arch, sizeof(arch));
		return 0; /* Dont use sharedmem */
	}

	/* step 1:  Yes, we talk shm. */
	pscom_writeall(con_fd, &arch, sizeof(arch));

	/* step 2: Send shm_id. */
	msg.shm_id = shm.local_id;
	pscom_writeall(con_fd, &msg, sizeof(msg));


	/* step 3: Recv shm_id. */
	if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	    msg.shm_id == -1) goto err_remote;

	if (shm_initsend(&shm, msg.shm_id)) goto err_local;

	/* step 4: Shared mem initialized. Send final ACK. */
	msg.shm_id = 0;
	pscom_writeall(con_fd, &msg, sizeof(msg));

	shm_init_con(con, con_fd, &shm);

	return 1;
	/* --- */
err_local:
	msg.shm_id = -1; /* send error */
	pscom_writeall(con_fd, &msg, sizeof(msg));
err_remote:
	shmdt(shm.local_com);
	return 0; /* shm failed */
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
	.con_connect	= pscom_shm_connect,
	.con_accept	= pscom_shm_accept,
};
