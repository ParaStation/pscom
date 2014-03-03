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

#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "psport_priv.h"
#include "psport_shm.h"


#if defined(__x86_64__) && !(defined(__KNC__) || defined(__MIC__))
/* We need memory barriers only for x86_64 (?) */
#define shm_mb()    asm volatile("mfence":::"memory")
#elif defined(__ia64__)
#define shm_mb()    asm volatile ("mf" ::: "memory")
#else
/* Dont need it for ia32, alpha (?) */
#define shm_mb()    asm volatile ("" :::"memory")
#endif

static
int shm_initrecv(shm_info_t *shm)
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
    shmctl(shmid, IPC_RMID, NULL);
 err:
    return -1;
}

static
int shm_initsend(shm_info_t *shm, int rem_shmid)
{
    void *buf;
    buf = shmat(rem_shmid, 0, 0);
    if (((long)buf == -1) || !buf) goto err_shmat;

    shm->remote_id = rem_shmid;
    shm->remote_com = buf;
    shm->send_cur = 0;
    return 0;
 err_shmat:
    return -1;
}


static inline
int shm_cansend(shm_info_t *shm)
{
    return !shm->local_com->ctrl[shm->send_cur].used;
}

#if 0
static
void shm_send(shm_info_t *shm, char *buf, int len)
{
    int cur = shm->send_cur;
    shm_buf_t *shmbuf = &shm->remote_com->buf[cur];
//    /* wait for unused sendbuffer */
//    while (shm->local_com->ctrl[cur].used) sched_yield();
    shm->local_com->ctrl[cur].used = 1;

    /* copy to sharedmem */
    memcpy(SHM_DATA(shmbuf, len), buf, len);
    /* Notify the new message */
    shmbuf->header.len = len;

    shm_mb();

    shmbuf->header.msg_type = SHM_MSGTYPE_STD;
    shm->send_cur = (shm->send_cur + 1) % SHM_BUFS;
}
#endif

/* send iov.
   Call only after successful shm_cansend() (no check inside)!
   len must be smaller or equal SHM_BUFLEN!
*/
static
void shm_iovsend(shm_info_t *shm, struct iovec *iov, int len)
{
    int cur = shm->send_cur;
    shm_buf_t *shmbuf = &shm->remote_com->buf[cur];

//    /* wait for unused sendbuffer */
//    while (shm->local_com->ctrl[cur].used) sched_yield();
    shm->local_com->ctrl[cur].used = 1;

    /* copy to sharedmem */
    PSP_memcpy_from_iov(SHM_DATA(shmbuf, len), iov, len);

//    printf("Send SHM %d %s\n", len, dumpstr(SHM_DATA(shmbuf, len), PSP_MIN(40, len)));

    /* Notify the new message */
    shmbuf->header.len = len;

    shm_mb();

    shmbuf->header.msg_type = SHM_MSGTYPE_STD;
    shm->send_cur = (shm->send_cur + 1) % SHM_BUFS;
}

static inline
int shm_canrecv(shm_info_t *shm)
{
    return shm->local_com->buf[shm->recv_cur].header.msg_type
	!= SHM_MSGTYPE_NONE;
}

/* receive.
   Call only after successful shm_canrecv() (no check inside)!
*/
static
void shm_recvstart(shm_info_t *shm, char **buf, unsigned int *len)
{
    int cur = shm->recv_cur;
    shm_buf_t *shmbuf = &shm->local_com->buf[cur];
//    while (shm->local_com->buf[cur].header.msg_type == SHM_MSGTYPE_NONE)
//	sched_yield();
    *len = shmbuf->header.len;
    *buf = SHM_DATA(shmbuf, *len);
}

static
void shm_recvdone(shm_info_t *shm)
{
    int cur = shm->recv_cur;
    shm_buf_t *shmbuf = &shm->local_com->buf[cur];

    shm_mb();

    shmbuf->header.msg_type = SHM_MSGTYPE_NONE;
    /* free buffer */
    shm->remote_com->ctrl[cur].used = 0;
    shm->recv_cur = (shm->recv_cur + 1) % SHM_BUFS;
}

/*
static
void DoSendAbortAllShm(PSP_Port_t *port, con_t *con)
{
    PSP_Request_t *req;

    while (!sendq_empty(con)) {
	req = sendq_head(con);
	req->state |= PSP_REQ_STATE_PROCESSED;
	DelFirstSendRequest(port, req, CON_TYPE_SHM);
    };
}
*/

static
void PSP_do_read_shm(PSP_Port_t *port, PSP_Connection_t *con)
{
    char *buf;
    unsigned int size;

    shm_recvstart(&con->arch.shm, &buf, &size);

    PSP_read_do(port, con, buf, size);

    shm_recvdone(&con->arch.shm);
    return;
}

static
void PSP_do_write_shm(PSP_Port_t *port, PSP_Connection_t *con)
{
    int len;
    PSP_Req_t *req = con->out.req;

    if (req && shm_cansend(&con->arch.shm)) {
	len = PSP_MIN(req->u.req.iov_len, (int)SHM_BUFLEN);

	shm_iovsend(&con->arch.shm, req->u.req.iov, len);
	req->u.req.iov_len -= len;

	PSP_update_sendq(port, con);
    }
    return;
}

int PSP_do_sendrecv_shm(PSP_Port_t *port)
{
    struct list_head *pos, *next;
    int ret = 0;

    if (!list_empty(&port->shm_list)) {
	list_for_each_safe(pos, next, &port->shm_list_send) {
	    PSP_Connection_t *con = list_entry(pos, PSP_Connection_t, arch.shm.next_send);
	    PSP_do_write_shm(port, con);
	}

	list_for_each_safe(pos, next, &port->shm_list) {
	    PSP_Connection_t *con = list_entry(pos, PSP_Connection_t, arch.shm.next);
	    if (shm_canrecv(&con->arch.shm)) {
		/* ToDo:  if (list_empty(&port->recvq_any)) break; */
		PSP_do_read_shm(port, con);
		ret = 1;
	    }
	}
    }
    return ret;
}

static
void PSP_set_write_shm(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
//    printf("set Write %d shm\n", start);
    if (start) {
	if (list_empty(&con->arch.shm.next_send)) {
	    list_add_tail(&con->arch.shm.next_send, &port->shm_list_send);
	}
	PSP_do_write_shm(port, con);
	/* Dont do anything after this line.
	   PSP_do_write_shm() can reenter PSP_set_write_shm()! */
    } else {
	/* it's save to dequeue more then once */
	list_del_init(&con->arch.shm.next_send);
    }
}

static
void PSP_set_read_shm(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
//    printf("set Read %d shm\n", start);
//    if (start)
//	ufd_event_set(&port->ufd, con->arch.tcp.ufd_idx, POLLIN);
//    else
//	ufd_event_set(&port->ufd, con->arch.tcp.ufd_idx, POLLOUT);
}

static
int PSP_is_local(PSP_Connection_t *con)
{
    return con->remote_con_info.node_id == PSP_GetNodeID();
}

static
void PSP_init_con_shm(PSP_Port_t *port, PSP_Connection_t *con,
		      int con_fd, shm_info_t *shm)
{
    con->state = PSP_CON_STATE_OPEN_SHM;
    close(con_fd);

    memcpy(&con->arch.shm, shm, sizeof(*shm));

    INIT_LIST_HEAD(&con->arch.shm.next_send);
    list_add_tail(&con->arch.shm.next, &port->shm_list);

    con->set_write = PSP_set_write_shm;
    con->set_read = PSP_set_read_shm;
}

void PSP_terminate_con_shm(PSP_Port_t *port, PSP_Connection_t *con)
{
    if (con->arch.shm.local_com) {
	shm_info_t *shm = &con->arch.shm;
	if (shm->local_com) shmdt(shm->local_com);
	shm->local_com = NULL;
	if (shm->remote_com) shmdt(shm->remote_com);
	shm->remote_com = NULL;

	list_del(&con->arch.shm.next_send);
	list_del(&con->arch.shm.next);

	con->arch.shm.local_com = NULL;
    }
}

typedef struct shm_info_msg_s {
    int shm_id;
} shm_info_msg_t;

int PSP_connect_shm(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_SHM;
    shm_info_t shm;
    shm_info_msg_t msg;
    int err;

    if ((!PSP_is_local(con)) || (!env_sharedmem))
	return 0; /* Dont use sharedmem */

    /* We want talk shm */
    PSP_writeall(con_fd, &arch, sizeof(arch));
    /* step 1 */
    if ((PSP_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	(arch != PSP_ARCH_SHM))
	goto err_remote;

    /* step 2 : recv shm_id */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	(msg.shm_id == -1))
	goto err_remote;

    shm.local_com = NULL;
    shm.remote_com = NULL;
    err = shm_initrecv(&shm) || shm_initsend(&shm, msg.shm_id);

    /* step 3 : send shm_id or error */
    msg.shm_id = err ? -1 : shm.local_id;
    PSP_writeall(con_fd, &msg, sizeof(msg));
    if (err) goto err_local;

    /* step 4: Shared mem initialized. Recv final ACK. */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	(msg.shm_id == -1)) goto err_ack;

    PSP_init_con_shm(port, con, con_fd, &shm);

    return 1;
    /* --- */
 err_ack:
 err_local:
    if (shm.local_com) shmdt(shm.local_com);
    if (shm.remote_com) shmdt(shm.remote_com);
 err_remote:
    return 0;
}


int PSP_accept_shm(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_SHM;
    shm_info_t shm;
    shm_info_msg_t msg;

    if ((!PSP_is_local(con)) || (!env_sharedmem) || shm_initrecv(&shm)) {
	arch = PSP_ARCH_ERROR;
	PSP_writeall(con_fd, &arch, sizeof(arch));
	return 0; /* Dont use sharedmem */
    }

    /* step 1:  Yes, we talk shm. */
    PSP_writeall(con_fd, &arch, sizeof(arch));

    /* step 2: Send shm_id. */
    msg.shm_id = shm.local_id;
    PSP_writeall(con_fd, &msg, sizeof(msg));


    /* step 3: Recv shm_id. */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	msg.shm_id == -1) goto err_remote;

    if (shm_initsend(&shm, msg.shm_id)) goto err_local;

    /* step 4: Shared mem initialized. Send final ACK. */
    msg.shm_id = 0;
    PSP_writeall(con_fd, &msg, sizeof(msg));

    PSP_init_con_shm(port, con, con_fd, &shm);

    return 1;
    /* --- */
 err_local:
    msg.shm_id = -1; /* send error */
    PSP_writeall(con_fd, &msg, sizeof(msg));
 err_remote:
    shmdt(shm.local_com);
    return 0; /* shm failed */
    /* --- */
}
