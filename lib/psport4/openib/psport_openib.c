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
 * psp_openib.c: OPENIB/Infiniband communication
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "psport_priv.h"
#include "psport_openib.h"

#include "../pscom4openib/psoib.c"


static
int PSP_do_read_openib(PSP_Port_t *port, PSP_Connection_t *con)
{
    void *buf;
    int size;

    size = psoib_recvlook(con->arch.openib.mcon, &buf);

    if (size > 0) {
	PSP_read_do(port, con, buf, size);

	psoib_recvdone(con->arch.openib.mcon);
	return 1;
    } else if (size == -EAGAIN) {
	/* retry later */
	return 0;
    } else if (size == 0) {
	PSP_con_terminate(port, con, PSP_TERMINATE_REASON_REMOTECLOSE);
    } else {
	errno = -size;
	PSP_con_terminate(port, con, PSP_TERMINATE_REASON_READ_FAILED);
    }

    return 0;
}

static
void PSP_do_write_openib(PSP_Port_t *port, PSP_Connection_t *con)
{
    int len, rlen;
    PSP_Req_t *req = con->out.req;

    if (req) {
	len = req->u.req.iov_len;
	rlen = psoib_sendv(con->arch.openib.mcon, req->u.req.iov, len);
	if (rlen >= 0) {
	    req->u.req.iov_len -= rlen;
	    PSP_update_sendq(port, con);
	} else if (rlen == -EAGAIN) {
	    /* retry later */
	} else {
	    errno = -rlen;
	    PSP_con_terminate(port, con, PSP_TERMINATE_REASON_WRITE_FAILED);
	}
    }
}

int PSP_do_sendrecv_openib(PSP_Port_t *port)
{
    struct list_head *pos, *next;
    int ret = 0;

    list_for_each_safe(pos, next, &port->openib_list_send) {
	PSP_Connection_t *con = list_entry(pos, PSP_Connection_t, arch.openib.next_send);
	PSP_do_write_openib(port, con);
    }

    /*psoib_poll(&default_hca, 0);*/

    /* ToDo: Dont loop over all connections! Use a con receive queue! */
    list_for_each_safe(pos, next, &port->openib_list) {
	PSP_Connection_t *con = list_entry(pos, PSP_Connection_t, arch.openib.next);
	ret = PSP_do_read_openib(port, con);
	if (ret) break;
    }
    return ret;
}

static
void PSP_set_write_openib(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
//    printf("set Write %d openib\n", start);
    if (start) {
	if (list_empty(&con->arch.openib.next_send)) {
	    list_add_tail(&con->arch.openib.next_send, &port->openib_list_send);
	}
	PSP_do_write_openib(port, con);
	/* Dont do anything after this line.
	   PSP_do_write_openib() can reenter PSP_set_write_openib()! */
    } else {
	/* it's save to dequeue more then once */
	list_del_init(&con->arch.openib.next_send);
    }
}

static
void PSP_set_read_openib(PSP_Port_t *port, PSP_Connection_t *con, int start)
{
//    printf("set Read %d openib\n", start);
}

static
void PSP_init_con_openib(PSP_Port_t *port, PSP_Connection_t *con, int con_fd,
			psoib_con_info_t *mcon)
{
    con->state = PSP_CON_STATE_OPEN_OPENIB;
    close(con_fd);

    con->arch.openib.mcon = mcon;

    INIT_LIST_HEAD(&con->arch.openib.next_send);
    list_add_tail(&con->arch.openib.next, &port->openib_list);

    con->set_write = PSP_set_write_openib;
    con->set_read = PSP_set_read_openib;
}

void PSP_terminate_con_openib(PSP_Port_t *port, PSP_Connection_t *con)
{
    if (con->arch.openib.mcon) {
	psoib_con_info_t *mcon = con->arch.openib.mcon;

	list_del(&con->arch.openib.next_send);
	list_del(&con->arch.openib.next);

	psoib_con_cleanup(mcon, &default_hca);
	psoib_con_free(mcon);

	con->arch.openib.mcon = NULL;
    }
}


int PSP_connect_openib(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_OPENIB;
    psoib_con_info_t *mcon = psoib_con_create();
    psoib_info_msg_t msg;
    int call_cleanup_con = 0;
    int err;

    if (!env_openib || psoib_init() || !mcon) {
	if (mcon) psoib_con_free(mcon);
	return 0; /* Dont use openib */
    }

    /* We want talk openib */
    PSP_writeall(con_fd, &arch, sizeof(arch));

    /* step 1 */
    if ((PSP_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
	(arch != PSP_ARCH_OPENIB))
	goto err_remote;

    /* step 2 : recv connection id's */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)))
	goto err_remote;

    err = psoib_con_init(mcon, &default_hca, &default_port);
    if (!err) {
	call_cleanup_con = 1;
	err = psoib_con_connect(mcon, &msg);
    }

    /* step 3 : send connection id's (or error) */
    psoib_con_get_info_msg(mcon, &msg);
    if (err) msg.lid = 0xffff;

    PSP_writeall(con_fd, &msg, sizeof(msg));

    if (err) goto err_connect;

    /* step 4: openib initialized. Recv final ACK. */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	(msg.lid == 0xffff)) goto err_ack;

    PSP_init_con_openib(port, con, con_fd, mcon);

    return 1;
    /* --- */
 err_ack:
 err_connect:
    if (call_cleanup_con) psoib_con_cleanup(mcon, &default_hca);
 err_remote:
    if (mcon) psoib_con_free(mcon);
    return 0;
}


int PSP_accept_openib(PSP_Port_t *port, PSP_Connection_t *con, int con_fd)
{
    int arch = PSP_ARCH_OPENIB;
    psoib_con_info_t *mcon = NULL;
    psoib_info_msg_t msg;

    if (!env_openib || psoib_init())
	goto out_noopenib;

    if (!(mcon = psoib_con_create()))
	goto out_noopenib;

    if (psoib_con_init(mcon, &default_hca, &default_port)) {
	goto err_init_con;
    }

    /* step 1:  Yes, we talk openib. */
    PSP_writeall(con_fd, &arch, sizeof(arch));

    /* step 2: Send Connection id's */
    psoib_con_get_info_msg(mcon, &msg);

    PSP_writeall(con_fd, &msg, sizeof(msg));

    /* step 3 : recv connection id's */
    if ((PSP_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg)) ||
	(msg.lid == 0xffff))
	goto err_remote;


    if (psoib_con_connect(mcon, &msg))
	goto err_connect_con;

    /* step 4: OPENIB mem initialized. Send final ACK. */
    msg.lid = 0;
    PSP_writeall(con_fd, &msg, sizeof(msg));

    PSP_init_con_openib(port, con, con_fd, mcon);

    return 1;
    /* --- */
 err_connect_con:
    /* Send NACK */
    msg.lid = 0xffff;
    PSP_writeall(con_fd, &msg, sizeof(msg));
 err_remote:
    psoib_con_cleanup(mcon, &default_hca);
 err_init_con:
 out_noopenib:
    if (mcon) psoib_con_free(mcon);
    arch = PSP_ARCH_ERROR;
    PSP_writeall(con_fd, &arch, sizeof(arch));
    return 0; /* Dont use openib */
    /* --- */

}


void PSP_openib_init(PSP_Port_t *port)
{
    psoib_debug = env_debug;
    port->openib_users = 0;
    INIT_LIST_HEAD(&port->openib_list);
    INIT_LIST_HEAD(&port->openib_list_send);
}
