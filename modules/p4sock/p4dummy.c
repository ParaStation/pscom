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

#include <linux/slab.h>
#include <asm/uaccess.h>
//#include <linux/mm.h>
#include <linux/poll.h>

#include "p4dummy.h"

p4_ci_t p4_ci_dummy_usr;

static
int p4dummy_sendmsg(p4_ci_t *ci, struct iovec *msg_iov, size_t *msgsize, p4_frag_t **sf)
{
    return -ECHRNG;
}

static
int p4dummy_recvmsg(struct p4_ci_s *ci, struct iovec *msg_iov, p4_frag_t *rf, size_t fsize)
{
    return -ENOTCONN;
}

static
int p4dummy_net_send_frag(p4_ci_t *ci, p4_frag_t *sf)
{
    DPRINT("%s: ERROR\n", __func__);
    return -ENOTCONN;
}

static
int p4dummy_net_send_ctrl(p4_remserv_t *rs, p4msg_ctrl_t *msg, size_t msgsize)
{
    DPRINT("%s: ERROR\n", __func__);
    return -ESERVERFAULT;
}

static
int p4dummy_isequal(p4_ci_t *ci, p4_remaddr_t *ra, p4msg_syn_t *syn)
{
    DPRINT("%s: ERROR\n", __func__);
    return 0;
}

static
int p4dummy_init_ci(p4_ci_t *ci, p4_remaddr_t *ra, int ralen)
{
    DPRINT("%s: ERROR\n", __func__);
    return -ENOTCONN;
}

static
void p4dummy_cleanup_ci(p4_ci_t *ci)
{
    DPRINT("%s: ERROR\n", __func__);
}

static
void p4dummy_getremaddr(p4_remaddr_t *ra, p4_remserv_t *rs)
{
    DPRINT("%s: ERROR\n", __func__);
}

static
p4_net_opts_t p4dummy_opts_usr = {
    _sinit(MaxResend)	0,
    _sinit(ResendTimeout)	HZ,
//    _sinit(WaitWinTimeout)	HZ,
    _sinit(AckDelay)		2 * HZ / 50,

    _sinit(sendmsg)		p4dummy_sendmsg,
    _sinit(recvmsg)		p4dummy_recvmsg,
    _sinit(net_send_frag)	p4dummy_net_send_frag,
    _sinit(net_send_ctrl)	p4dummy_net_send_ctrl,
    _sinit(isequal)		p4dummy_isequal,
    _sinit(set_rem_saddr)	NULL,
    _sinit(init_ci)		p4dummy_init_ci,
    _sinit(cleanup_ci)		p4dummy_cleanup_ci,
    _sinit(getremaddr)		p4dummy_getremaddr
};

int p4dummy_init(void)
{
    memset(&p4_ci_dummy_usr, 0, sizeof(p4_ci_dummy_usr));

    p4_ci_init(&p4_ci_dummy_usr);
    p4_ci_dummy_usr.net_opts = &p4dummy_opts_usr;

    return 0;
}

void p4dummy_cleanup(void)
{
}
