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
 * p4local: local communication
 */

#include <linux/sched.h>
#include <linux/slab.h>

#include "p4s_debug.h"
#include "p4prot.h"
#include "p4local.h"

#include "p4rel.h"

typedef struct p4local_lf_s{
    p4_frag_t	rf;
    char	data[ 0 ];
}p4local_lf_t;

#define P4LOCAL_MTU (64000 - sizeof( p4local_lf_t ))
//#define P4LOCAL_MTU 1
#define P4LOCAL_RECVWINSIZE	10


static
void p4local_lf_free(p4local_lf_t *lf){
    FRAG_DEC;
    DP_LOCTRACE("%s(%d)\n", __func__, RFRAGCNT);
    kfree(lf);
}

static
void p4local_destruct_frag(struct p4_frag_s *rf)
{
    p4local_lf_t *lf = list_entry(rf, p4local_lf_t, rf);
    p4local_lf_free(lf);
}


static
p4local_lf_t *p4local_lf_new(int size)
{
    p4local_lf_t *ret;
    FRAG_INC;
    DP_LOCTRACE("%s(%d)\n", __func__, RFRAGCNT);

    ret = (p4local_lf_t *)kmalloc(sizeof(p4local_lf_t) + size, GFP_ATOMIC);
    if (!ret) goto err_nomem;

    ret->rf.fsize = size;
    ret->rf.foffset = 0;
    atomic_set(&ret->rf.refcnt, 1);
    ret->rf.destructor = p4local_destruct_frag;
    ret->rf.Flags = 0;
    return ret;
    /* --- */
 err_nomem:
    if (p4s_ratelimit())
	printk(KERN_WARNING "P4: %s(): kmalloc failed\n", __func__);
    return NULL;
}



static
int p4local_recvmsg(struct p4_ci_s *ci, struct iovec *msg_iov,
		    p4_frag_t *rf, size_t fsize)
{
    int ret;
    p4local_lf_t *lf = list_entry(rf, p4local_lf_t, rf);

    DP_LOCTRACE("%s():%d\n", __func__, __LINE__);

    ret = memcpy_toiovec(msg_iov, lf->data + lf->rf.foffset, fsize);

    return ret ? -EINVAL : 0;
}


/*
  Create one fragment and send the fragment if possible.
  I : ci->
  IO: msg_iov
  IO: msgsize
  O : sf

*/
static
int p4local_sendmsg(p4_ci_t *ci, struct iovec *msg_iov, size_t *msgsize, p4_frag_t **sf)
{
    p4local_lf_t *lf;
    int ret;
//    size_t msglen = msgsize;
    int cflags;
    size_t csize;

    DP_LOCTRACE("%s()\n", __func__);

    if (*msgsize <= P4LOCAL_MTU) {
	/* last fragment */
	csize = *msgsize;
	cflags = P4_FFLAGS_LASTFRAG;
    } else {
	csize = P4LOCAL_MTU;
	cflags = 0;
    }

    lf = p4local_lf_new(csize);
    if (!lf) goto err_nobuf; /* busy or out of mem*/

    /* Copy Data */
    ret = memcpy_fromiovec(lf->data, msg_iov, csize);
    if (ret) goto err_memcpy;

    /* Build reduced PS4 header */
    lf->rf.Flags = cflags;

    /* xmit */
    p4_net_receive_noseq(ci->rem_net_idx, &lf->rf);
    p4_frag_put(&lf->rf);

    proc_send_net_data_cnt++;

    *sf = NULL; /* local is reliable. No need for retransmission. */
    *msgsize -= csize;

    return 0;
    /* ----- */
 err_nobuf:
//    return -ENOBUFS;
    return -EAGAIN;
    /* ----- */
 err_memcpy:
    p4_frag_put(&lf->rf);
    return -EINVAL;
}

static
int p4local_net_send_frag_error(p4_ci_t *ci, p4_frag_t *sf)
{
    DPRINT(KERN_ERR "P4LOC: ERROR: send_frag called in p4local\n");
    return 0;
}

static
int p4local_net_send_ctrl(p4_remserv_t *rs, p4msg_ctrl_t *msg, size_t msgsize)
{
    DP_LOCTRACE("%s()\n", __func__);
    p4_net_recv_ctrl(&p4local_opts, rs, msg);
    return 0;
}

static
int p4local_isequal(p4_ci_t *ci, p4_remaddr_t *ra, p4msg_syn_t *syn)
{
    return 1;
}

static
int  p4local_init_ci(p4_ci_t *ci, p4_remaddr_t *ra, int ralen)
{
    /* Nothing to do for local */
    return 0;
}

static
void  p4local_cleanup_ci(p4_ci_t *ci)
{
    /* Nothing to do for local */
}

static
void p4local_getremaddr(p4_remaddr_t *ra, p4_remserv_t *rs)
{
    ra->type = P4REMADDR_LOCAL;
}



p4_net_opts_t p4local_opts = {
    _sinit(MaxResend)	3,	/* maximal retrys for resend */
    _sinit(ResendTimeout)	1 + HZ * 3,	/* timeout until resend in USER_HZ */
//    _sinit(WaitWinTimeout)	1 + HZ * 4,
    _sinit(AckDelay)		2 * HZ / 50,

    _sinit(MaxRecvQSize)	0, /* Unused on reliable connetions */
    _sinit(MaxAcksPending)	0, /* Unused on reliable connections */

    _sinit(sendmsg)		p4local_sendmsg,
    _sinit(recvmsg)		p4local_recvmsg,
    _sinit(net_send_frag)	p4local_net_send_frag_error,
    _sinit(net_send_ctrl)	p4local_net_send_ctrl,
    _sinit(isequal)		p4local_isequal,
    _sinit(set_rem_saddr)	NULL,
    _sinit(init_ci)		p4local_init_ci,
    _sinit(cleanup_ci)		p4local_cleanup_ci,
    _sinit(getremaddr)		p4local_getremaddr
};


P4_EXPORT_SYMBOL(p4local_opts);
