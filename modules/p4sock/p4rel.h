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

#ifndef _P4REL_H_
#define _P4REL_H_

#include "p4prot.h"
#include "p4io.h"

#ifdef __KERNEL__
#include <linux/list.h>
#else
#include "p4_fifo.h"
#endif


/*
 * External Events
 */

void p4_continue_send(p4_ci_t *ci);
void p4_delayed_continue_send(p4_ci_t *ci);

void p4_enq_for_resend(p4_ci_t *ci, p4_frag_t *sf);

/*
 * @brief Initialize a connection
 * @param ci connection info
 */
void p4_rel_init_ci(p4_ci_t *ci);


/*
 * @brief Network received a fragment
 * @param ci connection info
 * @param f fragment received by the network
 */
void p4rel_net_receive(p4_ci_t *ci, p4_frag_t *rf);

/*
 * @brief Set the receive window
 * @param ci connection info
 * @param win new window end
 */
void p4_setrwindow(p4_ci_t *ci, p4_seqno_t win);


void p4_cleanup_sendq(p4_ci_t *ci);


#ifndef list_for_each_safe
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)
#endif

static inline
int p4_sendqsize(p4_ci_t *ci)
{
    /* This is only true, if p4_cleanup_sendq() is called before */
    return p4_seqcmp(ci->s.SSeqNo, ci->s.SAckNo);
}



#define p4_build_header_dat_1(ci, msghead, csize, cflags) {	\
    (msghead)->cito = (ci)->rem_net_idx;			\
    (msghead)->seqno = (ci)->s.SSeqNo;				\
    (msghead)->ackno = (ci)->r.RSeqNo - 1;			\
    (msghead)->winno = (ci)->r.RWindow;				\
    (msghead)->len  = (csize);					\
    (msghead)->flags = (cflags);				\
}

#define p4_build_header_dat_2(ci, sf, csize, cflags) {	\
    (sf)->SeqNo = (ci)->s.SSeqNo;			\
    (sf)->Flags = (cflags);				\
}

#define p4_build_header_dat(ci, sf, msghead, csize, cflags) {	\
    p4_build_header_dat_1(ci, msghead, csize, cflags);		\
    p4_build_header_dat_2(ci, sf, csize, cflags);		\
}

#define p4_update_header_dat(ci, msghead) {	\
    (msghead)->ackno = (ci)->r.RSeqNo - 1;	\
    (msghead)->winno = (ci)->r.RWindow;		\
}


#endif /* _P4REL_H_ */
