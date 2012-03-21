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

#ifndef _P4PROC4_H_
#define _P4PROC4_H_

#include <linux/sysctl.h>


extern struct ctl_table  ps4_sysctl_ps4_ether[];

void p4_proc_init(void);
void p4_proc_cleanup(void);

void p4_proc_add_ctl_table(ctl_table *ctl_table);
void p4_proc_del_ctl_table(ctl_table *ctl_table);

#define CTL_TABENTRY_MINMAX(_ctl_name, _procname, pvalvar, pminmax)	\
{									\
    ctl_name: PS_CTL_NAME(_ctl_name),					\
    procname: _procname,						\
    data: pvalvar,							\
    maxlen: sizeof(*pvalvar),						\
    mode:0644,								\
    child: 0,								\
    proc_handler: &proc_dointvec_minmax,				\
    extra1: (void*)pminmax,						\
    extra2: (void*)(pminmax + 1),					\
}

#define CTL_TABENTRY_INTINFO(_ctl_name, _procname, pvalvar)		\
{									\
    ctl_name: PS_CTL_NAME(_ctl_name),					\
    procname: _procname,						\
    data: pvalvar,							\
    maxlen: sizeof(*pvalvar),						\
    mode:0444,								\
    child: 0,								\
    proc_handler: &proc_dointvec,					\
}

#ifdef CTL_UNNUMBERED
#define PS_CTL_NAME(num) CTL_UNNUMBERED
#else
#define PS_CTL_NAME(num) num
#endif

extern int proc_ci_counter;
extern int proc_sock_alloc_cnt;
extern int proc_send_user_cnt;
extern int proc_send_net_data_cnt;// network part (p4ether, p4local....) must increment this counter!
extern int proc_send_net_ctrl_cnt;
extern int proc_send_net_ack_cnt;
extern int proc_send_net_nack_cnt;

extern int proc_timer_resend_cnt;
extern int proc_timer_ack_cnt;

extern int proc_recv_user_cnt;
extern int proc_recv_net_data_cnt;
extern int proc_recv_net_ctrl_cnt;
extern int proc_recv_net_ack_cnt;
extern int proc_recv_net_nack_cnt;

extern int proc_polling;
extern int proc_recvqcheck;

#endif
