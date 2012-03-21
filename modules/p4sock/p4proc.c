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

#include <linux/kernel.h>   /* We're doing kernel work */
// #include <linux/config.h>

#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/mm.h>    /* for verify_area */
#include <linux/errno.h> /* for -EBUSY */
// #include <asm/segment.h> /* for put_user_byte */
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/pci.h>

#include "p4linux.h"
#include "p4s_debug.h"
#include "p4proc.h"

int proc_ci_counter;
int proc_sock_alloc_cnt;
int proc_send_user_cnt;
int proc_send_net_data_cnt;
int proc_send_net_ctrl_cnt;
int proc_send_net_ack_cnt;
int proc_send_net_nack_cnt;

int proc_timer_resend_cnt;
int proc_timer_ack_cnt;

int proc_recv_user_cnt;
int proc_recv_net_data_cnt;
int proc_recv_net_ctrl_cnt;
int proc_recv_net_ack_cnt;
int proc_recv_net_nack_cnt;

int proc_polling = 2;
int proc_recvqcheck = 1;
int proc_HZ = HZ;
int proc_USER_HZ = USER_HZ;
static struct ctl_table_header *sysctls_root_header = NULL;

static const int ProcBooleanMinMax[]	= {0 , 1};
static const int pollingMinMax[] = {0, 2};
/*
 *  /proc/sys/ps4/local
 */

static
ctl_table  ps4_sysctl_ps4_local[] = {
    {
	ctl_name: 0
    }
};

static
ctl_table ps4_sysctl_ps4_state[] = {
    CTL_TABENTRY_INTINFO( 1, "connections", &proc_ci_counter),
    CTL_TABENTRY_INTINFO( 2, "sockets", &proc_sock_alloc_cnt),

    CTL_TABENTRY_INTINFO( 3, "send_user", &proc_send_user_cnt),
    CTL_TABENTRY_INTINFO( 4, "send_net_data", &proc_send_net_data_cnt),
    CTL_TABENTRY_INTINFO( 5, "send_net_ctrl", &proc_send_net_ctrl_cnt),
    CTL_TABENTRY_INTINFO( 6, "send_net_ack", &proc_send_net_ack_cnt),
    CTL_TABENTRY_INTINFO( 7, "send_net_nack", &proc_send_net_nack_cnt),

    CTL_TABENTRY_INTINFO( 8, "timer_resend", &proc_timer_resend_cnt),
    CTL_TABENTRY_INTINFO( 9, "timer_ack", &proc_timer_ack_cnt),

    CTL_TABENTRY_INTINFO(10, "recv_user", &proc_recv_user_cnt),
    CTL_TABENTRY_INTINFO(11, "recv_net_data", &proc_recv_net_data_cnt),
    CTL_TABENTRY_INTINFO(12, "recv_net_ctrl", &proc_recv_net_ctrl_cnt),
    CTL_TABENTRY_INTINFO(13, "recv_net_ack", &proc_recv_net_ack_cnt),
    CTL_TABENTRY_INTINFO(14, "recv_net_nack", &proc_recv_net_nack_cnt),

    CTL_TABENTRY_INTINFO(15, "HZ", &proc_HZ),
    CTL_TABENTRY_INTINFO(16, "USER_HZ", &proc_USER_HZ),

    CTL_TABENTRY_MINMAX(17, "polling", &proc_polling, pollingMinMax),
    CTL_TABENTRY_MINMAX(18, "recvqcheck", &proc_recvqcheck, ProcBooleanMinMax),

    {
	ctl_name: 0
    }
};


/*
 *  /proc/sys/ps4/
 */
#define SIZE_ps4_sysctl_ps4 10
static
ctl_table  ps4_sysctl_ps4[SIZE_ps4_sysctl_ps4] = {
    {
	ctl_name: PS_CTL_NAME(1),
	procname: "ether",
	data: NULL,
	maxlen: 0,
	mode:0555,
	child: ps4_sysctl_ps4_ether,
    },{
	ctl_name: PS_CTL_NAME(2),
	procname: "local",
	data: NULL,
	maxlen: 0,
	mode:0555,
	child: ps4_sysctl_ps4_local,
    },{
	ctl_name: PS_CTL_NAME(100),
	procname: "state",
	data: NULL,
	maxlen: 0,
	mode:0555,
	child: ps4_sysctl_ps4_state,
    },{
	ctl_name: 0
    }
};

/*
 *  /proc/sys/
 */

static
ctl_table  ps4_sysctl_root[] = {
    {
	ctl_name: PS_CTL_NAME(34163),
	procname: "ps4",
	data: NULL,
	maxlen: 0,
	mode:0555,
	child: ps4_sysctl_ps4,
    },{
	ctl_name: 0
    }
};


void p4_proc_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
    sysctls_root_header = register_sysctl_table(ps4_sysctl_root);
#else
    sysctls_root_header = register_sysctl_table(ps4_sysctl_root,0);
#endif
}


void p4_proc_cleanup(void)
{
    if (sysctls_root_header) {
	unregister_sysctl_table(sysctls_root_header);
    }
}


void p4_proc_add_ctl_table(ctl_table *ctl_table)
{
    int i;
    int idx;

    if (!ctl_table ||
	!ctl_table->procname ||
	!ctl_table->ctl_name)
	return;

    p4_proc_cleanup();

    idx = -1;
    for (i = 0; i < SIZE_ps4_sysctl_ps4 - 1; i++) {
	if (!ps4_sysctl_ps4[i].ctl_name) {
	    idx = i;
	    break;
	}
	if (ps4_sysctl_ps4[i].procname &&
	    ctl_table->procname &&
	    !strcmp(ps4_sysctl_ps4[i].procname, ctl_table->procname))
	    break;
	if (ps4_sysctl_ps4[i].ctl_name == ctl_table->ctl_name) {
	    printk(KERN_WARNING
		   "p4_proc_add_ctl_table(): ctl_name %d used by %s and %s\n",
		   ctl_table->ctl_name, ps4_sysctl_ps4[i].procname,
		   ctl_table->procname);
	    break;
	}
    }

    if (idx >= 0) {
	memcpy(&ps4_sysctl_ps4[idx], ctl_table, sizeof(*ctl_table));
    }

    p4_proc_init();
}

void p4_proc_del_ctl_table(ctl_table *ctl_table)
{
    int i;
    int idx;

    if (!ctl_table ||
	!ctl_table->procname ||
	!ctl_table->ctl_name)
	return;

    p4_proc_cleanup();

    idx = -1;
    for (i = 0; i < SIZE_ps4_sysctl_ps4 - 1; i++) {
	if (!strcmp(ps4_sysctl_ps4[i].procname, ctl_table->procname)) {
	    idx = i;
	    break;
	}
    }

    if (idx >= 0) {
	memcpy(&ps4_sysctl_ps4[idx], &ps4_sysctl_ps4[idx + 1],
	       sizeof(ps4_sysctl_ps4[idx]) * (SIZE_ps4_sysctl_ps4 - idx - 1));
    }

    p4_proc_init();
}


P4_EXPORT_SYMBOL(p4_proc_add_ctl_table);
P4_EXPORT_SYMBOL(p4_proc_del_ctl_table);
