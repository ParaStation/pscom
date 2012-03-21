/*
 * ParaStation
 *
 * Copyright (C) 2001,2002 ParTec AG, Karlsruhe
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * p4ethertest: test some ethernet functions
 */
/* 2001-06-08 Jens Hauke */
/* 2002-03-27 Jens Hauke */

#include <linux/kernel.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <net/ip.h>
#include <asm/uaccess.h>
#include <linux/poll.h>
#include <net/inet_common.h>

#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

static
int recv_func(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt)
{
    printk( KERN_DEBUG __FUNCTION__"():XXXXXXXXXXXXXXX\n");



    kfree_skb(skb);
    return 0;
}

#define ETH_P_P4 0x0820

struct packet_type pt_test =
{
    type:  __constant_htons(ETH_P_P4),
    dev: NULL,
    func: recv_func,
    data: (void*)0,
    next: NULL
};

static
int register_packs( void )
{
    dev_add_pack( &pt_test );
    return 0;
}

static
void unregister_packs( void )
{
    dev_remove_pack( &pt_test );
}




#ifdef MODULE
MODULE_AUTHOR("Jens Hauke <hauke@par-tec.de>");
MODULE_DESCRIPTION("Testmodule");

int init_module(void)
{
	int ret = 0;
	printk( KERN_DEBUG __FUNCTION__"():\n");

	register_packs();

	printk( KERN_DEBUG __FUNCTION__"(): done\n");
	return ret;
}




void cleanup_module(void)
{
    printk( KERN_DEBUG __FUNCTION__"():\n");
    unregister_packs();
}

#else /* !MODULE */

#error Please compile as module

#endif






/*
 * Local Variables:
 *  compile-command: "make p4ethertestr.o"
 * End:
 *
 */
