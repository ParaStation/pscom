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




static struct net_device *netdev = NULL;


void dest(struct sk_buff *skb)
{
    printk( KERN_DEBUG __FUNCTION__"():\n");
}


void print_skb( struct sk_buff *skb )
{
    printk( KERN_DEBUG __FUNCTION__"():"
	    "head-end: %p %p %p %p\n",
	    skb->head, skb->data, skb->tail, skb->end );
}

//#define ETH_P_P4 4711
#define ETH_P_P4 0x0820
//#define ETH_P_P4 0x0202


void send( void )
{
    if (!netdev){
	/* eth0 dont loopback ??? */
//	netdev = dev_get_by_name( "eth0" );
	/* dummy0 talks only IP ? */
//	netdev = dev_get_by_name( "dummy0" );
	/* lo works */
	netdev = dev_get_by_name( "lo" );
	if (netdev) dev_put( netdev );

	printk( KERN_DEBUG __FUNCTION__"(): netdev = %p\n",netdev );
	if (!netdev) return;
    }

    /* Send one skb */
    {
	struct sk_buff *skb;
	int size = 200;
	int ret;
	unsigned char h_dest[ETH_ALEN]=
	{0xff,0xff,0xff,0xff,0xff,0xff};/* destination eth addr */

	skb = alloc_skb( size + ETH_HLEN, GFP_KERNEL );

	if (!skb) goto error_noskb;

	skb->dev = netdev;
	skb->destructor = dest;

	/* Fill in data */

	skb->protocol =  __constant_htons(ETH_P_P4);

	skb_reserve(skb, (skb->dev->hard_header_len+15)&~15);
	skb->nh.raw = skb->data;

	if (skb->dev->hard_header &&
	    skb->dev->hard_header(skb,skb->dev, ETH_P_P4,
				  skb->dev->dev_addr/*dest_hw*/,
//				  h_dest/*dest_hw*/,
				  NULL/*src_hw*/,
				  skb->len) < 0)
	    goto error_hardheader;



	sprintf( skb_put( skb,91 ), "HALLO"
	    "1234567890123456789012345678901234567890");

	/* */


	print_skb( skb );
	ret = dev_queue_xmit( skb );
	printk( KERN_DEBUG __FUNCTION__"(): dev_queue_xmit() return %d\n", ret);
    }



    return;

 error_noskb:
    printk( KERN_DEBUG __FUNCTION__"(): no skb\n");
    return;
 error_hardheader:
    printk( KERN_DEBUG __FUNCTION__"(): hardheader error\n");
    return;
}

#ifdef MODULE
MODULE_AUTHOR("Jens Hauke <hauke@par-tec.de>");
MODULE_DESCRIPTION("Testmodule");

int init_module(void)
{
	int ret = 0;
	printk( KERN_DEBUG __FUNCTION__"():\n");

	send();

	printk( KERN_DEBUG __FUNCTION__"(): Byee\n");
	ret = -EALREADY;
	return ret;
}




void cleanup_module(void)
{
    printk( KERN_DEBUG __FUNCTION__"():\n");
}

#else /* !MODULE */

#error Please compile as module

#endif






/*
 * Local Variables:
 *  compile-command: "make p4ethertest.o"
 * End:
 *
 */
