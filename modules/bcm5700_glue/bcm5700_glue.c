/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * bcm5700_glue.c: Connect the p4sock with the bcm5700 Module
 */

#include <linux/stddef.h>
// #include <linux/config.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include "p4prot_pub.h"
#include "p4ether_pub.h"

static char vcid[] __attribute__(( unused )) =
"$Id$";

MODULE_AUTHOR("Jens Hauke <hauke@par-tec.com>");
MODULE_DESCRIPTION("ParaStation4 - Broadcom BCM5700 Glue");
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

void bcm5700_polling(void);

extern p4ether_netif_rx_t *bcm5700_netif_rx;
static p4ether_netif_rx_t *old_bcm5700_netif_rx;

static
p4_pollfunc_t bcm5700glue_poll = {
	.next = LIST_HEAD_INIT(bcm5700glue_poll.next),
	.func = bcm5700_polling
};

#if 0
static int bcm5700_new_netif_rx(struct sk_buff *skb)
{
    return old_bcm5700_netif_rx(skb);

    if (p4ether_netif_rx_try(skb)) {
	return old_bcm5700_netif_rx(skb);
    } else {
	if (net_ratelimit()) {
	    printk(KERN_INFO "bcm5700 fast path\n");
	}
	return 0;
    }
}
#endif

static int __init
bcm5700glue_init_module(void)
{
	p4_poll_add(&bcm5700glue_poll);
	old_bcm5700_netif_rx = bcm5700_netif_rx;
	bcm5700_netif_rx = /* bcm5700_new_netif_rx */ p4ether_netif_rx;
	return 0;
}

module_init(bcm5700glue_init_module);


static void __exit
bcm5700glue_exit_module(void)
{
	bcm5700_netif_rx = old_bcm5700_netif_rx;
	p4_poll_del(&bcm5700glue_poll);
}

module_exit(bcm5700glue_exit_module);
