/*
 * ParaStation
 *
 * Copyright (C) 2002,2003 ParTec AG, Karlsruhe
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
 * tg3_glue.c: Connect the p4sock with the tg3 Module
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
MODULE_DESCRIPTION("ParaStation4 - Intel(R) PRO/1000 Glue");
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

void tg3_polling(void);

extern p4ether_netif_rx_t *tg3_netif_rx;
static p4ether_netif_rx_t *old_tg3_netif_rx;

static
p4_pollfunc_t tg3glue_poll = {
	.next = LIST_HEAD_INIT(tg3glue_poll.next),
	.func = tg3_polling
};

static int tg3_new_netif_rx(struct sk_buff *skb)
{
    return old_tg3_netif_rx(skb);

    if (p4ether_netif_rx_try(skb)) {
	return old_tg3_netif_rx(skb);
    } else {
	if (net_ratelimit()) {
	    printk(KERN_INFO "tg3 fast path\n");
	}
	return 0;
    }
}

static int __init
tg3glue_init_module(void)
{
	p4_poll_add(&tg3glue_poll);
	old_tg3_netif_rx = tg3_netif_rx;
	tg3_netif_rx = tg3_new_netif_rx/* p4ether_netif_rx */;
	return 0;
}

module_init(tg3glue_init_module);


static void __exit
tg3glue_exit_module(void)
{
	tg3_netif_rx = old_tg3_netif_rx;
	p4_poll_del(&tg3glue_poll);
}

module_exit(tg3glue_exit_module);
