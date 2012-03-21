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
 * e1000_glue.c: Connect the p4sock with the e1000 Module
 */

#include <linux/stddef.h>
#include <linux/config.h>
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

void e1000_poll(void);

extern p4ether_netif_rx_t *e1000_netif_rx;
static p4ether_netif_rx_t *old_e1000_netif_rx;

static
p4_pollfunc_t e1000glue_poll = {
	.next = LIST_HEAD_INIT(e1000glue_poll.next),
	.func = e1000_poll
};


static int __init
e1000glue_init_module(void)
{
	p4_poll_add(&e1000glue_poll);
	old_e1000_netif_rx = e1000_netif_rx;
	e1000_netif_rx = p4ether_netif_rx;
	return 0;
}

module_init(e1000glue_init_module);


static void __exit
e1000glue_exit_module(void)
{
	e1000_netif_rx = old_e1000_netif_rx;
	p4_poll_del(&e1000glue_poll);
}

module_exit(e1000glue_exit_module);
