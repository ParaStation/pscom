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
 * p4ether_pub.h: p4ether public Prototypes
 */

#ifndef _P4ETHER_PUB_H_
#define _P4ETHER_PUB_H_

#include <linux/skbuff.h>

typedef int p4ether_netif_rx_t(struct sk_buff *skb);

/* shortcut for netif_rx(). */
int p4ether_netif_rx(struct sk_buff *skb);

int p4ether_netif_rx_try(struct sk_buff *skb);

#endif /* _P4ETHER_PUB_H_ */
