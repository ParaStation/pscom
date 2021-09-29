/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * psockt.h: Configuration interface for p4tcp
 */

#ifndef _PSOCKT_H_
#define _PSOCKT_H_

#include <linux/ioctl.h>
#ifndef __KERNEL__
#include <netinet/in.h>
#endif

#define PF_TINET	29
/*
  #define PF_TINET	PF_INET
*/


typedef struct p4tcp_ip_range_s {
    struct in_addr	sin_from; /* IPv4 address */
    struct in_addr	sin_to;
} p4tcp_ip_range_t;

typedef struct p4tcp_ip_range_get_s {
    int	index;
    p4tcp_ip_range_t range;
} p4tcp_ip_range_get_t;



/*
 * Ioctl definitions
 */

#define P4TCP_IOC_MAGIC  'T'



#define P4TCP_ADD_IP_RANGE	_IOW(P4TCP_IOC_MAGIC, 1, p4tcp_ip_range_t)
#define P4TCP_DEL_IP_RANGE	_IOW(P4TCP_IOC_MAGIC, 2, p4tcp_ip_range_t)
#define P4TCP_GET_IP_RANGE	_IOR(P4TCP_IOC_MAGIC, 3, p4tcp_ip_range_get_t)


#endif /* _PSOCKT_H_ */
