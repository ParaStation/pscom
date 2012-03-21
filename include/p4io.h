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
 * p4io.h: p4sock ioctl's
 */

#ifndef _P4IO_H_
#define _P4IO_H_

#ifndef __KERNEL__
#include <stdint.h> /** for int16_t ... */
#endif

#include "p4sockets.h"

/* Maximal number of connections */
#define P4_N_CON_NET  8192 /* must be power of 2! */

#define P4_N_CON_USR  2048 /* must be power of 2! and smaller PSP_DEST_LOOPBACK=0x7fff */
typedef uint16_t p4_seqno_t;



/*
 * ioctl's
 */




/*
 * structs for dump
 */

typedef struct {
	p4_addr_t	addr;		/* Address of this socket */
	uint16_t	last_idx;	/* last used ci_list_usr index */
        int		RefCnt;
} p4_dumpsock_t;

typedef union {
    struct {
	int	sockno;
    } in;
    p4_dumpsock_t	sock;
}p4_io_dumpsock_t;


typedef struct {
    /* Reliable part */
    p4_seqno_t	SSeqNo;
    p4_seqno_t	SWindow;
    p4_seqno_t	RSeqNo;
    p4_seqno_t	RWindow;

    /* Protocolpart */
    int16_t	list_usr_idx;
    int16_t	list_net_idx;
    uint16_t	sendcnt;	/* Retransmissioncnt of SYN */
    int16_t	rem_net_idx;

    int		SFragQN;	/* Fragmentcount in SendQ */
    int		RFragQN;	/* Fragmentcount in ReceiveQ */
    int		RefCnt;

    struct sockaddr_p4 sap4;
} p4_dumpci_t;

typedef union {
    struct {
	int	sockno;
	int	ci_usr_idx;
    } in;
    p4_dumpci_t	ci;
}p4_io_dumpusrci_t;
#define P4_SOCKNO_SELF -1

typedef union {
    struct {
	int	ci_net_idx;
    } in;
    p4_dumpci_t	ci;
}p4_io_dumpnetci_t;


#define P4_DUMPSOCK	_IOWR(P4S_IOC_MAGIC, 1, p4_io_dumpsock_t)
#define P4_DUMPUSRCI	_IOWR(P4S_IOC_MAGIC, 2, p4_io_dumpusrci_t)
#define P4_DUMPNETCI	_IOWR(P4S_IOC_MAGIC, 3, p4_io_dumpnetci_t)

#define P4_GETNODEID	_IO(P4S_IOC_MAGIC, 4)
#define P4_CLOSE_CON	_IO(P4S_IOC_MAGIC, 5) /* Close one connection */
//#define P4_SETNODEID	5
#define P4_NODE_ID_UNDEF 0x7fffffff



#endif
