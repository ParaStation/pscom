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
 * p4io_old.h : Old ioctl's
 */

#ifndef _P4IO_OLD_H_
#define _P4IO_OLD_H_

#define P4_DUMPSOCK_OLD		1
#define P4_DUMPUSRCI_OLD	2
#define P4_DUMPNETCI_OLD	3

#define P4_GETNODEID_OLD	4
#define P4_CLOSE_CON_OLD	5 /* Close one connection */

#define P4S_IO_SEND_OLD		100 /* 0x64 */
#define P4S_IO_RECV_OLD		101 /* 0x65 */
#define P4S_IO_TIMING_OLD	102 /* 0x66 */
#define P4S_IO_SEND_IOV_OLD	103 /* 0x67 */
#define P4S_IO_RECV_IOV_OLD	104 /* 0x68 */


#endif /* _P4IO_OLD_H_ */
