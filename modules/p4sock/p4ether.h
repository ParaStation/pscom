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
 * p4ether: p4 protocol over ethernet
 */

#ifndef _P4ETHER_H_
#define _P4ETHER_H_

#include "p4prot.h"
#include "p4ether_pub.h"

extern p4_net_opts_t p4ether_opts;

int p4ether_init( void );
void p4ether_cleanup( void );

#ifdef ENABLE_P4ETHER_MAGIC
#define P4ETHER_MAGIC_END  { 0x7e, 0x61, 0x3a, 0x42 }
#endif

#endif /* _P4ETHER_H_ */
