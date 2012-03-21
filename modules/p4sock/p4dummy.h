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

#ifndef _P4_DUMMY_H_
#define _P4_DUMMY_H_

#include "p4prot.h"

extern p4_ci_t p4_ci_dummy_usr;

int p4dummy_init(void);
void p4dummy_cleanup(void);


#endif
