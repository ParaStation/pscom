/*
 * ParaStation
 *
 * Copyright (C) 2006-2009 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#ifndef _PSPORT_UTIL_H_
#define _PSPORT_UTIL_H_

#include "psport4.h"

/* return PSP_GetNodeID() and PSP_GetPortNo(porth) as a string */
const char *PSP_local_name(PSP_PortH_t porth);

/* call PSP_Connect() with a string */
int PSP_Connect_name(PSP_PortH_t porth, const char *name);

#endif /* _PSPORT_UTIL_H_ */
