/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * psport_gm.h: Header for GM communication
 */

#ifndef _PSPORT_GM_H_
#define _PSPORT_GM_H_

#include "pscom_types.h"

typedef struct psgm_conn {
	struct psgm_con_info	*gmcon;
	unsigned		reading : 1;
} psgm_conn_t;


typedef struct psgm_sock {
	int			readers;
	pscom_poll_t		poll_read;
} psgm_sock_t;

#endif /* _PSPORT_GM_H_ */
