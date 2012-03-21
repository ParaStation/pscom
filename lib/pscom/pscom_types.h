/*
 * ParaStation
 *
 * Copyright (C) 2007 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#ifndef _PSCOM_TYPES_H_
#define _PSCOM_TYPES_H_

#include "list.h"

typedef struct PSCOM_con pscom_con_t;
typedef struct PSCOM_req pscom_req_t;
typedef struct PSCOM_sock pscom_sock_t;
typedef struct PSCOM pscom_t;

typedef struct pscom_poll_reader pscom_poll_reader_t;
struct pscom_poll_reader {
	struct list_head	next; // Used by pscom.poll_reader
	int (*do_read)(pscom_poll_reader_t *poll_reader); // return 1, if you made progress
};

#endif /* _PSCOM_TYPES_H_ */
