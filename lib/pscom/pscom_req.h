/*
 * ParaStation
 *
 * Copyright (C) 2008 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#ifndef _PSCOM_REQ_H_
#define _PSCOM_REQ_H_

#include "pscom_priv.h"

pscom_req_t *pscom_req_create(unsigned int max_xheader_len, unsigned int user_size);

void pscom_req_free(pscom_req_t *req);

unsigned int pscom_req_write(pscom_req_t *req, char *buf, unsigned int len);

/* append data on req. used for partial send requests with pending data. */
void pscom_req_append(pscom_req_t *req, char *buf, unsigned int len);



#endif /* _PSCOM_REQ_H_ */
