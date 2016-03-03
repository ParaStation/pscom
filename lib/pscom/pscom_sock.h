/*
 * ParaStation
 *
 * Copyright (C) 2007, 2016 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#ifndef _PSCOM_SOCK_H_
#define _PSCOM_SOCK_H_

#include "pscom_priv.h"

pscom_err_t _pscom_listen(pscom_sock_t *sock, int portno);

#endif /* _PSCOM_SOCK_H_ */
