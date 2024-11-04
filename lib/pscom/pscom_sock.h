/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_SOCK_H_
#define _PSCOM_SOCK_H_

#include "pscom.h"
#include "pscom_priv.h"

pscom_err_t _pscom_listen(pscom_sock_t *sock, int portno);
void pscom_sock_stop_listen(pscom_sock_t *sock);
void pscom_sock_close(pscom_sock_t *sock);

#endif /* _PSCOM_SOCK_H_ */
