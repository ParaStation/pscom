/*
 * ParaStation
 *
 * Copyright (C) 2024-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_UTIL_LISTEN_H_
#define _PSCOM_UTIL_LISTEN_H_

#include "pscom_types.h"

void start_listen(pscom_sock_t *sock);
void stop_listen(pscom_sock_t *sock);
void restart_listen(pscom_sock_t *sock, int portno);
void suspend_listen(pscom_sock_t *sock);
void resume_listen(pscom_sock_t *sock);

#endif /* _PSCOM_UTIL_LISTEN_H_ */
