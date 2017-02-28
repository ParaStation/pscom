/*
 * ParaStation
 *
 * Copyright (C) 2011 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author: Thomas Moschny <moschny@par-tec.com>
 */
/**
 * pscom_psm.h: Header for PSM communication
 */

#ifndef _PSCOM_PSM_H_
#define _PSCOM_PSM_H_

#include <sys/uio.h>
#include <errno.h>
#include <stdlib.h>
#include <malloc.h>
#include <inttypes.h>

#include "pscom_types.h"
#include "pscom_priv.h"
#include "pscom_util.h"
#include "pscom_debug.h"
#include "pscom_io.h"
#include "p4sockets.h"


/*
 * Methods
 */

static int pscom_psm_do_read(pscom_con_t *con);
static void pscom_psm_do_write(pscom_con_t *con);
static void pscom_psm_close(pscom_con_t *con);
static void pscom_psm_init(void);
static int pscom_psm_connect(pscom_con_t *con, int con_fd);
static int pscom_psm_accept(pscom_con_t *con, int con_fd);
static void pscom_psm_finalize();


#endif /* _PSCOM_PSM_H_ */
