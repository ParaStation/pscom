/*
 * ParaStation
 *
 * Copyright (C) 2017 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#define _GNU_SOURCE

#define LIBPSCOM
#ifndef PSCOM_ALLIN
#define PSCOM_ALLIN
#endif

#include "../pscom/perf.c"
#include "../pscom/pscom.c"
#include "../pscom/pscom_async.c"
#include "../pscom/pscom_con.c"
#include "../pscom/pscom_debug.c"
#include "../pscom/pscom_dprint.c"
#include "../pscom/pscom_env.c"
#include "../pscom/pscom_group.c"
#include "../pscom/pscom_group_bcast.c"
#include "../pscom/pscom_io.c"
#include "../pscom/pscom_listener.c"
#include "../pscom/pscom_ondemand.c"
#include "../pscom/pscom_p4s.c"

#ifdef PSCOM_ALLIN_PSM2
#include "../pscom4psm/pscom_psm.c"
// ../pscom4psm/pspsm.c is included by pscom_psm.c
#endif

#ifdef PSCOM_ALLIN_OPENIB
#include "../pscom4openib/pscom_openib.c"
#include "../pscom4openib/psoib.c"
#endif

#include "../pscom/pscom_plugin.c"

#include "../pscom/pscom_precon.c"
#include "../pscom/pscom_queues.c"
#include "../pscom/pscom_req.c"
#include "../pscom/pscom_shm.c"
#include "../pscom/pscom_sock.c"
#include "../pscom/pscom_str_util.c"
#include "../pscom/pscom_suspend.c"
#include "../pscom/pscom_tcp.c"
#include "../pscom/pscom_ufd.c"
#include "../pscom/pslib.c"
#include "../pscom/psshmalloc.c"
