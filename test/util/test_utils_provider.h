/*
 * ParaStation
 *
 * Copyright (C) 2025-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_UTIL_PROVIDER_H_
#define _PSCOM_UTIL_PROVIDER_H_

#include "pscom_precon.h"

extern pscom_precon_provider_t pscom_provider_tcp;

#ifdef RRCOMM_PRECON_ENABLED
extern pscom_precon_provider_t pscom_provider_rrc;
#endif /* RRComm enabled */

void setup_dummy_provider(const char *type);
void teardown_dummy_provider(void);

#endif /* _PSCOM_UTIL_PROVIDER_H_*/
