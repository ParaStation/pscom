/*
 * ParaStation
 *
 * Copyright (C) 2009-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSLIB_H_
#define _PSLIB_H_
#include <stddef.h>

void pscom_pslib_init(void);
void pscom_pslib_read_config(const char *configfiles);
void pscom_pslib_cleanup(void);
void pscom_info_connect(const char *url);
void pscom_info_set(const char *path, const char *value);
void pscom_info_set_uint(const char *path, unsigned value);
void pscom_info_set_size_t(const char *path, size_t value);
void pscom_info_set_int(const char *path, int value);

extern int pscom_pslib_available;
#endif /* _PSLIB_H_ */
