/*
 * ParaStation
 *
 * Copyright (C) 2009 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#ifndef _PSLIB_H_
#define _PSLIB_H_

void pscom_pslib_init(void);
void pscom_pslib_read_config(const char *configfiles);
void pscom_pslib_cleanup(void);
void pscom_info_connect(const char *url);
void pscom_info_set(const char *path, const char *value);
void pscom_info_set_uint(const char *path, unsigned value);
void pscom_info_set_int(const char *path, int value);

extern int pscom_pslib_available;
#endif /* _PSLIB_H_ */
