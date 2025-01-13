/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PERF_H_
#define _PERF_H_

#ifdef PERF_ENABLED
void perf_add(char *id);
void perf_print(void);
#else
#define perf_add(id)                                                           \
    do {                                                                       \
    } while (0)
#define perf_print()                                                           \
    do {                                                                       \
    } while (0)
#endif

#endif /* _PERF_H_ */
