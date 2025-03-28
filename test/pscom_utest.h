/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_UTEST_H_
#define _PSCOM_UTEST_H_

typedef struct pscom_utest {
    struct {
        unsigned int memcpy;
        unsigned int free;
        unsigned int read;
        unsigned int sched_yield;
        struct {
            unsigned int enabled;
            void *addr;
        } malloc;
        struct {
            unsigned int extended_ptl_put;
        } portals;
    } mock_functions;
} pscom_utest_t;

extern pscom_utest_t pscom_utest;

#endif /* _PSCOM_UTEST_H_ */
