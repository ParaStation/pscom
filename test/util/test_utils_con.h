/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_UTIL_CON_H_
#define _PSCOM_UTIL_CON_H_

typedef struct dummy_con_pair {
        void *send_con;
        void *recv_con;
} dummy_con_pair_t;

int setup_dummy_con(void **state);
int teardown_dummy_con(void **state);

int setup_dummy_con_pair(void **state);
int teardown_dummy_con_pair(void **state);

#endif /* _PSCOM_UTIL_CON_H_*/
