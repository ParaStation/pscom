/*
 * ParaStation
 *
 * Copyright (C) 2020 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Simon Pickartz <pickartz@par-tec.com>
 */

#ifndef _PSCOM_UTEST_H_
#define _PSCOM_UTEST_H_

typedef struct pscom_utest {
    struct {
        unsigned int memcpy;
    } mock_functions;
} pscom_utest_t;

extern pscom_utest_t pscom_utest;

#endif /* _PSCOM_UTEST_H_ */
