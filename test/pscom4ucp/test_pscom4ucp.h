/*
 * ParaStation
 *
 * Copyright (C) 2021 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Simon Pickartz <pickartz@par-tec.com>
 */

#ifndef _TEST_PSCOM4UCP_H_
#define _TEST_PSCOM4UCP_H_

void test_ucp_is_initialized_within_plugin(void **state);
void test_ucp_disable_fast_initialization(void **state);
void test_ucp_disable_fast_initialization_via_environment(void **state);

#endif /* _TEST_PSCOM4UCP_H_ */
