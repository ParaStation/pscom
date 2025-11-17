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

#ifndef _TEST_RRCOMM_H_
#define _TEST_RRCOMM_H_

void test_rrc_parse_ep_str(void **state);
void test_rrc_recv_msg(void **state);
void test_rrc_resend_signal(void **state);
void test_rrc_send_msg(void **state);
#endif /* _TEST_RRCOMM_H_ */