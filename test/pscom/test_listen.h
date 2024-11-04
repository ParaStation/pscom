/*
 * ParaStation
 *
 * Copyright (C) 2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _TEST_LISTEN_H_
#define _TEST_LISTEN_H_

void test_start_stop_listen_anyport(void **state);
void test_start_stop_listen_ondemand(void **state);
void test_start_stop_listen_ondemand_recv_req(void **state);
void test_suspend_listen(void **state);
void test_suspend_resume_listen(void **state);
void test_suspend_resume_listen_ondemand(void **state);
void test_suspend_resume_listen_ondemand_recv_req(void **state);

#endif /* _TEST_LISTEN_H_ */
