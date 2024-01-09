/*
 * ParaStation
 *
 * Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _TEST_IO_H_
#define _TEST_IO_H_
void test_post_recv_partial_genreq(void **state);
void test_post_recv_genreq_state(void **state);
void test_post_recv_on_con(void **state);
void test_post_any_recv_on_sock(void **state);
void test_post_any_recv_on_global_queue(void **state);
void test_post_recv_on_con_after_any_recv_on_sock(void **state);
void test_post_recv_on_con_after_any_recv_on_global_queue(void **state);
void test_post_any_recvs_on_sock_and_global_after_recv_on_con(void **state);
void test_post_recv_on_con_and_cancel(void **state);
void test_post_any_recv_on_sock_and_cancel(void **state);
void test_post_any_recv_on_global_queue_and_cancel(void **state);
void test_post_recv_on_con_and_terminate_recvq(void **state);
void test_post_any_recv_on_sock_and_terminate_recvq(void **state);
void test_post_any_recv_on_global_queue_and_terminate_recvq(void **state);
void test_post_any_recv_on_sock_and_terminate_sock_queue(void **state);
void test_post_any_recv_on_global_queue_and_terminate_global_queue(void **state);
void test_req_prepare_send_pending_valid_send_request(void **state);
void test_req_prepare_send_pending_truncate_data_len(void **state);
void test_pscom_get_rma_read_receiver_failing_rma_write(void **state);
void test_rndv_recv_read_error(void **state);
void test_write_pending_first_io_con_closed(void **state);
void test_write_pending_first_io_con_open(void **state);
void test_write_pending_done_last_io(void **state);
void test_write_pending_done_second_last_io(void **state);
void test_read_pending_done_unrelated_genreq(void **state);
#endif /* _TEST_IO_H_ */
