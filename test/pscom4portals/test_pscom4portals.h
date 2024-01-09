/*
 * ParaStation
 *
 * Copyright (C) 2022-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _TEST_PSCOM4PORTALS_H_
#define _TEST_PSCOM4PORTALS_H_

int setup_dummy_portals_con(void **state);
int teardown_dummy_portals_con(void **state);

void test_portals_first_initialization(void **state);
void test_portals_second_initialization(void **state);
void test_portals_initialization_after_failure(void **state);
void test_portals_initialization_after_socket_failure(void **state);
void test_portals_creates_arch_sock(void **state);
void test_portals_arch_sock_is_found_after_initialization(void **state);
void test_portals_arch_sock_is_correctly_removed(void **state);
void test_portals_creates_arch_sock_with_arch_sock_present(void **state);

void test_portals_read_after_con_read(void **state);
void test_portals_read_after_con_read_stop_out_of_two(void **state);
void test_portals_one_reader_per_socket(void **state);
void test_portals_read_on_event_put(void **state);
void test_portals_read_out_of_order_receive(void **state);
void test_portals_read_three_out_of_order_receive(void **state);

void test_portals_read_after_send_request(void **state);
void test_portals_put_fail(void **state);
void test_portals_defer_close_with_outstanding_put_requests(void **state);
void test_portals_close_with_no_outstanding_put_requests(void **state);
void test_portals_ack_after_con_close(void **state);
void test_portals_handle_message_drop(void **state);

void test_portals_memory_registration(void **state);
void test_portals_failed_memory_registration(void **state);
void test_portals_mem_deregister_releases_resources(void **state);
void test_portals_rma_write(void **state);
void test_portals_rma_write_fragmentation(void **state);
void test_portals_rma_write_fragmentation_remainder(void **state);
void test_portals_rma_write_fail_put(void **state);
void test_portals_rma_write_completion(void **state);
void test_portals_rma_write_fail_ack(void **state);

#endif /* _TEST_PSCOM4PORTALS_H_ */
