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

#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "pscom_utest.h"
#include "pscom/test_cuda.h"
#include "pscom/test_io.h"
#include "util/test_utils_con.h"

pscom_utest_t pscom_utest = {
	.mock_functions = {
		.memcpy = 0,
	},
};

#define TEST_GROUP_SIZE(test_group) (sizeof(test_group)/sizeof(struct CMUnitTest))

////////////////////////////////////////////////////////////////////////////////
/// Setup/teardown helpers
////////////////////////////////////////////////////////////////////////////////
static
int pscom_utest_enable_memcpy_mock(void **state)
{
	(void) state;
	pscom_utest.mock_functions.memcpy = 1;

	return 0;
}

static
int pscom_utest_disable_memcpy_mock(void **state)
{
	(void) state;
	pscom_utest.mock_functions.memcpy = 0;

	return 0;
}

int main(void)
{
	size_t failed_tests = 0;
	size_t total_tests = 0;

	/* pscom_io tests */
	const struct CMUnitTest pscom_io_tests[] = {
		cmocka_unit_test(test_req_prepare_send_pending_valid_send_request),
		cmocka_unit_test(test_req_prepare_send_pending_truncate_data_len),
		cmocka_unit_test_setup_teardown(
			test_post_recv_partial_genreq,
			setup_dummy_con,
			teardown_dummy_con),
	};
	total_tests += TEST_GROUP_SIZE(pscom_io_tests);
	failed_tests += cmocka_run_group_tests(pscom_io_tests, NULL, NULL);

#ifdef PSCOM_CUDA_AWARENESS
	/* CUDA-related tests */
	const struct CMUnitTest pscom_cuda_tests[] = {
		cmocka_unit_test(test_is_cuda_enabled_returns_zero_if_disabled),
		cmocka_unit_test(test_is_cuda_enabled_returns_one_if_enabled),
		cmocka_unit_test(test_cuda_init_cuInit_error),
		cmocka_unit_test(test_cuda_init_returns_success_if_disabled),
		cmocka_unit_test(test_cuda_init_device_count_error),
		cmocka_unit_test(test_cuda_init_device_count_zero),
		cmocka_unit_test(test_cuda_init_uva_check_fails),
		cmocka_unit_test(test_cuda_init_no_uva_support),
		cmocka_unit_test(test_buffer_needs_staging_if_cuda_disabled),
		cmocka_unit_test(test_buffer_needs_staging_con_not_cuda_aware),
		cmocka_unit_test(test_buffer_needs_staging_con_cuda_aware),
		cmocka_unit_test(test_is_gpu_mem_if_cuda_disabled),
		cmocka_unit_test(test_is_gpu_mem_get_attributes_fails),
		cmocka_unit_test(test_is_gpu_mem_managed_memory),
		cmocka_unit_test(test_is_gpu_mem_device_memory),
		cmocka_unit_test(test_is_gpu_mem_wrapper_device_memory),
		cmocka_unit_test(test_is_gpu_mem_sync_memop_disabled),
		cmocka_unit_test(test_is_gpu_mem_sync_memop_enabled),
		cmocka_unit_test_setup_teardown(
			test_pscom_memcpy_gpu_safe_from_user_host_mem,
			pscom_utest_enable_memcpy_mock,
			pscom_utest_disable_memcpy_mock),
		cmocka_unit_test(test_pscom_memcpy_gpu_safe_from_user_device_mem),
		cmocka_unit_test_setup_teardown(
			test_pscom_memcpy_gpu_safe_to_user_host_mem,
			pscom_utest_enable_memcpy_mock,
			pscom_utest_disable_memcpy_mock),
		cmocka_unit_test(test_pscom_memcpy_gpu_safe_to_user_device_mem),
		cmocka_unit_test_setup_teardown(
			test_pscom_memcpy_gpu_safe_default_host_mem,
			pscom_utest_enable_memcpy_mock,
			pscom_utest_disable_memcpy_mock),
		cmocka_unit_test(test_pscom_memcpy_gpu_safe_default_device_mem),
		cmocka_unit_test_setup_teardown(
			test_pscom_memcpy_host_mem,
			pscom_utest_enable_memcpy_mock,
			pscom_utest_disable_memcpy_mock),
		cmocka_unit_test(test_pscom_stage_buffer_dev_mem_no_con),
		cmocka_unit_test(test_pscom_stage_buffer_host_mem),
		cmocka_unit_test(test_pscom_unstage_buffer_dev_mem),
		cmocka_unit_test(test_pscom_unstage_buffer_dev_mem_no_copy),
		cmocka_unit_test(test_pscom_unstage_buffer_host_mem),
	};
	total_tests += TEST_GROUP_SIZE(pscom_cuda_tests);
	failed_tests += cmocka_run_group_tests(pscom_cuda_tests, NULL, NULL);
#endif

	printf("\n\n");
	printf("Total tests      : %lu\n", total_tests);
	printf("Succeeding tests : %lu\n", total_tests-failed_tests);
	printf("Failing tests    : %lu\n", failed_tests);
	printf("\n\n");

	return (int)failed_tests;
}
