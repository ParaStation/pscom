#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "pscom/test_cuda.h"
#include "pscom/test_io.h"

int main(void)
{
	const struct CMUnitTest pscom_tests[] = {
		cmocka_unit_test(test_req_prepare_send_pending_valid_send_request),
		cmocka_unit_test(test_req_prepare_send_pending_truncate_data_len),
#ifdef PSCOM_CUDA_AWARENESS
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
		cmocka_unit_test(test_pscom_memcpy_gpu_safe_from_user_host_mem),
		cmocka_unit_test(test_pscom_memcpy_gpu_safe_from_user_device_mem),
		cmocka_unit_test(test_pscom_memcpy_gpu_safe_to_user_host_mem),
		cmocka_unit_test(test_pscom_memcpy_gpu_safe_to_user_device_mem),
		cmocka_unit_test(test_pscom_memcpy_gpu_safe_default_host_mem),
		cmocka_unit_test(test_pscom_memcpy_gpu_safe_default_device_mem),
		cmocka_unit_test(test_pscom_memcpy_host_mem),
		cmocka_unit_test(test_pscom_stage_buffer_dev_mem_no_con),
		cmocka_unit_test(test_pscom_stage_buffer_host_mem),
		cmocka_unit_test(test_pscom_unstage_buffer_dev_mem),
		cmocka_unit_test(test_pscom_unstage_buffer_dev_mem_no_copy),
		cmocka_unit_test(test_pscom_unstage_buffer_host_mem),
#endif
	};
	return cmocka_run_group_tests(pscom_tests, NULL, NULL);
}
