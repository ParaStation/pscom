#ifndef _TEST_CUDA_H_
#define _TEST_CUDA_H_
void test_is_cuda_enabled_returns_zero_if_disabled(void **state);
void test_is_cuda_enabled_returns_one_if_enabled(void **state);

void test_cuda_init_cuInit_error(void **state);
void test_cuda_init_returns_success_if_disabled(void **state);
void test_cuda_init_device_count_error(void **state);
void test_cuda_init_device_count_zero(void **state);
void test_cuda_init_uva_check_fails(void **state);
void test_cuda_init_no_uva_support(void **state);

void test_buffer_needs_staging_if_cuda_disabled(void **state);
void test_buffer_needs_staging_con_not_cuda_aware(void **state);
void test_buffer_needs_staging_con_cuda_aware(void **state);

void test_is_gpu_mem_if_cuda_disabled(void **state);
void test_is_gpu_mem_get_attributes_fails(void **state);
void test_is_gpu_mem_managed_memory(void **state);
void test_is_gpu_mem_device_memory(void **state);
void test_is_gpu_mem_wrapper_device_memory(void **state);
void test_is_gpu_mem_sync_memop_disabled(void **state);
void test_is_gpu_mem_sync_memop_enabled(void **state);

void test_pscom_memcpy_gpu_safe_from_user_host_mem(void **state);
void test_pscom_memcpy_gpu_safe_from_user_device_mem(void **state);
void test_pscom_memcpy_gpu_safe_to_user_host_mem(void **state);
void test_pscom_memcpy_gpu_safe_to_user_device_mem(void **state);
void test_pscom_memcpy_gpu_safe_default_host_mem(void **state);
void test_pscom_memcpy_gpu_safe_default_device_mem(void **state);
void test_pscom_memcpy_host_mem(void **state);

void test_pscom_stage_buffer_dev_mem_no_con(void **state);
void test_pscom_stage_buffer_host_mem(void **state);
void test_pscom_unstage_buffer_dev_mem(void **state);
void test_pscom_unstage_buffer_dev_mem_no_copy(void **state);
void test_pscom_unstage_buffer_host_mem(void **state);
#endif /* _TEST_CUDA_H_ */