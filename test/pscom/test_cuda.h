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

void test_cuda_cleanup_returns_success_if_disabled(void **state);
void test_cuda_cleanup_destroys_cuda_streams(void **state);
void test_cuda_cleanup_for_inactive_device(void **state);
void test_cuda_cleanup_for_unclear_device_status(void **state);
void test_cuda_cleanup_for_cuda_deinitialized(void **state);
void test_cuda_cleanup_for_failing_stream_destroy(void **state);

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
void test_pscom_memcpy_gpu_safe_from_user_creates_cuda_stream(void **state);
void test_pscom_memcpy_gpu_safe_to_user_host_mem(void **state);
void test_pscom_memcpy_gpu_safe_to_user_device_mem(void **state);
void test_pscom_memcpy_gpu_safe_default_host_mem(void **state);
void test_pscom_memcpy_gpu_safe_default_device_mem(void **state);
void test_pscom_memcpy_host_mem(void **state);

void test_pscom_memcmp_gpu_safe_equal(void **state);
void test_pscom_memcmp_gpu_safe_larger(void **state);
void test_pscom_memcmp_gpu_safe_smaller(void **state);

void test_pscom_stage_buffer_dev_mem_no_con(void **state);
void test_pscom_stage_buffer_host_mem(void **state);
void test_pscom_unstage_buffer_dev_mem(void **state);
void test_pscom_unstage_buffer_dev_mem_no_copy(void **state);
void test_pscom_unstage_buffer_dev_mem_err_req(void **state);
void test_pscom_unstage_buffer_host_mem(void **state);

void test_cuda_post_recv_without_staging(void **state);
void test_cuda_post_send_without_staging(void **state);
#endif /* _TEST_CUDA_H_ */
