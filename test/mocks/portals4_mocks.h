/*
 * ParaStation
 *
 * Copyright (C) 2022-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PORTALS4_MOCKS_H_
#define _PORTALS4_MOCKS_H_

#include <portals4.h>
#include "pscom_utest.h"

static inline void enable_extended_ptl_put_mock(void)
{
    pscom_utest.mock_functions.portals.extended_ptl_put = 1;
}
static inline void disable_extended_ptl_put_mock(void)
{
    pscom_utest.mock_functions.portals.extended_ptl_put = 0;
}

/* Mocking functions for portals4 */

int __wrap_PtlNIInit(ptl_interface_t iface, unsigned int options, ptl_pid_t pid,
                     const ptl_ni_limits_t *desired, ptl_ni_limits_t *actual,
                     ptl_handle_ni_t *ni_handle);
int __wrap_PtlNIFini(ptl_handle_ni_t ni_handle);
int __wrap_PtlInit(void);
int __wrap_PtlFini(void);
int __wrap_PtlGetPhysId(ptl_handle_ni_t ni_handle, ptl_process_t *id);
int __wrap_PtlEQAlloc(ptl_handle_ni_t ni_handle, ptl_size_t count,
                      ptl_handle_eq_t *eq_handle);
int __wrap_PtlEQFree(ptl_handle_eq_t eq_handle);
int __wrap_PtlEQGet(ptl_handle_eq_t eq_handle, ptl_event_t *event);
int __wrap_PtlEQPoll(const ptl_handle_eq_t *eq_handles, unsigned int size,
                     ptl_time_t timeout, ptl_event_t *event,
                     unsigned int *which);
int __wrap_PtlMDBind(ptl_handle_ni_t ni_handle, const ptl_md_t *md,
                     ptl_handle_md_t *md_handle);
int __wrap_PtlMDRelease(ptl_handle_md_t md_handle);
int __wrap_PtlPTAlloc(ptl_handle_ni_t ni_handle, unsigned int options,
                      ptl_handle_eq_t eq_handle, ptl_pt_index_t pt_index_req,
                      ptl_pt_index_t *pt_index);
int __wrap_PtlPTFree(ptl_handle_ni_t ni_handle, ptl_pt_index_t pt_index);
int __wrap_PtlPut(ptl_handle_md_t md_handle, ptl_size_t local_offset,
                  ptl_size_t length, ptl_ack_req_t ack_req,
                  ptl_process_t target_id, ptl_pt_index_t pt_index,
                  ptl_match_bits_t match_bits, ptl_size_t remote_offset,
                  void *user_ptr, ptl_hdr_data_t hdr_data);
int __wrap_PtlMEAppend(ptl_handle_ni_t ni_handle, ptl_pt_index_t pt_index,
                       const ptl_me_t *me, ptl_list_t ptl_list, void *user_ptr,
                       ptl_handle_me_t *me_handle);
int __wrap_PtlMEUnlink(ptl_handle_me_t me_handle);

#endif /* _PORTALS4_MOCKS_H_ */
