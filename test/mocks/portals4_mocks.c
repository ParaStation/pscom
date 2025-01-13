/*
 * ParaStation
 *
 * Copyright (C) 2022-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdarg.h> /* IWYU pragma: keep */
#include <stddef.h> /* IWYU pragma: keep */
#include <stdint.h> /* IWYU pragma: keep */
#include <setjmp.h> /* IWYU pragma: keep */
#include <cmocka.h>

#include <portals4.h>

#include "mocks/portals4_mocks.h"
#include "pscom_utest.h"

static void *save_user_ptr = NULL;

////////////////////////////////////////////////////////////////////////////////
/// Mocking funktions for Portals4
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Mocking function for PtlNIInit()
 */
int __wrap_PtlNIInit(ptl_interface_t iface, unsigned int options, ptl_pid_t pid,
                     const ptl_ni_limits_t *desired, ptl_ni_limits_t *actual,
                     ptl_handle_ni_t *ni_handle)
{
    /* provide a max_msg_size used by rendezvous transfers */
    actual->max_msg_size = 64 * 1024 * 1024;

    return PTL_OK;
}


/**
 * \brief Mocking function for PtlNIFini()
 */
int __wrap_PtlNIFini(ptl_handle_ni_t ni_handle)
{
    return PTL_OK;
}


/**
 * \brief Mocking function for PtlInit()
 */
int __wrap_PtlInit(void)
{
    function_called();

    return PTL_OK;
}


/**
 * \brief Mocking function for PtlFini()
 */
int __wrap_PtlFini(void)
{
    return PTL_OK;
}


/**
 * \brief Mocking function for PtlGetPhysId()
 */
int __wrap_PtlGetPhysId(ptl_handle_ni_t ni_handle, ptl_process_t *id)
{
    return PTL_OK;
}


/**
 * \brief Mocking function for PtlEQAlloc()
 */
int __wrap_PtlEQAlloc(ptl_handle_ni_t ni_handle, ptl_size_t count,
                      ptl_handle_eq_t *eq_handle)
{
    return PTL_OK;
}


/**
 * \brief Mocking function for PtlEQFree()
 */
int __wrap_PtlEQFree(ptl_handle_eq_t eq_handle)
{
    return PTL_OK;
}


/**
 * \brief Mocking function for PtlEQGet()
 */
int __wrap_PtlEQGet(ptl_handle_eq_t eq_handle, ptl_event_t *event)
{
    void *user_ptr = mock_type(void *);

    event->hdr_data     = mock_type(uint64_t);
    event->type         = mock_type(ptl_event_kind_t);
    event->ni_fail_type = mock_type(ptl_ni_fail_t);
    event->mlength      = mock_type(uint64_t);
    event->rlength      = mock_type(uint64_t);
    event->user_ptr     = user_ptr ? user_ptr : save_user_ptr;
    event->pt_index     = 0;
    return mock_type(int);
}


/**
 * \brief Mocking function for PtlEQPoll()
 */
int __wrap_PtlEQPoll(const ptl_handle_eq_t *eq_handles, unsigned int size,
                     ptl_time_t timeout, ptl_event_t *event,
                     unsigned int *which)
{
    void *user_ptr = mock_type(void *);

    event->hdr_data     = mock_type(uint64_t);
    event->type         = mock_type(ptl_event_kind_t);
    event->ni_fail_type = mock_type(ptl_ni_fail_t);
    event->mlength      = mock_type(uint64_t);
    event->rlength      = mock_type(uint64_t);
    event->pt_index     = mock_type(uint32_t);
    event->user_ptr     = user_ptr ? user_ptr : save_user_ptr;

    *which = mock_type(int);

    return mock_type(int);
}


/**
 * \brief Mocking function for PtlMDBind()
 */
int __wrap_PtlMDBind(ptl_handle_ni_t ni_handle, const ptl_md_t *md,
                     ptl_handle_md_t *md_handle)
{
    function_called();
    return PTL_OK;
}


/**
 * \brief Mocking function for PtlMDRelease()
 */
int __wrap_PtlMDRelease(ptl_handle_md_t md_handle)
{
    function_called();
    return PTL_OK;
}


/**
 * \brief Mocking function for PtlPTAlloc()
 */
int __wrap_PtlPTAlloc(ptl_handle_ni_t ni_handle, unsigned int options,
                      ptl_handle_eq_t eq_handle, ptl_pt_index_t pt_index_req,
                      ptl_pt_index_t *pt_index)
{
    *pt_index = 0x42;

    return PTL_OK;
}


/**
 * \brief Mocking function for PtlPTFree()
 */
int __wrap_PtlPTFree(ptl_handle_ni_t ni_handle, ptl_pt_index_t pt_index)
{
    return PTL_OK;
}


/**
 * \brief Mocking function for PtlPut()
 */
int __wrap_PtlPut(ptl_handle_md_t md_handle, ptl_size_t local_offset,
                  ptl_size_t length, ptl_ack_req_t ack_req,
                  ptl_process_t target_id, ptl_pt_index_t pt_index,
                  ptl_match_bits_t match_bits, ptl_size_t remote_offset,
                  void *user_ptr, ptl_hdr_data_t hdr_data)
{
    function_called();

    save_user_ptr = user_ptr;

    if (pscom_utest.mock_functions.portals.extended_ptl_put) {
        check_expected(local_offset);
        check_expected(length);
    }

    return mock_type(int);
}


/**
 * \brief Mocking function for PtlMEAppend()
 */
int __wrap_PtlMEAppend(ptl_handle_ni_t ni_handle, ptl_pt_index_t pt_index,
                       const ptl_me_t *me, ptl_list_t ptl_list, void *user_ptr,
                       ptl_handle_me_t *me_handle)
{
    function_called();

    return mock_type(int);
}


/**
 * \brief Mocking function for PtlMEUnlink()
 */
int __wrap_PtlMEUnlink(ptl_handle_me_t me_handle)
{
    function_called();

    return PTL_OK;
}
