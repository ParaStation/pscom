/*
 * ParaStation
 *
 * Copyright (C) 2023-2024 ParTec AG, Munich
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

#include <assert.h>
#include <errno.h>
#include <poll.h>

#include "mocks/misc_mocks.h"
#include "pscom_precon.h"
#include "pscom_priv.h"
#include "pscom_ufd.h"

#include "pscom_precon.c"
#include "pscom_precon_tcp.h"
#include "pscom_ufd.c"

#include "util/test_utils_ufd.h"

////////////////////////////////////////////////////////////////////////////////
/// Helper functions
////////////////////////////////////////////////////////////////////////////////
static void delete_pollfd(ufd_t *ufd, ufd_info_t *ufd_info)
{
    ufd_del(ufd, ufd_info);
    function_called();
}

static void check_can_read(ufd_t *ufd, ufd_info_t *ufd_info)
{
    function_called();
}

static void check_can_write(ufd_t *ufd, ufd_info_t *ufd_info)
{
    function_called();
}

int mock_sched_yield_close_global_ufd(void *arg)
{
    ufd_info_t *ufd_info = (ufd_info_t *)arg;

    /* remove the global ufd */
    _ufd_put_pollfd_idx(&pscom.ufd, ufd_info);

    return 0;
}

/**
 * \brief Test avoid writing when preconnection was refused
 *
 * Given: A multi-threaded environment
 * When: reading from file descriptor and connection is refused
 * Then: data will not be sent due to a Bad file descriptor
 */
void test_ufd_do_not_write_when_con_refused(void **state)
{
    /* initialize and do checks with the global ufd object in threaded mode */
    ufd_t *ufd = test_utils_init_ufd_threaded(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* set POLLIN and POLLOUT events*/
    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLIN | POLLOUT);

    pre_tcp->recv_done = 0;
    enable_read_mock();

    /* force connection refused when reading */
    will_return(__wrap_read, ECONNREFUSED);
    will_return(__wrap_read, -1);

    will_return(__wrap_poll, (POLLIN | POLLOUT));
    will_return(__wrap_poll, 1);

    pre_tcp->ufd_info.can_write = &check_can_write;

    /* There is a valid pollfd index */
    assert_true(pre_tcp->ufd_info.pollfd_idx != -1);

    pscom_progress(0);

    /* No valid pollfd index anymore */
    assert_true(pre_tcp->ufd_info.pollfd_idx == -1);

    disable_read_mock();

    /* clean up ufd and disable threaded mode */
    test_utils_cleanup_ufd_threaded(ufd);
}


/**
 * \brief Test avoid writing when preconnection was reset by peer
 *
 * Given: A multi-threaded environment
 * When: reading from file descriptor and connection is reset by peer
 * Then: data will not be sent due to a Bad file descriptor
 */
void test_ufd_do_not_write_con_reset_by_peer(void **state)
{
    /* initialize and do checks with the global ufd object in threaded mode */
    ufd_t *ufd = test_utils_init_ufd_threaded(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* set POLLIN and POLLOUT events*/
    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLIN | POLLOUT);

    pre_tcp->recv_done = 0;
    enable_read_mock();

    /* force connection refused when reading */
    will_return(__wrap_read, ECONNRESET);
    will_return(__wrap_read, -1);

    will_return(__wrap_poll, (POLLIN | POLLOUT));
    will_return(__wrap_poll, 1);

    pre_tcp->ufd_info.can_write = &check_can_write;

    /* There is a valid pollfd index */
    assert_true(pre_tcp->ufd_info.pollfd_idx != -1);

    pscom_progress(0);

    /* No valid pollfd index anymore */
    assert_true(pre_tcp->ufd_info.pollfd_idx == -1);

    disable_read_mock();

    /* clean up ufd and disable threaded mode */
    test_utils_cleanup_ufd_threaded(ufd);
}


/**
 * \brief Test the avoidance of writing when global pollfd has been cleared
 *
 * Given: A multi-threaded environment
 * When: clearing global pollfd while reading
 * Then: there will not be a write due to an outdated local pollfd
 */
void test_ufd_do_not_write_when_pollfd_is_cleared(void **state)
{
    /* initialize and do checks with the global ufd object in threaded mode */
    ufd_t *ufd = test_utils_init_ufd_threaded(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* set POLLIN and POLLOUT events*/
    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLIN | POLLOUT);

    /* remove pollfd */
    pre_tcp->ufd_info.can_read = &delete_pollfd;
    expect_function_call_any(delete_pollfd);

    will_return(__wrap_poll, (POLLIN | POLLOUT));
    will_return(__wrap_poll, 1);

    /* we cannot write due to the removed pollfd */
    pre_tcp->ufd_info.can_write = &check_can_write;

    /* There is a valid pollfd equals to the current ufd_info */
    assert_true(ufd->ufd_pollfd_info[0] == &pre_tcp->ufd_info);

    pscom_progress(0);

    /* No valid pollfd anymore after deleting it */
    assert_true(ufd->ufd_pollfd_info[0] == NULL);

    /* clean up ufd and disable threaded mode */
    test_utils_cleanup_ufd_threaded(ufd);
}


/**
 * \brief Test write after reading when global pollfd is not updated
 *
 * Given: A multi-threaded environment
 * When: global pollfd is not updated while reading
 * Then: there will be a write as POLLOUT is in the flags
 */
void test_ufd_write_when_pollfd_is_not_updated(void **state)
{
    /* initialize and do checks with the global ufd object in threaded mode */
    ufd_t *ufd = test_utils_init_ufd_threaded(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* set POLLIN and POLLOUT events*/
    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLIN | POLLOUT);

    /* we read without updating the current pollfd */
    pre_tcp->ufd_info.can_read = &check_can_read;
    expect_function_call_any(check_can_read);

    will_return(__wrap_poll, (POLLIN | POLLOUT));
    will_return(__wrap_poll, 1);

    /* we will be able to write with the current pollfd */
    pre_tcp->ufd_info.can_write = &check_can_write;
    expect_function_call_any(check_can_write);

    /* There is a valid pollfd equals to the current ufd_info */
    assert_true(ufd->ufd_pollfd_info[0] == &pre_tcp->ufd_info);

    pscom_progress(0);

    /* There is still a valid pollfd equals to the current ufd_info */
    assert_true(ufd->ufd_pollfd_info[0] == &pre_tcp->ufd_info);

    /* clean up ufd and disable threaded mode */
    test_utils_cleanup_ufd_threaded(ufd);
}


/**
 * \brief Test avoid reading when preconnection receive was stopped
 *
 * Given: A multi-threaded environment
 * When: precon is stopped and data has been completely received
 * Then: there will not be more read unless precon->recv_done becomes 0 again
 */
void test_ufd_do_not_read_when_stopped_precon(void **state)
{
    /* initialize and do checks with the global ufd object in threaded mode */
    ufd_t *ufd = test_utils_init_ufd_threaded(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* set POLLIN and POLLOUT events*/
    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLIN | POLLOUT);

    pre_tcp->ufd_info.can_read = &check_can_read;

    /* stop preconnection. The next function will unset POLLIN from pollfd */
    pscom_precon_recv_stop(precon);

    will_return(__wrap_poll, (POLLIN | POLLOUT));
    /* return here 0 since stopping precon clears POLLIN event */
    will_return(__wrap_poll, 0);

    pscom_progress(0);

    /* implicit test: check_can_read() is NOT called */

    /* clean up ufd and disable threaded mode */
    test_utils_cleanup_ufd_threaded(ufd);
}


/**
 * \brief Test reading when preconnection was not destroyed
 *
 * Given: A multi-threaded environment
 * When: precon is destroyed
 * Then: there will not be further progress
 */
void test_ufd_do_not_progress_when_destroyed_precon(void **state)
{
    /* initialize and do checks with the global ufd object in threaded mode */
    ufd_t *ufd = test_utils_init_ufd_threaded(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* set POLLIN and POLLOUT events*/
    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLIN);

    /* Call teardown of connection since precon will be destroyed */
    *state = pre_tcp->con;

    /* There is a valid precon */
    assert_true(precon->magic == MAGIC_PRECON);

    /* destroy preconnection */
    pscom_precon_destroy(precon);
    precon = NULL;

    int progress = pscom_progress(0);

    /* There is no further progress */
    assert(progress == 0);

    /* clean up ufd and disable threaded mode */
    test_utils_cleanup_ufd_threaded(ufd);
}


/**
 * \brief Test write when preconnection was neither refused nor reset by peer
 *
 * Given: A multi-threaded environment
 * When: connection is fine
 * Then: reading and sending data are working normally
 */
void test_ufd_read_and_write_normally(void **state)
{
    /* initialize and do checks with the global ufd object in threaded mode */
    ufd_t *ufd = test_utils_init_ufd_threaded(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLIN | POLLOUT);

    will_return(__wrap_poll, (POLLIN | POLLOUT));
    will_return(__wrap_poll, 1);

    pre_tcp->ufd_info.can_read = &check_can_read;
    expect_function_call_any(check_can_read);
    pre_tcp->ufd_info.can_write = &check_can_write;
    expect_function_call_any(check_can_write);

    /* There is a valid pollfd index */
    assert_true(pre_tcp->ufd_info.pollfd_idx != -1);

    pscom_progress(0);

    /* There is still a valid pollfd index */
    assert_true(pre_tcp->ufd_info.pollfd_idx != -1);

    /* clean up ufd and disable threaded mode */
    test_utils_cleanup_ufd_threaded(ufd);
}


/**
 * \brief Test write when preconnection was neither refused nor reset by peer
 *
 * Given: A multi-threaded environment
 * When: only POLLOUT is set
 * Then: the data will be sent without reading before
 */
void test_ufd_only_write_when_no_pollin(void **state)
{
    /* initialize and do checks with the global ufd object in threaded mode */
    ufd_t *ufd = test_utils_init_ufd_threaded(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLOUT);

    will_return(__wrap_poll, POLLOUT);
    will_return(__wrap_poll, 1);

    pre_tcp->ufd_info.can_read  = &check_can_read;
    pre_tcp->ufd_info.can_write = &check_can_write;
    expect_function_call_any(check_can_write);

    /* There is a valid pollfd index */
    assert_true(pre_tcp->ufd_info.pollfd_idx != -1);

    pscom_progress(0);

    /* There is still a valid pollfd index */
    assert_true(pre_tcp->ufd_info.pollfd_idx != -1);

    /* clean up ufd and disable threaded mode */
    test_utils_cleanup_ufd_threaded(ufd);
}


/**
 * \brief Test avoid reading if the global ufd is not valid anymore
 *
 * Given: Threading is enabled and poll() returns POLLING for a given ufd
 * When: another thread thread first processes POLLIN on a given ufd
 * Then: this thread does not try to further read on this ufd.
 */
void test_ufd_do_not_read_if_global_ufd_is_gone(void **state)
{
    /* initialize and do checks with the global ufd object in threaded mode */
    ufd_t *ufd = test_utils_init_ufd_threaded(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* set the can_red/can_write callbacks */
    pre_tcp->ufd_info.can_read  = &check_can_read;
    pre_tcp->ufd_info.can_write = &check_can_write;

    /* set POLLIN event */
    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLIN);

    enable_sched_yield_mock();

    will_return(__wrap_sched_yield, &mock_sched_yield_close_global_ufd);
    will_return(__wrap_sched_yield, (void *)&pre_tcp->ufd_info);
    will_return(__wrap_poll, POLLIN);
    will_return(__wrap_poll, 1);

    pscom_progress(0);

    /* implicit test: check_can_read() is NOT called */

    disable_sched_yield_mock();

    /* clean up ufd and disable threaded mode */
    test_utils_cleanup_ufd_threaded(ufd);
}


/**
 * \brief Test avoid writing if the global ufd is not valid anymore
 *
 * Given: Threading is enabled and poll() returns POLLOUT for a given ufd
 * When: another thread thread first processes POLLOUT on a given ufd
 * Then: this thread does not try to further write on this ufd.
 */
void test_ufd_do_not_write_if_global_ufd_is_gone(void **state)
{
    /* initialize and do checks with the global ufd object in threaded mode */
    ufd_t *ufd = test_utils_init_ufd_threaded(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* set the can_red/can_write callbacks */
    pre_tcp->ufd_info.can_read  = &check_can_read;
    pre_tcp->ufd_info.can_write = &check_can_write;

    /* set POLLOUT event */
    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLOUT);

    enable_sched_yield_mock();

    will_return(__wrap_sched_yield, &mock_sched_yield_close_global_ufd);
    will_return(__wrap_sched_yield, (void *)&pre_tcp->ufd_info);
    will_return(__wrap_poll, POLLOUT);
    will_return(__wrap_poll, 1);

    pscom_progress(0);

    /* implicit test: check_can_write() is NOT called */

    disable_sched_yield_mock();

    /* clean up ufd and disable threaded mode */
    test_utils_cleanup_ufd_threaded(ufd);
}
