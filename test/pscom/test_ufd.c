/*
 * ParaStation
 *
 * Copyright (C) 2023-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>

#include "pscom_utest.h"
#include "mocks/misc_mocks.h"
#include "pscom_precon.c"

////////////////////////////////////////////////////////////////////////////////
/// Helper functions
////////////////////////////////////////////////////////////////////////////////
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

    /* destroy the connection and implicitely close the global ufd*/
    pscom_precon_destroy(ufd_info->priv);

    return 0;
}

/**
 * \brief Test avoid writing when preconnection was refused
 *
 * Given: A multi-threaded environment
 * When: reading from file descriptor and connection is refused
 * Then: data will not be sent due to a Bad file descriptor
 */
void test_do_not_write_when_con_refused(void **state)
{
    /* create and initialize the precon object */
    precon_t *precon = (precon_t *)(*state);
    pscom_precon_assign_fd(precon, 0x42);

    /* enabled threaded mode */
    pscom.threaded = 1;

    /* set POLLIN and POLLOUT events*/
    ufd_event_set(&pscom.ufd, &precon->ufd_info, POLLIN | POLLOUT);

    precon->recv_done = 0;
    enable_read_mock();

    /* force connection refused when reading */
    will_return(__wrap_read, ECONNREFUSED);
    will_return(__wrap_read, -1);

    will_return(__wrap_poll, (POLLIN | POLLOUT));
    will_return(__wrap_poll, 1);

    precon->ufd_info.can_write = &check_can_write;

    /* There is a valid pollfd index */
    assert_true(precon->ufd_info.pollfd_idx != -1);

    pscom_progress(0);

    /* No valid pollfd index anymore */
    assert_true(precon->ufd_info.pollfd_idx == -1);

    disable_read_mock();

    /* disable threaded mode */
    pscom.threaded = 0;
}


/**
 * \brief Test avoid writing when preconnection was reset by peer
 *
 * Given: A multi-threaded environment
 * When: reading from file descriptor and connection is reset by peer
 * Then: data will not be sent due to a Bad file descriptor
 */
void test_do_not_write_con_reset_by_peer(void **state)
{
    /* create and initialize the precon object */
    precon_t *precon = (precon_t *)(*state);
    pscom_precon_assign_fd(precon, 0x42);

    /* enabled threaded mode */
    pscom.threaded = 1;

    /* set POLLIN and POLLOUT events*/
    ufd_event_set(&pscom.ufd, &precon->ufd_info, POLLIN | POLLOUT);

    precon->recv_done = 0;
    enable_read_mock();

    /* force connection refused when reading */
    will_return(__wrap_read, ECONNRESET);
    will_return(__wrap_read, -1);

    will_return(__wrap_poll, (POLLIN | POLLOUT));
    will_return(__wrap_poll, 1);

    precon->ufd_info.can_write = &check_can_write;

    /* There is a valid pollfd index */
    assert_true(precon->ufd_info.pollfd_idx != -1);

    pscom_progress(0);

    /* No valid pollfd index anymore */
    assert_true(precon->ufd_info.pollfd_idx == -1);

    disable_read_mock();

    /* disable threaded mode */
    pscom.threaded = 0;
}


/**
 * \brief Test avoid reading when preconnection receive was stopped
 *
 * Given: A multi-threaded environment
 * When: precon is stopped and data has been completely received
 * Then: there will not be more read unless precon->recv_done becomes 0 again
 */
void test_do_not_read_when_stopped_precon(void **state)
{
    /* create and initialize the precon object */
    precon_t *precon = (precon_t *)(*state);
    pscom_precon_assign_fd(precon, 0x42);

    /* enabled threaded mode */
    pscom.threaded = 1;

    /* set POLLIN and POLLOUT events*/
    ufd_event_set(&pscom.ufd, &precon->ufd_info, POLLIN | POLLOUT);

    /* stop preconnection. The next function will unset POLLIN from pollfd */
    pscom_precon_recv_stop(precon);

    will_return(__wrap_poll, (POLLIN | POLLOUT));
    will_return(__wrap_poll, 1);

    precon->ufd_info.can_read = &check_can_read;

    /* There is a valid pollfd index */
    assert_true(precon->ufd_info.pollfd_idx != -1);

    pscom_progress(0);

    /* No valid pollfd index anymore */
    assert_true(precon->ufd_info.pollfd_idx == -1);

    /* disable threaded mode */
    pscom.threaded = 0;
}


/**
 * \brief Test reading when preconnection was not destroyed
 *
 * Given: A multi-threaded environment
 * When: precon is destroyed
 * Then: there will not be further progress
 */
void test_do_not_progress_when_destroyed_precon(void **state)
{
    /* create and initialize the precon object */
    precon_t *precon = (precon_t *)(*state);
    pscom_precon_assign_fd(precon, 0x42);

    /* enabled threaded mode */
    pscom.threaded = 1;

    /* set POLLIN and POLLOUT events*/
    ufd_event_set(&pscom.ufd, &precon->ufd_info, POLLIN);

    /* There is a valid pollfd index */
    assert_true(precon->ufd_info.pollfd_idx != -1);

    /* destroy preconnection. The next function
       will set precon->ufd_info.fd to -1 as well*/
    pscom_precon_destroy(precon);

    pscom_progress(0);

    /* No valid pollfd index anymore */
    assert_true(precon->ufd_info.pollfd_idx == -1);

    /* disable threaded mode */
    pscom.threaded = 0;
}


/**
 * \brief Test write when preconnection was neither refused nor reset by peer
 *
 * Given: A multi-threaded environment
 * When: connection is fine
 * Then: reading and sending data are working normally
 */
void test_read_and_write_normally(void **state)
{
    /* create and initialize the precon object */
    precon_t *precon = (precon_t *)(*state);
    pscom_precon_assign_fd(precon, 0x42);

    /* enabled threaded mode */
    pscom.threaded = 1;

    ufd_event_set(&pscom.ufd, &precon->ufd_info, POLLIN | POLLOUT);

    will_return(__wrap_poll, (POLLIN | POLLOUT));
    will_return(__wrap_poll, 1);

    precon->ufd_info.can_read = &check_can_read;
    expect_function_call_any(check_can_read);
    precon->ufd_info.can_write = &check_can_write;
    expect_function_call_any(check_can_write);

    /* There is a valid pollfd index */
    assert_true(precon->ufd_info.pollfd_idx != -1);

    pscom_progress(0);

    /* There is still a valid pollfd index */
    assert_true(precon->ufd_info.pollfd_idx != -1);

    /* disable threaded mode */
    pscom.threaded = 0;
}


/**
 * \brief Test write when preconnection was neither refused nor reset by peer
 *
 * Given: A multi-threaded environment
 * When: only POLLOUT is set
 * Then: the data will be sent without reading before
 */
void test_only_write_when_no_pollin(void **state)
{
    /* create and initialize the precon object */
    precon_t *precon = (precon_t *)(*state);
    pscom_precon_assign_fd(precon, 0x42);

    /* enabled threaded mode */
    pscom.threaded = 1;

    ufd_event_set(&pscom.ufd, &precon->ufd_info, POLLOUT);

    will_return(__wrap_poll, POLLOUT);
    will_return(__wrap_poll, 1);

    precon->ufd_info.can_read  = &check_can_read;
    precon->ufd_info.can_write = &check_can_write;
    expect_function_call_any(check_can_write);

    /* There is a valid pollfd index */
    assert_true(precon->ufd_info.pollfd_idx != -1);

    pscom_progress(0);

    /* There is still a valid pollfd index */
    assert_true(precon->ufd_info.pollfd_idx != -1);

    /* disable threaded mode */
    pscom.threaded = 0;
}


/**
 * \brief Test avoid reading if the global ufd is not valid anymore
 *
 * Given: Threading is enabled and poll() returns POLLING for a given ufd
 * When: another thread thread first processes POLLIN on a given ufd
 * Then: this thread does not try to further read on this ufd.
 */
void test_do_not_read_if_global_ufd_is_gone(void **state)
{
    /* create and initialize the precon object */
    precon_t *precon = (precon_t *)(*state);
    pscom_precon_assign_fd(precon, 0x42);

    /* set the can_red/can_write callbacks */
    precon->ufd_info.can_read  = &check_can_read;
    precon->ufd_info.can_write = &check_can_write;

    /* enabled threaded mode */
    pscom.threaded = 1;

    /* set POLLIN event */
    ufd_event_set(&pscom.ufd, &precon->ufd_info, POLLIN);


    enable_sched_yield_mock();

    will_return(__wrap_sched_yield, &mock_sched_yield_close_global_ufd);
    will_return(__wrap_sched_yield, (void *)&precon->ufd_info);
    will_return(__wrap_poll, POLLIN);
    will_return(__wrap_poll, 1);

    pscom_progress(0);

    /* implicit test: check_can_read() is NOT called */

    disable_sched_yield_mock();

    /* disable threaded mode */
    pscom.threaded = 0;
}


/**
 * \brief Test avoid writing if the global ufd is not valid anymore
 *
 * Given: Threading is enabled and poll() returns POLLOUT for a given ufd
 * When: another thread thread first processes POLLOUT on a given ufd
 * Then: this thread does not try to further write on this ufd.
 */
void test_do_not_write_if_global_ufd_is_gone(void **state)
{
    /* create and initialize the precon object */
    precon_t *precon = (precon_t *)(*state);
    pscom_precon_assign_fd(precon, 0x42);

    /* set the can_red/can_write callbacks */
    precon->ufd_info.can_read  = &check_can_read;
    precon->ufd_info.can_write = &check_can_write;

    /* enabled threaded mode */
    pscom.threaded = 1;

    /* set POLLOUT event */
    ufd_event_set(&pscom.ufd, &precon->ufd_info, POLLOUT);


    enable_sched_yield_mock();

    will_return(__wrap_sched_yield, &mock_sched_yield_close_global_ufd);
    will_return(__wrap_sched_yield, (void *)&precon->ufd_info);
    will_return(__wrap_poll, POLLOUT);
    will_return(__wrap_poll, 1);

    pscom_progress(0);

    /* implicit test: check_can_write() is NOT called */

    disable_sched_yield_mock();

    /* disable threaded mode */
    pscom.threaded = 0;
}
