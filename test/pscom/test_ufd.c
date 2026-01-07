/*
 * ParaStation
 *
 * Copyright (C) 2023-2026 ParTec AG, Munich
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

#include "list.h"
#include "mocks/misc_mocks.h"
#include "pscom_precon.h"
#include "pscom_priv.h"
#include "pscom_ufd.h"

#include "pscom_precon.c"
#include "pscom_precon_tcp.h"
#include "pscom_ufd.c"

#include "test_ufd.h"
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

static int mock_sched_yield_close_global_ufd(void *arg)
{
    ufd_info_t *ufd_info = (ufd_info_t *)arg;

    /* remove the global ufd */
    _ufd_put_pollfd_idx(&pscom.ufd, ufd_info);

    return 0;
}

/* Global ufd info object that can be accessed by callback functions below */
static ufd_info_t global_ufd_info;

static void remove_global_pollfd_info_from_ufd_array(ufd_t *ufd,
                                                     ufd_info_t *ufd_info)
{
    /* remove the global_ufd_info object from the ufd array */
    _ufd_put_pollfd_idx(ufd, &global_ufd_info);
    function_called();
}

static void add_global_pollfd_info_to_ufd_array(ufd_t *ufd, ufd_info_t *ufd_info)
{
    /* add the global_ufd_info object to the ufd array */
    _ufd_get_pollfd_idx(ufd, &global_ufd_info);

    /* and (re)set its function pointers to the common mock
       functions that check if can_read/write are called */
    global_ufd_info.can_read  = &check_can_read;
    global_ufd_info.can_write = &check_can_write;

    function_called();
}


////////////////////////////////////////////////////////////////////////////////
/// The ufd tests
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Test the general ufd initialization and cleaning-up
 *
 * Given: The global ufd object and a TCP precon
 * When: the file descriptor of the precon is set for being polled
 * for different events
 * Then: all ufd related data structures are being initialized
 * correctly and properly cleaned-up at the end
 */
void test_ufd_init_set_and_cleanup(void **state)
{
    /* initialize and do checks with global ufd object in non-threaded mode */
    ufd_t *ufd = test_utils_init_ufd(&pscom.ufd);

    /* make sure that ufd has been initialized correctly */
    assert_true((&ufd->ufd_info)->next == &ufd->ufd_info);
    assert_true((&ufd->ufd_info)->prev == &ufd->ufd_info);
    assert_true(ufd->n_ufd_pollfd == 0);
    assert_true(ufd->ufd_tag == NULL);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* check that ufd_info has been initialized correctly */
    assert_true((&pre_tcp->ufd_info)->pollfd_idx == -1);
    assert_true((&pre_tcp->ufd_info)->fd == 0x42);

    /* check that ufd_info has been added to the global list */
    ufd_info_t *ufd_info = ufd_info_find_fd(ufd, 0x42);
    assert_true(ufd_info == &pre_tcp->ufd_info);

    /* check again that the ufd array is still empty */
    assert_true(ufd->n_ufd_pollfd == 0);

    /* set POLLIN event */
    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLIN);

    /* check that pollfd has been added */
    assert_true(ufd->n_ufd_pollfd == 1);
    assert_true((&pre_tcp->ufd_info)->pollfd_idx >= 0);

    /* check that pollfd has been set correctly */
    struct pollfd *pollfd = ufd_get_pollfd(ufd, &pre_tcp->ufd_info);
    assert_true(pollfd != NULL);
    assert_true(pollfd->fd == 0x42);
    assert_true(pollfd->events == POLLIN);
    assert_true(pollfd->revents == 0);

    /* set POLLOUT event in addition and store index before */
    int old_idx = (&pre_tcp->ufd_info)->pollfd_idx;
    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLOUT);

    /* check that event has been set and index hasn't changed */
    assert_true(pollfd->events == (POLLIN | POLLOUT));
    assert_true((&pre_tcp->ufd_info)->pollfd_idx == old_idx);

    /* clear each of both events and check it */
    ufd_event_clr(ufd, &pre_tcp->ufd_info, POLLIN);
    ufd_event_clr(ufd, &pre_tcp->ufd_info, POLLOUT);
    assert_true(pollfd->events == 0);

    /* check also that pollfd/ufd_info has been removed */
    assert_true(ufd->n_ufd_pollfd == 0);
    assert_true((&pre_tcp->ufd_info)->pollfd_idx == -1);
    pollfd = ufd_get_pollfd(ufd, &pre_tcp->ufd_info);
    assert_true(pollfd == NULL);

    /* clean up the ufd */
    test_utils_cleanup_ufd(ufd);
}


/**
 * \brief Test ufd initialization and cleaning-up in the threaded case
 *
 * Given: The global ufd object and a TCP precon in a multi-threaded
 * environment
 * When: the file descriptor of the precon is set for being polled
 * for different events
 * Then: all ufd related data structures (especially also the ufd_tag for
 * thread synchronization) are being set correctly as well as cleaned-up
 * at the end
 */
void test_ufd_init_set_and_cleanup_threaded(void **state)
{
    /* initialize and do checks with the global ufd object in threaded mode */
    ufd_t *ufd = test_utils_init_ufd_threaded(&pscom.ufd);

    /* make sure that the ufd tag array has been allocated */
    assert_true(ufd->ufd_tag != NULL);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* set POLLIN event */
    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLIN);

    /* check that events have been added to array */
    int idx = (&pre_tcp->ufd_info)->pollfd_idx;
    assert_true(idx >= 0);

    /* check the tag for this pollfd entry */
    uint64_t tag = ufd->ufd_tag[idx];
    assert_true(tag > 0);

    /* set POLLOUT event in addition */
    ufd_event_set(ufd, &pre_tcp->ufd_info, POLLOUT);

    /* check that tag has been updated */
    assert_true(ufd->ufd_tag[idx] != tag);

    /* clear POLLIN event */
    tag = ufd->ufd_tag[idx];
    ufd_event_clr(ufd, &pre_tcp->ufd_info, POLLIN);

    /* check that tag has been updated */
    assert_true(ufd->ufd_tag[idx] != tag);

    /* now clear also POLLOUT event */
    tag = ufd->ufd_tag[idx];
    ufd_event_clr(ufd, &pre_tcp->ufd_info, POLLOUT);

    /* check that tag has been updated */
    assert_true(ufd->ufd_tag[idx] != tag);

    /* and check that the entry has been removed */
    idx = (&pre_tcp->ufd_info)->pollfd_idx;
    assert_true(idx == -1);

    /* clean up ufd and disable threaded mode */
    test_utils_cleanup_ufd_threaded(ufd);

    /* check that the ufd tag array has been released */
    assert_true(ufd->ufd_tag == NULL);
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


/**
 * \brief Test that a UFD array element is not processed if it has been updated
 *
 * Given: A multi-threaded environment
 * When: updating the global pollfd array while reading/writing
 * Then: an array element that has been changed will not be processed for read
 * since the thread-local copy has become outdated
 */
void test_ufd_do_not_read_when_array_is_updated(void **state)
{
    /* initialize and do checks with the global ufd object in threaded mode */
    ufd_t *ufd = test_utils_init_ufd_threaded(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* This test adds two ufd_info objects to the global ufd array:
     * (1) pre_tcp->ufd_info (the ufd_info attached to the precon object)
     * (2) global_ufd_info (the ufd object accessible by the callback functions)
     */

    /* (1) set the ufd info of the precon */
    ufd_event_set(&pscom.ufd, &pre_tcp->ufd_info, POLLIN | POLLOUT);
    /* check that it has been added at the first position of the array */
    assert_true(pscom.ufd.ufd_pollfd_info[0] == &pre_tcp->ufd_info);
    /* set can_read() so that the global info object is removed from array */
    pre_tcp->ufd_info.can_read = &remove_global_pollfd_info_from_ufd_array;
    expect_function_call_any(remove_global_pollfd_info_from_ufd_array);
    /* set can_write() so that the global ufd info is added again to array */
    pre_tcp->ufd_info.can_write = &add_global_pollfd_info_to_ufd_array;
    expect_function_call_any(add_global_pollfd_info_to_ufd_array);

    /* (2) add and set the global ufd info object */
    ufd_add(&pscom.ufd, &global_ufd_info);
    ufd_event_set(&pscom.ufd, &global_ufd_info, POLLIN);
    /* check that it has been added at the second position of the array */
    assert_true(pscom.ufd.ufd_pollfd_info[1] == &global_ufd_info);
    /* implicit test: check_can_read() is NOT called */
    global_ufd_info.can_read = &check_can_read;

    /* let poll report POLLIN | POLLOUT for both fds */
    will_return(__wrap_poll, (POLLIN | POLLOUT));
    will_return(__wrap_poll, 2);

    /* Do the ufd processing: While the first object is being processed,
     * `can_read()` removes the second object, whereas the subsequent
     * `can_write()` adds it back again. However, when the second object
     * is then processed afterwards, `can_read()` must not be called here
     * because even if the pointer hasn't changed, the array has been updated.
     */
    pscom_progress(0);

    /* implicit test: check_can_read() is NOT called */

    /* check that the order of the two objects in the array is still the same */
    assert_true(pscom.ufd.ufd_pollfd_info[0] == &pre_tcp->ufd_info);
    assert_true(pscom.ufd.ufd_pollfd_info[1] == &global_ufd_info);

    /* clean up ufd and disable threaded mode */
    test_utils_cleanup_ufd_threaded(ufd);
}


/**
 * \brief Test that a UFD array element is not processed if it has been updated
 *
 * Given: A multi-threaded environment
 * When: updating the global pollfd array while reading/writing
 * Then: an array element that has been changed will not be processed for write
 * since the thread-local copy has become outdated
 */
void test_ufd_do_not_write_when_array_is_updated(void **state)
{
    /* initialize and do checks with the global ufd object in threaded mode */
    ufd_t *ufd = test_utils_init_ufd_threaded(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_precon_t *precon      = (pscom_precon_t *)(*state);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* This test adds three ufd_info objects to the global ufd array:
     * (1) global_ufd_info (the ufd object accessible by the callback functions)
     * (2) pre_tcp->ufd_info (the ufd_info attached to the precon object)
     * (3) ufd_info_dummy (a function-local ufd info object as a dummy)
     */

    ufd_info_t ufd_info_dummy;

    /* (1) add and set the global ufd info object */
    ufd_add(&pscom.ufd, &global_ufd_info);
    ufd_event_set(&pscom.ufd, &global_ufd_info, POLLIN | POLLOUT);
    /* check that it has been added at the beginning of the array */
    assert_true(pscom.ufd.ufd_pollfd_info[0] == &global_ufd_info);
    /* set can_read() so that this object is removed again from the array */
    global_ufd_info.can_read = &remove_global_pollfd_info_from_ufd_array;
    expect_function_call_any(remove_global_pollfd_info_from_ufd_array);
    /* implicit test: check_can_write() is NOT called */
    global_ufd_info.can_write = &check_can_write;

    /* (2) set the ufd info of the precon */
    ufd_event_set(&pscom.ufd, &pre_tcp->ufd_info, POLLIN | POLLOUT);
    /* check that it has been added at the second position of the array */
    assert_true(pscom.ufd.ufd_pollfd_info[1] == &pre_tcp->ufd_info);
    /* check that can_read() is still being called */
    pre_tcp->ufd_info.can_read = &check_can_read;
    expect_function_call_any(check_can_read);
    /* set can_write() so that the global ufd info is added again */
    pre_tcp->ufd_info.can_write = &add_global_pollfd_info_to_ufd_array;
    expect_function_call_any(add_global_pollfd_info_to_ufd_array);

    /* (3) add and set the dummy info object */
    ufd_add(&pscom.ufd, &ufd_info_dummy);
    /* check for POLLOUT only to see if object is being processed */
    ufd_event_set(&pscom.ufd, &ufd_info_dummy, POLLOUT);
    /* check that it has been added at the third position */
    assert_true(pscom.ufd.ufd_pollfd_info[2] == &ufd_info_dummy);
    /* implicit test: check_can_write() is NOT called */
    ufd_info_dummy.can_write = &check_can_write;

    /* let poll report POLLIN | POLLOUT for all three fds */
    will_return(__wrap_poll, (POLLIN | POLLOUT));
    will_return(__wrap_poll, 3);

    /* check again that the array is set up correctly */
    assert_true(pscom.ufd.n_ufd_pollfd == 3);
    assert_true(pscom.ufd.ufd_pollfd_info[0] == &global_ufd_info);
    assert_true(pscom.ufd.ufd_pollfd_info[1] == &pre_tcp->ufd_info);
    assert_true(pscom.ufd.ufd_pollfd_info[2] == &ufd_info_dummy);

    /* Do the ufd processing: While `can_read()` is called on the first
     * ufd info object in the array (index 0), this object gets removed
     * from the array and the last of the three elements is moved to this
     * position instead. When the second element is then processed afterwards,
     * the removed object is added back by this `can_read()` method -- now
     * becoming the object at the third position in the array. However, during
     * processing of this third element, the `can_write()` operation must not
     * be called because it has been moved and the array has been updated.
     */
    pscom_progress(0);

    /* implicit test: check_can_write() is NOT called */
    /* because the array entry/index of global_pollfd_info has been changed */

    /* check that the objects are located in the array in the right order */
    assert_true(pscom.ufd.ufd_pollfd_info[0] == &ufd_info_dummy);
    assert_true(pscom.ufd.ufd_pollfd_info[1] == &pre_tcp->ufd_info);
    assert_true(pscom.ufd.ufd_pollfd_info[2] == &global_ufd_info);

    /* clean up ufd and disable threaded mode */
    test_utils_cleanup_ufd_threaded(ufd);
}
