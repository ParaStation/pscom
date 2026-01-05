/*
 * ParaStation
 *
 * Copyright (C) 2025-2026 ParTec AG, Munich
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

#include <sys/types.h>

#include "pscom.h"
#include "pscom_priv.h"
#include "pscom_precon.h"

#include "list.h"
#include "pscom_precon_rrc.h"
#include "pscom_ufd.h"

#include <stdlib.h>
#include <errno.h>

#include "test_rrcomm.h"
#include "util/test_utils_provider.h"

#include "pscom_precon_rrc.c" // check some variables.

/**
 * \brief Test parsing `ep_str`
 *
 * Given: `ep_str` with a correct format
 * When: `parse_ep_info` is called
 * Then: parse and set the ep information
 */
void test_rrc_parse_ep_str(void **state)
{
    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* re-init provider pointer with rrcomm */
    setup_dummy_provider("rrcomm");

    pscom_precon_provider_t *provider_rrc = pscom_precon_provider_lookup("rrcom"
                                                                         "m");
    assert_ptr_equal(pscom_precon_provider, provider_rrc);

    pscom_err_t res;

    /* obtain the dummy connection from the test setup */
    pscom_con_t *con = (pscom_con_t *)(*state);

    /* parse the ep str rank:jobid:sockid:name of an inter-job sock */
    res = pscom_precon_parse_ep_info("111:222:333:sock",
                                     &con->pub.remote_con_info);

    assert_true(res == PSCOM_SUCCESS);
    assert_true(con->pub.remote_con_info.rank == 111);
    assert_true(con->pub.remote_con_info.rrcomm.jobid == 222);
    assert_true(con->pub.remote_con_info.rrcomm.remote_sockid == 333);

    /* parse invalid ep str rank:jobid:sockid:name of an inter-job sock */
    res = pscom_precon_parse_ep_info("111asd:222:333:sock",
                                     &con->pub.remote_con_info);

    assert_true(res == PSCOM_ERR_STDERROR);

    /* parse the ep str rank:jobid:sockid:name of an intra-job sock */
    con->pub.remote_con_info.rank = 888; // set rank to 888, rank must be set
                                         // for intra-job sock
    res = pscom_precon_parse_ep_info(NULL, &con->pub.remote_con_info);

    assert_true(res == PSCOM_SUCCESS);
    assert_true(con->pub.remote_con_info.rank == 888);
    assert_true(con->pub.remote_con_info.rrcomm.jobid == 88);
    assert_true(con->pub.remote_con_info.rrcomm.remote_sockid == 0);

    /* check if precon is freed */
    assert_true(list_empty(&pscom_precon_provider->precon_list));

    /* clean up ufd */
    ufd_cleanup(&pscom.ufd);
}


/**
 * \brief Test rrc_recvx
 *
 * Given: recv a message from RRC client
 * When: `pscom_precon_do_read_rrc` is called
 * Then: recv and handle message from `rrc_recvx`
 */
void test_rrc_recv_msg(void **state)
{
    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* re-init provider pointer with rrcomm */
    setup_dummy_provider("rrcomm");

    pscom_precon_provider_t *provider_rrc = pscom_precon_provider_lookup("rrcom"
                                                                         "m");
    assert_ptr_equal(pscom_precon_provider, provider_rrc);

    /* obtain the dummy connection from the test setup */
    pscom_con_t *con = (pscom_con_t *)(*state);

    /* create a new precon */
    pscom_precon_t *precon      = pscom_precon_create(con);
    pscom_precon_rrc_t *pre_rrc = (pscom_precon_rrc_t *)&precon->precon_data;

    /* check local jobid */
    assert_true(pre_rrc->local_jobid == 88);

    /* the return value here is not used */
    will_return(__wrap_RRC_recvX, 11);

    /* recv a message with correct buffer */
    pscom_precon_do_read_rrc(&pscom.ufd, NULL); // ufd and ufd_info is not used

    /* destroy precon */
    pscom_precon_destroy(precon);

    /* check if precon is freed */
    assert_true(list_empty(&pscom_precon_provider->precon_list));

    /* clean up ufd */
    ufd_cleanup(&pscom.ufd);
}


/**
 * \brief Test resend signal
 *
 * Given: recv a message from RRC client
 * When: `pscom_precon_do_read_rrc` is called
 * Then: the resend signal is triggered
 */
void test_rrc_resend_signal(void **state)
{
    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* re-init provider pointer with rrcomm */
    setup_dummy_provider("rrcomm");

    pscom_precon_provider_t *provider_rrc = pscom_precon_provider_lookup("rrcom"
                                                                         "m");
    assert_ptr_equal(pscom_precon_provider, provider_rrc);

    /* obtain the dummy connection from the test setup */
    pscom_con_t *con = (pscom_con_t *)(*state);

    /* create a new precon */
    pscom_precon_t *precon      = pscom_precon_create(con);
    pscom_precon_rrc_t *pre_rrc = (pscom_precon_rrc_t *)&precon->precon_data;


    /* check local jobid */
    assert_true(pre_rrc->local_jobid == 88);

    /* set the dest and jobid to match the return values from RRC_recvx */
    con->pub.remote_con_info.rank         = 1;
    con->pub.remote_con_info.rrcomm.jobid = 1;

    /* set errno and return value of rrc_recv to trigger resend */
    errno = 0;
    will_return(__wrap_RRC_recvX, -1);

    /* recv a resend signal */
    pscom_precon_do_read_rrc(&pscom.ufd, NULL); // ufd and ufd_info is not used

    /* a resend request is added to the resend list */
    assert_true(!list_empty(&resend_requests));
    assert_true(resend_count == 1);

    /* check the resend information set in the mocking function */
    struct list_head *pos, *next;
    list_for_each_safe (pos, next, &resend_requests) {
        pscom_resend_request_t *resend = list_entry(pos, pscom_resend_request_t,
                                                    next);
        assert_true(resend->dest == 1);
        assert_true(resend->jobid == 1);
        assert_true(resend->msg_type == 0);

        /* Remove this resend from the list as it has been already resent */
        list_del(&resend->next);
        resend_count--;
        free(resend);
    }

    /* no resend check */
    assert_true(list_empty(&resend_requests));
    assert_true(resend_count == 0);

    /* destroy precon */
    pscom_precon_destroy(precon);

    /* check if precon is freed */
    assert_true(list_empty(&pscom_precon_provider->precon_list));

    /* clean up ufd */
    ufd_cleanup(&pscom.ufd);
}


/**
 * \brief Test rrc_sendx
 *
 * Given: recv a message from RRC client
 * When: `pscom_precon_send` is called
 * Then: check different return value from `rrc_sendx`
 */
void test_rrc_send_msg(void **state)
{
    /* Start ufd */
    ufd_init(&pscom.ufd);

    /* re-init provider pointer with rrcomm */
    setup_dummy_provider("rrcomm");

    pscom_precon_provider_t *provider_rrc = pscom_precon_provider_lookup("rrcom"
                                                                         "m");
    assert_ptr_equal(pscom_precon_provider, provider_rrc);

    /* obtain the dummy connection from the test setup */
    pscom_con_t *con = (pscom_con_t *)(*state);

    /* create a new precon */
    pscom_precon_t *precon = pscom_precon_create(con);

    ssize_t msg_size = (ssize_t)sizeof(pscom_info_rrc_t);
    /* set correct return value */
    will_return(__wrap_RRC_sendX, msg_size);

    pscom_err_t ret = pscom_precon_send(precon, 0, NULL, 0);
    assert_true(ret == PSCOM_SUCCESS);

    /* let an error return */
    will_return(__wrap_RRC_sendX, -1);

    ret = pscom_precon_send(precon, 0, NULL, 0);
    assert_true(ret == PSCOM_ERR_STDERROR);

    /* destroy precon */
    pscom_precon_destroy(precon);

    /* check if precon is freed */
    assert_true(list_empty(&pscom_precon_provider->precon_list));

    /* clean up ufd */
    ufd_cleanup(&pscom.ufd);
}
