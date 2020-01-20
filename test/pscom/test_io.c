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
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>

#include "pscom_con.h"
#include "pscom_io.h"
#include "pscom_priv.h"
#include "pscom_queues.h"
#include "pscom_util.h"
#include "pscom_req.h"

////////////////////////////////////////////////////////////////////////////////
/// pscom_post_recv()
////////////////////////////////////////////////////////////////////////////////

typedef enum { TESTCON_STATE_CLOSED=0, TESTCON_STATE_OPENED } connection_state_t;
typedef enum { TESTCON_OP_NOP=0, TESTCON_OP_STOP_READ, TESTCON_OP_START_READ } connection_action_t;

connection_state_t transition_table[2][3] = {
	{TESTCON_STATE_CLOSED, TESTCON_STATE_CLOSED, TESTCON_STATE_OPENED},
	{TESTCON_STATE_OPENED, TESTCON_STATE_CLOSED, TESTCON_STATE_OPENED}
};

static
int connection_state(connection_action_t action)
{
	static connection_state_t connection_state = TESTCON_STATE_CLOSED;
	connection_state_t old_state = connection_state;

	connection_state = transition_table[connection_state][action];

	return old_state;
}

static
void check_read_start_called(pscom_con_t *con)
{
	function_called();
	check_expected(con);

	connection_state(TESTCON_OP_START_READ);
}

static
void check_read_stop_called(pscom_con_t *con)
{
	function_called();
	check_expected(con);

	connection_state(TESTCON_OP_STOP_READ);
}

/**
 * \brief Test pscom_post_recv() for partially received message
 *
 * Given: A partially received message in a generated request
 * When: pscom_post_recv() is called
 * Then: the request should be merged properly and the connection should be
 *       open for reading.
 */
void test_post_recv_partial_genreq(void **state)
{
	/* obtain the dummy connection from the test setup */
	pscom_con_t *recv_con =  (pscom_con_t*)(*state);

	/* create generated requests and enqueue to the list of net requests */
	pscom_req_t *gen_req = pscom_req_create(0, 100);
	gen_req->pub.connection = &recv_con->pub;
	_pscom_net_recvq_user_enq(recv_con, gen_req);

	/* set the read_start()/read_stop() functions */
	recv_con->read_start = &check_read_start_called;
	recv_con->read_stop = &check_read_stop_called;

	/*
	 * set the appropriate request state:
	 * -> generated requests
	 * -> IO has been started
	 */
	gen_req->pub.state = PSCOM_REQ_STATE_GRECV_REQUEST;
	gen_req->pub.state |= PSCOM_REQ_STATE_IO_STARTED;

	/* the request shall be the current request of the connection */
	recv_con->in.req = gen_req;

	/* create the receive request */
	pscom_request_t *recv_req = pscom_request_create(0, 100);
	recv_req->connection = &recv_con->pub;

	/* read_start() should be called at least once */
	expect_function_call_any(check_read_start_called);
	expect_value(check_read_start_called, con, recv_con);

	/* post the actual receive request */
	pscom_post_recv(recv_req);

	/*
	 * read_start() should be called lastly
	 * TODO: check connection state, once this is available within the pscom
	 */
	assert_int_equal(connection_state(TESTCON_OP_NOP), TESTCON_STATE_OPENED);
}
////////////////////////////////////////////////////////////////////////////////
/// pscom_req_prepare_send_pending()
////////////////////////////////////////////////////////////////////////////////
/**
 * \brief Test pscom_req_prepare_send_pending() for a regular user request
 *
 * Given: A send request
 * When: pscom_req_prepare_send_pending() is called
 * Then: the request is prepared for sending
 */
void test_req_prepare_send_pending_valid_send_request(void **state)
{
	(void) state;

	const uint16_t xheader_len = 42;
	const size_t data_len = 1024;
	pscom_req_t req = {
		.magic = MAGIC_REQUEST,
		.pub.xheader_len = xheader_len,
		.pub.data_len = data_len,
		.pub.data = (void*)0x42,
	};

	pscom_req_prepare_send_pending(&req, PSCOM_MSGTYPE_USER, 0);

	assert_int_equal(req.pub.header.msg_type, PSCOM_MSGTYPE_USER);
	assert_int_equal(req.pub.header.xheader_len, xheader_len);
	assert_int_equal(req.pub.header.data_len, data_len);

	assert_ptr_equal(req.cur_header.iov_base, &req.pub.header);
	assert_ptr_equal(req.cur_data.iov_base, req.pub.data);
	assert_int_equal(req.cur_header.iov_len, sizeof(pscom_header_net_t)+req.pub.xheader_len);
	assert_int_equal(req.cur_data.iov_len, req.pub.data_len);

	assert_int_equal(req.skip, 0);
}

/**
 * \brief Test pscom_req_prepare_send_pending() very long data lengths
 *
 * Given: A send request with a data_len exceeding  PSCOM_DATA_LEN_MASK
 * When: pscom_req_prepare_send_pending() is called
 * Then: the data_len is truncated to PSCOM_DATA_LEN_MASK in the network header
 *
 * TODO: What is the purpose of this behavior?
 */
void test_req_prepare_send_pending_truncate_data_len(void **state)
{
	(void) state;

	const uint16_t xheader_len = 42;
	const size_t data_len = PSCOM_DATA_LEN_MASK + 1024;
	pscom_req_t req = {
		.magic = MAGIC_REQUEST,
		.pub.data_len = data_len,
	};

	pscom_req_prepare_send_pending(&req, PSCOM_MSGTYPE_USER, 0);

	assert_true(req.pub.header.data_len <= PSCOM_DATA_LEN_MASK);
}
