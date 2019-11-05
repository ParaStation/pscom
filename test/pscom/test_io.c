#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>

#include "pscom_io.h"
#include "pscom_priv.h"
#include "pscom_util.h"
#include "pscom_req.h"

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
