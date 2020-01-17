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

#ifndef _TEST_IO_H_
#define _TEST_IO_H_
void test_post_recv_partial_genreq(void **state);
void test_req_prepare_send_pending_valid_send_request(void **state);
void test_req_prepare_send_pending_truncate_data_len(void **state);
#endif /* _TEST_IO_H_ */
