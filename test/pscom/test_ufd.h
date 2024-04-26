/*
 * ParaStation
 *
 * Copyright (C) 2023-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _TEST_UFD_H_
#define _TEST_UFD_H_

void test_do_not_write_when_con_refused(void **state);
void test_do_not_write_con_reset_by_peer(void **state);
void test_do_not_write_when_pollfd_is_cleared(void **state);
void test_write_when_pollfd_is_not_updated(void **state);
void test_do_not_read_when_stopped_precon(void **state);
void test_do_not_progress_when_destroyed_precon(void **state);
void test_read_and_write_normally(void **state);
void test_only_write_when_no_pollin(void **state);
void test_do_not_read_if_global_ufd_is_gone(void **state);
void test_do_not_write_if_global_ufd_is_gone(void **state);

#endif /* _TEST_UFD_H_ */
