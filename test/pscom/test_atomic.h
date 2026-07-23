/*
 * ParaStation
 *
 * Copyright (C) 2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _TEST_ATOMIC_H_
#define _TEST_ATOMIC_H_

void test_atomic_cacheline_size(void **state);
void test_atomic_load_store(void **state);
void test_atomic_fetch_add_sub(void **state);
void test_atomic_swap(void **state);
void test_atomic_cas(void **state);

#endif /* _TEST_ATOMIC_H_ */
