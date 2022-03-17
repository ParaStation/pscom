/*
 * ParaStation
 *
 * Copyright (C) 2022      ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _TEST_PLUGIN_H_
#define _TEST_PLUGIN_H_

void test_load_plugin_lib(void **state);
void test_load_plugin_lib_invalid_version(void **state);
void test_load_plugin_lib_invalid_name(void **state);
void test_load_plugin_lib_invalid_path(void **state);

#endif /* _TEST_PLUGIN_H_ */
