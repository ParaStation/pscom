/*
 * ParaStation
 *
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _TEST_ENV_H_
#define _TEST_ENV_H_

void test_env_table_parse_empty_table(void **state);
void test_env_table_parse_null_table(void **state);
void test_env_table_parse_null_var(void **state);
void test_env_table_parse_null_parser(void **state);
void test_env_table_parse_single_uint_default(void **state);
void test_env_table_parse_single_uint(void **state);
void test_env_table_parse_single_uint_inf(void **state);
void test_env_table_parse_single_uint_auto(void **state);
void test_env_table_parse_single_uint_typo(void **state);
void test_env_table_parse_single_int_default(void **state);
void test_env_table_parse_single_int(void **state);
void test_env_table_parse_single_int_empty(void **state);
void test_env_table_parse_single_size_t_default(void **state);
void test_env_table_parse_single_size_t(void **state);
void test_env_table_parse_single_size_t_typo(void **state);
void test_env_table_parse_single_str_default(void **state);
void test_env_table_parse_single_str(void **state);
void test_env_table_parse_single_dir_default(void **state);
void test_env_table_parse_single_dir(void **state);
void test_env_table_parse_multi_entry(void **state);
void test_env_table_parse_multi_entry_failing_entry(void **state);
void test_env_table_parse_single_size_t_parent_set(void **state);
void test_env_table_parse_single_size_t_parent_set_and_env_set(void **state);

void test_env_parser_get_int(void **state);
void test_env_parser_get_uint(void **state);
void test_env_parser_get_uint_inf(void **state);
void test_env_parser_get_uint_auto(void **state);
void test_env_parser_get_size_t(void **state);
void test_env_parser_get_str(void **state);
void test_env_parser_get_dir(void **state);

void test_env_table_register_simple(void **state);
void test_env_table_register_no_mem(void **state);

void test_env_table_register_and_parse_no_mem(void **state);
void test_env_table_register_and_parse_simple(void **state);
void test_env_table_register_and_parse_env_var(void **state);

void test_env_clear_table_list_empty(void **state);
void test_env_clear_table_list_filled(void **state);
#endif /* _TEST_ENV_H_ */
