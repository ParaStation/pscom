/*
 * ParaStation
 *
 * Copyright (C) 2021-2025 ParTec AG, Munich
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "mocks/misc_mocks.h"

#include "list.h"
#include "pscom.h"
#include "pscom_env.h"
#include "pscom_priv.h"

#include "util/test_utils_env.h"


////////////////////////////////////////////////////////////////////////////////
/// pscom_env_table_parse()
////////////////////////////////////////////////////////////////////////////////
/**
 * @brief Test pscom_env_table_parse() for an empty table
 *
 * Given: An empty environment table
 * When: pscom_env_table_parse() is called
 * Then: it should exit without error.
 */
void test_env_table_parse_empty_table(void **state)
{
    pscom_env_table_entry_t env_table[] = {{0}};

    pscom_err_t ret = pscom_env_table_parse(env_table, NULL, NULL, NULL);

    assert_true(ret == PSCOM_SUCCESS);
}


/**
 * @brief Test pscom_env_table_parse() for env_table == NULL
 *
 * Given: A NULL passed as env_table
 * When: pscom_env_table_parse() is called
 * Then: it should exit with PSCOM_ERR_INVALID.
 */
void test_env_table_parse_null_table(void **state)
{
    pscom_err_t ret = pscom_env_table_parse(NULL, NULL, NULL, NULL);

    assert_true(ret == PSCOM_ERR_INVALID);
}

/**
 * @brief Test pscom_env_table_parse() for NULL pointer to config variable
 *
 * Given: A table entry containing a NULL pointer to the configuration variable
 * When: pscom_env_table_parse() is called
 * Then: it should exit with PSCOM_ERR_INVALID.
 */
void test_env_table_parse_null_var(void **state)
{
    pscom_env_table_entry_t env_table[] = {
        {"TEST_VAR", "3", NULL, NULL, 0, PSCOM_ENV_PARSER_UINT},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table, NULL, NULL, NULL);

    assert_true(ret == PSCOM_ERR_INVALID);
}


/**
 * @brief Test pscom_env_table_parse() for NULL pointer to the parser
 *
 * Given: A table entry containing a NULL pointer to the parser
 * When: pscom_env_table_parse() is called
 * Then: it should exit with PSCOM_ERR_INVALID.
 */
void test_env_table_parse_null_parser(void **state)
{
    char *test_var_one;
    int test_var_two = 0;

    pscom_env_table_entry_t env_table[] = {
        {"TEST_VAR_ONE", "string", NULL, &test_var_one, 0, PSCOM_ENV_PARSER_STR},

        {"TEST_VAR_TWO", "-42", NULL, &test_var_two, 0, {NULL, NULL}},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table, NULL, NULL, NULL);

    assert_true(ret == PSCOM_ERR_INVALID);
}


/**
 * @brief Test pscom_env_table_parse() for a single entry uint table
 *
 * Given: An environment table with a single unsigned integer entry
 * When: the according environment variable is not set
 * Then: pscom_env_table_parse() should update the configuration parameter
 *       accordingly.
 */
void test_env_table_parse_single_uint_default(void **state)
{
    unsigned int test_var = 0;

    pscom_env_table_entry_t env_table_uint[] = {
        {"TEST_VAR", "3", NULL, &test_var, 0, PSCOM_ENV_PARSER_UINT},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_uint, NULL, NULL, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_int_equal(test_var, 3);
}


/**
 * @brief Test pscom_env_table_parse() for a single entry uint table
 *
 * Given: An environment table with a single unsigned integer entry
 * When: the according environment variable is set
 * Then: pscom_env_table_parse() should update the configuration parameter
 *       with the value from the environment variable accordingly.
 */
void test_env_table_parse_single_uint(void **state)
{
    unsigned int test_var = 0;
    const char *env_var   = ((env_var_backup_t *)(*state))->name;

    /* set the environment variable */
    setenv(env_var, "42", 1);

    pscom_env_table_entry_t env_table_uint[] = {
        {env_var, "3", NULL, &test_var, 0, PSCOM_ENV_PARSER_UINT},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_uint, NULL, NULL, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_int_equal(test_var, 42);
}


/**
 * @brief Test pscom_env_table_parse() for 'inf' unsigned integer entry
 *
 * Given: An environment table with a single unsigned integer entry that is set
 *        to 'inf'
 * When:  pscom_env_table_parse() is called
 * Then:  it should update the configuration parameter to PSCOM_ENV_UINT_INF.
 */
void test_env_table_parse_single_uint_inf(void **state)
{
    unsigned int test_var = 0;
    const char *env_var   = ((env_var_backup_t *)(*state))->name;

    pscom_env_table_entry_t env_table_uint[] = {
        {env_var, PSCOM_ENV_UINT_INF_STR, NULL, &test_var, 0,
         PSCOM_ENV_PARSER_UINT},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_uint, NULL, NULL, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_int_equal(test_var, PSCOM_ENV_UINT_INF);
}


/**
 * @brief Test pscom_env_table_parse() for 'auto' unsigned integer entry
 *
 * Given: An environment table with a single unsigned integer entry that is set
 *        to 'auto'
 * When:  pscom_env_table_parse() is called
 * Then:  it should update the configuration parameter to PSCOM_ENV_UINT_AUTO.
 */
void test_env_table_parse_single_uint_auto(void **state)
{
    unsigned int test_var = 0;
    const char *env_var   = ((env_var_backup_t *)(*state))->name;

    pscom_env_table_entry_t env_table_uint[] = {
        {env_var, PSCOM_ENV_UINT_AUTO_STR, NULL, &test_var, 0,
         PSCOM_ENV_PARSER_UINT},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_uint, NULL, NULL, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_int_equal(test_var, PSCOM_ENV_UINT_AUTO);
}


/**
 * @brief Test pscom_env_table_parse() for unsigned integer with a typo
 *
 * Given: An environment table with a single unsigned integer entry
 * When: the according environment variable is set to 'infi'
 * Then: pscom_env_table_parse() should return with PSCOM_ERR_INVALID and set
 *       the correpsonding configuration parameter to its default
 */
void test_env_table_parse_single_uint_typo(void **state)
{
    unsigned int test_var = 0;
    const char *env_var   = ((env_var_backup_t *)(*state))->name;

    /* set the environment variable */
    setenv(env_var, "infi", 1);

    pscom_env_table_entry_t env_table_uint[] = {
        {env_var, "3", NULL, &test_var, 0, PSCOM_ENV_PARSER_UINT},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_uint, NULL, NULL, NULL);
    assert_true(ret == PSCOM_ERR_INVALID);

    assert_int_equal(test_var, 3);
}


/**
 * @brief Test pscom_env_table_parse() for a single entry int table
 *
 * Given: An environment table with a single integer entry
 * When: the according environment variable is not set
 * Then: pscom_env_table_parse() should update the configuration parameter
 *       accordingly.
 */
void test_env_table_parse_single_int_default(void **state)
{
    int test_var        = 0;
    const char *env_var = ((env_var_backup_t *)(*state))->name;

    pscom_env_table_entry_t env_table_int[] = {
        {env_var, "-1", NULL, &test_var, 0, PSCOM_ENV_PARSER_INT},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_int, NULL, NULL, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_int_equal(test_var, -1);
}


/**
 * @brief Test pscom_env_table_parse() for a single entry int table
 *
 * Given: An environment table with a single integer entry
 * When: the according environment variable is set
 * Then: pscom_env_table_parse() should update the configuration parameter
 *       with the value from the environment variable accordingly.
 */
void test_env_table_parse_single_int(void **state)
{
    int test_var        = 0;
    const char *env_var = ((env_var_backup_t *)(*state))->name;

    /* set the environment variable */
    setenv(env_var, "13", 1);

    pscom_env_table_entry_t env_table_int[] = {
        {env_var, "3", NULL, &test_var, 0, PSCOM_ENV_PARSER_INT},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_int, NULL, NULL, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_int_equal(test_var, 13);
}


/**
 * @brief Test pscom_env_table_parse() for a int table with empty input string
 *
 * Given: An environment table with a single integer entry
 * When: the according environment variable is set to an empty string
 * Then: pscom_env_table_parse() should return with PSCOM_ERR_INVALID and leave
 *       the correpsonding configuration parameter untouched
 */
void test_env_table_parse_single_int_empty(void **state)
{
    int test_var        = 0;
    const char *env_var = ((env_var_backup_t *)(*state))->name;

    /* set the environment variable */
    setenv(env_var, "", 1);

    pscom_env_table_entry_t env_table_int[] = {
        {env_var, "3", NULL, &test_var, 0, PSCOM_ENV_PARSER_INT},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_int, NULL, NULL, NULL);
    assert_true(ret == PSCOM_ERR_INVALID);

    assert_int_equal(test_var, 3);
}


/**
 * @brief Test pscom_env_table_parse() for a single entry size_t table
 *
 * Given: An environment table with a single size_t entry
 * When: the according environment variable is not set
 * Then: pscom_env_table_parse() should update the configuration parameter
 *       accordingly.
 */
void test_env_table_parse_single_size_t_default(void **state)
{
    size_t test_var = 0;

    pscom_env_table_entry_t env_table_size_t[] = {
        {"TEST_VAR", "8589934592", NULL, &test_var, 0, PSCOM_ENV_PARSER_SIZE_T},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_size_t, NULL, NULL, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_int_equal(test_var, 8589934592);
}


/**
 * @brief Test pscom_env_table_parse() for a single entry size_t table
 *
 * Given: An environment table with a single size_t entry
 * When: the according environment variable is set
 * Then: pscom_env_table_parse() should update the configuration parameter
 *       with the value from the environment variable accordingly.
 */
void test_env_table_parse_single_size_t(void **state)
{
    size_t test_var     = 0;
    const char *env_var = ((env_var_backup_t *)(*state))->name;

    /* set the environment variable */
    setenv(env_var, "8589934592", 1);

    pscom_env_table_entry_t env_table_size_t[] = {
        {env_var, "3", NULL, &test_var, 0, PSCOM_ENV_PARSER_SIZE_T},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_size_t, NULL, NULL, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_int_equal(test_var, 8589934592);
}


/**
 * @brief Test pscom_env_table_parse() for a size_t table with wrong input
 *
 * Given: An environment table with a single size_t entry
 * When: the according environment variable is set to a string with a typo
 * Then: pscom_env_table_parse() should return with PSCOM_ERR_INVALID and leave
 *       the correpsonding configuration parameter untouched
 */
void test_env_table_parse_single_size_t_typo(void **state)
{
    size_t test_var     = 0;
    const char *env_var = ((env_var_backup_t *)(*state))->name;

    /* set the environment variable */
    setenv(env_var, "I100B", 1);

    pscom_env_table_entry_t env_table_size_t[] = {
        {env_var, "3", NULL, &test_var, 0, PSCOM_ENV_PARSER_SIZE_T},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_size_t, NULL, NULL, NULL);
    assert_true(ret == PSCOM_ERR_INVALID);

    assert_int_equal(test_var, 3);
}


/**
 * @brief Test pscom_env_table_parse() for a single entry string table
 *
 * Given: An environment table with a single string type entry
 * When: the according environment variable is not set
 * Then: pscom_env_table_parse() should update the configuration parameter
 *       accordingly.
 */
void test_env_table_parse_single_str_default(void **state)
{
    char *test_var = "";

    pscom_env_table_entry_t env_table_str[] = {
        {"TEST_VAR", "testval", NULL, &test_var, 0, PSCOM_ENV_PARSER_STR},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_str, NULL, NULL, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_string_equal(test_var, "testval");
}


/**
 * @brief Test pscom_env_table_parse() for a single entry str table
 *
 * Given: An environment table with a single string entry
 * When: the according environment variable is set
 * Then: pscom_env_table_parse() should update the configuration parameter
 *       with the value from the environment variable accordingly.
 */
void test_env_table_parse_single_str(void **state)
{
    char *test_var      = "Hello";
    const char *env_var = ((env_var_backup_t *)(*state))->name;

    /* set the environment variable */
    setenv(env_var, "World", 1);

    pscom_env_table_entry_t env_table_str[] = {
        {env_var, "dummy text", NULL, &test_var, 0, PSCOM_ENV_PARSER_STR},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_str, NULL, NULL, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_string_equal(test_var, "World");
}


/**
 * @brief Test pscom_env_table_parse() for a single entry directory table
 *
 * Given: An environment table with a single directory type entry
 * When: the according environment variable is not set
 * Then: pscom_env_table_parse() should update the configuration parameter
 *       accordingly (incl. '/' termination).
 */
void test_env_table_parse_single_dir_default(void **state)
{
    char *test_var = "";

    pscom_env_table_entry_t env_table_dir[] = {
        {"TEST_VAR", "/path/to/testdir/", NULL, &test_var, 0,
         PSCOM_ENV_PARSER_DIR},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_dir, NULL, NULL, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_string_equal(test_var, "/path/to/testdir/");
}


/**
 * @brief Test pscom_env_table_parse() for a single entry directory table
 *
 * Given: An environment table with a single directory entry
 * When: the according environment variable is set
 * Then: pscom_env_table_parse() should update the configuration parameter
 *       with the value from the environment variable accordingly (incl.
 *       termination with '/').
 */
void test_env_table_parse_single_dir(void **state)
{
    char *test_var      = "/path/to/hello";
    const char *env_var = ((env_var_backup_t *)(*state))->name;

    /* set the environment variable */
    setenv(env_var, "/path/to/world", 1);

    pscom_env_table_entry_t env_table_dir[] = {
        {env_var, "dummy text", NULL, &test_var, 0, PSCOM_ENV_PARSER_DIR},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_dir, NULL, NULL, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_string_equal(test_var, "/path/to/world/");
}


/**
 * @brief Test pscom_env_table_parse() for a multi entry mixed type table
 *
 * Given: An environment table with a multiple entries of different type
 * When: pscom_env_table_parse is called()
 * Then: the specified configuration parameters should be updated with the
 * 	 default values or from the environment accordingly.
 */
void test_env_table_parse_multi_entry(void **state)
{
    int test_var_int                 = -1;
    char *test_var_str               = "oldstring";
    unsigned int test_var_uint       = 1001;
    env_var_backup_t *env_var_backup = (env_var_backup_t *)(*state);

    /* set the second environment variable */
    setenv(env_var_backup[2].name, "World", 1);

    pscom_env_table_entry_t env_table[] = {
        {env_var_backup[0].name, "-42", NULL, &test_var_int, 0,
         PSCOM_ENV_PARSER_INT},

        {env_var_backup[1].name, "13", NULL, &test_var_uint, 0,
         PSCOM_ENV_PARSER_UINT},

        {env_var_backup[2].name, "wrong string", NULL, &test_var_str, 0,
         PSCOM_ENV_PARSER_STR},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table, NULL, NULL, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_int_equal(test_var_int, -42);
    assert_int_equal(test_var_uint, 13);
    assert_string_equal(test_var_str, "World");
}


int parser_set_not_implemented(void *env_entry, const char *config_val)
{
    return PSCOM_NOT_IMPLEMENTED;
}

/**
 * @brief Test pscom_env_table_parse() for a multi entry table with wrong entry
 *
 * Given: An environment table with a multiple entries of different type and
 *        one entry failing to be parsed
 * When: pscom_env_table_parse is called()
 * Then: the specified configuration parameters should be updated with the
 * 	 default values or from the environment accordingly and it should return
 *       with PSCOM_ERR_INVALID.
 */
void test_env_table_parse_multi_entry_failing_entry(void **state)
{
    int test_var_int                 = -1;
    char *test_var_str               = "oldstring";
    unsigned int test_var_uint       = 1001;
    env_var_backup_t *env_var_backup = (env_var_backup_t *)(*state);

    /* set the second environment variable */
    setenv(env_var_backup[2].name, "World", 1);

    pscom_env_table_entry_t env_table[] = {
        {env_var_backup[0].name, "-42", NULL, &test_var_int, 0,
         PSCOM_ENV_PARSER_INT},

        {env_var_backup[1].name,
         "13",
         NULL,
         &test_var_uint,
         0,
         {&parser_set_not_implemented, NULL}},

        {env_var_backup[2].name, "wrong string", NULL, &test_var_str, 0,
         PSCOM_ENV_PARSER_STR},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table, NULL, NULL, NULL);
    assert_true(ret == PSCOM_ERR_INVALID);

    assert_int_equal(test_var_int, -42);
    assert_string_equal(test_var_str, "World");
}


/**
 * @brief Test pscom_env_table_parse() for an entry with parent
 *
 * Given: An environment table with a single size_t entry with parent
 * When: the according parent environment variable is set
 * Then: pscom_env_table_parse() should update the configuration parameter
 *       with the value from the parent accordingly.
 */
void test_env_table_parse_single_size_t_parent_set(void **state)
{
    size_t test_var     = 0;
    const char *env_var = ((env_var_backup_t *)(*state))->name;

    /* set the environment variable */
    setenv(env_var, "8589934592", 1);

    pscom_env_table_entry_t env_table_size_t[] = {
        {env_var, "3", NULL, &test_var, 1, PSCOM_ENV_PARSER_SIZE_T},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_size_t, NULL, "SUBTABLE_",
                                            NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_int_equal(test_var, 8589934592);
}


/**
 * @brief Test pscom_env_table_parse() for an entry with parent and env set
 *
 * Given: An environment table with a single size_t entry with parent
 * When: the according parent environment variable and actual environment
 *       variable is set
 * Then: pscom_env_table_parse() should update the configuration parameter
 *       with the value from the actual environment variable.
 */
void test_env_table_parse_single_size_t_parent_set_and_env_set(void **state)
{
    size_t test_var           = 0;
    env_var_backup_t *env_var = (env_var_backup_t *)(*state);

    /* set the parent environment variable */
    setenv(env_var->name, "8589934592", 1);

    /* set the actual environment variable */
    char envvar[128];
    snprintf(envvar, sizeof(envvar) - 1, "%s%s", env_var->prefix, env_var->name);
    setenv(envvar, "10000000000", 1);

    pscom_env_table_entry_t env_table_size_t[] = {
        {env_var->name, "3", NULL, &test_var, 1, PSCOM_ENV_PARSER_SIZE_T},

        {0},
    };

    pscom_err_t ret = pscom_env_table_parse(env_table_size_t, NULL,
                                            env_var->prefix, NULL);
    assert_true(ret == PSCOM_SUCCESS);

    assert_int_equal(test_var, 10000000000);
}


////////////////////////////////////////////////////////////////////////////////
/// pscom_env_table_register()
////////////////////////////////////////////////////////////////////////////////
/**
 * @brief Test pscom_env_table_register() for a simple configuration table
 *
 * Given: An environment table
 * When: pscom_table_register() is called
 * Then: the table should be registered with the global list.
 */
void test_env_table_register_simple(void **state)
{
    pscom_err_t ret;
    int test_var_int         = 42;
    const char *table_name   = "Dummy Table";
    const char *table_prefix = "TMP_";

    /* initialize the global table list */
    INIT_LIST_HEAD(&pscom.env_config);

    pscom_env_table_entry_t env_table[] = {
        {"TEST_VAR", "-42", NULL, &test_var_int, 0, PSCOM_ENV_PARSER_INT},

        {0},
    };

    ret = pscom_env_table_register(table_name, table_prefix, env_table);
    assert_true(ret == PSCOM_SUCCESS);

    /* there should be exactly one list element */
    assert_int_equal(list_count(&pscom.env_config), 1);

    /* the list element should match our table */
    struct list_head *pos;
    list_for_each (pos, &pscom.env_config) {
        pscom_env_list_entry_t *list_entry = list_entry(pos,
                                                        pscom_env_list_entry_t,
                                                        next);

        assert_string_equal(list_entry->name, table_name);
        assert_string_equal(list_entry->prefix, table_prefix);
        assert_ptr_equal(list_entry->table, &env_table);
    }
}


/**
 * @brief Test pscom_env_table_register() for out-of-memory
 *
 * Given: An environment table and
 * When:  malloc cannot allocate memory
 * Then:  pscom_table_register() should fail with PSCOM_ERR_STDERR and errno
 *        should be set accordingly.
 */
void test_env_table_register_no_mem(void **state)
{
    pscom_err_t ret;
    int test_var_int         = 42;
    const char *table_name   = "Dummy Table";
    const char *table_prefix = "TMP_";

    /* initialize the global table list */
    INIT_LIST_HEAD(&pscom.env_config);

    pscom_env_table_entry_t env_table[] = {
        {"TEST_VAR", "-42", NULL, &test_var_int, 0, PSCOM_ENV_PARSER_INT},

        {0},
    };

    enable_malloc_mock(NULL);

    ret = pscom_env_table_register(table_name, table_prefix, env_table);
    assert_true(ret == PSCOM_ERR_STDERROR);
    assert_int_equal(errno, ENOMEM);

    /* there should not be any list element */
    assert_int_equal(list_count(&pscom.env_config), 0);

    disable_malloc_mock();
}


////////////////////////////////////////////////////////////////////////////////
/// pscom_env_parser_t -> get()
////////////////////////////////////////////////////////////////////////////////
/**
 * @brief Test getter from pscom_env_parser_t for int entry
 *
 * Given: An environment table entry with an integer parameter
 * When: the get() routine of the parser is called
 * Then: its current value is written to the provided buffer.
 */
void test_env_parser_get_int(void **state)
{
    int test_var = -42;

    pscom_env_table_entry_t env_entry = {"TEST_VAR", "dummy text",
                                         "-1",       &test_var,
                                         0,          PSCOM_ENV_PARSER_INT};

    char val_str[16] = "wrong string";
    pscom_err_t ret  = env_entry.parser.get((&env_entry)->config_var, val_str,
                                            sizeof(val_str));
    assert_true(ret == PSCOM_SUCCESS);

    assert_string_equal(val_str, "-42");
}


/**
 * @brief Test getter from pscom_env_parser_t for unsigend int entry
 *
 * Given: An environment table entry with an unsigned integer parameter
 * When: the get() routine of the parser is called
 * Then: its current value is written to the provided buffer.
 */
void test_env_parser_get_uint(void **state)
{
    unsigned int test_var = 42;

    pscom_env_table_entry_t env_entry = {"TEST_VAR", "dummy text",
                                         "13",       &test_var,
                                         0,          PSCOM_ENV_PARSER_UINT};

    char val_str[16] = "wrong string";
    pscom_err_t ret  = env_entry.parser.get((&env_entry)->config_var, val_str,
                                            sizeof(val_str));
    assert_true(ret == PSCOM_SUCCESS);

    assert_string_equal(val_str, "42");
}


/**
 * @brief Test getter from pscom_env_parser_t for unsigend int "inf" entry
 *
 * Given: An environment table entry with an unsigned integer parameter equal to
 *        PSCOM_ENV_UINT_INF.
 * When: the get() routine of the parser is called
 * Then: "inf" is written to the provided buffer.
 */
void test_env_parser_get_uint_inf(void **state)
{
    unsigned int test_var = PSCOM_ENV_UINT_INF;

    pscom_env_table_entry_t env_entry = {"TEST_VAR", "dummy text",
                                         "13",       &test_var,
                                         0,          PSCOM_ENV_PARSER_UINT};

    char val_str[16] = "wrong string";
    pscom_err_t ret  = env_entry.parser.get((&env_entry)->config_var, val_str,
                                            sizeof(val_str));
    assert_true(ret == PSCOM_SUCCESS);

    assert_string_equal(val_str, "inf");
}


/**
 * @brief Test getter from pscom_env_parser_t for unsigend int "auto" entry
 *
 * Given: An environment table entry with an unsigned integer parameter equal to
 *        PSCOM_ENV_UINT_AUTO.
 * When: the get() routine of the parser is called
 * Then: "auto" is written to the provided buffer.
 */
void test_env_parser_get_uint_auto(void **state)
{
    unsigned int test_var = PSCOM_ENV_UINT_AUTO;

    pscom_env_table_entry_t env_entry = {"TEST_VAR", "dummy text",
                                         "13",       &test_var,
                                         0,          PSCOM_ENV_PARSER_UINT};

    char val_str[16] = "wrong string";
    pscom_err_t ret  = env_entry.parser.get((&env_entry)->config_var, val_str,
                                            sizeof(val_str));
    assert_true(ret == PSCOM_SUCCESS);

    assert_string_equal(val_str, "auto");
}


/**
 * @brief Test getter from pscom_env_parser_t for size_t entry
 *
 * Given: An environment table entry with a size_t parameter
 * When: the get() routine of the parser is called
 * Then: its current value is written to the provided buffer.
 */
void test_env_parser_get_size_t(void **state)
{
    size_t test_var = 4294967296;

    pscom_env_table_entry_t env_entry = {"TEST_VAR", "dummy text",
                                         "13",       &test_var,
                                         0,          PSCOM_ENV_PARSER_SIZE_T};

    char val_str[32] = "wrong string";
    pscom_err_t ret  = env_entry.parser.get((&env_entry)->config_var, val_str,
                                            sizeof(val_str));
    assert_true(ret == PSCOM_SUCCESS);

    assert_string_equal(val_str, "4294967296");
}


/**
 * @brief Test getter from pscom_env_parser_t for string entry
 *
 * Given: An environment table entry with a string parameter
 * When: the get() routine of the parser is called
 * Then: its current value is written to the provided buffer.
 */
void test_env_parser_get_str(void **state)
{
    char *test_var = "Correct String";

    pscom_env_table_entry_t env_entry = {"TEST_VAR", "dummy text",
                                         "13",       &test_var,
                                         0,          PSCOM_ENV_PARSER_STR};

    char val_str[32] = "wrong string";
    pscom_err_t ret  = env_entry.parser.get((&env_entry)->config_var, val_str,
                                            sizeof(val_str));
    assert_true(ret == PSCOM_SUCCESS);

    assert_string_equal(val_str, "Correct String");
}


/**
 * @brief Test getter from pscom_env_parser_t for directory entry
 *
 * Given: An environment table entry with a directory parameter
 * When: the get() routine of the parser is called
 * Then: its current value is written to the provided buffer.
 */
void test_env_parser_get_dir(void **state)
{
    char *test_var = "/path/to/correct/dir/";

    pscom_env_table_entry_t env_entry = {"TEST_VAR", "dummy text",
                                         "13",       &test_var,
                                         0,          PSCOM_ENV_PARSER_DIR};

    char val_str[64] = "/wrong/dir/";
    pscom_err_t ret  = env_entry.parser.get((&env_entry)->config_var, val_str,
                                            sizeof(val_str));
    assert_true(ret == PSCOM_SUCCESS);

    assert_string_equal(val_str, "/path/to/correct/dir/");
}
////////////////////////////////////////////////////////////////////////////////
/// pscom_env_table_register_and_parse()
////////////////////////////////////////////////////////////////////////////////
/**
 * @brief Test pscom_env_table_register_and_parse() for out-of-memory
 *
 * Given: An environment table and
 * When:  malloc cannot allocate memory
 * Then:  pscom_table_register_and_parse() should fail with PSCOM_ERR_STDERR,
 *        errno should be set accordingly, and the table should not be parsed.
 */
void test_env_table_register_and_parse_no_mem(void **state)
{
    pscom_err_t ret;
    int test_var_int         = 42;
    const char *table_name   = "Dummy Table";
    const char *table_prefix = "TMP_";

    /* initialize the global table list */
    INIT_LIST_HEAD(&pscom.env_config);

    pscom_env_table_entry_t env_table[] = {
        {"TEST_VAR", "-42", NULL, &test_var_int, 0, PSCOM_ENV_PARSER_INT},

        {0},
    };

    enable_malloc_mock(NULL);

    ret = pscom_env_table_register_and_parse(table_name, table_prefix,
                                             env_table);
    assert_true(ret == PSCOM_ERR_STDERROR);
    assert_int_equal(errno, ENOMEM);

    /* there should not be any list element */
    assert_int_equal(list_count(&pscom.env_config), 0);

    /* test_var_int should not be touched */
    assert_int_equal(test_var_int, 42);

    disable_malloc_mock();
}


/**
 * @brief Test pscom_env_table_register_and_parse() for a simple config table
 *
 * Given: An environment table
 * When: pscom_table_register() is called
 * Then: the table should be registered with the global list and parsed.
 */
void test_env_table_register_and_parse_simple(void **state)
{
    pscom_err_t ret;
    int test_var_int         = 42;
    const char *table_name   = "Dummy Table";
    const char *table_prefix = "TMP_";

    /* initialize the global table list */
    INIT_LIST_HEAD(&pscom.env_config);

    pscom_env_table_entry_t env_table[] = {
        {"TEST_VAR", "-42", NULL, &test_var_int, 0, PSCOM_ENV_PARSER_INT},

        {0},
    };

    ret = pscom_env_table_register_and_parse(table_name, table_prefix,
                                             env_table);
    assert_true(ret == PSCOM_SUCCESS);

    /* there should be exactly one list element */
    assert_int_equal(list_count(&pscom.env_config), 1);

    /* the list element should match our table */
    struct list_head *pos;
    list_for_each (pos, &pscom.env_config) {
        pscom_env_list_entry_t *list_entry = list_entry(pos,
                                                        pscom_env_list_entry_t,
                                                        next);

        assert_string_equal(list_entry->name, table_name);
        assert_string_equal(list_entry->prefix, table_prefix);
        assert_ptr_equal(list_entry->table, &env_table);
    }

    /* check if the table has been parsed */
    assert_int_equal(test_var_int, -42);
}


/**
 * @brief Test pscom_env_table_register_and_parse() with environment variable
 *
 * Given: A single-entry environment table and the environment variable being
 *        set
 * When:  pscom_table_register() is called
 * Then:  the table should be registered with the global list and parsed in
 *        accordance with the environment variable.
 */
void test_env_table_register_and_parse_env_var(void **state)
{
    pscom_err_t ret;
    unsigned int test_var  = 0;
    const char *table_name = "Dummy Table";
    const char *env_var    = ((env_var_backup_t *)(*state))->name;
    char env_var_with_prefix[64];

    /* set the environment variable includeing global prefix */
    snprintf(env_var_with_prefix, sizeof(env_var_with_prefix) - 1, "%s%s",
             PSCOM_ENV_GLOBAL_PREFIX, env_var);
    setenv(env_var_with_prefix, "42", 1);

    /* initialize the global table list */
    INIT_LIST_HEAD(&pscom.env_config);

    pscom_env_table_entry_t env_table[] = {
        {env_var, "3", NULL, &test_var, 0, PSCOM_ENV_PARSER_UINT},

        {0},
    };

    ret = pscom_env_table_register_and_parse(table_name, NULL, env_table);
    assert_true(ret == PSCOM_SUCCESS);

    /* there should be exactly one list element */
    assert_int_equal(list_count(&pscom.env_config), 1);

    /* the list element should match our table */
    struct list_head *pos;
    list_for_each (pos, &pscom.env_config) {
        pscom_env_list_entry_t *list_entry = list_entry(pos,
                                                        pscom_env_list_entry_t,
                                                        next);

        assert_string_equal(list_entry->name, table_name);
        assert_ptr_equal(list_entry->prefix, NULL);
        assert_ptr_equal(list_entry->table, &env_table);
    }

    /* check if the table has been parsed */
    assert_int_equal(test_var, 42);
}


////////////////////////////////////////////////////////////////////////////////
/// pscom_env_table_list_clear()
////////////////////////////////////////////////////////////////////////////////
/**
 * @brief Test pscom_env_table_list_clear() for an empty list
 *
 * Given: An empty global list of configuration definition tables
 * When:  pscom_env_table_list_clear() is called
 * Then:  the global list should be still empty.
 */
void test_env_clear_table_list_empty(void **state)
{
    /* initialize the global table list */
    INIT_LIST_HEAD(&pscom.env_config);

    pscom_env_table_list_clear();

    /* there should be exactly one list element */
    assert_int_equal(list_count(&pscom.env_config), 0);
}


/**
 * @brief Test pscom_env_table_list_clear() for a filled list
 *
 * Given: An global list of configuration definition tables with entries
 * When:  pscom_env_table_list_clear() is called
 * Then:  the global list should be empty.
 */
void test_env_clear_table_list_filled(void **state)
{
    pscom_err_t ret;
    int test_var_int         = 42;
    const char *table_name   = "Dummy Table";
    const char *table_prefix = "TMP_";

    /* initialize the global table list */
    INIT_LIST_HEAD(&pscom.env_config);

    pscom_env_table_entry_t env_table[] = {
        {"TEST_VAR", "-42", NULL, &test_var_int, 0, PSCOM_ENV_PARSER_INT},

        {0},
    };

    ret = pscom_env_table_register(table_name, table_prefix, env_table);
    assert_true(ret == PSCOM_SUCCESS);

    pscom_env_table_list_clear();

    /* there should be exactly one list element */
    assert_int_equal(list_count(&pscom.env_config), 0);
}
