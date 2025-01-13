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
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include "pscom_env.h"
#include "pscom_debug.h"
#include "pscom_precon.h"
#include "pscom_priv.h"
#include "pscom_ufd.h"
#include "pscom_precon_tcp.h"

#include "util/test_utils_debug.h"
/**
 * @brief Test PSP_DEBUG_OUT for PSP_DEBUG set to max
 *
 * Given: PSP_DEBUG is set to max and PSP_DEBUG_OUT is set
 * When:  DPRINT() is called
 * Then:  nothing should be written to stderr.
 */
void test_debug_psp_debug_out_max_debug_level(void **state)
{
    char template[]          = "/tmp/tmpdir.XXXXXX";
    char stderr_buf[128]     = {0};
    char debug_out_name[128] = {0};
    char *debug_dir;
    int captured_stderr;

    /* create temporary directory for our debug file */
    debug_dir = mkdtemp(template);
    assert_true(debug_dir);
    snprintf(debug_out_name, 128, "%s/psp-debug.out", debug_dir);

    /* capture STDERR */
    captured_stderr = capture_fd(STDERR_FILENO);

    /* set debug level to max  redirect to a file */
    setenv("PSP_DEBUG", "6", 1);
    setenv("PSP_DEBUG_OUT", debug_out_name, 1);

    /* initialize the environment module */
    pscom_env_init();

    /* write a debug message */
    DPRINT(D_ERR, "THIS SHOULD NOT APPEAR ON STDERR");

    /* write something to stderr so we can retrieve it via read() */
    fprintf(stderr, "EOF");
    fflush(stderr);

    /* read stderr and restore */
    assert_true(read(captured_stderr, stderr_buf, sizeof(stderr_buf) - 1) >= 0);

    restore_fd(STDERR_FILENO);

    /* cleanup the environment module to prevent memory leaks */
    pscom_env_cleanup();

    /* explicitly reset pscom.env to prevent side effects */
    memset(&pscom.env, 0, sizeof(struct PSCOM_env));

    /* remove the debug file and the temporary directory */
    assert_true(remove(debug_out_name) == 0);
    assert_true(rmdir(debug_dir) == 0);

    /* stderr should contain nothing than our 'EOF' */
    assert_string_equal(stderr_buf, "EOF");
}


/**
 * @brief Test debug output for broken pipe errors on the precon socket
 *
 * Given: PSP_DEBUG is set to default
 * When:  the precon sees an EPIPE
 * Then:  nothing should be written to stderr.
 */
void test_debug_precon_broken_pipe(void **state)
{
    char stderr_buf[128] = {0};
    int captured_stderr;

    /* capture STDERR */
    captured_stderr = capture_fd(STDERR_FILENO);

    /* initialize the environment module */
    pscom_env_init();
    ufd_init(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_con_t *dummy_con      = (pscom_con_t *)(*state);
    /* only precon tcp is tested */
    pscom_precon_t *precon      = pscom_precon_create(dummy_con);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    assert(precon->magic == MAGIC_PRECON);
    assert(pre_tcp->magic == MAGIC_PRECON);
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* start writing on the precon and generate EPIPE */
    will_return(__wrap_send, EPIPE);
    will_return(__wrap_send, -1);
    pre_tcp->send_len = 42;
    pre_tcp->ufd_info.can_write(NULL, &pre_tcp->ufd_info);

    /* write something to stderr so we can retrieve it via read() */
    fprintf(stderr, "EOF");
    fflush(stderr);

    /* read stderr and restore */
    assert_true(read(captured_stderr, stderr_buf, sizeof(stderr_buf) - 1) >= 0);

    restore_fd(STDERR_FILENO);

    /* cleanup the environment module to prevent memory leaks */
    pscom_env_cleanup();

    /* explicitly reset pscom.env to prevent side effects */
    memset(&pscom.env, 0, sizeof(struct PSCOM_env));

    /* stderr should contain nothing than our 'EOF' */
    assert_string_equal(stderr_buf, "EOF");
}


/**
 * @brief Test debug output for unexpected errors on the precon socket
 *
 * Given: PSP_DEBUG is set to default
 * When:  the precon sees an EIO
 * Then:  the user should see an according error message.
 */
void test_debug_precon_io_error(void **state)
{
    char stderr_buf[128] = {0};
    int captured_stderr;

    /* capture STDERR */
    captured_stderr = capture_fd(STDERR_FILENO);

    /* initialize the environment module */
    pscom_env_init();
    ufd_init(&pscom.ufd);

    /* create and initialize the precon object */
    pscom_con_t *dummy_con      = (pscom_con_t *)(*state);
    /* only precon tcp is tested */
    pscom_precon_t *precon      = pscom_precon_create(dummy_con);
    pscom_precon_tcp_t *pre_tcp = (pscom_precon_tcp_t *)&precon->precon_data;
    pscom_precon_assign_fd_tcp(pre_tcp, 0x42);

    /* start writing on the precon and generate EPIPE */
    will_return(__wrap_send, EIO);
    will_return(__wrap_send, -1);
    pre_tcp->send_len = 42;
    pre_tcp->ufd_info.can_write(NULL, &pre_tcp->ufd_info);

    /* write something to stderr so we can retrieve it via read() */
    fprintf(stderr, "EOF");
    fflush(stderr);

    /* read stderr and restore */
    assert_true(read(captured_stderr, stderr_buf, sizeof(stderr_buf) - 1) >= 0);

    restore_fd(STDERR_FILENO);

    /* cleanup the environment module to prevent memory leaks */
    pscom_env_cleanup();

    /* explicitly reset pscom.env to prevent side effects */
    memset(&pscom.env, 0, sizeof(struct PSCOM_env));

    /* stderr should contain 'Input/output error' */
    assert_true(strstr(stderr_buf, "Input/output error") != NULL);
}
