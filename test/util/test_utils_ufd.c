/*
 * ParaStation
 *
 * Copyright (C) 2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <assert.h>

#include "pscom_ufd.h"
#include "pscom_priv.h"

#include "test_utils_ufd.h"

ufd_t *test_utils_init_ufd(ufd_t *ufd)
{
    /* explicitly disable threaded mode here */
    pscom.threaded = 0;

    ufd_init(ufd);

    return ufd;
}

ufd_t *test_utils_init_ufd_threaded(ufd_t *ufd)
{
    /* enable threaded mode */
    pscom.threaded = 1;

    ufd_init(ufd);

    return ufd;
}

ufd_t *test_utils_cleanup_ufd(ufd_t *ufd)
{
    /* for threaded mode, use counterpart below */
    assert(!pscom.threaded);

    ufd_cleanup(ufd);

    return ufd;
}

ufd_t *test_utils_cleanup_ufd_threaded(ufd_t *ufd)
{
    /* for non-threaded mode, use counterpart above */
    assert(pscom.threaded);

    ufd_cleanup(ufd);

    /* disable threaded mode again */
    pscom.threaded = 0;

    return ufd;
}
