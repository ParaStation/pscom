/*
 * ParaStation
 *
 * Copyright (C) 2024-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSCOM_TEST_UTILS_UFD_H_
#define _PSCOM_TEST_UTILS_UFD_H_

#include "pscom_ufd.h"

ufd_t *test_utils_init_ufd(ufd_t *ufd);
ufd_t *test_utils_init_ufd_threaded(ufd_t *ufd);
ufd_t *test_utils_cleanup_ufd(ufd_t *ufd);
ufd_t *test_utils_cleanup_ufd_threaded(ufd_t *ufd);

#endif /* _PSCOM_TEST_UTILS_UFD_H_ */
