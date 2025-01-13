/*
 * ParaStation
 *
 * Copyright (C) 2022-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PORTALS4_MOCKS_H_
#define _PORTALS4_MOCKS_H_

#include "pscom_utest.h"

static inline void enable_extended_ptl_put_mock(void)
{
    pscom_utest.mock_functions.portals.extended_ptl_put = 1;
}
static inline void disable_extended_ptl_put_mock(void)
{
    pscom_utest.mock_functions.portals.extended_ptl_put = 0;
}

#endif /* _PORTALS4_MOCKS_H_ */
