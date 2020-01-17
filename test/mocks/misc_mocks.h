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

#ifndef _MOCKS_H_
#define _MOCKS_H_

#include <stddef.h>

void *__real_memcpy(void *restrict dst, const void *restrict src, size_t nbytes);

#endif /* _MOCKS_H_ */
