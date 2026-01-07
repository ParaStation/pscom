/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

/* -*- linux-c -*- */
#ifndef _PSCOM_STR_UTIL_H_
#define _PSCOM_STR_UTIL_H_


#define INET_ADDR_SPLIT(addr)                                                  \
    ((addr) >> 24) & 0xff, ((addr) >> 16) & 0xff, ((addr) >> 8) & 0xff,        \
        (addr)&0xff
#define INET_ADDR_FORMAT "%u.%u.%u.%u"

const char *pscom_inetstr(int addr);


#define BLACK   "\033[30m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define BROWN   "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define NORM    "\033[39m"

#endif /* _PSCOM_STR_UTIL_H_ */
