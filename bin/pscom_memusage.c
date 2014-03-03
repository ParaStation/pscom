/*
 * ParaStation
 *
 * Copyright (C) 2010 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <math.h>

#include "pscom.h"
#include "pscom_priv.h"

#ifndef OFED
#include "psoib.c"
#else
#include "psofed.c"
#endif

#define USAGE(sof) printf("%8zu : %s\n", sof, #sof)

int main(int argc, char **argv)
{
	USAGE(sizeof(struct PSCOM_con));
#ifndef OFED
	USAGE(sizeof(psoib_con_info_t));
	USAGE(sizeof(struct PSCOM_con) + sizeof(psoib_con_info_t));
#else
	USAGE(sizeof(psofed_con_info_t));
	USAGE(sizeof(struct PSCOM_con) + sizeof(psofed_con_info_t));
#endif
	return 0;
}
