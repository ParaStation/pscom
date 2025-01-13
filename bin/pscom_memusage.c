/*
 * ParaStation
 *
 * Copyright (C) 2010-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdio.h>

#include "pscom_priv.h"


#undef PSCOM_CUDA_AWARENESS

#ifdef OPENIB
#include "psoib.c"
pscom_t pscom; // fake pscom
#endif

#ifdef OFED
#include "psofed.h"
#include "psofed.c"
pscom_t pscom; // fake pscom
#endif

#if defined(EXTOLL) || defined(VELO)
#include "psextoll.c"
pscom_t pscom; // fake pscom
#endif

#define USAGE(sof) printf("%8zu : %s\n", sof, #sof)

int main(int argc, char **argv)
{
    USAGE(sizeof(struct PSCOM_con));
#ifdef OPENIB
    USAGE(sizeof(psoib_con_info_t));
    USAGE(sizeof(struct PSCOM_con) + sizeof(psoib_con_info_t));
#endif
#ifdef OFED
    USAGE(sizeof(psofed_con_info_t));
    USAGE(sizeof(struct PSCOM_con) + sizeof(psofed_con_info_t));
#endif
#ifdef EXTOLL
    USAGE(sizeof(struct psex_con_info));
    USAGE(sizeof(struct PSCOM_con) + sizeof(struct psex_con_info));
#endif
#ifdef VELO
    USAGE(sizeof(struct psex_con_info));
    USAGE(sizeof(struct PSCOM_con) + sizeof(struct psex_con_info));
#endif
    return 0;
}
