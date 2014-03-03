/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * PSPort: Communication Library for Parastation
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include "psport4.h"

PSP_Err_t PSP_Init(void)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


char **PSP_HWList(void)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


int PSP_GetConnectionState(PSP_PortH_t porth, int dest, PSP_ConnectionState_t *cs)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


const char *PSP_ConState_str(int state)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


int PSP_GetNodeID(void)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


PSP_PortH_t PSP_OpenPort(int portno)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


void PSP_StopListen(PSP_PortH_t porth)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


int PSP_GetPortNo(PSP_PortH_t porth)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


PSP_Err_t PSP_ClosePort(PSP_PortH_t porth)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}

int PSP_Connect( PSP_PortH_t porth, int nodeid, int portno )
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


int PSP_RecvAny(PSP_Header_Net_t* header, int from, void *param)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}

int PSP_RecvFrom(PSP_Header_Net_t* header, int from, void *param)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


PSP_RequestH_t PSP_IReceiveCBFrom(PSP_PortH_t porth,
				  void* buf, unsigned buflen,
				  PSP_Header_t* header, unsigned xheaderlen,
				  PSP_RecvCallBack_t* cb, void* cb_param,
				  PSP_DoneCallback_t* dcb, void* dcb_param,
				  int sender)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


int PSP_IProbeFrom(PSP_PortH_t porth,
		   PSP_Header_t* header, unsigned xheaderlen,
		   PSP_RecvCallBack_t *cb, void* cb_param,
		   int sender)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


int PSP_ProbeFrom(PSP_PortH_t porth,
		  PSP_Header_t* header, unsigned xheaderlen,
		  PSP_RecvCallBack_t *cb, void* cb_param,
		  int sender)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


PSP_RequestH_t PSP_ISend(PSP_PortH_t porth,
			 void* buf, unsigned buflen,
			 PSP_Header_t* header, unsigned xheaderlen,
			 int dest,int flags)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


PSP_Status_t PSP_Test(PSP_PortH_t porth, PSP_RequestH_t request)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


PSP_Status_t PSP_Wait(PSP_PortH_t porth, PSP_RequestH_t request)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}


PSP_Status_t PSP_Cancel(PSP_PortH_t porth, PSP_RequestH_t request)
{
    fprintf(stderr, "libpsport4std.so is not a runtime library!(%s)\n", __func__);
    exit(1);
}
