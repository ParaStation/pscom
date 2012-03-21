/* -*- linux-c -*- */
#ifndef _PSPORT_UTIL_H_
#define _PSPORT_UTIL_H_

#include "psport4.h"

/* return PSP_GetNodeID() and PSP_GetPortNo(porth) as a string */
const char *PSP_local_name(PSP_PortH_t porth);

/* call PSP_Connect() with a string */
int PSP_Connect_name(PSP_PortH_t porth, const char *name);

#define INET_ADDR_SPLIT(addr) ((addr) >> 24) & 0xff, ((addr) >> 16) & 0xff, ((addr) >>  8) & 0xff, (addr) & 0xff
#define INET_ADDR_FORMAT "%u.%u.%u.%u"

const char *pscom_inetstr(int addr);


#define BLACK	"\033[30m"
#define RED	"\033[31m"
#define GREEN	"\033[32m"
#define BROWN	"\033[33m"
#define BLUE	"\033[34m"
#define MAGENTA	"\033[35m"
#define CYAN	"\033[36m"
#define WHITE	"\033[37m"
#define NORM	"\033[39m"

#endif /* _PSPORT_UTIL_H_ */
