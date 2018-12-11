/* -*- linux-c -*- */
#ifndef _PSPORT_UTIL_H_
#define _PSPORT_UTIL_H_


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
