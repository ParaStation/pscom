/* Logging module 2002-11-20 jh */

#ifndef _P4LOG_H_
#define _P4LOG_H_


struct logentry_s {
    long long	time;
    int		type;
    int		reserved;
    long	value;
};


#define LOG_OVERRUN -1
#define LOG_READ    -2
#define LOG_NOP     -3


void p4log(int type, long value);










#endif
