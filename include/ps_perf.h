/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * ps_perf.h: get some performance counters (eg. CPU cycles)
 */

#ifndef _PS_PERF_H_
#define _PS_PERF_H_

#include <sys/time.h>

static inline unsigned long long ps_getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_usec + tv.tv_sec * 1000000LL);
}


#if defined(__i386)
/*#include <asm/msr.h>*/
#ifndef rdtsc
#define rdtsc(low, high) __asm__ __volatile__("rdtsc" : "=a"(low), "=d"(high))
#endif
#ifndef rdtscl
#define rdtscl(low) __asm__ __volatile__("rdtsc" : "=a"(low) : : "edx")
#endif
#ifndef rdtscll
#define rdtscll(val) __asm__ __volatile__("rdtsc" : "=A"(val))
#endif


#define GET_CPU_CYCLES(/*unsigned long*/ cycl)         rdtscl(cycl)
#define GET_CPU_CYCLES_LL(/*unsigned long long*/ cycl) rdtscll(cycl)

#elif defined(__ia64)

/* #include <asm/timex.h> timex sucks in 2.6 without types.h */
static inline unsigned long ps_get_cycles(void)
{
    unsigned long ret;
    __asm__ __volatile__("mov %0=ar.itc" : "=r"(ret));
    return ret;
}

#define GET_CPU_CYCLES(/*unsigned long*/ cycl)         cycl = ps_get_cycles()
#define GET_CPU_CYCLES_LL(/*unsigned long long*/ cycl) cycl = ps_get_cycles()

#elif defined(__x86_64)

#ifndef rdtsc
#define rdtsc(low, high) __asm__ __volatile__("rdtsc" : "=a"(low), "=d"(high))
#endif
#ifndef rdtscl
#define rdtscl(low) __asm__ __volatile__("rdtsc" : "=a"(low) : : "edx")
#endif
#ifndef rdtscll
#define rdtscll(val) __asm__ __volatile__("rdtsc" : "=A"(val))
#endif


#define GET_CPU_CYCLES(/*unsigned long*/ cycl)         rdtscl(cycl)
#define GET_CPU_CYCLES_LL(/*unsigned long long*/ cycl) rdtscll(cycl)

#elif defined(__powerpc64__)

static inline unsigned long ps_get_cycles_long(void)
{
    unsigned int cycles_lo, cycles_hi;
    __asm__ __volatile__("mftb %0,268\n" : "=r"(cycles_lo));
    __asm__ __volatile__("mftb %0,269\n" : "=r"(cycles_hi));
    return (((unsigned long)cycles_hi << 32) | cycles_lo);
}
static inline unsigned int ps_get_cycles(void)
{
    unsigned int cycles_lo;
    __asm__ __volatile__("mftb %0,268\n" : "=r"(cycles_lo));
    return cycles_lo;
}

#define GET_CPU_CYCLES(/*unsigned long*/ cycl) cycl = ps_get_cycles()
#define GET_CPU_CYCLES_LL(/*unsigned long long*/ cycl)                         \
    cycl = ps_get_cycles_long()

#elif defined(__powerpc__)

static inline unsigned long long ps_get_cycles_long(void)
{
    unsigned int cycles_lo, cycles_hi;
    __asm__ __volatile__("mftb %0,268\n" : "=r"(cycles_lo));
    __asm__ __volatile__("mftb %0,269\n" : "=r"(cycles_hi));
    return (((unsigned long long)cycles_hi << 32) | cycles_lo);
}
static inline unsigned long ps_get_cycles(void)
{
    unsigned int cycles_lo;
    __asm__ __volatile__("mftb %0,268\n" : "=r"(cycles_lo));
    return cycles_lo;
}

#define GET_CPU_CYCLES(/*unsigned long*/ cycl) cycl = ps_get_cycles()
#define GET_CPU_CYCLES_LL(/*unsigned long long*/ cycl)                         \
    cycl = ps_get_cycles_long()

#elif defined(__aarch64__)

#define GET_CPU_CYCLES_LL(/*u long long*/ cycl) cycl = ps_getusec()
#define GET_CPU_CYCLES(/*unsigned long*/ cycl)  GET_CPU_CYCLES_LL(cycl)

#else

#warning Unknown architecture

#define GET_CPU_CYCLES_LL(/*u long long*/ cycl) cycl = ps_getusec()
#define GET_CPU_CYCLES(/*unsigned long*/ cycl)  GET_CPU_CYCLES_LL(cycl)

#endif


#endif /* _PS_PERF_H_ */
