#ifndef _PERF_H_
#define _PERF_H_

// #define ENABLE_PERF

#ifdef ENABLE_PERF
void perf_add(char *id);
void perf_print(void);
#else
#define perf_add(id) do {} while (0)
#define perf_print() do {} while (0)
#endif

#endif /* _PERF_H_ */
