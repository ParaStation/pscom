/*
 * ParaStation
 *
 * Copyright (C) 2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef PSCOM_ATOMIC_H
#define PSCOM_ATOMIC_H

#include <stdint.h>
#include <stdatomic.h>

#ifndef PSCOM_CACHELINE_SIZE
#define PSCOM_CACHELINE_SIZE 64
#endif

/* cacheline align macro */
#define PSCOM_CACHELINE_ALIGNED _Alignas(PSCOM_CACHELINE_SIZE)

typedef _Atomic int32_t pscom_atomic_int32_t;
typedef _Atomic uint32_t pscom_atomic_uint32_t;
typedef _Atomic int64_t pscom_atomic_int64_t;
typedef _Atomic uint64_t pscom_atomic_uint64_t;

/* atomic_relaxed_load */
static int32_t pscom_atomic_relaxed_load_int32(const pscom_atomic_int32_t *ptr);
static uint32_t
pscom_atomic_relaxed_load_uint32(const pscom_atomic_uint32_t *ptr);
static int64_t pscom_atomic_relaxed_load_int64(const pscom_atomic_int64_t *ptr);
static uint64_t
pscom_atomic_relaxed_load_uint64(const pscom_atomic_uint64_t *ptr);

/* atomic_acquire_load */
static int32_t pscom_atomic_acquire_load_int32(const pscom_atomic_int32_t *ptr);
static uint32_t
pscom_atomic_acquire_load_uint32(const pscom_atomic_uint32_t *ptr);
static int64_t pscom_atomic_acquire_load_int64(const pscom_atomic_int64_t *ptr);
static uint64_t
pscom_atomic_acquire_load_uint64(const pscom_atomic_uint64_t *ptr);

/* atomic_relaxed_store */
static void pscom_atomic_relaxed_store_int32(pscom_atomic_int32_t *ptr,
                                             int32_t val);
static void pscom_atomic_relaxed_store_uint32(pscom_atomic_uint32_t *ptr,
                                              uint32_t val);
static void pscom_atomic_relaxed_store_int64(pscom_atomic_int64_t *ptr,
                                             int64_t val);
static void pscom_atomic_relaxed_store_uint64(pscom_atomic_uint64_t *ptr,
                                              uint64_t val);

/* atomic_release_store */
static void pscom_atomic_release_store_int32(pscom_atomic_int32_t *ptr,
                                             int32_t val);
static void pscom_atomic_release_store_uint32(pscom_atomic_uint32_t *ptr,
                                              uint32_t val);
static void pscom_atomic_release_store_int64(pscom_atomic_int64_t *ptr,
                                             int64_t val);
static void pscom_atomic_release_store_uint64(pscom_atomic_uint64_t *ptr,
                                              uint64_t val);

/* atomic_fetch_add */
static int32_t pscom_atomic_fetch_add_int32(pscom_atomic_int32_t *ptr,
                                            int32_t val);
static uint32_t pscom_atomic_fetch_add_uint32(pscom_atomic_uint32_t *ptr,
                                              uint32_t val);
static int64_t pscom_atomic_fetch_add_int64(pscom_atomic_int64_t *ptr,
                                            int64_t val);
static uint64_t pscom_atomic_fetch_add_uint64(pscom_atomic_uint64_t *ptr,
                                              uint64_t val);

/* atomic_fetch_sub */
static int32_t pscom_atomic_fetch_sub_int32(pscom_atomic_int32_t *ptr,
                                            int32_t val);
static uint32_t pscom_atomic_fetch_sub_uint32(pscom_atomic_uint32_t *ptr,
                                              uint32_t val);
static int64_t pscom_atomic_fetch_sub_int64(pscom_atomic_int64_t *ptr,
                                            int64_t val);
static uint64_t pscom_atomic_fetch_sub_uint64(pscom_atomic_uint64_t *ptr,
                                              uint64_t val);

/* atomic_swap */
static int32_t pscom_atomic_swap_int32(pscom_atomic_int32_t *ptr, int32_t val);
static uint32_t pscom_atomic_swap_uint32(pscom_atomic_uint32_t *ptr,
                                         uint32_t val);
static int64_t pscom_atomic_swap_int64(pscom_atomic_int64_t *ptr, int64_t val);
static uint64_t pscom_atomic_swap_uint64(pscom_atomic_uint64_t *ptr,
                                         uint64_t val);

/* atomic_cas (compare-and-swap) */
/* note: for current design, the oldv value will be updated to the compared
 * value (*ptr) for a self-spin lock, however, MPICH version will not update
 * oldv to the compared value. */
static _Bool pscom_atomic_cas_int32(pscom_atomic_int32_t *ptr, int32_t *oldv,
                                    int32_t newv);
static _Bool pscom_atomic_cas_uint32(pscom_atomic_uint32_t *ptr, uint32_t *oldv,
                                     uint32_t newv);
static _Bool pscom_atomic_cas_int64(pscom_atomic_int64_t *ptr, int64_t *oldv,
                                    int64_t newv);
static _Bool pscom_atomic_cas_uint64(pscom_atomic_uint64_t *ptr, uint64_t *oldv,
                                     uint64_t newv);

#define PSCOM_ATOMIC_DECL_FUNC_COMMON(VALUE_TYPE, ATOMIC_TYPE, NAME)           \
    static inline VALUE_TYPE pscom_atomic_relaxed_load_##NAME(                 \
        const ATOMIC_TYPE *ptr)                                                \
    {                                                                          \
        return (VALUE_TYPE)atomic_load_explicit(ptr, memory_order_relaxed);    \
    }                                                                          \
                                                                               \
    static inline VALUE_TYPE pscom_atomic_acquire_load_##NAME(                 \
        const ATOMIC_TYPE *ptr)                                                \
    {                                                                          \
        return (VALUE_TYPE)atomic_load_explicit(ptr, memory_order_acquire);    \
    }                                                                          \
                                                                               \
    static inline void pscom_atomic_relaxed_store_##NAME(ATOMIC_TYPE *ptr,     \
                                                         VALUE_TYPE val)       \
    {                                                                          \
        atomic_store_explicit(ptr, val, memory_order_relaxed);                 \
    }                                                                          \
                                                                               \
    static inline void pscom_atomic_release_store_##NAME(ATOMIC_TYPE *ptr,     \
                                                         VALUE_TYPE val)       \
    {                                                                          \
        atomic_store_explicit(ptr, val, memory_order_release);                 \
    }                                                                          \
                                                                               \
    static inline VALUE_TYPE pscom_atomic_fetch_add_##NAME(ATOMIC_TYPE *ptr,   \
                                                           VALUE_TYPE val)     \
                                                                               \
    {                                                                          \
        return atomic_fetch_add_explicit(ptr, val, memory_order_acq_rel);      \
    }                                                                          \
                                                                               \
    static inline VALUE_TYPE pscom_atomic_fetch_sub_##NAME(ATOMIC_TYPE *ptr,   \
                                                           VALUE_TYPE val)     \
    {                                                                          \
        return (VALUE_TYPE)atomic_fetch_sub_explicit(ptr, val,                 \
                                                     memory_order_acq_rel);    \
    }                                                                          \
                                                                               \
    static inline VALUE_TYPE pscom_atomic_swap_##NAME(ATOMIC_TYPE *ptr,        \
                                                      VALUE_TYPE val)          \
    {                                                                          \
        return (VALUE_TYPE)atomic_exchange_explicit(ptr, val,                  \
                                                    memory_order_acq_rel);     \
    }                                                                          \
                                                                               \
    static inline _Bool pscom_atomic_cas_##NAME(ATOMIC_TYPE *ptr,              \
                                                VALUE_TYPE *oldv,              \
                                                VALUE_TYPE newv)               \
    {                                                                          \
        return atomic_compare_exchange_strong_explicit(ptr, oldv, newv,        \
                                                       memory_order_acq_rel,   \
                                                       memory_order_acquire);  \
    }


PSCOM_ATOMIC_DECL_FUNC_COMMON(int32_t, pscom_atomic_int32_t, int32)

PSCOM_ATOMIC_DECL_FUNC_COMMON(uint32_t, pscom_atomic_uint32_t, uint32)

PSCOM_ATOMIC_DECL_FUNC_COMMON(int64_t, pscom_atomic_int64_t, int64)

PSCOM_ATOMIC_DECL_FUNC_COMMON(uint64_t, pscom_atomic_uint64_t, uint64)

#undef PSCOM_ATOMIC_DECL_FUNC_COMMON


static inline void pscom_atomic_fence_release(void)
{
    atomic_thread_fence(memory_order_release);
}

static inline void pscom_atomic_fence_acquire(void)
{
    atomic_thread_fence(memory_order_acquire);
}

static inline void pscom_atomic_fence_acq_rel(void)
{
    atomic_thread_fence(memory_order_acq_rel);
}


#endif /* PSCOM_ATOMIC_H */
