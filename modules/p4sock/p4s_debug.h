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
 * p4s_debug: Enable/Disable debugs
 */

#ifndef _P4S_DEBUG_
#define _P4S_DEBUG_
#include <linux/version.h>

#if 1
#define DPRINT(fmt, param...) do {		\
    /*MCPIF_PRINT(fmt,##param);*/		\
    printk(fmt,##param);			\
} while (0)
#else
#define DPRINT(fmt, param...)
#endif

#define _STRINGIFY(param) #param
#define INT2STR(param) _STRINGIFY(param)


/********************************************************
 *
 * Configuration part
 *
 */

//#define DEBUG_TIMER /* statistics every 10 sec */

#define ENABLE_ASSERTS  /* some checks */

//#define ENABLE_LOCK_CHECK /* check for hanging spin_locks (dont work anymore) */

//#define ENABLE_P4LOG     /* p4 perf. logging (need module p4log.o) */

//#define ENABLE_FRAGCNT	/* count send and receive fragments */

// #define ENABLE_P4ETHER_MAGIC /* No advantage, if enabled... */

//#define DP_SOCKTRACE(fmt, param...) DPRINT(KERN_DEBUG "P4S: " fmt,##param);
//#define DP_PROTRACE(fmt, param...)  DPRINT(KERN_DEBUG "P4PRO: " fmt ,##param);
//#define DP_PROTRACE2(fmt, param...)  DPRINT(KERN_DEBUG "P4PRO: " fmt ,##param);
//#define DP_REFCNT(fmt, param...)  DPRINT(KERN_DEBUG "P4: " fmt ,##param);
//#define DP_RELTRACE(fmt, param...)  DPRINT(KERN_DEBUG "P4REL: " fmt ,##param);
//#define DP_LOCTRACE(fmt, param...)  DPRINT(KERN_DEBUG "P4LOC: " fmt ,##param);
//#define DP_MYRITRACE(fmt, param...)  DPRINT(KERN_DEBUG "P4MYR: " fmt ,##param);
//#define DP_ETHTRACE(fmt, param...)  DPRINT(KERN_DEBUG "P4ETH: " fmt,##param);
//#define DP_HOLDPUT(fmt, param...)  DPRINT(KERN_DEBUG "P4:%25s:%4d :" fmt, __func__, __LINE__,##param);
//#define DP_LOCK(fmt, param...)  DPRINT(KERN_DEBUG "P4:%25s:%4d :" fmt, __func__, __LINE__,##param);
//#define DP_CISTATE(fmt, param...)  DPRINT(KERN_DEBUG "P4STAT: " fmt ,##param);
//#define DP_MODUSECOUNT  DPRINT(KERN_DEBUG "P4:%20s:%4d module_refcount = %u\n", __func__, __LINE__, module_refcount(THIS_MODULE));





/*
 *
 * Configuration part end
 *
 *********************************************************/


/* Defaults: dont print anything */

#ifndef DP_SOCKTRACE
#define DP_SOCKTRACE(fmt,param...)
#endif
#ifndef DP_PROTRACE
#define DP_PROTRACE(fmt,param...)
#endif
#ifndef DP_PROTRACE2
#define DP_PROTRACE2(fmt,param...)
#endif
#ifndef DP_REFCNT
#define DP_REFCNT(fmt,param...)
#endif
#ifndef DP_RELTRACE
#define DP_RELTRACE(fmt,param...)
#endif
#ifndef DP_LOCTRACE
#define DP_LOCTRACE(fmt,param...)
#endif
#ifndef DP_ETHTRACE
#define DP_ETHTRACE(fmt,param...)
#endif
#ifndef DP_MYRITRACE
#define DP_MYRITRACE(fmt,param...)
#endif
#ifndef DP_HOLDPUT
#define DP_HOLDPUT(fmt, param...)
#endif
#ifndef DP_LOCK
#define DP_LOCK(fmt, param...)
#endif
#ifndef DP_CISTATE
#define DP_CISTATE(fmt, param...)
#endif
#ifndef DP_MODUSECOUNT
#define DP_MODUSECOUNT
#endif



#ifdef ENABLE_ASSERTS
#define P4_ASSERT(eq) if (!(eq)) {				\
    DPRINT(KERN_ERR "P4: ASSERT(" #eq ") in %s():%d failed!\n",	\
	__func__, __LINE__);					\
}
#else
#define P4_ASSERT(eq)
#endif


#ifdef ENABLE_LOCK_CHECK
int lock_check(rwlock_t *rwlock, char *desc);
int slock_check(p4_spinlock_t *slock, char *desc);

#define LOCK_CHECK(lockp, desc) do {						\
    if (lock_check(lockp, __FUNCTION__ ":" INT2STR(__LINE__) " " desc)) {	\
	goto lockescape;							\
    }										\
} while (0);

#define SLOCK_CHECK(lockp, desc) do {						\
    if (slock_check(lockp, __FUNCTION__ ":" INT2STR(__LINE__) " " desc)) {	\
	goto lockescape;							\
    }										\
} while (0);

#define LOCKESCAPE(expr) lockescape: expr

#else

#define LOCK_CHECK(lockp, desc)
#define SLOCK_CHECK(lockp, desc)
#define LOCKESCAPE(expr)
#endif


#define READ_LOCK(lockp) do {				\
 LOCK_CHECK(lockp, "RLOCK " #lockp " hang");		\
 DP_LOCK("READ   LOCK (%2d)" #lockp " %p\n",		\
	    RW_LOCK_BIAS ^ (lockp)->lock, lockp);	\
    read_lock(lockp);					\
} while (0);
#define READ_LOCK_IRQ(lockp) do {			\
 LOCK_CHECK(lockp, "RLOCK IRQ " #lockp " hang");	\
 DP_LOCK("READ   LOCK IRQ (%2d)" #lockp " %p\n",	\
	    RW_LOCK_BIAS ^ (lockp)->lock, lockp);	\
    read_lock_irq(lockp);				\
} while (0);
#define READ_LOCK_IRQSAVE(lockp, flags) do {		\
 LOCK_CHECK(lockp, "RLOCK IRQSAVE " #lockp " hang");	\
 DP_LOCK("READ   LOCK IRQSAVE (%2d)" #lockp " %p\n",	\
	    RW_LOCK_BIAS ^ (lockp)->lock, lockp);	\
    read_lock_irqsave(lockp, flags);			\
} while (0);
#define READ_UNLOCK(lockp) do {				\
    read_unlock(lockp);					\
    DP_LOCK("READ UNLOCK (%2d)" #lockp " %p\n",		\
	    RW_LOCK_BIAS ^ (lockp)->lock, lockp);	\
} while (0);
#define READ_UNLOCK_IRQ(lockp) do {			\
    read_unlock_irq(lockp);				\
    DP_LOCK("READ UNLOCK IRQ(%2d)" #lockp " %p\n",	\
	    RW_LOCK_BIAS ^ (lockp)->lock, lockp);	\
} while (0);
#define READ_UNLOCK_IRQRESTORE(lockp, flags) do {	\
    read_unlock_irqrestore(lockp, flags);		\
    DP_LOCK("READ UNLOCK IRQREST(%2d)" #lockp " %p\n",	\
	    RW_LOCK_BIAS ^ (lockp)->lock, lockp);	\
} while (0);
#define WRITE_LOCK(lockp) do {				\
    LOCK_CHECK(lockp, "WLOCK " #lockp " hang");		\
    DP_LOCK("WRITE  LOCK (%2d)" #lockp " %p\n",		\
	    RW_LOCK_BIAS ^ (lockp)->lock, lockp);	\
    write_lock(lockp);					\
} while (0);
#define WRITE_LOCK_IRQ(lockp) do {			\
    LOCK_CHECK(lockp, "WLOCK IRQ " #lockp " hang");	\
    DP_LOCK("WRITE  LOCK IRQ (%2d)" #lockp " %p\n",	\
	    RW_LOCK_BIAS ^ (lockp)->lock, lockp);	\
    write_lock_irq(lockp);				\
} while (0);
#define WRITE_LOCK_IRQSAVE(lockp, flags) do {		\
    LOCK_CHECK(lockp, "WLOCK IRQ " #lockp " hang");	\
    DP_LOCK("WRITE  LOCK IRQ (%2d)" #lockp " %p\n",	\
	    RW_LOCK_BIAS ^ (lockp)->lock, lockp);	\
    write_lock_irqsave(lockp, flags);			\
} while (0);
#define WRITE_TRYLOCK(lockp) ({			        \
    DP_LOCK("WRI TRYLOCK (%2d)" #lockp " %p\n",		\
	    RW_LOCK_BIAS ^ (lockp)->lock, lockp);	\
    write_trylock(lockp);				\
})
#define WRITE_UNLOCK(lockp) do {			\
    write_unlock(lockp);				\
    DP_LOCK("WRITEUNLOCK (%2d)" #lockp " %p\n",		\
	    RW_LOCK_BIAS ^ (lockp)->lock, lockp);	\
} while (0);
#define WRITE_UNLOCK_IRQ(lockp) do {			\
    write_unlock_irq(lockp);				\
    DP_LOCK("WRITEUNLOCK IRQ (%2d)" #lockp " %p\n",	\
	    RW_LOCK_BIAS ^ (lockp)->lock, lockp);	\
} while (0);
#define WRITE_UNLOCK_IRQRESTORE(lockp, flags) do {	\
    write_unlock_irqrestore(lockp, flags);		\
    DP_LOCK("WRITEUNLOCK IRQ (%2d)" #lockp " %p\n",	\
	    RW_LOCK_BIAS ^ (lockp)->lock, lockp);	\
} while (0);

#define SYNC_WLOCK(lockp, code)			\
do {						\
    unsigned long __flags;			\
    WRITE_LOCK_IRQSAVE(lockp, __flags);		\
    code					\
    WRITE_UNLOCK_IRQRESTORE(lockp, __flags);	\
} while(0)

#define SYNC_WLOCK_GOTO(lockp, label)		\
do {						\
    WRITE_UNLOCK_IRQRESTORE(lockp, __flags);	\
    goto label;					\
} while (0)


#define SYNC_RLOCK(lockp, code)			\
do {						\
    unsigned long __flags;			\
    READ_LOCK_IRQSAVE(lockp, __flags);		\
    code					\
    READ_UNLOCK_IRQRESTORE(lockp, __flags);	\
} while (0)

#ifdef CONFIG_SMP /* only SMP nodes need (and have) rw locks */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
#define _RAW_RWLOCK_
#else
#define _RAW_RWLOCK_ raw_lock.
#endif

#if   defined( __ia64 )
#define _READ_LOCKED(lockp) ((lockp)->_RAW_RWLOCK_ read_counter != 0)
#define _WRITE_LOCKED(lockp) (((lockp)->_RAW_RWLOCK_ write_lock) != 0)
#elif defined( __x86_64 )
#define _READ_LOCKED(lockp) ((lockp)->_RAW_RWLOCK_ lock != RW_LOCK_BIAS)
#define _WRITE_LOCKED(lockp) (((int)(lockp)->_RAW_RWLOCK_ lock) <= 0)
#elif defined( __powerpc64__ )
#define _READ_LOCKED(lockp) ((lockp)->_RAW_RWLOCK_ lock != 0)
#define _WRITE_LOCKED(lockp) (((int)(lockp)->_RAW_RWLOCK_ lock) <= 0)
#elif defined( __powerpc__ )
#define _READ_LOCKED(lockp) ((lockp)->_RAW_RWLOCK_ lock != 0)
#define _WRITE_LOCKED(lockp) (((int)(lockp)->_RAW_RWLOCK_ lock) <= 0)
#elif defined( __i386 )
#define _READ_LOCKED(lockp) ((lockp)->_RAW_RWLOCK_ lock != RW_LOCK_BIAS)
#define _WRITE_LOCKED(lockp) (((int)(lockp)->_RAW_RWLOCK_ lock) <= 0)
#else
#error Unknown architecture
#endif


#define READ_LOCK_ASSERT(lockp) do {		\
    P4_ASSERT(_READ_LOCKED(lockp));		\
} while (0)

#define WRITE_LOCK_ASSERT(lockp) do {		\
    P4_ASSERT(_WRITE_LOCKED(lockp));		\
} while (0)

#else /* !CONFIG_SMP */

#define READ_LOCK_ASSERT(lockp) do { } while(0)
#define WRITE_LOCK_ASSERT(lockp) do { } while(0)
#endif

#ifdef CONFIG_SMP /* only SMP nodes create a spin_lock with working spin_trylock! */

#define SPIN_LOCK(lockp)	spin_lock(&((lockp)->lock))
#define SPIN_UNLOCK(lockp)	spin_unlock(&((lockp)->lock))
#define SPIN_TRYLOCK(lockp)	spin_trylock(&((lockp)->lock))

#define SPIN_LOCK_ASSERT(lockp) do {		\
    P4_ASSERT(spin_is_locked(&(lockp)->lock));	\
} while (0)

typedef struct p4_spinlock_s {
    spinlock_t	lock;
} p4_spinlock_t;

#define P4_SPIN_LOCK_UNLOCKED (p4_spinlock_t){ .lock = SPIN_LOCK_UNLOCKED }

#else /* !CONFIG_SMP */

/* SPIN_LOCK() can never block on UP machines (if used correct).
 * Its not allowed, to use SPIN_LOCK inside a interrupthandler, but
 * you can use SPIN_TRYLOCK instead!
 * We just remember the state, for a try_lock.
 */
#define SPIN_LOCK(lockp)	(lockp)->up_locked = 1
#define SPIN_UNLOCK(lockp)	(lockp)->up_locked = 0
#define SPIN_TRYLOCK(lockp)	({		\
    int _tmp_ = (lockp)->up_locked;		\
    (lockp)->up_locked = 1;			\
    !_tmp_;					\
})

#define SPIN_IS_LOCKED(lockp) ((lockp)->up_locked)

#define SPIN_LOCK_ASSERT(lockp) do {		\
    P4_ASSERT(SPIN_IS_LOCKED(lockp));		\
} while (0)

typedef struct p4_spinlock_s {
    int		up_locked;
} p4_spinlock_t;

#define P4_SPIN_LOCK_UNLOCKED (p4_spinlock_t){ .up_locked = 0 }

#endif /* CONFIG_SMP */


char *dumpstr(void *buf, int size);

/* return 1 if assert failed */
#define P4_ASSERT_ALWAYS(comp) ({			\
    int ret = !(comp);					\
    if (ret) {						\
        DPRINT(KERN_ERR "assert(" #comp ") failed!\n");	\
    }							\
    ret;						\
})

#ifdef ENABLE_P4LOG
#include "p4log.h"
#define LOG_SENDENQ 1
#define LOG_TX      2
#define LOG_RXACK   3
#define LOG_RXDAT   4
#define LOG_RXWIN   5
#define LOG_SENDSTART   6
#define LOG_SENDSTOP    7
#define LOG_RECVSTART   8
#define LOG_RECVSTOP    9
#define LOG_RX___	10
#define LOG_RX__2	11
#define LOG_RX__3	12
#define LOG_SENDBUSY	13

#define P4LOG(type, value) p4log(type, value)
#else
#define P4LOG(type, value)
#endif


#ifndef XREF
#define _sinit( name ) .name =
#else
#define _sinit( name )
#endif

#include "ps_perf.h"

#endif /* _P4S_DEBUG_ */
