/*************************************************************fdb*
 * $Id$
 * Linux specific defines
 *************************************************************fde*/

#ifndef _P4LINUX_H_
#define _P4LINUX_H_

// #include <linux/config.h>

#ifdef MODULE
#include <linux/module.h>
#endif

#include <linux/version.h>
#ifndef KERNEL_VERSION
#  define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#ifndef LINUX_VERSION_CODE
  error "You need to use at least 2.2 Linux kernel."
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,2,0)
  error "You need to use at least 2.2 Linux kernel."
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,2,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define KERN26
#else
#define KERN24
#endif
#else
#define KERN22
#endif
#endif


#ifdef KERN22
#define P4_WAITQ_HEADVAR(name)	struct wait_queue *name
#define P4_WAITQ_INIT(wqh)	init_waitqueue(&(wqh))
#define P4_WAITQ_WAKEUP(wqh)	wake_up(&(wqh))
#define P4_WAITQ_VAR(name)	struct wait_queue name = {current,NULL}
#define P4_WAITQ_ADD(wqh,wq)	add_wait_queue(&(wqh),&(wq))
#define P4_WAITQ_REMOVE(wqh,wq) remove_wait_queue(&(wqh),&(wq))
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
#include <linux/wait.h>
#include <linux/sched.h>
#define P4_WAITQ_HEADVAR(name)	wait_queue_head_t name
#define P4_WAITQ_INIT(wqh)	init_waitqueue_head(&(wqh))
#define P4_WAITQ_WAKEUP(wqh)	wake_up(&wqh)
#define P4_WAITQ_VAR(name)	DECLARE_WAITQUEUE(name,current)
#define P4_WAITQ_ADD(wqh,wq)	add_wait_queue(&(wqh),&(wq))
#define P4_WAITQ_REMOVE(wqh,wq) remove_wait_queue(&(wqh),&(wq))
#endif

#ifdef XREF
#define P4_WAITQ_VAR(name)
#endif

/* Export symbol. */
#define P4_EXPORT_SYMBOL(var) EXPORT_SYMBOL(var)

#include <linux/times.h>

#ifndef USER_HZ
/* 2.4.x vanilla kernels */
#define USER_HZ HZ
/* No user - kernel translation of hz: */
#define jiffies_to_clock_t(x) x
#define clock_t_to_jiffies(x) x

#else /* USER_HZ */
/* with USER_HZ we expect to have also
   clock_t_to_jiffies() and
   jiffies_to_clock_t() */

#ifdef user_to_kernel_hz
/* exception: 2.4.21-111 SuSE patch, clock_t_to_jiffies is user_to_kernel_hz */
#define clock_t_to_jiffies(x)  user_to_kernel_hz(x)
#endif /* user_to_kernel_hz */

#endif /* USER_HZ */

#endif /* _P4LINUX_H_ */
