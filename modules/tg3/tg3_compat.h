#ifndef _TG3_COMPAT_H_
#define _TG3_COMPAT_H_


#if 0
//#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,20)

/* Remove interface from poll list: it must be in the poll list
 * on current cpu. This primitive is called by dev->poll(), when
 * it completes the work. The device cannot be out of poll list at this
 * moment, it is BUG().
 */
static inline void netif_rx_complete(struct net_device *dev)
{
	unsigned long flags;

	local_irq_save(flags);
	if (!test_bit(__LINK_STATE_RX_SCHED, &dev->state)) BUG();
	list_del(&dev->poll_list);
	smp_mb__before_clear_bit();
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
	local_irq_restore(flags);
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,24)
/*
 * netdevice.h (2.4.24)
 */

static inline void netif_poll_disable(struct net_device *dev)
{
	while (test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state)) {
		/* No hurry. */
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(1);
	}
}

static inline void netif_poll_enable(struct net_device *dev)
{
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

/* same as netif_rx_complete, except that local_irq_save(flags)
 * has already been issued
 */
static inline void __netif_rx_complete(struct net_device *dev)
{
	if (!test_bit(__LINK_STATE_RX_SCHED, &dev->state)) BUG();
	list_del(&dev->poll_list);
	smp_mb__before_clear_bit();
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

static inline void netif_tx_disable(struct net_device *dev)
{
	spin_lock_bh(&dev->xmit_lock);
	netif_stop_queue(dev);
	spin_unlock_bh(&dev->xmit_lock);
}


/*
 * interupt.h (2.4.24)
 */
typedef void irqreturn_t;
#define IRQ_RETVAL(x)

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,4,24) */


#endif /* _TG3_COMPAT_H_ */
