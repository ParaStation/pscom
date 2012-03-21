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

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <net/route.h>

#include "p4s_debug.h"
#include "p4prot.h"
#include "p4local.h"
#include "p4ether.h"

#include "p4rel.h"
#include "p4proc.h"

#ifdef P4REL_AS_INCLUDE
#include "p4rel.c"
#endif


#define P4ETHER_ResendTimeout	(HZ / 200 + 2 /* 5 ms + 2 HZ*/)
/* 120sec for HZ=100 is 23.4sec on HZ=512.
   (only if compiletime HZ differ from running kernel) */
#define P4ETHER_MaxResend	((120 /* 120 sec */* HZ) / P4ETHER_ResendTimeout)
#define P4ETHER_AckDelay	(HZ / 1000 + 1 /* 1 ms + 1 HZ */)
//#define P4ETHER_ResendTimeout	(1 + HZ / 2)
//#define P4ETHER_AckDelay	(HZ / 10)

#define P4ETHER_MaxSendQSize	360
#define P4ETHER_MaxRecvQSize	360
#define P4ETHER_MaxAcksPending	20
#define P4ETHER_MaxDevSendQSize 40
#define P4ETHER_MaxMTU		9000
#define P4ETHER_MinMTU		100

static const int MaxResendMinMax[]	= { 0	, 2000000	};
static const int ResendTimeoutMinMax[] = { 1	, 20 * HZ	};
static const int AckDelayMinMax[]	= { 0	, 20 * HZ	};
static const int MaxSendQSizeMinMax[]	= { 5	, 1000		};
static const int MaxRecvQSizeMinMax[]	= { 5	, 1000		};
static const int MaxAcksPendingMinMax[]= { 1	, 1000		};
static const int MaxDevSendQSizeMinMax[]= { 1	, 1000		};

static const int MaxMTUMinMax[]= { P4ETHER_MinMTU, P4ETHER_MaxMTU };

static int MaxSendQSize = P4ETHER_MaxSendQSize;
static int MaxDevSendQSize = P4ETHER_MaxDevSendQSize;

static int MaxMTU = P4ETHER_MaxMTU;
static int LastMTU = 0;

#ifdef ENABLE_P4ETHER_MAGIC
static const char p4ether_magic[4] = P4ETHER_MAGIC_END;
#endif

/*
 *  /proc/sys/ps4/ether
 */
ctl_table  ps4_sysctl_ps4_ether[] = {
    CTL_TABENTRY_MINMAX( 1, "MaxResend", &p4ether_opts.MaxResend, MaxResendMinMax),
    CTL_TABENTRY_MINMAX( 2, "ResendTimeout", &p4ether_opts.ResendTimeout, ResendTimeoutMinMax),
    CTL_TABENTRY_MINMAX( 3, "AckDelay", &p4ether_opts.AckDelay, AckDelayMinMax),
    CTL_TABENTRY_MINMAX( 4, "MaxSendQSize", &MaxSendQSize, MaxSendQSizeMinMax),
    CTL_TABENTRY_MINMAX( 5, "MaxRecvQSize", &p4ether_opts.MaxRecvQSize, MaxRecvQSizeMinMax),
    CTL_TABENTRY_MINMAX( 6, "MaxAcksPending", &p4ether_opts.MaxAcksPending, MaxAcksPendingMinMax),
    CTL_TABENTRY_MINMAX( 7, "MaxDevSendQSize", &MaxDevSendQSize, MaxDevSendQSizeMinMax),

    CTL_TABENTRY_MINMAX( 8, "MaxMTU", &MaxMTU, MaxMTUMinMax),
    CTL_TABENTRY_INTINFO( 9, ".last_mtu", &LastMTU),
    {ctl_name: 0}
};


typedef struct p4ether_frag_s {
    p4_frag_t	f;
    struct sk_buff *skb;
} p4ether_frag_t;


typedef struct p4msg_ether_syn_s {
    p4msg_syn_t p4syn;
    uint32_t	ipaddr; /* destination IP if mac is broadcast or 0 */
} p4msg_ether_syn_t;

/* default MTU */
#define P4ETHER_MTU (1450 - sizeof(p4msg_data_header_t))
//#define P4ETHER_MTU (ci->rem_saddr.tec.ether.netdev->mtu - sizeof(p4msg_data_header_t)-50)
//#define P4ETHER_MTU 1
//#define P4ETHER_RECVWINSIZE	100

#define ETH_P_P4_DAT	0x0814		/* P4 Packet Type 	*/
#define ETH_P_P4_CTRL	0x0816 		/* P4 Packet Type 	*/


#if P4_IFHWADDRLEN < IFHWADDRLEN
#error P4_IFHWADDRLEN to small
#endif

#if P4_IFNAMSIZ < IFNAMSIZ
#error P4_IFNAMSIZ to small
#endif


/* eth_hdr() is only available in kernels >= 2.6.9 */
static inline struct ethhdr *p4_eth_hdr(const struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
    return eth_hdr(skb);
#else
    return (struct ethhdr *)skb->mac.raw;
#endif
}


static inline void p4_skb_set_network_header(struct sk_buff *skb, const int offset)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    skb_set_network_header(skb, offset /* offset from skb->data */);
#else
    skb->nh.raw = skb->data + offset;
#endif
}

static inline unsigned char *p4_skb_network_header(const struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    return skb_network_header(skb);
#else
    return skb->nh.raw;
#endif
}


static inline struct net_device *p4_next_net_device(struct net_device *dev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    return next_net_device(dev);
#else
    return dev->next;
#endif
}


static inline struct net_device *p4_first_net_device(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
    return dev_base;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    return first_net_device();
#else
    return first_net_device(&init_net);
#endif
}


static inline struct kmem_cache *p4_kmem_cache_create(const char *name, size_t size,
					       size_t align, unsigned long flags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
    return kmem_cache_create(name, size,
			     align, flags, NULL /* ctor */);
#else
    return kmem_cache_create(name, size,
			     align, flags,
			     NULL /* ctor */, NULL /* dtor */);
#endif
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static kmem_cache_t *frame_cachep;
#else
static struct kmem_cache *frame_cachep;
#endif


static inline
int p4_dev_hard_header(struct sk_buff *skb, struct net_device *dev,
		       unsigned short type,
		       const void *daddr, const void *saddr,
		       unsigned len)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    return dev &&
	dev->hard_header &&
	(dev->hard_header(skb, dev, type,
			  (void*)daddr, (void*)saddr, len) < 0);
#else
    return dev && (dev_hard_header(skb, dev, type,
				   daddr, saddr, len) < 0);
#endif
}


static inline
struct net_device *p4_dev_get_by_name(const char *name)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    return dev_get_by_name(name);
#else
    return dev_get_by_name(&init_net, name);
#endif
}

static inline
unsigned int p4_inet_addr_type(uint32_t ip)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    return inet_addr_type(ip);
#else
    return inet_addr_type(&init_net, ip);
#endif
}


#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
static inline
int p4_netdev_has_poll_controller(struct net_device *net)
{
    return !!(net->netdev_ops && net->netdev_ops->ndo_poll_controller);
}


static inline
void p4_netdev_poll_controller(struct net_device *net)
{
    if (p4_netdev_has_poll_controller(net)) {
	net->netdev_ops->ndo_poll_controller(net);
    }
}

#else // before and including 2.6.28

static inline
int p4_netdev_has_poll_controller(struct net_device *net)
{
    return !!(net->poll_controller);
}


static inline
void p4_netdev_poll_controller(struct net_device *net)
{
    if (p4_netdev_has_poll_controller(net)) {
	net->poll_controller(net);
    }
}
#endif


static inline
void *alloc_frame(void)
{
    void *ret;
    ret = kmem_cache_alloc(frame_cachep, GFP_ATOMIC);
    return ret;
}

static inline
void free_frame(void *frame)
{
//    kfree(frame);
    kmem_cache_free(frame_cachep, frame);
}


static
void p4ether_frame_cache_init(void)
{
    frame_cachep = p4_kmem_cache_create("p4etherframe",
					sizeof(p4ether_frag_t),
					0,
					SLAB_HWCACHE_ALIGN);
    if (1) { /* fill cache */
	int i;
	void *arr[100];
	for (i = 0; i < 100; i++) {
	    arr[i] = alloc_frame();
	}
	for (i = 0; i < 100; i++) {
	    if (arr[i]) free_frame(arr[i]);
	}
    }
}

static
void p4ether_frame_cache_cleanup(void)
{
    kmem_cache_destroy(frame_cachep);
}

static
void p4ether_frag_free(p4ether_frag_t *f)
{
    FRAG_DEC;
    DP_ETHTRACE("%s(%d)\n", __func__, FRAGCNT);
    if (f->skb) {
	kfree_skb(f->skb);
	f->skb = NULL;
    }
    free_frame(f);
}


static inline
void p4ether_destruct_frag(p4_frag_t *f)
{
    p4ether_frag_t *ef = list_entry(f, p4ether_frag_t, f);
    p4ether_frag_free(ef);
}


static inline
p4ether_frag_t *p4ether_frag_new(struct sk_buff *skb, int size)
{
    p4ether_frag_t *ret;
    FRAG_INC;
    DP_ETHTRACE("%s(%d)\n", __func__, FRAGCNT);

    ret = (p4ether_frag_t *)alloc_frame();
    if (!ret) goto err_nomem;

    ret->skb = skb;

    ret->f.fsize = size;
    ret->f.foffset = 0;
    ret->f.Flags = 0;
    ret->f.destructor = p4ether_destruct_frag;
    atomic_set(&ret->f.refcnt, 1);

    return ret;
    /* --- */
 err_nomem:
    if (p4s_ratelimit())
	printk(KERN_WARNING "P4: %s(): kmalloc failed\n", __func__);
    if (skb) {
	kfree_skb(skb);
    }
    return NULL;
}

static inline
p4ether_frag_t *p4ether_sf_new(int size)
{
    struct sk_buff *skb;

    skb = alloc_skb(size + sizeof(p4msg_data_header_t) + ETH_HLEN + 16/*safety*/,
		    GFP_ATOMIC);
    if (!skb) goto err_noskb;

    return p4ether_frag_new(skb, size);
    /* --- */
 err_noskb:
    if (p4s_ratelimit())
	printk(KERN_WARNING "P4: %s(): alloc_skb failed\n", __func__);
    return NULL;
}

//static inline
//p4ether_frag_t *p4ether_rf_new(void)
//{
//    return p4ether_frag_new(NULL, 0);
//}


static
void p4ether_getremaddr(p4_remaddr_t *ra, p4_remserv_t *rs)
{
    p4_remserv_ether_t *ers = &rs->tec.ether;
    ra->type = P4REMADDR_ETHER;
    if (ers->netdev) {
	/* device and MAC */
	memcpy(&ra->tec.ether.addr.mac, ers->addr.mac, sizeof(ra->tec.ether.addr.mac));
	memcpy(&ra->tec.ether.devname, ers->netdev->name, sizeof(ra->tec.ether.devname));
    } else {
	/* IP address */
	ra->tec.ether.addr.ipaddr = ers->addr.ipaddr;
	memset(&ra->tec.ether.devname, 0, sizeof(ra->tec.ether.devname));
    }
}


static
int p4_inet_addr_onlink(struct in_device *in_dev, u32 a, u32 b)
{
    /* ToDo: missing locks! fixme! We should use inet_addr_onlink(). But there
       is no EXPORT_SYMBOL(inet_addr_onlink) */
//    rcu_read_lock();
    for_ifa/*for_primary_ifa*/(in_dev) {
	if (inet_ifa_match(a, ifa)) {
	    if (!b || inet_ifa_match(b, ifa)) {
//		rcu_read_unlock();
		return 1;
	    }
	}
    } endfor_ifa(in_dev);
//    rcu_read_unlock();
    return 0;
}


/* check if ip is a local IP.
   if dev != NULL : local IP AND from dev. */
static
int islocal(uint32_t ip, struct net_device *netdev)
{
    int ret = 0;

    if (ip == htonl(0x7f000001)) { /* 127.0.0.1 */
	DP_ETHTRACE("IP %u.%u.%u.%u is local\n", NIPQUAD(ip));
	return 1;
    }

    if (ntohl(ip) == p4_node_id) { /* Local p4_node_id */
	DP_ETHTRACE("PSID p4_node_id %d is local\n", p4_node_id);
	return 1;
    }
/*
    {
	struct net_device *dev;

	dev = ip_dev_find(ip);
	if (dev) {
	    int local;
	    DP_ETHTRACE("%s IP %u.%u.%u.%u is local\n", __func__,
			NIPQUAD(ip));
	    local = (dev == netdev) || (!netdev);
	    dev_put(dev);
	    return local;
	} else {
	    DP_ETHTRACE("%s IP %u.%u.%u.%u is not local\n", __func__,
			NIPQUAD(ip));
	    return 0;
	}
    }
*/
    if (!netdev) {
	unsigned int ntype = p4_inet_addr_type(ip);
	ret = (ntype == RTN_LOCAL);

	DP_ETHTRACE("IP %u.%u.%u.%u : type %d (local = %s)\n",
		    NIPQUAD(ip), ntype, ret ? "true" : "false");
    } else {
	struct in_device *in_dev = in_dev_get(netdev);

	if (!in_dev) return 0; // No IP on this device

	for_ifa(in_dev) {
	    DP_ETHTRACE("dev '%s' IP %u.%u.%u.%u\n",
			ifa->ifa_label, NIPQUAD(ifa->ifa_address));

	    ret |= (ifa->ifa_address == ip);
	} endfor_ifa(in_dev);

	in_dev_put(in_dev);

	DP_ETHTRACE("dev '%s' : IP %u.%u.%u.%u is%s local\n",
		    netdev->name, NIPQUAD(ip), ret ? "" : " not");
    }
    return ret;
}


static
int p4ether_recvmsg(struct p4_ci_s *ci, struct iovec *msg_iov,
		    p4_frag_t *rf, size_t fsize)
{
    int ret;
    p4ether_frag_t *erf = list_entry(rf, p4ether_frag_t, f);
    size_t packoffset;

    DP_ETHTRACE("%s():%d\n", __func__, __LINE__);

    packoffset = sizeof(p4msg_data_header_t) + rf->foffset;
    ret = memcpy_toiovec(msg_iov, erf->skb->data + packoffset, fsize);

    return ret ? -EINVAL : 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
static
int p4ether_recv_dat(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt)
#else
static
int p4ether_recv_dat(struct sk_buff *skb, struct net_device *dev,
		     struct packet_type *pt, struct net_device *orig_dev)
#endif
{
    p4ether_frag_t *erf;
    p4msg_data_header_t *dat;

    if (skb_linearize(skb))
	goto err_linearize;

    dat = (p4msg_data_header_t *)skb->data;

    DP_ETHTRACE("%s\n", __func__);

    if (0) {
	struct ethhdr *eth = p4_eth_hdr(skb);

	DPRINT("%s from MAC %02x:%02x:%02x:%02x:%02x:%02x to %02x:%02x:%02x:%02x:%02x:%02x\n",
	       __func__,
	       eth->h_source[0],eth->h_source[1], eth->h_source[2],
	       eth->h_source[3],eth->h_source[4], eth->h_source[5],
	       eth->h_dest[0],eth->h_dest[1], eth->h_dest[2],
	       eth->h_dest[3],eth->h_dest[4], eth->h_dest[5]);
    }

    if (dat->len + sizeof(*dat) > skb->len) goto err_shortread;

    erf = p4ether_frag_new(skb, dat->len);
    if (!erf) goto err_nomem;

    p4_net_receive(&erf->f, dat);

#ifdef ENABLE_P4ETHER_MAGIC
    {
	char *magic = (char *)dat + dat->len + sizeof(p4msg_data_header_t);
//	if (p4s_ratelimit())
//	    DPRINT(KERN_DEBUG "Recv Magic at %p = %02x%02x%02x%02x\n",
//		   magic, magic[0], magic[1], magic[2], magic[3]);
	*magic = 0; /* clear first byte of magic */
    }
#endif

    p4_frag_put(&erf->f);

    return 0;
 err_nomem:
    /* drop skb */
    return 0;
 err_shortread:
    /* drop skb. (lengthcheck failed) */
    if (p4s_ratelimit())
	printk(KERN_INFO "P4: %s(): short skb dropped.\n", __func__);
    kfree_skb(skb);
    return 0;
 err_linearize:
    if (p4s_ratelimit())
	printk(KERN_INFO "P4: %s(): skb_linearize(skb) failed. skb dropped.\n", __func__);
    kfree_skb(skb);
    return 0;
}

/*
 * polling via poll_controler
 */

static struct list_head p4ether_polling_list = LIST_HEAD_INIT(p4ether_polling_list);

struct p4ether_polling {
    struct list_head next;
    struct net_device *netdev;
    unsigned int users;
};


void p4ether_poll(void)
{
#ifdef CONFIG_NET_POLL_CONTROLLER
    struct list_head *pos;
    struct p4ether_polling *p;

    list_for_each(pos, &p4ether_polling_list) {
	struct net_device *net;

	p = list_entry(pos, struct p4ether_polling, next);
	net = p->netdev;

	p4_netdev_poll_controller(net);
    }
#endif
}


static
p4_pollfunc_t p4ether_poll_ops = {
	.next = LIST_HEAD_INIT(p4ether_poll_ops.next),
	.func = p4ether_poll
};


static
struct p4ether_polling *p4ether_poll_hold(struct p4ether_polling *poll)
{
    poll->users ++;

    DPRINT(KERN_DEBUG "P4ETH: p4ether_poll_hold(): dev='%s', ref=%d\n", poll->netdev->name, poll->users);

    return poll;
}


static
void p4ether_poll_put(struct p4ether_polling *poll)
{
    DPRINT(KERN_DEBUG "P4ETH: p4ether_poll_put (): dev='%s', ref=%d\n", poll->netdev->name, poll->users);
    poll->users --;
    if (!poll->users) {
	list_del(&poll->next); /* dequeue */
	kfree(poll);
    }
}


struct p4ether_polling *_p4ether_poll_get_by_netdev(struct net_device *netdev)
{
    struct list_head *pos;
    struct p4ether_polling *p;

    list_for_each(pos, &p4ether_polling_list) {
	p = list_entry(pos, struct p4ether_polling, next);
	if (netdev == p->netdev) {
	    return p;
	}
    }
    return NULL;
}


static
void _p4ether_poll_add(struct net_device *netdev)
{
    struct p4ether_polling *p;

    p = _p4ether_poll_get_by_netdev(netdev);

    if (!p) {
	/* New entry */
	p = (struct p4ether_polling *) kmalloc(sizeof(*p), GFP_ATOMIC);

	if (!p) return; /* out of mem? */

	p->users = 0;
	p->netdev = netdev;

	if (list_empty(&p4ether_polling_list)) {
	    DPRINT(KERN_DEBUG "P4ETH: p4_poll_add()\n");
	    p4_poll_add(&p4ether_poll_ops);
	}
	list_add(&p->next, &p4ether_polling_list);
    }

    p4ether_poll_hold(p);
}


static
void _p4ether_poll_del(struct net_device *netdev)
{
    struct p4ether_polling *p;

    p = _p4ether_poll_get_by_netdev(netdev);

    if (p) {
	p4ether_poll_put(p);
	p = NULL;

	if (list_empty(&p4ether_polling_list)) {
	    DPRINT(KERN_DEBUG "P4ETH: p4_poll_del()\n");
	    p4_poll_del(&p4ether_poll_ops);
	}

    }
}


/* ToDo: test poll_controler and reenable it! */
#define DISABLE_ETHER_POLLING 1


#ifndef CONFIG_NET_POLL_CONTROLLER
#ifndef DISABLE_ETHER_POLLING
#warning "psglue: Kernel without CONFIG_NET_POLL_CONTROLLER!"
#endif
#endif

static
void p4ether_poll_add(p4_ci_t *ci)
{
    struct net_device *netdev = ci->rem_saddr.tec.ether.netdev;
    if (netdev) {
#ifdef CONFIG_NET_POLL_CONTROLLER
	int enabled = 1;
#ifdef DISABLE_ETHER_POLLING
	enabled = 0;
#endif /* DISABLE_ETHER_POLLING */
	if (enabled && p4_netdev_has_poll_controller(netdev)) {
	    _p4ether_poll_add(netdev);
	}
#endif /* CONFIG_NET_POLL_CONTROLLER */
    } else {
	printk(KERN_ERR "P4S: Error: p4ether_poll_add() without net_device!\n");
    }
}


static
void p4ether_poll_del(p4_ci_t *ci)
{
    struct net_device *netdev = ci->rem_saddr.tec.ether.netdev;
    if (netdev) {
	/* delete a netdev with netdev->poll_controler == NULL is ok.
	 * delete without add is ok. */
	_p4ether_poll_del(netdev);
    } else {
	printk(KERN_ERR "P4S: Error: p4ether_poll_del() without net_device!\n");
    }
}


/*
 * end polling
 */


static
void p4ether_adjust_mtu(p4_ci_t *ci)
{
    struct net_device *netdev = ci->rem_saddr.tec.ether.netdev;
    if (netdev) {
	ci->u.eth.mtu = MAX(P4ETHER_MinMTU,
			    MIN(MaxMTU,
				netdev->mtu - sizeof(p4msg_data_header_t) - 50));
	LastMTU = ci->u.eth.mtu;
    }
}

static
void p4ether_set_rem_saddr(p4_ci_t *ci, p4_remserv_t *rs)
{
    if (ci && !ci->rem_saddr.tec.ether.netdev && rs->tec.ether.netdev) {
	/* set netdev and mac from remoteside */
	memcpy(&ci->rem_saddr.tec.ether.addr.mac, &rs->tec.ether.addr.mac,
	       sizeof(rs->tec.ether.addr.mac));
	/* we now use this device */
	dev_hold(rs->tec.ether.netdev);
	ci->rem_saddr.tec.ether.netdev = rs->tec.ether.netdev;
	p4ether_adjust_mtu(ci);
	p4ether_poll_add(ci);
    }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
static
int p4ether_recv_ctrl(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt)
#else
static
int p4ether_recv_ctrl(struct sk_buff *skb, struct net_device *dev,
		      struct packet_type *pt, struct net_device *orig_dev)
#endif
{
    p4_remserv_t rs;
    struct ethhdr *eth = p4_eth_hdr(skb);
    p4msg_ctrl_t *msg = (p4msg_ctrl_t *)skb->data;

    DP_ETHTRACE("%s() from MAC %02x:%02x:%02x:%02x:%02x:%02x type %d\n", __func__,
		eth->h_source[0],eth->h_source[1], eth->h_source[2],
		eth->h_source[3],eth->h_source[4], eth->h_source[5],
		msg->type
	);

    memcpy(&rs.tec.ether.addr.mac, &eth->h_source, sizeof(eth->h_source));
    rs.tec.ether.netdev = dev;

    if (msg->type != P4TYPE_SYN) {
	p4_net_recv_ctrl(&p4ether_opts, &rs, msg);
    } else {
	/* SYN need a check here. */
	p4msg_syn_t *syn = &msg->t.syn;
	int match = 0;
	if (syn->destsaddr.type != P4REMADDR_ETHER) goto err_synremaddr;

	/* Mybe we should check skb->pkt_type==PACKET_BROADCAST to avoid the memcmp */
	if (!syn->destsaddr.tec.ether.devname[0]) {
	    /* Etherdev name from sender is NOT specified.
	       Use IP or PSID for comparison. */
	    match = islocal(syn->destsaddr.tec.ether.addr.ipaddr, dev);
	    /*
	    DPRINT("%s() from MAC %02x:%02x:%02x:%02x:%02x:%02x SYN check local %d dev %s\n",
		   eth->h_source[0],eth->h_source[1], eth->h_source[2],
		   eth->h_source[3],eth->h_source[4], eth->h_source[5],
		   match, dev ? dev->name : "<NULL>");
	    */
	} else {
	    /* Etherdev name from sender IS specified. Compare the MAC addresses.
	       Maybe compare also syn->destsaddr.tec.ether.mac with local mac? */
	    match = !memcmp(eth->h_dest, dev->dev_addr, sizeof(eth->h_dest));
	    /*
	    DPRINT("%s() from MAC %02x:%02x:%02x:%02x:%02x:%02x SYN MAC match dev %s\n",
		   eth->h_source[0],eth->h_source[1], eth->h_source[2],
		   eth->h_source[3],eth->h_source[4], eth->h_source[5],
		   dev ? dev->name : "<NULL>");
	    */
	}
	if (match) {
	    p4_net_recv_ctrl(&p4ether_opts, &rs, msg);
	}
    }

 bye:
    kfree_skb(skb);
    return 0;
 err_synremaddr:
    DPRINT("%s(): SYN: assert(syn->destsaddr.type == P4REMADDR_ETHER) failed!\n", __func__);
    goto bye;
}

static
struct packet_type p4pt_dat =
{
    _sinit(type)  __constant_htons(ETH_P_P4_DAT),
    _sinit(dev)  NULL, /* wildcard */
    _sinit(func) p4ether_recv_dat,
//    _sinit(data) (void*)0, /* No shared skb */
//    _sinit(next) NULL
};

static
struct packet_type p4pt_ctrl =
{
    _sinit(type)  __constant_htons(ETH_P_P4_CTRL),
    _sinit(dev)  NULL, /* wildcard */
    _sinit(func) p4ether_recv_ctrl,
//    _sinit(data) (void*)0, /* No shared skb */
//    _sinit(next) NULL
};


int p4ether_netif_rx(struct sk_buff *skb)
{
    if (!in_irq()) {
	if (skb->protocol == __constant_htons(ETH_P_P4_DAT)) {
	    p4_skb_set_network_header(skb, 0);
	    // skb->h.raw = skb->nh.raw = skb->data;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
	    p4ether_recv_dat(skb, skb->dev, NULL);
#else
	    p4ether_recv_dat(skb, skb->dev, NULL, NULL);
#endif
//	    if (in_irq() && p4s_ratelimit()) {
//		DPRINT(KERN_DEBUG "P4ETH: Receive direct DATA\n");
//	    }
	    return 0;
	} else if (skb->protocol == __constant_htons(ETH_P_P4_CTRL)) {
	    p4_skb_set_network_header(skb, 0);
	    // skb->h.raw = skb->nh.raw = skb->data;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
	    p4ether_recv_ctrl(skb, skb->dev, NULL);
#else
	    p4ether_recv_ctrl(skb, skb->dev, NULL, NULL);
#endif
//	    if (in_irq() && p4s_ratelimit()) {
//		DPRINT(KERN_DEBUG "P4ETH: Receive direct CTRL\n");
//	    }
	    return 0;
	} else {
	    return netif_rx(skb);
	}
    } else {
	    return netif_rx(skb);
    }
}

int p4ether_netif_rx_try(struct sk_buff *skb)
{
    if (!in_irq()) {
	if (skb->protocol == __constant_htons(ETH_P_P4_DAT)) {
	    p4_skb_set_network_header(skb, 0);
	    // skb->h.raw = skb->nh.raw = skb->data;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
	    p4ether_recv_dat(skb, skb->dev, NULL);
#else
	    p4ether_recv_dat(skb, skb->dev, NULL, NULL);
#endif
//	    if (in_irq() && p4s_ratelimit()) {
//		DPRINT(KERN_DEBUG "P4ETH: Receive direct DATA\n");
//	    }
	    return 0;
	} else if (skb->protocol == __constant_htons(ETH_P_P4_CTRL)) {
	    p4_skb_set_network_header(skb, 0);
	    // skb->h.raw = skb->nh.raw = skb->data;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
	    p4ether_recv_ctrl(skb, skb->dev, NULL);
#else
	    p4ether_recv_ctrl(skb, skb->dev, NULL, NULL);
#endif
//	    if (in_irq() && p4s_ratelimit()) {
//		DPRINT(KERN_DEBUG "P4ETH: Receive direct CTRL\n");
//	    }
	    return 0;
	} else {
	    return -1;
	}
    } else {
	    return -1;
    }
}




static
void p4ether_header_dat_hw(struct p4_ci_s *ci, p4ether_frag_t *f)
{
    struct sk_buff *skb = f->skb;

    skb->dev = ci->rem_saddr.tec.ether.netdev;

    skb->protocol =  __constant_htons(ETH_P_P4_DAT);

    /* Build ether header */
    if (p4_dev_hard_header(skb, skb->dev, ETH_P_P4_DAT,
			   ci->rem_saddr.tec.ether.addr.mac/*dest_hw*/,
			   NULL/*src_hw*/,
			   skb->len)) {
	/* Ignore the error ... goto error_hardheader;*/
    }

    if (0) {
	struct ethhdr *eth = p4_eth_hdr(skb);

	DPRINT("%s from MAC %02x:%02x:%02x:%02x:%02x:%02x to %02x:%02x:%02x:%02x:%02x:%02x\n",
	       __func__,
	       eth->h_source[0],eth->h_source[1], eth->h_source[2],
	       eth->h_source[3],eth->h_source[4], eth->h_source[5],
	       eth->h_dest[0],eth->h_dest[1], eth->h_dest[2],
	       eth->h_dest[3],eth->h_dest[4], eth->h_dest[5]);
    }

    return;
}

static inline
void p4ether_header_dat_ps4(struct p4_ci_s *ci, p4ether_frag_t *f, size_t msgsize, int flags)
{
    p4msg_data_header_t *msghead = (p4msg_data_header_t *) p4_skb_network_header(f->skb)
    DP_ETHTRACE("%s(): %p prepared header address\n", __func__, msghead);

    p4_build_header_dat(ci, &f->f, msghead, msgsize, flags);

    return;
}

static inline
void p4ether_header_dat_ps4_update(struct p4_ci_s *ci, p4ether_frag_t *f)
{
    p4msg_data_header_t *msghead = (p4msg_data_header_t *) p4_skb_network_header(f->skb)
    DP_ETHTRACE("%s(): %p updated header address\n", __func__, msghead);
    p4_update_header_dat(ci, msghead);
    return;
}

static
void p4ether_skb_destructor(struct sk_buff *skb)
{
    p4_ci_t *ci = *(p4_ci_t **)&(skb->cb[0]);
    atomic_dec(&ci->dev_SendQsize);
    p4_delayed_continue_send(ci);
    p4_ci_put(ci);
}

/* Transmit cloned skb */
static
int p4ether_xmit_countedclone(p4_ci_t *ci, p4ether_frag_t *esf)
{
    struct sk_buff *skbclone = skb_clone(esf->skb, GFP_ATOMIC);
    int ret;

    if (!skbclone) goto err_noclone;

//	look here for usage of skb->destructor : skb_set_owner_w(skb2, sk);
    atomic_inc(&ci->dev_SendQsize);
    skbclone->destructor = p4ether_skb_destructor;
    *(p4_ci_t **)&(skbclone->cb[0]) = ci;
    p4_ci_hold(ci);

    if (0) {
	static p4_seqno_t nextseqno = 0;
	static int nextseqnoerr = 0;
	if (esf->f.SeqNo != nextseqno) {
	    nextseqnoerr++;
	    if (p4s_ratelimit()){
		DPRINT(KERN_DEBUG " nextseqnoerr (%d)\n", nextseqnoerr);
	    }
	}
	nextseqno = esf->f.SeqNo + 1;
    }

    /* dev_queue_xmit() will always call kfree_skb(skbclone). Also on error! */
    ret = dev_queue_xmit(skbclone);

    P4LOG(LOG_TX, esf->f.SeqNo);
    if (ret) {
	static int err=0;
	err++;
	if (p4s_ratelimit()){
	    DPRINT(KERN_DEBUG "dev_queue_xmit() return %d (%d)\n", ret, err);
	}
    } else {
	p4_small_ack_sent(ci);
	proc_send_net_data_cnt++;
#if 0
	{
	    static p4_seqno_t lastseq=0;
	    static unsigned long lastjif = 0;
	    if (p4_seqcmp(lastseq + 1, esf->sf.SeqNo) != 0) {
		proc_test++;
		if (p4s_ratelimit()){
		    DPRINT(KERN_DEBUG "Seqdouble %7d %7d %4d\n", lastseq, esf->sf.SeqNo,
			   (int)(jiffies - lastjif));
		}
	    }
	    lastseq = esf->sf.SeqNo;
	    lastjif = jiffies;
	}
#endif
    }
    return ret;
 err_noclone:
    return -EBUSY;
}


static inline
int p4ether_can_xmit(p4_ci_t *ci, p4_seqno_t seqno)
{
    /* Window open, lowlevel sendq free, remote address defined, netdev running */

    return (p4_seqcmp(seqno, ci->s.SWindow) <= 0) &&
	(atomic_read(&ci->dev_SendQsize) < MaxDevSendQSize) &&
	(ci->rem_saddr.tec.ether.netdev &&
	 !netif_queue_stopped(ci->rem_saddr.tec.ether.netdev));
}

static
int p4ether_net_send_frag(p4_ci_t *ci, p4_frag_t *sf)
{
    p4ether_frag_t *esf = list_entry(sf, p4ether_frag_t, f);
    int ret;
    int xmit;
    DP_ETHTRACE("%s\n", __func__);

    xmit = p4ether_can_xmit(ci, esf->f.SeqNo);
    if (esf->skb->dev && xmit) {
	/* Transmit skb */
	p4ether_header_dat_ps4_update(ci, esf);
//#warning Debug
//	{
//	    if (jiffies % 10 != 0) {
	ret = p4ether_xmit_countedclone(ci, esf);

//	    } else {
//		ret = 0;
//	    }
//	}
	return ret;
    } else {
	P4LOG(LOG_SENDBUSY, esf->f.SeqNo);
	return -EBUSY;
    }
}

static
int p4ether_dev_send(struct net_device *dev, void *dmac, int prot,
		      void *msg, int len)
{
    struct sk_buff *skb;

    /* if this function is called at interrupttime, we need GFP_ATOMIC! */
    skb = alloc_skb(len + (ETH_HLEN + 16 /*safety*/), GFP_ATOMIC);
    if (!skb) goto err_noskb;

    skb->dev = dev;

    skb->protocol = __constant_htons(prot);
    /* skb_reserve(skb, (skb->dev->hard_header_len+15)&~15); */
    skb_reserve(skb, (ETH_HLEN + 16 /*safety*/));
    p4_skb_set_network_header(skb, 0);

    /* Build ether header */
    if (p4_dev_hard_header(skb, dev, prot,
			   dmac/*dest_hw*/,
			   NULL/*src_hw*/,
			   skb->len)){
	/* Ignore the error ... goto error_hardheader;*/
    }

    memcpy(skb_put(skb, len), msg, len);

    return dev_queue_xmit(skb);
 err_noskb:
    if (p4s_ratelimit())
	printk(KERN_WARNING "P4: %s(): alloc_skb failed\n", __func__);
//    return -ENOMEM;
    return -EAGAIN;
}


/*
  Create one fragment and send the fragment if possible.
  I : ci->
  IO: msg_iov
  IO: msgsize
  O : sf

*/
static
int p4ether_sendmsg(p4_ci_t *ci, struct iovec *msg_iov, size_t *msgsize, p4_frag_t **sf)
{
    p4ether_frag_t *esf;

    int cflags;
    size_t csize;
    int ret;
    int xmit;
    unsigned char *msghead; /* (p4msg_data_header_t *) */

    if (p4_sendqsize(ci) >= MaxSendQSize)
	goto err_busy;

    if (*msgsize <= ci->u.eth.mtu /* P4ETHER_MTU */) {
	/* last fragment */
	csize = *msgsize;
	cflags = P4_FFLAGS_LASTFRAG;
    } else {
	csize = ci->u.eth.mtu /* P4ETHER_MTU */;
	cflags = 0;
    }

    esf = p4ether_sf_new(csize);
    if (!esf) goto err_nobuf; /* busy or out of mem*/

    skb_reserve(esf->skb, (16 /*safety*/) + ETH_HLEN);

    msghead = skb_put(esf->skb, sizeof(p4msg_data_header_t));

    p4_skb_set_network_header(esf->skb, msghead - esf->skb->data);

    /* Copy Data */
    ret = memcpy_fromiovec(skb_put(esf->skb, csize), msg_iov, csize);
    if (ret) goto err_memcpy;

#ifdef ENABLE_P4ETHER_MAGIC
    /* Copy Ether Magic */
    memcpy(skb_put(esf->skb, 4), p4ether_magic, 4);
#endif

    /* Build HW header */
    p4ether_header_dat_hw(ci, esf);

    /* Build PS4 header */
    p4ether_header_dat_ps4(ci, esf, csize, cflags);

    xmit = p4ether_can_xmit(ci, ci->s.SSeqNo) &&
	(p4_seqcmp(ci->s.SUntil + 1, ci->s.SSeqNo) == 0);

    if (xmit) {
	if (!p4ether_xmit_countedclone(ci, esf)) {
	    /* No errors */
	    ci->s.SUntil = ci->s.SSeqNo;
	}
    } else {
	P4LOG(LOG_SENDBUSY, esf->f.SeqNo);
    }

    *sf = &esf->f;
    *msgsize -= csize;

    return 0;
    /* ----- */
 err_busy:
    return -EAGAIN;
    /* ----- */
 err_nobuf:
//    return -ENOBUFS;
    return -EAGAIN;
    /* ----- */
 err_memcpy:
    p4_frag_put(&esf->f);
    return -EINVAL;
}


static
int p4ether_net_send_ctrl(p4_remserv_t *rs, p4msg_ctrl_t *msg, size_t msgsize)
{
    struct net_device *dev;
    void *dmac;
    int all_if;

    DP_ETHTRACE("%s() len:%d Type %s\n", __func__, (int)msgsize,
		P4TYPESTR(msg->type));

    all_if = !rs->tec.ether.netdev;

    if (all_if) {
	int cnt = 0;
	read_lock(&dev_base_lock);

	for (dev = p4_first_net_device(); dev != NULL; dev = p4_next_net_device(dev)) {
	    struct in_device *in_dev;

	    dev_hold(dev);
	    read_unlock(&dev_base_lock);

	    in_dev = in_dev_get(dev);
	    if (in_dev) {
		if (p4_inet_addr_onlink(in_dev, rs->tec.ether.addr.ipaddr, 0)) {
		    /* Send message through all interfaces where ipaddr is onlink */
		    dmac = dev->broadcast;
		    p4ether_dev_send(dev, dmac, ETH_P_P4_CTRL, msg, msgsize);
		    cnt ++;
		}
		in_dev_put(in_dev);
	    }

	    read_lock(&dev_base_lock);
	    /* ToDo: is dev_put allowed inside the lock? */
	    dev_put(dev);
	}
	read_unlock(&dev_base_lock);
	if ((cnt != 1) && p4s_ratelimit()) {
	    printk(KERN_WARNING "P4S: warning: p4ether_net_send_ctrl() to IP %u.%u.%u.%u"
		   " via %d interfaces.\n", NIPQUAD(rs->tec.ether.addr.ipaddr), cnt);
	}
	return 0;
    } else {
	dev = rs->tec.ether.netdev;
	if (!dev) goto err_no_dev;
	dmac = rs->tec.ether.addr.mac;

	return p4ether_dev_send(dev, dmac, ETH_P_P4_CTRL, msg, msgsize);
    }
    return 0;
 err_no_dev:
    return -ENODEV;
}

static
int p4ether_isequal(p4_ci_t *ci, p4_remaddr_t *ra, p4msg_syn_t *syn)
{
    int ret;
    /* We compare only the MAC addresses */
    ret = memcmp(&ci->rem_saddr.tec.ether.addr.mac,
		 ra->tec.ether.addr.mac,
		 sizeof(ci->rem_saddr.tec.ether.addr.mac));
    ret = !ret;
    return ret;
}

static
int p4ether_init_ci(p4_ci_t *ci, p4_remaddr_t *ra, int ralen)
{
    p4_remaddr_ether_t *ei = &ra->tec.ether;
    p4_remserv_ether_t *eo = &ci->rem_saddr.tec.ether;
    DP_ETHTRACE("%s ralen:%d sof(ra) : %d\n", __func__,
		ralen, (int)sizeof(*ei));

    if (ralen < sizeof(ra->type) + sizeof(*ei)) goto error_shortaddr;

    if (ei->devname[0] != 0) {
	/* Remote address by devicename and MAC */

	eo->netdev = p4_dev_get_by_name(ei->devname); /* dev_get_by_name() call dev_hold()! */
	if (!eo->netdev) goto error_nodev;

	memcpy(&eo->addr.mac, &ei->addr.mac, sizeof(eo->addr.mac));

	p4ether_adjust_mtu(ci);
	p4ether_poll_add(ci);

	goto ok;
    } else {
	/* Remote address by IP address */
	if (islocal(ei->addr.ipaddr, NULL)) {
	    /* Change to local com */
	    p4_remaddr_t lra;
	    lra.type = P4REMADDR_LOCAL;
	    ci->net_opts = &p4local_opts;
	    return ci->net_opts->init_ci(ci, &lra, sizeof(lra));
	}
	eo->netdev = NULL; /* use broadcast syn to all devices */
	eo->addr.ipaddr = ei->addr.ipaddr;

	goto ok;
    }

 ok:
    atomic_set(&ci->dev_SendQsize, 0);
    /* First set to default MTU. This value will be changed, when we know the final netdev. */
    ci->u.eth.mtu = P4ETHER_MTU;
    return 0;
 error_shortaddr:
    return -EINVAL;
 error_nodev:
    return -ENODEV;
}


static
void p4ether_cleanup_ci(p4_ci_t *ci)
{
    p4_remserv_ether_t *eo = &ci->rem_saddr.tec.ether;

    p4ether_poll_del(ci);
    if (eo->netdev) {
	dev_put(eo->netdev);
	eo->netdev = NULL;
	eo->addr.ipaddr = 0;
    }
}

int p4ether_init(void)
{
    DP_ETHTRACE("%s INIT\n", __func__);
    p4ether_frame_cache_init();

    dev_add_pack(&p4pt_dat);
    dev_add_pack(&p4pt_ctrl);

    return 0;
}

void p4ether_cleanup(void)
{
    dev_remove_pack(&p4pt_dat);
    dev_remove_pack(&p4pt_ctrl);

    p4ether_frame_cache_cleanup();
}



p4_net_opts_t p4ether_opts = {
    _sinit(MaxResend)	P4ETHER_MaxResend,	/* maximal retrys for resend */

    _sinit(ResendTimeout)	P4ETHER_ResendTimeout,	/* timeout until resend in jiffies */
    _sinit(AckDelay)		P4ETHER_AckDelay,

    _sinit(MaxRecvQSize)	P4ETHER_MaxRecvQSize,
    _sinit(MaxAcksPending)	P4ETHER_MaxAcksPending,

    _sinit(sendmsg)		p4ether_sendmsg,
    _sinit(recvmsg)		p4ether_recvmsg,
    _sinit(net_send_frag)	p4ether_net_send_frag,
    _sinit(net_send_ctrl)	p4ether_net_send_ctrl,
    _sinit(isequal)		p4ether_isequal,
    _sinit(set_rem_saddr)	p4ether_set_rem_saddr,
    _sinit(init_ci)		p4ether_init_ci,
    _sinit(cleanup_ci)		p4ether_cleanup_ci,
    _sinit(getremaddr)		p4ether_getremaddr
};

P4_EXPORT_SYMBOL(p4ether_netif_rx);
P4_EXPORT_SYMBOL(p4ether_netif_rx_try);
