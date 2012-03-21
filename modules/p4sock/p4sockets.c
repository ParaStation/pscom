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
 * p4sockets.c: socket interface
 */

/* 2001-06-08 Jens Hauke */
/* 2002-03-27 Jens Hauke */

#include <linux/kernel.h>
// #include <linux/config.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <net/ip.h>
#include <asm/uaccess.h>
#include <linux/poll.h>
#include <net/inet_common.h>


//  #include "dump.c"
//  //#include "mod_socket.c"
//  #include "ps_types.h"
//  #include "pshal.h"
//  #include "psm_mcpif.h"

//#include "port_hash.h"
#include "p4s_debug.h"
#include "p4prot.h"
#include "p4sockets.h"
#include "p4io_old.h"

static char vcid[] __attribute__(( unused )) =
"$Id$";

char *p4_typestrs[] = P4TYPESTRS;

#define MIN(a,b)      (((a)<(b))?(a):(b))
#define MAX(a,b)      (((a)>(b))?(a):(b))

//#define P4SLdeb( fmt ) PRINT_TRACE( fmt"\n" )
#define P4SLdeb( fmt )

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define P4S_SOCK_PROTINFO( sock ) (*(p4_socket_t**)&(sock)->protinfo.af_inet)
#else
#define P4S_SOCK_PROTINFO( sock ) (*(p4_socket_t**)&(sock)->sk_protinfo)
#endif


/* To debug connect bind accept... */

//#define P4S_RATE (5*HZ)
#define P4S_RATE (1*USER_HZ)
static unsigned int p4s_msg_cost = P4S_RATE;
static unsigned int p4s_msg_burst = 20*P4S_RATE;
/*
 * This enforces a rate limit: not more than one kernel message
 * every 5secs to make a denial-of-service attack impossible.
 *
 * All warning printk()s should be guarded by this function.
 */
int p4s_ratelimit(void)
{
    static spinlock_t ratelimit_lock = SPIN_LOCK_UNLOCKED;
    static unsigned long toks = 20*P4S_RATE;
    static unsigned long last_msg;
    static int missed;
    unsigned long flags;
    unsigned long now = jiffies;

    spin_lock_irqsave(&ratelimit_lock, flags);
    toks += jiffies_to_clock_t(now - last_msg);
    last_msg = now;
    if (toks > p4s_msg_burst)
	toks = p4s_msg_burst;
    if (toks >= p4s_msg_cost) {
	int lost = missed;
	missed = 0;
	toks -= p4s_msg_cost;
	spin_unlock_irqrestore(&ratelimit_lock, flags);
	if (lost)
	    printk(KERN_WARNING "P4S: %d messages suppressed.\n", lost);
	return 1;
    }
    missed++;
    spin_unlock_irqrestore(&ratelimit_lock, flags);
    return 0;
}


static atomic_t p4s_usecnt = ATOMIC_INIT(0);

int p4s_inc_usecount(void)
{
    int ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    MOD_INC_USE_COUNT;
    ret = 1;
#else
    ret = try_module_get(THIS_MODULE);
#endif
    if (ret) {
	atomic_inc(&p4s_usecnt);
    }
    DP_REFCNT("%s() : Users %d (ret = %d)\n", __func__ , atomic_read(&p4s_usecnt), ret);
    return ret;
}

void p4s_dec_usecount(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    MOD_DEC_USE_COUNT;
#else
    module_put(THIS_MODULE);
#endif
    atomic_dec(&p4s_usecnt);
    DP_REFCNT("%s() : Users %d\n", __func__ , atomic_read(&p4s_usecnt));
}


static
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
int p4s_sendmsg(struct socket *sock, struct msghdr *msg, int size,
 		struct scm_cookie *scm)
#else
int p4s_sendmsg(struct kiocb *iocb, struct socket *sock,
		struct msghdr *msg, size_t size)
#endif
{
    int ret;
    p4_socket_t *socket;
    int lidx;
    DP_SOCKTRACE("%s()\n", __func__);

    socket = P4S_SOCK_PROTINFO(sock->sk);
    if ( msg->msg_name ){
        lidx = socket->last_idx = *(uint16_t *)msg->msg_name;
    }else{
        lidx = socket->last_idx;
    }
    ret = p4_sendmsg(socket , lidx, msg->msg_iov, size, msg->msg_flags);
    DP_SOCKTRACE("%s() done\n", __func__);
    return ret;
}

static
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
int p4s_recvmsg(struct socket *sock, struct msghdr *msg, int size,
		int flags, struct scm_cookie *scm)
#else
int p4s_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t size,
		int flags)
#endif
{
    int ret;
    DP_SOCKTRACE("%s()\n", __func__);
    ret = p4_recvmsg(P4S_SOCK_PROTINFO( sock->sk ), msg->msg_iov,
		     (uint16_t *)msg->msg_name, size, flags);
    DP_SOCKTRACE("%s() done\n", __func__);

    return ret;
}


/*
 *	The peer socket should always be NULL (or else). When we call this
 *	function we are destroying the object and from then on nobody
 *	should refer to it.
 */
static
int p4s_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    DP_SOCKTRACE("%p Release Socket(type %d) skrefs %d dctor %p\n",
		 sock, sock->type,
		 sk->sk_refcnt.counter,
		 sk->sk_destruct);

    p4_socket_close(P4S_SOCK_PROTINFO(sk));
    P4S_SOCK_PROTINFO(sk) = NULL;

    sock_orphan(sk);
    sock->sk = NULL;
    sock_put(sk);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    p4s_dec_usecount();
#endif
    return 0;
}


static
unsigned int
p4s_poll(struct file * file, struct socket *sock,poll_table *wait)
{
    DP_SOCKTRACE("%p %s()\n",sock, __func__);
    return p4_socket_poll(file, P4S_SOCK_PROTINFO( sock->sk ), wait);
}

/*
void p4s_dump_iovec(struct iovec *msg_iov,size_t msg_iovlen,int len,char *desc)
{
    int i;
    char buf [256];
    int siz=0;
    int nl;

    if (len > sizeof(buf))
	len=sizeof(buf);
    for (i=0;(i<msg_iovlen)&&(len>0);i++){
	nl =MIN(msg_iov[i].iov_len , len);
	if (nl){
	    copy_from_user(&buf[siz],msg_iov[i].iov_base,nl);
	}
	len-=nl;
	siz+=nl;
    }

    dump( buf,0,siz,0,16,desc);
}

*/

static void p4s_init_file_ops(struct socket *sock);

static
int p4s_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    int ret;
    DP_SOCKTRACE("%p %s()\n",sock, __func__);
    p4s_init_file_ops(sock);

    if (uaddr && (addr_len >= sizeof(*uaddr))){
	ret = p4_socket_bind( P4S_SOCK_PROTINFO( sock->sk ),(p4_addr_t *)uaddr->sa_data );
    }else{
	ret = -EINVAL;
    }
    DP_SOCKTRACE("%p %s() done\n",sock, __func__);
    return ret;
}

/*
 *	Connect to a remote host.
 */
static
int p4s_connect(struct socket *sock, struct sockaddr * uaddr,
			int addr_len, int flags)
{
    int ret;
    DP_SOCKTRACE("%p %s()\n",sock, __func__);
    if (uaddr && (addr_len >= (soffset(sockaddr_p4,sp4_ra)))) {
	p4_addr_t    *addr = &((struct sockaddr_p4 *)uaddr)->sp4_port;
	p4_remaddr_t *ra = &((struct sockaddr_p4 *)uaddr)->sp4_ra;
	int ralen = addr_len - soffset(sockaddr_p4,sp4_ra);
	ret = p4_socket_connect(P4S_SOCK_PROTINFO( sock->sk ),
				addr, ra, ralen);
    } else {
	ret = -EINVAL;
    }
    DP_SOCKTRACE("%p %s() done\n",sock, __func__);
    return ret;
}

/*
 *	Accept a pending connection. The TCP layer now gives BSD semantics.
 */
static
int p4s_accept(struct socket *sock, struct socket *newsock, int flags)
{
    int ret;
    DP_SOCKTRACE("%p new %p %s()\n",sock, newsock, __func__);
    ret=sock_no_accept(sock,newsock,flags);
    DP_SOCKTRACE("%p new %p %s() done\n",sock, newsock, __func__);
    return ret;
}

/*
 *	This does both peername and sockname.
 */
static
int p4s_getname(struct socket *sock, struct sockaddr *uaddr,
		 int *uaddr_len, int peer)
{
    int ret;
    DP_SOCKTRACE("%p %s()\n",sock, __func__);
    ret=sock_no_getname(sock,uaddr,uaddr_len,peer);
    DP_SOCKTRACE("%p %s() done\n",sock, __func__);
    return ret;
}

static
int p4s_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
    int ret;
    DP_SOCKTRACE("%p %s()\n",sock, __func__);

    /* switch inside critical path */
    switch (cmd) {
    case P4S_IO_SEND:
    old_p4s_io_send: {
	struct p4s_io_send_s s;

	if (copy_from_user(&s, (void*)arg, sizeof(s))) {
	    return -EINVAL;
	}

	ret = p4_sendmsg(P4S_SOCK_PROTINFO(sock->sk), s.DestNode,
			 &s.iov, s.iov.iov_len, s.Flags);
	return ret;
    }
	break;
    case P4S_IO_RECV:
    old_p4s_io_recv: {
	struct p4s_io_recv_s r;

	if (copy_from_user(&r, (void*)arg, sizeof(r))) {
	    return -EINVAL;
	}

	ret = p4_recvmsg(P4S_SOCK_PROTINFO(sock->sk),
			 &r.iov, &r.SrcNode, r.iov.iov_len, r.Flags);
	if (ret >=0) {
	    if (copy_to_user((void*)arg, &r, sizeof(r))) {
		return -EFAULT;
	    }
	}

	return ret;
    }
	break;
    case P4S_IO_TIMING:
    old_p4s_io_timing: {
	unsigned long time;
	GET_CPU_CYCLES(time);
	printk(KERN_DEBUG "ioctl() : Takes %ld cycles\n", time - arg);
	return 0;
    }
	break;

    case P4S_IO_SEND_IOV:
    old_p4s_io_send_iov: {
	struct p4s_io_send_iov_s s;
	struct iovec iov[16];
	unsigned int iov_len;
	unsigned int msg_len = 0;
	int i;

	if (copy_from_user(&s, (void*)arg, sizeof(s))) {
	    return -EINVAL;
	}
	iov_len = MIN(16, s.iov_len);
	if (copy_from_user(&iov, s.iov, sizeof(iov[0]) * iov_len)) {
	    return -EINVAL;
	}
	for (i = 0; i < iov_len; i++) {
	    msg_len += iov[i].iov_len;
	}

	ret = p4_sendmsg(P4S_SOCK_PROTINFO(sock->sk), s.DestNode,
			 iov, msg_len, s.Flags);
	return ret;
    }
	break;
    case P4S_IO_RECV_IOV:
    old_p4s_io_recv_iov: {
	struct p4s_io_recv_iov_s r;
	struct iovec iov[16];
	unsigned int iov_len;
	unsigned int msg_len = 0;
	int i;

	if (copy_from_user(&r, (void*)arg, sizeof(r))) {
	    return -EINVAL;
	}
	iov_len = MIN(16, r.iov_len);
	if (copy_from_user(&iov, r.iov, sizeof(iov[0]) * iov_len)) {
	    return -EINVAL;
	}
	for (i = 0; i < iov_len; i++) {
	    msg_len += iov[i].iov_len;
	}

	ret = p4_recvmsg(P4S_SOCK_PROTINFO(sock->sk),
			 iov, &r.SrcNode, msg_len, r.Flags);
	if (ret >=0) {
	    if (copy_to_user((void*)arg, &r, sizeof(r))) {
		return -EFAULT;
	    }
	}

	return ret;
    }
	break;

    default:
	/* switch outside critical path */
	switch (cmd) {
#if defined(_LP64) || defined(__powerpc64__)
	    /* Handle ioctl's from 32bit applications on 64bit arch */
	case P4S32_IO_SEND: {
	    struct p4s32_io_send_s s;
	    struct iovec iov;

	    if (copy_from_user(&s, (void*)arg, sizeof(s))) {
		return -EINVAL;
	    }
	    iov.iov_base = P4S32_PTR(s.iov.iov_base);
	    iov.iov_len = s.iov.iov_len;

	    ret = p4_sendmsg(P4S_SOCK_PROTINFO(sock->sk), s.DestNode,
			     &iov, iov.iov_len, s.Flags);
	    return ret;
	}
	    break;
	case P4S32_IO_RECV: {
	    struct p4s32_io_recv_s r;
	    struct iovec iov;

	    if (copy_from_user(&r, (void*)arg, sizeof(r))) {
		return -EINVAL;
	    }
	    iov.iov_base = P4S32_PTR(r.iov.iov_base);
	    iov.iov_len = r.iov.iov_len;

	    ret = p4_recvmsg(P4S_SOCK_PROTINFO(sock->sk),
			     &iov, &r.SrcNode, iov.iov_len, r.Flags);
	    if (ret >=0) {
		r.iov.iov_base += ret;
		r.iov.iov_len -= ret;
		if (copy_to_user((void*)arg, &r, sizeof(r))) {
		    return -EINVAL;
		}
	    }
	    return ret;
	}
	    break;
	case P4S32_IO_TIMING: goto old_p4s_io_timing;
	case P4S32_IO_SEND_IOV: {
	    struct p4s32_io_send_iov_s s;
	    struct p4s32_iovec iov32[16];
	    struct iovec iov[16];
	    unsigned int iov_len;
	    unsigned int msg_len = 0;
	    int i;

	    if (copy_from_user(&s, (void*)arg, sizeof(s))) {
		return -EINVAL;
	    }
	    iov_len = MIN(16, s.iov_len);
	    if (copy_from_user(&iov32, P4S32_PTR(s.iov), sizeof(iov32[0]) * iov_len)) {
		return -EINVAL;
	    }
	    for (i = 0; i < iov_len; i++) {
		iov[i].iov_base = P4S32_PTR(iov32[i].iov_base);
		iov[i].iov_len = iov32[i].iov_len;
		msg_len += iov[i].iov_len;
	    }

	    ret = p4_sendmsg(P4S_SOCK_PROTINFO(sock->sk), s.DestNode,
			     iov, msg_len, s.Flags);
	    return ret;

	}
	    break;
	case P4S32_IO_RECV_IOV: {
	    struct p4s32_io_recv_iov_s r;
	    struct p4s32_iovec iov32[16];
	    struct iovec iov[16];
	    unsigned int iov_len;
	    unsigned int msg_len = 0;
	    int i;

	    if (copy_from_user(&r, (void*)arg, sizeof(r))) {
		return -EINVAL;
	    }
	    iov_len = MIN(16, r.iov_len);
	    if (copy_from_user(&iov32, P4S32_PTR(r.iov), sizeof(iov32[0]) * iov_len)) {
		return -EINVAL;
	    }
	    for (i = 0; i < iov_len; i++) {
		iov[i].iov_base = P4S32_PTR(iov32[i].iov_base);
		iov[i].iov_len = iov32[i].iov_len;
		msg_len += iov[i].iov_len;
	    }

	    ret = p4_recvmsg(P4S_SOCK_PROTINFO(sock->sk),
			     iov, &r.SrcNode, msg_len, r.Flags);
	    if (ret >=0) {
		if (copy_to_user((void*)arg, &r, sizeof(r))) {
		    return -EINVAL;
		}
	    }

	    return ret;
	}
	    break;
#endif /* _LP64 */
	    /* Old ioctl for backward compatibility (dont work with 32bit apps on 64bit arch!)*/
	case P4S_IO_SEND_OLD: goto old_p4s_io_send;
	case P4S_IO_RECV_OLD: goto old_p4s_io_recv;
	case P4S_IO_TIMING_OLD: goto old_p4s_io_timing;
	case P4S_IO_SEND_IOV_OLD: goto old_p4s_io_send_iov;
	case P4S_IO_RECV_IOV_OLD: goto old_p4s_io_recv_iov;
	default:
	    ret = p4_ioctl(P4S_SOCK_PROTINFO( sock->sk ), cmd, arg);
	}
    }
    return ret;
}

/*
 *	Move a socket into listening state.
 */
static
int p4s_listen(struct socket *sock, int backlog)
{
    int ret;
    DP_SOCKTRACE("%p %s()\n",sock, __func__);
    ret=sock_no_listen(sock,backlog);
    DP_SOCKTRACE("%p %s() done\n",sock, __func__);
    return ret;
}

static
int p4s_shutdown(struct socket *sock, int how)
{
    int ret;
    DP_SOCKTRACE("%p %s()\n",sock, __func__);
    ret=sock_no_shutdown(sock,how);
    return ret;
}

/*
 *	Set socket options on an inet socket.
 */
static

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,31)
int p4s_setsockopt(struct socket *sock, int level, int optname,
		   char *optval, unsigned int optlen)
#else
int p4s_setsockopt(struct socket *sock, int level, int optname,
		   char *optval, int optlen)
#endif
{
    int ret;
    DP_SOCKTRACE("%p %s()\n",sock, __func__);
    ret=sock_no_setsockopt(sock,level,optname,optval,optlen);
    return ret;
}

/*
 *	Get a socket option on an AF_INET socket.
 */
static
int p4s_getsockopt(struct socket *sock, int level, int optname,
		    char *optval, int *optlen)
{
    int ret;
    DP_SOCKTRACE("%p %s()\n",sock, __func__);
    ret=sock_no_getsockopt(sock,level,optname,optval,optlen);
    return ret;
}

/* proto_ops for proxy */
static struct proto_ops p4s_proto_ops = { /* inet_stream_ops */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    _sinit(owner)	THIS_MODULE,
#endif
    _sinit(family)	PF_P4S,

    _sinit(release)	p4s_release,
    _sinit(bind)	p4s_bind,
    _sinit(connect)	p4s_connect,
    _sinit(socketpair)	sock_no_socketpair,
    _sinit(accept)	p4s_accept,
    _sinit(getname)	p4s_getname,
    _sinit(poll)	p4s_poll,
    _sinit(ioctl)	p4s_ioctl,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17)
    _sinit(compat_ioctl) p4s_ioctl,
#endif
    _sinit(listen)	p4s_listen,
    _sinit(shutdown)	p4s_shutdown,
    _sinit(setsockopt)	p4s_setsockopt,
    _sinit(getsockopt)	p4s_getsockopt,
    _sinit(sendmsg)	p4s_sendmsg,
    _sinit(recvmsg)	p4s_recvmsg,
    _sinit(mmap)	sock_no_mmap,
};


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
#define P4S_REGISTER_PROTO 1
#endif

#ifdef P4S_REGISTER_PROTO
static struct proto p4s_proto = {
    _sinit(name)	"P4S",
    _sinit(owner)	THIS_MODULE,
    _sinit(obj_size)	sizeof(struct sock),
};
#endif


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
/* 2.6.11 - 2.6.17 hack: patch file_ops to get p4s_compat_ioctl */
static
long p4s_compat_ioctl(struct file *filp, unsigned int cmd , unsigned long arg)
{
    return p4s_ioctl(SOCKET_I(filp->f_dentry->d_inode), cmd, arg);
    //return p4s_ioctl(&filp->f_dentry->d_inode->u.socket_i, cmd, arg);
}


static struct file_operations p4s_file_ops = {
    .owner = THIS_MODULE
    /* other fields will be initialized in p4s_init_file_ops() */
};


static
void p4s_init_file_ops(struct socket *sock)
{
    if (!sock->file) {
	printk(KERN_ERR "P4S: p4s_init_file_ops() : !sock->file\n");
	return;
    }
    if (!sock->file->f_op) {
	printk(KERN_ERR "P4S: p4s_init_file_ops() : !sock->file->f_op\n");
	return;
    }
    if (sock->file->f_op->owner) {
	printk(KERN_ERR "P4S: p4s_init_file_ops() : sock->file->f_op->owner\n");
	return;
    }

    // use socket file ops as default: (probably socket_file_ops)
    memcpy(&p4s_file_ops, sock->file->f_op, sizeof(p4s_file_ops));

    // p4s_file_ops.owner = THIS_MODULE; // Dont use THIS_MODULE! (would decrement modulecounter at exit!)
    // set compat_ioctl (the goal of this function):
    p4s_file_ops.compat_ioctl = p4s_compat_ioctl;

    sock->file->f_op = &p4s_file_ops;
}

#else
static
void p4s_init_file_ops(struct socket *sock)
{
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
static int p4s_create(struct net *net, struct socket *sock, int protocol)
#else
static int p4s_create(struct socket *sock, int protocol)
#endif
{
    struct sock *sk;
    p4_socket_t *p4s;
    DP_SOCKTRACE("%p Create Socket(type %d)\n",sock,sock->type);
// SOCK_STREAM	1   TCP
// SOCK_DGRAM	2   UDP
// SOCK_RAW	3
// SOCK_RDM	4
// SOCK_SEQPACKET	5
// SOCK_PACKET	10

    p4s = p4_socket_create();
    if (!p4s) goto err_no_p4s;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    sk = sk_alloc(PF_P4S, GFP_KERNEL, 1);
    if (sk) p4s_inc_usecount(); // inc_usecount always succeed in version < 2.6.0
#else
#ifndef P4S_REGISTER_PROTO
    sk = sk_alloc(PF_P4S, GFP_KERNEL, 1, NULL);
#else /* P4S_REGISTER_PROTO ( >= 2.6.12 ) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    sk = sk_alloc(PF_P4S, GFP_KERNEL, &p4s_proto, 1);
#else
    sk = sk_alloc(net, PF_P4S, GFP_KERNEL, &p4s_proto);
#endif
#endif
#endif
    if(sk == NULL)
  	goto err_no_mem;
    sock_init_data(sock, sk);

    P4S_SOCK_PROTINFO(sk) = p4s;

    sock->ops = &p4s_proto_ops;
    sock->state = SS_UNCONNECTED;

    return (0);
    /* --- */
 err_no_mem:
    p4_socket_close(p4s);
 err_no_p4s:
    return -ENOMEM;
// err_no_support:
//    return -ESOCKTNOSUPPORT;
}

#if ((defined(CONFIG_IA32_EMULATION) && defined(__x86_64__)) || defined(__powerpc64__)) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)

/* ToDo: which kernel version needs and have register_ioctl32_conversion() ? */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/ioctl32.h>
#include <linux/syscalls.h>
#define CONFIG_IA32_EMUL_USE_SYS_IOCTL 1
#else
#include <asm/ioctl32.h>
#endif

static char config_ia32_emul[] __attribute__(( unused )) =
"$Info: CONFIG_IA32_EMULATION $";

static
unsigned int ioctl32_cmd[] = {
    P4_DUMPSOCK,
    P4_DUMPUSRCI,
    P4_DUMPNETCI,
    P4_GETNODEID,
    P4_CLOSE_CON,
    P4S32_IO_SEND,
    P4S32_IO_RECV,
    P4S32_IO_TIMING,
    P4S32_IO_SEND_IOV,
    P4S32_IO_RECV_IOV,
    0
};


typedef int (*ioctl32_handler)(unsigned int, unsigned int, unsigned long, struct file *);

#ifndef CONFIG_IA32_EMUL_USE_SYS_IOCTL
static
int p4s_ioctl32(unsigned int fd, unsigned int cmd , unsigned long arg, struct file * filp)
{
    return p4s_ioctl(&filp->f_dentry->d_inode->u.socket_i, cmd, arg);
}
#endif

static
void p4s_init_ioctl32(void)
{
    unsigned int *c;

    for (c = ioctl32_cmd; *c; c++) {
#ifdef CONFIG_IA32_EMUL_USE_SYS_IOCTL
	/**
	   The comment "handler == NULL: use 64bit ioctl handler."
	   in <asm/ioctl32.h> is wrong and cause a kernel Oops.
	   sys_ioctl is of wrong type, but the one which is suggested
	   in arch/x86_64/ia32/ia32_ioctl.c.
	   IMHO: The 32bit part is a bad hack. So lets use a handler
	   of wrong type :-(.
	   2.4.x Kernels dont export sys_ioctl...
	*/
	register_ioctl32_conversion(*c, (ioctl32_handler)sys_ioctl);
#else
	register_ioctl32_conversion(*c, p4s_ioctl32);
#endif
    }

}

static
void p4s_cleanup_ioctl32(void)
{
    unsigned int *c;
    for (c = ioctl32_cmd; *c; c++) {
	unregister_ioctl32_conversion(*c);
    }
}

#else
static
void p4s_init_ioctl32(void)
{
}

static
void p4s_cleanup_ioctl32(void)
{
}
#endif /* CONFIG_IA32_EMULATION && __x86_64__ */


static struct net_proto_family p4s_family_ops =
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    _sinit(owner)	THIS_MODULE,
#endif
    _sinit(family)	PF_P4S,
    _sinit(create)	p4s_create
};

static int p4s_proto_init(void)
{
    int ret = 0;
    printk(KERN_INFO   "P4S: Protocol init\n");

#ifdef P4S_REGISTER_PROTO
    ret = proto_register(&p4s_proto, 0);
    if (ret != 0) {
	printk(KERN_ERR
	       "P4S: proto_register(\"%s\") failed!\n", p4s_proto.name);
	return ret;
    }
#endif

    p4s_init_ioctl32();

    ret = sock_register(&p4s_family_ops);
    if (ret != 0) {
	printk(KERN_ERR
	       "P4S: sock_register(PF_P4S = %d) failed!\n", PF_P4S);
#ifdef P4S_REGISTER_PROTO
	proto_unregister(&p4s_proto);
#endif
	return ret;
    }
    return ret;
}

static void p4s_proto_cleanup(void)
{
    printk(KERN_INFO "P4S: Protocol cleanup\n");

    p4s_cleanup_ioctl32();

    sock_unregister(PF_P4S);

#ifdef P4S_REGISTER_PROTO
    proto_unregister(&p4s_proto);
#endif
}

#ifdef MODULE
MODULE_AUTHOR("Jens Hauke <hauke@par-tec.com>");
MODULE_DESCRIPTION("P4 socket layer. Version " P4_VERSION " " __DATE__ " " __TIME__ ".");
#ifdef MODULE_LICENSE
MODULE_LICENSE("QPL");
#endif

int init_module(void)
{
	int ret;

	printk(KERN_NOTICE "P4S: ParaStation, (c)2003,2004 ParTec AG, (c)2005-2007 ParTec CCC GmbH\n");

	ret = p4_init();
	if (ret) goto do_err_p4init;

	ret = p4s_proto_init();
	if (ret) goto do_err_p4sinit;

	return 0;
	/* --- */
 do_err_p4sinit:
	p4_cleanup();
 do_err_p4init:
	return ret;
}




void cleanup_module(void)
{
    p4s_proto_cleanup();
    p4_cleanup();
}

P4_EXPORT_SYMBOL(p4s_ratelimit);

#else /* !MODULE */

#error Please compile as module

#endif
