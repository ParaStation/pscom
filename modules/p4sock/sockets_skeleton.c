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
/* 2001-06-08 Jens Hauke */
/* 2002-03-27 Jens Hauke */

#include <linux/kernel.h>
#include <linux/config.h>
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


#define NO_USE_COUNT
#define PF_P4S	30

#define MIN(a,b)      (((a)<(b))?(a):(b))
#define MAX(a,b)      (((a)>(b))?(a):(b))

#define PRINT_TRACE(fmt,param...) printk(KERN_INFO fmt,##param);


//#define P4SLdeb( fmt ) PRINT_TRACE( fmt"\n" )
#define P4SLdeb( fmt )

static spinlock_t p4s_lock=SPIN_LOCK_UNLOCKED;
#define P4SLVAR
/* p4s lock*/
#define P4SL   P4SLdeb("wl ");spin_lock(&p4s_lock)
#define P4SUL  P4SLdeb("wul");spin_unlock(&p4s_lock)

static
int p4s_sendmsg(struct socket *sock, struct msghdr *msg, int size,
		 struct scm_cookie *scm)
{
    return 0;
}


static
int p4s_recvmsg(struct socket *sock, struct msghdr *msg, int size,
		 int flags, struct scm_cookie *scm)
{
    return 0;
}


/*
 *	The peer socket should always be NULL (or else). When we call this
 *	function we are destroying the object and from then on nobody
 *	should refer to it.
 */
static
int p4s_release(struct socket *sock)
{
    PRINT_TRACE( "P4S_PS: %p %p "__FUNCTION__"()\n",sock,sock->inode);

#ifndef NO_USE_COUNT
    MOD_DEC_USE_COUNT;
#endif
    return 0;
}


static
unsigned int
p4s_poll(struct file * file, struct socket *sock,struct poll_table_struct *wait)
{
//    P4SLVAR;
    PRINT_TRACE( "P4S_PS: %p %p "__FUNCTION__"()\n",sock,sock->inode);
//    P4SL;
//    P4SUL;
    return 0;
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

static
int p4s_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
    int ret;
    PRINT_TRACE( "P4S: %p %p "__FUNCTION__"()\n",sock,sock->inode);
    ret=sock_no_bind(sock,uaddr,addr_len);
    PRINT_TRACE( "P4S: %p %p "__FUNCTION__"() done\n",sock,sock->inode);
    return ret;
}

/*
 *	Connect to a remote host. There is regrettably still a little
 *	TCP 'magic' in here.
 */
static
int p4s_connect(struct socket *sock, struct sockaddr * uaddr,
			int addr_len, int flags)
{
    int ret;
    PRINT_TRACE( "P4S: %p %p "__FUNCTION__"()\n",sock,sock->inode);
    ret=sock_no_connect(sock,uaddr,addr_len,flags);
    PRINT_TRACE( "P4S: %p %p "__FUNCTION__"() done\n",sock,sock->inode);
    return ret;
}

/*
 *	Accept a pending connection. The TCP layer now gives BSD semantics.
 */
static
int p4s_accept(struct socket *sock, struct socket *newsock, int flags)
{
    int ret;
    PRINT_TRACE( "P4S: %p %p new %p "__FUNCTION__"()\n",sock,sock->inode,newsock);
    ret=sock_no_accept(sock,newsock,flags);
    PRINT_TRACE( "P4S: %p %p new %p "__FUNCTION__"() done\n",sock,sock->inode,newsock);
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
    PRINT_TRACE( "P4S: %p %p "__FUNCTION__"()\n",sock,sock->inode);
    ret=sock_no_getname(sock,uaddr,uaddr_len,peer);
    PRINT_TRACE( "P4S: %p %p "__FUNCTION__"() done\n",sock,sock->inode);
    return ret;
}

static
int p4s_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
    int ret;
    PRINT_TRACE( "P4S: %p %p "__FUNCTION__"()\n",sock,sock->inode);
    ret=sock_no_ioctl(sock,cmd,arg);
    return ret;
}

/*
 *	Move a socket into listening state.
 */
static
int p4s_listen(struct socket *sock, int backlog)
{
    int ret;
    PRINT_TRACE( "P4S: %p %p "__FUNCTION__"()\n",sock,sock->inode);
    ret=sock_no_listen(sock,backlog);
    PRINT_TRACE( "P4S: %p %p "__FUNCTION__"() done\n",sock,sock->inode);
    return ret;
}

static
int p4s_shutdown(struct socket *sock, int how)
{
    int ret;
    PRINT_TRACE( "P4S: %p %p "__FUNCTION__"()\n",sock,sock->inode);
    ret=sock_no_shutdown(sock,how);
    return ret;
}

/*
 *	Set socket options on an inet socket.
 */
static
int p4s_setsockopt(struct socket *sock, int level, int optname,
		    char *optval, int optlen)
{
    int ret;
    PRINT_TRACE( "P4S: %p %p "__FUNCTION__"()\n",sock,sock->inode);
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
    PRINT_TRACE( "P4S: %p %p "__FUNCTION__"()\n",sock,sock->inode);
    ret=sock_no_getsockopt(sock,level,optname,optval,optlen);
    return ret;
}

#define _sinit( name ) name:

/* proto_ops for proxy */
static struct proto_ops p4s_proto_ops = { /* inet_stream_ops */
    _sinit(family)	PF_P4S,
    _sinit(release)	p4s_release,
    _sinit(bind)	p4s_bind,
    _sinit(connect)	p4s_connect,
    _sinit(socketpair)	sock_no_socketpair,
    _sinit(accept)	p4s_accept,
    _sinit(getname)	p4s_getname,
    _sinit(poll)	p4s_poll,
    _sinit(ioctl)	p4s_ioctl,
    _sinit(listen)	p4s_listen,
    _sinit(shutdown)	p4s_shutdown,
    _sinit(setsockopt)	p4s_setsockopt,
    _sinit(getsockopt)	p4s_getsockopt,
    _sinit(sendmsg)	p4s_sendmsg,
    _sinit(recvmsg)	p4s_recvmsg,
    _sinit(mmap)	sock_no_mmap,
};

static int p4s_create(struct socket *sock, int protocol)
{
    struct sock *sk;
    PRINT_TRACE( "P4S: %p Create Socket(type %d)\n",sock,sock->type);
// SOCK_STREAM	1   TCP
// SOCK_DGRAM	2   UDP
// SOCK_RAW	3
// SOCK_RDM	4
// SOCK_SEQPACKET	5
// SOCK_PACKET	10
    sk = sk_alloc(PF_P4S, GFP_KERNEL, 1);
    if(sk == NULL)
  	goto err_no_mem;
    sock_init_data(sock, sk);

    sock->ops = &p4s_proto_ops;
    sock->state = SS_UNCONNECTED;
//	sk->destruct	= NULL;
//	sk->no_check 	= 1;		/* Checksum off by default */

#ifndef NO_USE_COUNT
    MOD_INC_USE_COUNT;
#endif
    return (0);

 err_no_mem:
    return -ENOMEM;
// err_no_support:
//    return -ESOCKTNOSUPPORT;
}





static struct net_proto_family p4s_family_ops =
{
	PF_P4S,
	p4s_create
};





static int p4s_proto_init(void)
{
    PRINT_TRACE( "P4S:Protocol init\n");
    sock_register(&p4s_family_ops);
    return 0;
}

static void p4s_proto_cleanup(void)
{
    PRINT_TRACE( "P4S:Protocol cleanup\n");
    sock_unregister( PF_P4S );
}


#ifdef MODULE
MODULE_AUTHOR("Jens Hauke <hauke@par-tec.de>");
MODULE_DESCRIPTION("P4 socket layer");

int init_module(void)
{
	int ret;
	P4SLVAR;
	P4SL;
	ret = p4s_proto_init();
	if (ret) goto do_err_init;
	P4SUL;
	return 0;

 do_err_init:
	P4SUL;
	return ret;
}




void cleanup_module(void)
{
    P4SLVAR;
    P4SL;
    p4s_proto_cleanup();
    P4SUL;
}

#else /* !MODULE */

#error Please compile as module

#endif
