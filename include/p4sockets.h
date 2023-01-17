/*
 * ParaStation
 *
 * Copyright (C) 2003,2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _P4SOCKETS_H_
#define _P4SOCKETS_H_

#include <linux/ioctl.h>

#ifndef __KERNEL__
#include <sys/socket.h>
#include <inttypes.h>
#endif

#define PF_P4S	30

#define P4S_ADDRLEN  8
typedef char p4_addr_t[P4S_ADDRLEN];

/* #define P4CALLBACKS 1 */

#define P4REMADDR_PSID  1

#define P4REMADDR_LOCAL 2
#define P4REMADDR_ETHER 3
#define P4REMADDR_MYRI  4

typedef struct p4_remaddr_psid_s {
    uint32_t	psid;
} p4_remaddr_psid_t;

typedef struct p4_remaddr_local_s {
} p4_remaddr_local_t;

#define P4_IFHWADDRLEN 6
#define P4_IFNAMSIZ 16

typedef struct p4_remaddr_ether_s {
    union {
	unsigned char	mac[ P4_IFHWADDRLEN ];
	uint32_t	ipaddr; /* should be: in_addr_t */
    }addr;
    char	devname[ P4_IFNAMSIZ ];/* devname[0] == \0 is magic for ipaddr */
} p4_remaddr_ether_t;


typedef struct p4_remaddr_myri_s {
    uint32_t	nodeid;
} p4_remaddr_myri_t;

typedef struct p4_remaddr_s {
    int16_t	type; /* e.g. P4REMADDR_LOCAL */
    union{
	p4_remaddr_local_t local;
	p4_remaddr_psid_t psid;
	p4_remaddr_ether_t ether;
	p4_remaddr_myri_t myri;
    } tec;
} p4_remaddr_t;

struct sockaddr_p4 {
    sa_family_t	 sp4_family;
    p4_addr_t    sp4_port;
    p4_remaddr_t sp4_ra;
};


#ifndef MIN
#define MIN(a,b)      (((a)<(b))?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b)      (((a)>(b))?(a):(b))
#endif

#define ssizeof( structname , fieldname )			\
sizeof( ((struct structname *)0)->fieldname)
/* fieldoffset offield in struct structname */
#define soffset(structname , fieldname)				\
((long int)&(((struct structname*)0)->fieldname))

#ifdef __KERNEL__
int p4s_ratelimit(void);
int p4s_inc_usecount(void);
void p4s_dec_usecount(void);

struct p4_socket_s *p4_socket_create(void);
int p4_socket_bind(struct p4_socket_s *socket, p4_addr_t *addr);
void p4_socket_close(struct p4_socket_s *socket);
int p4_socket_connect(struct p4_socket_s *socket,
		      p4_addr_t *addr, p4_remaddr_t *ra, int ralen);
unsigned int p4_socket_poll(struct file * file, struct p4_socket_s *socket,
			    struct poll_table_struct *wait);
int p4_sendmsg(struct p4_socket_s *socket, int destidx,
	       struct iovec *msg_iov, size_t msgsize, int flags);
int p4_shutdown(struct p4_socket_s *socket, int destidx);
int p4_recvmsg(struct p4_socket_s *socket, struct iovec *msg_iov,uint16_t *msg_src,
	       size_t msgsize, int flags);
int p4_get_nodeid(void);
void p4_set_nodeid(uint32_t node_id);
int p4_ioctl(struct p4_socket_s *socket, unsigned long cmd, unsigned long arg);

void p4_setcb_new_connection(struct p4_socket_s *socket,
			     void (*new_connection)(struct p4_socket_s *socket,
						    int fromidx, void * priv),
			     void *priv);
#ifdef P4CALLBACKS

void p4_setcb_data_ready(struct p4_socket_s *socket,
			 void (*data_ready)(struct p4_socket_s *socket, void * priv),
			 void *priv);
void p4_setcb_write_space(struct p4_socket_s *socket,
			  void (*write_space)(struct p4_socket_s *socket, void * priv),
			  void *priv);
#endif
#endif

#define P4S_IOC_MAGIC	'4'
#define P4S_IO_SEND		_IOWR(P4S_IOC_MAGIC, 100, long) /* 0x64 */
#define P4S_IO_RECV		_IOWR(P4S_IOC_MAGIC, 101, long) /* 0x65 */
#define P4S_IO_TIMING		_IOWR(P4S_IOC_MAGIC, 102, long) /* 0x66 */
#define P4S_IO_SEND_IOV		_IOWR(P4S_IOC_MAGIC, 103, long) /* 0x67 */
#define P4S_IO_RECV_IOV		_IOWR(P4S_IOC_MAGIC, 104, long) /* 0x68 */

struct p4s_io_send_s {
    uint16_t		DestNode;
    uint16_t		Flags;
    struct iovec	iov;
};

struct p4s_io_recv_s {
    uint16_t		SrcNode;
    uint16_t		Flags;
    struct iovec	iov;
};

struct p4s_io_send_iov_s {
    uint16_t		DestNode;
    uint16_t		Flags;
    uint16_t		iov_len;
    struct iovec	*iov;
};

struct p4s_io_recv_iov_s {
    uint16_t		SrcNode;
    uint16_t		Flags;
    uint16_t		iov_len;
    struct iovec	*iov;
};

#if defined(_LP64) || defined(__powerpc64__)
/* 32bit support on 64bit arch */

#define P4S32_IO_SEND		_IOWR(P4S_IOC_MAGIC, 100, uint32_t) /* 0x64 */
#define P4S32_IO_RECV		_IOWR(P4S_IOC_MAGIC, 101, uint32_t) /* 0x65 */
#define P4S32_IO_TIMING		_IOWR(P4S_IOC_MAGIC, 102, uint32_t) /* 0x66 */
#define P4S32_IO_SEND_IOV	_IOWR(P4S_IOC_MAGIC, 103, uint32_t) /* 0x67 */
#define P4S32_IO_RECV_IOV	_IOWR(P4S_IOC_MAGIC, 104, uint32_t) /* 0x68 */

typedef uint32_t p4s32_ptr_t;

#define P4S32_PTR(ptr32) ((void *)(unsigned long)(ptr32))

struct p4s32_iovec
{
    p4s32_ptr_t iov_base;
    uint32_t iov_len;
};

struct p4s32_io_send_s {
    uint16_t		DestNode;
    uint16_t		Flags;
    struct p4s32_iovec	iov;
};

struct p4s32_io_recv_s {
    uint16_t		SrcNode;
    uint16_t		Flags;
    struct p4s32_iovec	iov;
};

struct p4s32_io_send_iov_s {
    uint16_t		DestNode;
    uint16_t		Flags;
    uint16_t		iov_len;
    p4s32_ptr_t		iov;
};

struct p4s32_io_recv_iov_s {
    uint16_t		SrcNode;
    uint16_t		Flags;
    uint16_t		iov_len;
    p4s32_ptr_t		iov;
};

#endif /* _LP64 */

#endif /* _P4SOCKETS_H_ */
