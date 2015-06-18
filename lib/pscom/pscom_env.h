/*
 * ParaStation
 *
 * Copyright (C) 2007 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#ifndef _PSCOM_ENV_H_
#define _PSCOM_ENV_H_


/* Set debuglevel */
#define ENV_DEBUG     "PSP_DEBUG"
/* output filename */
#define ENV_DEBUG_OUT "PSP_DEBUG_OUT"
#define ENV_INFO "PSP_INFO"

#define ENV_CONFIG_FILES "/dev/environment:.parastation:$HOME/.parastation:/etc/pscom.conf"

#define ENV_NETWORK "PSP_NETWORK"

/* Socket options */
#define ENV_SO_SNDBUF "PSP_SO_SNDBUF"
#define ENV_SO_RCVBUF "PSP_SO_RCVBUF"
#define ENV_TCP_NODELAY "PSP_TCP_NODELAY"
#define ENV_TCP_BACKLOG "PSP_TCP_BACKLOG"
#define ENV_TCP_ACCEPT_BACKLOG "PSP_TCP_ACCEPT_BACKLOG"

/* Receive from a connection without receives posted? 0: No 1: Yes */
#define ENV_UNEXPECTED_RECEIVES "PSP_UNEXPECTED_RECEIVES"
/* Call sched_yield() inside idle loop? 0: No 1: Yes. Default: 0 */
#define ENV_SCHED_YIELD "PSP_SCHED_YIELD"
/* Start rendezvous at messagesize x. Default ~0 = never */
#define ENV_RENDEZVOUS "PSP_RENDEZVOUS"
/* ENV_RENDEZVOUS_xxx: Messagesize for arch xxx.
   Default to ENV_RENDEZVOUS */
#define ENV_RENDEZVOUS_SHM "PSP_RENDEZVOUS_SHM"
#define ENV_RENDEZVOUS_DAPL "PSP_RENDEZVOUS_DAPL"
#define ENV_RENDEZVOUS_ELAN "PSP_RENDEZVOUS_ELAN"
#define ENV_RENDEZVOUS_EXTOLL "PSP_RENDEZVOUS_EXTOLL"
#define ENV_RENDEZVOUS_VELO "PSP_RENDEZVOUS_VELO"

/* Used in constructing the UUID for QLogic */
#define ENV_PSM_UNIQ_ID "PSP_PSM_UNIQ_ID"
#define ENV_PMI_ID "PMI_ID"

/* Debugoutput on signal SIGQUIT (i386:3) (key: ^\) */
#define ENV_SIGQUIT "PSP_SIGQUIT"
#define ENV_READAHEAD "PSP_READAHEAD"
#define ENV_RETRY "PSP_RETRY"

/* Enable/Disable the connection guard */
#define ENV_GUARD "PSP_GUARD"

#define ENV_PLUGINDIR "PSP_PLUGINDIR"
#define ENV_ARCH_PREFIX "PSP_"

/* Use this, if ENV_ARCH_NEW_SHM is not set */
#define ENV_ARCH_OLD_SHM "PSP_SHAREDMEM"
#define ENV_ARCH_NEW_SHM ENV_ARCH_PREFIX "SHM"

/* Use this, if ENV_ARCH_NEW_P4S is not set */
#define ENV_ARCH_OLD_P4S "PSP_P4SOCK"
#define ENV_ARCH_NEW_P4S ENV_ARCH_PREFIX "P4S"

/* The DAPL Provider to use */
#define ENV_DAPL_PROVIDER "PSP_DAPL_PROVIDER"

/* OpenIB HCA and port */
#define ENV_OPENIB_HCA "PSP_OPENIB_HCA"   /* default: first hca */
#define ENV_OPENIB_PORT "PSP_OPENIB_PORT" /* default: port 1 */
#define ENV_OPENIB_PATH_MTU "PSP_OPENIB_PATH_MTU" /* default: 3
						     1 : IBV_MTU_256
						     2 : IBV_MTU_512
						     3 : IBV_MTU_1024 */
#define ENV_OPENIB_SENDQ_SIZE "PSP_OPENIB_SENDQ_SIZE"
#define ENV_OPENIB_RECVQ_SIZE "PSP_OPENIB_RECVQ_SIZE"
#define ENV_OPENIB_COMPQ_SIZE "PSP_OPENIB_COMPQ_SIZE"
#define ENV_OPENIB_PENDING_TOKENS "PSP_OPENIB_PENDING_TOKENS"
#define ENV_OPENIB_GLOBAL_SENDQ "PSP_OPENIB_GLOBAL_SENDQ" /* bool: Use one sendq for all connections? default: 0(no) */
#define ENV_OPENIB_EVENT_CNT "PSP_OPENIB_EVENT_CNT" /* bool: Be busy if outstanding_cq_entries is to high? default: 1(yes) */
#define ENV_OPENIB_IGNORE_WRONG_OPCODES "PSP_OPENIB_IGNORE_WRONG_OPCODES" /* bool: ignore wrong cq opcodes */
#define ENV_OPENIB_LID_OFFSET "PSP_OPENIB_LID_OFFSET" /* int: offset to base LID (adaptive routing) */


/* OFED HCA and port */
#define ENV_OFED_HCA "PSP_OFED_HCA"   /* default: first hca */
#define ENV_OFED_PORT "PSP_OFED_PORT" /* default: port 1 */
#define ENV_OFED_PATH_MTU "PSP_OFED_PATH_MTU" /* default: 3
						 1 : IBV_MTU_256
						 2 : IBV_MTU_512
						 3 : IBV_MTU_1024 */
#define ENV_OFED_SENDQ_SIZE "PSP_OFED_SENDQ_SIZE"
#define ENV_OFED_RECVQ_SIZE "PSP_OFED_RECVQ_SIZE"
#define ENV_OFED_COMPQ_SIZE "PSP_OFED_COMPQ_SIZE"
#define ENV_OFED_PENDING_TOKENS "PSP_OFED_PENDING_TOKENS"
#define ENV_OFED_WINSIZE "PSP_OFED_WINSIZE"
#define ENV_OFED_RESEND_TIMEOUT "PSP_OFED_RESEND_TIMEOUT"
#define ENV_OFED_RESEND_TIMEOUT_SHIFT "PSP_OFED_RESEND_TIMEOUT_SHIFT"


#define ENV_OFED_EVENT_CNT "PSP_OFED_EVENT_CNT" /* bool: Be busy if outstanding_cq_entries is to high? default: 1(yes) */
#define ENV_OFED_LID_OFFSET "PSP_OFED_LID_OFFSET" /* int: offset to base LID (adaptive routing) */

/* Extoll */
#define ENV_EXTOLL_RECVQ_SIZE "PSP_EXTOLL_RECVQ_SIZE"
#define ENV_EXTOLL_SENDQ_SIZE "PSP_EXTOLL_SENDQ_SIZE"
#define ENV_EXTOLL_GLOBAL_SENDQ "PSP_EXTOLL_GLOBAL_SENDQ" /* bool: Use one sendq for all connections? default: 0(no) */
#define ENV_EXTOLL_EVENT_CNT "PSP_EXTOLL_EVENT_CNT" /* bool: Be busy on empty global sendq? default: 0(no) */
#define ENV_EXTOLL_PENDING_TOKENS "PSP_EXTOLL_PENDING_TOKENS"
#define ENV_EXTOLL_MCACHE_SIZE "PSP_EXTOLL_MCACHE_SIZE"

/* Allocate memory in a shared mem segment */
/* "PSP_MALLOC*" settings have to be known already in the __malloc_initialize_hook() before we
   run through pscom_pslib_init(). Therefore they are not printed with PSP_DEBUG > 0 and can only set from
   the environment (not from pslib). */
#define ENV_MALLOC "PSP_MALLOC" /* bool: Use a hook into glibc malloc (__morecore())? default: 1(yes) */
#define ENV_MALLOC_MIN "PSP_MALLOC_MIN" /* ulong: minimum size of the shared mem segment */
#define ENV_MALLOC_MAX "PSP_MALLOC_MAX" /* ulong: maximum size of the shared mem segment */

/* Use shm direct for messages >= PSP_SHM_DIRECT. Set PSP_SHM_DIRECT=-1 to disable shm direct. */
#define ENV_SHM_DIRECT "PSP_SHM_DIRECT" /* min message size to use shm direct */

/* Manage a list of all requests for debug dumps (decrease performance!) */
#define ENV_DEBUG_REQ     "PSP_DEBUG_REQ"

/* Print statistic at the end. (no need, if PSP_DEBUG >=2) */
#define ENV_DEBUG_STATS   "PSP_DEBUG_STATS"

/* make progress every count itteration in iprobe */
#define ENV_IPROBE_COUNT "PSP_IPROBE_COUNT"

#define ENV_UINT_AUTO ((unsigned)~0U)

struct PSCOM_env {
	int		debug;
	int		debug_req;
	int		debug_stats;
	unsigned int	so_sndbuf;
	unsigned int	so_rcvbuf;
	int		tcp_nodelay;
	unsigned int	tcp_backlog;
	unsigned int	precon_reconnect_timeout;
	int		unexpected_receives;
	int		sched_yield;
	unsigned int	rendezvous_size;
	unsigned int	rendezvous_size_shm;
	unsigned int	rendezvous_size_dapl;
	unsigned int	rendezvous_size_elan;
	unsigned int	rendezvous_size_extoll;
	unsigned int	rendezvous_size_velo;
	unsigned int	psm_uniq_id;
	int		sigquit;
	unsigned int	readahead;
	unsigned int	retry;
	unsigned int	guard;
	unsigned int	skipblocksize;
	unsigned int	iprobe_count;

	char		*network;
	char		*info;
	char		*plugindir;
};


#define PSCOM_ENV_defaults {						\
	.debug = 0,							\
	.debug_req = 0,							\
	.debug_stats = 0,						\
									\
	.so_sndbuf = 32768,						\
	.so_rcvbuf = 32768,						\
	.tcp_nodelay = 1,						\
	.tcp_backlog = 262144 /*SOMAXCONN = 128 */,			\
	.precon_reconnect_timeout = 2000, /* try reconnect in [ms] */	\
									\
	.unexpected_receives = 0,					\
	.sched_yield = 0,						\
	.rendezvous_size = ~0,						\
	.rendezvous_size_shm = ~0, /* default rendezvous_size for shm */ \
	.rendezvous_size_dapl = ~0, /* default rendezvous_size for dapl */ \
	.rendezvous_size_elan = ~0, /* default rendezvous_size for elan */ \
	.rendezvous_size_extoll = ~0, /* default rendezvous_size for extoll */ \
	.rendezvous_size_velo = 1024, /* default rendezvous_size for velo */ \
	.psm_uniq_id = 0,						\
	.sigquit = 0,							\
	.readahead = 100,						\
	.skipblocksize = 8192,						\
	.retry = 10,							\
	.guard = 1,							\
	.iprobe_count = 0,						\
									\
	.network = NULL,						\
	.info = NULL,							\
	.plugindir = "",						\
}


void pscom_env_init(void);

#endif /* _PSCOM_ENV_H_ */
