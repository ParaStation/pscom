/*
 * ParaStation
 *
 * Copyright (C) 2007,2010 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#ifndef _PSCOM_PRIV_H_
#define _PSCOM_PRIV_H_

#include "pscom.h"
#include "pscom_types.h"
#include "list.h"
#include "pscom_ufd.h"
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>

#include "pscom_tcp.h"
#include "pscom_shm.h"
#include "pscom_p4s.h"
#include "pscom_gm.h"
#include "pscom_env.h"
#include "pscom_precon.h"

#include "pscom_debug.h"


#define MAGIC_REQUEST		0x72657175
struct PSCOM_req
{
	unsigned long magic;

	struct list_head next;		/* General purpose next. Used by:
					   - list PSCOM.io_doneq
					   - list pscom_con_t.recvq_rma
					   - list pscom_con_t.sendq
					   - list pscom_con_t.recvq_user
					   - list pscom_con_t.net_recvq_user
					   - list pscom_sock_t.recvq_any
					   - list pscom_sock_t.group_req_unknown
					*/
	struct list_head next_alt;	/* Alternative next. Used by:
					   - list pscom_sock_t.genrecvq_any
					   - list pscom_bcast_req_t.fw_send_requests
					   - list pscom_group_mem_t.recvq
					   - list pscom_group_mem_t.genrecvq
					*/
	struct list_head all_req_next; // used by list struct PSCOM.requests

	struct iovec cur_header;
	struct iovec cur_data;
	unsigned int skip; /* recv: overread skip bytes at the end.
			    * send: skip bytes to send, but currently
			    *       not available (forwards/bcasts) */
	unsigned int pending_io; /* count pending io send requests */

	/* partner_req:
	   rma send:
	   - user req point to rendezvous_req (PSCOM_MSGTYPE_RENDEZVOUS_REQ).
	   rma recv:
	   - generated request point to rendezvous_req
	   - rendezvous requests point to user recv request.
	   bcast fw_send:
	   - fw_send point to req_master
	*/
	pscom_req_t *partner_req;

	void (*write_hook)(pscom_req_t *req, char *buf, unsigned len);

	unsigned int req_no; // debug counter
	pscom_request_t pub;
};

struct con_guard {
	int fd;
};

typedef struct loopback_conn {
	int	sending;
} loopback_conn_t;


typedef struct psib_conn {
	void	*priv;
} psib_conn_t;


typedef struct psoib_conn {
	struct psoib_con_info *mcon;
} psoib_conn_t;


typedef struct psofed_conn {
	struct psofed_con_info *mcon;
	int			reading : 1;
} psofed_conn_t;


typedef struct psdapl_conn {
	struct psdapl_con_info *ci;
} psdapl_conn_t;


typedef struct pselan_conn {
	struct pselan_con_info *ci;
} pselan_conn_t;


typedef struct pspsm_conn {
	struct pspsm_con_info *ci;
	int			reading : 1;
} pspsm_conn_t;


typedef struct psextoll_conn {
	struct psex_con_info *ci;
	int                     reading : 1;
} psextoll_conn_t;


typedef struct psmxm_conn {
	struct psmxm_con_info	*ci;
	int			reading : 1;
	pscom_req_t		*sreq;
} psmxm_conn_t;


typedef struct psucp_conn {
	struct psucp_con_info	*ci;
	int			reading : 1;
} psucp_conn_t;


typedef struct ondemand_conn {
	int node_id; /* on demand node_id to connect to */
	int portno;  /*           portno to connect to */
	char name[8];/* name to listen on */
	unsigned active : 1; /* bool: active listening on new connections? */
} ondemand_conn_t;


typedef struct user_conn {
	void	*priv;
} user_conn_t;


/* rendezvous message for RMA requests. */
typedef struct pscom_rendezvous_msg {
	void		*id; /* == pscom_req_t *user_req; from sending side */
	void		*data;
	unsigned int	data_len;
	union {
		struct {} shm;
		struct {
			uint32_t /* DAT_RMR_CONTEXT */	rmr_context;
			uint64_t /* DAT_CONTEXT */	rmr_vaddr;
		} dapl;
		struct {
			uint64_t /* RMA2_NLA */		rma2_nla; /* Network logical address of the sender */
		} extoll;
		struct {
			uint32_t mr_key;
			uint64_t mr_addr;
			int  padding_size;
			char padding_data[64]; // >= IB_RNDV_PADDING_SIZE (see psoib.h)
		} openib;
	}	arch;
} pscom_rendezvous_msg_t;

static inline
unsigned pscom_rendezvous_msg_size(unsigned arch_size) {
	return sizeof(pscom_rendezvous_msg_t) - sizeof(((pscom_rendezvous_msg_t*)0)->arch) + arch_size;
}

typedef struct pscom_rendezvous_data_shm {
} pscom_rendezvous_data_shm_t;


typedef struct _pscom_rendezvous_data_dapl {
	char /* struct psdapl_rdma_req */ data[128];
} _pscom_rendezvous_data_dapl_t;

typedef struct _pscom_rendezvous_data_extoll {
	/* placeholder for struct pscom_rendezvous_data_extoll */
	char /* struct psex_rma_req */ _rma_req[128];
} _pscom_rendezvous_data_extoll_t;


typedef struct _pscom_rendezvous_data_openib {
	/* placeholder for struct pscom_rendezvous_data_openib */
	char /* struct psiob_rma_req */ _rma_req[128]; /* ??? */
} _pscom_rendezvous_data_openib_t;


typedef struct pscom_rendezvous_data {
	pscom_rendezvous_msg_t	msg;
	int	use_arch_read;
	union {
		pscom_rendezvous_data_shm_t	shm;
		_pscom_rendezvous_data_dapl_t	dapl;
		_pscom_rendezvous_data_extoll_t	extoll;
		_pscom_rendezvous_data_openib_t openib;
	}		arch;
} pscom_rendezvous_data_t;


typedef struct pscom_backlog {
	struct list_head next;
	void (*call)(void *priv);
	void *priv;
} pscom_backlog_t;


#define MAGIC_CONNECTION	0x78626c61
struct PSCOM_con
{
	unsigned long		magic;
	struct list_head	next;
	void (*read_start)(pscom_con_t *con);
	void (*read_stop)(pscom_con_t *con);
	void (*write_start)(pscom_con_t *con);
	void (*write_stop)(pscom_con_t *con);
	void (*do_write)(pscom_con_t *con); // used only if .write_start = pscom_poll_write_start
	void (*close)(pscom_con_t *con);

	/* RMA functions: */
	/* register mem region for RMA. should return size of
	 * rd->msg.arch.xxx (this is used, to calculate the size of
	 * the rendezvous message). return 0 to disable arch read (in
	 * case of a failure). */
	unsigned int (*rma_mem_register)(pscom_con_t *con, pscom_rendezvous_data_t *rd);
	/* deregister mem. */
	void (*rma_mem_deregister)(pscom_con_t *con, pscom_rendezvous_data_t *rd);
	/* return -1 on error.
	   see _pscom_rendezvous_read_data()  */
	int (*rma_read)(pscom_req_t *rendezvous_req, pscom_rendezvous_data_t *rd);
	int (*rma_write)(pscom_con_t *con, void *src, pscom_rendezvous_msg_t *des,
			 void (*io_done)(void *priv), void *priv);

	precon_t		*precon;	// Pre connection handshake data.

	unsigned int		rendezvous_size;
	unsigned int		recv_req_cnt;	// count all receive requests on this connection

	uint16_t		suspend_on_demand_portno; // remote listening portno on suspended connections

	struct list_head	sendq;		// List of pscom_req_t.next

	struct list_head	recvq_user;	// List of pscom_req_t.next
	struct list_head	recvq_ctrl;	// List of pscom_req_t.next
	struct list_head	recvq_rma;	// List of pscom_req_t.next
	/* more receivequeues in pscom_group_t:
	 *                      recvq_bcast */

	struct list_head	net_recvq_user;	// List of pscom_req_t.next
	struct list_head	net_recvq_ctrl; // List of pscom_req_t.next
	/* more net receivequeues in pscom_group_t:
	 *                      net_recvq_bcast */

	pscom_poll_reader_t	poll_reader;
	struct list_head	poll_next_send; // used by pscom.poll_sender

	struct con_guard	con_guard; // connection guard

	struct {
		pscom_req_t	*req;
		pscom_req_t	*req_locked; /* request in use by a plugin with an asynchronous receive (RMA)
						set/unset by pscom_read_get_buf_locked/pscom_read_done_unlock */
		struct iovec	readahead;
		unsigned int	readahead_size;

		unsigned int	skip;
	}			in;

	union {
		loopback_conn_t	loop;
		tcp_conn_t	tcp;
		shm_conn_t	shm;
		p4s_conn_t	p4s;
		psib_conn_t	mvapi;
		psoib_conn_t	openib;
		psofed_conn_t	ofed;
		psgm_conn_t	gm;
		psdapl_conn_t	dapl;
		pselan_conn_t	elan;
		psextoll_conn_t	extoll;
		psmxm_conn_t	mxm;
		psucp_conn_t	ucp;
		ondemand_conn_t ondemand;
		pspsm_conn_t    psm;
		user_conn_t	user; // Future usage (new plugins)
	}			arch;

	struct {
		int		eof_received : 1;
		int		close_called : 1;
		int		suspend_active : 1;
		int		con_cleanup : 1;
	}			state;

	pscom_connection_t	pub;
};


#define MAGIC_SOCKET		0x6a656e73
struct PSCOM_sock
{
	unsigned long		magic;
	struct list_head	next;		// used by list pscom.sockets

	struct list_head	connections;	// List of pscom_con_t.next

	struct list_head	recvq_any;	// List of pscom_req_t.next (all recv any requests)
	struct list_head	genrecvq_any;	// List of pscom_req_t.next_alt(all generated requests)

	struct list_head	groups;		// List of pscom_group_t.next
	struct list_head	group_req_unknown; // List of pscom_req_t.next (requests with unknown group id)

	struct pscom_listener {
		ufd_info_t	ufd_info;	// TCP listen for new connections
		unsigned	usercnt;	// Count the users of the listening fd. (keep fd open, if > 0)
						// (pscom_listen and "on demand" connections)
		unsigned	activecnt;	// Count active listeners. (poll on fd, if > 0)
	} listen;

	unsigned int		recv_req_cnt_any; // count all ANY_SOURCE receive requests on this socket

	struct list_head	pendingioq;	// List of pscom_req_t.next, requests with pending io

	struct list_head	sendq_suspending;// List of pscom_req_t.next, requests from suspending connections

	uint64_t		con_type_mask;	/* allowed con_types.
						   Or'd value from: (1 << (pscom_con_type_t) con_type)
						   default = ~0 */
	tcp_sock_t		tcp;
	shm_sock_t		shm;
	p4s_sock_t		p4s;
//	psib_sock_t		mvapi;
//	psoib_sock_t		openib;
//	psofed_sock_t		ofed;
	psgm_sock_t		gm;
//	psdapl_sock_t		dapl;
//	pselan_sock_t		elan;
//	psextoll_sock_t		extoll;

	pscom_socket_t		pub;
};


struct PSCOM
{
	ufd_t			ufd;
	struct list_head	sockets; // List of pscom_sock_t.next
	struct list_head	requests; // List of pscom_req_t.all_req_next

	pthread_mutex_t		global_lock;
	pthread_mutex_t		lock_requests;
	int			threaded;	// Bool: multithreaded? (=Use locking)

	struct list_head	io_doneq; // List of pscom_req_t.next

	struct list_head	poll_reader;	// List of pscom_poll_reader_t.next
	struct list_head	poll_sender;	// List of pscom_con_t.poll_next_send
	struct list_head	backlog;	// List of pscom_backlog_t.next

	pthread_mutex_t		backlog_lock;	// Lock for backlog

	struct PSCOM_env	env;

	struct {
		unsigned int	reqs;
		unsigned int	gen_reqs;
		unsigned int	gen_reqs_used;

		unsigned int	progresscounter;
		unsigned int	progresscounter_check;

		unsigned int	reqs_any_source; // count enqueued ANY_SOURCE requests in sock->recvq_any
		unsigned int	recvq_any;  // count enqueued requests in sock->recvq_any (SOURCED and ANY_SOURCE)

		unsigned int	probes;		// All probes (including any)
		unsigned int	iprobes_ok;	// All iprobes returning 1 = "received"
		unsigned int	probes_any_source; // All ANY_SOURCE probes

		unsigned int	shm_direct;	// successful shm direct sends
		unsigned int	shm_direct_nonshmptr; // shm direct with copy because !is_psshm_ptr(data)
		unsigned int	shm_direct_failed; // failed shm direct because !is_psshm_ptr(malloc(data))
	}			stat;
};

extern pscom_t pscom;

#define PSCOM_ARCH2CON_TYPE(arch) ((arch) - 101)
#define PSCOM_CON_TYPE2ARCH(con_type) ((con_type) + 101)

/* Keep PSCOM_ARCH_{} in sync with PSCOM_CON_TYPE_{} ! */
#define PSCOM_ARCH_ERROR	101
#define PSCOM_ARCH_LOOP		/* 102 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_LOOP)
#define PSCOM_ARCH_TCP		/* 103 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_TCP)
#define PSCOM_ARCH_SHM		/* 104 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_SHM)
#define PSCOM_ARCH_P4S		/* 105 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_P4S)
#define PSCOM_ARCH_GM		/* 106 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_GM)
#define PSCOM_ARCH_MVAPI	/* 107 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_MVAPI)
#define PSCOM_ARCH_OPENIB	/* 108 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_OPENIB)
#define PSCOM_ARCH_ELAN		/* 109 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_ELAN)
#define PSCOM_ARCH_DAPL		/* 110 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_DAPL)
#define PSCOM_ARCH_ONDEMAND	/* 111 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_ONDEMAND)
#define PSCOM_ARCH_OFED		/* 112 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_OFED)
#define PSCOM_ARCH_EXTOLL	/* 113 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_EXTOLL)
#define PSCOM_ARCH_PSM		/* 114 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_PSM)
#define PSCOM_ARCH_VELO		/* 115 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_VELO)
#define PSCOM_ARCH_CBC		/* 116 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_CBC)
#define PSCOM_ARCH_MXM		/* 117 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_MXM)
#define PSCOM_ARCH_SUSPEND	/* 118 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_SUSPEND)
#define PSCOM_ARCH_UCP		/* 119 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_UCP)
#define PSCOM_ARCH_GW		/* 120 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_GW)


#define PSCOM_TCP_PRIO		2
#define PSCOM_SHM_PRIO		90
#define PSCOM_P4S_PRIO		10
#define PSCOM_GM_PRIO		15
#define PSCOM_MVAPI_PRIO	20
#define PSCOM_OPENIB_PRIO	20
#define PSCOM_ELAN_PRIO		20
#define PSCOM_DAPL_PRIO		15
#define PSCOM_OFED_PRIO		30
#define PSCOM_EXTOLL_PRIO	30
#define PSCOM_PSM_PRIO		30
#define PSCOM_MXM_PRIO		30
#define PSCOM_UCP_PRIO		30


#define PSCOM_MSGTYPE_USER	0
#define PSCOM_MSGTYPE_RMA_WRITE	1
#define PSCOM_MSGTYPE_RMA_READ	2
#define PSCOM_MSGTYPE_RMA_READ_ANSWER	3
#define PSCOM_MSGTYPE_RENDEZVOUS_REQ	4 /* Request for a rendezvous */
#define PSCOM_MSGTYPE_RENDEZVOUS_FIN	5 /* Rendezvous done */
#define PSCOM_MSGTYPE_BCAST	6
#define PSCOM_MSGTYPE_BARRIER	7
#define PSCOM_MSGTYPE_EOF	8
#define PSCOM_MSGTYPE_SUSPEND	9

extern int mt_locked;

static inline
void pscom_lock(void)
{
	if (!pscom.threaded) return;
	int res_mutex_lock;
	res_mutex_lock = pthread_mutex_lock(&pscom.global_lock);
	assert(res_mutex_lock == 0);
}


void pscom_unlock(void);

static inline
void _pscom_unlock(void)
{
	if (!pscom.threaded) return;
	int res_mutex_unlock;
	res_mutex_unlock = pthread_mutex_unlock(&pscom.global_lock);
	assert(res_mutex_unlock == 0);
}


static inline
void pscom_lock_yield(void)
{
	pscom_unlock();
	pscom_lock();
}


static inline
void pscom_call_io_done(void)
{
	pscom_unlock();
	pscom_lock();
}


static inline
pscom_con_t *get_con(pscom_connection_t *con)
{
	return list_entry(con, pscom_con_t, pub);
}


static inline
pscom_sock_t *get_sock(pscom_socket_t *socket)
{
	return list_entry(socket, pscom_sock_t, pub);
}


static inline
pscom_req_t *get_req(pscom_request_t *request)
{
	return list_entry(request, pscom_req_t, pub);
}


/* Get a buffer usable for receives. *buf is valid in the current
 * event dispatch only! Use pscom_read_get_buf_locked() if you need
 * persistent buffer space. */
void
pscom_read_get_buf(pscom_con_t *con, char **buf, size_t *len);

void
pscom_read_done(pscom_con_t *con, char *buf, size_t len);

/* Get a buffer usable for asynchronous RMA operations. Caller has also to
 * call pscom_read_done_unlock() after usage. */
void pscom_read_get_buf_locked(pscom_con_t *con, char **buf, size_t *len);

/* Progress the in stream and unlock the buffer from
 * pscom_read_get_buf_locked(). */
void pscom_read_done_unlock(pscom_con_t *con, char *buf, size_t len);

// return true at the end of each message (no current request)
int pscom_read_is_at_message_start(pscom_con_t *con);

pscom_req_t *pscom_write_get_iov(pscom_con_t *con, struct iovec iov[2]);
void pscom_write_done(pscom_con_t *con, pscom_req_t *req, size_t len);

/* Asynchronous write. len bytes consumed, but not save for reuse (pending io in data)
 * Call pscom_write_pending_done, if io has finished. */
void pscom_write_pending(pscom_con_t *con, pscom_req_t *req, size_t len);

/* Asynchronous write on req done. */
void pscom_write_pending_done(pscom_con_t *con, pscom_req_t *req);


void pscom_con_error(pscom_con_t *con, pscom_op_t operation, pscom_err_t error);
void pscom_con_info(pscom_con_t *con, pscom_con_info_t *con_info);

void _pscom_con_suspend(pscom_con_t *con);
void _pscom_con_resume(pscom_con_t *con);
void _pscom_con_suspend_received(pscom_con_t *con, void *xheader, unsigned xheaderlen);
pscom_err_t _pscom_con_connect_ondemand(pscom_con_t *con,
					int nodeid, int portno, const char name[8]);

/*
void _pscom_send(pscom_con_t *con, unsigned msg_type,
		 void *xheader, unsigned xheader_len,
		 void *data, unsigned data_len);
*/

void _pscom_send_inplace(pscom_con_t *con, unsigned msg_type,
			 void *xheader, unsigned xheader_len,
			 void *data, unsigned data_len,
			 void (*io_done)(pscom_req_state_t state, void *priv), void *priv);

void pscom_poll_write_start(pscom_con_t *con);
void pscom_poll_write_stop(pscom_con_t *con);
void pscom_poll_read_start(pscom_con_t *con);
void pscom_poll_read_stop(pscom_con_t *con);

int pscom_progress(int timeout);

int _pscom_con_type_mask_is_set(pscom_sock_t *sock, pscom_con_type_t con_type);

void pscom_listener_init(struct pscom_listener *listener,
			 void (*can_read)(ufd_t *ufd, ufd_info_t *ufd_info),
			 void *priv);
void pscom_listener_set_fd(struct pscom_listener *listener, int fd);
int  pscom_listener_get_fd(struct pscom_listener *listener);
/* keep fd open, until user_cnt == 0 */
void pscom_listener_user_inc(struct pscom_listener *listener);
void pscom_listener_user_dec(struct pscom_listener *listener);
/* active listening on fd */
void pscom_listener_active_inc(struct pscom_listener *listener);
void pscom_listener_active_dec(struct pscom_listener *listener);

const char *pscom_con_str_reverse(pscom_connection_t *connection);

#endif /* _PSCOM_PRIV_H_ */
