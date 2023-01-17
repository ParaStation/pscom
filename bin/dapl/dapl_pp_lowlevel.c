/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <popt.h>
#include <assert.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "dat/udat.h"


const char *arg_server_addr = NULL;

int arg_loops = 1024;
int arg_maxtime = 3000;
#define MAX_XHEADER 100
int arg_xheader = 10;
unsigned arg_maxmsize = 4 * 1024 * 1024;
int arg_run_once = 0;
int arg_verbose = 0;

static
void parse_opt(int argc, char **argv)
{
	int c;
	poptContext optCon;
	const char *no_arg;

	struct poptOption optionsTable[] = {
		{ "loops"  , 'n', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_loops , 0, "pp loops", "count" },
		{ "time"  , 't', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_maxtime, 0, "max time", "ms" },
		{ "maxsize"  , 0, POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_maxmsize , 0, "maximal messagesize", "size" },
		{ "xheader"  , 0, POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_xheader , 0, "xheader size", "size" },

		{ "once" , '1', POPT_ARGFLAG_OR | POPT_ARG_VAL,
		  &arg_run_once, 1, "stop after one client", NULL },

		{ "verbose"	, 'v', POPT_ARG_NONE,
		  NULL		, 'v', "increase verbosity", NULL },
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext(NULL, argc, (const char **) argv, optionsTable, 0);

	poptSetOtherOptionHelp(optCon, "[serveraddr]");

	while ((c = poptGetNextOpt(optCon)) >= 0) {
		switch (c) { // c = poptOption.val;
		case 'v': arg_verbose++; break;
		//default: fprintf(stderr, "unhandled popt value %d\n", c); break;
		}
	}

	if (c < -1) { /* an error occurred during option processing */
		fprintf(stderr, "%s: %s\n",
			poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
			poptStrerror(c));
		poptPrintHelp(optCon, stderr, 0);
		exit(1);
	}

//	arg_1 = poptGetArg(optCon);
//	arg_2 = poptGetArg(optCon);
	/* if (arg_client)*/ {
		const char *server = poptGetArg(optCon);
		if (server) arg_server_addr = server;
	}

	no_arg = poptGetArg(optCon); // should return NULL
	if (no_arg) {
		fprintf(stderr, "%s: %s\n",
			no_arg, poptStrerror(POPT_ERROR_BADOPT));
		poptPrintHelp(optCon, stderr, 0);
		exit(1);
	}

	poptFreeContext(optCon);
}


#define EVD_MIN_QLEN	8
#define PSDAPL_BUFPAIR_SIZE (10000*1000)
//char *mem;
//char *remote_mem;

/**************************************************************************************/
int psdapl_debug = 2;

#define psdapl_dprint(level,fmt,arg... ) do {			\
	if ((level) <= psdapl_debug) {				\
		fprintf(stderr, "<psdapl:"fmt">\n",##arg);	\
		fflush(stderr);					\
	}							\
}while(0);

#define psdapl_dprint_dat_err(level,dat_err,fmt,arg... ) do {		\
	if ((level) <= psdapl_debug) {					\
		const char *major_message = "?";			\
		const char *minor_message = "?";			\
		DAT_RETURN __res = dat_strerror(dat_err, &major_message,	\
					      &minor_message);		\
		assert(__res == DAT_SUCCESS);				\
									\
		psdapl_dprint(level, fmt " : %s : %s",##arg,		\
			      major_message, minor_message);		\
	}								\
}while(0);

#define psdapl_dprint_errno(level,_errno,fmt,arg... ) do {		\
	if ((level) <= psdapl_debug) {					\
		psdapl_dprint(level, fmt " : %s",##arg,			\
			      strerror(_errno));			\
	}								\
}while(0);


static inline
DAT_VADDR psdapl_mem2vaddr(char *mem)
{
	return (DAT_VADDR)(long)mem;
}

typedef struct psdapl_bufpair {
	char		*lmr_mem;
	DAT_LMR_CONTEXT lmr_context;
	// DAT_VADDR	lmr_vaddr; == psdapl_mem2vaddr(lmr_mem);

	DAT_RMR_CONTEXT rmr_context;
	DAT_VADDR	rmr_vaddr;

	DAT_LMR_HANDLE  lmr_handle;
	DAT_RMR_CONTEXT lmr_rmr_context;
} psdapl_bufpair_t;


typedef struct psdapl_init_msg {
	struct {
		DAT_RMR_CONTEXT rmr_context;
		DAT_VADDR	vaddr;
	} send;
	struct {
		DAT_RMR_CONTEXT rmr_context;
		DAT_VADDR	vaddr;
	} recv;
} psdapl_init_msg_t;


static
DAT_EVD_HANDLE async_evd_handle = DAT_HANDLE_NULL;


typedef struct psdapl_socket {
	DAT_IA_HANDLE ia_handle;
	DAT_SOCK_ADDR sock_addr;

	DAT_PZ_HANDLE pz_handle;

	DAT_PSP_HANDLE psp_handle;
	DAT_EVD_HANDLE evd_handle;

	DAT_CONN_QUAL listen_conn_qual;
} psdapl_socket_t;


typedef struct psdapl_con_info {
	psdapl_bufpair_t send_bufs;
	psdapl_bufpair_t recv_bufs;

	DAT_EVD_HANDLE recv_evd_handle;
	DAT_EVD_HANDLE connect_evd_handle;
	DAT_EP_HANDLE  ep_handle;
} psdapl_con_info_t;



/* return -1 on error. on error debug messages printed on stderr */
static
int psdapl_bufpair_init_local(psdapl_bufpair_t *bufp, size_t size,
			      DAT_IA_HANDLE ia_handle, DAT_PZ_HANDLE pz_handle)
{
	DAT_RETURN res;

	bufp->lmr_mem = valloc(size);
	memset(bufp->lmr_mem, 0xee, size); /* touch the mem */

	if (!bufp->lmr_mem) goto err_malloc;

	DAT_REGION_DESCRIPTION region;
	region.for_va = bufp->lmr_mem;

	DAT_VLEN registered_size = 0;
	DAT_VADDR registered_address = 0;

	res = dat_lmr_create(
		ia_handle,
		DAT_MEM_TYPE_VIRTUAL,
		region,
		size,
		pz_handle,
		DAT_MEM_PRIV_ALL_FLAG,
		&bufp->lmr_handle,
		&bufp->lmr_context,
		&bufp->lmr_rmr_context,
		&registered_size,
		&registered_address);

	if (res != DAT_SUCCESS) goto err_lmr_create;

	return 0;
err_malloc:
	psdapl_dprint_errno(1, errno, "calloc(%lu, 1) failed", (long)size);
	return -1;
err_lmr_create:
	psdapl_dprint_dat_err(1, res, "dat_lmr_create() failed");
	return -1;
}


static
void psdapl_bufpair_init_remote(psdapl_bufpair_t *bufp,
				DAT_RMR_CONTEXT rmr_context, DAT_VADDR rmr_vaddr)
{
	bufp->rmr_context = rmr_context;
	bufp->rmr_vaddr = rmr_vaddr;
}


/* return -1 on error. dprint on stderr */
static
int psdapl_ia_open(DAT_IA_HANDLE *ia_handlep, /*const*/char *ia_name)
{
	DAT_RETURN dat_rc;
	DAT_IA_HANDLE ia_handle;

	dat_rc = dat_ia_open(ia_name, EVD_MIN_QLEN, &async_evd_handle, &ia_handle);
	if (dat_rc != DAT_SUCCESS) goto err_dat_ia_open;

	*ia_handlep = ia_handle;

	psdapl_dprint(3, "dat_ia_open(\"%s\", ...) success", ia_name);
	return 0;
err_dat_ia_open:
	psdapl_dprint_dat_err(1, dat_rc, "dat_ia_open(\"%s\", ...) failed", ia_name);
	return -1;
}


static
void psdapl_ia_close(DAT_IA_HANDLE ia_handle)
{
	dat_ia_close(ia_handle, DAT_CLOSE_DEFAULT);
}


/* Initialize addr with ia address of ia_handle.
   on error: memset(addr,0) and return -1. */
static
int psdapl_get_sock_addr(DAT_SOCK_ADDR *addr, DAT_IA_HANDLE ia_handle)
{
	DAT_EVD_HANDLE	evd_handle;
	DAT_IA_ATTR	ia_attr;
	DAT_RETURN	dat_rc;

	dat_rc = dat_ia_query(ia_handle, &async_evd_handle,
			      DAT_IA_FIELD_IA_ADDRESS_PTR,
			      &ia_attr, 0, NULL);
	if (dat_rc != DAT_SUCCESS) goto err_dat_ia_query;

	memcpy(addr, ia_attr.ia_address_ptr, sizeof(*addr));

	return 0;
err_dat_ia_query:
	psdapl_dprint_dat_err(1, dat_rc, "dat_ia_query(DAT_IA_FIELD_IA_ADDRESS_PTR) failed");
	memset(addr, 0, sizeof(*addr));
	return -1;
}


/* return -1 on error */
static
int psdapl_pz_create(DAT_PZ_HANDLE *pz_handle, DAT_IA_HANDLE ia_handle)
{
	DAT_RETURN dat_rc;
	dat_rc = dat_pz_create(ia_handle, pz_handle);
	if (dat_rc != DAT_SUCCESS) goto err_pz_create;

	return 0;
err_pz_create:
	psdapl_dprint_dat_err(1, dat_rc, "dat_pz_create() failed");
	return -1;
}


const char *psdapl_addr2str(DAT_SOCK_ADDR *addr, DAT_CONN_QUAL conn_qual)
{
	static char buf[sizeof(
			"ffffff_000:001:002:003:004:005:006:007:008:009:010:011:012:013_12345678910_save_")];
	snprintf(buf, sizeof(buf),
		 "%u_%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u_%lu",
		 addr->sa_family,
		 (unsigned char) addr->sa_data[0], (unsigned char) addr->sa_data[1],
		 (unsigned char) addr->sa_data[2], (unsigned char) addr->sa_data[3],
		 (unsigned char) addr->sa_data[4], (unsigned char) addr->sa_data[5],
		 (unsigned char) addr->sa_data[6], (unsigned char) addr->sa_data[7],
		 (unsigned char) addr->sa_data[8], (unsigned char) addr->sa_data[9],
		 (unsigned char) addr->sa_data[10], (unsigned char) addr->sa_data[11],
		 (unsigned char) addr->sa_data[12], (unsigned char) addr->sa_data[13],
		 (unsigned long)conn_qual);
	return buf;
}


/* return -1 on parse error */
int psdapl_str2addr(DAT_SOCK_ADDR *addr, DAT_CONN_QUAL *conn_qual, const char *str)
{
	if (!addr || !str) return -1;
	unsigned data[14];
	unsigned long cq;
	unsigned fam;
	int rc;
	int i;
	rc = sscanf(str,
		    "%u_%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u_%lu",
		    &fam,
		    &data[0], &data[1], &data[2], &data[3],
		    &data[4], &data[5], &data[6], &data[7],
		    &data[8], &data[9], &data[10], &data[11],
		    &data[12], &data[13], &cq);

	addr->sa_family = fam;
	for (i = 0; i < 14; i++) addr->sa_data[i] = data[i];
	*conn_qual = cq;
	return rc == 16 ? 0 : -1;
}


/* return 0 on success, -1 on error */
int psdapl_init(psdapl_socket_t *socket)
{
	static int init_state = 1;
	if (init_state == 1) {
		int rc;
		init_state = 0;

		memset(socket, 0, sizeof(*socket));

		/* ToDo: Use some environment variable */
		rc = psdapl_ia_open(&socket->ia_handle, "ib0") &&
			psdapl_ia_open(&socket->ia_handle, "nes0");
		if (rc) goto err_ia_open;

		rc = psdapl_get_sock_addr(&socket->sock_addr, socket->ia_handle);
		if (rc) goto err_get_sock;

		rc = psdapl_pz_create(&socket->pz_handle, socket->ia_handle);
		if (rc) goto err_pz_create;
	}

	return init_state; /* 0 = success, -1 = error */
err_pz_create:
err_get_sock:
	psdapl_ia_close(socket->ia_handle);
err_ia_open:
	init_state = -1;
	return init_state;
}


/* return -1 on error. */
int psdapl_listen(psdapl_socket_t *socket)
{
	DAT_RETURN dat_rc;

	if (socket->psp_handle) return 0; /* already listening */

	dat_rc = dat_evd_create(socket->ia_handle,
				EVD_MIN_QLEN /* ToDo: evd_min_qlen */,
				DAT_HANDLE_NULL, // cno_handle
				DAT_EVD_CR_FLAG,//DAT_EVD_DEFAULT_FLAG,
				&socket->evd_handle);
	if (dat_rc != DAT_SUCCESS) goto err_evd_create;

	DAT_CONN_QUAL conn_qual = getpid();
	int maxcnt = 100;
	while (1) {
		dat_rc = dat_psp_create(socket->ia_handle,
					conn_qual,
					socket->evd_handle,
					DAT_PSP_CONSUMER_FLAG /* DAT_PSP_PROVIDER_FLAG */,
					&socket->psp_handle);

		if (dat_rc == DAT_SUCCESS) break;
		maxcnt--;
		if (!maxcnt ||
		    (DAT_GET_TYPE(dat_rc) != DAT_CONN_QUAL_IN_USE)) goto err_psp_create;

		conn_qual++;
	}

	socket->listen_conn_qual = conn_qual;

	return 0;
err_psp_create:
	psdapl_dprint_dat_err(0, dat_rc, "dat_psp_create(conn_qual=%u) failed",
			      (unsigned)conn_qual);
	return -1;
err_evd_create:
	psdapl_dprint_dat_err(0, dat_rc, "dat_evd_create() failed");
	return -1;

}


static
void psdapl_init_init_msg(psdapl_init_msg_t *imsg, psdapl_con_info_t *ci)
{
	imsg->send.rmr_context = ci->recv_bufs.lmr_rmr_context;
	imsg->send.vaddr = psdapl_mem2vaddr(ci->recv_bufs.lmr_mem);

	imsg->recv.rmr_context = ci->send_bufs.lmr_rmr_context;
	imsg->recv.vaddr = psdapl_mem2vaddr(ci->send_bufs.lmr_mem);
}


static
int psdapl_create_ep(psdapl_socket_t *socket, psdapl_con_info_t *ci)
{
	DAT_RETURN dat_rc;

	dat_rc = dat_evd_create(socket->ia_handle,
				EVD_MIN_QLEN,
				DAT_HANDLE_NULL, // cno_handle
				DAT_EVD_DTO_FLAG,//DAT_EVD_DEFAULT_FLAG,
				&ci->recv_evd_handle);
	if (dat_rc != DAT_SUCCESS) goto err_recv_evd_create;

	dat_rc = dat_evd_create(socket->ia_handle,
				EVD_MIN_QLEN,
				DAT_HANDLE_NULL, // cno_handle
				DAT_EVD_CR_FLAG | DAT_EVD_CONNECTION_FLAG,
				&ci->connect_evd_handle);
	if (dat_rc != DAT_SUCCESS) goto err_connect_evd_create;

	dat_rc = dat_ep_create(socket->ia_handle,
			       socket->pz_handle,
			       ci->recv_evd_handle,
			       ci->recv_evd_handle,
			       ci->connect_evd_handle,
			       NULL /* DAT_EP_ATTR *ep_attributes */,
			       &ci->ep_handle);

	if (dat_rc != DAT_SUCCESS) goto err_ep_create;

	return 0;
err_ep_create:
	psdapl_dprint_dat_err(0, dat_rc, "dat_ep_create() failed");
	return -1;
err_connect_evd_create:
	psdapl_dprint_dat_err(0, dat_rc, "connect : dat_evd_create() failed");
	return -1;
err_recv_evd_create:
	psdapl_dprint_dat_err(0, dat_rc, "recv : dat_evd_create() failed");
	return -1;
}


static
psdapl_con_info_t *_psdapl_get_con_accept(psdapl_socket_t *socket,
					 DAT_CR_HANDLE cr_handle,
					 psdapl_init_msg_t *imsg)
{
	psdapl_con_info_t *ci = calloc(sizeof(*ci), 1);
	DAT_RETURN dat_rc;
	int rc;

	rc = psdapl_bufpair_init_local(&ci->send_bufs, PSDAPL_BUFPAIR_SIZE,
				       socket->ia_handle, socket->pz_handle);
	if (rc) goto err_init_send;

	rc = psdapl_bufpair_init_local(&ci->recv_bufs, PSDAPL_BUFPAIR_SIZE,
				       socket->ia_handle, socket->pz_handle);
	if (rc) goto err_init_recv;

	psdapl_bufpair_init_remote(&ci->send_bufs,
				   imsg->send.rmr_context, imsg->send.vaddr);
	psdapl_bufpair_init_remote(&ci->recv_bufs,
				   imsg->recv.rmr_context, imsg->recv.vaddr);

	rc = psdapl_create_ep(socket, ci);
	if (rc) goto err_create_ep;

	psdapl_init_msg_t res_imsg;
	psdapl_init_init_msg(&res_imsg, ci);

	/* accept connect request. Send info message about my buffers: */
	dat_rc = dat_cr_accept(cr_handle,
			       ci->ep_handle,//   DAT_HANDLE_NULL /* ep_handle */,
			       sizeof(res_imsg) /* private_data_size */,
			       &res_imsg /* private_data*/);
	if (dat_rc != DAT_SUCCESS) goto err_cr_accept;

	return ci;
	/*---*/
err_cr_accept:
	psdapl_dprint_dat_err(0, dat_rc, "CR: dat_cr_accept() failed");
err_create_ep:
err_init_send:
err_init_recv:
	/* ToDo: Cleanup recv_evd_handle!! */
	/* ToDo: Cleanup connect_evd_handle!! */
	/* ToDo: Cleanup bufpairs!!!!! */
	return NULL;
}

/* return NULL on error */
static
psdapl_con_info_t *psdapl_accept_wait(psdapl_socket_t *socket)
{
	DAT_EVENT event;
	DAT_COUNT nmore;
	DAT_RETURN dat_rc;
	dat_rc = dat_evd_wait(socket->evd_handle,
			      DAT_TIMEOUT_INFINITE /* 5*1000*1000 timeout in usec*/,
			      1 /* threshold */,
			      &event, &nmore);

	switch (DAT_GET_TYPE(dat_rc)) {
/*
	case DAT_TIMEOUT_EXPIRED:
		fprintf(stderr, "<mark (timeout)>\n");
		break;
*/
	case DAT_SUCCESS:
		switch (event.event_number) {
		case DAT_CONNECTION_EVENT_TIMED_OUT:
			psdapl_dprint(2, "psdapl_accept_wait: event DAT_CONNECTION_EVENT_TIMED_OUT");
			break;
		case DAT_CONNECTION_REQUEST_EVENT:
			psdapl_dprint(3, "psdapl_accept_wait: event DAT_CONNECTION_REQUEST_EVENT");

			DAT_CR_ARRIVAL_EVENT_DATA *cr = &event.event_data.cr_arrival_event_data;
			DAT_CR_PARAM cr_param;

			dat_rc = dat_cr_query(cr->cr_handle, DAT_CR_FIELD_ALL, &cr_param);
			assert(dat_rc == DAT_SUCCESS);

			psdapl_init_msg_t *imsg = (psdapl_init_msg_t *)(cr_param.private_data);

			return _psdapl_get_con_accept(socket, cr->cr_handle, imsg);
			break;
			/*
			  DAT_DTO_COMPLETION_EVENT                     = 0x00001,
			  DAT_RMR_BIND_COMPLETION_EVENT                = 0x01001,
			  DAT_CONNECTION_REQUEST_EVENT                 = 0x02001,
			  DAT_CONNECTION_EVENT_ESTABLISHED             = 0x04001,
			  DAT_CONNECTION_EVENT_PEER_REJECTED           = 0x04002,
			  DAT_CONNECTION_EVENT_NON_PEER_REJECTED       = 0x04003,
			  DAT_CONNECTION_EVENT_ACCEPT_COMPLETION_ERROR = 0x04004,
			  DAT_CONNECTION_EVENT_DISCONNECTED            = 0x04005,
			  DAT_CONNECTION_EVENT_BROKEN                  = 0x04006,
			  DAT_CONNECTION_EVENT_TIMED_OUT               = 0x04007,
			  DAT_CONNECTION_EVENT_UNREACHABLE             = 0x04008,
			  DAT_ASYNC_ERROR_EVD_OVERFLOW                 = 0x08001,
			  DAT_ASYNC_ERROR_IA_CATASTROPHIC              = 0x08002,
			  DAT_ASYNC_ERROR_EP_BROKEN                    = 0x08003,
			  DAT_ASYNC_ERROR_TIMED_OUT                    = 0x08004,
			  DAT_ASYNC_ERROR_PROVIDER_INTERNAL_ERROR      = 0x08005,
			  DAT_SOFTWARE_EVENT                           = 0x10001
			*/
		default:
			psdapl_dprint(2, "psdapl_accept_wait: unexpected event 0x%x",
				      (unsigned)event.event_number);
			break;
		}
		break;
	default:
		psdapl_dprint_dat_err(1, dat_rc, "psdapl_accept_wait: dat_evd_wait()");
	}

	return NULL; /* error */
}


psdapl_con_info_t *psdapl_connect(psdapl_socket_t *socket, DAT_SOCK_ADDR *addr, DAT_CONN_QUAL conn_qual)
{
	psdapl_con_info_t *ci = calloc(sizeof(*ci), 1);
	int rc;
	DAT_RETURN dat_rc;

	rc = psdapl_bufpair_init_local(&ci->send_bufs, PSDAPL_BUFPAIR_SIZE,
				       socket->ia_handle, socket->pz_handle);
	if (rc) goto err_init_send;

	rc = psdapl_bufpair_init_local(&ci->recv_bufs, PSDAPL_BUFPAIR_SIZE,
				       socket->ia_handle, socket->pz_handle);
	if (rc) goto err_init_recv;

	rc = psdapl_create_ep(socket, ci);
	if (rc) goto err_create_ep;

	psdapl_init_msg_t res_imsg;
	psdapl_init_init_msg(&res_imsg, ci);

	dat_rc = dat_ep_connect(ci->ep_handle,
				addr,
				conn_qual,
				DAT_TIMEOUT_INFINITE /* 5 * 1000 * 1000 */,

				sizeof(res_imsg) /* private_data_size */,
				&res_imsg /* private_data */,
				DAT_QOS_BEST_EFFORT /* DAT_QOS */,
				DAT_CONNECT_DEFAULT_FLAG /* DAT_CONNECT_FLAGS */);
	if (dat_rc != DAT_SUCCESS) goto err_ep_connect;


	DAT_EVENT event;
	DAT_COUNT nmore;

	event.event_number = -1;
	dat_rc = dat_evd_wait(ci->connect_evd_handle,
			      DAT_TIMEOUT_INFINITE /* 5*1000*1000 timeout in usec*/,
			      1 /* threshold */,
			      &event, &nmore);


	psdapl_init_msg_t *imsg = NULL;

	switch (DAT_GET_TYPE(dat_rc)) {
/*
	case DAT_TIMEOUT_EXPIRED:
		fprintf(stderr, "<mark (timeout)>\n");
		break;
*/
	case DAT_SUCCESS:
		switch (event.event_number) {
		case DAT_CONNECTION_EVENT_TIMED_OUT:
			psdapl_dprint(2, "psdapl_connect: event DAT_CONNECTION_EVENT_TIMED_OUT");
			break;
		case DAT_CONNECTION_EVENT_ESTABLISHED:
			psdapl_dprint(3, "psdapl_connect: event DAT_CONNECTION_EVENT_ESTABLISHED");

			DAT_CONNECTION_EVENT_DATA *cd = &event.event_data.connect_event_data;

			imsg = (psdapl_init_msg_t *)(cd->private_data);

			break;
		default:
			psdapl_dprint(2, "psdapl_connect: unexpected event 0x%x",
				      (unsigned)event.event_number);
			break;
		}

		break;
	default:
		psdapl_dprint_dat_err(1, dat_rc, "psdapl_connect: dat_evd_wait()");
		break;
	}


	if (!imsg) goto err_wait;
	psdapl_bufpair_init_remote(&ci->send_bufs,
				   imsg->send.rmr_context, imsg->send.vaddr);
	psdapl_bufpair_init_remote(&ci->recv_bufs,
				   imsg->recv.rmr_context, imsg->recv.vaddr);

	return ci;
	/* --- */
err_ep_connect:
	psdapl_dprint_dat_err(0, dat_rc, "dat_ep_connect() failed");
	goto err_all;
	/* --- */
err_all:
err_wait:
err_create_ep:
err_init_recv:
err_init_send:
	/* ToDo: Cleanup recv_evd_handle!! */
	/* ToDo: Cleanup connect_evd_handle!! */
	/* ToDo: Cleanup bufpairs!!!!! */
	return NULL;
}


/* return -1 on error */
static
int psdapl_flush_sendbuf(psdapl_socket_t *sock, psdapl_con_info_t *ci,
			 off_t offset, size_t size)
{
	DAT_RETURN dat_rc;
	DAT_LMR_TRIPLET lmr;
	DAT_RMR_TRIPLET rmr;

	lmr.lmr_context = ci->send_bufs.lmr_context;
	lmr.pad = 0;
	lmr.virtual_address = psdapl_mem2vaddr(ci->send_bufs.lmr_mem) + offset;
	lmr.segment_length = size;

	rmr.rmr_context = ci->send_bufs.rmr_context;
	rmr.pad = 0;
	rmr.target_address = ci->send_bufs.rmr_vaddr + offset;
	rmr.segment_length = size;

	DAT_DTO_COOKIE cookie;
	cookie.as_64 = 0;//0x1234;

	dat_rc = dat_ep_post_rdma_write(ci->ep_handle, 1,
					&lmr, cookie, &rmr, 0/* DAT_COMPLETION_SUPPRESS_FLAG*/);
	if (dat_rc != DAT_SUCCESS) goto err_rdma_write;

	return 0;
err_rdma_write:
	psdapl_dprint_dat_err(0, dat_rc, "dat_ep_post_rdma_write() failed");
	return -1;
}


void psdapl_flush_evd(psdapl_socket_t *sock, psdapl_con_info_t *ci)
{
	while (1) {
		DAT_RETURN dat_rc;
		DAT_EVENT event;
		DAT_COUNT nmore = 0;
#if 0
		dat_rc = dat_evd_wait(ci->recv_evd_handle,
				      0 /*timeout in usec*/,
				      1 /* threshold */,
				      &event, &nmore);
#else
		dat_rc = dat_evd_dequeue(ci->recv_evd_handle, &event);
		nmore = DAT_GET_TYPE(dat_rc) != DAT_QUEUE_EMPTY;
#endif

		if (psdapl_debug >= 2) {
			/* Only debug prints: */
			switch (DAT_GET_TYPE(dat_rc)) {
			case DAT_TIMEOUT_EXPIRED:
				psdapl_dprint(3, "psdapl_flush_evd event DAT_TIMEOUT_EXPIRED. nmore:%d", nmore);
				break;
			case DAT_SUCCESS:
				switch (event.event_number) {
				case DAT_DTO_COMPLETION_EVENT:
					psdapl_dprint(3, "psdapl_flush_evd event DAT_DTO_COMPLETION_EVENT. nmore:%d", nmore);
					break;
				default:
					psdapl_dprint(1, "psdapl_flush_evd: unexpected event 0x%x. nmore:%d",
						      (unsigned)event.event_number, nmore);
					break;
				}
				break;
			case DAT_QUEUE_EMPTY:
				psdapl_dprint(3, "psdapl_flush_evd event DAT_QUEUE_EMPTY. nmore:%d", nmore);
				break;
			default:
				psdapl_dprint_dat_err(1, dat_rc, "psdapl_flush_evd: dat_evd_wait(). nmore:%d",
						      nmore);
			}
		}
		if (!nmore) break;
	}
}


typedef struct tail {
	volatile uint32_t len;
	volatile uint32_t mark;
} tail_t;

static
void idle(void)
{
	volatile unsigned y;
	y++;
//	sched_yield();
}


static
void run_pp_server(psdapl_socket_t *sock, psdapl_con_info_t *ci)
{
#if 0
	unsigned cnt = 0;
	snprintf(ci->recv_bufs.lmr_mem, PSDAPL_BUFPAIR_SIZE, "InitServer");
	while (1) {
		cnt++;

		snprintf(ci->send_bufs.lmr_mem, PSDAPL_BUFPAIR_SIZE,
			 "ServerMessage#%u", cnt);
		psdapl_flush_sendbuf(sock, ci, 0, strlen(ci->send_bufs.lmr_mem) + 1);
		psdapl_flush_evd(sock, ci);
		printf("Send: %30s Recv: %30s\n",
		       ci->send_bufs.lmr_mem, ci->recv_bufs.lmr_mem);
		usleep(900*1000);
	}
#else
	tail_t *send_tail = (tail_t *)(ci->send_bufs.lmr_mem + PSDAPL_BUFPAIR_SIZE - sizeof(tail_t));
	tail_t *recv_tail = (tail_t *)(ci->recv_bufs.lmr_mem + PSDAPL_BUFPAIR_SIZE - sizeof(tail_t));

	while (1) {
		while (recv_tail->mark != 1) idle();

		unsigned len = recv_tail->len;
		char *rbuf = (char*)recv_tail - len;
		char *sbuf = (char*)send_tail - len;

		memcpy(sbuf, rbuf, len);
		send_tail->len = len;
		send_tail->mark = 1;
		recv_tail->mark = 0;

		psdapl_flush_sendbuf(sock, ci,
				     sbuf - ci->send_bufs.lmr_mem,
				     len + sizeof(tail_t));
		psdapl_flush_evd(sock, ci);
	}
#endif
}


static
int run_pp_c(psdapl_socket_t *sock, psdapl_con_info_t *ci, unsigned msgsize, unsigned loops)
{
	unsigned cnt;
	tail_t *send_tail = (tail_t *)(ci->send_bufs.lmr_mem + PSDAPL_BUFPAIR_SIZE - sizeof(tail_t));
	tail_t *recv_tail = (tail_t *)(ci->recv_bufs.lmr_mem + PSDAPL_BUFPAIR_SIZE - sizeof(tail_t));
	recv_tail->len = msgsize;

	for (cnt = 0; cnt < loops; cnt++) {
		unsigned len = recv_tail->len;
		char *rbuf = (char*)recv_tail - len;
		char *sbuf = (char*)send_tail - len;

		memcpy(sbuf, rbuf, len);
		send_tail->len = len;
		send_tail->mark = 1;
		recv_tail->mark = 0;


		psdapl_flush_sendbuf(sock, ci,
				     sbuf - ci->send_bufs.lmr_mem,
				     len + sizeof(tail_t));
		psdapl_flush_evd(sock, ci);

		while (recv_tail->mark != 1) idle();
	}
	recv_tail->mark = 0;
	assert(recv_tail->len == msgsize);
	return 0;
}


static inline
unsigned long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return (tv.tv_usec+tv.tv_sec*1000000);
}


static
void run_pp_client(psdapl_socket_t *sock, psdapl_con_info_t *ci)
{
#if 0
	unsigned cnt = 0;
	snprintf(ci->recv_bufs.lmr_mem, PSDAPL_BUFPAIR_SIZE, "InitClient");
	while (1) {
		cnt++;

		snprintf(ci->send_bufs.lmr_mem, PSDAPL_BUFPAIR_SIZE,
			 "ClientMessage#%u", cnt);

		psdapl_flush_sendbuf(sock, ci, 0, strlen(ci->send_bufs.lmr_mem) + 1);
		psdapl_flush_evd(sock, ci);
		printf("Send: %30s Recv: %30s\n",
		       ci->send_bufs.lmr_mem, ci->recv_bufs.lmr_mem);
		sleep(1);
	}
#else
	unsigned long t1, t2;
	double time;
	double throuput;
	unsigned int msgsize;
	double ms;
	int res;
	double loops = arg_loops;

	if (arg_maxmsize >= PSDAPL_BUFPAIR_SIZE - sizeof(tail_t)) {
		arg_maxmsize = PSDAPL_BUFPAIR_SIZE - sizeof(tail_t);
	}

	printf("%7s %8s %8s %8s\n", "msize", "loops", "time", "throughput");
	printf("%7s %8s %8s %8s\n", "[bytes]", "[cnt]", "[us/cnt]", "[MB/s]");
	for (ms = 1.4142135; ms < arg_maxmsize; ms = ms * 1.4142135) {
		unsigned int iloops = loops;
		msgsize = ms + 0.5;

		/* warmup, for sync */
		run_pp_c(sock, ci, 2, 5);

		t1 = getusec();
		res = run_pp_c(sock, ci, msgsize, iloops);
		t2 = getusec();

		time = (double)(t2 - t1) / (iloops * 2);
		throuput = msgsize / time;
		if (res == 0) {
			printf("%7d %8d %8.2f %8.2f\n", msgsize, iloops, time, throuput);
			fflush(stdout);
		} else {
			printf("Error in communication...\n");
		}

		{
			double t = (t2 - t1) / 1000;
			while (t > arg_maxtime) {
				loops = loops / 1.4142135;
				t /= 1.4142135;
			}
			if (loops < 1) loops = 1;
		}
	}
#endif

}


int main(int argc, char **argv)
{
	int rc;

	parse_opt(argc, argv);

	psdapl_debug = arg_verbose;

	psdapl_socket_t socket;

	rc = psdapl_init(&socket);
	assert(rc == 0);

	if (!arg_server_addr) { // server
		do {

			rc = psdapl_listen(&socket);

			printf("Waiting for client.\nCall client with:\n");
			printf("%s %s\n", argv[0],
			       psdapl_addr2str(&socket.sock_addr, socket.listen_conn_qual));

			psdapl_con_info_t *ci = psdapl_accept_wait(&socket);
			if (!ci) continue;
			/*
			while (1) {
				con = pscom_get_next_connection(socket, NULL);
				if (con) {
					break;
				} else {
					pscom_wait_any();
				}
			}
			pscom_stop_listen(socket);
			*/
			run_pp_server(&socket, ci);
//			psdapl_close_con(ci);

		} while (!arg_run_once);
	} else {
		DAT_SOCK_ADDR sock_addr;
		DAT_CONN_QUAL conn_qual;

		rc = psdapl_str2addr(&sock_addr, &conn_qual,  arg_server_addr);
		if (rc) {
			psdapl_dprint(0, "Can parse server address \"%s\"", arg_server_addr);
			exit(1);
		}

		psdapl_con_info_t *ci = psdapl_connect(&socket, &sock_addr, conn_qual);

		if (!ci) {
			psdapl_dprint(0, "Connect server at \"%s\" failed", arg_server_addr);
			exit(1);
		}

		run_pp_client(&socket, ci);
	}


	return 0;
}
