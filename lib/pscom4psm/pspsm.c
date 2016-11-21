/*
 * ParaStation
 *
 * Copyright (C) 2016 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#include "pspsm.h"
#include "pscom_util.h"
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef PSM1
#include "psm2.h"
#include "psm2_mq.h"
#else
#include "psm1_compat.h"
#endif

struct pspsm_con_info {
	/* general info */
	psm2_epaddr_t epaddr;    /**< destination address of peer */
	uint64_t send_id;       /**< tag used when sending to peer */
	uint64_t recv_id;       /**< tag used when receiving from peer*/
	int con_broken;         /**< set to 1 if connection broken */

	/* sending */
	struct PSCOM_req *sreq;       /**< pscom open send request */
	size_t sreq_len;	/**< size of open send request */
	psm2_mq_req_t sreqs[2];  /**< MQ send requests */

	/* receiving */
	char* rbuf;             /**< buffer used for current receive */
	psm2_mq_req_t rreq;      /**< MQ recv request */

	/* pointing back */
	struct PSCOM_con *con;

	/* debug */
	uint64_t magic;
};


/*
 * UUID Helper
 */
typedef union {
	psm2_uuid_t as_uuid;
	unsigned int as_uint;
} pspsm_uuid_t;


/*
 * use 48 bits for the peer id
 * and 16 bits for other information
 */
static const uint64_t PSPSM_MAGIC_IO = UINTMAX_C(1) << 48;
static const uint64_t mask = (UINTMAX_C(1) << 48) - 1;

int pspsm_debug = 2;
FILE *pspsm_debug_stream = NULL;


/*
 * For now, psm allows only one endpoint per process, so we can safely
 * use a global variable.
 */
static char *pspsm_err_str = NULL; /* last error string */
static char* sendbuf = NULL;
static pspsm_uuid_t pspsm_uuid;
static psm2_epid_t pspsm_epid;
static psm2_ep_t pspsm_ep;
static psm2_mq_t pspsm_mq;


static
void pspsm_err(const char *str)
{
	if (pspsm_err_str) free(pspsm_err_str);

	if (str) {
		pspsm_err_str = strdup(str);
	} else {
		pspsm_err_str = strdup("");
	}
	return;
}


/* Check for one of the device files /dev/ipath, ipath0 or ipath1.
   return 0 if at least one file is there, -1 else. */
static
int pspsm_check_dev_ipath(void)
{
	struct stat s;
	int rc;
	rc = stat("/dev/ipath", &s);
	if (rc) rc = stat("/dev/ipath0", &s);
	if (rc) rc = stat("/dev/ipath1", &s);

	return rc;
}


static
int pspsm_open_endpoint(void)
{
	psm2_error_t ret;

	if (!pspsm_ep){
		struct psm2_ep_open_opts opts;

		ret = psm2_ep_open_opts_get_defaults(&opts);
		if (ret != PSM2_OK) goto err;

		ret = psm2_ep_open(pspsm_uuid.as_uuid, &opts,
				  &pspsm_ep, &pspsm_epid);
		if (ret != PSM2_OK) goto err;

		//sendbuf = malloc(pscom.env.readahead);
		sendbuf = valloc(pscom.env.readahead);

		pspsm_dprint(2, "pspsm_open_endpoint: OK");
	}
	return 0;

 err:
	pspsm_err(psm2_error_get_string(ret));
	pspsm_dprint(1, "pspsm_open_endpoint: %s", pspsm_err_str);
	return -1;
}


static
int pspsm_init_mq(void)
{
	psm2_error_t ret;

	if (!pspsm_mq){
		ret = psm2_mq_init(pspsm_ep, PSM2_MQ_ORDERMASK_ALL, NULL, 0,
				   &pspsm_mq);

		if (ret != PSM2_OK) goto err;
		pspsm_dprint(2, "pspsm_init_mq: OK");
	}
	return 0;

 err:
	pspsm_err(psm2_error_get_string(ret));
	pspsm_dprint(1, "pspsm_init_mq: %s", pspsm_err_str);
	return -1;
}


static
int pspsm_close_endpoint(void)
{
#if 1
	/* psm_ep_close() SegFaults. A sleep(1) before sometimes helps, disabling
	   the cleanup always helps.
	   (Seen with infinipath-libs-3.2-32129.1162_rhel6_qlc.x86_64) */
	return 0;
#else
	psm_error_t ret;

	if (pspsm_ep){
		ret = psm_ep_close(pspsm_ep, PSM_EP_CLOSE_GRACEFUL, 0);
		pspsm_ep = NULL;
		if (ret != PSM_OK) goto err;

		if (sendbuf) free(sendbuf);

		pspsm_dprint(2, "pspsm_close_endpoint: OK");
	}
	return 0;

 err:
	pspsm_err(psm_error_get_string(ret));
	pspsm_dprint(1, "pspsm_close_endpoint: %s", pspsm_err_str);
	return -1;
#endif
}


int pspsm_finalize_mq(void)
{
	psm2_error_t ret;

	if (pspsm_mq){
		ret = psm2_mq_finalize(pspsm_mq);
		if (ret != PSM2_OK) goto err;
		pspsm_dprint(2, "pspsm_finalize_mq: OK");
	}
	return 0;

 err:
	pspsm_err(psm2_error_get_string(ret));
	pspsm_dprint(1, "pspsm_finalize_mq: %s", pspsm_err_str);
	return -1;
}


static
int pspsm_con_init(pspsm_con_info_t *con_info, struct PSCOM_con *con)
{
	static uint64_t id = 42;

	con_info->con_broken = 0;
	con_info->recv_id = id++;
	con_info->rbuf = NULL;
	con_info->sreq = NULL;

	con_info->rreq = PSM2_MQ_REQINVALID;
	con_info->sreqs[0] = PSM2_MQ_REQINVALID;
	con_info->sreqs[1] = PSM2_MQ_REQINVALID;

	con_info->con = con;

	/* debug */
	con_info->magic = UINTMAX_C(0xdeadbeefcafebabe);

	pspsm_dprint(2, "pspsm_con_init: OK");
	return 0;
}


static
int pspsm_con_connect(pspsm_con_info_t *con_info, pspsm_info_msg_t *info_msg)
{
	psm2_error_t ret, ret1;

	if (memcmp(info_msg->protocol_version, PSPSM_PROTOCOL_VERSION,
		   sizeof(info_msg->protocol_version))) {
		goto err_protocol;
	}

	ret = psm2_ep_connect(pspsm_ep, 1, &info_msg->epid, NULL, &ret1,
			      &con_info->epaddr, 0);
	con_info->send_id = info_msg->id;

	if (ret != PSM2_OK) goto err_connect;
	pspsm_dprint(2, "pspsm_con_connect: OK");
	pspsm_dprint(2, "sending with %"PRIx64", receiving %"PRIx64,
		     con_info->send_id, con_info->recv_id);
	return 0;

 err_connect:
	pspsm_err(psm2_error_get_string(ret));
	pspsm_dprint(1, "pspsm_con_connect: %s", pspsm_err_str);
	return -1;
 err_protocol:
	{
		char str[80];
		snprintf(str, sizeof(str), "protocol error : '%.8s' != '%.8s'",
			 info_msg->protocol_version, PSPSM_PROTOCOL_VERSION);
		pspsm_err(str);
		pspsm_dprint(1, "pspsm_con_connect: %s", pspsm_err_str);
	}
	return -1;
}


static
int pspsm_init(void)
{
	static pspsm_init_state_t init_state = PSPSM_INIT_START;
	int verno_minor = PSM2_VERNO_MINOR;
	int verno_major = PSM2_VERNO_MAJOR;
	psm2_error_t ret;

	if (init_state == PSPSM_INIT_START) {
		/* Check for an available /dev/ipath */
		ret = pspsm_check_dev_ipath();
		if (ret != 0) {
			goto err_dev_ipath;
		}

		ret = psm2_init(&verno_major, &verno_minor);
		if (ret != PSM2_OK) {
			goto err_init;
		}

		/*
		 * All processes wanting to communicate need to use
		 * the same UUID.
		 *
		 * It is unclear whether there are drawbacks from
		 * simply using the same UUID for groups of processes
		 * that will never communicate.
		 *
		 * On top of a constant fill pattern, we use:
		 *
		 * - PSP_PSM_UNIQ_ID if set and not zero, or
		 * - PMI_ID, if set and not zero - that's not entirely
		 *   clean, but a practical solution for MPI apps (as
		 *   long as we do not implement communication between
		 *   two sets of MPI processes not sharing a
		 *   communicator).
		 */
		memset(pspsm_uuid.as_uuid, DEFAULT_UUID_PATTERN,
		       sizeof(pspsm_uuid.as_uuid));

		if (pscom.env.psm_uniq_id) {
			pspsm_dprint(2, "seeding PSM UUID with %u", pscom.env.psm_uniq_id);
			pspsm_uuid.as_uint = pscom.env.psm_uniq_id;
		}

		/* Open the endpoint here in init with the hope that
		   every mpi rank call indirect psm_ep_open() before
		   transmitting any data from or to this endpoint.
		   This is to avoid a race condition in
		   libpsm_infinipath.  Downside: We consume PSM
		   Contexts even in the case of only local
		   communication. You could use PSP_PSM=0 in this
		   case.
		*/
		if (pspsm_open_endpoint()) goto err_ep;
		if (pspsm_init_mq()) goto err_mq;

		pspsm_dprint(2, "pspsm_init: OK");
		init_state = PSPSM_INIT_DONE;
	}
	return init_state; /* 0 = success, -1 = error */
err_dev_ipath:
	pspsm_dprint(2, "pspsm_init: No \"/dev/ipath\" found. Arch psm is disabled.");
	goto err_exit;
err_init:
	pspsm_err(psm2_error_get_string(ret));
	pspsm_dprint(1, "pspsm_init: %s", pspsm_err_str);
	// Fall through
 err_ep:
 err_mq:
err_exit:
	init_state = PSPSM_INIT_FAILED;
	return init_state; /* 0 = success, -1 = error */
}


#if 0
static
void pspsm_iov_print(const struct iovec *iov, size_t len)
{
	while (len > 0) {
		if (iov->iov_len) {
			pspsm_dprint(2, "SENDV %p %zu", iov->iov_base, iov->iov_len);
			len -= iov->iov_len;
		}
		iov++;
	}
}
#endif


/* Process a mq_status. return 1, if a read made progress. 0 else */
static
int pspsm_process(psm2_mq_status_t *status)
{
	uintptr_t c = (uintptr_t)status->context & 7;
	pspsm_con_info_t *ci = (pspsm_con_info_t *)((uintptr_t)status->context & ~(uintptr_t)7);
	struct PSCOM_con *con = ci->con;

	assert(ci->magic == UINTMAX_C(0xdeadbeefcafebabe));

	switch (c) {
	case 0:
		/* first send request */
		assert(ci->sreqs[0] != PSM2_MQ_REQINVALID);
		poll_user_dec();
		ci->sreqs[0] = PSM2_MQ_REQINVALID;
		/* pspsm_dprint(0, "Send0 done %p len %d con %s\n", ci->iov[0].iov_base,
		   (int)ci->iov[0].iov_len, ci->con->pub.remote_con_info.name); */
		if (ci->sreqs[1] == PSM2_MQ_REQINVALID) {
			pscom_write_done(con, ci->sreq, ci->sreq_len);
			ci->sreq = NULL;
		}
		break;
	case 1:
		/* second send request */
		assert(ci->sreqs[1] != PSM2_MQ_REQINVALID);
		poll_user_dec();
		ci->sreqs[1] = PSM2_MQ_REQINVALID;
		/* pspsm_dprint(0, "Send1 done %p len %d con %s\n", ci->iov[1].iov_base,
		   (int)ci->iov[1].iov_len, ci->con->pub.remote_con_info.name); */
		if (ci->sreqs[0] == PSM2_MQ_REQINVALID) {
			pscom_write_done(con, ci->sreq, ci->sreq_len);
			ci->sreq = NULL;
		}
		break;
	case 2:
		/* receive request */
		assert(ci->rbuf);
		assert(status->msg_length == status->nbytes);
		ci->rreq = PSM2_MQ_REQINVALID;
		/* pspsm_dprint(0, "read done %p len %d con %s\n", ci->rbuf,
		   (int)status->msg_length, ci->con->pub.remote_con_info.name); */
		pscom_read_done_unlock(con, ci->rbuf, status->msg_length);
		ci->rbuf = NULL;
		/* Check, if there is more to read. Post the next receive request, if so. */
		pscom_psm_do_read_check(con);
		return 1;
		break;
	default:
		/* this shouldn't happen */
		assert(0);
	}
	return 0;
}


static inline
int _pspsm_send_buf(pspsm_con_info_t *con_info, char *buf, size_t len,
		    uint64_t tag, psm2_mq_req_t *req, unsigned long nr)
{
	void *context = (void *)((uintptr_t)con_info | nr);
	psm2_error_t ret;
	assert(*req == PSM2_MQ_REQINVALID);
	ret = psm2_mq_isend(pspsm_mq, con_info->epaddr,
			    /* flags */ 0, tag, buf, len,
			    context, req);
	if (ret != PSM2_OK) goto err;
	return 0;

 err:
	pspsm_err(psm2_error_get_string(ret));
	pspsm_dprint(1, "_pspsm_send_buf: %s", pspsm_err_str);
	return -EPIPE;
}


static
int pspsm_send_pending(pspsm_con_info_t *con_info)
{
	return !!con_info->sreq;
}


static
int pspsm_sendv(pspsm_con_info_t *con_info, struct iovec iov[2], struct PSCOM_req *req)
{
	uint64_t tag = con_info->send_id | PSPSM_MAGIC_IO;
	unsigned int i=0;
	psm2_error_t ret;
	size_t len = iov[0].iov_len + iov[1].iov_len;

	if (len <= pscom.env.readahead){
		pscom_memcpy_from_iov(sendbuf, iov, len);
		/* we hope that doesn't block - it shouldn't, as the
		 * message is sufficiently small */
		ret = psm2_mq_send(pspsm_mq, con_info->epaddr,
				   /* flags*/ 0, tag, sendbuf, len);
		if (ret != PSM2_OK) goto err;
		return 0;
	}

	for (i=0; i<2; i++){
		if (iov[i].iov_len){
			/* pspsm_dprint(0, "Send part[%d], %p len %d to con %s\n", i,
			   iov[i].iov_base, (int)iov[i].iov_len,
			   con_info->con->pub.remote_con_info.name); */
			if (_pspsm_send_buf(con_info,
					    iov[i].iov_base, iov[i].iov_len,
					    tag, &con_info->sreqs[i], i)){
				return -EPIPE;
			}
			/* inc for each outstanding send request */
			poll_user_inc();
		}
	}

	con_info->sreq_len = len;
	con_info->sreq = req;

	return -EAGAIN;

 err:
	pspsm_err(psm2_error_get_string(ret));
	pspsm_dprint(1, "_pspsm_send_buf: %s", pspsm_err_str);
	return -EPIPE;
}


static
int pspsm_recv_start(pspsm_con_info_t *con_info, char *rbuf, size_t rbuflen)
{
	/* ToDo: rename me to something like "post a receive". */
	psm2_error_t ret;
	uint64_t rtag = con_info->recv_id;
	void *context = (void *)((uintptr_t)con_info | 2);

	assert(con_info->rreq == PSM2_MQ_REQINVALID);
	ret = psm2_mq_irecv(pspsm_mq, rtag, mask, 0 /*flags*/,
			    rbuf, rbuflen,
			    context, &con_info->rreq);
	con_info->rbuf = rbuf;
	if (ret != PSM2_OK) goto out_err;

	return 0;

 out_err:
	pspsm_err(psm2_error_get_string(ret));
	pspsm_dprint(1, "pspsm_recvlook: %s", pspsm_err_str);
	return -EPIPE;
}


static int pspsm_recv_pending(pspsm_con_info_t *con_info)
{
	return !!con_info->rbuf;
}


static
int pspsm_progress()
{
	unsigned read_progress = 0;
	psm2_mq_req_t req;
	psm2_mq_status_t status;
	psm2_error_t ret;
	do {
		ret = psm2_mq_ipeek(pspsm_mq, &req, /* status */ NULL);
		if (ret == PSM2_MQ_INCOMPLETE)
			return read_progress;
		if (ret != PSM2_OK)
			goto err;
		ret = psm2_mq_test(&req, &status);
		if (ret != PSM2_OK)
			goto err;
		read_progress += pspsm_process(&status);
	}
	while (!read_progress);

	return read_progress;
 err:
	pspsm_err(psm2_error_get_string(ret));
	pspsm_dprint(1, "pspsm_peek: %s", pspsm_err_str);
	return read_progress;

}


static
pspsm_con_info_t *pspsm_con_create(void)
{
	pspsm_con_info_t *con_info = memalign(8, sizeof(*con_info));
	return con_info;
}


static
void pspsm_con_free(pspsm_con_info_t *con_info)
{
	free(con_info);
}


static
void pspsm_con_cleanup(pspsm_con_info_t *con_info)
{
	/* FIXME: implement */
}


static
void pspsm_con_get_info_msg(pspsm_con_info_t *con_info,
			    pspsm_info_msg_t *info_msg)
{
	info_msg->epid = pspsm_epid;
	info_msg->id = con_info->recv_id;
	memcpy(info_msg->protocol_version, PSPSM_PROTOCOL_VERSION,
	       sizeof(info_msg->protocol_version));
}
