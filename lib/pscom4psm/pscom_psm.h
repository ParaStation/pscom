/*
 * ParaStation
 *
 * Copyright (C) 2011 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author: Thomas Moschny <moschny@par-tec.com>
 */
/**
 * pscom_psm.h: Header for PSM communication
 */

#ifndef _PSCOM_PSM_H_
#define _PSCOM_PSM_H_

#include <sys/uio.h>
#include <errno.h>
#include <stdlib.h>
#include <malloc.h>
#include <inttypes.h>

#include "pscom_types.h"
#include "pscom_priv.h"
#include "pscom_util.h"
#include "pscom_debug.h"
#include "pscom_io.h"
#include "p4sockets.h"

#include "psm.h"
#include "psm_mq.h"

typedef struct pspsm_con_info {
	/* general info */
	psm_epaddr_t epaddr;    /**< destination address of peer */
	uint64_t send_id;       /**< tag used when sending to peer */
	uint64_t recv_id;       /**< tag used when receiving from peer*/
	int con_broken;         /**< set to 1 if connection broken */

	/* sending */
	pscom_req_t *req;       /**< pscom open send request */
	struct iovec iov[2];    /**< iov of open send request */
	psm_mq_req_t sreqs[2];  /**< MQ send requests */

	/* receiving */
	char* rbuf;             /**< buffer to be used for next receive */
	size_t rbuflen;         /**< size of buffer */
	psm_mq_req_t rreq;      /**< MQ recv request */

	/* pointing back */
	pscom_con_t* con;

	/* debug */
	uint64_t magic;
} pspsm_con_info_t;

/*
 * Contact endpoint info
 */
typedef struct pspsm_info_msg_s {
	psm_epid_t epid;        /**< endpoint id */
	uint64_t id;            /**< tag to be used sending to that epid */
	char protocol_version[8];  /**< 8 byte psm protocol identifier */
} pspsm_info_msg_t;

#define DEFAULT_UUID_PATTERN 42
#define PSPSM_PROTOCOL_VERSION "master01"

/*
 * UUID Helper
 */
typedef union {
	psm_uuid_t as_uuid;
	unsigned int as_uint;
} pspsm_uuid_t;

/*
 * fixme
 */
typedef enum pspsm_init_state {
	PSPSM_INIT_START = 1,
	PSPSM_INIT_DONE = 0,
	PSPSM_INIT_FAILED = -1 /* init failed once */
} pspsm_init_state_t;


typedef struct {
	struct pscom_poll_reader poll;
	unsigned poll_user; // count the users which wait for progress
} pspsm_poll_t;


#define pspsm_dprint(level, fmt, arg... )			\
	do {							\
		if ((level) <= pspsm_debug) {			\
			fprintf(pspsm_debug_stream ?		\
				pspsm_debug_stream : stderr,	\
				"psm:" fmt "\n", ##arg);	\
		}						\
	} while(0)

/*
 * Methods
 */
static int pspsm_init(void);
static pspsm_con_info_t *pspsm_con_create(void);
static void pspsm_con_free(pspsm_con_info_t *con_info);
static int pspsm_con_init(pspsm_con_info_t *con_info);
static int pspsm_con_connect(pspsm_con_info_t *con_info, pspsm_info_msg_t *info_msg);
static void pspsm_con_cleanup(pspsm_con_info_t *con_info);
static void pspsm_con_get_info_msg(pspsm_con_info_t *con_info /* in */, pspsm_info_msg_t *info /* out */);
static int pspsm_recvlook(pspsm_con_info_t *con_info);
static int pspsm_sendv(pspsm_con_info_t *con_info);
static void pspsm_send_eof(pspsm_con_info_t *con_info);

static int pscom_psm_do_read(pscom_con_t *con);
static void pscom_psm_do_write(pscom_con_t *con);
static void pscom_psm_close(pscom_con_t *con);
static void pscom_psm_con_init(pscom_con_t *con, int con_fd, pspsm_con_info_t *ci);
static void pscom_psm_init(void);
static int pscom_psm_connect(pscom_con_t *con, int con_fd);
static int pscom_psm_accept(pscom_con_t *con, int con_fd);
static void pspsm_err(const char *str);
static int pspsm_open_endpoint(void);
static int pspsm_init_mq(void);
static int pspsm_close_endpoint(void);
static void pscom_psm_finalize();
static int pspsm_finalize_mq(void);
static int pspsm_con_init(pspsm_con_info_t *con_info);
static int pspsm_con_connect(pspsm_con_info_t *con_info, pspsm_info_msg_t *info_msg);

/*
 * Configuration
 */
extern int pspsm_debug; /**< debug level */
extern FILE *pspsm_debug_stream; /**< Stream to use for debug output */

#endif /* _PSCOM_PSM_H_ */
