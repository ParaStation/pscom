/*
 * ParaStation
 *
 * Copyright (C) 2016-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#ifndef _PSPSM_H_
#define _PSPSM_H_


/*
 * Contact endpoint info
 */
typedef struct pspsm_info_msg_s {
	uint64_t epid;          /**< endpoint id */
	uint64_t id;            /**< tag to be used sending to that epid */
	char protocol_version[8];  /**< 8 byte psm protocol identifier */
	uint32_t small_msg_len; /**< max length for small messages (= size of "xheader" receive request) */
} pspsm_info_msg_t;

typedef struct pspsm_con_info pspsm_con_info_t;

#define DEFAULT_UUID_PATTERN 42
#define PSPSM_PROTOCOL_VERSION "master02"

/*
 * fixme
 */
typedef enum pspsm_init_state {
	PSPSM_INIT_START = 1,
	PSPSM_INIT_DONE = 0,
	PSPSM_INIT_FAILED = -1 /* init failed once */
} pspsm_init_state_t;



#define pspsm_dprint(level, fmt, arg... )			\
	do {							\
		if ((level) <= pspsm_debug) {			\
			fprintf(pspsm_debug_stream ?		\
				pspsm_debug_stream : stderr,	\
				"psm:" fmt "\n", ##arg);	\
		}						\
	} while(0)

struct PSCOM_req;
struct PSCOM_con;

static int pspsm_init(void);

static pspsm_con_info_t *pspsm_con_create(void);
static void pspsm_con_free(pspsm_con_info_t *con_info);
static int pspsm_con_init(pspsm_con_info_t *con_info, struct PSCOM_con *con);
static int pspsm_con_connect(pspsm_con_info_t *con_info, pspsm_info_msg_t *info_msg);
static void pspsm_con_cleanup(pspsm_con_info_t *con_info);
static void pspsm_con_get_info_msg(pspsm_con_info_t *con_info /* in */, pspsm_info_msg_t *info /* out */);

static int pspsm_recv_start(pspsm_con_info_t *con_info, char *rbuf, size_t rbuflen);
static int pspsm_recv_pending(pspsm_con_info_t *con_info);

/* pspsm_sendv sends an iov. FIXME: returns 0 if the send is complete, -EAGAIN if
   it created one or more requests for it, and -EPIPE in case of an
   error. */
static int pspsm_sendv(pspsm_con_info_t *con_info, struct iovec iov[2], struct PSCOM_req *req);
static int pspsm_send_pending(pspsm_con_info_t *con_info);

static int pspsm_progress();

static void pspsm_err(const char *str);

static int pspsm_finalize_mq(void);
static int pspsm_close_endpoint(void);


/*
 * To be implemented by upper layers
 */

void pscom_write_done(struct PSCOM_con *con, struct PSCOM_req *req, size_t len);
void pscom_read_done_unlock(struct PSCOM_con *con, char *buf, size_t len);

static void poll_user_inc(void);
static void poll_user_dec(void);
static void pscom_psm_post_recv_check(struct PSCOM_con *con);

/*
 * Configuration
 */
extern int pspsm_debug; /**< debug level */
extern FILE *pspsm_debug_stream; /**< Stream to use for debug output */
extern unsigned pspsm_devcheck; /* bool: check for psm device? */


#endif /* _PSPSM_H_ */
