/*
 * ParaStation
 *
 * Copyright (C) 2011 ParTec Cluster Competence Center GmbH, Munich
 *
 * All rights reserved.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
#ifndef _PSCOM_PRECON_H_
#define _PSCOM_PRECON_H_


#define PSCOM_INFO_FD_ERROR	0x0ffffe	/* int errno; Pseudo message. Error in read(). */
#define PSCOM_INFO_FD_EOF	0x0fffff	/* Pseudo message fd got EOF */

#define PSCOM_INFO_EOF		0x100000	/* Last info message */
//#define PSCOM_INFO_ANSWER	0x100001	/* request remote side, to send answers */
#define PSCOM_INFO_CON_INFO	0x100002	/* pscom_info_con_info_t; */
#define PSCOM_INFO_VERSION	0x100003	/* pscom_info_version_t;	Supported version range */
#define PSCOM_INFO_CON_INFO_DEMAND	0x100004/* pscom_info_con_info_t; On demand connect request. */
#define PSCOM_INFO_BACK_CONNECT	0x100005	/* pscom_info_con_info_t; Request a back connect */
#define PSCOM_INFO_BACK_ACK	0x100006	/* null; Ack a back_connect */
#define PSCOM_INFO_ARCH_REQ	0x100010	/* pscom_info_arch_req_t;	Request to connect with .arch_id */
#define PSCOM_INFO_ARCH_OK	0x100011	/* Use last requested arch */
#define PSCOM_INFO_ARCH_NEXT	0x100012	/* Try next arch */
#define PSCOM_INFO_ARCH_STEP1	0x100013
#define PSCOM_INFO_ARCH_STEP2	0x100014
#define PSCOM_INFO_ARCH_STEP3	0x100015
#define PSCOM_INFO_ARCH_STEP4	0x100016


#define MAGIC_PRECON	0x4a656e73
typedef struct precon {
	/* Pre connection data. Used for the initial TCP handshake. */
	unsigned long	magic;
	ufd_info_t	ufd_info;
	unsigned	send_len;	// Length of send
	unsigned	recv_len;	// Length of recv
	char		*send;		// Send buffer
	char		*recv;		// Receive buffer

	unsigned	recv_done : 1;
	unsigned	closefd_on_cleanup : 1; // Call close(fd) on cleanup?
	unsigned	back_connect : 1;	// Is this a back connect precon?

	int		nodeid, portno; // Retry connect to nodeid:portno on ECONNREFUSED
	unsigned	reconnect_cnt;

	pscom_con_t	*con;
	pscom_sock_t	*sock;

	unsigned long		last_print_stat; // usec of last print_stat
	unsigned long		last_reconnect; // usec of last reconnect
	pscom_poll_reader_t	poll_reader; // timeout handling

	size_t		stat_send;	// bytes send
	size_t		stat_recv;	// bytes received
	unsigned	stat_poll_cnt;	// loops in poll

	/* state information */
	pscom_plugin_t	*plugin;	// The plugin handling the handshake messages (==plugin_cur or NULL)
	pscom_plugin_t	*_plugin_cur;	// Current plugin iterator (used to loop through all plugins)
} precon_t;


typedef struct {
	unsigned int arch_id;
} pscom_info_arch_req_t;


typedef struct {
	pscom_con_info_t	con_info;
} pscom_info_con_info_t;


/* Create a precon object */
precon_t *pscom_precon_create(pscom_con_t *con);

/* Destroy a precon object. Cleanup and free all internal resources. */
void pscom_precon_destroy(precon_t *pre);

/* Connect a precon via tcp to nodeid:portno. Return 0 on sucess, -1 on error with errno set. */
int pscom_precon_tcp_connect(precon_t *pre, int nodeid, int portno);

/* Assign the fd to precon. fd is typically from a previous fd = accept(listen_fd). */
void pscom_precon_assign_fd(precon_t *pre, int fd);

/* Send a message of type type */
void pscom_precon_send(precon_t *pre, unsigned type, void *data, unsigned size);

/* Start receiving. */
void pscom_precon_recv_start(precon_t *pre);

/* Send a PSCOM_INFO_ARCH_NEXT message and disable current plugin */
void pscom_precon_send_PSCOM_INFO_ARCH_NEXT(precon_t *pre);
/* Send a con_info message of type CON_INFO, CON_INFO_DEMAND or BACK_CONNECT*/
void pscom_precon_send_PSCOM_INFO_CON_INFO(precon_t *pre, int type);

/* Close the precon: Stop receiving data, flush Sendqueue. */
void pscom_precon_close(precon_t *pre);

void pscom_precon_handshake(precon_t *pre);

#endif /* _PSCOM_PRECON_H_ */
