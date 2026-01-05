/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * psofed.h: OFED/Infiniband communication (in UD mode)
 */

#ifndef _PSOFED_H_
#define _PSOFED_H_

#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>


typedef struct psofed_con_info psofed_con_info_t;
typedef struct context_info context_info_t;

// contact endpoint info
typedef struct psofed_info_msg_s {
    uint16_t version; /* == PSOFED_INFO_VERSION */
    uint16_t lid;     /* LID */
    uint32_t qp_num;  /* Queue pair  number */
    uint32_t use_src; /* id the sender should use as src */
} psofed_info_msg_t;

#define PSOFED_INFO_VERSION 0x0100

/*
 * Initialization
 */

/* Initialize the lib.
 * Multiple calls are allowed (and cheap).
 * On success return 0, -1 on error with errno set. */
int psofed_init(void);


/*
 * Connection handling:
 *
 * Typical life cycle:
 *
 * con_info = psofed_con_create();
 * psofed_con_init(con_info, NULL, NULL);
 * psofed_con_get_info_msg(con_info, &my_info);
 * send my_info to remote somehow
 * info_msg = receive remote info somehow.
 * psofed_con_connect(con_info, info_msg);
 * doing io
 * psofed_con_cleanup(con_info);
 * psofed_con_free(con_info);
 */

/* malloc() wrapper */
psofed_con_info_t *psofed_con_create(void);

/* free() wrapper */
void psofed_con_free(psofed_con_info_t *con_info);

/* Prepare con_info for psofed_con_connect()
 * Initialize internal structures
 * Use default_context, if context is NULL
 * Assign a "src" id for the connection
 */
int psofed_con_init(psofed_con_info_t *con_info, context_info_t *context,
                    void *priv);

/* Connect to peer described by info_msg */
int psofed_con_connect(psofed_con_info_t *con_info, psofed_info_msg_t *info_msg);

/* Closing connection.
 * Cleanup all internal structures */
void psofed_con_cleanup(psofed_con_info_t *con_info);

/* Get a info_msg usable for psofed_con_connect() at the other side. */
void psofed_con_get_info_msg(psofed_con_info_t *con_info /* in */,
                             psofed_info_msg_t *info /* out */);


/*
 *  Input/Output
 */

typedef struct psofed_recv_s {
    void *data;                  /* received data */
    int len;                     /* len or negative error value. */
    psofed_con_info_t *con_info; /* this message comes from */
    void *priv;                  /* from psofed_con_set_priv() */
} psofed_recv_t;

/* Receive a message from any connections.
 * Never blocks. Return NULL in case of no receive. */
psofed_recv_t *psofed_recv(context_info_t *context);
void psofed_recvdone(context_info_t *context);


/* returnvalue like writev(), except on error errno is negative return */
/* It's important, that the sending side is aligned to IB_MTU_SPEC,
   else we loose a lot of performance!!! */
int psofed_sendv(psofed_con_info_t *con_info, struct iovec *iov, size_t size);

/* Handle outstanding cq events on context.
 * Use default_context, if context is NULL.
 * return 0, if call made no progress */
int psofed_progress(context_info_t *context); //, int blocking);

/* Suggest a value for psofed_pending_tokens. Result depends on
 * psofed_recvq_size. */
unsigned psofed_pending_tokens_suggestion(void);
char *psofed_pending_tokens_suggestion_str(void);


/*
 * Configuration
 */
extern int psofed_debug;
extern FILE *psofed_debug_stream; /* Stream to use for debug output */
extern char *psofed_hca;          /* hca name to use. Default: first hca */
extern unsigned int psofed_port;  /* port index to use. Default: 0 (means first
                                     active port) */
extern unsigned int psofed_path_mtu; /* path mtu to use. */

/* size (=buffers used) for send and receive queue. You must not change
 * these values after a call to psofed_init()! */
extern unsigned int psofed_sendq_size;
extern unsigned int psofed_recvq_size;

extern unsigned int psofed_compq_size; /* should be at least sendq_size +
                                          recvq_size !*/
extern unsigned int psofed_pending_tokens;

extern unsigned int psofed_winsize; /* Do not send more then winsize unacked
                                       messsages */

extern unsigned long psofed_resend_timeout;      /* resend in usec. doubling the
                                                    timeout on each resend.*/
extern unsigned int psofed_resend_timeout_shift; /* Never wait longer then
                                                    psofed_resend_timeout <<
                                                    psofed_resend_timeout_shift
                                                  */


extern int psofed_event_count; /* bool. Be busy if outstanding_cq_entries is to
                                  high? */
extern int psofed_lid_offset;  /* int: offset to base LID (adaptive routing) */

/*
 * Information
 */
extern unsigned psofed_outstanding_cq_entries; /* counter */

#endif /* _PSOFED_H_ */
