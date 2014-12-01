/*
 * ParaStation
 *
 * Copyright (C) 2007-2010 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */
/**
 * ParaStation Communication Library
 */

#ifndef _PSCOM_H_
#define _PSCOM_H_

#ifdef __cplusplus
extern "C" {
#if 0
}
#endif
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PSCOM_VERSION 0x0200

typedef enum PSCOM_err {
	PSCOM_SUCCESS = 0,		/* Success */
	PSCOM_ERR_STDERROR = -1,	/* standard error. see errno */
	PSCOM_ERR_INVALID = -2,		/* Invalid argument */
	PSCOM_ERR_ALREADY = -3,		/* Operation already in progress */
	PSCOM_NOT_IMPLEMENTED = -4,	/* Function not implemented */
	PSCOM_ERR_EOF = -5,		/* End of file */
	PSCOM_ERR_IOERROR = -6,		/* IO Error */
	PSCOM_ERR_UNSUPPORTED_VERSION = -7, /* Unsupported version */
} pscom_err_t;


typedef enum PSCOM_con_state {
	PSCOM_CON_STATE_NO_RW	= 0x0,
	PSCOM_CON_STATE_R	= 0x1,
	PSCOM_CON_STATE_W	= 0x2,
	PSCOM_CON_STATE_RW	= 0x3,
	PSCOM_CON_STATE_CLOSED  = 0x4,
	PSCOM_CON_STATE_CONNECTING = 0x8,
	PSCOM_CON_STATE_ACCEPTING = 0x10,
	PSCOM_CON_STATE_CLOSING = 0x20,
} pscom_con_state_t;


typedef enum PSCOM_con_type {
	PSCOM_CON_TYPE_NONE	= 0x00,
	PSCOM_CON_TYPE_LOOP	= 0x01,
	PSCOM_CON_TYPE_TCP	= 0x02,
	PSCOM_CON_TYPE_SHM	= 0x03,
	PSCOM_CON_TYPE_P4S	= 0x04,
	PSCOM_CON_TYPE_GM	= 0x05,
	PSCOM_CON_TYPE_MVAPI	= 0x06,
	PSCOM_CON_TYPE_OPENIB	= 0x07,
	PSCOM_CON_TYPE_ELAN	= 0x08,
	PSCOM_CON_TYPE_DAPL	= 0x09,
	PSCOM_CON_TYPE_ONDEMAND	= 0x0a,
	PSCOM_CON_TYPE_OFED	= 0x0b,
	PSCOM_CON_TYPE_EXTOLL	= 0x0c,
	PSCOM_CON_TYPE_PSM      = 0x0d,
	PSCOM_CON_TYPE_VELO	= 0x0e,
	PSCOM_CON_TYPE_CBC      = 0x0f,
	PSCOM_CON_TYPE_MXM      = 0x10
} pscom_con_type_t;


typedef enum PSCOM_op {
	PSCOM_OP_READ = 1,
	PSCOM_OP_WRITE = 2,
	PSCOM_OP_CONNECT = 3,
} pscom_op_t;

#define PSCOM_REQ_STATE_SEND_REQUEST		0x00000001
#define PSCOM_REQ_STATE_RECV_REQUEST		0x00000002
#define PSCOM_REQ_STATE_GRECV_REQUEST		0x00000004

#define PSCOM_REQ_STATE_POSTED			0x00000008

#define PSCOM_REQ_STATE_IO_STARTED		0x00000010
#define PSCOM_REQ_STATE_IO_DONE			0x00000020

#define PSCOM_REQ_STATE_ERROR			0x00000040
#define PSCOM_REQ_STATE_CANCELED		0x00000080
#define PSCOM_REQ_STATE_TRUNCATED		0x00000100

#define PSCOM_REQ_STATE_DONE			0x00000200

#define PSCOM_REQ_STATE_RMA_READ_REQUEST	0x00000400
#define PSCOM_REQ_STATE_RMA_WRITE_REQUEST	0x00000800
#define PSCOM_REQ_STATE_PASSIVE_SIDE		0x00001000
#define PSCOM_REQ_STATE_RENDEZVOUS_REQUEST	0x00002000

#define PSCOM_REQ_STATE_GRECV_MERGED		0x00004000

typedef unsigned int pscom_req_state_t;



typedef struct PSCOM_socket pscom_socket_t;
typedef struct PSCOM_connection pscom_connection_t;
typedef struct PSCOM_request pscom_request_t;
typedef struct PSCOM_header_net pscom_header_net_t;
typedef struct PSCOM_con_info pscom_con_info_t;


typedef struct PSCOM_xheader_rma_write
{
	void		*dest;
} pscom_xheader_rma_write_t;


typedef struct PSCOM_xheader_rma_read
{
	void		*id;
	void		*src;
	uint32_t	src_len;
} pscom_xheader_rma_read_t;


typedef struct PSCOM_xheader_rma_read_answer
{
	void *id;
} pscom_xheader_rma_read_answer_t;


typedef struct PSCOM_xheader_rendezvous_fin
{
	void *id;
} pscom_xheader_rendezvous_fin_t;


typedef struct PSCOM_xheader_bcast
{
	uint32_t	group_id;
	uint32_t	bcast_root;
	uint32_t	bcast_arg1; /* internal usage */
	uint32_t	bcast_arg2; /* internal usage */
	char		user[0];
} pscom_xheader_bcast_t;


typedef union PSCOM_xheader
{
	pscom_xheader_rma_read_t	rma_read;
	pscom_xheader_rma_read_answer_t	rma_read_answer;
	pscom_xheader_rma_write_t	rma_write;
	pscom_xheader_rendezvous_fin_t	ren_fin;
	pscom_xheader_bcast_t		bcast;
#ifdef PSCOM_XHEADER_USER_TYPE
	PSCOM_XHEADER_USER_TYPE		user;
#else
	char				user[0];
#endif
} pscom_xheader_t;


struct PSCOM_header_net {
	uint16_t	msg_type;
	uint16_t	xheader_len;
	uint32_t	data_len;

	pscom_xheader_t	xheader[0]; /* zero length xheader */
};

struct PSCOM_request
{
	pscom_req_state_t state;

	unsigned int	xheader_len;
	unsigned int	data_len;
	void		*data;

	pscom_connection_t *connection;
	pscom_socket_t	*socket;

	struct PSCOM_request_ops {
		/* recv_accept shall return 1 to accept a message */
		int	(*recv_accept)(pscom_request_t *request,
				       pscom_connection_t *connection,
				       pscom_header_net_t *header_net);
		void	(*io_done)(pscom_request_t *request);
	} ops;

	unsigned int		user_size;
	struct PSCOM_req_user	*user; /* define your own struct PSCOM_req_user! */

	unsigned int		max_xheader_len;

	pscom_header_net_t	header;

	/* warning: Storagesize of xheader depends on
	   sizeof(PSCOM_XHEADER_USER_TYPE) !!! */
	pscom_xheader_t		xheader;
};


struct PSCOM_con_info
{
	int	node_id;
	int	pid;
	void	*id;
	char	name[8];
};


struct PSCOM_socket
{
	struct PSCOM_socket_ops {
		void	(*con_accept)(pscom_connection_t *new_connection);
		void	(*con_error)(pscom_connection_t *connection,
				     pscom_op_t operation,
				     pscom_err_t error);

		pscom_request_t *(*default_recv)(pscom_connection_t *connection,
						 pscom_header_net_t *header_net);
	} ops;
	int		listen_portno; /* portno or -1 */

	pscom_con_info_t local_con_info;

	unsigned int	connection_userdata_size;
	unsigned int	userdata_size;
#ifdef PSCOM_SOCKET_USERDATA_TYPE
	PSCOM_SOCKET_USERDATA_TYPE userdata;
#else
	char		userdata[0];
#endif
};


struct PSCOM_connection
{
	pscom_socket_t	*socket;
	pscom_con_state_t state;
	pscom_con_type_t type;

	pscom_con_info_t remote_con_info;

	unsigned int	userdata_size;
#ifdef PSCOM_CONNECTION_USERDATA_TYPE
	PSCOM_CONNECTION_USERDATA_TYPE userdata;
#else
	char		userdata[0];
#endif
};


/**
 * @brief Initialize the library.
 *
 * This function must be called before any other call
 * to the library. Call with PSCOM_VERSION.
 * return PSCOM_SUCCESS or PSCOM_ERR_UNSUPPORTED_VERSION
 */
pscom_err_t pscom_init(int pscom_version);


/**
 * @brief Initialize the library for multithreaded usage.
 *
 * This function must be called before any other call
 * to the library. Call with PSCOM_VERSION.
 * return PSCOM_SUCCESS or PSCOM_ERR_UNSUPPORTED_VERSION
 */
pscom_err_t pscom_init_thread(int pscom_version);


/**
 * @brief Get the ID of this node.
 *
 * Get the ParaStation ID of this node.
 *
 * @return	NodeID	on success and
 * @return	-1	on error
 */
int pscom_get_nodeid(void);

/*
 * @return On success the port number is returned. On error, -1 is
 * returned (no listen on socket).
 */
int pscom_get_portno(pscom_socket_t *socket);


pscom_socket_t *pscom_open_socket(unsigned int socket_userdata_size,
				  unsigned int connection_userdata_size);

#define PSCOM_OPEN_SOCKET()						\
	pscom_open_socket(sizeof(PSCOM_SOCKET_USERDATA_TYPE),		\
			  sizeof(PSCOM_CONNECTION_USERDATA_TYPE))


/* set the socket name (socket->local_con_info.name[]) */
void pscom_socket_set_name(pscom_socket_t *socket, const char *name);

pscom_err_t pscom_listen(pscom_socket_t *socket, int portno);
#define PSCOM_ANYPORT -1 /**< When used as a port-number, stands for any
			    port (wildcard). */

/**
 * @brief Stop listening for new connections on port.
 *
 */
void pscom_stop_listen(pscom_socket_t *socket);

/* Flush the sendqueue */
void pscom_flush(pscom_connection_t *connection);

/* cancel all active send/recv requests and close the connection */
void pscom_close_connection(pscom_connection_t *connection);


/* PSCOM_Close_Socket() close all connections. */
void pscom_close_socket(pscom_socket_t *socket);


pscom_connection_t *pscom_open_connection(pscom_socket_t *socket);

pscom_err_t pscom_connect(pscom_connection_t *connection, int nodeid, int portno);

/* connect to nodeid:port or accept a connection from a socket with the name name
   (see pscom_socket_set_name()) */
#define PSCOM_HAS_ON_DEMAND_CONNECTIONS 1
pscom_err_t pscom_connect_ondemand(pscom_connection_t *connection,
				   int nodeid, int portno, const char name[8]);

pscom_request_t *pscom_request_create(unsigned int max_xheader_len, unsigned int user_size);

#define PSCOM_REQUEST_CREATE()						\
	pscom_request_create(sizeof(PSCOM_XHEADER_USER_TYPE),		\
			     sizeof(struct PSCOM_req_user))


void pscom_request_free(pscom_request_t *request);

/* post the receive request request.
   Receiving up to req->xheader_len bytes to req->xheader and
   up to req->data_len bytes to req->data from connection
   req->connection or from ANY connection from req->socket in
   the case of req->connection==NULL.

   req->xheader_len
   req->xheader
   req->data_len
   req->data
   req->connection or req->connection==NULL and req->socket

   optional:
   req->ops.recv_accept
   req->ops.io_done
*/
void pscom_post_recv(pscom_request_t *request);

void pscom_post_send(pscom_request_t *request);

static inline
pscom_request_t *pscom_req_prepare(pscom_request_t *req,
				   pscom_connection_t *connection,
				   void *data, unsigned int data_len,
				   void *xheader, unsigned int xheader_len)
{
	req->connection = connection;
	req->data = data; req->data_len = data_len;
	req->xheader_len = xheader_len;
	if (xheader) {
		assert(xheader_len <= req->max_xheader_len);
		memcpy(&req->xheader.user, xheader, xheader_len);
	}
	return req;
}


/* send a copy of data (non blocking) */
void pscom_send(pscom_connection_t *connection,
		void *xheader, unsigned int xheader_len,
		void *data, unsigned int data_len);

/* send data. (non blocking). Do not modify data, until io_done is called. */
void pscom_send_inplace(pscom_connection_t *connection,
			void *xheader, unsigned int xheader_len,
			void *data, unsigned int data_len,
			void (*io_done)(pscom_req_state_t state, void *priv), void *priv);


/* blocking receive */
pscom_err_t pscom_recv(pscom_connection_t *connection, pscom_socket_t *socket,
		       void *xheader, unsigned int xheader_len,
		       void *data, unsigned int data_len);


/* blocking receive */
static inline
pscom_err_t pscom_recv_from(pscom_connection_t *connection,
			    void *xheader, unsigned int xheader_len,
			    void *data, unsigned int data_len)
{
	return pscom_recv(connection, connection->socket,
			  xheader, xheader_len,
			  data, data_len);
}


/* blocking receive */
static inline
pscom_err_t pscom_recv_any(pscom_socket_t *socket,
			   void *xheader, unsigned int xheader_len,
			   void *data, unsigned int data_len)
{
	return pscom_recv(NULL, socket,
			  xheader, xheader_len,
			  data, data_len);
}


/* post the rma_write request.
   Write req->data_len bytes from req->data to remote mem
   at req->xheader.rma_write.dest at connection req->connection.

   req->data_len
   req->data
   req->connection
   req->xheader.rma_write.dest

   optional:
   req->ops.io_done
*/
void pscom_post_rma_write(pscom_request_t *request);


/* post the rma_read request.
   Read req->data_len bytes from remote mem at
   req->xheader.rma_read.src at connection req->connection
   and save it at req->data.

   req->data_len
   req->data
   req->connection
   req->xheader.rma_read.src

   optional:
   req->ops.io_done
*/
void pscom_post_rma_read(pscom_request_t *request);

void pscom_wait(pscom_request_t *request);

/* wait for all requests in list requests (NULL teriminated) */
void pscom_wait_all(pscom_request_t **requests);

/* return 1 on progress */
int pscom_test_any(void);

void pscom_wait_any(void);

/* cancel send or recv request
 * return 1: request canceled. return 0: request already done or cancel failed
 */
int pscom_cancel(pscom_request_t *request);

/* cancel send request */
int pscom_cancel_send(pscom_request_t *request);
/* cancel recv request */
int pscom_cancel_recv(pscom_request_t *request);


/* return 1, if there is a matching receive. 0 otherwise. */
/* in case 1: copy also the message header */
int pscom_iprobe(pscom_request_t *request);

/* Blocking version of pscom_iprobe */
void pscom_probe(pscom_request_t *request);

static inline
int pscom_req_state_successful(pscom_req_state_t state)
{
	return (state &
		(PSCOM_REQ_STATE_ERROR |
		 PSCOM_REQ_STATE_CANCELED |
		 PSCOM_REQ_STATE_TRUNCATED |
		 PSCOM_REQ_STATE_DONE)) ==
		(PSCOM_REQ_STATE_DONE);
}

static inline
int pscom_req_successful(pscom_request_t *req)
{
	return pscom_req_state_successful(req->state);
}


static inline
int pscom_req_state_is_done(pscom_req_state_t state)
{
	return state & PSCOM_REQ_STATE_DONE;
}


static inline
int pscom_req_is_done(pscom_request_t *req)
{
	return pscom_req_state_is_done(req->state);
}


/*
 * Collective Operations/ Group handling
 */

typedef struct PSCOM_group pscom_group_t;

pscom_group_t *pscom_group_open(pscom_socket_t *socket,
				uint32_t group_id, uint32_t my_grank,
				uint32_t group_size, pscom_connection_t **connections);

void pscom_group_close(pscom_group_t *group);


/* post the broadcast request request.
   Send/Receive up to req->xheader_len bytes from/to req->xheader and
   up to req->data_len bytes from/to req->data from/to group with id
   req->xheader.bcast.group_id of socket req->socket.
   receive if req->xheader.bcast.group_src != group->my_rank, else send.

   req->xheader_len		: user len + sizeof(xheader.bcast)!
   req->xheader.bcast.group_id
   req->xheader.bcast.bcast_root
   req->xheader.bcast.user	: user data behind req->xheader.bcast
   req->data_len
   req->data
   req->socket

   optional:
   req->ops.recv_accept
   req->ops.io_done
*/
void pscom_post_bcast(pscom_request_t *request);

/* Blocking version of bcast */
void pscom_bcast(pscom_group_t *group, unsigned bcast_root,
		 void *xheader, unsigned int xheader_len,
		 void *data, unsigned int data_len);


/* communication barrier in group group. */
void pscom_barrier(pscom_group_t *group);

/* find group by id */
pscom_group_t *pscom_group_find(pscom_socket_t *socket, uint32_t group_id);

/* get id from group */
uint32_t pscom_group_get_id(pscom_group_t *group);


/*
 * Connection type's
 */

/* Allow ALL communication paths on socket (=default).
   (This does'nt overwrite env PSP_{arch}=0) */
void pscom_con_type_mask_all(pscom_socket_t *socket);

/* Disallow ALL communication paths on socket except con_type. */
void pscom_con_type_mask_only(pscom_socket_t *socket, pscom_con_type_t con_type);

/* Allow communication path con_type on socket. */
void pscom_con_type_mask_add(pscom_socket_t *socket, pscom_con_type_t con_type);

/* Disallow communication path con_type on socket. */
void pscom_con_type_mask_del(pscom_socket_t *socket, pscom_con_type_t con_type);

/* Communication path con_type on socket allowed? */
int pscom_con_type_mask_is_set(pscom_socket_t *socket, pscom_con_type_t con_type);


/*
 * query
 */
/* get next connection from socket. call with con == NULL to get the first connection.
 */
pscom_connection_t *pscom_get_next_connection(pscom_socket_t *socket, pscom_connection_t *con);


/* call pscom_connect with a string */
pscom_err_t pscom_connect_socket_str(pscom_connection_t *connection, const char *socket_str);

/* get the address of a listening socket */
const char *pscom_listen_socket_str(pscom_socket_t *socket);
/* get the address of a listening socket for on demand connections */
const char *pscom_listen_socket_ondemand_str(pscom_socket_t *socket);



const char *pscom_con_state_str(pscom_con_state_t state);
const char *pscom_con_type_str(pscom_con_type_t type);
const char *pscom_con_info_str(pscom_con_info_t *con_info);
const char *pscom_con_info_str2(pscom_con_info_t *con_info1, pscom_con_info_t *con_info2);
const char *pscom_con_str(pscom_connection_t *connection);
const char *pscom_req_state_str(pscom_req_state_t state);

const char *pscom_err_str(pscom_err_t error);
const char *pscom_op_str(pscom_op_t operation);

const char *pscom_socket_str(int nodeid, int portno);
const char *pscom_socket_ondemand_str(int nodeid, int portno, const char name[8]);
int pscom_parse_socket_str(const char *socket_str, int *nodeid, int *portno);
int pscom_parse_socket_ondemand_str(const char *socket_str, int *nodeid, int *portno, char (*name)[8]);


void pscom_set_debug(unsigned int level);

int pscom_readall(int fd, void *buf, int count);
int pscom_writeall(int fd, const void *buf, int count);
int pscom_atoport(const char *service, const char *proto);
int pscom_atoaddr(const char *address, struct in_addr *addr);
int pscom_ascii_to_sockaddr_in(const char *host, const char *port,
			       const char *protocol,
			       struct sockaddr_in *addr);

const char *pscom_dumpstr(const void *buf, int size);


#define pscom_min(a,b)      (((a)<(b))?(a):(b))
#define pscom_max(a,b)      (((a)>(b))?(a):(b))

void pscom_dump_reqstat(FILE *out);
void pscom_dump_info(FILE *out);

/* Get value name from environment */
void pscom_env_get_int(int *val, const char *name);
void pscom_env_get_uint(unsigned int *val, const char *name);
void pscom_env_get_str(char **val, const char *name);
void pscom_env_get_dir(char **val, const char *name);

extern char *(*pscom_env_get)(const char *name);
extern int (*pscom_env_set)(const char *name, const char *value, int overwrite);


#ifdef __cplusplus
}/* extern "C" */
#endif

#endif /* _PSCOM_H_ */

/*
 * Local Variables:
 *   mode: c
 *   c-basic-offset: 8
 * End:
 */
