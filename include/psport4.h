/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Authors:	Jens Hauke <hauke@par-tec.com>
 *		Thomas Moschny <moschny@ira.uka.de>
 */
/**
 * PSPort: Communication Library for Parastation , third edition
 * This library is DEPRECATED! new programs should use the libpscom
 * and pscom.h which replace libpsport4.
 */

#ifndef _PSPORT4_H_
#define _PSPORT4_H_

#ifdef __cplusplus
extern "C" {
#if 0
} // <- just for emacs indentation
#endif
#endif

#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>

/**
 * Handle to identify an open port.
 */
typedef struct PSP_PortH * PSP_PortH_t;

/**
 * Handle for a send or receive request. See PSP_ISend().
 */
typedef struct PSP_RequestH * PSP_RequestH_t;

/**
 * Routines that do not return a handle or something similar, are
 * declared to return PSP_Err_t to indicate errors.
 */
typedef enum {
  PSP_OK = 0,                /**< no error, operation successful */
  PSP_UNSPECIFIED_ERR = -1,  /**< there was some error, but we don't
				know the details */
  PSP_WRONG_ARG = -2,        /**< one of the arguments is invalid */
} PSP_Err_t;

/**
 * The PSP_Test(), PSP_Wait() and PSP_Cancel() routines show the
 * status of the request and, if the request is complete, the status
 * of the operation itself.
 *
 * @note The documentation differentiates between the (send or
 * receive) @e request and the (send or receive) @e operation. The
 * first term denotes the operations this library performs while
 * trying to send or receive something, whereas the latter stands for
 * the more abstract operation itself. The request is always
 * completed, but the operation may fail.
 */
typedef enum {
  PSP_NOT_COMPLETE = 0,      /**< request is pending */
  PSP_SUCCESS = 1,           /**< request is complete and the send or
				receive operation was successful */
  PSP_CANCELED = 2           /**< request is complete (but the send or
				receive operation was canceled) */
} PSP_Status_t;

typedef struct PSP_Header_Net_T {
    uint32_t            xheaderlen;
    uint32_t		datalen;
    long		xheader[0];
} PSP_Header_Net_t;

/* compatiblity to psport for p3 */
#define PSP_RecvHeader_t PSP_Header_Net_t

struct PSP_Header_T;

/**
 * Type of the callback to be passed to PSP_IReceive().
 */
typedef int (PSP_RecvCallBack_t)
(struct PSP_Header_Net_T* header, int from, void *param);

/**
 * Type of the callback that is executed upon finishing a send or
 * receive request. See PSP_IsendCB() and PSP_IReceiveCB().
 */
typedef void (PSP_DoneCallback_t)
(struct PSP_Header_T *header, void *param);



/*
 * private to psport:
 */
typedef struct PSP_Request_T{
    struct PSP_Request_T	*Next;
    struct PSP_Request_T	*NextGen; /* Used only for automatic generated requests */
    int                 state;
    int			UseCnt;		/* Count References to this request */
    PSP_RecvCallBack_t	*cb;		/*< Callback to check message */
    void		*cb_param;
    PSP_DoneCallback_t	*dcb;
    void		*dcb_param;

    struct iovec	iovec[2];
    unsigned int	skip;
    struct msghdr	msgheader;
} PSP_Request_t;


/**
 * General header to be used for send or receive requests.
 */
typedef struct PSP_Header_T {
    PSP_Request_t	Req;	/*< psport internal */
    union{
	uint32_t	from;
	uint32_t	to;
	long		_align_long_; /* align xheaderlen to long */
    } addr;
#define PSP_HEADER_NET( header ) ((PSP_Header_Net_t *)&(header)->xheaderlen)
#define PSP_HEADER_NET_LEN (sizeof(PSP_Header_Net_t))
    /* Here the PSP_Header_Net_t begins */
    uint32_t            xheaderlen;  /**< len of the user extra header,
					read-only. */
    uint32_t		datalen;     /**< len of message data,
					read-only. */
    long		xheader[0];  /**< from here on, the extra
					header is placed */
} PSP_Header_t;

/** Number of receives without recv request */
extern unsigned PSP_GenReqCount;
/** Number of uses of generated requests */
extern unsigned PSP_GenReqUsedCount;

/* ----------------------------------------------------------------------
 * PSP_Init()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Initialize the library.
 *
 * No parameters. This function must be called before any other call
 * to the library.
 *
 * DEPRECATED! new programs should use the libpscom and pscom.h which
 * replace libpsport4.
 *
 * @return Returns PSP_OK if the initialization was successful and
 * (maybe) an error code otherwise. Additionally, some diagnostics
 * might have been written to stderr.
 */
PSP_Err_t PSP_Init(void);


/* ----------------------------------------------------------------------
 * PSP_HWList()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Get a list of supportet hardwaretypes.
 *
 * No parameters.
 *
 * @return Returns a NULL terminated list of strings with the names of
 * supported hardwaretypes.
 */
char **PSP_HWList(void);

/* ----------------------------------------------------------------------
 * PSP_GetNodeID()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Get the ID of this node.
 *
 * Get the ParaStation ID of this node.
 *
 * @return	NodeID	on success and
 * @return	-1	on error
 */
int PSP_GetNodeID(void);

/* ----------------------------------------------------------------------
 * PSP_OpenPort()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Open a communication port.
 *
 * In order to do any communication, a port must be opened. The port
 * can be addressed by its number from other nodes later.
 *
 * Note: Every port-number can only be used once on every node. It is
 * an error to do a fork() with open ports. This is different from
 * standard Unix behavior.
 *
 * @param portno the desired port-number. The call will fail if this
 * port-number is not available. If portno is PSP_ANYPORT, the
 * allocated port will get an arbitrary port-number. The actual number
 * can then be obtained from PSP_GetPortNo()). The range for valid
 * port-numbers is 0..MAXINT.
 * @return Returns a handle for the port if open was successful and 0
 * otherwise. The port-handle must be passed to the communication calls.
 */
PSP_PortH_t PSP_OpenPort(int portno);
#define PSP_ANYPORT -1 /**< When used as a port-number, stands for any
			  port (wildcard). */


/* ----------------------------------------------------------------------
 * PSP_StopListen()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Stop listening for new connections on port.
 *
 */
void PSP_StopListen(PSP_PortH_t porth);

/* ----------------------------------------------------------------------
 * PSP_GetPortNo()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Get the number of an open port.
 *
 * The number of a previously opened port can be obtained by calling
 * this function with the port-handle.
 *
 * @param porth handle of the port, from PSP_OpenPort()
 * @return Returns the number of the port. A value <0 is returned, if
 * the number could not be determined, especially if the port-handle is
 * invalid. Currently, no error codes are returned.
 */
int PSP_GetPortNo(PSP_PortH_t porth);

/* ----------------------------------------------------------------------
 * PSP_ClosePort()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Close a port.
 *
 * A port can be closed if it is not used any longer. Outstanding
 * send/receive requests are canceled (implicitly) before the port is
 * really closed.
 *
 * @param porth handle of the port, from PSP_OpenPort()
 * @return Returns PSP_OK if the port could be closed and (maybe) an
 * error code otherwise. A diagnostic message might have been written
 * to stderr.
 */
PSP_Err_t PSP_ClosePort(PSP_PortH_t porth);



/* ----------------------------------------------------------------------
 * PSP_Connect()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Open a connection to remote server.
 *
 * @param porth handle of the port, from PSP_OpenPort()
 * @param nodeid unique ID of the remote server (comparable to IP address)
 * @param portno port number on the remote server
 * @return Returns the connection number usefull for PSP_ISend()
 * or -1 on error ( reason in errno )
 */
int PSP_Connect( PSP_PortH_t porth, int nodeid, int portno );

/* ----------------------------------------------------------------------
 * PSP_RecvFrom(), PSP_RecvAny()
 * ----------------------------------------------------------------------
 */

/**
 * Already existing call-back functions for PSP_IReceive().
 *
 */
PSP_RecvCallBack_t PSP_RecvAny;  /**< Receive from any sender */
PSP_RecvCallBack_t PSP_RecvFrom; /**< Receive from a certain sender */

/**
 *  Parameter for PSP_RecvFrom().
 */
typedef struct PSP_RecvFrom_Param_T{
    int from;
} PSP_RecvFrom_Param_t;


/* ----------------------------------------------------------------------
 * PSP_IReceive()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Start a non-blocking receive.
 *
 * With this call, the communication library is prepared to receive a
 * message asynchronously from the application. @e Two buffers must be
 * provided: one for the message itself and one for the header data.
 *
 * The length of the memory header buffer has to be equal to (and may
 * be greater than) sizeof(PSP_Header_t). It is up to the user to
 * provide enough room for any extra header data that might be
 * contained in the message. (at least sizeof(PSP_Header_t) + xheaderlen)
 * The whole header will never occupy more than PSP_MAX_HEADERSIZE bytes.
 *
 * Both buffers must be valid until the receive request is completed
 * (see PSP_Wait(), PSP_Test() and PSP_Cancel()) and may not be used
 * by the user for that time.
 *
 * A call-back function that is used to determine for a newly arrived
 * message whether it should be received by this receive-request can
 * be specified. Not more than buflen bytes are received from one
 * message.
 *
 * If the sender of the message to be received (i.e. it's node number)
 * is already kown, it can be specified in the PSP_IReceiveFrom() or
 * PSP_IReceiveCBFrom() calls. Fewer messages headers have to be
 * reviewed by the callback function then.
 *
 * @param porth handle of the port, from PSP_OpenPort()
 * @param buf address of buffer for message data
 * @param buflen length of message data buffer, in bytes
 * @param header address of buffer for header data
 * @param xheaderlen length of message extra header buffer, in bytes
 * @param cb call-back function that will be used to determine whether
 * a certain message is to be received by this receive-request
 * @param cb_param this pointer is passed to the call-back function
 * @param dcb call-back function that will be called upon completion
 * of the receive request
 * @param dcb_param this pointer is passed to dcb
 * @param sender one can specify the sender (node number) of the
 * message to be received here if already known, or PSP_AnySender
 * @return Returns a handle for the request or NULL if there is an
 * error. The handle can be passed to PSP_Test() and PSP_Wait().
 */
PSP_RequestH_t PSP_IReceiveCBFrom(PSP_PortH_t porth,
				  void* buf, unsigned buflen,
				  PSP_Header_t* header, unsigned xheaderlen,
				  PSP_RecvCallBack_t* cb, void* cb_param,
				  PSP_DoneCallback_t* dcb, void* dcb_param,
				  int sender);

#define PSP_AnySender -1

static inline
PSP_RequestH_t PSP_IReceiveCB(PSP_PortH_t porth,
			      void* buf, unsigned buflen,
			      PSP_Header_t* header, unsigned xheaderlen,
			      PSP_RecvCallBack_t* cb, void* cb_param,
			      PSP_DoneCallback_t* dcb, void* dcb_param)
{
    return PSP_IReceiveCBFrom(porth, buf, buflen, header, xheaderlen,
			      cb, cb_param, dcb, dcb_param, PSP_AnySender);
}

static inline
PSP_RequestH_t PSP_IReceiveFrom(PSP_PortH_t porth,
				void* buf, unsigned buflen,
				PSP_Header_t* header, unsigned xheaderlen,
				PSP_RecvCallBack_t* cb, void* cb_param,
				int sender)
{
    return PSP_IReceiveCBFrom(porth, buf, buflen, header, xheaderlen,
			      cb, cb_param, 0, 0, sender);
}

static inline
PSP_RequestH_t PSP_IReceive(PSP_PortH_t porth,
			    void* buf, unsigned buflen,
			    PSP_Header_t* header, unsigned xheaderlen,
			    PSP_RecvCallBack_t* cb, void* cb_param)
{
    return PSP_IReceiveCBFrom(porth, buf, buflen, header, xheaderlen,
			      cb, cb_param, 0, 0, PSP_AnySender);
}


/* ----------------------------------------------------------------------
 * PSP_IProbe()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Test for availability of a message.
 *
 * This call returns true if a message is already available that would
 * be received by a call to PSP_IReceive() with the same callback
 * function and parameters. The header data of this message is copied
 * to the given header buffer, then.
 *
 * @param porth handle of the port, from PSP_OpenPort()
 * @param header address of buffer for header data
 * @param xheaderlen length of message extra header buffer, in bytes
 * @param cb callback function
 * @param cb_param this pointer is passed to the callback function
 * @param sender one can specify the sender (node number) of the
 * message to be received here if already known, or PSP_AnySender
 * @return Returns true if a matching message is available (already
 * received) and false otherwise.
 */
int PSP_IProbeFrom(PSP_PortH_t porth,
		   PSP_Header_t* header, unsigned xheaderlen,
		   PSP_RecvCallBack_t *cb, void* cb_param,
		   int sender);

static inline
int PSP_IProbe(PSP_PortH_t porth,
	       PSP_Header_t* header, unsigned xheaderlen,
	       PSP_RecvCallBack_t *cb, void* cb_param)
{
    return PSP_IProbeFrom(porth, header, xheaderlen, cb, cb_param,
			  PSP_AnySender);
}

/* ----------------------------------------------------------------------
 * PSP_Probe()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Wait for availability of a message.
 *
 * This call returns when and if a message is available that would be
 * received by a call to PSP_IReceive() with the same callback
 * function and parameters. The header data of this message is copied
 * to the given header buffer.
 *
 * @param porth handle of the port, from PSP_OpenPort()
 * @param header address of buffer for header data
 * @param xheaderlen length of message extra header buffer, in bytes
 * @param cb callback function
 * @param cb_param this pointer is passed to the callback function
 * @param sender ???
 * @return Returns true.
 */
int PSP_ProbeFrom(PSP_PortH_t porth,
		  PSP_Header_t* header, unsigned xheaderlen,
		  PSP_RecvCallBack_t *cb, void* cb_param,
		  int sender);

static inline
int PSP_Probe(PSP_PortH_t porth,
	      PSP_Header_t* header, unsigned xheaderlen,
	      PSP_RecvCallBack_t *cb, void* cb_param)
{
    return PSP_ProbeFrom(porth, header, xheaderlen, cb, cb_param,
			 PSP_AnySender);
}


#define PSP_MSGFLAG_HIGHPRIO 1
#define PSP_DEST_LOOPBACK    0x7fff

/* ----------------------------------------------------------------------
 * PSP_ISend()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Start a non-blocking send.
 *
 * With this call, the communication library is advised to send a
 * message asynchronously from the application. Two addresses must be
 * provided: one points to the data itself and one to the header
 * data.
 *
 * The memory for header must be provided by the user. Its length has
 * to be equal to or greater than sizeof(PSP_Header_t). xheaderlen extra
 * header bytes are sent along with the message.
 *
 * Both buffers (for message data and message header) have to be valid
 * and their contents may not be altered anymore until the send
 * request is completed (see PSP_Wait(), PSP_Test() and PSP_Cancel()).
 *
 * @param porth handle of the port, from PSP_OpenPort()
 * @param buf address of buffer for message data
 * @param buflen length of message data buffer, in bytes
 * @param header address of header data buffer
 * @param xheaderlen length of message extra header buffer, in bytes
 * @param dest ????
 * @param flags ????
 * @return Returns a handle for the request or Null if there is an
 * error.
 *
 * @note The returned request handle can be passed to PSP_Test(),
 * PSP_Wait() and PSP_Cancel() and is valid as long as the
 * user-provided memory for the header data is valid and not altered
 * (e.g. reused for another send or receive request.)
 */

PSP_RequestH_t PSP_ISend(PSP_PortH_t porth,
			 void* buf, unsigned buflen,
			 PSP_Header_t* header, unsigned xheaderlen,
			 int dest,int flags);


/* ----------------------------------------------------------------------
 * PSP_Test()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Test for the completion of a non-blocking send/receive
 * request.
 *
 * This call can be used to test whether the processing of a send or
 * receive request has been completed or stopped. Note: The send or
 * receive operation itself might have been unsuccessful or canceled;
 * the return code provides information about that fact.
 *
 * @note A call to PSP_Wait() or PSP_Test() is always necessary to
 * know whether the buffers for message data and message header may be
 * reused.
 *
 * @param porth handle of the port, from PSP_OpenPort()
 * @param request handle of the send or receive request
 * @return Returns PSP_NOT_COMPLETE, if the send or receive request has
 * not completed yet and information the status of the send/receive
 * operation otherwise.
 */
PSP_Status_t PSP_Test(PSP_PortH_t porth, PSP_RequestH_t request);

/* ----------------------------------------------------------------------
 * PSP_Wait()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Wait for the completion of a non-blocking send/receive
 * request.
 *
 * This call can be used to wait until the processing of the send or
 * receive request specified via its request-handle has completed or
 * stopped. Note: The send or receive operation itself might have been
 * unsuccessful or canceled; the return code provides information
 * about that fact.
 *
 * @note A call to PSP_Wait() or PSP_Test() is always necessary to
 * know whether the buffers for message data and message header may be
 * reused.
 *
 * @param porth handle of the port, from PSP_OpenPort()
 * @param request handle of the send or receive request
 * @return Returns information about the status of the send/receive
 * operation. Unlike PSP_Test() this call doesn't return
 * PSP_NOT_COMPLETE.
 */
PSP_Status_t PSP_Wait(PSP_PortH_t porth, PSP_RequestH_t request);

/* ----------------------------------------------------------------------
 * PSP_Cancel()
 * ----------------------------------------------------------------------
 */

/**
 * @brief Try to cancel a non-blocking send/receive request.
 *
 * The user can try to cancel a send or receive request, however,
 * there is no guaranty that this is successful.
 *
 * @param porth handle of the port, from PSP_OpenPort()
 * @param request handle of the send or receive request
 * @return Returns information about the status of the send/receive
 * operation. If this call returns PSP_NOT_READY, the request could
 * not canceled.
 */
PSP_Status_t PSP_Cancel(PSP_PortH_t porth, PSP_RequestH_t request);




#define PSP_CON_STATE_UNUSED	0
#define PSP_CON_STATE_OPEN	1
#define PSP_CON_STATE_OPEN_LOOP	2
#define PSP_CON_STATE_OPEN_TCP	3
#define PSP_CON_STATE_OPEN_SHM	4
#define PSP_CON_STATE_OPEN_P4S	5
#define PSP_CON_STATE_OPEN_GM	6
#define PSP_CON_STATE_OPEN_MVAPI 7
#define PSP_CON_STATE_OPEN_OPENIB 8

struct PSP_ConInfo_s {
    int node_id;
    int pid;
    int con_idx;
};

typedef struct PSP_ConnectionState_T {
    int	state; /**< State of connection (= PSP_CON_STATE_xxx) */

    struct PSP_ConInfo_s local;
    struct PSP_ConInfo_s remote;
} PSP_ConnectionState_t;

int PSP_GetConnectionState(PSP_PortH_t porth, int dest, PSP_ConnectionState_t *cs);

const char *PSP_ConState_str(int state);


#ifdef __cplusplus
}/* extern "C" */
#endif

#endif /* _PSPORT4_H_ */

/*
 * Local Variables:
 *   mode: c
 *   c-basic-offset: 4
 *   c-font-lock-extra-types: ( "\\sw+_t" "UINT16" "UINT32" )
 * End:
 */
