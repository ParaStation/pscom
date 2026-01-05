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

#ifndef _PSCOM_PRIV_H_
#define _PSCOM_PRIV_H_

#include "pscom.h"
#include "pscom_types.h" /* IWYU pragma: export */
#include "pscom_poll.h"
#include "list.h"
#include "pscom_ufd.h"
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "pscom_tcp.h"
#include "pscom_shm.h"
#include "pscom_gm.h"
#include "pscom_env.h"
#include "pscom_precon.h"

#include "pscom_debug.h"

#define MAGIC_REQUEST 0x72657175
struct PSCOM_req {
    unsigned long magic;

    struct list_head next;         /* General purpose next. Used by:
                                      - list PSCOM.io_doneq
                                      - list pscom_con_t.recvq_rma
                                      - list pscom_con_t.sendq
                                      - list pscom_con_t.recvq_user
                                      - list pscom_con_t.net_recvq_user
                                      - list pscom_sock_t.recvq_any
                                      - list pscom_sock_t.group_req_unknown
                                   */
    struct list_head next_alt;     /* Alternative next. Used by:
                                      - list pscom_sock_t.genrecvq_any
                                      - list pscom_bcast_req_t.fw_send_requests
                                      - list pscom_group_mem_t.recvq
                                      - list pscom_group_mem_t.genrecvq
                                      - list pscom_con_t.sendq_gw_fw
                                   */
    struct list_head all_req_next; // used by list struct PSCOM.requests

    struct iovec cur_header;
    struct iovec cur_data;
    size_t skip;             /* recv: overread skip bytes at the end.
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
    pscom_req_t *pending_io_req;

#ifdef PSCOM_CUDA_AWARENESS
    void *stage_buf; /* stage buf for non-CUDA-aware connections */
#endif

    struct pscom_rendezvous_data *rndv_data;

    /* used to store result_addr for get_acc, fetch&op and comp&swap */
    void *rma_result;

    void (*write_hook)(pscom_req_t *req, char *buf, size_t len);

    unsigned int req_no; // debug counter
    pscom_request_t pub;
};


typedef struct pscom_portals_sock pscom_portals_sock_t;
typedef struct pscom_arch_sock pscom_arch_sock_t;

/* RMA functions */
/**
 * @brief Function pointer of memory region registration.
 *
 * This function registers the memory region starting from addr with length.
 * The memory region will be registered in the plugin associated with arch_sock.
 * A remote key buffer and its size will be returned.
 *
 * @param [in]  addr            The starting address of the memory region.
 * @param [in]  length          The length of the memory region.
 * @param [out] rkey_buf        The pointer to store the remote key buffer.
 * @param [out] bufsize         The size of the remote key buffer.
 * @param [in]  arch_sock       The arch_sock associated with certain plugin.
 * @param [out] plugin_memh     The opaque handle of memory region in the
 *                              plugin.
 */
typedef int (*pscom_rma_mem_register_fn_t)(void *addr, size_t length,
                                           void **rkey_buf, uint16_t *bufsize,
                                           pscom_arch_sock_t *arch_sock,
                                           void **plugin_memh);

/**
 * @brief Function pointer of memory region de-registration.
 *
 * This function deregisters the memory region.
 *
 * @param [in] plugin_memh The opaque handle of memory region in the plugin.
 */
typedef int (*pscom_rma_mem_deregister_fn_t)(void *plugin_memh);

/**
 * @brief Function pointer of remote key generation.
 *
 * This function generates the remote key bound to the connection in the plugin.
 * The remote key buffer received from the process which shares the memory
 * region is used to generate the remote key in the plugin.
 *
 * @param [in]  con         The connection which the remote key is bound to.
 * @param [in]  rekey_buf   The buffer used to generate remote key.
 * @param [out] plugin_rkey The opaque handle of remote key in the plugin.
 */
typedef int (*pscom_rma_rkey_generate_fn_t)(pscom_con_t *con, void *rkey_buf,
                                            void **plugin_rkey);

/**
 * @brief Function pointer of remote key destroy.
 *
 * This function destroys the remote key bound to the connection in the plugin.
 *
 * @param [in] plugin_rkey The opaque handle of remote key in the plugin.
 */
typedef int (*pscom_rma_rkey_destroy_fn_t)(void *plugin_rkey);


/**
 * @brief Function pointer of remote key buffer free.
 *
 * This function frees the remote key buffer allocated in the plugin.
 *
 * @param [in] rkey_buf The pointer to remote key buffer.
 */
typedef void (*pscom_rma_rkey_buf_free_fn_t)(void *rkey_buf);

/**
 * @brief Function pointer of RMA put.
 *
 * This function performs RMA put operation in the plugin via the connection.
 * RMA put transfer the data in buffer to the target remote_addr. This operation
 * is non-blocking, and req is used to track the progress.
 *
 * @param [in] con          The connection handle.
 * @param [in] buffer       The source address in the local process.
 * @param [in] length       The number of bytes to be sent.
 * @param [in] remote_addr  The destination address at the remote process.
 * @param [in] plugin_rkey  The remote key handle in the plugin.
 * @param [in] req          The pscom request handle.
 */
typedef int (*pscom_rma_put_fn_t)(pscom_con_t *con, void *buffer, size_t length,
                                  void *remote_addr, void *plugin_rkey,
                                  pscom_req_t *req);

/**
 * @brief Function pointer of RMA get.
 *
 * This function performs RMA get operation in the plugin via the connection.
 * RMA get will copy the data from the target remote_addr into the buffer.
 * This operation is non-blocking, and req is used to track the progress.
 *
 * @param [in] con          The connection handle.
 * @param [in] buffer       The target address in the local process.
 * @param [in] length       The number of bytes to be sent.
 * @param [in] remote_addr  The source address at the remote process.
 * @param [in] plugin_rkey  The remote key handle in the plugin.
 * @param [in] req          The pscom request handle.
 */
typedef int (*pscom_rma_get_fn_t)(pscom_con_t *con, void *buffer, size_t length,
                                  void *remote_addr, void *plugin_rkey,
                                  pscom_req_t *req);

struct pscom_arch_sock {
    struct list_head next;
    pscom_con_type_t plugin_con_type;
    struct {
        pscom_rma_mem_register_fn_t mem_register;
        pscom_rma_mem_deregister_fn_t mem_deregister;
        pscom_rma_rkey_buf_free_fn_t rkey_buf_free;
    } rma;
    union {
        psgm_sock_t gm;
        pscom_portals_sock_t *portals;
    } arch;
    char arch_sock_data[0];
};

struct con_guard {
    int fd;
};

typedef struct loopback_conn {
    int sending;
} loopback_conn_t;


typedef struct psib_conn {
    void *priv;
} psib_conn_t;


typedef struct psoib_conn {
    struct psoib_con_info *mcon;
} psoib_conn_t;


typedef struct psofed_conn {
    struct psofed_con_info *mcon;
    unsigned reading : 1;
} psofed_conn_t;


typedef struct psdapl_conn {
    struct psdapl_con_info *ci;
} psdapl_conn_t;


typedef struct pselan_conn {
    struct pselan_con_info *ci;
} pselan_conn_t;


typedef struct pspsm_conn {
    struct pspsm_con_info *ci;
    unsigned reading : 1;
} pspsm_conn_t;


typedef struct psextoll_conn {
    struct psex_con_info *ci;
    unsigned reading : 1;
} psextoll_conn_t;


typedef struct psmxm_conn {
    struct psmxm_con_info *ci;
    unsigned reading : 1;
    pscom_req_t *sreq;
} psmxm_conn_t;


typedef struct psucp_conn {
    struct psucp_con_info *ci;
    unsigned reading : 1;
} psucp_conn_t;

typedef struct psptl_conn {
    struct psptl_con_info *ci;
    pscom_portals_sock_t *arch_sock;
    unsigned reading : 1;
} psptl_conn_t;

typedef struct psgw_conn {
    struct psgw_con_info *ci;
    unsigned reading : 1;
    unsigned info_received : 1;
    unsigned info_sent : 1;
    unsigned ack_sent : 1;
} psgw_conn_t;


typedef struct ondemand_conn {
    unsigned active; /* active listening on new connections? */
} ondemand_conn_t;


typedef struct user_conn {
    void *priv;
} user_conn_t;


/* rendezvous message for RMA requests. */

/*
  Net layout of a PSCOM_MSGTYPE_RENDEZVOUS_REQ message:

  header (pscom_header_net_t):
      xheader_len: calculated
      msg_type:    PSCOM_MSGTYPE_RENDEZVOUS_REQ
      data_len:    0
  xheader:
      user_header (pscom_header_net_t):
          xheader_len: user_req->pub.xheader_len
          msg_type:    PSCOM_MSGTYPE_USER
          data_len:    user_req->pub.data_len
      user_xheader:
          char user_xheader[user_req->pub.xheader_len]

      rendezvous_msg (pscom_rendezvous_msg_t):
          common data: id and data pointer
          arch dependent. Size is calculated. sizeof(rendezvous_msg) <=
  sizeof(pscom_rendezvous_msg_t) data: // no data
 */
typedef struct pscom_rendezvous_xheader {
    pscom_header_net_t user_header_net;
    char user_xheader[0 /* user_req->pub.xheader_len */];
    /* after user_header: (pscom_rendezvous_data_t)
     * &user_xheader[user_header_net.xheader_len] */
} pscom_rendezvous_xheader_t;

typedef struct pscom_rendezvous_msg {
    void *id; /* == pscom_req_t *user_req; from sending side */
    void *data;
    size_t data_len;
    union {
        struct {
        } shm;
        struct {
            uint32_t /* DAT_RMR_CONTEXT */ rmr_context;
            uint64_t /* DAT_CONTEXT */ rmr_vaddr;
        } dapl;
        struct {
            uint64_t /* RMA2_NLA */ rma2_nla; /* Network logical address of the
                                                 sender */
        } extoll;
        struct {
            uint32_t mr_key;
            uint64_t mr_addr;
            int padding_size;
            char padding_data[64]; // >= IB_RNDV_PADDING_SIZE (see psoib.h)
        } openib;
        struct {
            uint64_t /* ptl_match_bits_t */ match_bits;
        } portals;
    } arch;
} pscom_rendezvous_msg_t;


static inline size_t pscom_rendezvous_msg_len(size_t arch_len)
{
    return sizeof(pscom_rendezvous_msg_t) -
           sizeof(((pscom_rendezvous_msg_t *)0)->arch) + arch_len;
}


static inline size_t pscom_rendezvous_xheader_len(size_t arch_len,
                                                  size_t user_xheader_len)
{
    return sizeof(pscom_rendezvous_xheader_t) +
           pscom_rendezvous_msg_len(arch_len) + user_xheader_len;
}


// Inverted pscom_rendezvous_xheader_len(). return arch_len;
static inline size_t pscom_rendezvous_arch_len(size_t xheader_len,
                                               size_t user_xheader_len)
{
    return xheader_len - pscom_rendezvous_xheader_len(0, user_xheader_len);
}


typedef struct pscom_rendezvous_data_shm {
} pscom_rendezvous_data_shm_t;


typedef struct _pscom_rendezvous_data_dapl {
    char /* struct psdapl_rdma_req */ data[128];
} _pscom_rendezvous_data_dapl_t;

typedef struct _pscom_rendezvous_data_extoll {
    /* placeholder for struct pscom_rendezvous_data_extoll */
    char /* struct psex_rma_req */ _rma_req[192];
} _pscom_rendezvous_data_extoll_t;


typedef struct _pscom_rendezvous_data_openib {
    /* placeholder for struct pscom_rendezvous_data_openib */
    char /* struct psiob_rma_req */ _rma_req[128]; /* ??? */
} _pscom_rendezvous_data_openib_t;


typedef struct _pscom_rendezvous_data_portals {
    /* placeholder for struct pscom_rendezvous_data_portals */
    char /* struct psiob_rma_req */ _rma_req[128]; /* ??? */
} _pscom_rendezvous_data_portals_t;


typedef struct pscom_rendezvous_data {
    pscom_rendezvous_msg_t msg;
    size_t msg_arch_len;
    union {
        pscom_rendezvous_data_shm_t shm;
        _pscom_rendezvous_data_dapl_t dapl;
        _pscom_rendezvous_data_extoll_t extoll;
        _pscom_rendezvous_data_openib_t openib;
        _pscom_rendezvous_data_portals_t portals;
    } arch;
} pscom_rendezvous_data_t;


typedef struct pscom_backlog {
    struct list_head next;
    void (*call)(void *priv);
    void *priv;
} pscom_backlog_t;


typedef uint32_t pscom_con_id_t;
typedef uint32_t pscom_sock_id_t;


/* RNDV protocol funcitons */
typedef unsigned int (*pscom_rndv_mem_register_fn_t)(
    pscom_con_t *con, struct pscom_rendezvous_data *rd);
typedef int (*pscom_rndv_mem_register_check_fn_t)(pscom_con_t *con,
                                                  pscom_rendezvous_data_t *rd);
typedef void (*pscom_rndv_mem_deregister_fn_t)(pscom_con_t *con,
                                               pscom_rendezvous_data_t *rd);
typedef int (*pscom_rndv_rma_read_fn_t)(pscom_req_t *rendezvous_req,
                                        pscom_rendezvous_data_t *rd);
typedef int (*pscom_rndv_rma_write_fn_t)(pscom_con_t *con, void *src,
                                         pscom_rendezvous_msg_t *des,
                                         void (*io_done)(void *priv, int error),
                                         void *priv);


#define MAGIC_CONNECTION 0x78626c61
struct PSCOM_con {
    unsigned long magic;
    struct list_head next;

    /**
     * @brief Start reading on a connection
     *
     * This function sets a connection to reading state *without* passing
     * any received data to the upper pscom layer. This has to be done in a
     * seperate call.
     *
     * \remark The read_start() function can be called safely multiple times
     *         without the need to call read_stop() in between.
     *
     * @param [in] con The connection to be opened
     */
    pscom_poll_t poll_read; // used if .read_start = pscom_poll_read_start
    void (*read_start)(pscom_con_t *con);
    void (*read_stop)(pscom_con_t *con);

    pscom_poll_t poll_write; // used if .write_start = pscom_poll_write_start
    void (*write_start)(pscom_con_t *con);
    void (*write_stop)(pscom_con_t *con);

    void (*close)(pscom_con_t *con);

    struct {
        /* RMA functions: */
        /* register mem region for RMA. should return size of
         * rd->msg.arch.xxx (this is used, to calculate the size of
         * the rendezvous message). return 0 to disable arch read (in
         * case of a failure). */
        pscom_rndv_mem_register_fn_t mem_register;
        pscom_rndv_mem_register_check_fn_t mem_register_check;
        /* deregister mem. */
        pscom_rndv_mem_deregister_fn_t mem_deregister;
        /* return -1 on error.
           see _pscom_rendezvous_read_data()  */
        pscom_rndv_rma_read_fn_t rma_read;
        pscom_rndv_rma_write_fn_t rma_write;
    } rndv;

    struct {
        pscom_rma_rkey_generate_fn_t rkey_generate;
        pscom_rma_rkey_destroy_fn_t rkey_destroy;
        pscom_rma_put_fn_t put;
        pscom_rma_get_fn_t get;
    } rma;

    pscom_precon_t *precon; // Pre connection handshake data.

    unsigned int rendezvous_size;
    unsigned int recv_req_cnt; // count all receive requests on this connection

    unsigned int write_pending_io_cnt; // count all send requests with pending
                                       // I/O
#ifdef PSCOM_CUDA_AWARENESS
    unsigned int is_gpu_aware; // we can safely pass pointers to GPU buffers to
                               // this connection
#endif
    int suspend_on_demand_portno; // remote listening portno on suspended
                                  // connections
    pscom_con_id_t id;            // Process local unique connection id

    struct list_head sendq; // List of pscom_req_t.next

    struct list_head recvq_user; // List of pscom_req_t.next
    struct list_head recvq_ctrl; // List of pscom_req_t.next
    struct list_head recvq_rma;  // List of pscom_req_t.next
    /* more receivequeues in pscom_group_t:
     *                      recvq_bcast */

    struct list_head net_recvq_user; // List of pscom_req_t.next
    struct list_head net_recvq_ctrl; // List of pscom_req_t.next
    /* more net receivequeues in pscom_group_t:
     *                      net_recvq_bcast */

    struct list_head sendq_gw_fw; // List of pscom_req_t.next_alt

    struct con_guard con_guard; // connection guard

    struct {
        pscom_req_t *req;
        pscom_req_t *req_locked; /* request in use by a plugin with an
                                    asynchronous receive (RMA) set/unset by
                                    pscom_read_get_buf_locked/pscom_read_done_unlock
                                  */
        struct iovec readahead;
        size_t readahead_size;

        size_t skip;
    } in;

    union {
        loopback_conn_t loop;
        tcp_conn_t tcp;
        shm_conn_t shm;
        psib_conn_t mvapi;
        psoib_conn_t openib;
        psofed_conn_t ofed;
        psgm_conn_t gm;
        psdapl_conn_t dapl;
        pselan_conn_t elan;
        psextoll_conn_t extoll;
        psmxm_conn_t mxm;
        psucp_conn_t ucp;
        psgw_conn_t gateway;
        ondemand_conn_t ondemand;
        pspsm_conn_t psm;
        psptl_conn_t portals;
        user_conn_t user; // Future usage (new plugins)
    } arch;

    struct {
        unsigned eof_expect : 1;
        unsigned eof_received : 1;
        unsigned read_failed : 1;
        unsigned close_called : 1;
        unsigned destroyed : 1;
        unsigned suspend_active : 1;
        unsigned con_cleanup : 1;
        unsigned internal_connection : 1;
        unsigned use_count : 3;
    } state;
    uint64_t con_flags;
    pscom_connection_t pub;
};


#define MAGIC_SOCKET 0x6a656e73
struct PSCOM_sock {
    unsigned long magic;
    struct list_head next; // used by list pscom.sockets

    struct list_head connections; // List of pscom_con_t.next

    struct list_head recvq_any;    // List of pscom_req_t.next (all recv any
                                   // requests)
    struct list_head genrecvq_any; // List of pscom_req_t.next_alt(all generated
                                   // requests)

    struct list_head groups;            // List of pscom_group_t.next
    struct list_head group_req_unknown; // List of pscom_req_t.next (requests
                                        // with unknown group id)

    struct pscom_listener listen;

    unsigned int recv_req_cnt_any; // count all ANY_SOURCE receive requests on
                                   // this socket

    pscom_sock_id_t id; // Process local unique socket id

    struct list_head sendq_suspending; // List of pscom_req_t.next, requests
                                       // from suspending connections

    uint64_t con_type_mask; /* allowed con_types.
                               Or'd value from: (1 << (pscom_con_type_t)
                               con_type) default = ~0 */

    struct list_head archs; // List of architecture-specific sockets

    struct {
        unsigned close_called : 1;
        unsigned close_timeout : 1;
        unsigned destroyed : 1;
    } state;

    uint64_t sock_flags;
    pscom_socket_t pub;
};


struct PSCOM {
    ufd_t ufd;
    struct list_head sockets;  // List of pscom_sock_t.next
    struct list_head requests; // List of pscom_req_t.all_req_next
    int ufd_timeout;           // next timeout or -1

    struct list_head recvq_any_global;
    unsigned int recv_req_cnt_any_global;

    pthread_mutex_t global_lock;
    pthread_mutex_t lock_requests;
    int threaded; // Bool: multithreaded? (=Use locking)

    struct list_head io_doneq; // List of pscom_req_t.next

    pscom_poll_list_t poll_read;
    pscom_poll_list_t poll_write;
    struct list_head backlog; // List of pscom_backlog_t.next

    pthread_mutex_t backlog_lock; // Lock for backlog

    struct list_head env_config; // List of environment configuration tables
    struct PSCOM_env env;

    struct {
        unsigned int reqs;
        unsigned int gen_reqs;
        unsigned int gen_reqs_used;

        unsigned int rendezvous_reqs;
        unsigned int fallback_to_eager;
        unsigned int fallback_to_sw_rndv;

        unsigned int progresscounter;
        unsigned int progresscounter_check;

        unsigned int reqs_any_source; // count enqueued ANY_SOURCE requests in
                                      // sock->recvq_any
        unsigned int recvq_any; // count enqueued requests in sock->recvq_any
                                // (SOURCED and ANY_SOURCE)
        unsigned int recvq_any_global; // count enqueued requests in global
                                       // queueu (")

        unsigned int probes;            // All probes (including any)
        unsigned int iprobes_ok;        // All iprobes returning 1 = "received"
        unsigned int probes_any_source; // All ANY_SOURCE probes

        unsigned int shm_direct;           // successful shm direct sends
        unsigned int shm_direct_nonshmptr; // shm direct with copy because
                                           // !is_psshm_ptr(data)
        unsigned int shm_direct_failed;    // failed shm direct because
                                           // !is_psshm_ptr(malloc(data))
#ifdef PSCOM_CUDA_AWARENESS
        unsigned int gpu_staging;   // counts all gpu buffer staging
        unsigned int gpu_unstaging; // counts all gpu buffer unstaging
#endif                              /* PSCOM_CUDA_AWARENESS */
    } stat;
};


extern pscom_t pscom;


#define PSCOM_ARCH2CON_TYPE(arch)     ((pscom_con_type_t)((arch)-101))
#define PSCOM_CON_TYPE2ARCH(con_type) ((con_type) + 101)

/* Keep PSCOM_ARCH_{} in sync with PSCOM_CON_TYPE_{} ! */
#define PSCOM_ARCH_ERROR    101
#define PSCOM_ARCH_LOOP     /* 102 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_LOOP)
#define PSCOM_ARCH_TCP      /* 103 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_TCP)
#define PSCOM_ARCH_SHM      /* 104 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_SHM)
#define PSCOM_ARCH_GM       /* 106 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_GM)
#define PSCOM_ARCH_MVAPI    /* 107 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_MVAPI)
#define PSCOM_ARCH_OPENIB   /* 108 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_OPENIB)
#define PSCOM_ARCH_ELAN     /* 109 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_ELAN)
#define PSCOM_ARCH_DAPL     /* 110 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_DAPL)
#define PSCOM_ARCH_ONDEMAND /* 111 */                                          \
    PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_ONDEMAND)
#define PSCOM_ARCH_OFED    /* 112 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_OFED)
#define PSCOM_ARCH_EXTOLL  /* 113 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_EXTOLL)
#define PSCOM_ARCH_PSM     /* 114 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_PSM)
#define PSCOM_ARCH_VELO    /* 115 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_VELO)
#define PSCOM_ARCH_CBC     /* 116 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_CBC)
#define PSCOM_ARCH_MXM     /* 117 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_MXM)
#define PSCOM_ARCH_SUSPEND /* 118 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_SUSPEND)
#define PSCOM_ARCH_UCP     /* 119 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_UCP)
#define PSCOM_ARCH_GW      /* 120 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_GW)
#define PSCOM_ARCH_PORTALS /* 121 */ PSCOM_CON_TYPE2ARCH(PSCOM_CON_TYPE_PORTALS)


#define PSCOM_TCP_PRIO     2
#define PSCOM_SHM_PRIO     90
#define PSCOM_GM_PRIO      15
#define PSCOM_MVAPI_PRIO   20
#define PSCOM_OPENIB_PRIO  20
#define PSCOM_ELAN_PRIO    20
#define PSCOM_DAPL_PRIO    15
#define PSCOM_OFED_PRIO    30
#define PSCOM_EXTOLL_PRIO  30
#define PSCOM_PSM_PRIO     30
#define PSCOM_MXM_PRIO     30
#define PSCOM_UCP_PRIO     30
#define PSCOM_GW_PRIO      10
#define PSCOM_PORTALS_PRIO 40

typedef uint8_t pscom_msgtype_t;

#define PSCOM_MSGTYPE_USER            0
#define PSCOM_MSGTYPE_RMA_WRITE       1
#define PSCOM_MSGTYPE_RMA_READ        2
#define PSCOM_MSGTYPE_RMA_READ_ANSWER 3
#define PSCOM_MSGTYPE_RENDEZVOUS_REQ  4 /* Request for a rendezvous */
#define PSCOM_MSGTYPE_RENDEZVOUS_FIN  5 /* Rendezvous done */
#define PSCOM_MSGTYPE_BCAST           6
#define PSCOM_MSGTYPE_BARRIER         7
#define PSCOM_MSGTYPE_EOF             8
#define PSCOM_MSGTYPE_SUSPEND         9
#define PSCOM_MSGTYPE_GW_ENVELOPE     10

/* RMA tags via send/recv */
#define PSCOM_MSGTYPE_RMA_PUT                  11
#define PSCOM_MSGTYPE_RMA_GET_REP              12
#define PSCOM_MSGTYPE_RMA_ACCUMULATE           13
#define PSCOM_MSGTYPE_RMA_GET_ACCUMULATE_REP   14
#define PSCOM_MSGTYPE_RMA_FETCH_AND_OP_REP     15
#define PSCOM_MSGTYPE_RMA_COMPARE_AND_SWAP_REP 16
#define PSCOM_MSGTYPE_RMA_GET_REQ              17
#define PSCOM_MSGTYPE_RMA_GET_ACCUMULATE_REQ   18
#define PSCOM_MSGTYPE_RMA_FETCH_AND_OP_REQ     19
#define PSCOM_MSGTYPE_RMA_COMPARE_AND_SWAP_REQ 20

#ifdef PSCOM_CUDA_AWARENESS
#define PSCOM_IF_CUDA(yes, no) yes
#else
#define PSCOM_IF_CUDA(yes, no) no
#endif

extern int mt_locked;

static inline void pscom_lock(void)
{
    if (!pscom.threaded) { return; }
    int res_mutex_lock;
    res_mutex_lock = pthread_mutex_lock(&pscom.global_lock);
    assert(res_mutex_lock == 0);
}


void pscom_unlock(void);

static inline void _pscom_unlock(void)
{
    if (!pscom.threaded) { return; }
    int res_mutex_unlock;
    res_mutex_unlock = pthread_mutex_unlock(&pscom.global_lock);
    assert(res_mutex_unlock == 0);
}


static inline void pscom_lock_yield(void)
{
    pscom_unlock();
    pscom_lock();
}


static inline void pscom_call_io_done(void)
{
    pscom_unlock();
    pscom_lock();
}


/**
 * @brief Establish a connection to a remote process.
 *
 * This routine establishes a connection to a remote process and blocks until
 * the connection has been established successfully or an error occurred.
 *
 * @param [in] con        The local connection to be used.
 *
 * @return PSCOM_SUCCESS or PSCOM_ERR_STDERROR otherwise (`errno` indicates
 *         the error type).
 */
pscom_err_t pscom_connect_direct(pscom_con_t *con);


/* connect to nodeid:port or accept a connection from a socket with the name
   (see pscom_socket_set_name()) */
#define PSCOM_HAS_ON_DEMAND_CONNECTIONS 1


/**
 * @brief Create an on-demand connection to a remote process.
 *
 * This routine creates an on-demand connection to a remote process. In contrast
 * to @ref pscom_connect_direct(), it does not block until this has been
 * established but rather sets up everything to connect upon the first write
 * attempt on that connection.
 *
 * @param [in] con        The local connection to be used.
 *
 * @return Always returns PSCOM_SUCCESS.
 */
pscom_err_t pscom_connect_ondemand(pscom_con_t *con);

static inline pscom_con_t *get_con(pscom_connection_t *con)
{
    return list_entry(con, pscom_con_t, pub);
}


static inline pscom_sock_t *get_sock(pscom_socket_t *socket)
{
    return list_entry(socket, pscom_sock_t, pub);
}

/**
 * @brief Get the arch sock object from pscom sock
 *
 * This function returns the architecture-specific socket object for a given
 * @ref con_type.
 *
 * @param [in] sock        pscom sock pointer
 * @param [in] con_type    connection type
 *
 * @return pscom_arch_sock_t* If an architecture-spcific socket object coult be
 *                            found
 * @return NULL               Otherwise
 */
static inline pscom_arch_sock_t *get_arch_sock(pscom_sock_t *sock,
                                               pscom_con_type_t con_type)
{
    struct list_head *pos;

    list_for_each (pos, &sock->archs) {
        pscom_arch_sock_t *arch_sock = list_entry(pos, pscom_arch_sock_t, next);

        if (arch_sock->plugin_con_type == con_type) { return arch_sock; }
    }

    return NULL;
}

void pscom_sock_set_name(pscom_sock_t *sock, const char *name);


static inline pscom_req_t *get_req(pscom_request_t *request)
{
    return list_entry(request, pscom_req_t, pub);
}


pscom_con_id_t pscom_con_to_id(pscom_con_t *con);
pscom_con_t *pscom_id_to_con(pscom_con_id_t id);


/* Get a buffer usable for receives. *buf is valid in the current
 * event dispatch only! Use pscom_read_get_buf_locked() if you need
 * persistent buffer space. */
void pscom_read_get_buf(pscom_con_t *con, char **buf, size_t *len);

void pscom_read_done(pscom_con_t *con, char *buf, size_t len);

pscom_req_t *pscom_read_pending(pscom_con_t *con, size_t len);

void pscom_read_pending_done(pscom_con_t *con, pscom_req_t *req);


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

/* Asynchronous write. len bytes consumed, but not save for reuse (pending io in
 * data) Call pscom_write_pending_done, if io has finished. */
void pscom_write_pending(pscom_con_t *con, pscom_req_t *req, size_t len);

/* Asynchronous write on req done. */
void pscom_write_pending_done(pscom_con_t *con, pscom_req_t *req);

/* Asynchronous write on req failed. */
void pscom_write_pending_error(pscom_con_t *con, pscom_req_t *req);


void pscom_con_error(pscom_con_t *con, pscom_op_t operation, pscom_err_t error);
void pscom_con_info(pscom_con_t *con, pscom_con_info_t *con_info);

void _pscom_con_suspend(pscom_con_t *con);
void _pscom_con_resume(pscom_con_t *con);
void _pscom_con_suspend_received(pscom_con_t *con, void *xheader,
                                 size_t xheaderlen);
pscom_err_t _pscom_con_connect_ondemand(pscom_con_t *con);

/*
void _pscom_send(pscom_con_t *con, unsigned msg_type,
                 void *xheader, unsigned xheader_len,
                 void *data, unsigned data_len);
*/

void _pscom_send_inplace(pscom_con_t *con, pscom_msgtype_t msg_type,
                         void *xheader, size_t xheader_len, void *data,
                         size_t data_len,
                         void (*io_done)(pscom_req_state_t state, void *priv),
                         void *priv);

static inline void pscom_poll_write_start(pscom_con_t *con,
                                          pscom_poll_func_t *do_poll)
{
    pscom_poll_start(&con->poll_write, do_poll, &pscom.poll_write);
}


void pscom_poll_write_stop(pscom_con_t *con);

static inline void pscom_poll_read_start(pscom_con_t *con,
                                         pscom_poll_func_t *do_poll)
{
    pscom_poll_start(&con->poll_read, do_poll, &pscom.poll_read);
}


void pscom_poll_read_stop(pscom_con_t *con);

int pscom_progress(int timeout);

int _pscom_con_type_mask_is_set(pscom_sock_t *sock, pscom_con_type_t con_type);
void _pscom_con_type_mask_del(pscom_sock_t *sock, pscom_con_type_t con_type);

void pscom_listener_init(struct pscom_listener *listener,
                         void (*can_read)(ufd_t *ufd, ufd_info_t *ufd_info),
                         void *priv);
void pscom_listener_set_fd(struct pscom_listener *listener, int fd);
int pscom_listener_get_fd(struct pscom_listener *listener);
/* active listening on fd */
void pscom_listener_active_inc(struct pscom_listener *listener);
void pscom_listener_active_dec(struct pscom_listener *listener);
/* close fd when sock is closed (tcp) */
void pscom_listener_close_fd(struct pscom_listener *listener);

static inline void _pscom_con_ref_hold(pscom_con_t *con)
{
    con->state.use_count++;
    assert(con->state.use_count);
}

void _pscom_con_ref_release(pscom_con_t *con);
void pscom_con_ref_release(pscom_con_t *con);

const char *pscom_con_str_reverse(pscom_connection_t *connection);

/* Translate name into an IPv4 address. Accept IPs in dotted notation or
 * hostnames. */
in_addr_t pscom_hostip(char *name);

void pscom_backtrace_dump(int sig);
void pscom_backtrace_onsigsegv_enable(void);
void pscom_backtrace_onsigsegv_disable(void);

void pscom_post_send_msgtype(pscom_request_t *request, pscom_msgtype_t msg_type);
void _pscom_post_send_msgtype(pscom_request_t *request,
                              pscom_msgtype_t msg_type);


/* number of RMA communication functions defined in MPI */
#define MAX_RMA_OP PSCOM_RMA_OP_COUNT

/* define the global callbacks for RMA communications via two-sided semantics */
typedef void (*rma_target_callback)(pscom_request_t *req);
typedef void (*rma_origin_callback)(pscom_request_t *req);

#ifndef ENABLE_PLUGIN_LOADING
#define ENABLE_PLUGIN_LOADING 1
#endif

#define API_EXPORT __attribute__((visibility("default")))
#define API_HIDDEN __attribute__((visibility("hidden")))

#if !defined(NO_PROTECTED_FUNC) || !NO_PROTECTED_FUNC
#define API_PROTECTED __attribute__((visibility("protected")))
#else
// The compiler does not support protected functions. Fallback to "default".
#define API_PROTECTED __attribute__((visibility("default")))
#endif

#ifndef PSCOM_ALLIN
#define PSCOM_API_EXPORT API_EXPORT
#else
#define PSCOM_API_EXPORT API_HIDDEN
#endif

#if ENABLE_PLUGIN_LOADING
#define PSCOM_PLUGIN_API_EXPORT API_PROTECTED
#else
#define PSCOM_PLUGIN_API_EXPORT API_HIDDEN
#endif

// Use PSCOM_PLUGIN_API_EXPORT_ONLY for all functions to which we use function
// pointers
#define PSCOM_PLUGIN_API_EXPORT_ONLY __attribute__((visibility("default")))
#define PSCOM_SHM_API_EXPORT         API_EXPORT

#define MAGIC_RKEYBUF                0x52425546
#define MAGIC_MEMH                   0x4D454D48
#define MAGIC_RKEY                   0x524B4559
#define PSCOM_INVALID_RKEYBUF_OFFSET (uint16_t) - 1

/**
 * @brief remote key buffer
 *
 * This remote key buffer is generated when registering memory region.
 * This buffer contains information about the memory region and the data
 * required to generate remote keys at the target side.
 * Since the memory region is registered with all active plugins, the data
 * to generate the remote key has to be stored in rkey_data for each of them
 * and the corresponding data offset must also be set in rkey_data_offset.
 * This buffer can be released after the local completion of sending this buffer
 * to the processes which have an access to the memory region.
 */
typedef struct {
    unsigned long magic;
    size_t remote_len;
    void *remote_addr; /**< used for internal rkey gen and remote check */
    void *remote_memh; /**< sent to remote */
    uint16_t rkeydata_length;
    uint16_t rkey_data_offset[PSCOM_CON_TYPE_COUNT]; /**< buffer size  returned
                                                          from plugin */
    char rkey_data[0]; /**< the buffer used for rkey gen in plugins */
} pscom_rkey_buffer_t;

/**
 * @brief plugin memory region handle
 *
 * This memory region handle contains the plugin_memh generated in plugin layer.
 * This handle will be added to the dynamic list in PSCOM_memh.
 */
typedef struct {
    struct list_head next;
    void *plugin_memh;            /**< plugin memory region handle */
    pscom_arch_sock_t *arch_sock; /**< architecture-dependent socket to which
                                       the arch_memh is bound to */
} pscom_arch_memh_t;

/**
 * @brief memory region handle for RMA operations
 *
 * This handle contains general information and a list for dynamic management of
 * the plugin memory handle.
 */
struct PSCOM_memh {
    unsigned long magic;
    void *addr;                      /**< address of allocated memory */
    size_t length;                   /**< size of allocated memory */
    pscom_sock_t *sock;              /**< associated socket */
    struct list_head arch_memh_list; /**< list of memory handles in different
                                          plugins */
    void *rkey_buffer; /**< pointer to remote key buffer, to be released during
                            de-registration */
    size_t rkey_buffer_length; /**< length of remote key buffer */
    rma_target_callback target_cbs[MAX_RMA_OP]; /**< callback when payload
                                                   arrives */
};

/**
 * @brief Remote memory key structure
 */
struct PSCOM_rkey {
    unsigned long magic;
    pscom_con_t *con;  /**< in which connection rkey is valid */
    void *plugin_rkey; /**< opaque handle in pscom layer and get the real remote
                            key in plugin layer */
    void *remote_addr; /**< address of the memory region at target */
    size_t remote_len; /**< length of memory region at target */
    void *remote_memh; /**< pointer of memory region at target */
};

#endif /* _PSCOM_PRIV_H_ */
