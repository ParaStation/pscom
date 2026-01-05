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
 * psdapl.c: DAPL communication
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <assert.h>

#include "pscom_util.h"
#include "pscom_env.h"
#include "pscom.h"
#include "psdapl.h"
#include "dat/udat.h"

/* Size of the send and receive queue */
#define SIZE_SR_QUEUE 16

#define MAX_PENDING_TOKS (SIZE_SR_QUEUE - 6)

#define EVD_MIN_QLEN SIZE_SR_QUEUE

/* Used buffersize */
#define DAPL_BUFSIZE                                                           \
    (16 * 1024) /* must be < 65536, or change sizeof                           \
                   psdapl_msgheader_t.payload */
#define DAPL_BUFSIZE_PAYLOAD (DAPL_BUFSIZE - sizeof(psdapl_msgheader_t))

#define PSDAPL_MAGIC_UNUSED 0
#define PSDAPL_MAGIC_IO     1


#define PSDAPL_LEN(len) ((len + 7) & ~7)
#define PSDAPL_DATA_OFFSET(pos, psdapllen)                                     \
    ((pos)*DAPL_BUFSIZE + DAPL_BUFSIZE_PAYLOAD - (psdapllen))

int psdapl_debug = 2;
char psdapl_provider[128];

FILE *psdapl_debug_stream = NULL;

static DAT_EVD_HANDLE async_evd_handle = DAT_HANDLE_NULL;


typedef struct psdapl_bufpair {
    char *lmr_mem;
    DAT_LMR_CONTEXT lmr_context;
    // DAT_VADDR	lmr_vaddr; == psdapl_mem2vaddr(lmr_mem);

    DAT_RMR_CONTEXT rmr_context;
    DAT_VADDR rmr_vaddr;

    DAT_LMR_HANDLE lmr_handle;
    DAT_RMR_CONTEXT lmr_rmr_context;
} psdapl_bufpair_t;


typedef struct psdapl_init_msg {
    struct {
        DAT_RMR_CONTEXT rmr_context;
        DAT_VADDR vaddr;
    } send;
    struct {
        DAT_RMR_CONTEXT rmr_context;
        DAT_VADDR vaddr;
    } recv;
} psdapl_init_msg_t;


struct psdapl_socket {
    DAT_IA_HANDLE ia_handle;
    DAT_SOCK_ADDR sock_addr;

    DAT_PZ_HANDLE pz_handle;

    DAT_PSP_HANDLE psp_handle;
    DAT_EVD_HANDLE evd_handle;

    DAT_CONN_QUAL listen_conn_qual;

    unsigned use_cnt; /* refcounter: count psdapl_con_info pointing to this */

#define PSDAPL_SOCKET_MAGIC 0x6861756b
    unsigned int magic;
};


struct psdapl_con_info {
    psdapl_socket_t *socket;
    psdapl_bufpair_t send_bufs;
    psdapl_bufpair_t recv_bufs;
    unsigned send_pos;
    unsigned recv_pos;

    DAT_EVD_HANDLE recv_evd_handle;
    DAT_EVD_HANDLE connect_evd_handle;
    DAT_EP_HANDLE ep_handle;

    unsigned outstanding_cq_entries;

    /* higher level */
    unsigned n_send_toks;
    uint16_t n_recv_toks;
    uint16_t n_tosend_toks;

    int con_broken;

#define PSDAPL_CON_INFO_MAGIC 0x6a656e73
    unsigned int magic;
};


typedef struct {
    uint16_t token;
    uint16_t payload;
    volatile uint32_t magic;
} psdapl_msgheader_t;


typedef struct {
    char __data[DAPL_BUFSIZE_PAYLOAD];
    psdapl_msgheader_t tail;
} psdapl_msg_t;

struct psdapl_stat_s {
    unsigned busy_notokens; // connection out of tokens for sending
    unsigned busy_local_cq; // connection sendqueue busy. (outstanding ev's)
    //	unsigned busy_global_cq;	// global completion queue busy.
    //	unsigned post_send_eagain;	// post_rdma_write() returned EAGAIN.
    unsigned post_send_error; // post_rdma_write() returned with an error.
    unsigned timeouts;        // dat_evd_dequeue() DAT_TIMEOUT_EXPIRED counter.
    unsigned busy_token_refresh; // sending tokens with nop message failed.
} psdapl_stat;


#define psdapl_dprint(level, fmt, arg...)                                      \
    do {                                                                       \
        if ((level) <= psdapl_debug) {                                         \
            fprintf(psdapl_debug_stream ? psdapl_debug_stream : stderr,        \
                    "dapl:" fmt "\n", ##arg);                                  \
        }                                                                      \
    } while (0);


#define psdapl_dprint_dat_err(level, dat_err, fmt, arg...)                     \
    do {                                                                       \
        if ((level) <= psdapl_debug) {                                         \
            const char *major_message = "?";                                   \
            const char *minor_message = "?";                                   \
            DAT_RETURN __res          = dat_strerror(dat_err, &major_message,  \
                                                     &minor_message);          \
            assert(__res == DAT_SUCCESS);                                      \
                                                                               \
            psdapl_dprint(level, fmt " : %s : %s", ##arg, major_message,       \
                          minor_message);                                      \
        }                                                                      \
    } while (0);


#define psdapl_dprint_errno(level, _errno, fmt, arg...)                        \
    do {                                                                       \
        if ((level) <= psdapl_debug) {                                         \
            psdapl_dprint(level, fmt " : %s", ##arg, strerror(_errno));        \
        }                                                                      \
    } while (0);


static void psdapl_bufpair_destroy(psdapl_bufpair_t *bufp)
{
    if (bufp->lmr_handle) {
        dat_lmr_free(bufp->lmr_handle);
        bufp->lmr_handle = 0;
    }

    free(bufp->lmr_mem);
    bufp->lmr_mem = NULL;
}


/* return -1 on error. on error debug messages printed on stderr */
static int psdapl_bufpair_init_local(psdapl_bufpair_t *bufp, size_t size,
                                     DAT_IA_HANDLE ia_handle,
                                     DAT_PZ_HANDLE pz_handle)
{
    DAT_RETURN res;

    bufp->lmr_mem = valloc(size);
    if (!bufp->lmr_mem) { goto err_malloc; }

    memset(bufp->lmr_mem, 0xee, size); /* touch the mem */

    DAT_REGION_DESCRIPTION region;
    region.for_va = bufp->lmr_mem;

    DAT_VLEN registered_size     = 0;
    DAT_VADDR registered_address = 0;

    res = dat_lmr_create(ia_handle, DAT_MEM_TYPE_VIRTUAL, region, size,
                         pz_handle, DAT_MEM_PRIV_ALL_FLAG, &bufp->lmr_handle,
                         &bufp->lmr_context, &bufp->lmr_rmr_context,
                         &registered_size, &registered_address);

    if (res != DAT_SUCCESS) { goto err_lmr_create; }

    return 0;
err_malloc:
    psdapl_dprint_errno(1, errno, "calloc(%lu, 1) failed", (long)size);
    return -1;
err_lmr_create:
    psdapl_dprint_dat_err(1, res, "dat_lmr_create() failed");
    return -1;
}


static void psdapl_bufpair_init_remote(psdapl_bufpair_t *bufp,
                                       DAT_RMR_CONTEXT rmr_context,
                                       DAT_VADDR rmr_vaddr)
{
    bufp->rmr_context = rmr_context;
    bufp->rmr_vaddr   = rmr_vaddr;
}


#include "psdapl_rdma.c"


/* return -1 on error. dprint on stderr */
static int psdapl_ia_open_name(DAT_IA_HANDLE *ia_handlep,
                               /*const*/ char *ia_name)
{
    DAT_RETURN dat_rc;
    DAT_IA_HANDLE ia_handle;

    dat_rc = dat_ia_open(ia_name, EVD_MIN_QLEN, &async_evd_handle, &ia_handle);
    if (dat_rc != DAT_SUCCESS) { goto err_dat_ia_open; }

    *ia_handlep = ia_handle;

    psdapl_dprint(3, "dat_ia_open(\"%s\", ...) success", ia_name);
    return 0;
err_dat_ia_open:
    psdapl_dprint_dat_err(1, dat_rc, "dat_ia_open(\"%s\", ...) failed", ia_name);
    return -1;
}


static int psdapl_ia_open(DAT_IA_HANDLE *ia_handlep)
{
    snprintf(psdapl_provider, sizeof(psdapl_provider) - 1, "<query>");
    DAT_RETURN dat_rc;
    int ret;

    if (strcmp(psdapl_provider, "<query>")) {
        ret = psdapl_ia_open_name(ia_handlep, psdapl_provider);
    } else {
        const unsigned max_providers = 64;
        DAT_PROVIDER_INFO _providers[max_providers];
        DAT_PROVIDER_INFO *providers[max_providers];
        DAT_COUNT i, n;
        unsigned j;

        /* Who wrote this stupid stupid DAT API? */
        for (j = 0; j < max_providers; j++) { providers[j] = _providers + j; }
        /* query the names from dat.conf: */
        dat_rc = dat_registry_list_providers(max_providers, &n, providers);

        if (dat_rc != DAT_SUCCESS) { goto err_list_providers; }
        if (n == 0) { goto err_no_result; }

        ret = -1;
        for (i = 0; i < n; i++) {
            ret = psdapl_ia_open_name(ia_handlep, providers[i]->ia_name);
            if (!ret) { break; /* found working provider */ }
        }
    }

    return ret;
err_list_providers:
    psdapl_dprint_dat_err(1, dat_rc,
                          "dat_registry_list_providers() failed. Use env "
                          "%s={provider}",
                          ENV_DAPL_PROVIDER);
    return -1;
err_no_result:
    psdapl_dprint(1, "dat_registry_list_providers() without results. Use "
                     "env " ENV_DAPL_PROVIDER "={provider}");
    return -1;
}


static void psdapl_ia_close(DAT_IA_HANDLE ia_handle)
{
    dat_ia_close(ia_handle, DAT_CLOSE_DEFAULT);
}


/* Initialize addr with ia address of ia_handle.
   on error: memset(addr,0) and return -1. */
static int psdapl_get_sock_addr(DAT_SOCK_ADDR *addr, DAT_IA_HANDLE ia_handle)
{
    DAT_IA_ATTR ia_attr;
    DAT_RETURN dat_rc;

    dat_rc = dat_ia_query(ia_handle, &async_evd_handle,
                          DAT_IA_FIELD_IA_ADDRESS_PTR, &ia_attr, 0, NULL);
    if (dat_rc != DAT_SUCCESS) { goto err_dat_ia_query; }

    memcpy(addr, ia_attr.ia_address_ptr, sizeof(*addr));

    return 0;
err_dat_ia_query:
    psdapl_dprint_dat_err(1, dat_rc,
                          "dat_ia_query(DAT_IA_FIELD_IA_ADDRESS_PTR) failed");
    memset(addr, 0, sizeof(*addr));
    return -1;
}


static void psdapl_pz_destroy(DAT_PZ_HANDLE pz_handle)
{
    dat_pz_free(pz_handle);
}


/* return -1 on error */
static int psdapl_pz_create(DAT_PZ_HANDLE *pz_handle, DAT_IA_HANDLE ia_handle)
{
    DAT_RETURN dat_rc;
    dat_rc = dat_pz_create(ia_handle, pz_handle);
    if (dat_rc != DAT_SUCCESS) { goto err_pz_create; }

    return 0;
err_pz_create:
    psdapl_dprint_dat_err(1, dat_rc, "dat_pz_create() failed");
    return -1;
}


const char *psdapl_addr2str(const psdapl_info_msg_t *msg /* in */)
{
    const DAT_SOCK_ADDR *addr     = &msg->sock_addr;
    const DAT_CONN_QUAL conn_qual = msg->conn_qual;
    static char buf[sizeof("ffffff_000:001:002:003:004:005:006:007:008:009:010:"
                           "011:012:013_12345678910_save_")];
    snprintf(buf, sizeof(buf),
             "%u_%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u_%lu",
             addr->sa_family, (unsigned char)addr->sa_data[0],
             (unsigned char)addr->sa_data[1], (unsigned char)addr->sa_data[2],
             (unsigned char)addr->sa_data[3], (unsigned char)addr->sa_data[4],
             (unsigned char)addr->sa_data[5], (unsigned char)addr->sa_data[6],
             (unsigned char)addr->sa_data[7], (unsigned char)addr->sa_data[8],
             (unsigned char)addr->sa_data[9], (unsigned char)addr->sa_data[10],
             (unsigned char)addr->sa_data[11], (unsigned char)addr->sa_data[12],
             (unsigned char)addr->sa_data[13], (unsigned long)conn_qual);
    return buf;
}


/* return -1 on parse error */
int psdapl_str2addr(psdapl_info_msg_t *msg, const char *str)
{
    DAT_SOCK_ADDR *addr = &msg->sock_addr;

    if (!addr || !str) { return -1; }
    unsigned data[14];
    unsigned long cq;
    unsigned short fam;
    int rc;
    int i;
    rc = sscanf(str, "%hu_%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u_%lu", &fam,
                &data[0], &data[1], &data[2], &data[3], &data[4], &data[5],
                &data[6], &data[7], &data[8], &data[9], &data[10], &data[11],
                &data[12], &data[13], &cq);

    addr->sa_family = fam;
    for (i = 0; i < 14; i++) { addr->sa_data[i] = (char)data[i]; }
    msg->conn_qual = cq;
    return rc == 16 ? 0 : -1;
}


DAT_CONN_QUAL psdapl_socket_get_conn_qual(psdapl_socket_t *socket)
{
    return socket->listen_conn_qual;
}


static void psdapl_socket_destroy(psdapl_socket_t *socket)
{
    assert(socket->magic == PSDAPL_SOCKET_MAGIC);

    psdapl_pz_destroy(socket->pz_handle);
    socket->pz_handle = 0;

    dat_ia_close(socket->ia_handle, DAT_CLOSE_DEFAULT);
    socket->ia_handle = 0;

    psdapl_mregion_cache_clear();

    socket->magic = 0;
    free(socket);
}


/* return NULL on error.
 * Will be automaticaly freed by last psdapl_con_destroy()
 * (socket->use_cnt == 0).
 */
psdapl_socket_t *psdapl_socket_create(void)
{
    psdapl_mregion_cache_init();
    psdapl_page_size_init();

    /* reset all counters */
    memset(&psdapl_stat, 0, sizeof(psdapl_stat));

    psdapl_socket_t *socket = calloc(sizeof(*socket), 1);
    if (!socket) { return NULL; }

    socket->magic = PSDAPL_SOCKET_MAGIC;

    int rc;

    /* ToDo: Use some environment variable */
    rc = psdapl_ia_open(&socket->ia_handle);
    if (rc) { goto err_ia_open; }

    rc = psdapl_get_sock_addr(&socket->sock_addr, socket->ia_handle);
    if (rc) { goto err_get_sock; }

    rc = psdapl_pz_create(&socket->pz_handle, socket->ia_handle);
    if (rc) { goto err_pz_create; }

    socket->use_cnt = 0;

    return socket;
err_pz_create:
err_get_sock:
    psdapl_ia_close(socket->ia_handle);
err_ia_open:
    free(socket);
    return NULL;
}


void psdapl_socket_put(psdapl_socket_t *socket)
{
    assert(socket->magic == PSDAPL_SOCKET_MAGIC);

    socket->use_cnt--;
    if (!socket->use_cnt) { psdapl_socket_destroy(socket); }
}


void psdapl_socket_hold(psdapl_socket_t *socket)
{
    assert(socket->magic == PSDAPL_SOCKET_MAGIC);
    socket->use_cnt++;
}


/* create a PSP to listen on a port.
 * return: DAT_CONN_QUAL (the port) in socket->listen_conn_qual and
 * the address in DAT_SOCK_ADDR socket->sock_addr (already set by
 * psdapl_socket_create()
 *
 * return -1 on error. */
int psdapl_listen(psdapl_socket_t *socket)
{
    DAT_RETURN dat_rc;

    if (socket->psp_handle) { return 0; /* already listening */ }

    dat_rc = dat_evd_create(socket->ia_handle,
                            EVD_MIN_QLEN /* ToDo: evd_min_qlen */,
                            DAT_HANDLE_NULL, // cno_handle
                            DAT_EVD_CR_FLAG, // DAT_EVD_DEFAULT_FLAG,
                            &socket->evd_handle);
    if (dat_rc != DAT_SUCCESS) { goto err_evd_create; }

    DAT_CONN_QUAL conn_qual = getpid();
    int maxcnt              = 100;
    while (1) {
        dat_rc =
            dat_psp_create(socket->ia_handle, conn_qual, socket->evd_handle,
                           DAT_PSP_CONSUMER_FLAG /* DAT_PSP_PROVIDER_FLAG */,
                           &socket->psp_handle);

        if (dat_rc == DAT_SUCCESS) { break; }
        maxcnt--;
        if (!maxcnt || (DAT_GET_TYPE(dat_rc) != DAT_CONN_QUAL_IN_USE)) {
            goto err_psp_create;
        }

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


static void psdapl_init_init_msg(psdapl_init_msg_t *imsg, psdapl_con_info_t *ci)
{
    imsg->send.rmr_context = ci->recv_bufs.lmr_rmr_context;
    imsg->send.vaddr       = psdapl_mem2vaddr(ci->recv_bufs.lmr_mem);

    imsg->recv.rmr_context = ci->send_bufs.lmr_rmr_context;
    imsg->recv.vaddr       = psdapl_mem2vaddr(ci->send_bufs.lmr_mem);
}


static int psdapl_wait4event(psdapl_con_info_t *ci, unsigned event,
                             const char *ev_name);


static void psdapl_destroy_ep(psdapl_con_info_t *ci)
{
    if (ci->ep_handle) {
        dat_ep_disconnect(ci->ep_handle, DAT_CLOSE_ABRUPT_FLAG);

        if (!psdapl_wait4event(ci, DAT_CONNECTION_EVENT_DISCONNECTED,
                               "DAT_CONNECTION_EVENT_DISCONNECTED")) {
            /* Got the DAT_CONNECTION_EVENT_DISCONNECTED event */
            dat_ep_free(ci->ep_handle);
            ci->ep_handle = 0;
        } else {
            /* ToDo: What to do here? */
        }
    }

    if (ci->recv_evd_handle) {
        dat_evd_free(ci->recv_evd_handle);
        ci->recv_evd_handle = 0;
    }

    if (ci->connect_evd_handle) {
        dat_evd_free(ci->connect_evd_handle);
        ci->connect_evd_handle = 0;
    }
}


static int psdapl_create_ep(psdapl_con_info_t *ci)
{
    DAT_RETURN dat_rc;

    dat_rc = dat_evd_create(ci->socket->ia_handle, EVD_MIN_QLEN,
                            DAT_HANDLE_NULL,  // cno_handle
                            DAT_EVD_DTO_FLAG, // DAT_EVD_DEFAULT_FLAG,
                            &ci->recv_evd_handle);
    if (dat_rc != DAT_SUCCESS) { goto err_recv_evd_create; }

    dat_rc = dat_evd_create(ci->socket->ia_handle, EVD_MIN_QLEN,
                            DAT_HANDLE_NULL, // cno_handle
                            DAT_EVD_CR_FLAG | DAT_EVD_CONNECTION_FLAG,
                            &ci->connect_evd_handle);
    if (dat_rc != DAT_SUCCESS) { goto err_connect_evd_create; }

    dat_rc = dat_ep_create(ci->socket->ia_handle, ci->socket->pz_handle,
                           ci->recv_evd_handle, ci->recv_evd_handle,
                           ci->connect_evd_handle,
                           NULL /* DAT_EP_ATTR *ep_attributes */,
                           &ci->ep_handle);

    if (dat_rc != DAT_SUCCESS) { goto err_ep_create; }

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


static void print_mlock_help(void)
{
    static int called = 0;
    struct rlimit rlim;

    if (called) { return; }
    called = 1;

    psdapl_dprint(0, "(Please check memlock limit in /etc/security/limits.conf "
                     "or try 'ulimit -l')");

    if (!getrlimit(RLIMIT_MEMLOCK, &rlim)) {
        psdapl_dprint(0, "Current RLIMIT_MEMLOCK: soft=%lu byte, hard=%lu byte",
                      rlim.rlim_cur, rlim.rlim_max);
    }
}


static void psdapl_destroy_buffers(psdapl_con_info_t *ci)
{
    psdapl_bufpair_destroy(&ci->recv_bufs);
    psdapl_bufpair_destroy(&ci->send_bufs);
}


static int psdapl_init_buffers_local(psdapl_con_info_t *ci)
{
    int rc;
    int i;

    rc = psdapl_bufpair_init_local(&ci->send_bufs, SIZE_SR_QUEUE * DAPL_BUFSIZE,
                                   ci->socket->ia_handle,
                                   ci->socket->pz_handle);
    if (rc) { goto err_init_send; }

    rc = psdapl_bufpair_init_local(&ci->recv_bufs, SIZE_SR_QUEUE * DAPL_BUFSIZE,
                                   ci->socket->ia_handle,
                                   ci->socket->pz_handle);
    if (rc) { goto err_init_recv; }

    ci->send_pos = 0;
    ci->recv_pos = 0;

    /* Clear all receive magics */
    for (i = 0; i < SIZE_SR_QUEUE; i++) {
        psdapl_msg_t *msg = ((psdapl_msg_t *)ci->recv_bufs.lmr_mem) + i;
        msg->tail.magic   = PSDAPL_MAGIC_UNUSED;
    }

    return rc;
err_init_recv:
err_init_send:
    print_mlock_help();
    return rc;
}


static void psdapl_init_buffers_remote(psdapl_con_info_t *ci,
                                       psdapl_init_msg_t *imsg)
{
    psdapl_bufpair_init_remote(&ci->send_bufs, imsg->send.rmr_context,
                               imsg->send.vaddr);
    psdapl_bufpair_init_remote(&ci->recv_bufs, imsg->recv.rmr_context,
                               imsg->recv.vaddr);
}


static int _psdapl_get_con_accept(psdapl_con_info_t *ci,
                                  DAT_CR_HANDLE cr_handle,
                                  psdapl_init_msg_t *imsg)
{
    DAT_RETURN dat_rc;
    int rc;

    rc = psdapl_init_buffers_local(ci);
    if (rc) { goto err_init_buf; }

    psdapl_init_buffers_remote(ci, imsg);

    rc = psdapl_create_ep(ci);
    if (rc) { goto err_create_ep; }

    psdapl_init_msg_t res_imsg;
    psdapl_init_init_msg(&res_imsg, ci);

    /* accept connect request. Send info message about my buffers: */
    dat_rc = dat_cr_accept(cr_handle,
                           ci->ep_handle, //   DAT_HANDLE_NULL /* ep_handle */,
                           sizeof(res_imsg) /* private_data_size */,
                           &res_imsg /* private_data*/);
    if (dat_rc != DAT_SUCCESS) { goto err_cr_accept; }


    rc = psdapl_wait4event(ci, DAT_CONNECTION_EVENT_ESTABLISHED,
                           "DAT_CONNECTION_EVENT_ESTABLISHED");
    if (rc) { goto err_con_established; }

    return 0;
    /*---*/
err_cr_accept:
    psdapl_dprint_dat_err(0, dat_rc, "CR: dat_cr_accept() failed");
err_con_established:
    /* ToDo: Cleanup ci->ep_handle!! */
err_create_ep:
err_init_buf:
    /* ToDo: Cleanup recv_evd_handle!! */
    /* ToDo: Cleanup connect_evd_handle!! */
    /* ToDo: Cleanup bufpairs!!!!! */
    return -1;
}


/* Wait for a new connection on the PSP (psdapl_listen()).
 *
 * return -1 on error */
int psdapl_accept_wait(psdapl_con_info_t *ci)
{
    DAT_EVENT event;
    DAT_COUNT nmore;
    DAT_RETURN dat_rc;
    dat_rc = dat_evd_wait(ci->socket->evd_handle,
                          DAT_TIMEOUT_INFINITE /* 5*1000*1000 timeout in usec*/,
                          1 /* threshold */, &event, &nmore);

    switch (DAT_GET_TYPE(dat_rc)) {
        /*
                case DAT_TIMEOUT_EXPIRED:
                        fprintf(stderr, "<mark (timeout)>\n");
                        break;
        */
    case DAT_SUCCESS:
        switch (event.event_number) {
        case DAT_CONNECTION_EVENT_TIMED_OUT:
            psdapl_dprint(2, "psdapl_accept_wait: event "
                             "DAT_CONNECTION_EVENT_TIMED_OUT");
            break;
        case DAT_CONNECTION_REQUEST_EVENT:
            psdapl_dprint(3, "psdapl_accept_wait: event "
                             "DAT_CONNECTION_REQUEST_EVENT");

            DAT_CR_ARRIVAL_EVENT_DATA *cr =
                &event.event_data.cr_arrival_event_data;
            DAT_CR_PARAM cr_param;

            dat_rc = dat_cr_query(cr->cr_handle, DAT_CR_FIELD_ALL, &cr_param);
            assert(dat_rc == DAT_SUCCESS);

            psdapl_init_msg_t *imsg =
                (psdapl_init_msg_t *)(cr_param.private_data);

            return _psdapl_get_con_accept(ci, cr->cr_handle, imsg);
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

    return -1;
}


/* Wait for a disconnected event.
 *
 * return -1 on error */
static int psdapl_wait4event(psdapl_con_info_t *ci, unsigned ev,
                             const char *ev_name)
{
    DAT_EVENT event;
    DAT_COUNT nmore;
    DAT_RETURN dat_rc;
    dat_rc = dat_evd_wait(ci->connect_evd_handle,
                          3 * 1000 * 1000 /* timeout in usec */,
                          1 /* threshold */, &event, &nmore);

    switch (DAT_GET_TYPE(dat_rc)) {
    case DAT_TIMEOUT_EXPIRED:
        psdapl_dprint(2, "psdapl_wait4event(%s): DAT_TIMEOUT_EXPIRED", ev_name);
        return -1;
        break;
    case DAT_SUCCESS:
        if (event.event_number == ev) {
            psdapl_dprint(3, "event %s", ev_name);
            return 0;
        } else {
            psdapl_dprint(2, "psdapl_wait4event(%s): unexpected event 0x%x",
                          ev_name, (unsigned)event.event_number);
        }
        break;
    default:
        psdapl_dprint_dat_err(2, dat_rc,
                              "psdapl_wait4event(%s): dat_evd_wait()", ev_name);
    }
    return -1;
}


/* Connect a remote PSP at addr : conn_qual
 * return -1 on error */
int psdapl_connect(psdapl_con_info_t *ci, psdapl_info_msg_t *msg)
{
    int rc;
    DAT_RETURN dat_rc;

    rc = psdapl_init_buffers_local(ci);
    if (rc) { goto err_init_buf; }

    rc = psdapl_create_ep(ci);
    if (rc) { goto err_create_ep; }

    psdapl_init_msg_t res_imsg;
    psdapl_init_init_msg(&res_imsg, ci);

    dat_rc = dat_ep_connect(ci->ep_handle, &msg->sock_addr, msg->conn_qual,
                            DAT_TIMEOUT_INFINITE /* 5 * 1000 * 1000 */,

                            sizeof(res_imsg) /* private_data_size */,
                            &res_imsg /* private_data */,
                            DAT_QOS_BEST_EFFORT /* DAT_QOS */,
                            DAT_CONNECT_DEFAULT_FLAG /* DAT_CONNECT_FLAGS */);
    if (dat_rc != DAT_SUCCESS) { goto err_ep_connect; }

    DAT_EVENT event;
    DAT_COUNT nmore;

    event.event_number = -1;
    dat_rc             = dat_evd_wait(ci->connect_evd_handle,
                                      DAT_TIMEOUT_INFINITE /* 5*1000*1000 timeout in usec*/,
                                      1 /* threshold */, &event, &nmore);


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
            psdapl_dprint(2, "psdapl_connect: event "
                             "DAT_CONNECTION_EVENT_TIMED_OUT");
            break;
        case DAT_CONNECTION_EVENT_ESTABLISHED:
            psdapl_dprint(3, "psdapl_connect: event "
                             "DAT_CONNECTION_EVENT_ESTABLISHED");

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


    if (!imsg) { goto err_wait; }

    psdapl_init_buffers_remote(ci, imsg);

    return 0;
    /* --- */
err_ep_connect:
    psdapl_dprint_dat_err(0, dat_rc, "dat_ep_connect() failed");
    goto err_all;
    /* --- */
err_all:
err_wait:
err_create_ep:
err_init_buf:
    /* ToDo: Cleanup recv_evd_handle!! */
    /* ToDo: Cleanup connect_evd_handle!! */
    /* ToDo: Cleanup bufpairs!!!!! */
    return -1;
}


/* return -1 on error */
static int psdapl_flush_sendbuf(psdapl_con_info_t *ci,
                                char *lmem /* ci->send_bufs.lmr_mem */,
                                off_t roffset, size_t size)
{
    DAT_RETURN dat_rc;
    DAT_LMR_TRIPLET lmr;
    DAT_RMR_TRIPLET rmr;

    lmr.lmr_context     = ci->send_bufs.lmr_context;
    lmr.pad             = 0;
    lmr.virtual_address = psdapl_mem2vaddr(lmem);
    lmr.segment_length  = size;

    rmr.rmr_context    = ci->send_bufs.rmr_context;
    rmr.pad            = 0;
    rmr.target_address = ci->send_bufs.rmr_vaddr + roffset;
    rmr.segment_length = size;

    DAT_DTO_COOKIE cookie;
    cookie.as_64 = 0;

    dat_rc = dat_ep_post_rdma_write(ci->ep_handle, 1, &lmr, cookie, &rmr,
                                    0 /* DAT_COMPLETION_SUPPRESS_FLAG*/);
    if (dat_rc != DAT_SUCCESS) { goto err_rdma_write; }

    return 0;
err_rdma_write:
    psdapl_dprint_dat_err(0, dat_rc, "dat_ep_post_rdma_write() failed");
    return -1;
}

/* read all events from recv_evd_handle */
static void psdapl_flush_evd(psdapl_con_info_t *ci)
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
        nmore  = 1;
#endif

        switch (DAT_GET_TYPE(dat_rc)) {
        case DAT_TIMEOUT_EXPIRED:
            // psdapl_dprint(3, "psdapl_flush_evd event DAT_TIMEOUT_EXPIRED.
            // nmore:%d", nmore);
            ci->outstanding_cq_entries = 0;
            psdapl_stat.timeouts++;
            break;
        case DAT_SUCCESS:
            switch (event.event_number) {
            case DAT_DTO_COMPLETION_EVENT:
                if (!event.event_data.dto_completion_event_data.user_cookie
                         .as_ptr) {
                    // From sendv
                    if (ci->outstanding_cq_entries) {
                        ci->outstanding_cq_entries--;
                    }
                } else {
                    do_DTO_COMPLETION_EVENT(
                        ci, &event.event_data.dto_completion_event_data);
                }
                // psdapl_dprint(3, "psdapl_flush_evd event
                // DAT_DTO_COMPLETION_EVENT. nmore:%d", nmore);
                break;
            default:
                psdapl_dprint(1,
                              "psdapl_flush_evd: unexpected event 0x%x. "
                              "nmore:%d",
                              (unsigned)event.event_number, nmore);
                break;
            }
            break;
        case DAT_QUEUE_EMPTY: nmore = 0; break;
        default:
            nmore = 0;
            psdapl_dprint_dat_err(1, dat_rc,
                                  "psdapl_flush_evd: dat_evd_wait(). nmore:%d",
                                  nmore);
        }

        if (!nmore) { break; }
    }
}


void psdapl_con_destroy(psdapl_con_info_t *ci)
{
    assert(ci->magic == PSDAPL_CON_INFO_MAGIC);
    psdapl_socket_t *socket = ci->socket;

    if (!ci->con_broken) { psdapl_flush_evd(ci); }

    psdapl_destroy_ep(ci);

    ci->con_broken = 1;

    psdapl_destroy_buffers(ci);

    ci->magic = 0;
    free(ci);

    psdapl_socket_put(socket);
}


/* Create a con_info usable for psdapl_accept_wait() or
 * psdapl_connect().
 * return NULL on error */
psdapl_con_info_t *psdapl_con_create(psdapl_socket_t *socket)
{
    if (!socket) { return NULL; }
    psdapl_con_info_t *ci = calloc(sizeof(*ci), 1);
    if (!ci) { return NULL; }
    ci->magic  = PSDAPL_CON_INFO_MAGIC;
    ci->socket = socket;

    ci->outstanding_cq_entries = 0;

    ci->n_send_toks   = SIZE_SR_QUEUE;
    ci->n_recv_toks   = 0;
    ci->n_tosend_toks = 0;

    ci->con_broken = 0;

    psdapl_socket_hold(socket);
    return ci;
}


static void psdapl_get_fresh_tokens(psdapl_con_info_t *ci);


/* returnvalue like write(), except on error errno is negative return */
static ssize_t _psdapl_sendv(psdapl_con_info_t *ci, struct iovec *iov,
                             size_t size, unsigned int magic)
{
    size_t len;
    size_t psdapllen;
    psdapl_msg_t *msg;
    int rc;
    psdapl_msgheader_t *tail;

    if (ci->con_broken) { goto err_broken; }

    /* Its allowed to send, if
       At least 2 tokens left or (1 token left AND n_tosend > 0)
    */

    if ((ci->n_send_toks < 2) &&
        ((ci->n_send_toks < 1) || (ci->n_tosend_toks == 0))) {
        psdapl_stat.busy_notokens++;
        goto err_busy;
    }

    if (ci->outstanding_cq_entries >= EVD_MIN_QLEN) {
        psdapl_stat.busy_local_cq++;
        goto err_busy;
    }
    /*
            if (psdapl_outstanding_cq_entries >= ???) {
                    psdapl_stat.busy_global_cq++;
                    goto err_busy;
            }
    */
    len       = (size <= DAPL_BUFSIZE_PAYLOAD) ? size : DAPL_BUFSIZE_PAYLOAD;
    psdapllen = PSDAPL_LEN(len);

    msg = ((psdapl_msg_t *)ci->send_bufs.lmr_mem) + ci->send_pos;

    tail = (psdapl_msgheader_t *)((char *)msg + psdapllen);

    tail->token   = ci->n_tosend_toks;
    tail->payload = (uint16_t)len;
    tail->magic   = magic;

    /* copy to registerd send buffer */
    pscom_memcpy_from_iov((void *)msg, iov, len);

    rc = psdapl_flush_sendbuf(ci, (char *)msg,
                              PSDAPL_DATA_OFFSET(ci->send_pos, psdapllen),
                              psdapllen + sizeof(psdapl_msgheader_t));

    if (rc != 0) { goto err_send; }

    ci->outstanding_cq_entries++;

    pscom_forward_iov(iov, len);

    ci->n_tosend_toks = 0;
    ci->send_pos      = (ci->send_pos + 1) % SIZE_SR_QUEUE;
    ci->n_send_toks--;

    psdapl_flush_evd(ci);

    return len;
err_busy:
    psdapl_get_fresh_tokens(ci);
    psdapl_flush_evd(ci);

    return -EAGAIN;
err_send:
    psdapl_stat.post_send_error++;
    /* ToDo: Check for EAGAIN ? */
    ci->con_broken = 1;
    return -EPIPE;
err_broken:
    return -EPIPE;
}


ssize_t psdapl_sendv(psdapl_con_info_t *ci, struct iovec *iov, size_t size)
{
    return _psdapl_sendv(ci, iov, size, PSDAPL_MAGIC_IO);
}


static inline void _psdapl_send_tokens(psdapl_con_info_t *ci)
{
    if (ci->n_tosend_toks >= MAX_PENDING_TOKS) {
        if (psdapl_sendv(ci, NULL, 0) == -EAGAIN) {
            psdapl_stat.busy_token_refresh++;
        }
    }
}


void psdapl_recvdone(psdapl_con_info_t *ci)
{
    ci->n_tosend_toks++;
    ci->n_recv_toks--;
    ci->recv_pos = (ci->recv_pos + 1) % SIZE_SR_QUEUE;

    // if send_tokens() fail, we will retry it in psdapl_recvlook.
    _psdapl_send_tokens(ci);
}


/* returnvalue like read() , except on error errno is negative return */
int psdapl_recvlook(psdapl_con_info_t *ci, void **buf)
{
    // assert(con_info->n_recv_toks == 0) as long as we only poll!
    while (1) {
        psdapl_msg_t *msg = ((psdapl_msg_t *)ci->recv_bufs.lmr_mem) +
                            ci->recv_pos;

        unsigned int magic = msg->tail.magic;
        if (!magic) { // Nothing received
            psdapl_flush_evd(ci);
            // Maybe we have to send tokens before we can receive more:
            _psdapl_send_tokens(ci);
            return (ci->con_broken) ? -EPIPE : -EAGAIN;
        }

        msg->tail.magic = PSDAPL_MAGIC_UNUSED;

        /* Fresh tokens ? */
        ci->n_send_toks += msg->tail.token;
        ci->n_recv_toks++;

        unsigned len       = msg->tail.payload;
        unsigned psdapllen = PSDAPL_LEN(len);

        *buf = ci->recv_bufs.lmr_mem +
               PSDAPL_DATA_OFFSET(ci->recv_pos, psdapllen);
        if (len) {
            // receive data
            return len;
        }

        /* skip 0 payload packages (probably fresh tokens) */
        psdapl_recvdone(ci);
    }
}


static void psdapl_get_fresh_tokens(psdapl_con_info_t *ci)
{
    psdapl_msg_t *msg  = ((psdapl_msg_t *)ci->recv_bufs.lmr_mem) + ci->recv_pos;
    unsigned int magic = msg->tail.magic;

    if ((magic == PSDAPL_MAGIC_IO) && (msg->tail.payload == 0)) {
        // Fresh tokens
        msg->tail.magic = PSDAPL_MAGIC_UNUSED;
        ci->n_send_toks += msg->tail.token;
        ci->n_recv_toks++;

        psdapl_recvdone(ci);
    }
}


void psdapl_con_get_info_msg(psdapl_con_info_t *ci /* in */,
                             psdapl_info_msg_t *msg /* out */)
{
    memcpy(&msg->sock_addr, &ci->socket->sock_addr, sizeof(msg->sock_addr));
    msg->conn_qual = ci->socket->listen_conn_qual;
}
