/*
 * ParaStation
 *
 * Copyright (C) 2016-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "pspsm.h"
#include "pscom_util.h"
#include "pscom_debug.h"
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef PSM1
#include "psm2.h"
#include "psm2_mq.h"
#else
#include "psm1_compat.h"
#endif

// #define PSPSM_TRACE
#define PSPSM_SKIP_EP_CLOSE 1

struct pspsm_con_info {
    /* general info */
    psm2_epaddr_t epaddr;    /**< destination address of peer */
    uint64_t send_id;        /**< tag used when sending to peer */
    uint64_t recv_id;        /**< tag used when receiving from peer*/
    unsigned con_broken : 1; /**< set to 1 if connection broken */
    unsigned connected : 1;  /**< set to 1 if connected */

    /* sending */
    struct PSCOM_req *sreq;      /**< pscom open send request */
    size_t sreq_len;             /**< size of open send request */
    unsigned sreqs_active_count; /**< # Active MQ send requests */
    unsigned small_msg_len;      // Remote pspsm_small_msg_len

    /* receiving */
    char *rbuf;         /**< buffer used for current receive */
    psm2_mq_req_t rreq; /**< MQ recv request */

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
static const uint64_t mask           = (UINTMAX_C(1) << 48) - 1;

#define PSPSM_CON_MAGIC          0xdeadbeefcafebabe
#define PSM_CONTEXT_TYPE_MASK    7
#define PSM_CONTEXT_TYPE_SENDREQ 0
#define PSM_CONTEXT_TYPE_RECVREQ 1


int pspsm_debug              = 2;
FILE *pspsm_debug_stream     = NULL;
unsigned pspsm_devcheck      = 1;
unsigned pspsm_small_msg_len = 350; // will be overwritten by
                                    // pscom.env.readahead (PSP_READAHEAD)

/*
 * For now, psm allows only one endpoint per process, so we can safely
 * use a global variable.
 */
static char *pspsm_err_str  = NULL; /* last error string */
static char *sendbuf        = NULL;
static unsigned sendbuf_len = 0;
static pspsm_uuid_t pspsm_uuid;
static psm2_epid_t pspsm_epid;
static psm2_ep_t pspsm_ep;
static psm2_mq_t pspsm_mq;


static void pspsm_err(const char *str)
{
    if (pspsm_err_str) { free(pspsm_err_str); }

    if (str) {
        pspsm_err_str = strdup(str);
    } else {
        pspsm_err_str = strdup("");
    }
    return;
}


/* Check for one of the device files /dev/ipath, ipath0 or ipath1.
   return 0 if at least one file is there, -1 else. */
static int pspsm_check_dev_ipath(void)
{
    struct stat s;
    const char **df;
    const char *devfiles[] = {"/dev/hfi1",   "/dev/hfi1_0", "/dev/hfi1_1",
                              "/dev/hfi1_2", "/dev/hfi2",   "/dev/hfi2_0",
                              "/dev/hfi2_1", "/dev/hfi2_2", "/dev/ipath",
                              "/dev/ipath0", "/dev/ipath1", NULL};
    if (!pspsm_devcheck) { return 0; }

    for (df = devfiles; *df; df++) {
        if (!stat(*df, &s)) { return 0; }
    }

    return -1;
}


static void pspsm_print_stats(void)
{
    psm2_mq_stats_t stats;

    if (!pspsm_mq) { return; }

    memset(&stats, 0, sizeof(stats));

    psm2_mq_get_stats(pspsm_mq, &stats);

    /* Bytes received into a matched user buffer */
    pspsm_dprint(D_STATS, "rx_user_bytes:   %8lu",
                 (unsigned long)stats.rx_user_bytes);
    /* Messages received into a matched user buffer */
    pspsm_dprint(D_STATS, "rx_user_num:     %8lu",
                 (unsigned long)stats.rx_user_num);
    /* Bytes received into an unmatched system buffer */
    pspsm_dprint(D_STATS, "rx_sys_bytes:    %8lu",
                 (unsigned long)stats.rx_sys_bytes);
    /* Messages received into an unmatched system buffer */
    pspsm_dprint(D_STATS, "rx_sys_num:      %8lu",
                 (unsigned long)stats.rx_sys_num);
    /* Total Messages transmitted (shm and hfi) */
    pspsm_dprint(D_STATS, "tx_num:          %8lu", (unsigned long)stats.tx_num);
    /* Messages transmitted eagerly */
    pspsm_dprint(D_STATS, "tx_eager_num:    %8lu",
                 (unsigned long)stats.tx_eager_num);
    /* Bytes transmitted eagerly */
    pspsm_dprint(D_STATS, "tx_eager_bytes:  %8lu",
                 (unsigned long)stats.tx_eager_bytes);
    /* Messages transmitted using expected TID mechanism */
    pspsm_dprint(D_STATS, "tx_rndv_num:     %8lu",
                 (unsigned long)stats.tx_rndv_num);
    /* Bytes transmitted using expected TID mechanism */
    pspsm_dprint(D_STATS, "tx_rndv_bytes:   %8lu",
                 (unsigned long)stats.tx_rndv_bytes);
    /* Messages transmitted (shm only) */
    pspsm_dprint(D_STATS, "tx_shm_num:      %8lu",
                 (unsigned long)stats.tx_shm_num);
    /* Messages received through shm */
    pspsm_dprint(D_STATS, "rx_shm_num:      %8lu",
                 (unsigned long)stats.rx_shm_num);
    /* Number of system buffers allocated  */
    pspsm_dprint(D_STATS, "rx_sysbuf_num:   %8lu",
                 (unsigned long)stats.rx_sysbuf_num);
    /* Bytes allcoated for system buffers */
    pspsm_dprint(D_STATS, "rx_sysbuf_bytes: %8lu",
                 (unsigned long)stats.rx_sysbuf_bytes);
}


#if !PSPSM_SKIP_EP_CLOSE
static void pspsm_sendbuf_free(void)
{
    if (!sendbuf) { return; }
    free(sendbuf);
    sendbuf     = NULL;
    sendbuf_len = 0;
}
#endif


static void pspsm_sendbuf_prepare(unsigned min_small_msg_len)
{
#ifdef PSPSM_TRACE
    pspsm_dprint(D_TRACE,
                 "(send_buf_len: %u) "
                 "pspsm_sendbuf_prepare(min_small_msg_len:%u)\n",
                 min_small_msg_len, sendbuf_len);
#endif
    if (min_small_msg_len >= sendbuf_len) {
        if (sendbuf) { free(sendbuf); }

        sendbuf = valloc(min_small_msg_len);
        assert(sendbuf != NULL);

        sendbuf_len = min_small_msg_len;
    }
}


static int pspsm_open_endpoint(void)
{
    psm2_error_t ret;

    if (!pspsm_ep) {
        struct psm2_ep_open_opts opts;

        ret = psm2_ep_open_opts_get_defaults(&opts);
        if (ret != PSM2_OK) { goto err; }

        ret = psm2_ep_open(pspsm_uuid.as_uuid, &opts, &pspsm_ep, &pspsm_epid);
        if (ret != PSM2_OK) { goto err; }

        pspsm_sendbuf_prepare(pspsm_small_msg_len);

        pspsm_dprint(D_DBG_V, "pspsm_open_endpoint: OK");
    }
    return 0;

err:
    pspsm_err(psm2_error_get_string(ret));
    pspsm_dprint(D_ERR, "pspsm_open_endpoint: %s", pspsm_err_str);
    return -1;
}


static int pspsm_init_mq(void)
{
    psm2_error_t ret;

    if (!pspsm_mq) {
        ret = psm2_mq_init(pspsm_ep, PSM2_MQ_ORDERMASK_ALL, NULL, 0, &pspsm_mq);

        if (ret != PSM2_OK) { goto err; }
        pspsm_dprint(D_DBG_V, "pspsm_init_mq: OK");
    }
    return 0;

err:
    pspsm_err(psm2_error_get_string(ret));
    pspsm_dprint(D_ERR, "pspsm_init_mq: %s", pspsm_err_str);
    return -1;
}


static int pspsm_close_endpoint(void)
{
#if PSPSM_SKIP_EP_CLOSE
    /* Hack: psm_ep_close() SegFaults. A sleep(1) before sometimes helps,
       disabling the cleanup always helps. (Seen with
       infinipath-libs-3.2-32129.1162_rhel6_qlc.x86_64) */
    if (pspsm_debug >= D_STATS) { pspsm_print_stats(); }
    return 0;
#else
    psm2_error_t ret;

    if (pspsm_debug >= D_STATS) { pspsm_print_stats(); }

    if (pspsm_ep) {
        ret      = psm2_ep_close(pspsm_ep, PSM2_EP_CLOSE_GRACEFUL,
                                 150000 /* nsec timeout*/);
        pspsm_ep = NULL;
        if (ret != PSM2_OK) { goto err; }

        pspsm_sendbuf_free();

        pspsm_dprint(D_DBG, "pspsm_close_endpoint: OK");
    }
    return 0;

err:
    pspsm_err(psm2_error_get_string(ret));
    pspsm_dprint(D_WARN, "pspsm_close_endpoint: %s", pspsm_err_str);
    return -1;
#endif
}


int pspsm_finalize_mq(void)
{
    psm2_error_t ret;

    if (pspsm_mq) {
        ret      = psm2_mq_finalize(pspsm_mq);
        pspsm_mq = 0;
        if (ret != PSM2_OK) { goto err; }
        pspsm_dprint(D_DBG_V, "pspsm_finalize_mq: OK");
    }
    return 0;

err:
    pspsm_err(psm2_error_get_string(ret));
    pspsm_dprint(D_WARN, "pspsm_finalize_mq: %s", pspsm_err_str);
    return -1;
}


static int pspsm_con_init(pspsm_con_info_t *con_info, struct PSCOM_con *con)
{
    static uint64_t id = 42;

    con_info->con_broken = 0;
    con_info->connected  = 0;
    con_info->recv_id    = id++;
    con_info->rbuf       = NULL;
    con_info->sreq       = NULL;

    con_info->rreq               = PSM2_MQ_REQINVALID;
    con_info->sreqs_active_count = 0;

    con_info->con = con;

    /* debug */
    con_info->magic = PSPSM_CON_MAGIC;

    pspsm_dprint(D_DBG_V, "pspsm_con_init: OK");
    return 0;
}


static int pspsm_con_connect(pspsm_con_info_t *con_info,
                             pspsm_info_msg_t *info_msg)
{
    psm2_error_t ret, ret1;

    if (memcmp(info_msg->protocol_version, PSPSM_PROTOCOL_VERSION,
               sizeof(info_msg->protocol_version))) {
        goto err_protocol;
    }

    ret = psm2_ep_connect(pspsm_ep, 1, &info_msg->epid, NULL, &ret1,
                          &con_info->epaddr, 0);

    con_info->send_id = info_msg->id;

    if (ret != PSM2_OK) { goto err_connect; }

    con_info->connected     = 1;
    con_info->small_msg_len = info_msg->small_msg_len;

    pspsm_sendbuf_prepare(con_info->small_msg_len);

    pspsm_dprint(D_DBG_V, "pspsm_con_connect: OK");
    pspsm_dprint(D_DBG_V, "sending with %" PRIx64 ", receiving %" PRIx64,
                 con_info->send_id, con_info->recv_id);
    return 0;

err_connect:
    pspsm_err(psm2_error_get_string(ret));
    pspsm_dprint(D_ERR, "pspsm_con_connect: %s", pspsm_err_str);
    return -1;
err_protocol : {
    char str[80];
    snprintf(str, sizeof(str), "protocol error : '%.8s' != '%.8s'",
             info_msg->protocol_version, PSPSM_PROTOCOL_VERSION);
    pspsm_err(str);
    pspsm_dprint(D_ERR, "pspsm_con_connect: %s", pspsm_err_str);
}
    return -1;
}


static int pspsm_init(void)
{
    static pspsm_init_state_t init_state = PSPSM_INIT_START;
    int verno_minor                      = PSM2_VERNO_MINOR;
    int verno_major                      = PSM2_VERNO_MAJOR;
    psm2_error_t ret;

    if (init_state == PSPSM_INIT_START) {
        /* Check for an available /dev/ipath */
        ret = pspsm_check_dev_ipath();
        if (ret != 0) { goto err_dev_ipath; }

        /* Change default from libpsm2 about cpu affinity */
        if (!getenv("HFI_NO_CPUAFFINITY")) { putenv("HFI_NO_CPUAFFINITY=1"); }

        ret = psm2_init(&verno_major, &verno_minor);
        if (ret != PSM2_OK) { goto err_init; }

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
            pspsm_dprint(D_DBG, "seeding PSM UUID with %u",
                         pscom.env.psm_uniq_id);
            pspsm_uuid.as_uint = pscom.env.psm_uniq_id;
        }

        pspsm_small_msg_len = pscom.env.readahead;
#ifdef PSPSM_TRACE
        pspsm_dprint(D_TRACE, "pspsm_small_msg_length = %u\n",
                     pspsm_small_msg_len);
#endif

        /* Open the endpoint here in init with the hope that
           every mpi rank call indirect psm_ep_open() before
           transmitting any data from or to this endpoint.
           This is to avoid a race condition in
           libpsm_infinipath.  Downside: We consume PSM
           Contexts even in the case of only local
           communication. You could use PSP_PSM=0 in this
           case.
        */
        if (pspsm_open_endpoint()) { goto err_ep; }
        if (pspsm_init_mq()) { goto err_mq; }

        pspsm_dprint(D_DBG_V, "pspsm_init: OK");
        init_state = PSPSM_INIT_DONE;
    }
    return init_state; /* 0 = success, -1 = error */
err_dev_ipath:
    pspsm_dprint(D_INFO, "pspsm_init: No psm2 device found. Arch psm is "
                         "disabled.");
    goto err_exit;
err_init:
    pspsm_err(psm2_error_get_string(ret));
    pspsm_dprint(D_ERR, "pspsm_init: %s", pspsm_err_str);
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
			pspsm_dprint(D_TRACE, "SENDV %p %zu", iov->iov_base, iov->iov_len);
			len -= iov->iov_len;
		}
		iov++;
	}
}
#endif


/* Process a mq_status. return 1, if a read made progress. 0 else */
static int pspsm_process(psm2_mq_status2_t *status)
{
    uintptr_t c = (uintptr_t)status->context & PSM_CONTEXT_TYPE_MASK;
    pspsm_con_info_t *ci =
        (pspsm_con_info_t *)((uintptr_t)status->context &
                             ~(uintptr_t)PSM_CONTEXT_TYPE_MASK);
    struct PSCOM_con *con = ci->con;

    assert(ci->magic == PSPSM_CON_MAGIC);

    switch (c) {
    case PSM_CONTEXT_TYPE_SENDREQ:
        /*  send request */
        poll_user_dec();
        ci->sreqs_active_count--;
#ifdef PSPSM_TRACE
        pspsm_dprint(D_TRACE,
                     "psm send request done. active: %u, length:%u, pscom req "
                     "length:%zu\n",
                     ci->sreqs_active_count, status->msg_length, ci->sreq_len);
#endif
        if (!ci->sreqs_active_count) {
            pscom_write_done(con, ci->sreq, ci->sreq_len);
            ci->sreq = NULL;
        }
        break;
    case PSM_CONTEXT_TYPE_RECVREQ:
        /* receive request */
        assert(ci->rbuf);
        if (status->msg_length != status->nbytes) {
            // ToDo: Implement "message truncated", if user post a recv req
            // smaller than the matching send.
            pspsm_dprint(D_FATAL,
                         "fatal error: status->msg_length(%u) != "
                         "status->nbytes(%u).\n",
                         status->msg_length, status->nbytes);
            exit(1);
        }

        ci->rreq = PSM2_MQ_REQINVALID;
#ifdef PSPSM_TRACE
        pspsm_dprint(D_TRACE, "psm read done %p len %u\n", ci->rbuf,
                     status->msg_length);
#endif
        pscom_read_done_unlock(con, ci->rbuf, status->msg_length);
        ci->rbuf = NULL;
        /* Check, if there is more to read. Post the next receive request, if
         * so. */
        pscom_psm_post_recv_check(con);
        return 1;
        break;
    default:
        /* this shouldn't happen */
        assert(0);
    }
    return 0;
}


static inline int _pspsm_send_buf(pspsm_con_info_t *con_info, char *buf,
                                  size_t len, uint64_t tag, psm2_mq_req_t *req,
                                  unsigned long nr)
{
    void *context = (void *)((uintptr_t)con_info | nr);
    psm2_error_t ret;
    assert(*req == PSM2_MQ_REQINVALID);
    ret = psm2_mq_isend(pspsm_mq, con_info->epaddr,
                        /* flags */ 0, tag, buf, (unsigned)len, context, req);
    assert(len < UINT_MAX);
    if (ret != PSM2_OK) { goto err; }
    return 0;

err:
    pspsm_err(psm2_error_get_string(ret));
    pspsm_dprint(D_ERR, "_pspsm_send_buf: %s", pspsm_err_str);
    return -EPIPE;
}


static int pspsm_send_pending(pspsm_con_info_t *con_info)
{
    return !!con_info->sreq;
}


static int pspsm_sendv(pspsm_con_info_t *con_info, struct iovec iov[2],
                       struct PSCOM_req *req)
{
    uint64_t tag   = con_info->send_id | PSPSM_MAGIC_IO;
    unsigned int i = 0;
    psm2_error_t ret;
    size_t len = iov[0].iov_len + iov[1].iov_len;

    // assert(con_info->connected);
    // assert(con_info->magic == PSPSM_CON_MAGIC);

    if (len <= con_info->small_msg_len) {
        pscom_memcpy_from_iov(sendbuf, iov, len);
        /* we hope that doesn't block - it shouldn't, as the
         * message is sufficiently small */
        ret = psm2_mq_send(pspsm_mq, con_info->epaddr,
                           /* flags*/ 0, tag, sendbuf, (unsigned)len);
        if (ret != PSM2_OK) { goto err; }
        return 0;
    }

    struct iovec split_iov[3];
    struct iovec *send_iov = iov;
    unsigned send_iov_cnt  = 2;
    unsigned first_len     = con_info->small_msg_len;

    if (iov[0].iov_len > first_len) {
        // First fragment must not be larger than remotes
        // pspsm_small_msg_length! The receive request has limited length.
        split_iov[0].iov_base = iov[0].iov_base;
        split_iov[0].iov_len  = first_len;
        split_iov[1].iov_base = (void *)((char *)iov[0].iov_base + first_len);
        split_iov[1].iov_len  = iov[0].iov_len - first_len;
        split_iov[2].iov_base = iov[1].iov_base;
        split_iov[2].iov_len  = iov[1].iov_len;
        send_iov              = split_iov;
        send_iov_cnt          = 3;
    }

    for (i = 0; i < send_iov_cnt; i++) {
        if (send_iov[i].iov_len) {
            psm2_mq_req_t sreq = PSM2_MQ_REQINVALID;
#ifdef PSPSM_TRACE
            pspsm_dprint(D_TRACE, "Send part[%d], %p len:%zu\n", i,
                         iov[i].iov_base, iov[i].iov_len);
#endif
            if (_pspsm_send_buf(con_info, send_iov[i].iov_base,
                                send_iov[i].iov_len, tag, &sreq,
                                PSM_CONTEXT_TYPE_SENDREQ)) {
                return -EPIPE;
            }
            /* inc for each outstanding send request */
            poll_user_inc();
            con_info->sreqs_active_count++;
        }
    }

    con_info->sreq_len = len;
    con_info->sreq     = req;

    return -EAGAIN;

err:
    pspsm_err(psm2_error_get_string(ret));
    pspsm_dprint(D_ERR, "_pspsm_send_buf: %s", pspsm_err_str);
    return -EPIPE;
}


static int pspsm_recv_start(pspsm_con_info_t *con_info, char *rbuf,
                            size_t rbuflen)
{
    /* ToDo: rename me to something like "post a receive". */
    psm2_error_t ret;
    uint64_t rtag = con_info->recv_id;
    void *context = (void *)((uintptr_t)con_info | PSM_CONTEXT_TYPE_RECVREQ);

    assert(con_info->rreq == PSM2_MQ_REQINVALID);
    ret            = psm2_mq_irecv(pspsm_mq, rtag, mask, 0 /*flags*/, rbuf,
                                   (unsigned)rbuflen, context, &con_info->rreq);
    con_info->rbuf = rbuf;
    if (ret != PSM2_OK) { goto out_err; }

    return 0;

out_err:
    pspsm_err(psm2_error_get_string(ret));
    pspsm_dprint(D_ERR, "pspsm_recvlook: %s", pspsm_err_str);
    return -EPIPE;
}


static int pspsm_recv_pending(pspsm_con_info_t *con_info)
{
    return !!con_info->rbuf;
}


static int pspsm_progress(void)
{
    unsigned read_progress = 0;
    psm2_mq_req_t req;
    psm2_mq_status2_t status;
    psm2_error_t ret;
    do {
        ret = psm2_mq_ipeek(pspsm_mq, &req, /* status */ NULL);
        if (ret == PSM2_MQ_INCOMPLETE) { return read_progress; }
        if (ret != PSM2_OK) { goto err; }
        ret = psm2_mq_test2(&req, &status);
        if (ret != PSM2_OK) { goto err; }
        read_progress += pspsm_process(&status);
    } while (!read_progress);

    return read_progress;
err:
    pspsm_err(psm2_error_get_string(ret));
    pspsm_dprint(D_ERR, "pspsm_peek: %s", pspsm_err_str);
    return read_progress;
}


static pspsm_con_info_t *pspsm_con_create(void)
{
    pspsm_con_info_t *con_info = malloc(sizeof(*con_info));
    return con_info;
}


static void pspsm_con_free(pspsm_con_info_t *con_info)
{
    assert(con_info->magic == PSPSM_CON_MAGIC);
    con_info->magic = 0;

    free(con_info);
}


static void pspsm_con_cleanup(pspsm_con_info_t *con_info)
{
    assert(con_info->magic == PSPSM_CON_MAGIC);
    assert(con_info->sreqs_active_count == 0);
#ifdef PSM2_EP_DISCONNECT_FORCE
    psm2_error_t err;

    if (con_info->connected) {
        psm2_ep_disconnect2(pspsm_ep, 1, &con_info->epaddr, NULL, &err,
                            PSM2_EP_DISCONNECT_FORCE, 0);
        con_info->connected = 0;
    }
#else
#warning "Missing psm2_ep_disconnect2(). Maybe update libpsm2-devel?"
#endif
}


static void pspsm_con_get_info_msg(pspsm_con_info_t *con_info,
                                   pspsm_info_msg_t *info_msg)
{
    info_msg->epid = pspsm_epid;
    info_msg->id   = con_info->recv_id;
    memcpy(info_msg->protocol_version, PSPSM_PROTOCOL_VERSION,
           sizeof(info_msg->protocol_version));
    info_msg->small_msg_len = pspsm_small_msg_len;
}
