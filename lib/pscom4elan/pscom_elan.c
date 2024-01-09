/*
 * ParaStation
 *
 * Copyright (C) 2007-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * pscom_elan.c: ELAN communication
 */

#include "pselan.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "pscom_priv.h"
#include "pscom_io.h"
#include "pscom_elan.h"


static pscom_env_table_entry_t pscom_env_table_elan[] = {
    {"RENDEZVOUS", PSCOM_ENV_UINT_INF_STR,
     "The rendezvous threshold for pscom4elan.", &pscom.env.rendezvous_size_elan,
     PSCOM_ENV_ENTRY_HAS_PARENT, PSCOM_ENV_PARSER_UINT},

    {0},
};


typedef struct pselan_info_msg {
    u_int destvp;
    void *remote_ptr;
} pselan_info_msg_t;


static int _pscom_elan_do_read(pscom_con_t *con, pselan_con_info_t *ci)
{
    void *buf;
    int size;

    size = pselan_recvlook(ci, &buf);

    if (size >= 0) {
        pscom_read_done(con, buf, size);

        pselan_recvdone(ci);
        return 1;
    } else if ((size == -EINTR) || (size == -EAGAIN)) {
        // Nothing received
        return 0;
    } else {
        // Error
        errno = -size;
        pscom_con_error(con, PSCOM_OP_READ, PSCOM_ERR_STDERROR);
        return 1;
    }
}


static int pscom_elan_do_read(pscom_poll_t *poll)
{
    pscom_con_t *con      = list_entry(poll, pscom_con_t, poll_read);
    pselan_con_info_t *ci = con->arch.elan.ci;

    return _pscom_elan_do_read(con, ci);
}


static void pscom_elan_do_write(pscom_con_t *con)
{
    unsigned int len;
    struct iovec iov[2];
    pscom_req_t *req;

    req = pscom_write_get_iov(con, iov);

    if (req) {
        pselan_con_info_t *ci = con->arch.elan.ci;
        len                   = iov[0].iov_len + iov[1].iov_len;

        int rlen = pselan_sendv(ci, iov, len);

        if (rlen >= 0) {
            pscom_write_done(con, req, rlen);
        } else if ((rlen == -EINTR) || (rlen == -EAGAIN)) {
            // Busy: Maybe out of tokens? try to read more tokens:
            _pscom_elan_do_read(con, ci);
        } else {
            // Error
            pscom_con_error(con, PSCOM_OP_WRITE, PSCOM_ERR_STDERROR);
        }
    }
}


/*
 * RMA
 */
#if 0
typedef struct pscom_rendezvous_data_elan {
	struct pselan_rdma_req	rma_req;
	pscom_req_t		*rendezvous_req;
} pscom_rendezvous_data_elan_t;


static inline
pscom_rendezvous_data_elan_t *get_req_data(pscom_rendezvous_data_t *rd)
{
	_pscom_rendezvous_data_elan_t *data = &rd->arch.elan;
	pscom_rendezvous_data_elan_t *res = (pscom_rendezvous_data_elan_t *) data;
	assert(sizeof(*res) <= sizeof(*data));
	return res;
}


static
unsigned int pscom_elan_rma_mem_register(pscom_con_t *con, pscom_rendezvous_data_t *rd)
{
	pscom_rendezvous_data_elan_t *elan_rd = get_req_data(rd);
	pselan_con_info_t *ci = con->arch.elan.ci;

	/* get mem region */
	pselan_mregion_cache_t *mreg =
		pselan_get_mregion(rd->msg.data, rd->msg.data_len, ci);
	if (!mreg)
		goto err_get_region;

	elan_rd->rma_req.mreg = mreg;

	rd->msg.arch.elan.rmr_context = pselan_get_rmr_context(mreg);
	rd->msg.arch.elan.rmr_vaddr = pselan_get_rmr_vaddr(rd->msg.data);

	return sizeof(rd->msg.arch.elan);
err_get_region:
	// ToDo: Count get_mregion errors!
	elan_rd->rma_req.mreg = NULL;
	return 0;
}


static
void pscom_elan_rma_mem_deregister(pscom_con_t *con, pscom_rendezvous_data_t *rd)
{
	pscom_rendezvous_data_elan_t *elan_rd = get_req_data(rd);

	if (elan_rd->rma_req.mreg) {
		pselan_put_mregion(elan_rd->rma_req.mreg);
		elan_rd->rma_req.mreg = NULL;
	}
}


static
void pscom_elan_rma_read_io_done(pselan_rdma_req_t *dreq)
{
	pscom_rendezvous_data_elan_t *elan_rd =
		(pscom_rendezvous_data_elan_t *)dreq->priv;

	pscom_req_t *rendezvous_req = elan_rd->rendezvous_req;

	/* called via
	   _pselan_sendv() -> pselan_flush_evd() ->
	   do_DTO_COMPLETION_EVENT() -> io_done.

	   we have the global lock!
	   Use locked version of req_done: */

	_pscom_recv_req_done(rendezvous_req);
}


static
int pscom_elan_rma_read(pscom_req_t *rendezvous_req, pscom_rendezvous_data_t *rd)
{
	pscom_rendezvous_data_elan_t *elan_rd = get_req_data(rd);
	pselan_rdma_req_t *dreq = &elan_rd->rma_req;
	pscom_con_t *con = get_con(rendezvous_req->pub.connection);
	pselan_con_info_t *ci = con->arch.elan.ci;


	dreq->ci = ci;
	dreq->rmr_context = rd->msg.arch.elan.rmr_context;
	dreq->rmr_vaddr = rd->msg.arch.elan.rmr_vaddr;
	dreq->lmr_buf = rendezvous_req->pub.data;
	dreq->size = rendezvous_req->pub.data_len;

	dreq->io_done = pscom_elan_rma_read_io_done;
	dreq->priv = elan_rd;

	elan_rd->rendezvous_req = rendezvous_req;

	return pselan_post_rdma_get(dreq);
}


/* RMA end */
#endif

static void pscom_elan_close(pscom_con_t *con)
{
    pselan_con_info_t *ci = con->arch.elan.ci;

    if (!ci) { return; }

    pselan_con_destroy(ci);

    con->arch.elan.ci = NULL;
}


static void pscom_poll_read_start_elan(pscom_con_t *con)
{
    pscom_poll_read_start(con, pscom_elan_do_read);
}


static void pscom_poll_write_start_elan(pscom_con_t *con)
{
    pscom_poll_write_start(con, pscom_elan_do_write);
}


static void pscom_elan_con_init(pscom_con_t *con, int con_fd,
                                pselan_con_info_t *ci)
{
    con->pub.state = PSCOM_CON_STATE_RW;
    con->pub.type  = PSCOM_CON_TYPE_ELAN;

    close(con_fd);

    con->arch.elan.ci = ci;

    // Only Polling:
    con->read_start = pscom_poll_read_start_elan;
    con->read_stop  = pscom_poll_read_stop;

    con->write_start = pscom_poll_write_start_elan;
    con->write_stop  = pscom_poll_write_stop;

    con->close = pscom_elan_close;

    //	con->rndv.mem_register = pscom_elan_rma_mem_register;
    //	con->rndv.mem_deregister = pscom_elan_rma_mem_deregister;
    //	con->rndv.rma_read = pscom_elan_rma_read;

    con->rendezvous_size = pscom.env.rendezvous_size_elan;
}

/*********************************************************************/
static void pscom_elan_init(void)
{
    pselan_debug = pscom.env.debug;

    /* register the environment configuration table */
    pscom_env_table_register_and_parse("pscom ELAN", "ELAN_",
                                       pscom_env_table_elan);

    pselan_init();
}


static void pscom_elan_destroy(void)
{
}


static int pscom_elan_connect(pscom_con_t *con, int con_fd)
{
    int arch              = PSCOM_ARCH_ELAN;
    pselan_con_info_t *ci = pselan_con_create();
    pselan_info_msg_t msg;
    pselan_info_msg_t my_msg;

    if (!ci) { goto dont_use; /* Dont use elan */ }

    /* We want talk elan */
    pscom_writeall(con_fd, &arch, sizeof(arch));

    /* step 1 */
    if ((pscom_readall(con_fd, &arch, sizeof(arch)) != sizeof(arch)) ||
        (arch != PSCOM_ARCH_ELAN)) {
        goto err_remote;
    }

    /* step 2 : recv connection id's */
    if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg))) {
        goto err_remote;
    }

    /* step 3: send my connection id's */
    my_msg.destvp     = pselan_get_myvp();
    my_msg.remote_ptr = pselan_get_r_ptr(ci);
    pscom_writeall(con_fd, &my_msg, sizeof(my_msg));


    /* Connect */
    pselan_connect(ci, msg.destvp, msg.remote_ptr);

    pscom_elan_con_init(con, con_fd, ci);

    return 1;
    /* --- */
err_remote:
dont_use:
    if (ci) { pselan_con_destroy(ci); }
    return 0;
}


static int pscom_elan_accept(pscom_con_t *con, int con_fd)
{
    int arch              = PSCOM_ARCH_ELAN;
    pselan_con_info_t *ci = pselan_con_create();
    pselan_info_msg_t msg;

    if (!ci) { goto out_noelan; }

    /* step 1:  Yes, we talk elan. */
    pscom_writeall(con_fd, &arch, sizeof(arch));

    /* step 2: Send Connection id's */
    msg.destvp     = pselan_get_myvp();
    msg.remote_ptr = pselan_get_r_ptr(ci);
    pscom_writeall(con_fd, &msg, sizeof(msg));

    /* step 3 : recv connection id's */
    if ((pscom_readall(con_fd, &msg, sizeof(msg)) != sizeof(msg))) {
        goto err_remote;
    }

    /* Connect */
    pselan_connect(ci, msg.destvp, msg.remote_ptr);

    pscom_elan_con_init(con, con_fd, ci);

    return 1;
    /* --- */
err_remote:
    if (ci) { pselan_con_destroy(ci); }
out_noelan:
    arch = PSCOM_ARCH_ERROR;
    pscom_writeall(con_fd, &arch, sizeof(arch));
    return 0; /* Dont use elan */
              /* --- */
}


PSCOM_PLUGIN_API_EXPORT
pscom_plugin_t pscom_plugin_elan = {
    .name     = "elan",
    .version  = PSCOM_PLUGIN_VERSION,
    .arch_id  = PSCOM_ARCH_ELAN,
    .priority = PSCOM_ELAN_PRIO,

    .init         = pscom_elan_init,
    .destroy      = pscom_elan_destroy,
    .sock_init    = NULL,
    .sock_destroy = NULL,
    .con_connect  = pscom_elan_connect,
    .con_accept   = pscom_elan_accept,
};
