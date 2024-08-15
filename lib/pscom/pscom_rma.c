/*
 * ParaStation
 *
 * Copyright (C) 2023-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "list.h"
#include "pscom.h"
#include "pscom_io.h"
#include "pscom_priv.h"

PSCOM_API_EXPORT
pscom_err_t pscom_mem_register(pscom_socket_t *socket, void *addr,
                               size_t length, pscom_memh_t *memh)
{
    /* invalid socket, return error */
    if (!socket) {
        *memh = NULL;
        return PSCOM_ERR_INVALID;
    }

    /* NULL with length, return error */
    if (addr == NULL && length != 0) {
        *memh = NULL;
        return PSCOM_ERR_INVALID;
    }

    /* init memory region handle */
    int pscom_err           = PSCOM_SUCCESS;
    pscom_sock_t *sock      = get_sock(socket);
    pscom_memh_t pscom_memh = NULL;
    pscom_memh              = (pscom_memh_t)malloc(sizeof(struct PSCOM_memh));
    pscom_memh->addr        = addr;
    pscom_memh->length      = length;
    pscom_memh->sock        = sock;
    pscom_memh->magic       = MAGIC_MEMH;
    pscom_memh->rkey_buffer = NULL;
    pscom_memh->rkey_buffer_length = 0;

    /* init lists */
    INIT_LIST_HEAD(&pscom_memh->arch_memh_list);

    /* no memory exposed, return memh and success */
    if (addr == NULL || length == 0) {
        *memh = pscom_memh;
        return PSCOM_SUCCESS;
    }

    /* init temp variables */
    void *temp_rkeybuf[PSCOM_CON_TYPE_COUNT]; /* temp buffers for rkeys from
                                            different plugins */
    pscom_rkey_buffer_t *temp_buf = NULL; /* temp buffer to store contiguously
                                             all rkey data */
    uint16_t temp_sizes[PSCOM_CON_TYPE_COUNT]; /* size of temp buffers */

    memset(temp_rkeybuf, 0, PSCOM_CON_TYPE_COUNT * sizeof(void *));
    memset(temp_sizes, 0, PSCOM_CON_TYPE_COUNT * sizeof(uint16_t));

    /* store total size of the rkey data */
    uint16_t sum_arch_bufsizes = 0;

    /* loop over all archs to register memory region */
    int pscom_reg_err = 0;
    struct list_head *pos;
    list_for_each (pos, &sock->archs) {
        pscom_arch_sock_t *arch_sock = list_entry(pos, pscom_arch_sock_t, next);
        int index                    = arch_sock->plugin_con_type;
        if (arch_sock->rma.mem_register) {
            /* allocate space for MR handle */
            pscom_arch_memh_t *arch_memh = (pscom_arch_memh_t *)malloc(
                sizeof(pscom_arch_memh_t));
            arch_memh->plugin_memh = NULL;
            arch_memh->arch_sock   = arch_sock;

            pscom_err = arch_sock->rma.mem_register(addr, length,
                                                    &temp_rkeybuf[index],
                                                    &temp_sizes[index],
                                                    arch_sock,
                                                    &(arch_memh->plugin_memh));
            if (pscom_err != PSCOM_SUCCESS) {
                /* if registration fails in this plugin, we free arch_memh and
                 * do not add it to list, this will not be an error,
                 * registration process will continue in next available plugin
                 * set pscom_reg_err = 1
                 */
                free(arch_memh);
                temp_sizes[index] = 0;
                pscom_reg_err     = 1;
            } else {
                list_add_tail(&arch_memh->next, &pscom_memh->arch_memh_list);
                /* sum up the rkey data size */
                sum_arch_bufsizes += temp_sizes[index];
            }
        }
    }

    /* calculate the total size of the rkey buffer and allocate the space */
    uint16_t total_rkey_bufsize = sizeof(pscom_rkey_buffer_t) +
                                  sum_arch_bufsizes;
    temp_buf              = (pscom_rkey_buffer_t *)malloc(total_rkey_bufsize);
    temp_buf->magic       = MAGIC_RKEYBUF;
    temp_buf->remote_addr = addr;
    temp_buf->remote_len  = length;
    temp_buf->rkeydata_length = sum_arch_bufsizes; /* set the rkey data length
                                                    */

    if (sum_arch_bufsizes == 0) {
        /* no plugin supports memory region registration, pack basic information
         * into rkey buffer, and return memh and success */
        pscom_memh->rkey_buffer_length = (size_t)total_rkey_bufsize;
        pscom_memh->rkey_buffer        = (void *)temp_buf;
        *memh                          = pscom_memh;
        if (pscom_reg_err) {
            /* if pscom_reg_err = 1, registration failed in at least one plugin,
             * return error. */
            errno = EPROTO;
            return PSCOM_ERR_STDERROR;
        }
        return PSCOM_SUCCESS;
    }

    uint16_t temp_rkey_data_offset = 0;
    for (int i = 0; i < PSCOM_CON_TYPE_COUNT; i++) {
        /* set the buffer offset and copy the data from temp_rkeybuf into the
         * correct position in temp_buf->rkey_data */
        if (temp_sizes[i]) {
            temp_buf->rkey_data_offset[i] = temp_rkey_data_offset;
            memcpy((char *)&temp_buf->rkey_data + temp_rkey_data_offset,
                   temp_rkeybuf[i], temp_sizes[i]);
            temp_rkey_data_offset += temp_sizes[i];
        } else {
            temp_buf->rkey_data_offset[i] = PSCOM_INVALID_RKEYBUF_SIZE;
        }
        /*  free temp rkey in plugin. */
        if (temp_rkeybuf[i] != NULL) {
            pscom_arch_sock_t *arch_sock = get_arch_sock(sock,
                                                         (pscom_con_type_t)i);
            /* each plugin must have rkey_buf_free */
            arch_sock->rma.rkey_buf_free(temp_rkeybuf[i]);
        }
    }
    /* set rkey_buffer in memh */
    pscom_memh->rkey_buffer_length = (size_t)total_rkey_bufsize;
    pscom_memh->rkey_buffer        = (void *)temp_buf;
    *memh                          = pscom_memh;

    /* if pscom_reg_err = 1 it means that error happened during memory
     * registration in at least one plugin.
     * However, when getting here, memory region registration was successful
     * in at least one plugin
     */
    if (pscom_reg_err) {
        errno = EPROTO;
        return PSCOM_ERR_STDERROR;
    }
    return PSCOM_SUCCESS;
}


/* de-register memory and free space */
PSCOM_API_EXPORT
pscom_err_t pscom_mem_deregister(pscom_memh_t memh)
{
    /* no memory region to deregister, directly return */
    if (memh == NULL) { return PSCOM_SUCCESS; }

    int pscom_err = PSCOM_SUCCESS;
    struct list_head *pos, *next;
    pscom_arch_memh_t *temp_arch_memh = NULL;
    assert(memh->magic == MAGIC_MEMH);

    /* loop over all arch_memh to deregister memory region */
    list_for_each_safe (pos, next, &memh->arch_memh_list) {
        temp_arch_memh               = list_entry(pos, pscom_arch_memh_t, next);
        pscom_arch_sock_t *arch_sock = temp_arch_memh->arch_sock;
        /* ensure a valid memory handle */
        assert(arch_sock);
        /* de-register on plugin level */
        int status = arch_sock->rma.mem_deregister(temp_arch_memh->plugin_memh);
        if (status) { pscom_err = status; }

        /* delete it from the list and free the space */
        list_del_init(&temp_arch_memh->next);
        free(temp_arch_memh);
    }
    /* assert list is empty after dereg */
    assert(list_empty(&memh->arch_memh_list));
    memh->addr  = NULL;
    memh->magic = 0;

    free(memh->rkey_buffer);
    free(memh);
    if (pscom_err) { goto err_exit; }
    return PSCOM_SUCCESS;

err_exit:
    errno = EPROTO;
    return PSCOM_ERR_STDERROR;
}


PSCOM_API_EXPORT
pscom_err_t pscom_rkey_buffer_pack(void **rkeybuf, size_t *bufsize,
                                   pscom_memh_t memh)
{
    if (memh == NULL) {
        /* NULL is not a valid memh, return an error code */
        *rkeybuf = NULL;
        bufsize  = 0;
        return PSCOM_ERR_INVALID;
    }

    if (memh->addr == NULL || memh->length == 0) {
        /* this is a zero-sized (but valid) memh,
         * return a likewise zero-sized rkeybuf */
        *rkeybuf = NULL;
        bufsize  = 0;
        return PSCOM_SUCCESS;
    }

    /* alloc space and copy buffer into it */
    void *newbuffer = malloc(memh->rkey_buffer_length);
    memcpy(newbuffer, memh->rkey_buffer, memh->rkey_buffer_length);

    *rkeybuf = newbuffer;
    *bufsize = memh->rkey_buffer_length;

    return PSCOM_SUCCESS;
}


/* release rkey buffer after it is sent to the target */
PSCOM_API_EXPORT
void pscom_rkey_buffer_release(void *rkey_buffer)
{
    if (rkey_buffer == NULL) { return; }
    pscom_rkey_buffer_t *temp = (pscom_rkey_buffer_t *)rkey_buffer;
    assert(temp->magic == MAGIC_RKEYBUF);
    temp->magic = 0;
    free(rkey_buffer);
}


/* generate remote key using rkeybuf received from origin side */
PSCOM_API_EXPORT
pscom_err_t pscom_rkey_generate(pscom_connection_t *connection, void *rkeybuf,
                                size_t bufsize, pscom_rkey_t *rkey)
{
    if (rkeybuf == NULL || bufsize == 0) {
        /* target proc has no memory exposed, return NULL as a valid wildcard
         * for this case */
        *rkey = NULL;
        return PSCOM_SUCCESS;
    }

    int pscom_err = PSCOM_ERR_STDERROR;
    unsigned buf_offset;
    pscom_con_t *con              = get_con(connection);
    pscom_rkey_buffer_t *temp_buf = rkeybuf;
    /* check rkey data length */
    size_t rkeydata_len           = bufsize - sizeof(pscom_rkey_buffer_t);
    assert(temp_buf->rkeydata_length == rkeydata_len);

    pscom_rkey_t new_rkey = (pscom_rkey_t)malloc(sizeof(struct PSCOM_rkey));
    new_rkey->con = con; /* where the remote key is valid and generated */
    new_rkey->plugin_rkey = NULL;
    new_rkey->magic       = MAGIC_RKEY;
    new_rkey->remote_addr = temp_buf->remote_addr;
    new_rkey->remote_len  = temp_buf->remote_len;

    /* connetion has rekey_gen, and temp_buf has valid remote key buffer */
    if (con->rma.rkey_generate && rkeydata_len != 0) {
        int index  = (int)connection->type;
        buf_offset = temp_buf->rkey_data_offset[index];
        if (buf_offset == PSCOM_INVALID_RKEYBUF_SIZE) {
            /* no plugin data is provided, so rkey will be NULL, this indicates
             * that the memory registration in this plugin failed at the process
             * which shares this memory segment */
            goto err_exit;
        }
        pscom_err = con->rma.rkey_generate(con,
                                           (char *)&temp_buf->rkey_data +
                                               buf_offset,
                                           &(new_rkey->plugin_rkey));
        if (pscom_err != PSCOM_SUCCESS) { goto err_exit; }
    }

    *rkey = new_rkey;
    return PSCOM_SUCCESS;

err_exit:
    /* error at rkey generation */
    *rkey = new_rkey;
    errno = EPROTO;
    return PSCOM_ERR_STDERROR;
}


/* destroy remote key and free space */
PSCOM_API_EXPORT
pscom_err_t pscom_rkey_destroy(pscom_rkey_t rkey)
{
    if (rkey == NULL) { return PSCOM_SUCCESS; }

    int pscom_err = PSCOM_SUCCESS;
    assert(rkey->magic == MAGIC_RKEY);
    rkey->magic = 0;

    pscom_con_t *con = rkey->con;
    if (con->rma.rkey_destroy && rkey->plugin_rkey != NULL) {
        /* rkey has a valid plugin_rkey, destroy also this */
        pscom_err = con->rma.rkey_destroy(rkey->plugin_rkey);
    }


    free(rkey);
    if (pscom_err) { goto err_exit; }
    return PSCOM_SUCCESS;
err_exit:
    errno = EPROTO;
    return PSCOM_ERR_STDERROR;
}


/* Prototype functions for RMA put with remote key parameter. */
PSCOM_API_EXPORT
void pscom_post_rma_put(pscom_request_t *request, void *remote_address,
                        pscom_rkey_t rkey)
{
    pscom_req_t *req = get_req(request);

    assert(req->magic == MAGIC_REQUEST);
    assert(request->state & PSCOM_REQ_STATE_DONE);
    assert(request->connection != NULL);

    pscom_con_t *con = get_con(request->connection);
    /* If plugin implements rma put, then use this: */
    if (con->rma.put) {
        if (con->rma.put(con, request->data, request->data_len, remote_address,
                         rkey->plugin_rkey, req)) {
            request->state |= PSCOM_REQ_STATE_ERROR;
        }
        return;
    }
    /* ...otherwise fall-back to two-sided protocol. */

    request->xheader.rma_write.dest = remote_address;

    if (rkey) {
        char *req_addr_start  = (char *)request->xheader.rma_write.dest;
        char *req_addr_end    = req_addr_start + request->data_len;
        char *rkey_addr_start = (char *)rkey->remote_addr;
        char *rkey_addr_end   = rkey_addr_start + rkey->remote_len;

        /* boundary checks */
        if ((req_addr_start < rkey_addr_start) ||
            (req_addr_end > rkey_addr_end)) {
            /* raise an error */
            request->state |= PSCOM_REQ_STATE_ERROR;
            return;
        }
    }

    req->pub.xheader_len = sizeof(req->pub.xheader.rma_write);
    pscom_post_send_direct(req, PSCOM_MSGTYPE_RMA_WRITE);
    return;
}

/* Prototype functions for RMA get with remote key parameter. See pscom_rma_get
 * test in /bin folder for a usage example. */
PSCOM_API_EXPORT
void pscom_post_rma_get(pscom_request_t *request, void *remote_address,
                        pscom_rkey_t rkey)
{
    pscom_req_t *req = get_req(request);

    assert(req->magic == MAGIC_REQUEST);
    assert(request->state & PSCOM_REQ_STATE_DONE);
    assert(request->connection != NULL);

    pscom_con_t *con = get_con(request->connection);
    /* If plugin implements rma get, then use this: */
    if (con->rma.get) {
        if (con->rma.get(con, request->data, request->data_len, remote_address,
                         rkey->plugin_rkey, req)) {
            request->state |= PSCOM_REQ_STATE_ERROR;
        }
        return;
    }
    /* ...otherwise fall-back to two-sided protocol. */

    request->xheader.rma_read.src     = remote_address;
    request->xheader.rma_read.src_len = request->data_len;

    if (rkey) {
        char *req_addr_start = (char *)request->xheader.rma_read.src;
        char *req_addr_end = req_addr_start + request->xheader.rma_read.src_len;
        char *rkey_addr_start = (char *)rkey->remote_addr;
        char *rkey_addr_end   = rkey_addr_start + rkey->remote_len;

        /* boundary checks */
        if ((req_addr_start < rkey_addr_start) ||
            (req_addr_end > rkey_addr_end)) {
            /* raise an error */
            request->state |= PSCOM_REQ_STATE_ERROR;
            return;
        }
    }

    pscom_lock();
    {
        _pscom_post_rma_read(req);
    }
    pscom_unlock();

    return;
}
