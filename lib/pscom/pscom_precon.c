/*
 * ParaStation
 *
 * Copyright (C) 2011-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>

#include "pscom_precon.h"
#include "list.h"
#include "pscom_con.h"
#include "pscom_debug.h"
#include "pscom_env.h"
#include "pscom_priv.h"

/* array serving as the "registry" for the precon providers */
extern pscom_precon_provider_t pscom_provider_tcp;
static pscom_precon_provider_t
    *pscom_precon_provider_registry[PSCOM_PRECON_TYPE_COUNT] = {
        [PSCOM_PRECON_TYPE_TCP] = &pscom_provider_tcp,
        /* Add new provider XYZ here and use macro PSCOM_PRECON_PROVIDER_XYZ in
           pscom_precon_xyz.h to initialize the respective array entry with
           index PSCOM_PRECON_TYPE_XYZ accordingly.
        */
};

/* the actual precon provider as a global/singleton object */
PSCOM_PLUGIN_API_EXPORT
pscom_precon_provider_t pscom_precon_provider;

const char *pscom_info_type_str(int type)
{
    switch (type) {
    case PSCOM_INFO_FD_EOF: return "FD_EOF";
    case PSCOM_INFO_FD_ERROR: return "FD_ERROR";
    case PSCOM_INFO_EOF:
        return "EOF";
        // case PSCOM_INFO_ANSWER:		return "ANSWER";
    case PSCOM_INFO_CON_INFO: return "CON_INFO";
    case PSCOM_INFO_CON_INFO_DEMAND: return "CON_INFO_DEMAND";
    case PSCOM_INFO_VERSION: return "VERSION";
    case PSCOM_INFO_BACK_CONNECT: return "BACK_CONNECT";
    case PSCOM_INFO_BACK_ACK: return "BACK_ACK";
    case PSCOM_INFO_ARCH_REQ: return "ARCH_REQ";
    case PSCOM_INFO_ARCH_OK: return "ARCH_OK";
    case PSCOM_INFO_ARCH_NEXT: return "ARCH_NEXT";
    case PSCOM_INFO_ARCH_STEP1: return "ARCH_STEP1";
    case PSCOM_INFO_ARCH_STEP2: return "ARCH_STEP2";
    case PSCOM_INFO_ARCH_STEP3: return "ARCH_STEP3";
    case PSCOM_INFO_ARCH_STEP4: return "ARCH_STEP4";
    default: {
        static char res[80];
        snprintf(res, sizeof(res), "#%d", type);
        return res;
    }
    }
}


void pscom_precon_info_dump(pscom_precon_t *precon, char *op, int type,
                            void *data, unsigned size)
{
    const char *plugin_name = precon->plugin ? precon->plugin->name : "";

    switch (type) {
    case PSCOM_INFO_FD_ERROR: {
        int noerr = 0;
        int *err  = size == sizeof(int) && data ? data : &noerr;
        DPRINT(D_PRECON_TRACE, "precon(%p):%s:%s %s\t%d(%s)", precon, op,
               plugin_name, pscom_info_type_str(type), *err, strerror(*err));
        break;
    }
    case PSCOM_INFO_ARCH_REQ: {
        pscom_info_arch_req_t *arch_req = data;
        DPRINT(D_PRECON_TRACE, "precon(%p):%s:%s %s\tarch_id:%u (%s)", precon,
               op, plugin_name, pscom_info_type_str(type), arch_req->arch_id,
               pscom_con_type_str(PSCOM_ARCH2CON_TYPE(arch_req->arch_id)));
        break;
    }
    case PSCOM_INFO_BACK_CONNECT:
    case PSCOM_INFO_CON_INFO_DEMAND:
    case PSCOM_INFO_CON_INFO: {
        pscom_info_con_info_t *msg = data;
        DPRINT(D_PRECON_TRACE, "precon(%p):%s:%s %s\tcon_info:%s", precon, op,
               plugin_name, pscom_info_type_str(type),
               pscom_con_info_str(&msg->con_info));
        break;
    }
    case PSCOM_INFO_VERSION: {
        pscom_info_version_t *version = data;
        DPRINT(D_PRECON_TRACE, "precon(%p):%s:%s %s\tver_from:%04x ver_to:%04x",
               precon, op, plugin_name, pscom_info_type_str(type),
               version->ver_from, version->ver_to);
        break;
    }
    default:
        DPRINT(D_PRECON_TRACE, "precon(%p):%s:%s %s\t%p %u", precon, op,
               plugin_name, pscom_info_type_str(type), data, size);
    }
}


// Connecting or accepting peer?
static int con_is_connecting_peer(pscom_con_t *con)
{
    return con && ((con->pub.state == PSCOM_CON_STATE_CONNECTING) ||
                   (con->pub.state == PSCOM_CON_STATE_CONNECTING_ONDEMAND));
}


static void _plugin_connect_next(pscom_con_t *con, int first)
{
    pscom_precon_t *precon = con->precon;
    pscom_sock_t *sock     = get_sock(con->pub.socket);
    assert(precon->magic == MAGIC_PRECON);
    assert(con->magic == MAGIC_CONNECTION);
    assert(first ? !precon->plugin : 1); // if first, precon->plugin has to be
                                         // NULL!

    if (!con_is_connecting_peer(con)) {
        return; // Nothing to do.
    }

    do {
        precon->plugin      = first ? pscom_plugin_first()
                                    : pscom_plugin_next(precon->_plugin_cur);
        precon->_plugin_cur = precon->plugin;
        first               = 0;
    } while (precon->plugin &&
             (!_pscom_con_type_mask_is_set(sock, PSCOM_ARCH2CON_TYPE(
                                                     precon->plugin->arch_id)) ||
              precon->plugin->con_init(con)));

    if (!precon->plugin) {
        // error: No working plugin found
        errno = ENOPROTOOPT;
        pscom_con_setup_failed(con, PSCOM_ERR_STDERROR);
    } else {
        // Try this plugin:
        pscom_precon_send(precon, PSCOM_INFO_ARCH_REQ, &precon->plugin->arch_id,
                          sizeof(precon->plugin->arch_id));
        precon->plugin->con_handshake(con, PSCOM_INFO_ARCH_REQ,
                                      &precon->plugin->arch_id,
                                      sizeof(precon->plugin->arch_id));
    }
}


void plugin_connect_next(pscom_con_t *con)
{
    _plugin_connect_next(con, 0);
}


void plugin_connect_first(pscom_con_t *con)
{
    _plugin_connect_next(con, 1);
}


/************************************************************************
 * pscom_precon functions
 */

PSCOM_PLUGIN_API_EXPORT
void pscom_precon_send_PSCOM_INFO_ARCH_NEXT(pscom_precon_t *precon)
{
    assert(precon->magic == MAGIC_PRECON);
    precon->plugin = NULL; // reject following STEPx and OK messages
    pscom_precon_send(precon, PSCOM_INFO_ARCH_NEXT, NULL, 0);
}


void pscom_precon_provider_init(void)
{
    memset(&pscom_precon_provider, 0, sizeof(pscom_precon_provider_t));
    pscom_precon_provider =
        *pscom_precon_provider_registry[pscom.env.precon_type];
    assert(pscom_precon_provider.precon_type ==
           (pscom_precon_type_t)pscom.env.precon_type);
    INIT_LIST_HEAD(&pscom_precon_provider.precon_list);
    pscom_precon_provider.precon_count = 0;
    pscom_precon_provider.init();
}


PSCOM_PLUGIN_API_EXPORT
void pscom_precon_send(pscom_precon_t *precon, unsigned type, void *data,
                       unsigned size)
{
    assert(precon->magic == MAGIC_PRECON);
    pscom_precon_provider.send(precon, type, data, size);
}


pscom_precon_t *pscom_precon_create(pscom_con_t *con)
{
    pscom_precon_t *precon = pscom_precon_provider.create(con);

    // add to list
    INIT_LIST_HEAD(&precon->next);
    assert(list_empty(&precon->next));
    list_add_tail(&precon->next, &pscom_precon_provider.precon_list);
    pscom_precon_provider.precon_count++;

    return precon;
}


void pscom_precon_destroy(pscom_precon_t *precon)
{
    assert(precon->magic == MAGIC_PRECON);
    pscom_precon_provider.destroy(precon);

    // remove precon from list
    list_del_init(&precon->next);
    pscom_precon_provider.precon_count--;
    // free space
    free(precon);
}
