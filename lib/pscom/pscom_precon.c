/*
 * ParaStation
 *
 * Copyright (C) 2011-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
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

pscom_env_table_entry_t pscom_env_table_precon[] = {
    {"TYPE", "tcp",
     "Type of the pre-connection provider to be used (tcp, rrcomm).",
     &pscom.env.precon_type, PSCOM_ENV_ENTRY_FLAGS_EMPTY, PSCOM_ENV_PARSER_STR},

    {0},
};

/* pscom provider implementations */
extern pscom_precon_provider_t pscom_provider_tcp;
#ifdef RRCOMM_PRECON_ENABLED
extern pscom_precon_provider_t pscom_provider_rrc;
#endif

/* precon provider registry to enable lookup-by-name */
static pscom_precon_provider_reg_entry_t pscom_precon_provider_registry[] = {
    {"tcp", &pscom_provider_tcp},
#ifdef RRCOMM_PRECON_ENABLED
    {"rrcomm", &pscom_provider_rrc},
#endif
};

#define PRECON_PROVIDER_REGISTRY_SIZE                                          \
    (sizeof(pscom_precon_provider_registry) /                                  \
     sizeof(pscom_precon_provider_reg_entry_t))


pscom_precon_provider_t *pscom_precon_provider_lookup(const char *name)
{
    uint8_t i;

    /* just return the default provider if not strategy was given */
    if (name == NULL) { goto err_out; }

    /* search the given strategy within the registry */
    for (i = 0; i < PRECON_PROVIDER_REGISTRY_SIZE; ++i) {
        pscom_precon_provider_reg_entry_t *reg_entry =
            &pscom_precon_provider_registry[i];
        if (strcmp(reg_entry->name, name) == 0) { return reg_entry->provider; }
    }

    assert(strcmp(name, pscom_env_table_precon[0].default_val) != 0);
    /* --- */
err_out:
    DPRINT(D_ERR,
           "Could not find provider with name '%s'. Using '%s' as the default.",
           name, pscom_env_table_precon[0].default_val);
    /* return the default if there was no match */
    return pscom_precon_provider_lookup(pscom_env_table_precon[0].default_val);
}

/* the actual precon provider as a global/singleton object */
PSCOM_PLUGIN_API_EXPORT
pscom_precon_provider_t *pscom_precon_provider = NULL;

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
    case PSCOM_INFO_CON_INFO_VERSION: return "CON_INFO_VERSION";
    case PSCOM_INFO_CON_INFO_VERSION_DEMAND: return "CON_INFO_VERSION_DEMAND";
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


void pscom_precon_info_dump(pscom_precon_t *precon, const char *op, int type,
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
    case PSCOM_INFO_CON_INFO:
    case PSCOM_INFO_CON_INFO_DEMAND:
    case PSCOM_INFO_CON_INFO_VERSION_DEMAND:
    case PSCOM_INFO_CON_INFO_VERSION: {
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
int precon_con_is_connecting_peer(pscom_con_t *con)
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

    if (!pscom_precon_provider->is_starting_peer(con)) { return; }

    do {
        precon->plugin      = first ? pscom_plugin_first()
                                    : pscom_plugin_next(precon->_plugin_cur);
        precon->_plugin_cur = precon->plugin;
        first               = 0;
    } while (precon->plugin && (!_pscom_con_type_mask_is_set(
                                    sock, (pscom_con_type_t)PSCOM_ARCH2CON_TYPE(
                                              precon->plugin->arch_id)) ||
                                precon->plugin->con_init(con)));

    if (!precon->plugin) {
        // error: No working plugin found
        errno = ENOPROTOOPT;
        pscom_con_setup_failed(con, PSCOM_ERR_STDERROR);
    } else {
        // Try this plugin:
        pscom_err_t ret = pscom_precon_send(precon, PSCOM_INFO_ARCH_REQ,
                                            &precon->plugin->arch_id,
                                            sizeof(precon->plugin->arch_id));
        assert(ret == PSCOM_SUCCESS);

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

    pscom_err_t ret = pscom_precon_send(precon, PSCOM_INFO_ARCH_NEXT, NULL, 0);
    assert(ret == PSCOM_SUCCESS);
}


void pscom_precon_provider_init(void)
{
    /* register the environment configuration table */
    pscom_env_table_register_and_parse("pscom PRECON", "PRECON_",
                                       pscom_env_table_precon);


    /* set the precon provider singleton */
    pscom_precon_provider = pscom_precon_provider_lookup(pscom.env.precon_type);

    INIT_LIST_HEAD(&pscom_precon_provider->precon_list);
    pscom_precon_provider->precon_count = 0;
    pscom_precon_provider->init();
}


void pscom_precon_provider_destroy(void)
{
    pscom_precon_provider->destroy();
}


PSCOM_PLUGIN_API_EXPORT
pscom_err_t pscom_precon_send(pscom_precon_t *precon, unsigned type, void *data,
                              unsigned size)
{
    assert(precon->magic == MAGIC_PRECON);
    return pscom_precon_provider->send(precon, type, data, size);
}


pscom_precon_t *pscom_precon_create(pscom_con_t *con)
{
    pscom_precon_t *precon = pscom_precon_provider->create(con);

    // add to list
    INIT_LIST_HEAD(&precon->next);
    assert(list_empty(&precon->next));
    list_add_tail(&precon->next, &pscom_precon_provider->precon_list);
    pscom_precon_provider->precon_count++;

    return precon;
}


void pscom_precon_destroy(pscom_precon_t *precon)
{
    assert(precon->magic == MAGIC_PRECON);
    pscom_precon_provider->cleanup(precon);

    // remove precon from list
    list_del_init(&precon->next);
    pscom_precon_provider->precon_count--;
    // free space
    free(precon);
}
