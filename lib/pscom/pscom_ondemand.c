/*
 * ParaStation
 *
 * Copyright (C) 2008-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2024 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <assert.h>
#include <string.h>

#include "list.h"
#include "pscom.h"
#include "pscom_con.h"
#include "pscom_debug.h"
#include "pscom_priv.h"
#include "pscom_str_util.h"

static void pscom_ondemand_read_start(pscom_con_t *con);
static void pscom_ondemand_read_stop(pscom_con_t *con);


static int pscom_name_is_equal(const char name1[8], const char name2[8])
{
    return !memcmp(name1, name2, 8);
}


static int pscom_name_is_lower(const char name1[8], const char name2[8])
{
    return memcmp(name1, name2, 8) < 0;
}

static void pscom_ondemand_cleanup(pscom_con_t *con)
{
    /* close the "on demand" connection */
    pscom_sock_t *sock = get_sock(con->pub.socket);

    assert(con->pub.type == PSCOM_CON_TYPE_ONDEMAND);

    con->write_start = pscom_no_rw_start_stop;
    con->read_start  = pscom_no_rw_start_stop;
    con->read_stop   = pscom_no_rw_start_stop;
    con->close       = NULL;

    pscom_ondemand_read_stop(con);
    pscom_listener_user_dec(&sock->listen);

    // con->pub.state = PSCOM_CON_STATE_CLOSED;
    // con->pub.type = PSCOM_CON_TYPE_NONE;
}


static void pscom_ondemand_direct_connect(pscom_con_t *con)
{
    /* connect to peer and change connection type */
    int nodeid = con->arch.ondemand.node_id;
    int portno = con->arch.ondemand.portno;

    pscom_ondemand_cleanup(con);

    /* reopen via tcp connection */
    int rc = pscom_con_connect_via_tcp(con, nodeid, portno);

    if (rc) {
        /* connect failed. set error falgs */
        pscom_con_error(con, PSCOM_OP_WRITE, rc);
    }
}


static void pscom_ondemand_write_start(pscom_con_t *con)
{
    if (pscom_name_is_lower(con->arch.ondemand.name,
                            con->pub.socket->local_con_info.name)) {
        pscom_ondemand_read_start(con); // be prepared for the back connect
        pscom_ondemand_indirect_connect(con);
    } else {
        pscom_sock_t *sock = get_sock(con->pub.socket);

        pscom_listener_user_inc(&sock->listen); // listen until we have the
                                                // connection

        pscom_ondemand_direct_connect(con);

        pscom_listener_user_dec(&sock->listen);
    }
}


static void pscom_ondemand_read_start(pscom_con_t *con)
{
    if (!con->arch.ondemand.active) {
        /* enable listen */
        pscom_sock_t *sock = get_sock(con->pub.socket);

        con->arch.ondemand.active = 1;
        pscom_listener_active_inc(&sock->listen);
    }
}


static void pscom_ondemand_read_stop(pscom_con_t *con)
{
    if (con->arch.ondemand.active) {
        /* disable listen */
        pscom_sock_t *sock = get_sock(con->pub.socket);

        pscom_listener_active_dec(&sock->listen);
        con->arch.ondemand.active = 0;
    }
}


static void pscom_ondemand_close(pscom_con_t *con)
{
    pscom_ondemand_cleanup(con);
}


pscom_con_t *pscom_ondemand_find_con(pscom_sock_t *sock, const char name[8])
{
    struct list_head *pos_con;

    list_for_each (pos_con, &sock->connections) {
        pscom_con_t *con = list_entry(pos_con, pscom_con_t, next);

        if ((con->pub.type == PSCOM_CON_TYPE_ONDEMAND) &&
            (pscom_name_is_equal(name, con->arch.ondemand.name))) {
            /* matching connection. Equal names with correct type. */
            return con;
        }
    }
    /* No match */
    return NULL;
}


pscom_con_t *pscom_ondemand_get_con(pscom_sock_t *sock, const char name[8])
{
    pscom_con_t *con = pscom_ondemand_find_con(sock, name);
    if (con) { pscom_ondemand_cleanup(con); }
    return con;
}


pscom_err_t _pscom_con_connect_ondemand(pscom_con_t *con, int nodeid,
                                        int portno, const char name[8])
{
    pscom_sock_t *sock = get_sock(con->pub.socket);
    pscom_con_info_t con_info;

    if (sock->pub.listen_portno == -1) { goto err_not_listening; }

    if (pscom_is_local(&sock->pub, nodeid, portno)) {
        return pscom_con_connect_loopback(con);
    }

    memset(&con->pub.remote_con_info, 0, sizeof(con->pub.remote_con_info));

    con->pub.remote_con_info.node_id = nodeid;
    memcpy(con->pub.remote_con_info.name, name,
           sizeof(con->pub.remote_con_info.name));

    con->arch.ondemand.node_id = nodeid;
    con->arch.ondemand.portno  = portno;
    memcpy(con->arch.ondemand.name, name, sizeof(con->arch.ondemand.name));
    con->arch.ondemand.active = 0;

    con->pub.state = PSCOM_CON_STATE_RW;
    con->pub.type  = PSCOM_CON_TYPE_ONDEMAND;
    pscom_listener_user_inc(&sock->listen);

    con->write_start = pscom_ondemand_write_start;
    con->read_start  = pscom_ondemand_read_start;
    con->read_stop   = pscom_ondemand_read_stop;
    con->close       = pscom_ondemand_close;

    assert(list_empty(&con->next));
    list_add_tail(&con->next, &sock->connections);

    pscom_con_setup(con);

    return PSCOM_SUCCESS;
    /* --- */
err_not_listening:
    pscom_con_info(con, &con_info);
    DPRINT(D_BUG_EXT,
           "CONNECT on demand %s to tcp:%s:%u FAILED : "
           "pscom_connect_ondemand() called without a prior pscom_listen()",
           pscom_con_info_str(&con_info), pscom_inetstr(nodeid), portno);
    return PSCOM_ERR_INVALID;
}


/*
******************************************************************************
*/


PSCOM_API_EXPORT
pscom_err_t pscom_connect_ondemand(pscom_connection_t *connection, int nodeid,
                                   int portno, const char name[8])
{
    pscom_con_t *con = get_con(connection);
    pscom_err_t rc;

    pscom_lock();
    {
        rc = _pscom_con_connect_ondemand(con, nodeid, portno, name);
    }
    pscom_unlock();

    return rc;
}
