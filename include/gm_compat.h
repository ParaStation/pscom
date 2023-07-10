#ifndef _GM_COMPAT_H_
#define _GM_COMPAT_H_

#include <gm.h>

#if GM_API_VERSION < 0x200
static gm_status_t gm_global_id_to_node_id(struct gm_port *port,
                                           unsigned int global_id,
                                           unsigned int *node_id)
{
    if (node_id) { *node_id = global_id; }
    return GM_SUCCESS;
}

static gm_status_t gm_node_id_to_global_id(struct gm_port *port,
                                           unsigned int node_id,
                                           unsigned int *global_id)
{
    if (global_id) { *global_id = node_id; }
    return GM_SUCCESS;
}

#endif

#endif /* _GM_COMPAT_H_ */
