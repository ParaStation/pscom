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
#ifndef _PSCOM_PRECON_H_
#define _PSCOM_PRECON_H_

#include <stdint.h>

#include "list.h"
#include "pscom.h"
#include "pscom_plugin.h"
#include "pscom_types.h"

#define PSCOM_INFO_FD_ERROR                                                    \
    0x0ffffe /* int errno; Pseudo message. Error in read(). */
#define PSCOM_INFO_FD_EOF 0x0fffff /* Pseudo message fd got EOF */

#define PSCOM_INFO_EOF 0x100000 /* Last info message */
// #define PSCOM_INFO_ANSWER	0x100001	/* request remote side, to send
// answers */
#define PSCOM_INFO_CON_INFO 0x100002 /* pscom_info_con_info_t; */
#define PSCOM_INFO_VERSION                                                     \
    0x100003 /* pscom_info_version_t;	Supported version range */
#define PSCOM_INFO_CON_INFO_DEMAND                                             \
    0x100004 /* pscom_info_con_info_t; On demand connect request. */
#define PSCOM_INFO_BACK_CONNECT                                                \
    0x100005 /* pscom_info_con_info_t; Request a back connect */
#define PSCOM_INFO_BACK_ACK 0x100006 /* null; Ack a back_connect */
#define PSCOM_INFO_ARCH_REQ                                                    \
    0x100010 /* pscom_info_arch_req_t;	Request to connect with .arch_id */
#define PSCOM_INFO_ARCH_OK    0x100011 /* Use last requested arch */
#define PSCOM_INFO_ARCH_NEXT  0x100012 /* Try next arch */
#define PSCOM_INFO_ARCH_STEP1 0x100013
#define PSCOM_INFO_ARCH_STEP2 0x100014
#define PSCOM_INFO_ARCH_STEP3 0x100015
#define PSCOM_INFO_ARCH_STEP4 0x100016

#define MAGIC_PRECON 0x4a656e73

typedef enum {
    PSCOM_PRECON_TYPE_TCP    = 0,
    PSCOM_PRECON_TYPE_RRCOMM = 1,
    PSCOM_PRECON_TYPE_COUNT
} pscom_precon_type_t;


/* common part of tcp and rrcomm plugin, used for general precon functions */
typedef struct PSCOM_precon {
    unsigned long magic;

    /* state information */
    pscom_plugin_t *plugin;      // The plugin handling the handshake messages
                                 // (==plugin_cur or NULL)
    pscom_plugin_t *_plugin_cur; // Current plugin iterator (used to loop
                                 // through all plugins)

    struct list_head next; // add to precon plugin list
    char precon_data[0];
} pscom_precon_t;


/* Global pre-connection struct containing shared functions and variables. Used
 * for the initial TCP or RRcomm handshaking. Global RRcomm variables will be
 * added here.
 */
typedef struct PSCOM_precon_provider {
    struct list_head precon_list; // List of precon objests, either tcp or rrcom
    int precon_count;
    pscom_precon_type_t precon_type;
    void (*init)(void);
    void (*send)(pscom_precon_t *precon, unsigned type, void *data,
                 unsigned size);
    pscom_precon_t *(*create)(pscom_con_t *con);
    void (*destroy)(pscom_precon_t *precon);
    void (*recv_start)(pscom_precon_t *precon);
    void (*recv_stop)(pscom_precon_t *precon);
    int (*connect)(pscom_con_t *con, int nodeid, int portno);
    int (*guard_setup)(pscom_precon_t *precon);
    char precon_provider_data[0];
} pscom_precon_provider_t;

extern pscom_precon_provider_t pscom_precon_provider;


#define VER_FROM 0x0200
#define VER_TO   0x0200

typedef struct {
    /* supported version range from sender,
       overlap must be non empty. */
    uint32_t ver_from;
    uint32_t ver_to;
} pscom_info_version_t;


typedef struct {
    unsigned int arch_id;
} pscom_info_arch_req_t;


typedef struct {
    pscom_con_info_t con_info;
} pscom_info_con_info_t;

/* initialize the precon module */
void pscom_precon_init(void);
void pscom_precon_provider_init(void);

/* Send a message of type type */
void pscom_precon_send(pscom_precon_t *precon, unsigned type, void *data,
                       unsigned size);

/* Send a PSCOM_INFO_ARCH_NEXT message and disable current plugin */
void pscom_precon_send_PSCOM_INFO_ARCH_NEXT(pscom_precon_t *precon);

/* Print handshake information */
const char *pscom_info_type_str(int type);

void pscom_precon_info_dump(pscom_precon_t *precon, char *op, int type,
                            void *data, unsigned size);

/* select and try plugin for connection */
void plugin_connect_next(pscom_con_t *con);

void plugin_connect_first(pscom_con_t *con);

pscom_precon_t *pscom_precon_create(pscom_con_t *con);

void pscom_precon_destroy(pscom_precon_t *precon);

static inline void pscom_precon_recv_start(pscom_precon_t *precon)
{
    pscom_precon_provider.recv_start(precon);
}

static inline void pscom_precon_recv_stop(pscom_precon_t *precon)
{
    pscom_precon_provider.recv_stop(precon);
}

static inline int pscom_precon_connect(pscom_con_t *con, int nodeid, int portno)
{
    return pscom_precon_provider.connect(con, nodeid, portno);
}

static inline int pscom_precon_guard_setup(pscom_precon_t *precon)
{
    return pscom_precon_provider.guard_setup(precon);
}

#endif /* _PSCOM_PRECON_H_ */
