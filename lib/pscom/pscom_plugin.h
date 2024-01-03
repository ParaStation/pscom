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

#ifndef _PSCOM_PLUGIN_H_
#define _PSCOM_PLUGIN_H_

#define PSCOM_PLUGIN_VERSION 0x0203

typedef struct pscom_plugin {
    char name[8];
    unsigned int version;   // must be equal to PSCOM_PLUGIN_VERSION
    unsigned int arch_id;   // PSCOM_ARCH_xyz
    unsigned int priority;  // default priority (0 == disabled, prefer higher
                            // values)
    unsigned int user_prio; // (0 == disabled, prefer higher values) Set by env
                            // PSP_{ARCH}

    void (*init)(void);
    void (*destroy)(void);
    void (*sock_init)(pscom_sock_t *sock);
    void (*sock_destroy)(pscom_sock_t *sock);

    int (*con_init)(pscom_con_t *con); // return 0, if init succeeded, -1 for
                                       // errors or disabled plugins.
    void (*con_handshake)(pscom_con_t *con, int type, void *data, unsigned size);

    struct list_head next;
} pscom_plugin_t;


/* Load and initialize all plugins. (also called by pscom_plugins_sock_init())
 */
void pscom_plugins_init(void);
void pscom_plugins_destroy(void);

void pscom_plugins_sock_init(pscom_sock_t *sock);
void pscom_plugins_sock_destroy(pscom_sock_t *sock);

pscom_plugin_t *pscom_plugin_by_name(const char *arch);
pscom_plugin_t *pscom_plugin_by_archid(unsigned int arch_id);

/* return first plugin or NULL */
pscom_plugin_t *pscom_plugin_first(void);
/* return cur's next plugin or NULL. If cur == NULL return NULL */
pscom_plugin_t *pscom_plugin_next(pscom_plugin_t *cur);

extern struct list_head pscom_plugins;

#endif /* _PSCOM_PLUGIN_H_ */
