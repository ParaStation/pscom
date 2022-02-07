/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2022 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/**
 * psport_gm.h: Header for GM communication
 */

#ifndef _PSGM_H_
#define _PSGM_H_

#include <sys/uio.h>

typedef struct gmport gmport_t;
typedef struct psgm_con_info psgm_con_info_t;

// contact endpoint info
typedef struct psgm_info_msg {
	unsigned int	remote_global_node_id;
	void		*remote_con_id;
	unsigned int	remote_port;
	int		error;
} psgm_info_msg_t;

int psgm_sendv(psgm_con_info_t *gmcon, const struct iovec *iov, int size);
void *psgm_recvlook(void **con_id, void **buf, unsigned int *size);
int psgm_recvdone(void *handle);

psgm_con_info_t *psgm_con_create(void);

int psgm_con_init(psgm_con_info_t *gmcon, gmport_t *gmport);
int psgm_con_connect(psgm_con_info_t *gmcon, gmport_t *gmport, psgm_info_msg_t *msg);

void psgm_con_cleanup(psgm_con_info_t *gmcon);
void psgm_con_free(psgm_con_info_t *gmcon);

void psgm_con_get_info_msg(psgm_con_info_t *gmcon, gmport_t *gm_port,
			   void *con_id, psgm_info_msg_t *msg);

int psgm_init(void);

extern int psgm_debug;

#endif /* _PSGM_H_ */
