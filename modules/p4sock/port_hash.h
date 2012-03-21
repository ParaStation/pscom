/*
 * ParaStation
 *
 * Copyright (C) 2002-2004 ParTec AG, Karlsruhe
 * Copyright (C) 2005 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Jens Hauke <hauke@par-tec.com>
 */

#ifndef _PORT_HASH_H_
#define _PORT_HASH_H_


#define PortTblHashSize 16

typedef struct PortInfo_T{
    struct PortInfo_T	*NextHash;
    struct PortSockId_T{
	UINT32		dport;
	UINT32		daddr;
	UINT32		sport;
	UINT32		saddr;
    }sid;
    struct wait_queue	*waitq;
    int			usecnt;
    char		*data;
    int			datalen;
    int			dataoff;
    int			dataavail;
}PortInfo_t;

typedef struct PortSockId_T PortSockId_t;

struct HashTablPortInfo_T{
    struct PortInfo_T *Entrys[PortTblHashSize];
};





void HashPortInfoInit(struct HashTablPortInfo_T *hashtabl);

void PortInfoEnq(struct HashTablPortInfo_T *ht,PortInfo_t *entry);

PortInfo_t *PortInfoDeq(struct HashTablPortInfo_T *ht,
			UINT32 dport,UINT32 daddr,UINT32 sport,UINT32 saddr);

static inline
PortInfo_t *PortInfoDeq2(struct HashTablPortInfo_T *ht,PortInfo_t *pi)
{
    return PortInfoDeq(ht,pi->sid.dport,pi->sid.daddr,pi->sid.sport,pi->sid.saddr);
}

PortInfo_t *PortInfoFind(struct HashTablPortInfo_T *ht,
			 UINT32 dport,UINT32 daddr,UINT32 sport,UINT32 saddr);


PortInfo_t *PortInfoAlloc(void);
void PortInfoFree(PortInfo_t *pi);

/* compare entry with data */
#define HashPortInfoCompare(entry,_dport,_daddr,_sport,_saddr)	\
 ((entry->sid.sport == (_sport))&&(entry->sid.dport==(_dport))&&		\
  (entry->sid.daddr == (_daddr))&&(entry->sid.saddr==(_saddr)))




#endif /* _PORT_HASH_H_ */
