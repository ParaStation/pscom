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

#include <linux/malloc.h>

#include "pshal.h"
#include "port_hash.h"

/* calculate index in hashtable */
#define HashPortInfoIndx(dport,daddr,sport,saddr)	(((dport)+(daddr))%PortTblHashSize)

/*
 *  Initialize the hashtable
 */
void HashPortInfoInit(struct HashTablPortInfo_T *hashtabl)
{
    int i;
    for (i=0;i<PortTblHashSize;i++){
	hashtabl->Entrys[i]=NULL;
    }
}

/*
 *  Enq entry
 */
void PortInfoEnq(struct HashTablPortInfo_T *ht,PortInfo_t *entry){
    int idx=HashPortInfoIndx(entry->sid.dport,entry->sid.daddr,entry->sid.sport,entry->sid.saddr);
    entry->NextHash = ht->Entrys[idx];
    ht->Entrys[idx] = entry;
}


/*
 *  Find Entry with port and node and deq entry, return NULL if not found
 */
PortInfo_t *PortInfoDeq(struct HashTablPortInfo_T *ht,
				   UINT32 dport,UINT32 daddr,UINT32 sport,UINT32 saddr)
{
    int idx=HashPortInfoIndx(dport,daddr,sport,saddr);
    PortInfo_t *ret=ht->Entrys[idx];
    PortInfo_t **prev = &ht->Entrys[idx];

    while (ret){
	if (HashPortInfoCompare(ret,dport,daddr,sport,saddr)){
	    *prev = ret->NextHash;
	    ret->NextHash = NULL;
	    break;
	}
	prev=&ret->NextHash;
	ret=ret->NextHash;
    }
    return ret;
}

/*
 *  Find Entry with port and node, return NULL if not found
 */
PortInfo_t *PortInfoFind(struct HashTablPortInfo_T *ht,
			 UINT32 dport,UINT32 daddr,UINT32 sport,UINT32 saddr)
{
    int idx=HashPortInfoIndx(dport,daddr,sport,saddr);
    PortInfo_t *ret=ht->Entrys[idx];

    while (ret){
	if (HashPortInfoCompare(ret,dport,daddr,sport,saddr)){
	    break;
	}
	ret=ret->NextHash;
    }
    return ret;
}


PortInfo_t *PortInfoAlloc(void)
{
    PortInfo_t *ret;
    ret =(PortInfo_t*)kmalloc(sizeof(PortInfo_t),GFP_KERNEL);
    if (ret){
	ret->waitq = NULL;
	ret->data  = kmalloc(PSHAL_MSGSIZE,GFP_KERNEL);
	if (!ret->data)
	    goto do_err_nomem_data;
	ret->datalen=0;
	ret->dataoff=0;
	ret->usecnt=0;
	ret->dataavail=0;
    }
    return ret;
 do_err_nomem_data:
    kfree(ret);
    return 0;
}

void PortInfoFree(PortInfo_t *pi)
{
    wake_up(&pi->waitq);
    kfree(pi);
}
