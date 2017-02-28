/* (c) 2016-11-21 Jens Hauke <jens.hauke@4k2.de>              -*- linux-c -*- */
#ifndef _PSM1_COMPAT_H_
#define _PSM1_COMPAT_H_

#include "psm.h"
#include "psm_mq.h"

#define psm2_epaddr_t		psm_epaddr_t
#define psm2_mq_req_t		psm_mq_req_t
#define psm2_mq_status_t	psm_mq_status_t
#define psm2_uuid_t		psm_uuid_t
#define psm2_epid_t		psm_epid_t
#define psm2_ep_t		psm_ep_t
#define psm2_mq_t		psm_mq_t
#define psm2_error_t		psm_error_t

#define psm2_ep_open_opts	psm_ep_open_opts
#define psm2_ep_open_opts_get_defaults psm_ep_open_opts_get_defaults
#define psm2_ep_open		psm_ep_open

#define psm2_init		psm_init
#define psm2_error_get_string	psm_error_get_string
#define psm2_mq_init		psm_mq_init
#define psm2_mq_finalize	psm_mq_finalize
#define psm2_ep_connect		psm_ep_connect
#define psm2_mq_isend		psm_mq_isend
#define psm2_mq_send		psm_mq_send
#define psm2_mq_irecv		psm_mq_irecv
#define psm2_mq_ipeek		psm_mq_ipeek
#define psm2_mq_test		psm_mq_test

#define PSM2_OK			PSM_OK
#define PSM2_VERNO_MINOR	PSM_VERNO_MINOR
#define PSM2_VERNO_MAJOR	PSM_VERNO_MAJOR
#define PSM2_MQ_ORDERMASK_ALL	PSM_MQ_ORDERMASK_ALL
#define PSM2_MQ_REQINVALID	PSM_MQ_REQINVALID
#define PSM2_MQ_INCOMPLETE	PSM_MQ_INCOMPLETE

#endif /* _PSM1_COMPAT_H_ */
