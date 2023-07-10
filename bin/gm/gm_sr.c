/*
 * ParaStation
 *
 * Copyright (C) 2003,2004 ParTec AG, Karlsruhe
 * Copyright (C) 2004-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2023 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include "gm_compat.h"
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>


typedef unsigned int uint32;

volatile int send_in_transit = 0;

void send_callb(struct gm_port *p, void *context, gm_status_t status)
{
    if (status == GM_SUCCESS) {
        send_in_transit--;
        //	printf("send ok.(%d)\n",send_in_transit);
    } else {
        printf("send not ok: %s.\n", gm_strerror(status));
    }
}

void recv_callb(struct gm_port *p, void *context, gm_status_t status)
{
    if (status == GM_SUCCESS)
        ;

    //    printf("send ok.\n");
    else {
        printf("send not ok: %s.\n", gm_strerror(status));
    }
}


uint32 get_time()
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    return (uint32)(tv.tv_sec * 1000000 + tv.tv_usec);
}

void gm_p_error(int code, char *desc)
{
    fprintf(stderr, "%s:%s.\n", desc ? desc : "", gm_strerror(code));
}


inline gm_recv_event_t *wait_for_msg(struct gm_port *port)
{
    gm_recv_event_t *event;
    while (1) {
        event = gm_blocking_receive(port);
        if (GM_RECV_EVENT_TYPE(event) == GM_RECV_EVENT) { return event; }
        gm_unknown(port, event);
    }
}

inline gm_recv_event_t *wait_for_event(struct gm_port *port)
{
    gm_recv_event_t *event;
    event = gm_blocking_receive(port);
    gm_unknown(port, event);
    return event;
}


int main(int argc, char **argv)
{

    gm_status_t status;
    struct gm_port *port;
    const unsigned max_size = 13;
    gm_size_t length;
#define nrbuf 8
#define nsbuf 28
    void *rbuffer[nrbuf] = {
        0,
    };
    void *sbuffer[nsbuf] = {
        0,
    };
    gm_recv_event_t *event;
    int sends               = 0;
    int const max_num_sends = 25000;
    int const our_length    = 8000;
    int arg_target_node     = (*argv[2] - '0');
    int arg_target_port     = (*argv[1] - '0');
    int i;

    uint32 t1, t2;

    if ((status = gm_init()) != GM_SUCCESS) {
        gm_p_error(status, "gm_init failed");
        exit(1);
    }

    if ((status = gm_open(&port, 0, *argv[1] - '0', "bla",
                          GM_API_VERSION_1_1)) != GM_SUCCESS) {
        gm_p_error(status, "gm_open failed");
        exit(1);
    }

    /* send buffer */

    length = gm_max_length_for_size(max_size);

    fprintf(stderr, "length is %d, our_length is %d.\n", (int)length,
            (int)our_length);


    fprintf(stderr, "Num SendTokens %u:\n",
            gm_send_token_available(port, GM_LOW_PRIORITY));
    fprintf(stderr, "Num RecvTokens %u:\n", gm_num_receive_tokens(port));

    for (i = 0; i < nsbuf; i++) {
        sbuffer[i] = gm_dma_malloc(port, length);
        if (!sbuffer[i]) {
            fprintf(stderr, "dma_alloc failed\n");
            exit(1);
        }
    }
    for (i = 0; i < nrbuf; i++) {
        /* receive buffer */
        rbuffer[i] = gm_dma_malloc(port, length);

        if (!rbuffer[i]) {
            fprintf(stderr, "dma_alloc failed\n");
            exit(1);
        }
        gm_provide_receive_buffer(port, rbuffer[i], max_size, GM_LOW_PRIORITY);
    }


    if (*argv[2] != 's') {
        int sendn = 0;
        t1        = get_time();
        for (sends = 0; sends < max_num_sends; sends++) {

            while (send_in_transit >= nsbuf) {
                event = wait_for_event(port);
                //		fprintf(stderr,".");fflush(stderr);
                //		usleep(10000);
            };

            gm_send_with_callback(port, sbuffer[sendn], max_size, our_length,
                                  GM_LOW_PRIORITY, arg_target_node,
                                  arg_target_port, send_callb, 0);

            send_in_transit++;
            //	    fprintf(stderr,"in_tran %d\n",send_in_transit);
            sendn = (sendn + 1) % nsbuf;
        }
        t2 = get_time();
        printf("Elapsed usec/send: %f  through %f\n",
               ((uint32)(t2 - t1)) / (1.0 * max_num_sends),
               (1.0 * our_length * max_num_sends) / ((uint32)(t2 - t1)));
    } else {
        int rcnt = 0;
        /* receiver */
        while (1) {
            event = wait_for_msg(port);
            gm_provide_receive_buffer(port, gm_ntohp(event->recv.buffer),
                                      max_size, GM_LOW_PRIORITY);
            rcnt++;
            //	    fprintf(stderr,"Recvcnt:%d\n",rcnt);
        }
    }
    return 0;
}
