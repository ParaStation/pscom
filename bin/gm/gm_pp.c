/*
 * ParaStation
 *
 * Copyright (C) 2003,2004 ParTec AG, Karlsruhe
 * Copyright (C) 2004-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <unistd.h>
#include <stdlib.h>
#include "gm_compat.h"
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <popt.h>

static inline unsigned long getusec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_usec + tv.tv_sec * 1000000);
}


int arg_verbose     = 0;
int arg_client      = 0;
int arg_server      = 0;
int arg_loops       = 1000;
int arg_gmport      = 4;
int arg_target_node = -1;
int arg_target_port = 4;

void usage(poptContext optCon, int exitcode, char *error, char *addl)
{
    poptPrintUsage(optCon, stderr, 0);
    if (error) { fprintf(stderr, "%s: %s\n", error, addl); }
    exit(exitcode);
}

void parse_opt(int argc, char **argv)
{
    int c;              /* used for argument parsing */
    poptContext optCon; /* context for parsing command-line options */

    struct poptOption optionsTable[] = {
        {"verbose", 'v', POPT_ARG_INT, &arg_verbose, 0, "be more verbose",
         "level"},
        {"server", 's', POPT_ARGFLAG_OR, &arg_server, 0, "run as server", ""},
        {"client", 'c', POPT_ARGFLAG_OR, &arg_client, 0, "run as client", ""},
        {"gmport", 'p', POPT_ARG_INT, &arg_gmport, 0, "gm port (default 4)",
         "port"},
        /* POPT_ARG_LONG wont work and POPT_ARG_UINT dont exists.
           So we must use also negative global node id s. */
        {"gmdestnode", 'd', POPT_ARG_INT, &arg_target_node, 0,
         "gm destination node", "gid"},
        {"gmdestport", 0, POPT_ARG_INT, &arg_target_port, 0,
         "gm destination port (default 4)", "port"},
        {"loops", 'l', POPT_ARG_INT, &arg_loops, 0, "pp loops", "count"},
        /*	{ "flag" , 'f', POPT_ARGFLAG_OR, &arg_flag, 0,
                  "flag description", "" },*/
        POPT_AUTOHELP // Add help option
        {NULL, 0, 0, NULL, 0, NULL, NULL},
    };

    optCon = poptGetContext(NULL, argc, (const char **)argv, optionsTable, 0);

    if (argc < 2) {
        poptPrintUsage(optCon, stderr, 0);
        exit(1);
    }

    /* Now do options processing, get portname */
    while ((c = poptGetNextOpt(optCon)) >= 0) {}
    if (c < -1) {
        /* an error occurred during option processing */
        fprintf(stderr, "%s: %s\n",
                poptBadOption(optCon, POPT_BADOPTION_NOALIAS), poptStrerror(c));
        poptPrintHelp(optCon, stderr, 0);
        exit(1);
    }

    poptFreeContext(optCon);
}


void send_cb(struct gm_port *p, void *context, gm_status_t status)
{
    if (status == GM_SUCCESS) {
        //    printf("send ok.\n");
    } else {
        printf("send not ok: %s.\n", gm_strerror(status));
    }
}

void gm_p_error(int code, char *desc)
{
    fprintf(stderr, "%s:%s.\n", desc ? desc : "", gm_strerror(code));
}


inline gm_recv_event_t *wait_for_msg(struct gm_port *port)
{
    gm_recv_event_t *event;
    while (1) {
#if 1 /* Test for FAST... saves about 0.2 us */
#if 0
	event = gm_blocking_receive(port);
#else
        do {
            /* This polling (against gm_blocking_receive()) saves about 0.25
             * us!*/
            event = gm_receive(port);
        } while (gm_ntohc(event->recv.type) == GM_NO_RECV_EVENT);
#endif

        switch (gm_ntohc(event->recv.type)) {
        case GM_NO_RECV_EVENT: break;

        case GM_FAST_RECV_EVENT:
        case GM_FAST_HIGH_RECV_EVENT:
        case GM_FAST_PEER_RECV_EVENT:
        case GM_FAST_HIGH_PEER_RECV_EVENT:
            //	  fast = 1;
        case GM_RECV_EVENT:
        case GM_HIGH_RECV_EVENT:
        case GM_PEER_RECV_EVENT:
        case GM_HIGH_PEER_RECV_EVENT:
            //	  if (fast == 1) {
            //	      ptr = gm_ntohp(event->recv.message);
            //	  } else {
            //	      ptr = gm_ntohp(event->recv.buffer);
            //	  }
            return event;
        default:
            //	    printf("Event unknown %d\n", gm_ntohc(event->recv.type));
            gm_unknown(port, event);
        }
#else
        event = gm_blocking_receive(port);
        if (GM_RECV_EVENT_TYPE(event) == GM_RECV_EVENT) { return event; }
        gm_unknown(port, event);
#endif
    }
}

#define GMCALL(func, param)                                                    \
    do {                                                                       \
        gm_status_t _status_;                                                  \
        if ((_status_ = func param) != GM_SUCCESS) {                           \
            gm_p_error(_status_, #func " failed");                             \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

void print_global_nodeid(struct gm_port *port)
{
    unsigned int id, gid;
    int rc;
    gm_status_t status;

    /*
      The semantic change is as follows: The GM "node IDs" passed to and
      from the API are now local IDs that only have meaning only for ports
      on a single network interface card (NIC).  These value should not be
      passed over the network to ports associated with other NICs.  If a
      program needs to pass a node reference over the network, it can use
      gm_node_id_to_global_id() to generate 32-bit global IDs that can
      safely be passed around the network, but must be converted back to a
      local node ID on the receiver with gm_global_id_to_node_id().  (Global
      IDs should never be passed to other GM API functions.)  gm_unique_id's
      (NIC MAC addresses) and host names may be used similarly, but are more
      expensive.
    */
    GMCALL(gm_get_node_id, (port, &id));
    GMCALL(gm_node_id_to_global_id, (port, id, &gid));

    printf("local_id = %u global_node_id = %d\n", id, gid);
}

int main(int argc, char **argv)
{
#define RBUFS 1000 /* using more than 1 rbuffer saves 0.2 - 0.25 us */
#define SBUFS 10   /* using more sbuffers increase sometimes the time */
    gm_status_t status;
    struct gm_port *port;
    const int max_size = 13; /* stupid size param from gm. */
    gm_size_t length;
    void *r_buffer[RBUFS];
    void *s_buffer[SBUFS];
    gm_recv_event_t *event;
    int sends               = 0;
    unsigned int our_length = 8184;
    int numrtokens, numstokens;
    int i;
    int s_idx;
    //    int arg_target_node = (*argv[2]-'0');
    //    int arg_target_port = (*argv[1]-'0');

    unsigned long t1, t2;

    parse_opt(argc, argv);

    if ((!arg_server && !arg_client) || (arg_server && arg_client)) {
        printf("run as server or client? (-s or -c)\n");
        exit(1);
    }

    if (gm_max_length_for_size(max_size) < our_length) {
        printf("gm_max_length_for_size(max_size) < our_length!!!\n");
        //	exit(1);
    }

    GMCALL(gm_init, ());

    GMCALL(gm_open, (&port, 0, arg_gmport, "bla", GM_API_VERSION));

    GMCALL(gm_allow_remote_memory_access, (port));


    /* send buffer */
#if 0
    for (i = 0; i < 30; i++) {
	printf("gm_max_length_for_size(%4d) = %4d\n",
	       i, (int)gm_max_length_for_size(i));
    }
#endif

    //    length=gm_max_length_for_size(max_size); /* whats this? */
    length = 4096; /* warning */

    fprintf(stderr, "length is %d, our_length is %d.\n", (int)length,
            (int)our_length);

    numrtokens = gm_num_receive_tokens(port);
    numrtokens = numrtokens > RBUFS ? RBUFS : numrtokens;
    fprintf(stderr, "rtokens: %d.\n", numrtokens);
    numstokens = gm_num_send_tokens(port) - 1;
    numstokens = numstokens > SBUFS ? SBUFS : numstokens;
    fprintf(stderr, "stokens: %d.\n", numstokens);

    /* send buffer */
    for (i = 0; i < numstokens; i++) {
        s_buffer[i] = gm_dma_malloc(port, length);
        if (!s_buffer[i]) {
            fprintf(stderr, "dma_alloc failed\n");
            exit(1);
        }
    }
    s_idx = 0;
    /* receive buffer */
    for (i = 0; i < numrtokens; i++) {
        r_buffer[i] = gm_dma_malloc(port, length);
        if (!r_buffer[i]) {
            fprintf(stderr, "dma_alloc failed\n");
            exit(1);
        }
        gm_provide_receive_buffer(port, r_buffer[i], max_size, GM_LOW_PRIORITY);
    }

    print_global_nodeid(port);

    if (arg_client) {
        int target_port = arg_target_port;
        unsigned int target_node;
        if (arg_target_node == -1) {
            printf("please set -gmdestnode (-d)!\n");
            exit(1);
        }
        GMCALL(gm_global_id_to_node_id, (port, arg_target_node, &target_node));
        printf("Destination is local_id %u, global_id %d\n", target_node,
               arg_target_node);

        while (our_length > 0) {
            t1 = getusec();
            for (sends = 0; sends < arg_loops; sends++) {
                gm_send_with_callback(port, s_buffer[s_idx], max_size,
                                      our_length, GM_LOW_PRIORITY, target_node,
                                      target_port, send_cb, 0);
                //	    printf("Send %d %d \n", max_size, our_length);
                s_idx = (s_idx + 1) % numstokens;
                event = wait_for_msg(port);
                gm_provide_receive_buffer(port, gm_ntohp(event->recv.buffer),
                                          max_size, GM_LOW_PRIORITY);
            }
            t2 = getusec();
            printf("Elapsed (Latency),loops %d len %5d usec/send: %f\n",
                   arg_loops, our_length,
                   (double)(t2 - t1) / (2.0 * arg_loops));
            our_length /= 2;
        }
    } else {
        while (1) {
            event = wait_for_msg(port);

            gm_send_with_callback(port, s_buffer[s_idx], max_size,
                                  gm_ntohl(event->recv.length), GM_LOW_PRIORITY,
                                  gm_ntohs(event->recv.sender_node_id),
                                  gm_ntohc(event->recv.sender_port_id), send_cb,
                                  0);
            //	    printf("Send %d %d \n", max_size,
            // gm_ntohl(event->recv.length));
            s_idx = (s_idx + 1) % numstokens;

            gm_provide_receive_buffer(port, gm_ntohp(event->recv.buffer),
                                      max_size, GM_LOW_PRIORITY);
        }
    }
    return 0;
}
