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
/**
 * elan_pp_lowlevel.c: PingPong over quadrics elan interfac
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <fcntl.h>
#include <assert.h>
#include <popt.h>
#include <ctype.h>

#include <elan/elan.h>


int arg_loops = 1024;
int arg_maxtime = 3000;
#define MAX_MSIZE (4 * 1024 * 1024)
int arg_maxmsize = MAX_MSIZE;
int arg_verbose = 0;

static
void parse_opt(int argc, char **argv)
{
	int c;
	poptContext optCon;
	const char *no_arg;

	struct poptOption optionsTable[] = {
		{ "loops"  , 'n', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_loops , 0, "pp loops", "count" },
		{ "time"  , 't', POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_maxtime, 0, "max time", "ms" },
		{ "maxsize"  , 0, POPT_ARGFLAG_SHOW_DEFAULT | POPT_ARG_INT,
		  &arg_maxmsize , 0, "maximal messagesize", "size" },
		{ "verbose"	, 'v', POPT_ARG_NONE,
		  NULL		, 'v', "increase verbosity", NULL },
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext(NULL, argc, (const char **) argv, optionsTable, 0);

	// poptSetOtherOptionHelp(optCon, "[serveraddr]");

	while ((c = poptGetNextOpt(optCon)) >= 0) {
		switch (c) { // c = poptOption.val;
		case 'v': arg_verbose++; break;
		}
	}

	if (c < -1) { /* an error occurred during option processing */
		fprintf(stderr, "%s: %s\n",
			poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
			poptStrerror(c));
		poptPrintHelp(optCon, stderr, 0);
		exit(1);
	}

//	arg_1 = poptGetArg(optCon);
//	arg_2 = poptGetArg(optCon);

	no_arg = poptGetArg(optCon); // should return NULL
	if (no_arg) {
		fprintf(stderr, "%s: %s\n",
			no_arg, poptStrerror(POPT_ERROR_BADOPT));
		poptPrintHelp(optCon, stderr, 0);
		exit(1);
	}

	poptFreeContext(optCon);
}


#define MIN(a,b)      (((a)<(b))?(a):(b))
#define MAX(a,b)      (((a)>(b))?(a):(b))

#include <sys/time.h>

static inline
unsigned long getusec(void)
{
	struct timeval tv;
	gettimeofday(&tv,NULL);
	return (tv.tv_usec+tv.tv_sec*1000000);
}


typedef struct msg_buf
{
	char _buf_[MAX_MSIZE];
	char buf[0];
#define TAIL_SIZE 8
	volatile uint32_t len;
	volatile uint32_t mark;
} msg_buf_t;


static
void idle(void)
{
	volatile unsigned y;
	y++;
//	sched_yield();
}

#define RANK_CLIENT 1
#define RANK_SERVER 0

msg_buf_t *s_buf;
msg_buf_t *r_buf;
msg_buf_t *remote_rbuf;
ELAN_BASE *base = NULL;
unsigned my_rank = 0xffffffff;

static
void init_bufs(void)
{
	s_buf = malloc(sizeof(*s_buf));
	r_buf = malloc(sizeof(*r_buf));

	memset(s_buf->_buf_, 52, sizeof(s_buf->_buf_));
	memset(r_buf->_buf_, 52, sizeof(r_buf->_buf_));

	r_buf->mark = 0;
	s_buf->mark = 0;

//	remote_rbuf = ?;
}


static
void init(void)
{
	int rc;
	if (!getenv("LIBELAN_MACHINES_FILE")) {
		printf("set?\nexport LIBELAN_MACHINES_FILE=elanidmap\n\n");
	}

	base = elan_baseInit(0);
	my_rank = base->state->vp;
	printf("My Rank:%2u from %2u\n", my_rank, base->state->nvp);
	assert(base->state->nvp >= 2);

	init_bufs();

	printf("r_buf:           %p\n", r_buf);
	printf("remote r_buf?\n");
	rc = scanf("%p", &remote_rbuf);
	assert(rc == 1);

	printf("Accept r_buf: %p\n", remote_rbuf);
}




static
void run_pp_server(void)
{
	ELAN_EVENT *event = NULL;

	while (1) {
		while (r_buf->mark != 1) idle();

		unsigned len = r_buf->len;

		//memcpy(s_buf->buf - len, r_buf->buf - len, len);

		s_buf->len = len;
		s_buf->mark = 1;
		r_buf->mark = 0;

		event = elan_put(base->state,
				 s_buf->buf - len,
				 remote_rbuf->buf - len,
				 len + TAIL_SIZE,
				 RANK_CLIENT);

		elan_wait(event, base->waitType);
	}

}


static
int run_pp_c(int msize, int loops)
{
	int cnt;
	assert(msize <= MAX_MSIZE);

	ELAN_EVENT *event = NULL;

	for (cnt = 0; cnt < loops; cnt++) {
		unsigned len = msize;

		s_buf->len = len;
		s_buf->mark = 1;
		r_buf->mark = 0;

		event = elan_put(base->state,
				 s_buf->buf - len,
				 remote_rbuf->buf - len,
				 len + TAIL_SIZE,
				 RANK_SERVER);
		elan_wait(event, base->waitType);
		while (r_buf->mark != 1) idle();
	}
	return 0;
}


static
void do_pp_client(void)
{
	unsigned long t1, t2;
	double time;
	double throuput;
	unsigned int msgsize;
	double ms;
	int res;
	double loops = arg_loops;

	printf("%7s %8s %8s %8s\n", "msize", "loops", "time", "throughput");
	printf("%7s %8s %8s %8s\n", "[bytes]", "[cnt]", "[us/cnt]", "[MB/s]");
	for (ms = 1.4142135; ms < arg_maxmsize; ms = ms * 1.4142135) {
		unsigned int iloops = loops;
		msgsize = ms + 0.5;

		/* warmup, for sync */
		run_pp_c(2, 2);

		t1 = getusec();
		res = run_pp_c(msgsize, iloops);
		t2 = getusec();

		time = (double)(t2 - t1) / (iloops * 2);
		throuput = msgsize / time;
		if (res == 0) {
			printf("%7d %8d %8.2f %8.2f\n", msgsize, iloops, time, throuput);
			fflush(stdout);
		} else {
			printf("Error in communication...\n");
		}

		{
			double t = (t2 - t1) / 1000;
			while (t > arg_maxtime) {
				loops = loops / 1.4142135;
				t /= 1.4142135;
			}
			if (loops < 1) loops = 1;
		}
	}

	return;
}


int main(int argc, char **argv)
{
	parse_opt(argc, argv);

	init();

	if (my_rank == RANK_SERVER) { // server
		run_pp_server();
	} else if (my_rank == RANK_CLIENT) {
		do_pp_client();
	} else {
		printf("Unkown rank:%d\n", my_rank);
		exit(1);
	}

	return 0;
}
