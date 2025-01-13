/*
 * ParaStation
 *
 * Copyright (C) 2008-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2025 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */
/*
  Check for gcc bug first seen in
  gcc (SUSE Linux) 4.3.1 20080507 (prerelease) [gcc-4_3-branch revision 135036]
  (openSUSE 11.0 (i586))
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <math.h>

struct list_head {
    struct list_head *next, *prev;
};

struct list_head ioq;


static void deq(void)
{
    /* fprintf(stderr, "%s: head %p %p %p\n", __func__, &ioq, ioq.next,
     * ioq.prev);*/
    while (ioq.next != &ioq) {
        struct list_head *h = ioq.next;
        h->prev->next       = h->next;
        h->next->prev       = h->prev;
    }
    /* fprintf(stderr, "%s: head %p %p %p\n", __func__, &ioq, ioq.next,
     * ioq.prev);*/
}


static void sig_alarm(int sig)
{
    fprintf(stderr, "\nError: GCC bug detected (see list_test.c)\n");
    fprintf(stderr, "choose a different compiler version!\n\n");
    exit(1);
}


int main(int argc, char **argv)
{
    struct list_head r;

    ioq.next = &r;
    r.next   = &ioq;

    ioq.prev = &r;
    r.prev   = &ioq;

    signal(SIGALRM, sig_alarm);
    alarm(2);

    deq();

    return 0;
}

/* clang-format off
 *
 * Local Variables:
 *  compile-command: "gcc list_test.c -g -Wall -W -Wno-unused -O2 -o list_test * && ./list_test"
 * End:
 *
 * clang-format on
 */
