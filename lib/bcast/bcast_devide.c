/*
 * ParaStation
 *
 * Copyright (C) 2008-2021 ParTec Cluster Competence Center GmbH, Munich
 * Copyright (C) 2021-2026 ParTec AG, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <math.h>

static const unsigned bcast_devide = 3; // ToDo: make it configurable/
                                        // messagelen dependant


typedef struct bcast_rank_iter {
    unsigned group_size;
    unsigned delta;
    unsigned med;
} bcast_rank_iter_t;


static inline unsigned bcast_rank_iter_begin(bcast_rank_iter_t *iter,
                                             unsigned group_size,
                                             unsigned devide)
{
    unsigned delta = (group_size) / devide;

    unsigned g1  = group_size - delta * devide;
    unsigned med = g1 * (delta + 1);

    iter->group_size = group_size;
    iter->delta      = delta;
    iter->med        = med;

    return 0;
}


static inline unsigned bcast_rank_iter_end(bcast_rank_iter_t *iter)
{
    return iter->group_size;
}


static inline unsigned bcast_rank_iter_next(bcast_rank_iter_t *iter,
                                            unsigned rank)
{
    return rank + iter->delta + (rank < iter->med);
}


static void send_ranks(unsigned int rank_first, unsigned int subgroup_size,
                       unsigned int group_size)
{
    bcast_rank_iter_t iter;
    unsigned urank;

    printf("#%2d(%2d) -> ", rank_first, subgroup_size);

    for (urank = bcast_rank_iter_begin(&iter, subgroup_size, bcast_devide);
         urank != bcast_rank_iter_end(&iter);
         urank = bcast_rank_iter_next(&iter, urank)) {
        unsigned rank  = (rank_first + urank) % group_size;
        unsigned delta = bcast_rank_iter_next(&iter, urank) - urank;

        printf(",  %2d-%2d", rank, rank + delta - 1);
    }
    printf("\n");
}


static void _gcompat_init(unsigned recvs[], unsigned my_rank,
                          unsigned group_size, unsigned devide)
{
    unsigned urank, urank_next;
    bcast_rank_iter_t iter;

    for (urank = bcast_rank_iter_begin(&iter, group_size - 1, devide);
         urank != bcast_rank_iter_end(&iter); urank = urank_next) {
        urank_next = bcast_rank_iter_next(&iter, urank);

        unsigned dest      = urank + my_rank + 1;
        unsigned dest_size = urank_next - urank;

        recvs[dest] = my_rank;

        _gcompat_init(recvs, dest, dest_size, devide);
    }
}


int main(int argc, char **argv)
{
    unsigned subg;

    for (subg = 0; subg < 50; subg++) { send_ranks(10, subg, 100); }


#define count 20
    unsigned recvs[count];
    recvs[0] = (unsigned)-1;
    _gcompat_init(recvs, 0, count, 3);

    unsigned i;
    for (i = 0; i < count; i++) { printf("#%2d from %2d\n", i, recvs[i]); }

    return 0;
}

/* clang-format off
 *
 * Local Variables:
 *  compile-command: "gcc bcast_devide.c -Wall -W -Wno-unused -O2 -o bcast_devide && ./bcast_devide"
 * End:
 *
 * clang-format on
 */
