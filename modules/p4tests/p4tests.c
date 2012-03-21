#include <linux/slab.h>
#include <asm/uaccess.h>
//#include <linux/mm.h>
#include <linux/poll.h>
#define P4_NR_RUNNING noneed
//#include "jmif.h"

#include "p4s_debug.h"
#include "p4rel.h"
#include "p4prot.h"
#include "p4local.h"
#include "p4ether.h"
#include "p4dummy.h"
#include "p4proc.h"



/* stdio.h must be after all kernel includes !!! */
#include <stdio.h>

int main(int argc, char **argv)
{
    p4_spinlock_t lock;

    lock = P4_SPIN_LOCK_UNLOCKED;

    if (SPIN_TRYLOCK(&lock)) {
	if (SPIN_TRYLOCK(&lock)) {
	    printf("%s:%d: Error: Test failed, SPIN_TRYLOCK works two times!\n", __FILE__, __LINE__);
	    return 1;
	} else {
	    printf("SPIN_TRYLOCK works.\n");
	}
    } else {
	printf("%s:%d: Test failed, SPIN_TRYLOCK failed!\n", __FILE__, __LINE__);
	return 1;
    }

    return 0;
}
