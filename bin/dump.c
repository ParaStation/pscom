/*
 * 2001-01-22 Jens Hauke <hauke@wtal.de>
 *
 */
/*************************************************************fdb*
 * include for debugging
 * void dump( void * addr, int offset, int len,int allign,
 *	   int cols, char * desc );
 *
 *************************************************************fde*/


#ifndef _DUMP_C_
#define _DUMP_C_

#ifdef __KERNEL__
#include <linux/ctype.h>
#define __PRINT printk
#else
#include <ctype.h>
#define __PRINT printf
#endif

#ifdef DUMP_PREFIX
DUMP_PREFIX
#endif
void dump(void *addr, int offset, int len, int allign, int cols, char *desc)
{
    int line[100];
    int i;
    int lbeg;
    int end;

    if (cols > 100) { cols = 100; }
    if (desc) { __PRINT("%s: %p\n", desc, addr); }

    lbeg = offset - ((offset + cols - allign) % cols);
    end  = offset + len;
    while (lbeg < end) {
        __PRINT("%08x ", lbeg);
        for (i = 0; i < cols; i++) {
            if ((lbeg < offset) || (lbeg >= end)) {
                line[i] = -1;
            } else {
                line[i] = ((unsigned char *)addr)[lbeg];
            }
            lbeg++;
        }
        for (i = 0; i < cols; i++) {
            if (line[i] >= 0) {
                __PRINT("%02x", line[i]);
            } else {
                __PRINT("  ");
            }
            __PRINT("%s", (i % 4 != 3) ? " " : "  ");
            //	    __PRINT("%s",(i%4!=3)?" ": (i%8!=7)?:"  ":"   ");
        }
        //__PRINT(":");
        for (i = 0; i < cols; i++) {
            if (line[i] >= 0) {
                __PRINT("%c", isprint(line[i]) ? line[i] : '.');
            } else {
                __PRINT(" ");
            }
            //	    __PRINT("%s",i%4!=3?" ":i%8!=7?:"  ":"   ");
        }
        __PRINT("\n");
    }
}

#endif

#if 0

int main(int argc,char *argv[]){
    dump(argv,0x101,120, 1,15,"test");
    return 0;

}


#endif
