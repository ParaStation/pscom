# $Id$

obj-m += bcm5700.o

bcm5700-objs    := b57um.o b57proc.o tigon3.o autoneg.o 5701rls.o tcp_seg.o b57diag.o

EXTRA_CFLAGS += -DDBG=0 -DT3_JUMBO_RCV_RCB_ENTRY_COUNT=256 -DNICE_SUPPORT
EXTRA_CFLAGS += -DPCIX_TARGET_WORKAROUND=1 -DINCLUDE_TBI_SUPPORT -DINCLUDE_5701_AX_FIX=1
EXTRA_CFLAGS += -I$(P4_TOP_SRCDIR)/include

-include ../Makefile.compat
