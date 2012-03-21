# $Id$

obj-m += e1000.o

e1000-objs	:= e1000_main.o e1000_hw.o e1000_ethtool.o
e1000-objs	+= e1000_param.o
# e1000_proc.o
e1000-objs	+= kcompat.o
EXTRA_CFLAGS += -I$(P4_TOP_SRCDIR)/include -DE1000_NO_NAPI

-include ../Makefile.compat
