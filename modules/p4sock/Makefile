#							-*- Makefile -*-

obj-m		+= p4sock.o

p4sock-objs	:= p4sockets.o p4prot.o p4rel.o
p4sock-objs	+= ps_develop.o p4proc.o
p4sock-objs	+= p4dummy.o p4local.o p4ether.o

EXTRA_CFLAGS	+= -I$(P4_TOP_SRCDIR)/include

VER:=$(shell cd $(P4_TOP_SRCDIR) && scripts/vcversion)
EXTRA_CFLAGS	+= "-DP4_VERSION=\"$(VER)\""

KDIR=.
#  P4_NR_RUNNING should be:
#  "nr_running"   : vanilla 2.4.x kernels and suse/redhat up to 2.4.18 (?)
#                   nr_running is: int nr_running
#  "nr_running()" : suse/redhat 2.4.19
#                   nr_running is: unsigned long nr_running(void)
#  "1000"         : suse/redhat >= 2.4.20, all 2.2.x and 2.6.x
#                   no EXPORT_SYMBOL(nr_running) (never poll)
P4_NR_RUNNING:=$(shell										\
	noexport=`grep -sq 'EXPORT_SYMBOL(nr_running)' $(KDIR)/kernel/ksyms.c;echo $$?`;	\
	noint=`grep -sq 'int nr_running' $(KDIR)/kernel/fork.c;echo $$?`;			\
	nofunc=`grep -sq 'unsigned long nr_running' $(KDIR)/kernel/sched.c;echo $$?`;		\
	case $${noexport}$${noint}$${nofunc} in							\
	    ("101"|"110") echo "1000";;								\
	    ("010") echo "\"nr_running()\"";;							\
	    ("001") echo "nr_running";;								\
	    (*) echo "1000";;									\
	esac;											\
)
ifneq ($(P4_NR_RUNNING),unknown_nr_running_in_this_kernel)
EXTRA_CFLAGS += -DP4_NR_RUNNING=$(P4_NR_RUNNING)
endif

-include ../Makefile.compat
