#
# ParaStation
#
# Copyright (C) 2018-2021 ParTec Cluster Competence Center GmbH, Munich
# Copyright (C) 2021      ParTec AG, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

all:

CPPFLAGS += -MMD
CFLAGS   += -Wall -W -Wno-unused-parameter -Wno-unused -g -O3 -shared -fPIC
LDFLAGS  += -g
LDLIBS += $(LDLIBS_$@)
#########################################################


CPPFLAGS += -I../pscom -I../../include -I. -DLIBDIR='"lib64"'
CPPFLAGS += -DPSCOM_ALLIN_PSM2
CPPFLAGS += -DPSCOM_ALLIN_OPENIB
PSCOM_OBJS = pscom_all.o
PSCOM_SONAME = libpscom.so.2

PROGS += libpscom.so $(PSCOM_SONAME)

$(PSCOM_SONAME): $(PSCOM_OBJS)
	$(CC) -shared $(LDFLAGS) $(PSCOM_OBJS) -o $@ -ldl -lpthread -Wl,-soname,$(PSCOM_SONAME)

libpscom.so:
	ln -s $(PSCOM_SONAME) $@


#########################################################

OBJECTS  += $(wildcard *.o)
DEPFILES := $(OBJECTS:.o=.d)
CLEAN    += $(patsubst .clean.%,%, $(wildcard .clean.*)) $(wildcard .clean.*)
CLEAN    += $(OBJECTS) $(DEPFILES)
MRPROPPER+= $(PROGS) $(wildcard *~)

all: $(PROGS)

clean:
	$(RM) $(CLEAN)

mrpropper distclean:
	$(RM) $(CLEAN) $(MRPROPPER)

-include $(DEPFILES) dummy.d
