#
# ParaStation
#
# Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
# Copyright (C) 2021      ParTec Cluster Competence Center GmbH, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

add_library(pscom4openib SHARED pscom_openib.c psoib.c)

target_include_directories(pscom4openib PRIVATE ${IBVERBS_INCLUDE_DIRS})

target_link_libraries(pscom4openib PRIVATE ${IBVERBS_LIBRARIES})

plugin_common(pscom4openib)
