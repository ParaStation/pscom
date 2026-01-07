#
# ParaStation
#
# Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
# Copyright (C) 2021-2026 ParTec AG, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

add_library(pscom4extoll SHARED pscom_extoll.c psextoll.c)

target_include_directories(pscom4extoll PRIVATE ${EXTOLL_INCLUDE_DIRS})

target_link_libraries(pscom4extoll PRIVATE ${EXTOLL_RMA2_LIBRARY})

plugin_common(pscom4extoll)
