#
# ParaStation
#
# Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
# Copyright (C) 2021      ParTec AG, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

add_library(
  pscom4mxm SHARED
  pscom_mxm.c
  psmxm.c
)

target_include_directories(
  pscom4mxm
  PRIVATE ${MXM_INCLUDE_DIRS}
)

target_link_libraries(
  pscom4mxm
  PRIVATE ${MXM_LIBRARIES}
)

plugin_common(pscom4mxm)
