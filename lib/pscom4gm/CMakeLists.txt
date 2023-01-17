#
# ParaStation
#
# Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
# Copyright (C) 2021-2023 ParTec AG, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

add_library(
  pscom4gm SHARED
  pscom_gm.c
  psgm.c
)

target_include_directories(
  pscom4gm
  PRIVATE ${GM_INCLUDE_DIRS}
)

target_link_libraries(
  pscom4gm
  PRIVATE ${GM_LIBRARIES}
)

plugin_common(pscom4gm)
