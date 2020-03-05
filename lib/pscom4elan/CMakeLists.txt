#
# ParaStation
#
# Copyright (C) 2020 ParTec Cluster Competence Center GmbH, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

add_library(
  pscom4elan SHARED
  pscom_elan.c
  pselan.c
)

target_include_directories(
  pscom4elan
  PRIVATE ${ELAN_INCLUDE_DIRS}
)

target_link_libraries(
  pscom4elan
  PRIVATE ${ELAN_LIBRARIES}
)

plugin_common(pscom4elan)
