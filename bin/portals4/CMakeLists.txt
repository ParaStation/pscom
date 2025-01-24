#
# ParaStation
#
# Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
# Copyright (C) 2021-2025 ParTec AG, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

if(PORTALS4_ENABLED)
  add_executable(portals4_pp portals4_pp.c)
  target_include_directories(
    portals4_pp
    PRIVATE ${PORTALS4_INCLUDE_DIRS}
    PRIVATE ${PROJECT_BINARY_DIR}/include
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom)
  target_link_libraries(portals4_pp PRIVATE ${PORTALS4_LIBRARIES})
endif(PORTALS4_ENABLED)
