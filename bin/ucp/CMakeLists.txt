#
# ParaStation
#
# Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
# Copyright (C) 2021-2024 ParTec AG, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

if(UCP_ENABLED)
  if(POPT_ENABLED)
    add_executable(ucp_pp ucp_pp.c)
    target_include_directories(
      ucp_pp
      PRIVATE ${UCP_INCLUDE_DIRS}
      PRIVATE ${POPT_INCLUDE_DIRS}
      PRIVATE ${PROJECT_BINARY_DIR}/include
      PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom
      PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom4ucp
      )

    target_link_libraries(
      ucp_pp
      PRIVATE ${UCP_LIBRARIES}
      PRIVATE ${POPT_LIBRARIES}
      )
  endif(POPT_ENABLED)
endif(UCP_ENABLED)
