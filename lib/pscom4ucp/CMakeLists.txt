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
  pscom4ucp SHARED
  pscom_ucp.c
  psucp.c
)

target_include_directories(
  pscom4ucp
  PRIVATE ${UCP_INCLUDE_DIRS}
)

target_link_libraries(
  pscom4ucp
  PRIVATE ${UCP_LIBRARIES}
)

plugin_common(pscom4ucp)

#
# Static libpscom4ucp for utests
#
get_target_property(PSCOM4UCP_SOURCES		pscom4ucp SOURCES)
get_target_property(PSCOM4UCP_INCLUDE_DIRECTORIES	pscom4ucp INCLUDE_DIRECTORIES)
get_target_property(PSCOM4UCP_COMPILE_DEFINITIONS	pscom4ucp COMPILE_DEFINITIONS)
get_target_property(PSCOM4UCP_LINK_LIBRARIES	pscom4ucp LINK_LIBRARIES)

add_library(pscom4ucp-static STATIC
  EXCLUDE_FROM_ALL
  ${PSCOM4UCP_SOURCES}
  )
target_include_directories(pscom4ucp-static PRIVATE ${PSCOM4UCP_INCLUDE_DIRECTORIES})
target_compile_definitions(pscom4ucp-static PRIVATE ${PSCOM4UCP_COMPILE_DEFINITIONS})
target_link_libraries(pscom4ucp-static PRIVATE ${PSCOM4UCP_LINK_LIBRARIES})
if(CUDA_ENABLED)
  target_add_cuda(pscom4ucp-static)
endif(CUDA_ENABLED)
if(COVERAGE_ENABLED)
  target_compile_options(pscom-static PRIVATE --coverage)
  target_link_options(pscom-static PRIVATE --coverage)
endif(COVERAGE_ENABLED)
