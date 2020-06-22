#
# ParaStation
#
# Copyright (C) 2020 ParTec Cluster Competence Center GmbH, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

add_library(pscom SHARED
  pscom.c
  pscom_async.c
  pscom_con.c
  pscom_cuda.c
  pscom_debug.c
  pscom_dprint.c
  pscom_env.c
  pscom_group.c
  pscom_group_bcast.c
  pscom_io.c
  pscom_listener.c
  pscom_ondemand.c
  pscom_p4s.c
  pscom_plugin.c
  pscom_poll.c
  pscom_precon.c
  pscom_queues.c
  pscom_req.c
  pscom_shm.c
  pscom_sock.c
  pscom_str_util.c
  pscom_suspend.c
  pscom_tcp.c
  pscom_ufd.c
  pslib.c
  psshmalloc.c
)

add_dependencies(pscom vc_version)

target_include_directories(
  pscom
  PRIVATE .
  PRIVATE ${PROJECT_BINARY_DIR}/include

  PUBLIC  ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(
  pscom
  PRIVATE dl
  PRIVATE pthread
)

target_compile_definitions(
  pscom
  PRIVATE LIBPSCOM
  PRIVATE LIBDIR="${CMAKE_INSTALL_LIBDIR}"
)

target_compile_options(
  pscom
  PRIVATE -fvisibility=hidden
  PRIVATE -flto
)

target_link_options(
  pscom
  PRIVATE -flto
)

set_target_properties(pscom
  PROPERTIES
  VERSION "2.0.0"
  SOVERSION "2"
)


if(CUDA_ENABLED)
  target_add_cuda(pscom)
endif(CUDA_ENABLED)

install(TARGETS pscom DESTINATION "${CMAKE_INSTALL_LIBDIR}")


#
# Static libpscom for utests
#
get_target_property(PSCOM_SOURCES		pscom SOURCES)
get_target_property(PSCOM_INCLUDE_DIRECTORIES	pscom INCLUDE_DIRECTORIES)
get_target_property(PSCOM_COMPILE_DEFINITIONS	pscom COMPILE_DEFINITIONS)
get_target_property(PSCOM_LINK_LIBRARIES	pscom LINK_LIBRARIES)

add_library(pscom-static STATIC
  EXCLUDE_FROM_ALL
  ${PSCOM_SOURCES}
  )
add_dependencies(pscom-static vc_version)
target_include_directories(pscom-static PRIVATE ${PSCOM_INCLUDE_DIRECTORIES})
target_compile_definitions(pscom-static PRIVATE ${PSCOM_COMPILE_DEFINITIONS})
target_link_libraries(pscom-static PRIVATE ${PSCOM_LINK_LIBRARIES})
if(CUDA_ENABLED)
  target_add_cuda(pscom-static)
endif(CUDA_ENABLED)
if(COVERAGE_ENABLED)
  target_compile_options(pscom-static PRIVATE --coverage)
  target_link_options(pscom-static PRIVATE --coverage)
endif(COVERAGE_ENABLED)
