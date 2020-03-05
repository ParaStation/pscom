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
  target_link_libraries(
    pscom
    PRIVATE cuda
  )
endif(CUDA_ENABLED)

install(TARGETS pscom DESTINATION "${CMAKE_INSTALL_LIBDIR}")
