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

if(OPENIB_ENABLED)
  if(POPT_ENABLED)
    function(openib_target target firstsrc)
      add_executable(
        ${target}
        ${firstsrc} ${PROJECT_SOURCE_DIR}/lib/pscom/pscom_dprint.c
        ${PROJECT_SOURCE_DIR}/lib/pscom/pscom_env.c
        ${PROJECT_SOURCE_DIR}/lib/pscom/pslib.c)

      add_dependencies(${target} vc_version)

      target_link_libraries(
        ${target}
        PRIVATE ${IBVERBS_LIBRARIES}
        PRIVATE ${POPT_LIBRARIES}
        PRIVATE dl)

      target_include_directories(
        ${target}
        PRIVATE ${IBVERBS_INCLUDE_DIRS}
        PRIVATE ${POPT_INCLUDE_DIRS}
        PRIVATE ${PROJECT_BINARY_DIR}/include
        PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom
        PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom4openib)
    endfunction()

    openib_target(openib_pp openib_pp.c)
    openib_target(openib_ud_pp openib_ud_pp.c)
  endif(POPT_ENABLED)
endif(OPENIB_ENABLED)
