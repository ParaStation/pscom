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

if(PSM2_ENABLED)
  if(POPT_ENABLED)
    add_executable(psm2_pp psm2_pp.c)
    target_include_directories(
      psm2_pp
      PRIVATE ${PSM2_INCLUDE_DIRS}
      PRIVATE ${POPT_INCLUDE_DIRS}
      )

    target_link_libraries(
      psm2_pp
      PRIVATE ${PSM2_LIBRARIES}
      PRIVATE ${POPT_LIBRARIES}
      )

    add_executable(pscom4psm_pp pscom4psm_pp.c)
    target_include_directories(
      pscom4psm_pp
      PRIVATE ${PSM2_INCLUDE_DIRS}
      PRIVATE ${POPT_INCLUDE_DIRS}
      PRIVATE ${PROJECT_BINARY_DIR}/include
      PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom
      PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom4psm
      )

    target_link_libraries(
      pscom4psm_pp
      PRIVATE ${PSM2_LIBRARIES}
      PRIVATE ${POPT_LIBRARIES}
      )
  endif(POPT_ENABLED)
endif(PSM2_ENABLED)
