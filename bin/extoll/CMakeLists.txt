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

if(EXTOLL_ENABLED)
  if(POPT_ENABLED)
    add_executable(extoll_pp_lowlevel extoll_pp_lowlevel.c)
    target_include_directories(
      extoll_pp_lowlevel
      PRIVATE ${EXTOLL_INCLUDE_DIRS}
      PRIVATE ${POPT_INCLUDE_DIRS})
    target_link_libraries(
      extoll_pp_lowlevel
      PRIVATE ${EXTOLL_RMA2_LIBRARY}
      PRIVATE ${POPT_LIBRARIES})

    add_executable(extoll_pp_velo extoll_pp_velo.c)
    target_include_directories(
      extoll_pp_velo
      PRIVATE ${EXTOLL_INCLUDE_DIRS}
      PRIVATE ${POPT_INCLUDE_DIRS})
    target_link_libraries(
      extoll_pp_velo
      PRIVATE ${EXTOLL_VELO2_LIBRARY}
      PRIVATE ${POPT_LIBRARIES})

    add_executable(extoll_one_message extoll_one_message.c)
    target_include_directories(
      extoll_one_message
      PRIVATE ${EXTOLL_INCLUDE_DIRS}
      PRIVATE ${POPT_INCLUDE_DIRS})
    target_link_libraries(
      extoll_one_message
      PRIVATE ${EXTOLL_RMA2_LIBRARY}
      PRIVATE ${POPT_LIBRARIES})
  endif(POPT_ENABLED)
endif(EXTOLL_ENABLED)
