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

add_library(
  pscom4velo SHARED
  pscom_extoll.c
  psextoll.c
)

target_include_directories(
  pscom4velo
  PRIVATE ${EXTOLL_INCLUDE_DIRS}
)

target_link_libraries(
  pscom4velo
  PRIVATE ${EXTOLL_LIBRARIES}
)

plugin_common(pscom4velo)

option(EXTOLL_MEMCACHE_ENABLED "Enable the registration cache of the pscom4velo plugin." OFF)
if(EXTOLL_MEMCACHE_ENABLED)
  target_compile_definitions(
    pscom4velo
    PRIVATE PSEX_USE_MREGION_CACHE)
endif(EXTOLL_MEMCACHE_ENABLED)
