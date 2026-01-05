#
# ParaStation
#
# Copyright (C) 2022-2026 ParTec AG, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

add_library(pscom4portals SHARED pscom_portals.c psptl.c)

target_include_directories(pscom4portals PRIVATE ${PORTALS4_INCLUDE_DIRS})

target_link_libraries(pscom4portals PRIVATE ${PORTALS4_LIBRARIES})

plugin_common(pscom4portals)

# Static libpscom4portals for utests
add_static_target(pscom4portals)
