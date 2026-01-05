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

add_library(pscom4ucp SHARED pscom_ucp.c psucp.c)

target_include_directories(pscom4ucp PRIVATE ${UCP_INCLUDE_DIRS})

target_link_libraries(pscom4ucp PRIVATE ${UCP_LIBRARIES})

plugin_common(pscom4ucp)

# Static libpscom4ucp for utests
add_static_target(pscom4ucp)
