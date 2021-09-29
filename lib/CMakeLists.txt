#
# ParaStation
#
# Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
# Copyright (C) 2021      ParTec AG, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

function(link_to_lib source)
  # Collect symlinks to all libraries in the current directory for
  # convenience. (LD_LIBRARY_PATH usage without installing the libraries)
  add_custom_target(lib${source} ALL
    ln -sf "${CMAKE_CURRENT_BINARY_DIR}/${source}/lib${source}.so*" .
    DEPENDS ${source}
    BYPRODUCTS lib${source}.so
    )
endfunction()


function(plugin_common plugin)
  target_include_directories(
    ${plugin}
    BEFORE PRIVATE .
    BEFORE PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom
    )

  target_link_libraries(
    ${plugin}
    PRIVATE pscom
    )

  target_compile_options(
    ${plugin}
    PRIVATE -fvisibility=hidden
    PRIVATE -flto
    )

  target_link_options(
    ${plugin}
    PRIVATE -flto
    )

  set_target_properties(
    ${plugin}
    PROPERTIES
    NO_SONAME TRUE
    )

  if(CUDA_ENABLED)
    target_add_cuda(${plugin})
  endif(CUDA_ENABLED)

  install(TARGETS ${plugin} DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endfunction()


function(add_static_target target)
  string(TOUPPER ${target} uc_target)

  get_target_property(${uc_target}_SOURCES	${target} SOURCES)
  get_target_property(${uc_target}_INCLUDE_DIRECTORIES	${target} INCLUDE_DIRECTORIES)
  get_target_property(${uc_target}_COMPILE_DEFINITIONS	${target} COMPILE_DEFINITIONS)
  get_target_property(${uc_target}_LINK_LIBRARIES	${target} LINK_LIBRARIES)

  add_library(${target}-static STATIC
    EXCLUDE_FROM_ALL
    ${${uc_target}_SOURCES}
    )
  target_include_directories(${target}-static PRIVATE ${${uc_target}_INCLUDE_DIRECTORIES})
  target_compile_definitions(${target}-static PRIVATE ${${uc_target}_COMPILE_DEFINITIONS})
  target_link_libraries(${target}-static PRIVATE ${${uc_target}_LINK_LIBRARIES})
  if(CUDA_ENABLED)
    target_add_cuda(${target}-static)
  endif(CUDA_ENABLED)
  if(COVERAGE_ENABLED)
    target_compile_options(${target}-static PRIVATE --coverage)
    target_link_options(${target}-static PRIVATE --coverage)
  endif(COVERAGE_ENABLED)
endfunction()


add_subdirectory(pscom)
link_to_lib(pscom)


add_subdirectory(psmalloc)
link_to_lib(psmalloc)


if (OPENIB_ENABLED)
  add_subdirectory(pscom4openib)
  link_to_lib(pscom4openib)
endif (OPENIB_ENABLED)


if (OFED_ENABLED)
  add_subdirectory(pscom4ofed)
  link_to_lib(pscom4ofed)
endif (OFED_ENABLED)


if (UCP_ENABLED)
  add_subdirectory(pscom4ucp)
  link_to_lib(pscom4ucp)
endif (UCP_ENABLED)


if (PSM2_ENABLED)
  add_subdirectory(pscom4psm)
  link_to_lib(pscom4psm)
endif (PSM2_ENABLED)


if (EXTOLL_ENABLED)
  add_subdirectory(pscom4extoll)
  link_to_lib(pscom4extoll)

  add_subdirectory(pscom4velo)
  link_to_lib(pscom4velo)
endif (EXTOLL_ENABLED)


if (DAPL_ENABLED)
  add_subdirectory(pscom4dapl)
endif (DAPL_ENABLED)


if (ELAN_ENABLED)
  add_subdirectory(pscom4elan)
endif (ELAN_ENABLED)


if (GM_ENABLED)
  add_subdirectory(pscom4gm)
endif (GM_ENABLED)


if (MXM_ENABLED)
  add_subdirectory(pscom4mxm)
endif (MXM_ENABLED)



# SUBDIRS += p4tcp
