#
# ParaStation
#
# Copyright (C) 2020 ParTec Cluster Competence Center GmbH, Munich
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


function(target_add_cuda target)
  if(CUDA_ENABLED)
    target_include_directories(
      ${target}
      PRIVATE ${CUDA_INCLUDE_DIRS}
      )

    target_link_libraries(
      ${target}
      PRIVATE ${CUDA_LIBRARIES}
      )
  endif(CUDA_ENABLED)
endfunction()


function(plugin_common plugin)
  target_include_directories(
    ${plugin}
    PRIVATE .
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom
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

  target_add_cuda(${plugin})

  install(TARGETS ${plugin} DESTINATION "${CMAKE_INSTALL_LIBDIR}")
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


if (PSM_ENABLED)
  add_subdirectory(pscom4psm)
  link_to_lib(pscom4psm)
endif (PSM_ENABLED)


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