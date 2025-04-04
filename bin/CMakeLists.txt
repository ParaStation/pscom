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

include_directories(${PROJECT_SOURCE_DIR}/include)

add_executable(pscom_pp pscom_pp.c)
target_link_libraries(pscom_pp PRIVATE pscom)
install(TARGETS pscom_pp DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(pscom_info pscom_info.c)
target_link_libraries(pscom_info PRIVATE pscom)
target_include_directories(pscom_info PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom)
install(TARGETS pscom_info DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(pscom_rma_get pscom_rma_get.c)
target_link_libraries(pscom_rma_get PRIVATE pscom)
target_include_directories(pscom_rma_get
                           PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom)
install(TARGETS pscom_rma_get DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(pscom_rma_sync_notify pscom_rma_sync_notify.c)
target_link_libraries(pscom_rma_sync_notify PRIVATE pscom)
target_include_directories(pscom_rma_sync_notify
                           PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom)
install(TARGETS pscom_rma_sync_notify DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(pscom_rma_sync_ctrl pscom_rma_sync_ctrl.c)
target_link_libraries(pscom_rma_sync_ctrl PRIVATE pscom)
target_include_directories(pscom_rma_sync_ctrl
                           PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom)
install(TARGETS pscom_rma_sync_ctrl DESTINATION "${CMAKE_INSTALL_BINDIR}")

if(POPT_ENABLED)
  add_executable(pscom_dispatch examples/pscom_dispatch.c)
  target_include_directories(pscom_dispatch PRIVATE ${POPT_INCLUDE_DIRS})
  target_link_libraries(pscom_dispatch PRIVATE pscom ${POPT_LIBRARIES})

  add_executable(pscom_test pscom_test.c)
  target_include_directories(pscom_test PRIVATE ${POPT_INCLUDE_DIRS})
  target_link_libraries(pscom_test PRIVATE pscom ${POPT_LIBRARIES})

  add_executable(pscom_ondemand pscom_ondemand.c)
  target_include_directories(pscom_ondemand PRIVATE ${POPT_INCLUDE_DIRS})
  target_link_libraries(pscom_ondemand PRIVATE pscom ${POPT_LIBRARIES})
  #install(TARGETS	pscom_ondemand	DESTINATION "${CMAKE_INSTALL_BINDIR}")

  add_executable(pscom_bcast_test pscom_bcast_test.c)
  target_include_directories(pscom_bcast_test PRIVATE ${POPT_INCLUDE_DIRS})
  target_link_libraries(pscom_bcast_test PRIVATE pscom ${POPT_LIBRARIES})
  #install(TARGETS	pscom_bcast_test DESTINATION "${CMAKE_INSTALL_BINDIR}")

  add_executable(pscom_request_create pscom_request_create.c)
  target_include_directories(pscom_request_create PRIVATE ${POPT_INCLUDE_DIRS})
  target_link_libraries(pscom_request_create PRIVATE pscom ${POPT_LIBRARIES})
  #install(TARGETS	pscom_request_create DESTINATION "${CMAKE_INSTALL_BINDIR}")

  add_executable(pscom_bcast_pp pscom_bcast_pp.c)
  target_include_directories(pscom_bcast_pp PRIVATE ${POPT_INCLUDE_DIRS})
  target_link_libraries(pscom_bcast_pp PRIVATE pscom ${POPT_LIBRARIES})
  #install(TARGETS	pscom_bcast_pp	DESTINATION "${CMAKE_INSTALL_BINDIR}")

  add_executable(pscom_maxcon pscom_maxcon.c)
  target_include_directories(pscom_maxcon PRIVATE ${POPT_INCLUDE_DIRS})
  target_link_libraries(pscom_maxcon PRIVATE pscom ${POP_LIBRARIES})
  #install(TARGETS	pscom_maxcon	DESTINATION "${CMAKE_INSTALL_BINDIR}")

  add_executable(pscom_test_fault pscom_test_fault.c)
  target_include_directories(pscom_test_fault PRIVATE ${POPT_INCLUDE_DIRS})
  target_link_libraries(pscom_test_fault PRIVATE pscom ${POPT_LIBRARIES})
  #install(TARGETS	pscom_test_fault DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif(POPT_ENABLED)

# Build flavours of pscom_memusage depending on selected plugins
function(pscom_memusage_target plugin includedirs libs def)
  add_executable(pscom_memusage_${plugin} pscom_memusage.c)
  target_include_directories(
    pscom_memusage_${plugin}
    PRIVATE ${PROJECT_BINARY_DIR}/include
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom4${plugin}
    PRIVATE ${includedirs})

  target_link_libraries(
    pscom_memusage_${plugin}
    PRIVATE ${libs}
    PRIVATE pscom)

  target_compile_definitions(pscom_memusage_${plugin} PRIVATE ${def})
endfunction()
if(OFED_ENABLED)
  pscom_memusage_target(ofed "${IBVERBS_INCLUDE_DIRS}" "${IBVERBS_LIBRARIES}"
                        OFED=1)
endif(OFED_ENABLED)
if(OPENIB_ENABLED)
  pscom_memusage_target(openib "${IBVERBS_INCLUDE_DIRS}" "${IBVERBS_LIBRARIES}"
                        OPENIB=1)
endif(OPENIB_ENABLED)
if(EXTOLL_ENABLED)
  pscom_memusage_target(extoll "${EXTOLL_INCLUDE_DIRS}"
                        "${EXTOLL_RMA2_LIBRARY}" EXTOLL=1)
  pscom_memusage_target(velo "${EXTOLL_INCLUDE_DIRS}" "${EXTOLL_LIBRARIES}"
                        VELO=1)
endif(EXTOLL_ENABLED)

# Subfolders for other plugin-related tools
add_subdirectory(extoll)
add_subdirectory(openib)
add_subdirectory(portals4)
add_subdirectory(psm)
add_subdirectory(ucp)

set(bindir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR})
set(configdir ${CMAKE_INSTALL_PREFIX}/config)
set(libdir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(docdir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DOCDIR})
set(includedir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})

configure_file(pscom_debug.sh pscom_debug @ONLY)
configure_file(pscom.gdb pscom.gdb COPYONLY)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/pscom_debug
        DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES pscom.gdb DESTINATION config)

# # -- additional rules --

# test: pscom_test
# 	$(builddir)/pscom_test
