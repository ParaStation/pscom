#
# ParaStation
#
# Copyright (C) 2020-2021 ParTec Cluster Competence Center GmbH, Munich
# Copyright (C) 2021-2022 ParTec AG, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

include_directories(
  ${PROJECT_SOURCE_DIR}/include
  )


add_executable(             pscom_pp	pscom_pp.c)
target_include_directories( pscom_pp	PRIVATE ${POPT_INCLUDE_DIRS})
target_link_libraries(      pscom_pp	PRIVATE pscom ${POPT_LIBRARIES})
install(TARGETS             pscom_pp	DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(             pscom_dispatch	examples/pscom_dispatch.c)
target_include_directories( pscom_dispatch	PRIVATE ${POPT_INCLUDE_DIRS})
target_link_libraries(      pscom_dispatch	PRIVATE pscom ${POPT_LIBRARIES})

add_executable(             pscom_info	pscom_info.c)
target_link_libraries(      pscom_info	PRIVATE pscom)
target_include_directories( pscom_info  PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom)
install(TARGETS             pscom_info	DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(             pscom_test	pscom_test.c)
target_include_directories( pscom_test	PRIVATE ${POPT_INCLUDE_DIRS})
target_link_libraries(      pscom_test	PRIVATE pscom ${POPT_LIBRARIES})


add_executable(             pscom_ondemand	pscom_ondemand.c)
target_include_directories( pscom_ondemand	PRIVATE ${POPT_INCLUDE_DIRS})
target_link_libraries(      pscom_ondemand	PRIVATE pscom ${POPT_LIBRARIES})
#install(TARGETS	pscom_ondemand	DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(             pscom_bcast_test pscom_bcast_test.c)
target_include_directories( pscom_bcast_test PRIVATE ${POPT_INCLUDE_DIRS})
target_link_libraries(      pscom_bcast_test PRIVATE pscom ${POPT_LIBRARIES})
#install(TARGETS	pscom_bcast_test DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(             pscom_request_create pscom_request_create.c)
target_include_directories( pscom_request_create PRIVATE ${POPT_INCLUDE_DIRS})
target_link_libraries(      pscom_request_create PRIVATE pscom ${POPT_LIBRARIES})
#install(TARGETS	pscom_request_create DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(             pscom_bcast_pp pscom_bcast_pp.c)
target_include_directories( pscom_bcast_pp PRIVATE ${POPT_INCLUDE_DIRS})
target_link_libraries(      pscom_bcast_pp PRIVATE pscom ${POPT_LIBRARIES})
#install(TARGETS	pscom_bcast_pp	DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(             pscom_maxcon pscom_maxcon.c)
target_include_directories( pscom_maxcon PRIVATE ${POPT_INCLUDE_DIRS})
target_link_libraries(      pscom_maxcon PRIVATE pscom ${POP_LIBRARIES})
#install(TARGETS	pscom_maxcon	DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(             pscom_test_fault pscom_test_fault.c)
target_include_directories( pscom_test_fault PRIVATE ${POPT_INCLUDE_DIRS})
target_link_libraries(      pscom_test_fault PRIVATE pscom ${POPT_LIBRARIES})
#install(TARGETS	pscom_test_fault DESTINATION "${CMAKE_INSTALL_BINDIR}")


add_executable(             test_nodes test_nodes.c)
target_include_directories( test_nodes PRIVATE ${POPT_INCLUDE_DIRS})
target_link_libraries(      test_nodes PRIVATE pscom ${POPT_LIBRARIES})
install(TARGETS             test_nodes	DESTINATION "${CMAKE_INSTALL_BINDIR}")
if(PSMGMT_ENABLED)
  target_add_psmgmt(	test_nodes)
endif(PSMGMT_ENABLED)


#
# p4sock tools
#
add_executable(		p4stat		p4stat.c)
target_link_libraries(	p4stat		PRIVATE popt)
#install(TARGETS	p4stat		DESTINATION bin)

add_executable(		p4tcp		p4tcp.c)
target_link_libraries(	p4tcp		PRIVATE popt)
#install(TARGETS	p4tcp		DESTINATION bin)

add_executable(		p4logd		p4logd.c)
target_link_libraries(	p4logd		PRIVATE popt)
#install(TARGETS	p4logd		DESTINATION bin)

add_executable(		psock_pp	psock_pp.c)
target_link_libraries(	psock_pp	PRIVATE popt)
#install(TARGETS	psock_pp	DESTINATION bin)

add_executable(		psock_test	psock_test.c)
target_link_libraries(	psock_test	PRIVATE popt)
#install(TARGETS	psock_test	DESTINATION bin)



if (PSMGMT_ENABLED)
#  pscp
endif (PSMGMT_ENABLED)

if (MELLANOX_ENABLED)
#  ps4_ib ps4_ib_pp ps4_ib_pp_rdma
#
# cppflags_mellanox = $(AM_CPPFLAGS) $(MELLANOX_CPPFLAGS) -D__LINUX__	\
# 	-DMT_LITTLE_ENDIAN -pthread
# ldflags_mellanox = $(AM_LDFLAGS) $(MELLANOX_LDFLAGS) -pthread
# ldadd_mellanox = -lvapi -lmtl_common -lmosal -lmpga

# ps4_ib_SOURCES = mellanox/ps4_ib.c
# ps4_ib_CPPFLAGS = $(cppflags_mellanox)
# ps4_ib_LDFLAGS = $(ldflags_mellanox)
# ps4_ib_LDADD = $(ldadd_mellanox)

# ps4_ib_pp_SOURCES = mellanox/ps4_ib_pp.c
# ps4_ib_pp_CPPFLAGS = $(cppflags_mellanox)
# ps4_ib_pp_LDFLAGS = $(ldflags_mellanox)
# ps4_ib_pp_LDADD = $(ldadd_mellanox) -lpopt

# ps4_ib_pp_rdma_SOURCES = mellanox/ps4_ib_pp_rdma.c
# ps4_ib_pp_rdma_CPPFLAGS = $(cppflags_mellanox)
# ps4_ib_pp_rdma_LDFLAGS = $(ldflags_mellanox)
# ps4_ib_pp_rdma_LDADD = $(ldadd_mellanox) -lpopt
endif (MELLANOX_ENABLED)

if (GM_ENABLED)
# gm_pp gm/gm_sr.c gm/gm_test.c
# gm_pp_SOURCES = gm/gm_pp.c
# gm_pp_CPPFLAGS = $(AM_CPPFLAGS) $(GM_CPPFLAGS)
# gm_pp_LDFLAGS = $(AM_LDFLAGS) $(GM_LDFLAGS)
# gm_pp_LDADD = -lgm -lpopt
endif (GM_ENABLED)

if (OPENIB_ENABLED)
  function(openib_target target firstsrc)
    add_executable(
      ${target}
      ${firstsrc}
      ${PROJECT_SOURCE_DIR}/lib/pscom/pscom_dprint.c
      ${PROJECT_SOURCE_DIR}/lib/pscom/pscom_env.c
      ${PROJECT_SOURCE_DIR}/lib/pscom/pslib.c
      )

    add_dependencies(${target} vc_version)

    target_link_libraries(
      ${target}
      PRIVATE ${IBVERBS_LIBRARIES}
      PRIVATE ${POPT_LIBRARIES}
      PRIVATE dl
      )

    target_include_directories(
      ${target}
      PRIVATE ${IBVERBS_INCLUDE_DIRS}
      PRIVATE ${POPT_INCLUDE_DIRS}
      PRIVATE ${PROJECT_BINARY_DIR}/include
      PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom
      PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom4openib
      )
  endfunction()

  openib_target(openib_pp	openib/openib_pp.c)
  #install(TARGETS	openib_pp	DESTINATION bin)

  openib_target(openib_ud_pp	openib/openib_ud_pp.c)
  #install(TARGETS	openib_ud_pp	DESTINATION bin)

  add_executable(pscom_memusage_openib pscom_memusage.c)
  target_include_directories(
    pscom_memusage_openib
    PRIVATE ${IBVERBS_INCLUDE_DIRS}
    PRIVATE ${PROJECT_BINARY_DIR}/include
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom4openib
    )
  target_link_libraries(
    pscom_memusage_openib
    PRIVATE ${IBVERBS_LIBRARIES}
    PRIVATE pscom
    )
  target_compile_definitions(pscom_memusage_openib
    PRIVATE OPENIB=1
    )
endif (OPENIB_ENABLED)

if (OFED_ENABLED)
  add_executable(pscom_memusage_ofed pscom_memusage.c)
  target_include_directories(
    pscom_memusage_ofed
    PRIVATE ${IBVERBS_INCLUDE_DIRS}
    PRIVATE ${PROJECT_BINARY_DIR}/include
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom4ofed
    )

  target_link_libraries(
    pscom_memusage_ofed
    PRIVATE ${IBVERBS_LIBRARIES}
    PRIVATE pscom
    )

  target_compile_definitions(pscom_memusage_ofed
    PRIVATE OFED=1
    )
endif (OFED_ENABLED)

if (UCP_ENABLED)
  add_executable(ucp_pp ucp/ucp_pp.c)
  target_include_directories(
    ucp_pp
    PRIVATE ${UCP_INCLUDE_DIRS}
    PRIVATE ${POPT_INCLUDE_DIRS}
    PRIVATE ${PROJECT_BINARY_DIR}/include
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom4ucp
    )

  target_link_libraries(
    ucp_pp
    PRIVATE ${UCP_LIBRARIES}
    PRIVATE ${POPT_LIBRARIES}
    )
endif (UCP_ENABLED)

if (PSM1_ENABLED)
  # noinst_PROGRAMS += psm_pp
  # psm_pp_SOURCES = psm/psm_pp.c
  # psm_pp_CPPFLAGS = $(AM_CPPFLAGS) $(PSM_CPPFLAGS)
  # psm_pp_LDFLAGS = $(AM_LDFLAGS) $(PSM_LDFLAGS)
  # psm_pp_LDADD = -lpsm_infinipath -lpopt
endif (PSM1_ENABLED)

if (PSM2_ENABLED)
  # noinst_PROGRAMS += psm2_pp pscom4psm_pp
  add_executable(psm2_pp psm/psm2_pp.c)
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

  add_executable(pscom4psm_pp psm/pscom4psm_pp.c)
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
endif (PSM2_ENABLED)

if (DAPL_ENABLED)
  # noinst_PROGRAMS += dapl_pp dapl_pp_lowlevel
  # cppflags_dapl = $(AM_CPPFLAGS) $(DAPL_CPPFLAGS)			\
  # 	-I$(top_srcdir)/lib/pscom -I$(top_srcdir)/lib/pscom4dapl
  # ldflags_dapl = $(AM_LDFLAGS) $(DAPL_LDFLAGS)

  # dapl_pp_SOURCES = dapl/dapl_pp.c
  # dapl_pp_CPPFLAGS = $(cppflags_dapl)
  # dapl_pp_LDFLAGS = $(ldflags_dapl)
  # dapl_pp_LDADD = $(top_builddir)/lib/pscom/libperf.la		\
  # 	$(top_builddir)/lib/pscom4dapl/libpsdapl.la 		\
  # 	-ldat -lpopt

  # dapl_pp_lowlevel_SOURCES = dapl/dapl_pp_lowlevel.c
  # dapl_pp_lowlevel_CPPFLAGS = $(cppflags_dapl)
  # dapl_pp_lowlevel_LDFLAGS = $(ldflags_dapl)
  # dapl_pp_lowlevel_LDADD = -ldat -lpopt
endif (DAPL_ENABLED)

if (ELAN_ENABLED)
  # # noinst_PROGRAMS += elan_pp
  #   noinst_PROGRAMS += elan_pp_lowlevel
  # elan_pp_lowlevel_SOURCES = elan/elan_pp_lowlevel.c
  # elan_pp_lowlevel_CPPFLAGS = $(AM_CPPFLAGS) $(ELAN_CPPFLAGS)	\
  # 	-I$(top_srcdir)/lib/pscom -I$(top_srcdir)/lib/pscom4elan
  # elan_pp_lowlevel_LDFLAGS = $(AM_LDFLAGS) $(ELAN_LDFLAGS)
  # elan_pp_lowlevel_LDADD = -lelan -lpopt
endif (ELAN_ENABLED)

if (EXTOLL_ENABLED)
  # noinst_PROGRAMS += extoll_pp_lowlevel extoll_pp_velo extoll_one_message
  add_executable(extoll_pp_lowlevel extoll/extoll_pp_lowlevel.c)
  target_include_directories(
    extoll_pp_lowlevel
    PRIVATE  ${EXTOLL_INCLUDE_DIRS}
    PRIVATE ${POPT_INCLUDE_DIRS}
    )
  target_link_libraries(
    extoll_pp_lowlevel
    PRIVATE ${EXTOLL_RMA2_LIBRARY}
    PRIVATE ${POPT_LIBRARIES}
    )

  add_executable(extoll_pp_velo extoll/extoll_pp_velo.c)
  target_include_directories(
    extoll_pp_velo
    PRIVATE  ${EXTOLL_INCLUDE_DIRS}
    PRIVATE ${POPT_INCLUDE_DIRS}
    )
  target_link_libraries(
    extoll_pp_velo
    PRIVATE ${EXTOLL_VELO2_LIBRARY}
    PRIVATE ${POPT_LIBRARIES}
    )

  add_executable(extoll_one_message extoll/extoll_one_message.c)
  target_include_directories(
    extoll_one_message
    PRIVATE  ${EXTOLL_INCLUDE_DIRS}
    PRIVATE ${POPT_INCLUDE_DIRS}
    )
  target_link_libraries(
    extoll_one_message
    PRIVATE ${EXTOLL_RMA2_LIBRARY}
    PRIVATE ${POPT_LIBRARIES}
    )

  add_executable(pscom_memusage_extoll pscom_memusage.c)
  target_include_directories(
    pscom_memusage_extoll
    PRIVATE ${PROJECT_BINARY_DIR}/include
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom4extoll
    PRIVATE ${EXTOLL_INCLUDE_DIRS}
    )
  target_link_libraries(
    pscom_memusage_extoll
    PRIVATE ${EXTOLL_RMA2_LIBRARY}
    PRIVATE pscom
    )
  target_compile_definitions(pscom_memusage_extoll
    PRIVATE EXTOLL=1
    )

  add_executable(pscom_memusage_velo pscom_memusage.c)
  target_include_directories(
    pscom_memusage_velo
    PRIVATE ${PROJECT_BINARY_DIR}/include
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom
    PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom4velo
    PRIVATE ${EXTOLL_INCLUDE_DIRS}
    )
  target_link_libraries(
    pscom_memusage_velo
    PRIVATE ${EXTOLL_LIBRARIES}
    PRIVATE pscom
    )
  target_compile_definitions(pscom_memusage_velo
    PRIVATE VELO=1
    )
endif (EXTOLL_ENABLED)

if (MXM_ENABLED)
  # noinst_PROGRAMS += mxm_pp
  # mxm_pp_SOURCES = mxm/mxm_pp.c
  # noinst_HEADERS += mxm/mxm_util.c
  # mxm_pp_CPPFLAGS = $(AM_CPPFLAGS) $(MXM_CPPFLAGS)
  # mxm_pp_LDFLAGS = $(AM_LDFLAGS) $(MXM_LDFLAGS)
  # mxm_pp_LDADD = -lmxm -lpopt
endif (MXM_ENABLED)


set(bindir     ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR})
set(configdir  ${CMAKE_INSTALL_PREFIX}/config)
set(libdir     ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(docdir     ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DOCDIR})
set(includedir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})

configure_file(pscom_debug.sh pscom_debug @ONLY)
configure_file(pscom.gdb pscom.gdb COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/scripts/parastation-config.sh parastation-config @ONLY)


install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/pscom_debug DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES pscom.gdb DESTINATION config)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/parastation-config DESTINATION config)


# # -- additional rules --

# test: pscom_test
# 	$(builddir)/pscom_test
