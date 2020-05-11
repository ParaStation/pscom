#
# ParaStation
#
# Copyright (C) 2020 ParTec Cluster Competence Center GmbH, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

# "make utest" : Build and call all utests
add_custom_target(utest
  COMMAND	${CMAKE_CURRENT_BINARY_DIR}/pscom_utest
  DEPENDS	utest-build
  )

# "make utest-build" : Build all tests (but do not call them)
add_custom_target(utest-build
  DEPENDS	pscom_utest
  )

#
# ctest
#
# Warning: "ctest" does not track dependencies and therefore does not
# rebuild the tests, if test dependencies change!

add_test(
  NAME	pscom_utest
  COMMAND	pscom_utest
  )


#
# Test build rules
#

add_executable(		pscom_utest
  EXCLUDE_FROM_ALL
  mocks/pscom_mocks.c
  mocks/misc_mocks.c
  pscom_utest.c
  pscom/test_io.c
  util/test_utils_con.c
  )

# Mocked functions
target_link_options(	pscom_utest
  PRIVATE
  -Wl,--wrap=pscom_unlock
  -Wl,--wrap=memcpy
#  -static
)

target_link_libraries(	pscom_utest
  PRIVATE
  pscom-static
  ${CMOCKA_LIBRARIES}
  )

target_include_directories(	pscom_utest
  PRIVATE
  .
  ${PROJECT_SOURCE_DIR}/lib/pscom
  ${PROJECT_SOURCE_DIR}/include
  ${CMOCKA_INCLUDE_DIR}
  )

message(STATUS	"pscom_utest CMOCKA_INCLUDE_DIR: ${CMOCKA_INCLUDE_DIR}")


if(CUDA_ENABLED)
  # CUDA-related configuration
  target_link_options(	pscom_utest
    PRIVATE
    -Wl,--wrap=cuInit
    -Wl,--wrap=cuDeviceGetCount
    -Wl,--wrap=cuDeviceGetAttribute
    -Wl,--wrap=cuGetErrorName
    -Wl,--wrap=cuPointerSetAttribute
    -Wl,--wrap=cuPointerGetAttributes
    -Wl,--wrap=cuMemcpy
    -Wl,--wrap=cuMemcpyDtoH_v2
    -Wl,--wrap=cuMemcpyHtoD_v2
    )

  target_link_libraries(	pscom_utest
    PRIVATE
    ${CUDA_LIBRARIES}
    )

  target_compile_definitions(	pscom_utest
    PRIVATE
    -DPSCOM_CUDA_AWARENESS
    )

  target_sources(	pscom_utest
    PRIVATE
    pscom/test_cuda.c
    mocks/cuda_mocks.c
    )

  target_link_libraries(	pscom_utest
    PRIVATE
    ${CUDA_LIBRARIES}
    )

  target_include_directories(	pscom_utest
    PRIVATE
    ${CUDA_INCLUDE_DIRS}
    )

#  target_add_cuda(pscom_utest)
endif(CUDA_ENABLED)


# ACLOCAL_AMFLAGS = -I m4

# noinst_PROGRAMS = pscom_utest

# pscom_utest_LDADD = \
#	$(top_builddir)/lib/pscom/libpscom_utest.la

# pscom_utest_CPPFLAGS = \
#	-I./pscom \
#	-I$(top_srcdir)/include \
#	-I$(top_srcdir)/lib/pscom
