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
  COMMAND	"${CMAKE_SOURCE_DIR}/scripts/testlocal.sh"
  DEPENDS	utest-build
  )

# "make utest-build" : Build all tests (but do not call them)
add_custom_target(utest-build
  DEPENDS	pscom_utest
  DEPENDS	pscom_pp
  )

#
# ctest
#
# Warning: "ctest" does not track dependencies and therefore does not
# rebuild the tests, if test dependencies change!
# The "build-tests" pseudo test tries to compensate for this missing feature.
add_test(
  NAME	build-tests
  COMMAND	"${CMAKE_MAKE_PROGRAM}" utest-build
  WORKING_DIRECTORY	${CMAKE_BINARY_DIR}
  )


add_test(
  NAME	pscom_utest
  COMMAND	pscom_utest
  )

add_test(
  NAME	testlocal
  COMMAND	"${CMAKE_SOURCE_DIR}/scripts/testlocal.sh"
  WORKING_DIRECTORY	"${CMAKE_BINARY_DIR}/bin"
  )
#
# Code coverage
#
if(COVERAGE_ENABLED)
  # Disable any optimizations and add necessary compiler flags
  string(REGEX REPLACE "-Og" "-O0" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}  -fprofile-arcs -ftest-coverage")

  # Check prerequisites
  find_program(GCOV_PATH gcov)
  if(NOT GCOV_PATH)
    message(FATAL_ERROR "Could not find the 'gcov' executable. Abort")
  endif(NOT GCOV_PATH)
  find_program(GCOVR_PATH gcovr)
  if(NOT GCOVR_PATH)
    message(FATAL_ERROR "Could not find the 'gcovr' executable. Abort")
  endif(NOT GCOVR_PATH)

  set(COVERAGE_NAME "pscom-coverage")

  # XML coverage report
  add_custom_target(coverage
      # Run tests
      pscom_utest

      # Running gcovr for XML generation
      COMMAND ${GCOVR_PATH} --xml
          -r ${PROJECT_SOURCE_DIR}
	  -e ${PROJECT_SOURCE_DIR}/test
          --object-directory=${PROJECT_BINARY_DIR}
	  -o ${COVERAGE_NAME}.xml
      # Running gcovr for HTML generation
      COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/${COVERAGE_NAME}
      COMMAND ${GCOVR_PATH} --html --html-details
          -r ${PROJECT_SOURCE_DIR}
	  -e ${PROJECT_SOURCE_DIR}/test
          --object-directory=${PROJECT_BINARY_DIR}
	  -o ${COVERAGE_NAME}/index.html
      BYPRODUCTS ${PROJECT_BINARY_DIR}/${COVERAGE_NAME}.xml ${PROJECT_BINARY_DIR}/${COVERAGE_NAME}
      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
      DEPENDS pscom_utest
      VERBATIM
      COMMENT "Running gcovr to produce HTML and XML code coverage report."
  )
endif(COVERAGE_ENABLED)


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

  target_sources(	pscom_utest
    PRIVATE
    pscom/test_cuda.c
    mocks/cuda_mocks.c
    )

  target_add_cuda(pscom_utest)
endif(CUDA_ENABLED)


# ACLOCAL_AMFLAGS = -I m4

# noinst_PROGRAMS = pscom_utest

# pscom_utest_LDADD = \
#	$(top_builddir)/lib/pscom/libpscom_utest.la

# pscom_utest_CPPFLAGS = \
#	-I./pscom \
#	-I$(top_srcdir)/include \
#	-I$(top_srcdir)/lib/pscom
