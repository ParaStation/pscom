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

# "make utest" : Build and call all utests
add_custom_target(
  utest
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/pscom_utest
  COMMAND "${CMAKE_SOURCE_DIR}/scripts/testlocal.sh"
  DEPENDS utest-build)

# "make utest-build" : Build all tests (but do not call them)
add_custom_target(
  utest-build
  DEPENDS pscom_utest
  DEPENDS pscom_pp)

#
# ctest
#
# Warning: "ctest" does not track dependencies and therefore does not
# rebuild the tests, if test dependencies change!
# The "build-tests" pseudo test tries to compensate for this missing feature.
add_test(
  NAME build-tests
  COMMAND "${CMAKE_MAKE_PROGRAM}" utest-build
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_test(NAME pscom_utest
         COMMAND ${CMAKE_COMMAND} -E env "PSP_UTEST_OUTPUT=xml"
                 ${PROJECT_BINARY_DIR}/test/pscom_utest)

add_test(
  NAME testlocal
  COMMAND "${CMAKE_SOURCE_DIR}/scripts/testlocal.sh"
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
#
# Code coverage
#
if(COVERAGE_ENABLED)
  # Disable any optimizations and add necessary compiler flags
  string(REGEX REPLACE "-Og" "-O0" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
  set(CMAKE_C_FLAGS_DEBUG
      "${CMAKE_C_FLAGS_DEBUG}  -fprofile-arcs -ftest-coverage")

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
  add_custom_target(
    coverage
    # Run tests
    pscom_utest
    # Running gcovr for XML generation
    COMMAND
      ${GCOVR_PATH} --xml -s -r ${PROJECT_SOURCE_DIR} -e
      ${PROJECT_SOURCE_DIR}/test --object-directory=${PROJECT_BINARY_DIR} -o
      ${COVERAGE_NAME}.xml
    # Running gcovr for HTML generation
    COMMAND ${CMAKE_COMMAND} -E make_directory
            ${PROJECT_BINARY_DIR}/${COVERAGE_NAME}
    COMMAND
      ${GCOVR_PATH} --html --html-details -r ${PROJECT_SOURCE_DIR} -e
      ${PROJECT_SOURCE_DIR}/test --object-directory=${PROJECT_BINARY_DIR} -o
      ${COVERAGE_NAME}/index.html
    BYPRODUCTS ${PROJECT_BINARY_DIR}/${COVERAGE_NAME}.xml
               ${PROJECT_BINARY_DIR}/${COVERAGE_NAME}
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    DEPENDS pscom_utest
    VERBATIM
    COMMENT "Running gcovr to produce HTML and XML code coverage report.")
endif(COVERAGE_ENABLED)

#
# Test build rules
#

add_executable(
  pscom_utest EXCLUDE_FROM_ALL
  mocks/misc_mocks.c
  pscom_utest.c
  pscom/test_debug.c
  pscom/test_env.c
  pscom/test_io.c
  pscom/test_listen.c
  pscom/test_ufd.c
  pscom/test_plugin.c
  pscom/test_version.c
  util/test_utils_con.c
  util/test_utils_debug.c
  util/test_utils_env.c
  util/test_utils_listen.c
  util/test_utils_sock.c
  util/test_utils_ufd.c)

# Mocked functions
target_link_options(
  pscom_utest
  PRIVATE
  -Wl,--wrap=dlsym
  -Wl,--wrap=dlopen
  -Wl,--wrap=dlerror
  -Wl,--wrap=dlclose
  -Wl,--wrap=free
  -Wl,--wrap=memcpy
  -Wl,--wrap=malloc
  -Wl,--wrap=read
  -Wl,--wrap=send
  -Wl,--wrap=poll
  -Wl,--wrap=setsockopt
  -Wl,--wrap=sched_yield
  #  -static
)

target_link_libraries(pscom_utest PRIVATE pscom-static ${CMOCKA_LIBRARIES})

target_include_directories(
  pscom_utest PRIVATE . ${PROJECT_SOURCE_DIR}/lib/pscom
                      ${PROJECT_SOURCE_DIR}/include ${CMOCKA_INCLUDE_DIR})

if(UCP_ENABLED)
  target_link_options(
    pscom_utest
    PRIVATE
    -Wl,--wrap=ucp_config_read
    -Wl,--wrap=ucp_config_release
    -Wl,--wrap=ucp_init_version
    -Wl,--wrap=ucp_worker_create
    -Wl,--wrap=ucp_worker_get_address
    -Wl,--wrap=ucp_worker_release_address
    -Wl,--wrap=ucp_worker_destroy
    -Wl,--wrap=ucp_cleanup
    -Wl,--wrap=ucs_status_string)

  target_include_directories(
    pscom_utest PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom4ucp ${UCP_INCLUDE_DIRS})

  target_sources(pscom_utest PRIVATE mocks/ucx_mocks.c
                                     pscom4ucp/test_pscom4ucp.c)

  target_link_libraries(pscom_utest PRIVATE pscom4ucp-static)

  target_compile_definitions(pscom_utest PRIVATE UCP_ENABLED)
endif(UCP_ENABLED)

if(PORTALS4_ENABLED)
  target_link_options(
    pscom_utest
    PRIVATE
    -Wl,--wrap=PtlNIInit
    -Wl,--wrap=PtlNIFini
    -Wl,--wrap=PtlInit
    -Wl,--wrap=PtlFini
    -Wl,--wrap=PtlGetPhysId
    -Wl,--wrap=PtlEQAlloc
    -Wl,--wrap=PtlEQFree
    -Wl,--wrap=PtlEQGet
    -Wl,--wrap=PtlEQPoll
    -Wl,--wrap=PtlMDBind
    -Wl,--wrap=PtlMDRelease
    -Wl,--wrap=PtlPTAlloc
    -Wl,--wrap=PtlPTFree
    -Wl,--wrap=PtlPut
    -Wl,--wrap=PtlMEAppend
    -Wl,--wrap=PtlMEUnlink)

  target_include_directories(
    pscom_utest PRIVATE ${PROJECT_SOURCE_DIR}/lib/pscom4portals
                        ${PORTALS4_INCLUDE_DIRS})

  target_sources(pscom_utest PRIVATE mocks/portals4_mocks.c
                                     pscom4portals/test_pscom4portals.c)

  target_link_libraries(pscom_utest PRIVATE pscom4portals-static)

  target_compile_definitions(pscom_utest PRIVATE PORTALS4_ENABLED)
endif(PORTALS4_ENABLED)

# CUDA-related configuration
if(CUDA_ENABLED)
  target_link_options(
    pscom_utest
    PRIVATE
    -Wl,--wrap=cuInit
    -Wl,--wrap=cuCtxGetCurrent
    -Wl,--wrap=cuCtxGetDevice
    -Wl,--wrap=cuDeviceGetCount
    -Wl,--wrap=cuDeviceGetAttribute
    -Wl,--wrap=cuDevicePrimaryCtxGetState
    -Wl,--wrap=cuGetErrorName
    -Wl,--wrap=cuPointerSetAttribute
    -Wl,--wrap=cuPointerGetAttributes
    -Wl,--wrap=cuMemcpy
    -Wl,--wrap=cuMemcpyDtoH_v2
    -Wl,--wrap=cuMemcpyHtoD_v2
    -Wl,--wrap=cuMemcpyAsync
    -Wl,--wrap=cuMemcpyDtoHAsync_v2
    -Wl,--wrap=cuMemcpyHtoDAsync_v2
    -Wl,--wrap=cuStreamSynchronize
    -Wl,--wrap=cuStreamDestroy_v2
    -Wl,--wrap=cuStreamCreate)

  target_sources(pscom_utest PRIVATE mocks/cuda_mocks.c pscom/test_cuda.c
                                     util/test_utils_cuda.c)

  target_add_cuda(pscom_utest)
endif(CUDA_ENABLED)
