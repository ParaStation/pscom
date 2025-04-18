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

cmake_minimum_required(VERSION 3.10)

project(pscom LANGUAGES C)

# Set default install directory for pscom
# if user did not provide CMAKE_INSTALL_PREFIX
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX
      "/opt/parastation"
      CACHE PATH "Use default install prefix" FORCE)
endif(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
include(AddCudaTarget)
include(FindPackageWithHints)
include(FindProgramWithHints)
include(CMakeDependentOption)
include(GNUInstallDirs)
include(CTest)
include(OptionConditional)
include(Legacy)

# VERSION.pscom:
# 	@echo "$(PACKAGE_NAME) $(VC_VERSION) ($(shell LC_ALL=C date))" > $@
# VC_VERSION="$(cd $(dirname $0) && ./vcversion -r .. -n)"
# execute_process(COMMAND echo bar OUTPUT_VARIABLE FOO)
# OUTPUT_STRIP_TRAILING_WHITESPACE

execute_process(COMMAND ${PROJECT_SOURCE_DIR}/scripts/vcversion -r .. -n
                OUTPUT_VARIABLE VC_VERSION)
message(STATUS "VC_VERSION:          ${VC_VERSION}")

# set the default build type
set(default_build_type "RelWithDebInfo")
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE
      ${default_build_type}
      CACHE
        STRING
        "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
        FORCE)
endif(NOT CMAKE_BUILD_TYPE)

# Explicitly configure the available build types
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O3 -g")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -g")
set(CMAKE_C_FLAGS_DEBUG "-Og -g")

set(_buildtypeEnum RelWithDebInfo Release MinSizeRel Debug)
set(trafficLight
    Green
    CACHE STRING "Status of something")
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS ${_buildtypeEnum})

add_compile_options(-Wall -Wextra -Wconversion -Wno-sign-conversion
                    -Wno-unused-parameter)

include(CheckVisibilityProtected)
if(NOT VISIBILITY_PROTECTED)
  add_compile_definitions(NO_PROTECTED_FUNC=1)
endif(NOT VISIBILITY_PROTECTED)

find_package_with_hints(Popt "/usr" "popt.h" "popt"
                        "Default location where to search popt.")
option_conditional(POPT_ENABLED "Enable popt" TRUE "POPT_FOUND" FALSE)

find_package_with_hints(
  IbVerbs "/usr" "infiniband/verbs.h" "ibverbs"
  "Default location where to search the IB verbs library.")
option_conditional(OPENIB_ENABLED "Enable pscom4openib" FALSE "IBVERBS_FOUND"
                   FALSE)
option_conditional(OFED_ENABLED "Enable pscom4ofed" TRUE "IBVERBS_FOUND" FALSE)

find_package_with_hints(Ucp "/usr" "ucp/api/ucp.h ucp/api/ucp_def.h" "ucp"
                        "Default location where to search UCX library.")
option_conditional(UCP_ENABLED "Enable pscom4ucp" TRUE "UCP_FOUND" FALSE)

find_package_with_hints(Portals4 "/usr" "portals4.h" "portals"
                        "Default location where to search Portals4 library.")
option_conditional(PORTALS4_ENABLED "Enable pscom4portals" TRUE
                   "PORTALS4_FOUND" FALSE)

find_package_with_hints(Psm2 "/usr" "psm2.h psm2_mq.h" "psm2"
                        "Default location where to search PSM2 library.")
option_conditional(PSM2_ENABLED "Enable pscom4psm" TRUE "PSM2_FOUND" FALSE)

find_package(Extoll)
option_conditional(EXTOLL_ENABLED "Enable pscom4extoll and pscom4velo" TRUE
                   "EXTOLL_FOUND" FALSE)

find_package_with_hints(Dapl "/usr" "dat/udat.h" "dat"
                        "Default location where to search DAPL library.")
option_conditional(DAPL_ENABLED "Enable pscom4dapl" TRUE "DAPL_FOUND" FALSE)

find_package_with_hints(Cuda "/usr/local/cuda" "cuda.h driver_types.h" "cuda"
                        "Default location where to search CUDA.")
option_conditional(CUDA_ENABLED "Enable cuda awareness" FALSE "CUDA_FOUND"
                   FALSE)

if(CUDA_ENABLED)
  add_compile_definitions(PSCOM_CUDA_AWARENESS=1)
endif(CUDA_ENABLED)

find_package_with_hints(Cmocka "/usr" "cmocka.h" "cmocka"
                        "Default location where to search cmocka library.")
option_conditional(
  UTEST_ENABLED "Enable unit tests ('ctest' or Target 'utest')" TRUE
  "CMOCKA_FOUND" FALSE)

find_program_with_hints(Iwyu "include-what-you-use" "/usr/bin"
                        "Default location whre to search iwyu binary.")
option_conditional(IWYU_ENABLED "Enable include-what-you-use analysis" FALSE
                   "IWYU_FOUND" FALSE)

#
# Build direct shared memory communication (default: no)
#
option(PSSHMALLOC_ENABLED "Enable psshmalloc" OFF)

if(PSSHMALLOC_ENABLED)
  add_compile_definitions(PSCOM_PSSHMALLOC_ENABLED=1)
endif(PSSHMALLOC_ENABLED)

#
# Enable IWYU analysis during compilation?
#
if(IWYU_ENABLED)
  set(CMAKE_C_INCLUDE_WHAT_YOU_USE
      "${IWYU_BIN};-Xiwyu;--no_fwd_decls;-Xiwyu;--mapping_file=${PROJECT_SOURCE_DIR}/scripts/pscom.imp"
      CACHE STRING
            "If IWYU_ENABLED is set, IWYU is run with the following options."
            FORCE)
endif(IWYU_ENABLED)

#
# Enable perf infrastructure?
#
option(
  PERF_ENABLED
  "enable perf (performance analysis) infrastructure. (Default is disabled.)"
  OFF)

add_subdirectory(include)
add_subdirectory(lib)
add_subdirectory(bin)

#
# Code coverage?
#
option(
  COVERAGE_ENABLED
  "enable code coverage analysis (Default is disabled.) This implies UTEST_ENABLED=ON'."
  OFF)

if(COVERAGE_ENABLED)
  string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_TOUPPER)
  if(NOT (UTEST_ENABLED AND (CMAKE_BUILD_TYPE_TOUPPER STREQUAL "DEBUG")))
    message(
      WARNING
        "COVERAGE_ENABLED requires: UTEST_ENABLED=ON and CMAKE_BUILD_TYPE=Debug. Disabling coverage!"
    )
    set(COVERAGE_ENABLED OFF)
  endif(NOT (UTEST_ENABLED AND (CMAKE_BUILD_TYPE_TOUPPER STREQUAL "DEBUG")))
endif(COVERAGE_ENABLED)

if(UTEST_ENABLED)
  add_subdirectory(test)
endif(UTEST_ENABLED)

add_custom_target(
  VERSION.pscom-target ALL
  BYPRODUCTS VERSION.pscom
  COMMAND ${PROJECT_SOURCE_DIR}/scripts/VERSION.pscom.sh VERSION.pscom
  VERBATIM)

install(FILES ChangeLog LICENSE.QPL ${PROJECT_BINARY_DIR}/VERSION.pscom
        DESTINATION ${CMAKE_INSTALL_DOCDIR})

# Prepare output for plugin-specific options
if(EXTOLL_ENABLED)
  set(EXTOLL_OPTIONS "(EXTOLL_MEMCACHE_ENABLED: ${EXTOLL_MEMCACHE_ENABLED})")
endif(EXTOLL_ENABLED)

message(STATUS "")
message(STATUS "OPENIB_ENABLED:       ${OPENIB_ENABLED}")
message(STATUS "OFED_ENABLED:         ${OFED_ENABLED}")
message(STATUS "UCP_ENABLED:          ${UCP_ENABLED}")
message(STATUS "PORTALS4_ENABLED:     ${PORTALS4_ENABLED}")
message(STATUS "PSM2_ENABLED:         ${PSM2_ENABLED}")
message(STATUS "EXTOLL_ENABLED:       ${EXTOLL_ENABLED}  ${EXTOLL_OPTIONS}")
message(STATUS "DAPL_ENABLED:         ${DAPL_ENABLED}")
message(STATUS "")
message(STATUS "CUDA_ENABLED:         ${CUDA_ENABLED}")
message(STATUS "PSSHMALLOC_ENABLED:   ${PSSHMALLOC_ENABLED}")
message(STATUS "")
message(STATUS "POPT_ENABLED:         ${POPT_ENABLED}")
message(STATUS "")
message(STATUS "UTEST_ENABLED:        ${UTEST_ENABLED}")
message(STATUS "COVERAGE_ENABLED:     ${COVERAGE_ENABLED}")
message(STATUS "PERF_ENABLED:         ${PERF_ENABLED}")
message(STATUS "IWYU_ENABLED:         ${IWYU_ENABLED}")
message(STATUS "")
message(STATUS "CMAKE_BUILD_TYPE:     ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
