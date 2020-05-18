#
# ParaStation
#
# Copyright (C) 2020 ParTec Cluster Competence Center GmbH, Munich
#
# This file may be distributed under the terms of the Q Public License
# as defined in the file LICENSE.QPL included in the packaging of this
# file.
#

project(pscom)

cmake_minimum_required(VERSION 3.10)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
include(CMakeDependentOption)
include(GNUInstallDirs)
include(CTest)
include(OptionConditional)

# VERSION.pscom:
# 	@echo "$(PACKAGE_NAME) $(VC_VERSION) ($(shell LC_ALL=C date))" > $@
# VC_VERSION="$(cd $(dirname $0) && ./vcversion -r .. -n)"
# execute_process(COMMAND echo bar OUTPUT_VARIABLE FOO)
# OUTPUT_STRIP_TRAILING_WHITESPACE

execute_process(COMMAND ${PROJECT_SOURCE_DIR}/scripts/vcversion -r .. -n OUTPUT_VARIABLE VC_VERSION)
message("VC_VERSION: ${VC_VERSION}")

#
# Optimizations?
#
option(OPTIMIZATIONS_ENABLED "compile using the -O3 or -O0 flag" ON)

if(OPTIMIZATIONS_ENABLED)
  add_compile_options(-O3)
else(OPTIMIZATIONS_ENABLED)
  add_compile_options(-O0)
endif(OPTIMIZATIONS_ENABLED)

add_compile_options(-g)
add_compile_options(-Wall -Wextra -Wconversion -Wno-sign-conversion -Wno-unused -Wno-unused-parameter)

include(CheckVisibilityProtected)
if(NOT VISIBILITY_PROTECTED)
  add_compile_definitions(NO_PROTECTED_FUNC=1)
endif(NOT VISIBILITY_PROTECTED)

find_package(IbVerbs)
option_conditional(OPENIB_ENABLED "Enable pscom4openib" TRUE "IBVERBS_FOUND" FALSE)
option_conditional(OFED_ENABLED "Enable pscom4ofed" TRUE "IBVERBS_FOUND" FALSE)

find_package(Ucp)
option_conditional(UCP_ENABLED "Enable pscom4ucp" TRUE "UCP_FOUND" FALSE)

find_package(Psm2)
option_conditional(PSM2_ENABLED "Enable pscom4psm" TRUE "PSM2_FOUND" FALSE)

find_package(Extoll)
option_conditional(EXTOLL_ENABLED "Enable pscom4extoll and pscom4velo" TRUE "EXTOLL_FOUND" FALSE)

find_package(Dapl)
option_conditional(DAPL_ENABLED "Enable pscom4dapl" TRUE "DAPL_FOUND" FALSE)

find_package(Cuda)
option_conditional(CUDA_ENABLED "Enable cuda awareness" FALSE "CUDA_FOUND" FALSE)

if(CUDA_ENABLED)
  add_compile_definitions(PSCOM_CUDA_AWARENESS=1)
endif(CUDA_ENABLED)

find_package(Psmgmt)
option_conditional(PSMGMT_ENABLED "Enable psmgmt" TRUE "PSMGMT_FOUND" FALSE)

find_package(CMocka)
option_conditional(UTEST_ENABLED "Enable unit tests ('ctest' or Target 'utest')" TRUE "CMOCKA_FOUND" FALSE)

add_subdirectory(include)
add_subdirectory(lib)
add_subdirectory(bin)


if(UTEST_ENABLED)
  add_subdirectory(test)
endif(UTEST_ENABLED)


#
# Code coverage?
#
option(COVERAGE_ENABLED "enable code coverage analysis (Default is disabled.) This implies OPTIMIZATIONS_ENABLED=OFF and UTEST_ENABLED=ON'." OFF)

if(COVERAGE_ENABLED)
  if(OPTIMIZATIONS_ENABLED OR NOT UTEST_ENABLED)
    message(WARNING "COVERAGE_ENABLED requires:
  UTEST_ENABLED=ON
  OPTIMIZATIONS_ENABLED=OFF")
    set(COVERAGE_ENABLED OFF)
    # AC_CHECK_PROG([HAVE_LCOV],[lcov],[yes],[no])
    # AC_CHECK_PROG([HAVE_GENHTML],[genhtml],[yes],[no])
  endif(OPTIMIZATIONS_ENABLED OR NOT UTEST_ENABLED)
endif(COVERAGE_ENABLED)


add_custom_target(VERSION.pscom-target ALL
  BYPRODUCTS VERSION.pscom
  COMMAND ${PROJECT_SOURCE_DIR}/scripts/VERSION.pscom.sh VERSION.pscom
  VERBATIM)

install(FILES
  ChangeLog
  LICENSE.QPL
  ${PROJECT_BINARY_DIR}/VERSION.pscom
  DESTINATION ${CMAKE_INSTALL_DOCDIR})

message(STATUS	  "OPENIB_ENABLED:	${OPENIB_ENABLED}")
message(STATUS	  "OFED_ENABLED:	${OFED_ENABLED}")
message(STATUS	  "UCP_ENABLED:		${UCP_ENABLED}")
message(STATUS	  "PSM2_ENABLED:	${PSM2_ENABLED}")
message(STATUS	  "EXTOLL_ENABLED:	${EXTOLL_ENABLED}")
message(STATUS	  "DAPL_ENABLED:	${DAPL_ENABLED}")
message(STATUS	  "CUDA_ENABLED:	${CUDA_ENABLED}")
message(STATUS	  "")
message(STATUS	  "PSMGMT_ENABLED:	${PSMGMT_ENABLED}")
message(STATUS	  "UTEST_ENABLED:	${UTEST_ENABLED}")
message(STATUS	  "COVERAGE_ENABLED:	${COVERAGE_ENABLED}")
message(STATUS	  "OPTIMIZATIONS_ENABLED:	${OPTIMIZATIONS_ENABLED}")

