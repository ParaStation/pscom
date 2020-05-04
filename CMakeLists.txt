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


# VERSION.pscom:
# 	@echo "$(PACKAGE_NAME) $(VC_VERSION) ($(shell LC_ALL=C date))" > $@
# VC_VERSION="$(cd $(dirname $0) && ./vcversion -r .. -n)"
# execute_process(COMMAND echo bar OUTPUT_VARIABLE FOO)
# OUTPUT_STRIP_TRAILING_WHITESPACE

execute_process(COMMAND ${PROJECT_SOURCE_DIR}/scripts/vcversion -r .. -n OUTPUT_VARIABLE VC_VERSION)
message("VC_VERSION: ${VC_VERSION}")

add_compile_options(-g -O3)
add_compile_options(-Wall -Wextra -Wconversion -Wno-sign-conversion -Wno-unused -Wno-unused-parameter)

find_package(IbVerbs)
find_package(Ucp)
find_package(Psm2)
find_package(Extoll)
find_package(Dapl)
find_package(Cuda)

cmake_dependent_option(OPENIB_ENABLED "Enable pscom4openib" TRUE "IBVERBS_FOUND" FALSE)
message(STATUS	  "OPENIB_ENABLED:	${OPENIB_ENABLED}")

cmake_dependent_option(OFED_ENABLED "Enable pscom4ofed" TRUE "IBVERBS_FOUND" FALSE)
message(STATUS	  "OFED_ENABLED:	${OFED_ENABLED}")

cmake_dependent_option(UCP_ENABLED "Enable pscom4ucp" TRUE "UCP_FOUND" FALSE)
message(STATUS	  "UCP_ENABLED:		${UCP_ENABLED}")

cmake_dependent_option(PSM2_ENABLED "Enable pscom4psm" TRUE "PSM2_FOUND" FALSE)
message(STATUS	  "PSM2_ENABLED:	${PSM2_ENABLED}")

cmake_dependent_option(EXTOLL_ENABLED "Enable pscom4extoll and pscom4velo" TRUE "EXTOLL_FOUND" FALSE)
message(STATUS	  "EXTOLL_ENABLED:	${EXTOLL_ENABLED}")

cmake_dependent_option(DAPL_ENABLED "Enable pscom4dapl" TRUE "DAPL_FOUND" FALSE)
message(STATUS	  "DAPL_ENABLED:	${DAPL_ENABLED}")

cmake_dependent_option(CUDA_ENABLED "Enable cuda awareness" FALSE "CUDA_FOUND" FALSE)
message(STATUS	  "CUDA_ENABLED:	${CUDA_ENABLED}")

if(CUDA_ENABLED)
add_compile_definitions(PSCOM_CUDA_AWARENESS=1)
endif(CUDA_ENABLED)

add_subdirectory(include)
add_subdirectory(lib)
add_subdirectory(bin)

add_custom_target(VERSION.pscom-target ALL
  BYPRODUCTS VERSION.pscom
  COMMAND ${PROJECT_SOURCE_DIR}/scripts/VERSION.pscom.sh VERSION.pscom
  VERBATIM)

install(FILES
  ChangeLog
  LICENSE.QPL
  ${PROJECT_BINARY_DIR}/VERSION.pscom
  DESTINATION ${CMAKE_INSTALL_DOCDIR})
