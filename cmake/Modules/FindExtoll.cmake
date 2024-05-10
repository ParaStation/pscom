set(EXTOLL_HOME
    "/opt/extoll/x86_64"
    CACHE STRING "Default location where to search the EXTOLL libraries.")

# We need to link to rma2gpud for GPUDirect support within librma2
if(CUDA_ENABLED)
  set(EXTOLL_RMA2_LIBRARY_NAME "rma2gpud")
else(CUDA_ENABLED)
  set(EXTOLL_RMA2_LIBRARY_NAME "rma2")
endif(CUDA_ENABLED)

find_path(
  EXTOLL_INCLUDE_DIR
  NAMES rma2.h velo2.h
  HINTS ${EXTOLL_HOME}
  PATH_SUFFIXES include)
find_library(
  EXTOLL_RMA2_LIBRARY
  NAMES ${EXTOLL_RMA2_LIBRARY_NAME}
  HINTS ${EXTOLL_HOME}
  PATH_SUFFIXES lib lib64)
find_library(
  EXTOLL_VELO2_LIBRARY
  NAMES velo2
  HINTS ${EXTOLL_HOME}
  PATH_SUFFIXES lib lib64)

set(EXTOLL_LIBRARIES ${EXTOLL_RMA2_LIBRARY} ${EXTOLL_VELO2_LIBRARY})
set(EXTOLL_INCLUDE_DIRS ${EXTOLL_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set EXTOLL_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(Extoll DEFAULT_MSG EXTOLL_RMA2_LIBRARY
                                  EXTOLL_VELO2_LIBRARY EXTOLL_INCLUDE_DIR)
