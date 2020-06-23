
set(CUDA_HOME "/usr/local/cuda" CACHE STRING "Default location where to search CUDA.")

find_path(CUDA_INCLUDE_DIR
  NAMES cuda.h driver_types.h
  HINTS ${CUDA_HOME} ENV CUDA_HOME
  PATH_SUFFIXES include)
find_library(CUDA_LIBRARY
  NAMES cuda
  HINTS ${CUDA_HOME} ENV CUDA_HOME
  PATH_SUFFIXES lib lib64)

set(CUDA_LIBRARIES ${CUDA_LIBRARY})
set(CUDA_INCLUDE_DIRS ${CUDA_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set CUDA_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(
  Cuda  DEFAULT_MSG
  CUDA_LIBRARY CUDA_INCLUDE_DIR)

function(target_add_cuda target)
  target_include_directories(
    ${target}
    PRIVATE ${CUDA_INCLUDE_DIRS}
    )

  target_link_libraries(
    ${target}
    PRIVATE ${CUDA_LIBRARIES}
    )
endfunction()
