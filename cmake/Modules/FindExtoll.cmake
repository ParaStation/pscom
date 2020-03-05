
find_path(EXTOLL_INCLUDE_DIR rma2.h velo2.h)
find_library(EXTOLL_RMA2_LIBRARY rma2)
find_library(EXTOLL_VELO2_LIBRARY velo2)

set(EXTOLL_LIBRARIES ${EXTOLL_RMA2_LIBRARY} ${EXTOLL_VELO2_LIBRARY})
set(EXTOLL_INCLUDE_DIRS ${EXTOLL_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set EXTOLL_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(
  Extoll DEFAULT_MSG
  EXTOLL_RMA2_LIBRARY EXTOLL_VELO2_LIBRARY EXTOLL_INCLUDE_DIR)
