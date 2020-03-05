
find_path(DAPL_INCLUDE_DIR dat/udat.h)
find_library(DAPL_LIBRARY dat)

set(DAPL_LIBRARIES ${DAPL_LIBRARY})
set(DAPL_INCLUDE_DIRS ${DAPL_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set DAPL_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(
  Dapl  DEFAULT_MSG
  DAPL_LIBRARY DAPL_INCLUDE_DIR)
