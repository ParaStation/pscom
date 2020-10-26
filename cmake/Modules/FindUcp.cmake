
set(UCP_HOME "/usr" CACHE STRING "Default location where to search UCX library.")

find_path(UCP_INCLUDE_DIR
  NAMES ucp/api/ucp.h ucp/api/ucp_def.h
  HINTS ${UCP_HOME} ENV UCP_HOME
  PATH_SUFFIXES include)
find_library(UCP_LIBRARY
  NAMES ucp
  HINTS ${UCP_HOME} ENV UCP_HOME
  PATH_SUFFIXES lib lib64)

set(UCP_LIBRARIES ${UCP_LIBRARY})
set(UCP_INCLUDE_DIRS ${UCP_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set UCP_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(
  Ucp  DEFAULT_MSG
  UCP_LIBRARY UCP_INCLUDE_DIR)
