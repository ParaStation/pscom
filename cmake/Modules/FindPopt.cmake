
set(POPT_HOME "/usr" CACHE STRING "Default location where to search popt.")

find_path(POPT_INCLUDE_DIR
  NAMES popt.h
  HINTS ${POPT_HOME} ENV POPT_HOME
  PATH_SUFFIXES include)
find_library(POPT_LIBRARY
  NAMES popt
  HINTS ${POPT_HOME} ENV POPT_HOME
  PATH_SUFFIXES lib lib64)

set(POPT_LIBRARIES ${POPT_LIBRARY})
set(POPT_INCLUDE_DIRS ${POPT_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set POPT_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(
  Popt  DEFAULT_MSG
  POPT_LIBRARY POPT_INCLUDE_DIR)
