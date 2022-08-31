
set(PORTALS4_HOME "/usr" CACHE STRING "Default location where to search Portals4 library.")

find_path(PORTALS4_INCLUDE_DIR
  NAMES portals4.h
  HINTS ${PORTALS4_HOME} ENV PORTALS4_HOME
  PATH_SUFFIXES include)
find_library(PORTALS4_LIBRARY
  NAMES portals
  HINTS ${PORTALS4_HOME} ENV PORTALS4_HOME
  PATH_SUFFIXES lib lib64)

set(PORTALS4_LIBRARIES ${PORTALS4_LIBRARY})
set(PORTALS4_INCLUDE_DIRS ${PORTALS4_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set PORTALS4_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(
  Portals4  DEFAULT_MSG
  PORTALS4_LIBRARY PORTALS4_INCLUDE_DIR)
