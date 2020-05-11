
find_path(CMOCKA_INCLUDE_DIR cmocka.h)
find_library(CMOCKA_LIBRARY cmocka)

set(CMOCKA_LIBRARIES ${CMOCKA_LIBRARY})
set(CMOCKA_INCLUDE_DIRS ${CMOCKA_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set CMOCKA_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(
  CMocka  DEFAULT_MSG
  CMOCKA_LIBRARY CMOCKA_INCLUDE_DIR)
