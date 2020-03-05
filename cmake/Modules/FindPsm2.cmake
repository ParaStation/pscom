
find_path(PSM2_INCLUDE_DIR psm2.h psm2_mq.h)
find_library(PSM2_LIBRARY psm2)

set(PSM2_LIBRARIES ${PSM2_LIBRARY})
set(PSM2_INCLUDE_DIRS ${PSM2_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set PSM2_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(
  Psm2 DEFAULT_MSG
  PSM2_LIBRARY PSM2_INCLUDE_DIR)
