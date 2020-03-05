
find_path(IBVERBS_INCLUDE_DIR infiniband/verbs.h)
find_library(IBVERBS_LIBRARY ibverbs)

set(IBVERBS_LIBRARIES ${IBVERBS_LIBRARY})
set(IBVERBS_INCLUDE_DIRS ${IBVERBS_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set IBVERBS_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(
  IbVerbs  DEFAULT_MSG
  IBVERBS_LIBRARY IBVERBS_INCLUDE_DIR)
