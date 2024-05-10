find_path(PSMGMT_INCLUDE_DIR psi.h pse.h HINTS /opt/parastation/include)
find_library(PSMGMT_LIBRARY_PSI psi HINTS /opt/parastation/lib64)
find_library(PSMGMT_LIBRARY_PSE pse HINTS /opt/parastation/lib64)

set(PSMGMT_LIBRARIES ${PSMGMT_LIBRARY_PSI} ${PSMGMT_LIBRARY_PSE})
set(PSMGMT_INCLUDE_DIRS ${PSMGMT_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set PSMGMT_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(Psmgmt DEFAULT_MSG PSMGMT_LIBRARY_PSI
                                  PSMGMT_LIBRARY_PSE PSMGMT_INCLUDE_DIR)

function(target_add_psmgmt target)
  target_include_directories(${target} PRIVATE ${PSMGMT_INCLUDE_DIRS})

  target_link_libraries(${target} PRIVATE ${PSMGMT_LIBRARIES})

  target_compile_definitions(${target} PRIVATE -DPSMGMT_ENABLED)
endfunction()
