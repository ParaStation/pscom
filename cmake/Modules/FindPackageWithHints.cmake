function(find_package_with_hints package search_path header_names lib_names doc)
  string(TOUPPER ${package} uc_package)

  set(${uc_package}_HOME ${search_path} CACHE STRING ${doc})

  # Separate the lists of library and header names
  separate_arguments(lib_names)
  separate_arguments(header_names)

  find_path(${uc_package}_INCLUDE_DIR
    NAMES ${header_names}
    HINTS ${${uc_package}_HOME} ENV ${uc_package}_HOME
    PATH_SUFFIXES include)
  find_library(${uc_package}_LIBRARY
    NAMES ${lib_names}
    HINTS ${${uc_package}_HOME} ENV ${uc_package}_HOME
    PATH_SUFFIXES lib lib64)

  set(${uc_package}_LIBRARIES ${${uc_package}_LIBRARY} PARENT_SCOPE)
  set(${uc_package}_INCLUDE_DIRS ${${uc_package}_INCLUDE_DIR} PARENT_SCOPE)

  include(FindPackageHandleStandardArgs)
  # handle the QUIETLY and REQUIRED arguments and set ${uc_package}_FOUND to
  # TRUE if all listed variables are TRUE
  find_package_handle_standard_args(
    ${package} DEFAULT_MSG
    ${uc_package}_LIBRARY ${uc_package}_INCLUDE_DIR)

  # Change the visibility of the resulting ${uc_package}_FOUND variable
  set(${uc_package}_FOUND ${${uc_package}_FOUND} PARENT_SCOPE)
endfunction()
