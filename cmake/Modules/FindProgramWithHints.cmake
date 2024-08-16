function(find_program_with_hints program_name binary search_path doc)
  string(TOUPPER ${program_name} uc_program_name)

  set(${uc_program_name}_HOME
      ${search_path}
      CACHE STRING ${doc})

  find_program(
    ${uc_program_name}_BIN
    NAMES ${binary}
    HINTS ${${uc_program_name}_HOME} ENV ${uc_program_name}_HOME
    PATH_SUFFIXES include)

  set(${uc_program_name}_BIN
      ${${uc_program_name}_BIN}
      PARENT_SCOPE)

  if(${uc_program_name}_BIN)
    message(STATUS "Found ${program_name}: ${${uc_program_name}_BIN}")
    set(${uc_program_name}_FOUND
        TRUE
        PARENT_SCOPE)
  else(${uc_program_name}_BIN)
    message(STATUS "Could NOT find ${program_name}")
    set(${uc_program_name}_FOUND
        FALSE
        PARENT_SCOPE)
  endif(${uc_program_name}_BIN)
endfunction()
