
if(COMMAND target_link_options)
else()
  # Legacy partial implementation of:
  # target_link_options(<target> PUBLIC [items1...])

  function(target_link_options)
    set(options)
    set(oneValueArgs)
    set(multiValueArgs PRIVATE)

    cmake_parse_arguments(ARGS "${options}" "${oneValueArgs}"
      "${multiValueArgs}" ${ARGN} )

    set(ARGS_TARGET ${ARGS_UNPARSED_ARGUMENTS})

    # Emulate:
    #
    # target_link_options(
    #   ${ARGS_TARGET}
    #   PRIVATE ${ARGS_PRIVATE})

    foreach(_priv ${ARGS_PRIVATE})
      set_property(
	TARGET ${ARGS_TARGET}
	APPEND_STRING
	PROPERTY LINK_FLAGS " ${_priv}")
    endforeach()
  endfunction()

endif()

if(COMMAND add_compile_definitions)
else()
  # Legacy partial implementation of:
  # add_compile_definitions(<definition>)

  function(add_compile_definitions def)
    add_definitions(-D${def})
  endfunction()
endif()
