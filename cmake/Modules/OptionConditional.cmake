function(option_conditional pkg_enabled label default_true condition_var
         default_false)
  if(${${condition_var}})
    option(${pkg_enabled} "${label}" ${default_true})
  else()
    option(${pkg_enabled} "${label}" ${default_false})
  endif()

  if(${${pkg_enabled}} AND (NOT ${${condition_var}}))
    message(
      FATAL_ERROR
        "${pkg_enabled}=${${pkg_enabled}}, but ${condition_var}=${${condition_var}}"
    )
  endif()
endfunction()
