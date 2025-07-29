function(target_add_rrcomm target)
  target_include_directories(${target} PRIVATE ${RRCOMM_INCLUDE_DIRS})

  target_link_libraries(${target} PRIVATE ${RRCOMM_LIBRARIES})

  target_compile_definitions(${target} PRIVATE -DRRCOMM_PRECON_ENABLED)
endfunction()
