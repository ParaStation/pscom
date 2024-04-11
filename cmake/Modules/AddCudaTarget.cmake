function(target_add_cuda target)
  target_include_directories(${target} PRIVATE ${CUDA_INCLUDE_DIRS})

  target_link_libraries(${target} PRIVATE ${CUDA_LIBRARIES})
endfunction()
