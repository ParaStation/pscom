include(CheckIPOSupported)
check_ipo_supported(RESULT LTO_SUPPORTED OUTPUT out)

if(LTO_SUPPORTED)
  if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL
                                            "RelWithDebInfo")
    message(
      STATUS
        "LTO is supported and will be enabled for `${CMAKE_BUILD_TYPE}` build.")
    set(LTO_ENABLED
        TRUE
        CACHE INTERNAL "Enable Link Time Optimization")
  else()
    message(
      STATUS "LTO is supported but disabled (build: `${CMAKE_BUILD_TYPE}`).")
    set(LTO_ENABLED
        FALSE
        CACHE INTERNAL "Disable Link Time Optimization")
  endif()
else()
  message(STATUS "LTO not supported by the toolchain: ${out}.")
  set(LTO_ENABLED
      FALSE
      CACHE INTERNAL "Disable Link Time Optimization")
endif()
