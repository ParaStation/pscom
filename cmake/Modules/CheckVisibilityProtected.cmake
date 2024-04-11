execute_process(
  COMMAND env CC=${CMAKE_C_COMPILER}
          ${CMAKE_SOURCE_DIR}/scripts/check-visibility-protected.sh
  RESULT_VARIABLE CHECK_VISIBILITY_RESULT
  OUTPUT_FILE cmake.CheckVisibilityProtected.log
  ERROR_FILE cmake.CheckVisibilityProtected.log)

if(CHECK_VISIBILITY_RESULT EQUAL 0)
  message(STATUS "CheckVisibilityProtected	OK")
  set(VISIBILITY_PROTECTED ON)
else()
  message(STATUS "CheckVisibilityProtected	FAILED")
  set(VISIBILITY_PROTECTED OFF)
endif()
