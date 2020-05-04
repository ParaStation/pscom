set(VERSION_FILE "vc_version.h")

# - "vc_version.h" must be listed as a BYPRODUCT for "make clean" and
#   "ninja clean" to work.
# - Naming the custom target "vc_version.h" would create a circular dependency
#   in ninja (but would work with make):
#   "ninja: warning: phony target 'include/vc_version.h' names itself as an input;"
# - add_custom_command() does not define targets usable in other directories.
# - In conclusion, the target is now named "vc_version" even if "vc_version.h"
#   will be generated.
add_custom_target(vc_version ALL
  BYPRODUCTS ./${VERSION_FILE} #<- For the "clean" target
  COMMAND ${PROJECT_SOURCE_DIR}/scripts/vc_version.h.sh ${VERSION_FILE}
  VERBATIM)

install(FILES pscom.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
