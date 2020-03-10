
set(VERSION_FILE "vc_version.h")

add_custom_target(${VERSION_FILE} ALL
  BYPRODUCTS ${VERSION_FILE} #<- make clean
  COMMAND ${PROJECT_SOURCE_DIR}/scripts/vc_version.h.sh ${VERSION_FILE}
  VERBATIM)

install(FILES pscom.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
