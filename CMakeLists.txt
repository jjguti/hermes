project (hermes)
set(SOURCES
  ${CMAKE_CURRENT_BINARY_DIR}/Configfile.cpp
  src/Exception.cpp
  src/hermes.cpp
  src/ServerSocket.cpp
  src/Spf.cpp
  src/Utils.cpp
  src/Database.cpp
  src/Proxy.cpp
  src/Socket.cpp
  src/UnixLogger.cpp)
if(WIN32)
  set(SOURCES ${SOURCES}
    src/FileLogger.cpp
    src/win32-service.cpp)
endif()

configure_file(config.h.in config.h)
find_package(OpenSSL)
pkg_search_module(libspf2 libspf2)
include_directories(${CMAKE_CURRENT_BINARY_DIR}
${CMAKE_CURRENT_SOURCE_DIR}/src)
add_executable (hermes ${SOURCES})
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Configfile.cpp
  COMMAND cpp ${CMAKE_CURRENT_SOURCE_DIR}/src/Configfile.tmpl -I
  ${CMAKE_CURRENT_BINARY_DIR} | ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_config.pl
  DEPENDS src/Configfile.cpp.in src/Configfile.h.in src/Configfile.tmpl
  docs/hermes-options.html.in scripts/generate_config.pl
  ${CMAKE_CURRENT_BINARY_DIR}/config.h )
target_link_libraries(hermes -lpthread -lsqlite3 -lcrypto -lssl -lspf2)
install(TARGETS hermes
  RUNTIME DESTINATION bin)
install(FILES dists/hermesrc.example
  TYPE SYSCONF
  DESTINATION etc)
