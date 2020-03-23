cmake_minimum_required(VERSION 3.12)

project (hermes)
set(LOGGER_CLASS UnixLogger CACHE STRING "One of UnixLogger, FileLogger or NullLogger")


add_executable (hermes
  ${CMAKE_CURRENT_BINARY_DIR}/Configfile.cpp
  src/Exception.cpp
  src/hermes.cpp
  src/ServerSocket.cpp
  src/Utils.cpp
  src/Database.cpp
  src/Proxy.cpp
  src/Socket.cpp)

if(WIN32)
  set(SOURCES ${SOURCES}
    src/FileLogger.cpp
    src/win32-service.cpp)
  target_compile_definitions(hermes PRIVATE WIN32)
endif()

target_compile_definitions(hermes PRIVATE LOGGER_CLASS=${LOGGER_CLASS})
target_sources(hermes PRIVATE src/${LOGGER_CLASS}.cpp)

# required dependency sqlite3
find_package (SQLite3)

# optional dependency libspf2
find_library (spf2 NAMES spf2 libspf2)
if(spf2)
  set(SPF2_LIB -lspf2)
  target_compile_definitions(hermes PRIVATE HAVE_SPF2)
  target_sources(hermes PRIVATE src/Spf.cpp)
  set(OPT_DEFS ${OPT_DEFS} -DHAVE_SPF2)
endif()

# optional dependency openssl
find_package (OpenSSL)
if(OPENSSL_FOUND)
  target_compile_definitions(hermes PRIVATE HAVE_SSL)
  set(OPT_DEFS ${OPT_DEFS} -DHAVE_SSL)
endif()

include_directories(
  ${CMAKE_CURRENT_BINARY_DIR}
  src)

# generation of various files
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Configfile.cpp
  COMMAND cpp ${OPT_DEFS} ${CMAKE_CURRENT_SOURCE_DIR}/src/Configfile.tmpl -I
  ${CMAKE_CURRENT_BINARY_DIR} |
  ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_config.pl
  DEPENDS src/Configfile.cpp.in src/Configfile.h.in src/Configfile.tmpl
  docs/hermes-options.html.in scripts/generate_config.pl)


target_link_libraries(hermes
  ${SQLite3_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${SPF2_LIB}
  pthread)

install(TARGETS hermes
  RUNTIME DESTINATION bin)

install(FILES dists/hermesrc.example
  DESTINATION etc)
