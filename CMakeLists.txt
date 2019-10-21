project (hermes)
set(SOURCES
  src/Configfile.cpp
  src/Exception.cpp
  src/hermes.cpp
  src/ServerSocket.cpp
  src/Spf.cpp
  src/Utils.cpp
  src/Database.cpp
  #  src/FileLogger.cpp
  src/Proxy.cpp
  src/Socket.cpp
  src/UnixLogger.cpp)
if(WIN32)
  set(SOURCES ${SOURCES}
    src/win32-service.cpp)
endif()

configure_file(config.h.in config.h)
find_package(OpenSSL)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_executable (hermes ${SOURCES})
target_link_libraries(hermes -lpthread -lsqlite3 -lcrypto -lssl -lspf2)
