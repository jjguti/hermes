INCLUDES = $(OpenSSL_CFLAGS) $(SQLite3_CFLAGS)
LIBS = $(OpenSSL_LIBS) $(SQLite3_LIBS)
CXXFLAGS += -Wall -pedantic -Wshadow -pthread -Werror --std=c++11

bin_PROGRAMS = hermes
nodist_hermes_SOURCES = Configfile.cpp
hermes_SOURCES = Proxy.cpp ServerSocket.cpp Socket.cpp Database.cpp Utils.cpp Exception.cpp hermes.cpp
noinst_HEADERS = Proxy.h ServerSocket.h Socket.h Database.h UnixLogger.cpp FileLogger.h NullLogger.h Logger.h Utils.h Exception.h hermes.h Spf.h
EXTRA_DIST = Configfile.cpp.in Configfile.h.in Configfile.tmpl UnixLogger.cpp UnixLogger.h FileLogger.cpp FileLogger.h

if LOGGER_UNIX
  hermes_SOURCES += UnixLogger.cpp
endif

if LOGGER_FILE
  hermes_SOURCES += FileLogger.cpp
endif

if HAVE_SPF
  hermes_SOURCES += Spf.cpp
  LIBS += -lspf2
endif

if WIN32_SERVICE
  hermes_SOURCES += win32-service.cpp
endif

Configfile.h: Configfile.cpp.in Configfile.h.in Configfile.tmpl ../docs/hermes-options.html.in ../scripts/generate_config.pl ../config.h
	cpp Configfile.tmpl|../scripts/generate_config.pl

Configfile.cpp: Configfile.h Configfile.cpp.in Configfile.h.in Configfile.tmpl ../docs/hermes-options.html.in ../scripts/generate_config.pl ../config.h

*.cpp: Configfile.h
