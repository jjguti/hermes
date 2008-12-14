/**
 * hermes antispam proxy
 * Copyright (C) 2006, 2007 Juan José Gutiérrez de Quevedo <juanjo@gutierrezdequevedo.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * @author Juan José Gutiérrez de Quevedo <juanjo@gutierrezdequevedo.com>
 */
#ifndef SOCKET_H
#define SOCKET_H

#include "hermes.h"

#include <iostream>
#include <string>
#include <sstream>
#include <sys/types.h>
#ifdef WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #ifndef AI_ADDRCONFIG
    #define AI_ADDRCONFIG 0 //if the windows we are compiling at is old, define it as 0
  #endif //AI_ADDRCONFIG
#else
  #include <sys/socket.h>
  #include <netdb.h>
  #include <arpa/inet.h>
#endif //WIN32
#include <errno.h>
#ifdef HAVE_SSL
#include <openssl/ssl.h>
#endif //HAVE_SSL

//this is a bit of a hack
//if a system doesn't have MSG_NOSIGNAL then we define it as 0 (that is, no options selected)
//I've tried this on Solaris and NetBSD and it seems to work. Still, recheck in the future (TODO)
#ifndef MSG_NOSIGNAL
  #define MSG_NOSIGNAL 0
#endif //MSG_NOSIGNAL

#include "Configfile.h"
#include "Utils.h"

using namespace std;

/**
 * implements a socket class independent of operating system and that supports ssl
 */
class Socket
{
  protected:
    int fd;
  private:
//    bool closed;
    static int created_sockets;
    #ifdef HAVE_SSL
    bool ssl_enabled;
    SSL *ssl;
    static SSL_CTX *ssl_ctx_client;
    static SSL_CTX *ssl_ctx_server;
    #endif //HAVE_SSL
  public:
    Socket();
    ~Socket();
    #ifdef HAVE_SSL
    void enableSSL(bool);
    #endif //HAVE_SSL
    void setFD(int);
    bool canRead(float);
    bool connect(string,unsigned int);
    int getFD();
    static struct sockaddr resolve(string);
    static string resolveToString(string);
    static string resolveInverselyToString(string);

    void init();
    void close();
    //reading and writing
    char readByte();
    ssize_t readBytes(void *,ssize_t);
    string readLine();

    void writeByte(char);
    void writeBytes(void *,ssize_t);
    void writeLine(string);

    bool isClosed();

    void setTimeout(float,float);
};

#endif //SOCKET_H
