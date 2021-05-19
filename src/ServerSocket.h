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
#ifndef SERVERSOCKET_H
#define SERVERSOCKET_H


#include <sys/types.h>
#ifdef WIN32
  #include <winsock2.h>
#else
  #include <sys/socket.h>
  #include <netdb.h>
  #include <libintl.h>
#endif //WIN32

#include <iostream>

#include "hermes.h"
#include "Socket.h"
/**
 * implement the server specific methods for socket, mainly listen() and accept()
 * @see Socket
 */
class ServerSocket: public Socket
{
  private:
    unsigned int port;
    string listen_ip;
  public:
    ServerSocket(){};
    ~ServerSocket(){};
    void setPort(unsigned int);
    void setListenIP(string&);
    void listen();
    void listen(unsigned int,string);
    int accept(string *);
};

#endif //SERVERSOCKET_H
