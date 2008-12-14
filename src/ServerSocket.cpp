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
#include "ServerSocket.h"

void ServerSocket::setPort(unsigned int p_port)
{
  port=p_port;
}

void ServerSocket::listen()
{
  struct sockaddr_in address;

  address.sin_family=AF_INET;
  #ifndef WIN32
  if("any"==listen_ip||""==listen_ip)
    address.sin_addr.s_addr=INADDR_ANY;
  else
    if(!inet_aton(listen_ip.c_str(),&address.sin_addr))
      throw Exception(_("IP address ")+listen_ip+_(" is not valid"),__FILE__,__LINE__);
  #else
  address.sin_addr.s_addr=INADDR_ANY;
  #endif //WIN32
  address.sin_port=htons(port);

  // ...and allow reuse of the socket
  int i=1;
  setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char *)&i,sizeof(i));

  if(bind(fd,(sockaddr*)&address,sizeof(address))==-1)
  {
    close();
    throw Exception(_("Error: binding to address ")+(""==listen_ip?"any":listen_ip)+":"+Utils::inttostr(port),__FILE__,__LINE__);
  }

  if(::listen(fd,10)==-1)
    throw Exception(_("Error: listening"),__FILE__,__LINE__);
}

/**
 * convenience wrapper for listen
 *
 * @param port  port to listen at
 * @param ip    ip to bind to
 */
void ServerSocket::listen(unsigned int p_port,string ip)
{
  setPort(p_port);
  setListenIP(ip);
  listen();
}

void ServerSocket::setListenIP(string& ip)
{
  listen_ip=ip;
}

int ServerSocket::accept(string *straddr)
{
  struct sockaddr_in address;
  socklen_t addresslength=sizeof(address);
  int retval;
  retval=::accept(fd,(sockaddr *)&address,&addresslength);

  if(-1==retval)
    throw Exception(_(Utils::inttostr(retval)),__FILE__,__LINE__);

  if(straddr!=NULL)
    (*straddr)=inet_ntoa(address.sin_addr);
  return retval;
}
