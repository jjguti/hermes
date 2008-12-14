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
#ifndef PROXY_H
#define PROXY_H

#include "hermes.h"
#include <sys/param.h>
#ifdef WIN32
  #include <winsock2.h>
#else
  #include <sys/select.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>

#include "Socket.h"
#include "Configfile.h"
#include "Utils.h"
#include "Logger.h"
#ifdef HAVE_SPF
#include "Spf.h"
#endif //HAVE_SPF

#define SMTP_STATE_WAIT_FOR_HELO 0
#define SMTP_STATE_WAIT_FOR_MAILFROM 1
#define SMTP_STATE_WAIT_FOR_RCPTTO 2
#define SMTP_STATE_WAIT_FOR_DATA 3

class Proxy
{
  private:
    Socket outside; //connection from someone sending mail
    Socket inside; //connection to our inside smtp
  public:
    //Proxy():outside(NULL),inside(NULL){};
    void setOutside(Socket&);
    void run(string&);
};

#endif //PROXY_H
