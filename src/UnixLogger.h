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
#ifndef UNIXLOGGER_H
#define UNIXLOGGER_H

#include <syslog.h>
#include <string>

#include "Logger.h"

using namespace std;

/**
 * implements the logger for Linux/UNIX
 *
 * @see Logger
 */
class UnixLogger: public Logger
{
  public:
    UnixLogger();
    ~UnixLogger();
    void addMessage(string,int,int,string);
};

#endif //UNIXLOGGER_H
