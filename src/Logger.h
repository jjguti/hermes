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
#ifndef LOGGER_H
#define LOGGER_H

#include <string>

using namespace std;

/**
 * logger base class
 */
class Logger
{
  public:
    virtual ~Logger(){}; //empty destructor, not creating anything
    virtual void addMessage(string,int,int,string)=0;
};

#ifndef WIN32
#include "UnixLogger.h"
#endif //WIN32

#ifndef HERMES_LOG_INFO
#define HERMES_LOG_ERR 0
#define HERMES_LOG_INFO 1
#define HERMES_LOG_DEBUG 2
#endif //HERMES_LOG_INFO
#include "FileLogger.h"
#include "NullLogger.h"

#endif //LOGGER_H
