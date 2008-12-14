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
#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <iostream>
#include <string>

#include "Configfile.h"
#include "Logger.h"

using namespace std;

class Exception
{
  private:
    string error;
    string file;
    unsigned line;
    void notifyByEmail(string);
  public:
    Exception(string,string,unsigned);
    operator string();
    friend ostream& operator<<(ostream&,Exception&);
};

class NetworkException:public Exception
{
  public:
    NetworkException(string p_error,string p_file,int p_line):Exception(p_error,p_file,p_line){}
};

class SQLException:public Exception
{
  public:
    SQLException(string p_error,string p_file,int p_line):Exception(p_error,p_file,p_line){}
};

class NotifyException
{
  private:
    string error;
  public:
    NotifyException(string p_error){ error=p_error; }
    operator string(){ return "NotifyException: "+error;};
};
#endif //EXCEPTION_H
