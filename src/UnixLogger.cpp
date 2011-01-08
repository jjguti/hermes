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
#include "UnixLogger.h"

extern __thread unsigned long connection_id;
extern Configfile cfg;

UnixLogger::UnixLogger()
{
  openlog("hermes",LOG_NDELAY,LOG_MAIL);
}

UnixLogger::~UnixLogger()
{
  closelog();
}

void UnixLogger::addMessage(string file,int line,int loglevel,string logmessage)
{
  string message;

  message=file+":"+Utils::inttostr(line)+" [" + Utils::inttostr(connection_id) + "] " + logmessage;
  if(false==cfg.getBackground())
    cout << message << endl;
  syslog(loglevel,message.c_str());
}
