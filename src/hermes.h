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
#ifndef SMTPPROXY_H
#define SMTPPROXY_H

#include "config.h"
#include "Exception.h"
#include <assert.h>
#include <string>

#define _(x) (x)
#define LOG(x,y) hermes_log.addMessage(__FILE__,__LINE__,x,y)
#define LERR(x) LOG(LOG_ERR,x)
#define LINF(x) LOG(LOG_INFO,x)
#define LDEB(x) LOG(LOG_DEBUG,x)


typedef struct
{
  int new_fd;
  std::string peer_address;
  unsigned long connection_id;
}new_conn_info;

#endif //SMTPPROXY_H
