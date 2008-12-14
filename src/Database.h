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
#ifndef DATABASE_H
#define DATABASE_H

#include "hermes.h"

#include <iostream>
#include <string>
#include <sqlite3.h>
#include <pthread.h>

#include "Utils.h"

using namespace std;

/**
 * this class implements an interface to the sqlite3 database
 */
class Database
{
  private:
    string dbfile;
    sqlite3 *dbh;
    void _open();
    int countRows(string);
    void doQuery(string);
    unsigned long getIntValue(string&);
  public:
    Database();
    ~Database();
    void setDatabaseFile(string);
    static string cleanString(string);
    void init();
    void open();
    void close();
    bool greylisted(string,string,string,int,int,int);
    bool whitelistedIP(string);
    bool whitelistedHostname(string);
    bool whitelistedTO(string);
    bool whitelistedDomain(string);
    bool blacklistedTO(string);
    bool blacklistedToDomain(string);
    bool blacklistedIP(string);
    bool blacklistedFROM(string);
    bool allowedDomainPerIP(string,string);
    unsigned long cleanDB();
};

#endif //DATABASE_H
