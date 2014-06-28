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
#ifndef UTILS_H
#define UTILS_H

#include "hermes.h"
#include <string>
#include <sstream>
#include <iostream>
#include <dirent.h>
#include <time.h>

#ifndef WIN32
  #include <pwd.h>
  #include <grp.h>
#endif //WIN32

#include "Database.h"
#include "Socket.h"

using namespace std;

#ifdef WIN32
#define sleep(x) Sleep(1000*(x))
#endif //WIN32

/*#ifndef MAX
#define MAX(x,y) (((x)>(y))?(x):(y))
#endif //MAX*/

/**
 * this class implements common utilities
 */
class Utils
{
  public:
    //string utilities
    static string strtolower(string);
    static string trim(string);
    static string inttostr(int);
    static string ulongtostr(unsigned long);

    //email-related utilities
    static string getmail(string&);
    static string getdomain(string&);
    static string reverseip(string&);

    //spam-related utilities (TODO: move to a different class)
    static bool greylist(string,string&,string&,string&);
    static bool listed_on_dns_lists(list<string>&,unsigned char,string&);
    static bool whitelisted(string,string&);
    static bool blacklisted(string,string&,string&);

    #ifndef WIN32
    //posix-utils
    static int usertouid(string);
    static int grouptogid(string);
    #endif //WIN32

    //misc
    static string get_canonical_filename(string);
    static bool file_exists(string);
    static bool dir_exists(string);
    static string errnotostrerror(int);
    static string rfc2821_date(time_t *timestamp=NULL);
    static string gethostname();
    static void write_pid(string,pid_t);
    static string gethostname(int s);
};

#endif //UTILS_H
