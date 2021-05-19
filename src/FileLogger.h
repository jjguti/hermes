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
#ifndef FILELOGGER_H
#define FILELOGGER_H

#include <stdio.h>
#include <pthread.h>
#include <string>
#include <list>

#include "Logger.h"
#include "Configfile.h"

using namespace std;

/**
 * this class implements a logger that writes to a file
 *
 * @see Logger
 */
class FileLogger: public Logger
{
  unsigned char linecount;
  time_t last_rotation;
  private:
    FILE *f;
    pthread_mutex_t mutex;
    list<string> tmpstrings;
    void openFile(string);
    void closeFile();
    void syncBufferToDisk();
    void rotateLog();
    string getProcessedRotateFilename();
  public:
    FileLogger();
    ~FileLogger();
    void addMessage(string,int,int,string);
};

#endif //FILELOGGER_H
