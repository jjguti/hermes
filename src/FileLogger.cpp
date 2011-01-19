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
#include "FileLogger.h"

extern Configfile cfg;
extern __thread unsigned long connection_id;

FileLogger::FileLogger():linecount(0)
{
  pthread_mutex_init(&mutex,NULL);
  tmpstrings.clear();
  last_rotation=time(NULL);
}

FileLogger::~FileLogger()
{
  if(!cfg.getKeepFileLocked())
    syncBufferToDisk();
  closeFile();
  pthread_mutex_destroy(&mutex);
}

void FileLogger::openFile(string file)
{
  if(NULL==f&&""!=file)
  {
    f=fopen(file.c_str(),"a");
    if(NULL==f)
      throw Exception(_("Couldn't start file logger, couldn't open ")+cfg.getFileLoggerFilename(),__FILE__,__LINE__);
  }
}

void FileLogger::closeFile()
{
  if(NULL!=f)
  {
    fclose(f);
    f=NULL;
  }
}

void FileLogger::syncBufferToDisk()
{
  openFile(cfg.getFileLoggerFilename());
  if(NULL!=f)
  {
    for(list<string>::iterator i=tmpstrings.begin();i!=tmpstrings.end();i++)
      fprintf(f,"%s\n",i->c_str());
    closeFile();
    tmpstrings.clear();
  }
}

void FileLogger::addMessage(string file,int line,int loglevel,string logmessage)
{
  pthread_mutex_lock(&mutex);
  if(cfg.getLogRotationFrequency()>0&&last_rotation+(cfg.getLogRotationFrequency()*60)<time(NULL))
  {
    #ifdef REALLY_VERBOSE_DEBUG
    cout << "Rotating log to file " << getProcessedRotateFilename() << " at " << time(NULL) << " with a last rotation of " << last_rotation << endl;
    #endif //REALLY_VERBOSE_DEBUG
    rotateLog();
    addMessage(__FILE__,__LINE__,LOG_DEBUG,"Rotated log to file " + getProcessedRotateFilename() + " at " + Utils::ulongtostr(time(NULL)) + " with a last rotation of " + Utils::ulongtostr(last_rotation));
  }
  try
  {
    if(!cfg.getKeepFileLocked())
      tmpstrings.push_back(Utils::rfc2821_date()+": "+logmessage);
    else
    {
      openFile(cfg.getFileLoggerFilename());
      if(NULL!=f)
        fprintf(f,"%s: %s:%ld [%ld] %s\n",Utils::rfc2821_date().c_str(),file.c_str(),long(line),connection_id,logmessage.c_str());
    }
    if(++linecount>30)
    {
      linecount=0;
      if(!cfg.getKeepFileLocked())
        syncBufferToDisk();
      else if(NULL!=f)
        fflush(f);
    }
  }
  catch(Exception &e)
  {
    pthread_mutex_unlock(&mutex);
    throw e;
  }
  pthread_mutex_unlock(&mutex);
}

void FileLogger::rotateLog()
{
  string filename="";

  if(!cfg.getKeepFileLocked())
    syncBufferToDisk();

  closeFile();

  filename=getProcessedRotateFilename();
  if(-1==rename(cfg.getFileLoggerFilename().c_str(),filename.c_str()))
    throw Exception("Error renaming logfile to "+filename+": "+Utils::errnotostrerror(errno),__FILE__,__LINE__);
  last_rotation=time(NULL);
}

#define SUBSTITUTE(x) \
sizetemp=tmpstr.find("%%" #x "%%");\
if(sizetemp!=string::npos)\
  tmpstr.replace(sizetemp,strlen("%%" #x "%%"),x);

#define GETDATECHR(x,y) \
strftime(tmpchar,sizeof(tmpchar),x,local_time);\
y=tmpchar;

string FileLogger::getProcessedRotateFilename()
{
  string tmpstr=cfg.getRotateFilename();
  string::size_type sizetemp;
  string year,month,day,hour,minute;
  char tmpchar[5];
  struct tm *local_time;
  time_t t;

  t=time(NULL);
  local_time=localtime(&t);

  GETDATECHR("%Y",year);
  GETDATECHR("%m",month);
  GETDATECHR("%d",day);
  GETDATECHR("%H",hour);
  GETDATECHR("%M",minute);

  SUBSTITUTE(day);
  SUBSTITUTE(month);
  SUBSTITUTE(year);
  SUBSTITUTE(hour);
  SUBSTITUTE(minute);

  return tmpstr;
}
