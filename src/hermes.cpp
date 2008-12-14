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
#include <iostream>
#include <list>
#include <stack>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#ifdef HAVE_SSL
#include <openssl/crypto.h>
#endif //HAVE_SSL
#ifndef WIN32
#include <grp.h>
#endif //WIN32

#include "Proxy.h"
#include "Socket.h"
#include "ServerSocket.h"
#include "Configfile.h"
#include "Utils.h"
#include "Logger.h"

using namespace std;

void *thread_main(void *);
void *cleaner_thread_run(void *);
void exit_requested(int);
void write_pid(string,pid_t);

//global var to know when we have to exit
bool quit=false;

//mutexes
pthread_mutex_t childrenlist_mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t info_stack_mutex=PTHREAD_MUTEX_INITIALIZER;

//our config
Configfile cfg;

//our logger
LOGGER_CLASS hermes_log;

list<pthread_t> children;

#ifdef HAVE_SSL
pthread_mutex_t ssl_locks[CRYPTO_NUM_LOCKS]={PTHREAD_MUTEX_INITIALIZER};

void ssl_locking_function(int mode,int n,const char *file,int line)
{
  if(n>CRYPTO_NUM_LOCKS)
    throw Exception(_("Error, "+Utils::inttostr(n)+" is bigger than CRYPTO_NUM_LOCKS("+Utils::inttostr(CRYPTO_NUM_LOCKS)+")"),__FILE__,__LINE__);
  if(mode&CRYPTO_LOCK)
    pthread_mutex_lock(&ssl_locks[n]);
  else
    pthread_mutex_unlock(&ssl_locks[n]);
}
#endif //HAVE_SSL

int
#ifdef WIN32_SERVICE
hermes_main
#else
main
#endif //WIN32_SERVICE
(int argc,char *argv[])
{
  /* TODO:think of this again
  if(argc>2)
  {
    for(unsigned i=1;i<argc;i++)
    {
      argv++
  }
  */

  #ifdef HAVE_SSL
    CRYPTO_set_locking_callback(ssl_locking_function);
    CRYPTO_set_id_callback(pthread_self);
  #endif //HAVE_SSL
  try
  {
    if(2==argc)
    {
      if(!Utils::file_exists(argv[1]))
        throw Exception(string(_("Config file "))+argv[1]+_(" doesn't exist or is not readable."),__FILE__,__LINE__);
      cfg.parse(argv[1]);
    }
    cfg.validateConfig();
  }
  catch(Exception &e)
  {
    cout << string(e) << endl;
    return -1;
  }

  #ifdef REALLY_VERBOSE_DEBUG
    unsigned long nconns=0;
  #endif //REALLY_VERBOSE_DEBUG

  signal(SIGTERM,exit_requested);
  signal(SIGINT,exit_requested);

  //we have to create the server socket BEFORE chrooting, because if we don't,
  //SSL cannot initialize because it's missing libz
  ServerSocket server;
  pthread_t cleaner_thread;
  string peer_address;

  #ifndef WIN32
    if(cfg.getBackground())
    {
      int retval;

      retval=fork();
      if(retval>0)
        exit(0); //succesful fork

      if(retval<0)
      {
        cout << _("Error forking into the background") << Utils::errnotostrerror(errno) << endl;
        return -1;
      }
    }
    
    if(cfg.getPidFile()!="")
    {
      try
      {
        write_pid(cfg.getPidFile(),getpid());
      }
      catch(Exception &e)
      {
        hermes_log.addMessage(LOG_ERR,e);
      }
    }

    if(cfg.getChroot()!="")
    {
      //this is needed to get hermes to load the dns resolver BEFORE chrooting
      (void)gethostbyname("hermes-project.com");
      chdir(cfg.getChroot().c_str());
      if(-1==chroot(cfg.getChroot().c_str()))
      {
        cout << _("Couldn't chroot ") << Utils::errnotostrerror(errno) << endl;
        return -1;
      }
      chdir("/");
    }
  #endif //WIN32

  try
  {
    server.init();
    server.setPort(cfg.getListeningPort());
    server.listen(cfg.getListeningPort(),cfg.getBindTo());
  }
  catch(Exception &e)
  {
    cout << e << endl;
    return -1; //couldn't bind, exit
  }

  #ifndef WIN32
  if(cfg.getDropPrivileges())
  {
    //drop privileges once we have opened the listening port
    setgroups(0,NULL);
    setgid(cfg.getGid());
    setuid(cfg.getUid());
    setuid(cfg.getUid());
  }
  #endif //WIN32

  /* start our cleaner thread */
  if(cfg.getCleanDb())
    pthread_create(&cleaner_thread,NULL,cleaner_thread_run,NULL);

  new_conn_info info;
  stack<new_conn_info> info_stack;
  while(!quit)
  {
    if(server.canRead(1)) //wait one second for incoming connections, if none then loop again(allows us to check for SIGTERM and SIGINT)
    {
      pthread_t thread;
      pthread_attr_t thread_attr;
      pthread_attr_init(&thread_attr);
      pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);

      int retval;
      int fd=server.accept(&peer_address);
      info.new_fd=fd;
      info.peer_address=peer_address;
      pthread_mutex_lock(&info_stack_mutex);
      info_stack.push(info);
      pthread_mutex_unlock(&info_stack_mutex);
      retval=pthread_create(&thread,&thread_attr,thread_main,(void *)&info_stack);
      if(retval)
      {
        #ifdef REALLY_VERBOSE_DEBUG
        cout << _("Error creating thread: ") << Utils::errnotostrerror(retval) << _(". Sleeping 5 seconds before continuing...") << endl;
        #endif //REALLY_VERBOSE_DEBUG
        sleep(5);
      }
      else
      {
        #ifdef REALLY_VERBOSE_DEBUG
        cout << "[ " << ++nconns << " ] " << endl;
        #endif //REALLY_VERBOSE_DEBUG
        pthread_mutex_lock(&childrenlist_mutex);
        children.push_back(thread);
        pthread_mutex_unlock(&childrenlist_mutex);
      }
    }
  }

  //close connection so that the port is no longer usable
  server.close();

  // wait for all threads to finish
  #ifdef REALLY_VERBOSE_DEBUG
  cout << "Waiting for all threads to finish" << endl;
  #endif //REALLY_VERBOSE_DEBUG
  while(children.size())
  {
    #ifdef REALLY_VERBOSE_DEBUG
    cout << "Threads active:" << children.size() << (char)13;
    fflush(stdout);
    #endif //REALLY_VERBOSE_DEBUG
    sleep(1);
  }
  if(cfg.getCleanDb())
    pthread_join(cleaner_thread,NULL);
  #ifdef REALLY_VERBOSE_DEBUG
  cout << endl;
  #endif //REALLY_VERBOSE_DEBUG

  #ifdef HAVE_SPF
  Spf::deinitialize();
  #endif //HAVE_SPF
  return 0;
}

/**
 * this threads cleans the database once each hour, deleting
 * the records on the database that have an expire time < now
 *
 */
void *cleaner_thread_run(void *)
{
  try
  {
    Database db;
    time_t next_run=time(NULL)+3600;

    db.setDatabaseFile(cfg.getDatabaseFile());

    db.open();
    while(!quit)
    {
      time_t now=time(NULL);
      sched_yield();
      if(now>next_run)
      {
        unsigned long spamcount;

        spamcount=db.cleanDB();
        hermes_log.addMessage(LOG_DEBUG,"Cleaning database, cleaning "+Utils::inttostr(spamcount)+" blocked spams.");
        if(spamcount>0&&cfg.getSubmitStats())
        {
          try
          {
            Socket s;
            string server_response;

            s.init();
            s.connect("stats.hermes-project.com",11125);
            #ifdef HAVE_SSL
            if(cfg.getSubmitStatsSsl())
            {
              s.writeLine("ssl");
              s.enableSSL(false);
            }
            else
            #endif //HAVE_SSL
              s.writeLine("non-ssl");
            s.writeLine(cfg.getSubmitStatsUsername());
            s.writeLine(cfg.getSubmitStatsPassword());
            s.writeLine(Utils::inttostr(spamcount));
            server_response=s.readLine();
            s.close();
            if("OK"!=server_response)
              throw Exception(server_response,__FILE__,__LINE__);
          }
          catch(Exception &e)
          {
            hermes_log.addMessage(LOG_DEBUG,"Exception sending stats: "+string(e));
          }
        }
        next_run+=3600;
      }
      #ifdef REALLY_VERBOSE_DEBUG
        if(!(now%10)) //echo info each 10 seconds
        {
          stringstream ss;

          pthread_mutex_lock(&childrenlist_mutex);
          ss << children.size() << " threads running: ";
          for(list<pthread_t>::iterator i=children.begin();i!=children.end();i++)
            ss << "[ " << *i << " ] ";
          pthread_mutex_unlock(&childrenlist_mutex);
          ss << endl;
          cout << ss.str();
        }
      #endif //REALLY_VERBOSE_DEBUG
      sleep(1);
    }
    db.close();
  }
  catch(Exception &e)
  {
    #ifdef REALLY_VERBOSE_DEBUG
    cout << e << endl;
    #endif //REALLY_VERBOSE_DEBUG
  }
  return NULL;
}

void remove_thread_from_list(pthread_t thread)
{
  pthread_mutex_lock(&childrenlist_mutex);
  children.remove(thread);
  pthread_mutex_unlock(&childrenlist_mutex);
}

void *thread_main(void *info_stack)
{
  try
  {
    Socket client; //for the input connection from the client
    Proxy p;
    new_conn_info peerinfo;

    //read a new peerinfo from the stack
    pthread_mutex_lock(&info_stack_mutex);
    peerinfo=((stack<new_conn_info>*)info_stack)->top();
    ((stack<new_conn_info>*)info_stack)->pop();
    pthread_mutex_unlock(&info_stack_mutex);

    client.setFD(peerinfo.new_fd);
    p.setOutside(client);
    p.run(peerinfo.peer_address);
    remove_thread_from_list(pthread_self());
  }
  catch(Exception &e)
  {
    #ifdef REALLY_VERBOSE_DEBUG
    cout << e << endl;
    #endif //REALLY_VERBOSE_DEBUG
    hermes_log.addMessage(LOG_DEBUG,e);
  }
  return NULL;
}

void exit_requested(int)
{
  if(!quit)
  {
    quit=true;
    #ifdef REALLY_VERBOSE_DEBUG
    cout << "Hit control+c again to force-quit" << endl;
    #endif //REALLY_VERBOSE_DEBUG
  }
  else
    exit(-1);
}

void write_pid(string file,pid_t pid)
{
  FILE *f;

  f=fopen(file.c_str(),"w");
  if(NULL==f)
    throw Exception(_("Couldn't open file ")+file+_(" to write the pidfile"),__FILE__,__LINE__);

  fprintf(f,"%d\n",pid);
  fclose(f);
}

#ifdef WIN32
//pthreads on win32 doesn't provide an operator== for pthread_t
//and it's also an struct, not an int, so supply one operator== here
bool operator==(pthread_t t1,pthread_t t2)
{
  return t1.p==t2.p&&t1.x==t2.x;
}
#endif //WIN32
