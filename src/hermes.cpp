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

//global var to know when we have to exit
bool quit=false;

//mutexes
pthread_mutex_t childrenlist_mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t info_stack_mutex=PTHREAD_MUTEX_INITIALIZER;

//our config
Configfile cfg;

//our logger
LOGGER_CLASS hermes_log;

//this variable is thread-local to allow having a unique id per-thread which we can
//print at the start of log messages
__thread unsigned long connection_id;

list<unsigned long> children;

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
    #ifndef WIN32 //getpid() returns different values for threads on windows, therefor this is not needed
    CRYPTO_set_id_callback(pthread_self);
    #endif //WIN32
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
    LERR(e);
    return -1;
  }

  unsigned long nconns=0;

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
        LERR(_("Error forking into the background") + Utils::errnotostrerror(errno));
        return -1;
      }
    }
    
    if(cfg.getPidFile()!="")
    {
      try
      {
        Utils::write_pid(cfg.getPidFile(),getpid());
      }
      catch(Exception &e)
      {
        LERR(e);
      }
    }

    if(cfg.getChroot()!="")
    {
      //this is needed to get hermes to load the dns resolver BEFORE chrooting
      (void)gethostbyname("hermes-project.com");
      chdir(cfg.getChroot().c_str());
      if(-1==chroot(cfg.getChroot().c_str()))
      {
        LERR(_("Couldn't chroot ") + Utils::errnotostrerror(errno));
        return -1;
      }
      chdir("/");
    }
  #endif //WIN32

  LINF("Starting hermes");
  try
  {
    server.init();
    server.setPort(cfg.getListeningPort());
    server.listen(cfg.getListeningPort(),cfg.getBindTo());
  }
  catch(Exception &e)
  {
    LERR(e);
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
      info.connection_id=++nconns;
      pthread_mutex_lock(&info_stack_mutex);
      info_stack.push(info);
      pthread_mutex_unlock(&info_stack_mutex);
      retval=pthread_create(&thread,&thread_attr,thread_main,(void *)&info_stack);
      if(retval)
      {
	LERR(_("Error creating thread: ") + Utils::errnotostrerror(retval) + _(". Sleeping 5 seconds before continuing..."));
        sleep(5);
      }
      else
      {
	#ifdef WIN32
	LDEB("New thread created [" + Utils::ulongtostr(nconns) + "] thread_id: " + Utils::ulongtostr(thread.p) + ":" + Utils::ulongtostr(thread.x));
	#else
	LDEB("New thread created [" + Utils::ulongtostr(nconns) + "] thread_id: " + Utils::ulongtostr(thread));
	#endif //WIN32
        pthread_mutex_lock(&childrenlist_mutex);
        children.push_back(nconns);
        pthread_mutex_unlock(&childrenlist_mutex);
      }
    }
  }

  //close connection so that the port is no longer usable
  server.close();

  // wait for all threads to finish
  LINF("Waiting for threads to finish");
  #ifndef WIN32
  while(children.size())
  {
    if(false==cfg.getBackground())
    {
      cout << "Threads active:" << children.size() << (char)13;
      fflush(stdout);
    }
    sleep(1);
  }
  #endif //WIN32
  if(cfg.getCleanDb())
    pthread_join(cleaner_thread,NULL);

  #ifndef WIN32
  if(false==cfg.getBackground())
    cout << endl;
  #endif //WIN32

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

        try
        {
          spamcount=db.cleanDB();
        }
        catch(Exception &e)
        {
          LERR("Error cleaning the database: " + string(e));
        }
        LDEB("Cleaning database, cleaning "+Utils::inttostr(spamcount)+" blocked spams.");
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
            LDEB("Exception sending stats: "+string(e));
          }
        }
        next_run+=3600;
      }
      #ifndef WIN32
      if(false==cfg.getBackground())
      {
        if(!(now%10)) //echo info each 10 seconds
        {
          stringstream ss;

          pthread_mutex_lock(&childrenlist_mutex);
          ss << children.size() << " threads running: ";
          for(list<unsigned long>::iterator i=children.begin();i!=children.end();i++)
            ss << "[ " << *i << " ] ";
          pthread_mutex_unlock(&childrenlist_mutex);
          ss << endl;
          cout << ss.str();
        }
      }
      #endif //WIN32
      sleep(1);
    }
    db.close();
  }
  catch(Exception &e)
  {
    LERR(e);
  }
  return NULL;
}

void remove_child_from_childlist(unsigned long child_id)
{
  pthread_mutex_lock(&childrenlist_mutex);
  children.remove(child_id);
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

    connection_id=peerinfo.connection_id;
    client.setFD(peerinfo.new_fd);
    p.setOutside(client);
    p.run(peerinfo.peer_address);
    remove_child_from_childlist(connection_id);
  }
  catch(Exception &e)
  {
    LDEB(e);
  }
  return NULL;
}

void exit_requested(int)
{
  if(!quit)
  {
    quit=true;
    #ifndef WIN32
    if(false==cfg.getBackground())
      cout << "Hit control+c again to force-quit" << endl;
    #endif //WIN32
  }
  else
    exit(-1);
}

#ifdef WIN32
//pthreads on win32 doesn't provide an operator== for pthread_t
//and it's also an struct, not an int, so supply one operator== here
bool operator==(pthread_t t1,pthread_t t2)
{
  return t1.p==t2.p&&t1.x==t2.x;
}
#endif //WIN32
