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
#include <string>
#include <windows.h>

using namespace std;

#define SERVICE_NAME "hermes anti-spam proxy"
#define SERVICE_SHORT_NAME "hermes"
#define SERVICE_DESCRIPTION_TEXT "An anti-spam proxy using a combination of techniques like greylisting, dnsbl/dnswl, SPF, etc."

//macros
#define ChangeServiceStatus(x,y,z) y.dwCurrentState=z; SetServiceStatus(x,&y);
#define MIN(x,y) (((x)<(y))?(x):(y))
#define cmp(x,y) strncmp(x,y,strlen(y))
#define msgbox(x,y,z) MessageBox(NULL,x,z SERVICE_NAME,MB_OK|y)
#define winerror(x) msgbox(x,MB_ICONERROR,"Error from ")
#define winmessage(x) msgbox(x,MB_ICONINFORMATION,"Message from ")
#define condfree(x) if(NULL!=x) free(x);
#define safemalloc(x,y,z) do { if(NULL==(x=(z)malloc(y))) { winerror("Error reserving memory"); exit(-1); } memset(x,0,y); } while(0)
#define _(x) x

/**
 * The docs on microsoft's web don't seem very clear, so I have
 * looked at the stunnel source code to understand how this thing
 * works. What you see here is still original source, but is 
 * "inspired" by stunnel's source code (gui.c mainly).
 * It's the real minimum needed to install, start and stop services
 */

extern bool quit;

extern int hermes_main(int,char**);

SERVICE_STATUS service_status;
SERVICE_STATUS_HANDLE service_status_handle;

int WINAPI WinMain(HINSTANCE,HINSTANCE,LPSTR,int);
static void WINAPI service_main(DWORD,LPTSTR*);
static void WINAPI handler(DWORD);
static int service_install();
static int service_uninstall();

char **params=NULL;
#define free_params() \
  do \
  {  \
    if(NULL!=params) \
    { \
      condfree(params[0]); \
      condfree(params[1]); \
    } \
    condfree(params);    \
  }  \
  while(0)

#define init_params() \
  do \
  {  \
    free_params(); \
    safemalloc(params,sizeof(char *)*2,char **); \
    safemalloc(params[0],1*sizeof(char),char *); \
    params[0][0]='\0'; \
    safemalloc(params[1],1024*sizeof(char),char *); \
  }  \
  while(0)

int WINAPI WinMain(HINSTANCE instance,HINSTANCE previous_instance,LPSTR cmdline,int cmdshow)
{
  if(!cmp(cmdline,"-service"))
  {
    SERVICE_TABLE_ENTRY service_table[]={
      {SERVICE_SHORT_NAME,service_main},
      {NULL,NULL}
    };

    if(0==StartServiceCtrlDispatcher(service_table))
    {
      winerror("Error starting service dispatcher.");
      return -1;
    }
  }
  else if(!cmp(cmdline,"-install"))
    service_install();
  else if(!cmp(cmdline,"-uninstall"))
    service_uninstall();
  else
  {
    //we know that hermes can only have one parameter, so
    //just copy it
    init_params();
    strncpy(params[1],cmdline,1024);
    hermes_main(2,(char **)params);
    free_params();
  }

  return 0;
}

static int service_install()
{
  SC_HANDLE scm,service_handle;
  SERVICE_DESCRIPTION service_description;
  char filename[1024];
  string exepath;

  if(NULL==(scm=OpenSCManager(NULL,NULL,SC_MANAGER_CREATE_SERVICE)))
  {
    winerror(_("Error opening connection to the Service Manager."));
    exit(-1);
  }
  if(0==GetModuleFileName(NULL,filename,sizeof(filename)))
  {
    winerror(_("Error getting the file name of the process."));
    exit(-1);
  }

  exepath=string("\"")+filename+"\" -service";

  service_handle=CreateService(
    scm,                        //scm handle
    SERVICE_SHORT_NAME,               //service name
    SERVICE_NAME,               //display name
    SERVICE_ALL_ACCESS,         //desired access
    SERVICE_WIN32_OWN_PROCESS,  //service type
    SERVICE_AUTO_START,         //start type
    SERVICE_ERROR_NORMAL,       //error control
    exepath.c_str(),            //executable path with arguments
    NULL,                       //load group
    NULL,                       //tag for group id
    NULL,                       //dependencies
    NULL,                       //user name
    NULL);                      //password

  if(NULL==service_handle)
  {
    winerror("Error creating service. Already installed?");
    exit(-1);
  }
  else
    winmessage("Service successfully installed.");

  //createservice doesn't have a field for description
  //so we use ChangeServiceConfig2
  service_description.lpDescription=SERVICE_DESCRIPTION_TEXT;
  ChangeServiceConfig2(service_handle,SERVICE_CONFIG_DESCRIPTION,(void *)&service_description);

  CloseServiceHandle(service_handle);
  CloseServiceHandle(scm);

  return 0;
}

static int service_uninstall()
{
  SC_HANDLE scm,service_handle;
  SERVICE_STATUS status;

  if(NULL==(scm=OpenSCManager(NULL,NULL,SC_MANAGER_CREATE_SERVICE)))
  {
    winerror(_("Error opening connection to the Service Manager."));
    exit(-1);
  }

  if(NULL==(service_handle=OpenService(scm,SERVICE_SHORT_NAME,SERVICE_QUERY_STATUS|DELETE)))
  {
    winerror(_("Error opening service."));
    CloseServiceHandle(scm);
    exit(-1);
  }

  if(0==QueryServiceStatus(service_handle,&status))
  {
    winerror(_("Error querying service."));
    CloseServiceHandle(scm);
    CloseServiceHandle(service_handle);
    exit(-1);
  }

  if(SERVICE_STOPPED!=status.dwCurrentState)
  {
    winerror(SERVICE_NAME _(" is still running. Stop it before trying to uninstall it."));
    CloseServiceHandle(scm);
    CloseServiceHandle(service_handle);
    exit(-1);
  }

  if(0==DeleteService(service_handle))
  {
    winerror(_("Error deleting service."));
    CloseServiceHandle(scm);
    CloseServiceHandle(service_handle);
    exit(-1);
  }

  CloseServiceHandle(scm);
  CloseServiceHandle(service_handle);
  winmessage(_("Service successfully uninstalled."));
  return 0;
}

static void WINAPI service_main(DWORD argc,LPTSTR *argv)
{
  char *tmpstr;

  //configure service_status structure
  service_status.dwServiceType=SERVICE_WIN32;
  service_status.dwControlsAccepted=0;
  service_status.dwWin32ExitCode=NO_ERROR;
  service_status.dwServiceSpecificExitCode=NO_ERROR;
  service_status.dwCheckPoint=0;
  service_status.dwWaitHint=0;
  service_status.dwControlsAccepted|=SERVICE_ACCEPT_STOP;

  service_status_handle=RegisterServiceCtrlHandler(SERVICE_SHORT_NAME,handler);

  if(0!=service_status_handle)
  {
    //set service status
    ChangeServiceStatus(service_status_handle,service_status,SERVICE_RUNNING);

    //get the path to the config file
    init_params();
    GetModuleFileName(NULL,params[1],1024);
    if(NULL==(tmpstr=strrchr(params[1],'\\'))) { winerror("Error finding default config file."); exit(-1); }
    *(++tmpstr)='\0';
    strncat(params[1],"hermes.ini",strlen("hermes.ini"));

    //now start our main program
    hermes_main(2,(char **)params);

    free_params();

    //when we are here, we have been stopped
    ChangeServiceStatus(service_status_handle,service_status,SERVICE_STOP_PENDING);
    ChangeServiceStatus(service_status_handle,service_status,SERVICE_STOPPED);
  }
}

static void WINAPI handler(DWORD code)
{
  if(SERVICE_CONTROL_STOP==code)
  {
    quit=true;
    ChangeServiceStatus(service_status_handle,service_status,SERVICE_STOP_PENDING);
  }
}
