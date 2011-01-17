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
#include "Utils.h"

extern Configfile cfg;
extern LOGGER_CLASS hermes_log;

//--------------------
// string functions:
//--------------------

/**
 * convert integer to string
 *
 * @param integer integer to convert
 *
 * @return string the integer converted to stringtype
 *
 */
string Utils::inttostr(int integer)
{
  stringstream s;
  s << integer;
  return s.str();
}

/**
 * convert unsigned long to string
 *
 * @param number number to convert
 *
 * @return string the number converted to stringtype
 *
 */
string Utils::ulongtostr(unsigned long number)
{
  stringstream s;
  s << number;
  return s.str();
}

/**
 * return lowercase version of s
 *
 * @param s string to convert
 *
 * @return string lowercase version of s
 *
 */
string Utils::strtolower(string s)
{
  for(unsigned int i=0;i<s.length();i++)
    s[i]=tolower(s[i]);

  return s;
}

/**
 * trim spaces from both sides of the string
 *
 * @param s string to trim
 *
 * @return string trimmed string
 *
 */
string Utils::trim(string s)
{
  while(isspace(s[0]))
    s.erase(0,1);

  while(isspace(s[s.length()-1]))
    s.erase(s.length()-1,1);

  return s;
}

//------------------------
// email-related functions:
//------------------------

/**
 * decide whether a triplet should be greylisted or not
 *
 * basically it follows this diagram:
 *
 * <pre>
 * +------------------------------------------+
 * |                                          |yes
 * | whitelisted?(IP or TO or DOMAIN or HOST) |----> don't greylist
 * |                                          |
 * +------------------------------------------+
 *               |
 *               | no
 *               |
 *               v
 * +----------------------------------+
 * |                                  |yes
 * |    blacklisted? (IP or FROM)     |----> greylist
 * |                                  |
 * +----------------------------------+
 *               |
 *               | no
 *               |
 *               v
 * +----------------------------------+
 * |                                  |yes
 * |    greylisted? (triplet)         |----> greylist
 * |                                  |
 * +----------------------------------+
 *               |
 *               | no
 *               |
 *               v
 *         don't greylist
 * </pre>
 *
 * @param dbfile   sqlite database file to use. if doesn't exist then initialize
 * @param ip       ip of remote client, first of our triplet
 * @param p_from   mail from header, second of our triplet
 * @param p_to     rcpt to header, third of our triplet
 *
 * @return whether triplet should get greylisted or not
 * @todo unify {white,black,grey}list in one function that returns a different constant in each case
 */
bool Utils::greylist(string dbfile,string& ip,string& p_from,string& p_to)
{
  string from=Database::cleanString(p_from);
  string to=Database::cleanString(p_to);
  string hostname;
  Database db;

  db.setDatabaseFile(dbfile);
  db.open();

  try
  {
    hostname=Socket::resolveInverselyToString(ip);
  }
  catch(Exception &e)
  {
    hostname="unresolved";
  }
  if(db.whitelistedIP(ip)||db.whitelistedTO(to)||db.whitelistedDomain(getdomain(to))||(""!=hostname&&db.whitelistedHostname(hostname)))
    return false;

  if(db.blacklistedIP(ip)||db.blacklistedFROM(from)||db.blacklistedTO(to)||db.blacklistedToDomain(getdomain(to)))
    return true;

  if(db.greylisted(ip,from,to,cfg.getInitialExpiry(),cfg.getInitialBlacklist(),cfg.getWhitelistExpiry()))
    return true;
  else
    return false;
}

/**
 * whether an ip is listed on the database as whitelisted
 *
 * @param dbfile  sqlite3 database file
 * @param ip      ip of remote machine
 *
 * @return whether ip is whitelisted or not
 * @todo unify {white,black,grey}list in one function that returns a different constant in each case
 */
bool Utils::whitelisted(string dbfile,string& ip)
{
  Database db;
  string hostname;

  db.setDatabaseFile(dbfile);
  db.open();

  try
  {
    hostname=Socket::resolveInverselyToString(ip);
  }
  catch(Exception &e)
  {
    hostname="unresolved";
  }

  if(db.whitelistedIP(ip)||(""!=hostname&&db.whitelistedHostname(hostname)))
    return true;

  return false;
}

/**
 * whether an ip is listed on the database as blacklisted
 *
 * @param dbfile  sqlite3 database file
 * @param ip      ip of remote machine
 *
 * @return whether ip is whitelisted or not
 * @todo this should contain all cases when we should reject a connection
 */
bool Utils::blacklisted(string dbfile,string& ip,string& to)
{
  Database db;
  string hostname;

  db.setDatabaseFile(dbfile);
  db.open();

  return false==db.allowedDomainPerIP(getdomain(to),ip);
}

/**
 * this function extracts the email from rcpt to and mail from lines
 * i.e.:
 * rcpt to: "BillG" <bill@m.com>  -->  bill@m.com
 *
 * @param rawline line read from the socket
 *
 * @return email extracted from rawline
 *
 */
string Utils::getmail(string& rawline)
{
  string email;
  string::size_type start=0,end=0;

  start=rawline.find('@');
  if(start!=string::npos) //case 1 -> email has an @(most common), start from there and look for spaces or </> as delimiters
  {
    start=rawline.find_last_of(":< ",start);
    end=rawline.find_first_of("> ",start+1);
    if(end==string::npos)  //there is no space at the end, from start to end-of-line
      end=rawline.length();
    if(start!=string::npos&&end!=string::npos&&start<=end)
      return trim(rawline.substr(start+1,end-start-1));
  }

  start=rawline.find(':');
  start=rawline.find_first_of("< ",start);
  if(start!=string::npos)  // case 2 -> email is between <> or spaces and doesn't contain an @(i.e. local user)
  {
    start=rawline.find_first_not_of("< ",start+1);
    if('"'==rawline[start]) // it can contain a name for the from(rcpt to: "BillG" billg@m.com)
    {
      start=rawline.find("\"",start+1);
      start=rawline.find_first_not_of("< ",start+1);
    }
    end=rawline.find_first_of("> ",start+1);
    if(start!=string::npos&&end!=string::npos&&start<=end)
      return trim(rawline.substr(start,end-start));
  }

  return ""; //if there's a problem just return an empty string
}

/**
 * this functions returns the domain part of email
 * bill@m.com --> m.com
 * it's mainly useful to whitelist destination domains, if
 * for example a customer doesn't want any of it's emails using greylisting
 * in contrast to only wanting _some_ specific email
 *
 * @param email email to get domain from
 *
 * @return domain of email
 *
 */
string Utils::getdomain(string& email)
{
  if(email.rfind('@'))
    return trim(email.substr(email.rfind('@')+1));
  else
    return string("");
}

#ifndef WIN32

//-----------------
// posix-functions:
//-----------------

/**
 * get uid from user
 *
 * keep in mind that this function is not thread-safe, because
 * getpwnam isn't, and we don't actually care, this function
 * gets called BEFORE we start spawning threads, but you should
 * keep this details in mind if you intend to use this outside hermes
 *
 * @param user user to query
 *
 * @return uid for user
 *
 */
int Utils::usertouid(string user)
{
  struct passwd *pwd;
  pwd=getpwnam(user.c_str());
  if(NULL==pwd)
    throw Exception(_("Error reading user data. user doesn't exist?"),__FILE__,__LINE__);
  return pwd->pw_uid;
}

/**
 * get gid from groupname
 *
 * IMPORTANT:
 * keep in mind that this function is not thread-safe, because
 * getgrnam isn't, and we don't actually care, this function
 * gets called BEFORE we start spawning threads, but you should
 * keep this details in mind if you intend to use this outside hermes
 *
 * @param groupname groupname to query
 *
 * @return gid for groupname
 *
 */
int Utils::grouptogid(string groupname)
{
  struct group *grp;
  grp=getgrnam(groupname.c_str());
  if(NULL==grp)
    throw Exception(_("Error reading group data. group doesn't exist?"),__FILE__,__LINE__);
  return grp->gr_gid;
}
#endif //WIN32


//----------------
// misc functions:
//----------------

/**
 * whether a file is accesible by current process/user
 *
 * @param file file to check
 *
 * @return is file readable?
 *
 */
bool Utils::file_exists(string file)
{
  FILE *f=fopen(file.c_str(),"r");
  if(NULL==f)
    return false;
  else
  {
    fclose(f);
    return true;
  }
}

#ifdef WIN32
string Utils::get_canonical_filename(string file)
{
  char buffer[MAX_PATH];
  
  GetFullPathName(file.c_str(),sizeof(buffer),buffer,NULL);

  return string(buffer);
}
#else
string Utils::get_canonical_filename(string file)
{
  char *buffer=NULL;
  string result;

  buffer=realpath(file.c_str(),NULL);
  result=buffer;
  free(buffer);

  return result;
}
#endif //WIN32
/**
 * whether a directory is accesible by current process/user
 *
 * @param string directory to check
 *
 * @return isdir readable?
 *
 */
bool Utils::dir_exists(string dir)
{
  DIR *d=opendir(dir.c_str());
  if(NULL==d)
    return false;
  else
  {
    closedir(d);
    return true;
  }
}

/**
 * return the error string corresponding to errnum
 *
 * @param errnum errno to get description for
 *
 * @return description of error
 *
 */
string Utils::errnotostrerror(int errnum)
{
  char buf[2048]="";
  char *strerr;
//  if(strerror_r(errnum,strerr,1024)!=-1)
  #ifndef WIN32
  strerr=strerror_r(errnum,buf,2048);
  #else
  strerr="Error ";
  #endif //WIN32
  return string(strerr)+" ("+inttostr(errnum)+")";
//  else
//    return string("Error "+inttostr(errno)+" retrieving error code for error number ")+inttostr(errnum);
}

/**
 * returns whether the ip is in a dns list or not
 *
 * to check a dns list, you just append at the begining of the
 * dns string the inversed ip and then resolve it. for example,
 * to check the ip 1.2.3.4 you just resolve the following
 * hostname:
 *   4.3.2.1.zen.spamhaus.org
 *
 * if it returns an ip, then it is listed, else it isn't.
 *
 * since 1.4 this doesn't check a single domain but lists of them. we also added a percentage to decide when
 * it's listed or not.
 * So for example, if you want to check if you are on zen.spamhaus.org AND on dnsbl.sorbs.net, you have two options:
 *  - you need your ip to be listed on both domains to be considered as listed (100% of the lists)
 *  - you need your ip to be listed on either of them (50% of the lists)
 *
 * @param dns_domains list of dns domains to check
 * @param percentage  percentage of domains that have to list the ip to be considered as "listed"
 * @param ip          ip to check
 *
 * @return whether ip is blacklisted or not
 */
bool Utils::listed_on_dns_lists(list<string>& dns_domains,unsigned char percentage,string& ip)
{
  string reversedip;
  unsigned char number_of_lists=dns_domains.size();
  unsigned char times_listed=0;
  unsigned char checked_lists=0;

  reversedip=reverseip(ip);

  for(list<string>::iterator i=dns_domains.begin();i!=dns_domains.end();i++)
  {
    string dns_domain;

    dns_domain=*i;
    //add a dot if domain doesn't include it
    if('.'!=dns_domain[0])
      dns_domain.insert(0,".");

    try
    {
      Socket::resolve(reversedip+dns_domain);
      times_listed++;
      LINF(ip + " listed on " + dns_domain);
    }
    catch(Exception &e)
    {
      LINF(ip + " NOT listed on " + dns_domain);
    }

    checked_lists++;

    if((times_listed*100/number_of_lists)>=percentage)
    {
      LINF("ip " + ip + " listed on " + Utils::ulongtostr(times_listed) + " out of " + Utils::ulongtostr(checked_lists) + " checked servers, out of " + Utils::ulongtostr(number_of_lists) + ". threshold is " + Utils::ulongtostr(percentage) + "% -> return true");
      return true;
    }
    //if we have checked a number of lists that make it impossible for this function
    //to return true, then return false
    if((checked_lists*100/number_of_lists)>100-percentage)
    {
      LINF("ip " + ip + " listed on " + Utils::ulongtostr(times_listed) + " out of " + Utils::ulongtostr(checked_lists) + " checked servers, out of " + Utils::ulongtostr(number_of_lists) + ". threshold is " + Utils::ulongtostr(percentage) + "% -> return false");
      return false;
    }
  }

  LINF("ip " + ip + " listed on " + Utils::ulongtostr(times_listed) + " out of " + Utils::ulongtostr(checked_lists) + " checked servers, out of " + Utils::ulongtostr(number_of_lists) + ". threshold is " + Utils::ulongtostr(percentage) + "% -> return false");
  return false;
}

/**
 * reverse an ip string from 1.2.3.4 to 4.3.2.1
 *
 * @param ip ip to reverse
 *
 * @return the reversed ip
 */
string Utils::reverseip(string& ip)
{
  string inverseip="";
  string::size_type pos=0,ppos=0;

  //find first digit
  pos=ip.rfind('.',ip.length());
  if(string::npos==pos)
    throw Exception(ip+" is not an IP",__FILE__,__LINE__);
  else
    inverseip=ip.substr(pos+1);

  //find second digit
  ppos=pos;
  pos=ip.rfind('.',ppos-1);
  if(string::npos==pos)
    throw Exception(ip+" is not an IP",__FILE__,__LINE__);
  else
    inverseip+="."+ip.substr(pos+1,ppos-pos-1);

  //find third digit
  ppos=pos;
  pos=ip.rfind('.',ppos-1);
  if(string::npos==pos)
    throw Exception(ip+" is not an IP",__FILE__,__LINE__);
  else
    inverseip+="."+ip.substr(pos+1,ppos-pos-1);

  //append fourth digit
  inverseip+="."+ip.substr(0,pos);

  return inverseip;
}

/**
 * get the time formatted according to rfc2821 and rfc2822
 *
 * @param timestamp time from which to return string. if null, it equals time(NULL)
 *
 * @return a formatted string of the form 18 May 2007 11:01:52 -0000
 */
string Utils::rfc2821_date(time_t *timestamp)
{
  time_t utctime;
  char buf[100]; //TODO:100 bytes should be enough, check though
  char tzbuf[6]; //max length of a tz string is 5 (i.e. -0800)
  struct tm local_time;
  struct tm *p_local_time;

  p_local_time=&local_time;

  if(NULL==timestamp)
    utctime=time(NULL);
  else
    utctime=*timestamp;

  #ifdef WIN32
  if(NULL==(p_local_time=localtime(&utctime)))
  #else
  if(NULL==(localtime_r(&utctime,&local_time)))
  #endif //WIN32
    throw Exception(_("Error converting date"),__FILE__,__LINE__);

  if(0==strftime(buf,sizeof(buf),"%a, %d %b %Y %H:%M:%S ",p_local_time))
    throw Exception(_("Error formatting date"),__FILE__,__LINE__);

  #ifdef WIN32
  //win32 doesn't return the same for %z on strftime, so do it manually
  _tzset();
  snprintf(tzbuf,sizeof(tzbuf),"%c%02d%02d",(-_timezone<0)?'-':'+',abs((_timezone/60)/60),abs((_timezone/60)%60));
  #else
  if(0==strftime(tzbuf,sizeof(tzbuf),"%z",p_local_time))
    throw Exception(_("Error formatting timezone"),__FILE__,__LINE__);
  #endif //WIN32

  return string(buf)+string(tzbuf);
}

//hack for machines not defining HOST_NAME_MAX
//according to docs, if it's not defined, it SHOULD be 255
#ifndef HOST_NAME_MAX
  #define HOST_NAME_MAX 255
#endif //HOST_NAME_MAX

/**
 * get the hostname of the computer we are running at
 *
 * since this will be done for each message sent, and hostname shouldn't change during
 * the execution of hermes, we will simply get it the first time and then we will store
 * it on a static variable
 *
 * added the option to set the hostname on the configfile. should be useful on windows,
 * where gethostname only returns the host part
 *
 * @return the hostname of the computer
 */
string Utils::gethostname()
{
  static char buf[HOST_NAME_MAX]={0};

  if('\0'==buf[0])
  {
    if(cfg.getHostname()!="")
      strncpy(buf,cfg.getHostname().c_str(),HOST_NAME_MAX);
    else
    {
      if(-1==::gethostname(buf,HOST_NAME_MAX))
        throw Exception("Error getting current hostname"+Utils::errnotostrerror(errno),__FILE__,__LINE__);
    }
  }

  return string(buf);
}

void Utils::write_pid(string file,pid_t pid)
{
  FILE *f;

  f=fopen(file.c_str(),"w");
  if(NULL==f)
    throw Exception(_("Couldn't open file ")+file+_(" to write the pidfile"),__FILE__,__LINE__);

  fprintf(f,"%d\n",pid);
  fclose(f);
}

