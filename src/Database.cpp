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
#include "Database.h"

void Database::setDatabaseFile(string p_dbfile)
{
  dbfile=p_dbfile;
}

/**
 *
 * this function executes a query and checks for error
 * it doesn't return any value, as it is not needed(the queries don't return data)
 *
 */
void Database::doQuery(string p_sql)
{
  int retval;
  do
  {
    retval=sqlite3_exec(dbh,p_sql.c_str(),NULL,NULL,NULL);
    if(SQLITE_OK!=retval&&SQLITE_BUSY!=retval)
      throw SQLException("SQL: "+p_sql+" sqlite3_errmsg: "+sqlite3_errmsg(dbh),__FILE__,__LINE__);
    if(SQLITE_BUSY==retval)
    {
      sleep(1+rand()%2);
      #ifdef REALLY_VERBOSE_DEBUG
      cout << pthread_self() << " doquery() sql failed with busy state, retrying" << endl;
      #endif //REALLY_VERBOSE_DEBUG
    }
  }
  while(SQLITE_BUSY==retval);
}

string Database::cleanString(string s)
{
  string result="";

  for(unsigned int i=0;i<s.length();i++)
    if(s[i]>31&&s[i]<127)
      switch(s[i])
      {
        case ' ':
        case '<':
        case '>':
        case '(':
        case ')':
        case '[':
        case ']':
        case '\\':
        case ',':
        case ';':
        case ':':
        case '"':
        case '%':
        case '\'':
          break;
        default:
          result+=s[i];
      }

  return result;
}

bool Database::greylisted(string ip,string from,string to,int initial_expiry,int initial_blacklist,int whitelist_expiry)
{
  char **result;
  int nrow=0;
  int ncolumn=0;
  bool retval=true;
  int sqlite_retval;
  int now=time(NULL);
  string strnow=Utils::inttostr(now);
  string sql="SELECT id,blocked_until FROM greylist WHERE ip=\""+ip+"\" AND emailfrom=\""+from+"\" AND emailto=\""+to+"\" AND "+strnow+" < expires LIMIT 1;";

  do
  {
    sqlite_retval=sqlite3_get_table(dbh,sql.c_str(),&result,&nrow,&ncolumn,NULL);
    if(sqlite_retval!=SQLITE_OK&&sqlite_retval!=SQLITE_BUSY)
    {
      if(NULL!=result)
        sqlite3_free_table(result);
      throw SQLException("SQL: "+sql+" sqlite3_errmsg: "+sqlite3_errmsg(dbh),__FILE__,__LINE__);
    }
    if(SQLITE_BUSY==sqlite_retval)
    {
      sleep(1+rand()%2);
      #ifdef REALLY_VERBOSE_DEBUG
      cout << pthread_self() << " greylisted() sql busy" << endl;
      #endif //REALLY_VERBOSE_DEBUG
    }
  }
  while(sqlite_retval==SQLITE_BUSY);

  sql="";

  if(nrow>0)
  {
    string id=result[2];
    //we have seen this triplet before
    if(now<atol(result[3]))
    {
      sql="UPDATE greylist SET blocked=blocked+1 WHERE id="+id+";";
      doQuery(sql.c_str());
      retval=true;
    }
    else
    {
      string expires=Utils::inttostr(now+(60*60*24*whitelist_expiry));

      sql="UPDATE greylist SET expires="+expires+",passed=passed+1 WHERE id="+id+";";
      doQuery(sql.c_str());
      retval=false;
    }
  }
  else
  {
    string blocked_until=Utils::inttostr(now+(60*initial_blacklist));
    string expires=Utils::inttostr(now+(60*initial_expiry));
    //new triplet, greylist and add new row
    retval=true;
    sql="INSERT INTO greylist(id,ip,emailfrom,emailto,created,blocked_until,expires,passed,blocked)"
      "VALUES(NULL,\""+ip+"\",\""+from+"\",\""+to+"\","+strnow+","+blocked_until+","+expires+",0,1);";
    doQuery(sql.c_str());
  }
  if(NULL!=result)
    sqlite3_free_table(result);
  return retval;
}

Database::Database():dbh(NULL)
{}

Database::~Database()
{
  close();
}

void Database::close()
{
  if(NULL!=dbh)
    sqlite3_close(dbh);
}

void Database::_open()
{
  if(sqlite3_open(dbfile.c_str(),&dbh))
  {
    dbh=NULL;
    throw Exception(_("Error creating/opening db ")+dbfile,__FILE__,__LINE__);
  }
}

void Database::open()
{
  // if dbfile is new, initialize first
  if(!Utils::file_exists(dbfile))
    init();

  _open();
}

void Database::init()
{
  _open();
  doQuery("CREATE TABLE whitelisted_ips(ip VARCHAR);");
  doQuery("CREATE TABLE whitelisted_tos(email VARCHAR);");
  doQuery("CREATE TABLE whitelisted_domains(domain VARCHAR);");
  doQuery("CREATE TABLE whitelisted_hostnames(hostname VARCHAR);");
  doQuery("CREATE TABLE blacklisted_tos(email VARCHAR);");
  doQuery("CREATE TABLE blacklisted_todomains(domain VARCHAR);");
  doQuery("CREATE TABLE blacklisted_ips(ip VARCHAR);");
  doQuery("CREATE TABLE blacklisted_froms(email VARCHAR);");
  doQuery("CREATE TABLE allowed_domains_per_ip(domain VARCHAR,ip VARCHAR);");
  doQuery("CREATE TABLE greylist(id INTEGER PRIMARY KEY,ip VARCHAR,emailfrom VARCHAR,emailto VARCHAR,created INTEGER,blocked_until INTEGER,expires INTEGER,passed INTEGER,blocked INTEGER);");

  //whitelist localhost
  doQuery("INSERT INTO whitelisted_ips(ip) VALUES(\"127.0.0.1\");");

  close();
}

int Database::countRows(string p_sql)
{
  char **result;
  int nrow=0;
  int ncolumn=0;
  int sqlite_retval;

  do
  {
    sqlite_retval=sqlite3_get_table(dbh,p_sql.c_str(),&result,&nrow,&ncolumn,NULL);
    if(SQLITE_OK!=sqlite_retval&&SQLITE_BUSY!=sqlite_retval)
    {
      if(NULL!=result)
        sqlite3_free_table(result);
      throw SQLException("SQL: "+p_sql+" sqlite3_errmsg: "+sqlite3_errmsg(dbh),__FILE__,__LINE__);
    }
    if(SQLITE_BUSY==sqlite_retval)
    {
      sleep(1+rand()%2);
      #ifdef REALLY_VERBOSE_DEBUG
      cout << pthread_self() << " countRows() retrying" << endl;
      #endif //REALLY_VERBOSE_DEBUG
    }
  }
  while(SQLITE_BUSY==sqlite_retval);

  if(NULL!=result)
    sqlite3_free_table(result);

  if(ncolumn)
    return (nrow/ncolumn);
  else
    return nrow;
}

bool Database::whitelistedIP(string p_ip)
{
  string sql="";

  sql="SELECT ip FROM whitelisted_ips WHERE ip=SUBSTR(\""+p_ip+"\",0,LENGTH(ip)) LIMIT 1;";

  if(countRows(sql)>0)
    return true;
  else
    return false;
}

bool Database::whitelistedTO(string p_email)
{
  string sql="";

  sql="SELECT email FROM whitelisted_tos WHERE email=\""+p_email+"\" LIMIT 1;";

  if(countRows(sql)>0)
    return true;
  else
    return false;
}

bool Database::whitelistedDomain(string p_domain)
{
  string sql="";

  sql="SELECT domain FROM whitelisted_domains WHERE domain=\""+p_domain+"\" LIMIT 1;";

  if(countRows(sql)>0)
    return true;
  else
    return false;
}

bool Database::blacklistedTO(string p_email)
{
  string sql="";

  sql="SELECT email FROM blacklisted_tos WHERE email=\""+p_email+"\" LIMIT 1;";

  if(countRows(sql)>0)
    return true;
  else
    return false;
}

bool Database::blacklistedToDomain(string p_domain)
{
  string sql="";

  sql="SELECT domain FROM blacklisted_todomains WHERE domain=\""+p_domain+"\" LIMIT 1;";

  if(countRows(sql)>0)
    return true;
  else
    return false;
}

bool Database::blacklistedIP(string p_ip)
{
  string sql="";

  sql="SELECT ip FROM blacklisted_ips WHERE ip=SUBSTR(\""+p_ip+"\",0,LENGTH(ip)) LIMIT 1;";

  if(countRows(sql)>0)
    return true;
  else
    return false;
}

bool Database::blacklistedFROM(string p_email)
{
  string sql="";

  sql="SELECT email FROM blacklisted_froms WHERE email=\""+p_email+"\" LIMIT 1;";

  if(countRows(sql)>0)
    return true;
  else
    return false;
}

bool Database::whitelistedHostname(string p_hostname)
{
  string sql="";

  sql="SELECT hostname FROM whitelisted_hostnames WHERE hostname=SUBSTR(\""+p_hostname+"\",-LENGTH(hostname),LENGTH(hostname)) LIMIT 1;";

  if(countRows(sql)>0)
    return true;
  else
    return false;
}

bool Database::allowedDomainPerIP(string p_domain,string p_ip)
{
  string sql="",sql_domain="";

  sql="SELECT ip FROM allowed_domains_per_ip WHERE domain=\""+p_domain+"\" AND ip=\""+p_ip+"\" LIMIT 1;";
  sql_domain="SELECT ip FROM allowed_domains_per_ip WHERE domain=\""+p_domain+"\" LIMIT 1;";

  if(countRows(sql_domain)>0&&0==countRows(sql))
    return false;
  else
    return true;
}

/**
 * this function returns an integer value from a sql
 * it is useful to calculate things with sql
 *
 * i.e.: SELECT SUM(intfield) FROM table
 *
 * @param p_sql SQL query to perform
 *
 * @return the first value of the first column, rest of data is ignored
 */
unsigned long Database::getIntValue(string& p_sql)
{
  char **result;
  int nrow=0;
  int ncolumn=0;
  int sqlite_retval;
  unsigned long value;

  do
  {
    sqlite_retval=sqlite3_get_table(dbh,p_sql.c_str(),&result,&nrow,&ncolumn,NULL);
    if(SQLITE_OK!=sqlite_retval&&SQLITE_BUSY!=sqlite_retval)
    {
      if(NULL!=result)
        sqlite3_free_table(result);
      throw SQLException("SQL: "+p_sql+" sqlite3_errmsg: "+sqlite3_errmsg(dbh),__FILE__,__LINE__);
    }
    if(SQLITE_BUSY==sqlite_retval)
    {
      sleep(1+rand()%2);
      #ifdef REALLY_VERBOSE_DEBUG
        cout << pthread_self() << " getIntValue() retrying" << endl;
      #endif //REALLY_VERBOSE_DEBUG
    }
  }
  while(SQLITE_BUSY==sqlite_retval);

  if(NULL==result)
    throw SQLException("SQL: "+p_sql+" didn't return any data, SQL query may be wrong",__FILE__,__LINE__);
  if('\0'==result[ncolumn])
    value=0; //why sqlite doesn't return 0 when there are no rows?
  else
    value=strtoul(result[ncolumn],NULL,10);
  sqlite3_free_table(result);

  return value;
}

/**
 * clean the spam database and return the number of spam messages
 *
 * @return number of spam messages deleted
 */
unsigned long Database::cleanDB()
{
  unsigned long spamcount=0; //shut compiler up
  string sql;

  try
  {
    //block database until we have finished cleaning it
    doQuery("BEGIN EXCLUSIVE TRANSACTION");

    //now count how many blocked emails we have to submit to stats
    //we do it always because if we don't submit stats it stills appears on the logs
    sql="SELECT SUM(blocked) FROM greylist WHERE expires<strftime('%s','now') AND passed=0;";
    spamcount=getIntValue(sql);
    #ifdef REALLY_VERBOSE_DEBUG
    cout << "We have processed " << spamcount << " spam emails in the last 4 hours" << endl;
    #endif //REALLY_VERBOSE_DEBUG

    //at last, delete them from the database
    doQuery("DELETE FROM greylist WHERE expires<strftime('%s','now');");

    //and close the transaction
    doQuery("COMMIT TRANSACTION");
  }
  catch(Exception &e)
  {
    doQuery("ROLLBACK TRANSACTION");
  }

  return spamcount;
}
