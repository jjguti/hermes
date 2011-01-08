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
#include "Exception.h"

extern Configfile cfg;
extern LOGGER_CLASS hermes_log;

Exception::Exception(string p_error,string p_file,unsigned p_line)
{
  error=p_error;
  #ifdef NOTIFY_EXCEPTIONS
  if(cfg.getNotifyTo()!="")
  {
    try
    {
      notifyByEmail("Exception: "+p_error);
    }
    catch(NotifyException &e)
    {
      LERR(e);
    }
  }
  #endif //NOTIFY_EXCEPTIONS
  file=p_file;
  line=p_line;
}

Exception::operator string()
{
 return file+":"+Utils::inttostr(line)+": "+error;
}

ostream& operator<<(ostream &os,Exception &e)
{
  os << string(e);
  return os;
}

#ifdef NOTIFY_EXCEPTIONS
#ifdef USE_SMTP_FOR_NOTIFICATIONS
/**
 * notify problem by email to address, using an smtp server
 * 
 * it will add some text before the message to be identificable
 * this function only makes mild error-checks on codes returned
 *  by server, so some email might not reach destination
 * this functions' mission in life is help those poor souls still
 *  using windows(and others), as they just don't have sendmail or popen,
 *  wich is way faster, way less complicated and much less error-prone
 * also if you're using chroot, you might want to use smtp instead of sendmail
 *  as it is a much simpler setup
 *
 * @param string message message of the problem
 *
 * @return void
 */
void Exception::notifyByEmail(string message)
{
  Socket smtpServer;
  string address=cfg.getNotifyTo();
  string response;

  if(""==address)
    throw Exception(_("Notification address is incorrect or empty, please check"),__FILE__,__LINE__);
  smtpServer.init();
  smtpServer.connect(cfg.getServerHost(),cfg.getServerPort());
  #ifdef HAVE_SSL
    if(cfg.getOutgoingSSL())
      smtpServer.enableSSL(false);
  #endif //HAVE_SSL

  #define ERROR_SENDING(x,y,z) if(x.substr(0,3)!=y) throw NotifyException(_("Error "+x.substr(0,3)+" sending email after ")+z);
  #define GET_RESPONSE_AND_CHECK(x,y) response=smtpServer.readLine(); ERROR_SENDING(response,x,y); cout << "s:" << response << endl;
  #define SEND_COMMAND_AND_CHECK(x,y,z) smtpServer.writeLine(x); cout << "c:" << x << endl; GET_RESPONSE_AND_CHECK(y,z);
  #define DEBUGSRV() //if(smtpServer.canRead(1)) cout << "s:" << smtpServer.readLine() << endl;

  GET_RESPONSE_AND_CHECK("220","CONNECT");

  SEND_COMMAND_AND_CHECK("HELO localhost","250","EHLO");
  SEND_COMMAND_AND_CHECK("MAIL FROM: \"hermes daemon\"<hermes@localhost>","250","MAIL FROM");
  SEND_COMMAND_AND_CHECK("RCPT TO: "+address,"250","RCPT TO");
  SEND_COMMAND_AND_CHECK("DATA","354","DATA");

  smtpServer.writeLine("From: \"hermes daemon\"<hermes@localhost>");
  DEBUGSRV();
  smtpServer.writeLine("To: "+address);
  DEBUGSRV();
  smtpServer.writeLine("Subject: Exception happened on hermes");
  DEBUGSRV();
  smtpServer.writeLine("");
  DEBUGSRV();
  smtpServer.writeLine("Hello "+address+",");
  DEBUGSRV();
  smtpServer.writeLine("Hermes gave an error, with the following error message:");
  DEBUGSRV();
  smtpServer.writeLine(message);
  DEBUGSRV();
  smtpServer.writeLine(".");
  GET_RESPONSE_AND_CHECK("250","sending data contents");
  SEND_COMMAND_AND_CHECK("QUIT","221","QUIT");

  #undef ERROR_SENDING
  #undef GET_RESPONSE_AND_CHECK
  #undef SEND_COMMAND_AND_CHECK
}
#else //THEN USE sendmail to send the email
void Exception::notifyByEmail(string message)
{
  FILE *sendmail;
  string address=cfg.getNotifyTo();

  sendmail=popen("/var/qmail/bin/sendmail -t","w");
  if(NULL==sendmail)
    throw NotifyException(_("Couldn't initialize sendmail command"));
  fprintf(sendmail,"From: \"hermes daemon\"<hermes@localhost>\n");
  fprintf(sendmail,"To: %s\n",address.c_str());
  fprintf(sendmail,"Subject: Exception happened on hermes\n");
  fprintf(sendmail,"\n");
  fprintf(sendmail,"Hello %s,\n",address.c_str());
  fprintf(sendmail,"Hermes gave an error, with the following error message:\n");
  fprintf(sendmail,"%s\n",message.c_str());
  fflush(sendmail);
  pclose(sendmail);
}
#endif //USE_SMTP_FOR_NOTIFICATIONS
#endif //NOTIFY_EXCEPTIONS
