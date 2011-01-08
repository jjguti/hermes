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
#include "Proxy.h"

extern LOGGER_CLASS hermes_log;
extern Configfile cfg;

void Proxy::setOutside(Socket& p_outside)
{
  outside=p_outside;
}

/**
 * this function is the main part of the program, it just sniffs traffic
 * between server and client and acts acording to the following diagram:
 *
 * TODO: fill diagram and point to website with graphical version
 *
 */
void Proxy::run(string &peer_address)
{
  #ifdef HAVE_SPF
  Spf spf_checker;
  #endif //HAVE_SPF

  string from="";
  string to="";
  string ehlostr="";
  string resolvedname="";
  unsigned char last_state=SMTP_STATE_WAIT_FOR_HELO;

  try
  {
    bool throttled=cfg.getThrottle(); //we start with a throttled connection
    bool authenticated=false; //we start with a non-authenticated connection
    bool esmtp=false;
    string strtemp;

    //check whitelist
    if(!cfg.getDnsWhitelistDomains().empty()&&Utils::listed_on_dns_lists(cfg.getDnsWhitelistDomains(),cfg.getDnsWhitelistPercentage(),peer_address))
    {
      authenticated=true;
      if(true==cfg.getWhitelistedDisablesEverything())
        throttled=false;
    }
    if(true==cfg.getWhitelistedDisablesEverything()&&Utils::whitelisted(cfg.getDatabaseFile(),peer_address))
    {
      throttled=false;
      authenticated=true;
    }
    else
    {
      if(false==cfg.getAllowDataBeforeBanner())
      {
        sleep(cfg.getBannerDelayTime());
        if(outside.canRead(0))  //if we have data waiting before the server gives us a 220 then quit, it's spam
        {
          LINF("421 (data_before_banner) (ip:"+peer_address+")");
          sleep(20); // but first let's annoy spammers once more
          outside.writeLine("421 Stop sending data before we show you the banner");
          return;
        }
      }
    }

    inside.init();
    inside.connect(cfg.getServerHost(),cfg.getServerPort());
    #ifdef HAVE_SSL
      if(cfg.getOutgoingSsl())
        inside.enableSSL(false);
      if(cfg.getIncomingSsl())
        outside.enableSSL(true);
    #endif //HAVE_SSL

    while(!outside.isClosed()&&!inside.isClosed())
    {
      if(outside.canRead(0.2))  //client wants to send something to server
      {
        strtemp=outside.readLine();
        if(outside.isClosed())
          return;
        if(strtemp.length()>10&&"mail from:"==Utils::strtolower(strtemp.substr(0,10)))
        {
          from=Utils::getmail(strtemp);
          last_state=SMTP_STATE_WAIT_FOR_RCPTTO;
        }

        if("ehlo"==Utils::strtolower(strtemp.substr(0,4)))
          esmtp=true;

        if(strtemp.length()>4&&("ehlo"==Utils::strtolower(strtemp.substr(0,4))||"helo"==Utils::strtolower(strtemp.substr(0,4))))
        {
          ehlostr=Utils::trim(strtemp.substr(5));
          last_state=SMTP_STATE_WAIT_FOR_MAILFROM;
        }

        if(strtemp.length()>8&&"rcpt to:"==Utils::strtolower(strtemp.substr(0,8)))
        {
          string strlog="";
          string code="";
          string mechanism="";
          string message="";

          to=Utils::getmail(strtemp);
          try
          {
            resolvedname=Socket::resolveInverselyToString(peer_address);
          }
          catch(Exception &e)
          {
            resolvedname="";
          }

          strlog="from "+from+" (ip:"+peer_address+", hostname:"+resolvedname+", "+(esmtp?"ehlo":"helo")+":"+ehlostr+") -> to "+to;

          //check greylisting
          if(cfg.getGreylist()&&!authenticated&&Utils::greylist(cfg.getDatabaseFile(),peer_address,from,to))
          {
            //should we greylist¿? if we have to, quit and then sleep 20 seconds before closing the connection
            code="421";
            mechanism="greylist";
            message=code+" Greylisted!! Please try again in a few minutes.";
	    LINF("checking " + mechanism);
          }
          #ifdef HAVE_SPF
          else if(cfg.getQuerySpf()&&!authenticated&&!spf_checker.query(peer_address,ehlostr,from))
          {
            code=cfg.getReturnTempErrorOnReject()?"421":"550";
            mechanism="spf";
            message=code+" You do not seem to be allowed to send email for that particular domain.";
	    LINF("checking " + mechanism);
          }
          #endif //HAVE_SPF
          //check blacklist
          else if(!authenticated&&Utils::blacklisted(cfg.getDatabaseFile(),peer_address,to))
          {
            code=cfg.getReturnTempErrorOnReject()?"421":"550";
            mechanism="allowed-domain-per-ip";
            message=code+" You do not seem to be allowed to send email to that particular domain from that address.";
	    LINF("checking " + mechanism);
          }
          //check rbl
          else if(!cfg.getDnsBlacklistDomains().empty()&&!authenticated&&Utils::listed_on_dns_lists(cfg.getDnsBlacklistDomains(),cfg.getDnsBlacklistPercentage(),peer_address))
          {
            code=cfg.getReturnTempErrorOnReject()?"421":"550";
            mechanism="dnsbl";
            message=code+" You are listed on some DNS blacklists. Get delisted before trying to send us email.";
	    LINF("checking " + mechanism);
          }
          else if(cfg.getRejectNoReverseResolution()&&!authenticated&&""==resolvedname)
          {
            code=cfg.getReturnTempErrorOnReject()?"421":"550";
            mechanism="no reverse resolution";
            message=code+" Your IP address does not resolve to a hostname.";
	    LINF("checking " + mechanism);
          }
          else if(cfg.getCheckHeloAgainstReverse()&&!authenticated&&ehlostr!=resolvedname)
          {
            code=cfg.getReturnTempErrorOnReject()?"421":"550";
            mechanism="helo differs from resolved name";
            message=code+" Your IP hostname doesn't match your envelope hostname.";
	    LINF("checking " + mechanism);
          }
          else
            code="250";

          if(""!=mechanism)
            strlog.insert(0,"("+mechanism+") ");
          strlog.insert(0,code+" ");

          //log the connection
          LINF(strlog);

          //if we didn't accept the email, punish spammers
          if("250"!=code)
          {
            inside.writeLine("QUIT");
            inside.close(); //close the socket now and leave server alone
            sleep(20);
            outside.writeLine(message);
            return;
          }
          last_state=SMTP_STATE_WAIT_FOR_DATA;
        }

        if("starttls"==Utils::strtolower(strtemp.substr(0,8)))
        {
          //if we have ssl then accept starttls, if not politely say fuck you
          #ifdef HAVE_SSL
            try
            {
	      LINF("STARTTLS issued by remote, TLS enabled");
              outside.writeLine("220 You can speak now, line is secure!!");
              outside.enableSSL(true);
            }
            catch(Exception &e)
            {
              LERR(e);
            }
          #else
            outside.writeLine("454 TLS temporarily not available");
	    LINF("STARTTLS issued by remote, TLS was not enabled because this build lacks SSL support");
          #endif //HAVE_SSL
          strtemp="";
        }

        if(strtemp.length())
          inside.writeLine(strtemp);
      }

      if(inside.canRead(0.2))  //server wants to send something to client
      {
        strtemp=inside.readLine();
        if(inside.isClosed())
          return;
        string code=strtemp.substr(0,3); //all responses by the server start with a code

        if("354"==code)  //354 -> you can start sending data, unthrottle now and read binary-safe
        {
          string endofdata="";
          ssize_t bytes_read=0;
          char buffer[4097];

          outside.writeLine(strtemp);
          strtemp="";
          if(cfg.getAddHeaders())
          {
            inside.writeLine("Received: from "+ehlostr+" ("+peer_address+")");
            inside.writeLine("  by "+Utils::gethostname()+" with "+(esmtp?"ESTMP":"SMTP")+" via TCP; "+Utils::rfc2821_date());
            inside.writeLine("X-Anti-Spam-Proxy: Proxied by Hermes [www.hermes-project.com]");
          }
          do
          {
            bytes_read=outside.readBytes(buffer,sizeof(buffer)-1);
            if(bytes_read<1)
              throw NetworkException("Problem reading DATA contents, recv returned "+Utils::inttostr(bytes_read),__FILE__,__LINE__);
            buffer[bytes_read]='\0';
            inside.writeBytes(buffer,bytes_read);
            if(bytes_read<5)
              endofdata+=string(buffer);
            else
              endofdata=string(buffer+bytes_read-5);
            if(endofdata.length()>5)
              endofdata=endofdata.substr(endofdata.length()-5);
          }
          while(endofdata!="\r\n.\r\n"/*&&endofdata.length()>3&&endofdata.substr(2)!="\n.\n"&&endofdata.substr(2)!="\r.\r"*/);
        }

        if("235"==code)  //235 -> you are correctly authenticated, unthrottle & authenticate
        {
          throttled=false;
          authenticated=true;
        }
        if("250-pipelining"==Utils::strtolower(strtemp)||"250-chunking"==Utils::strtolower(strtemp)) //this solves our problems with pipelining-enabled servers
          strtemp="";

        //this is a special case, we can't just ignore the line if it's the last line (doesn't have the dash after the code)
        //so we just say we support an imaginary extension (noextension).
        //caveat: this makes us identificable, so, if you can, configure your smtp server to either don't support pipelining
        //or to not advertise it as the last capability.
        if("250 pipelining"==Utils::strtolower(strtemp)||"250 chunking"==Utils::strtolower(strtemp))
          strtemp="250 x-noextension";
        if(strtemp.length())
          outside.writeLine(strtemp);
      }

      if(throttled)
        sleep(cfg.getThrottlingTime()); //we take 1 second between each command to make spammers angry
    }
  }
  catch(Exception &e)  //any exception will close both connections
  {
    LERR(e);
    if(last_state<SMTP_STATE_WAIT_FOR_DATA)
      LINF("421 (probably-throttling) from "+(""==from?"no-from":from)+" (ip:"+peer_address+", hostname:"+(""==resolvedname?"not-resolved":resolvedname)+", ehlo:"+(""==ehlostr?"no-ehlo":ehlostr)+") -> to "+(""==to?"no-to":to));
    return;
  }
}
