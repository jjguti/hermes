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
#include "Spf.h"

SPF_server_t *Spf::spfserver=NULL;

/**
 * constructor
 *
 * it will create a spfserver if this is the first created object of the class.
 * if it isn't, then we just create an spfrequest
 */
Spf::Spf():spfrequest(NULL),spfresponse(NULL)
{
  pthread_mutex_init(&mutex,NULL);
  if(NULL==spfserver)
    if(NULL==(spfserver=SPF_server_new(SPF_DNS_CACHE,0)))
      throw Exception(_("Can't initialize SPF library"),__FILE__,__LINE__);

  if(NULL==(spfrequest=SPF_request_new(spfserver)))
    throw Exception(_("Can't initialize SPF request"),__FILE__,__LINE__);
}

/**
 * destructor
 *
 * frees the memory of the spfrequest
 */
Spf::~Spf()
{
  pthread_mutex_destroy(&mutex);
  if(NULL!=spfrequest) SPF_request_free(spfrequest);
}

/**
 * frees all memory related to the spf class
 *
 * this is needed because the common things are only initialized
 * once (and are static), and when we close the program we need
 * to deinitialize them
 */
void Spf::deinitialize()
{
  if(NULL!=spfserver)
    SPF_server_free(spfserver);
}

/**
 * make a query to the dns system for an spf record
 *
 * highly inspired from fakehermes' source
 *
 * @param ip    the ip of the remote server
 * @param helo  the hello string of the remote server
 * @param from  the envelope from address
 *
 * @returns true if it is not incorrect
 */
bool Spf::query(string ip,string helo,string from)
{
  bool retval=false;

  if(SPF_request_set_ipv4_str(spfrequest,ip.c_str()))
    throw Exception(_("Error configuring IP for SPF request"),__FILE__,__LINE__);
  if(SPF_request_set_helo_dom(spfrequest,helo.c_str()))
    throw Exception(_("Error configuring HELO for SPF request"),__FILE__,__LINE__);
  if(SPF_request_set_env_from(spfrequest,from.c_str()))
    throw Exception(_("Error configuring FROM for SPF request"),__FILE__,__LINE__);

  //make the actual query
  pthread_mutex_lock(&mutex);
  SPF_request_query_mailfrom(spfrequest,&spfresponse);
  pthread_mutex_unlock(&mutex);

  if(NULL!=spfresponse)
  {
    retval=(SPF_RESULT_FAIL==SPF_response_result(spfresponse)||SPF_RESULT_SOFTFAIL==SPF_response_result(spfresponse))?false:true;
    SPF_response_free(spfresponse);
  }

  return retval;
}
