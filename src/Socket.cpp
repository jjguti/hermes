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
#include "Socket.h"
#include <unistd.h>

int Socket::created_sockets=0;

#ifdef HAVE_SSL
SSL_CTX *Socket::ssl_ctx_server=NULL;
SSL_CTX *Socket::ssl_ctx_client=NULL;
#endif //HAVE_SSL

extern Configfile cfg;
extern LOGGER_CLASS hermes_log;

Socket::Socket():fd(-1)
#ifdef HAVE_SSL
,ssl_enabled(false),ssl(NULL)
#endif //HAVE_SSL
{
  if(!created_sockets)
  {
    #ifdef WIN32
      /* fuck windows, it needs this sh*t before allowing sockets to work */
      WSADATA wsaData;
      int wsa=WSAStartup(0xff,&wsaData);
      if(wsa)
      { 
        perror("Windows not working, call microsoft");
        exit(-1);
      }
    #endif //WIN32
    #ifdef HAVE_SSL
      SSL_library_init();
      SSL_load_error_strings();

      //initialize the context for both server and client operation
      //server
      ssl_ctx_server=NULL;
      ssl_ctx_server=SSL_CTX_new(SSLv23_server_method());
      /* create context */
      if(!ssl_ctx_server)
        throw Exception(_("Error creating SSL context"),__FILE__,__LINE__);
      /* load certificate */
      if(SSL_CTX_use_certificate_file(ssl_ctx_server,cfg.getCertificateFile().c_str(),SSL_FILETYPE_PEM)==-1)
        throw Exception(_("Error loading certificate"),__FILE__,__LINE__);
      /* load private key */
      if(SSL_CTX_use_PrivateKey_file(ssl_ctx_server,cfg.getPrivateKeyFile().c_str(),SSL_FILETYPE_PEM)==-1)
        throw Exception(_("Error loading private key"),__FILE__,__LINE__);
      /* check that private key and cert match */
      if(!SSL_CTX_check_private_key(ssl_ctx_server))
        throw Exception(_("Private key doesn't match certificate file"),__FILE__,__LINE__);

      //client
      ssl_ctx_client=NULL;
      ssl_ctx_client=SSL_CTX_new(SSLv23_client_method());
      if(!ssl_ctx_client)
        throw Exception(_("Error creating SSL context"),__FILE__,__LINE__);

      //set options to make SSL_read and SSL_write behave more like read and write
      SSL_CTX_set_mode(ssl_ctx_server,SSL_MODE_ENABLE_PARTIAL_WRITE); //PARTIAL_WRITE allows a write to suceed with fewer bytes sent
      SSL_CTX_set_mode(ssl_ctx_client,SSL_MODE_ENABLE_PARTIAL_WRITE);
      SSL_CTX_set_mode(ssl_ctx_server,SSL_MODE_AUTO_RETRY); //AUTO_RETRY will block SSL_read and SSL_write if a renegotiation is required
      SSL_CTX_set_mode(ssl_ctx_client,SSL_MODE_AUTO_RETRY);


    #endif //HAVE_SSL
  }
  created_sockets++;
}

/**
 *
 * we have constructor and init because we may want to create the object
 * and afterwards assign an fd obtained in other way with setFD
 *
 */
void Socket::init()
{
  // create socket ...
  fd=socket(PF_INET,SOCK_STREAM,0);
  //configure timeout
  setTimeout(60,60);

  if(fd==-1)
    throw Exception(_(string("Error creating socket :")+Utils::inttostr(errno)+" "+Utils::errnotostrerror(errno)),__FILE__,__LINE__);
}

/**
 * close the socket
 */
void Socket::close()
{
  if(fd!=-1)
  {
    /* shutdown(fd,SHUT_RDWR); */ //we don't care about return, if we are on eof we are already closed and this doesn't hurt
    //the same applies to close/closesocket
    #ifndef WIN32
    ::close(fd);
    #else
    closesocket(fd);
    #endif //WIN32
    fd=-1;
  }
}

/**
 * destructor.
 *
 * we close the socket if it's still open, and we 
 * decrement the created_sockets count
 * when the count is 0, destroy the ssl contexts and,
 * if on windows, do a WSACleanup
 */
Socket::~Socket()
{
  #ifdef HAVE_SSL
  if(ssl_enabled&&ssl!=NULL)
    SSL_free(ssl);
  #endif //HAVE_SSL
  close();

  created_sockets--;
  if(!created_sockets)
  {
    #ifdef WIN32
      WSACleanup();
    #endif //WIN32
    #ifdef HAVE_SSL
      if(ssl_enabled&&ssl_ctx_server!=NULL)
        SSL_CTX_free(ssl_ctx_server);
      if(ssl_enabled&&ssl_ctx_client!=NULL)
        SSL_CTX_free(ssl_ctx_client);
    #endif //HAVE_SSL
  }
}

#ifdef HAVE_SSL
/**
 * prepare ssl on the socket
 *
 * @param server whether to enable server ssl or client ssl
 */
void Socket::prepareSSL(bool server)
{
  if(server)
    ssl=SSL_new(ssl_ctx_server);
  else
    ssl=SSL_new(ssl_ctx_client);

  if(NULL==ssl)
    throw Exception(_("Error creating ssl structure"),__FILE__,__LINE__);

  if(1!=SSL_set_fd(ssl,fd))
    throw Exception(_("Error setting FD"),__FILE__,__LINE__);

  if(0==RAND_status())
    throw Exception(_("PRNG has not enough data. Are you missing /dev/[u]random?"),__FILE__,__LINE__);
}

/**
 * actually do the ssl handshake and start receiving encoded
 *
 * @param server whether to enable server ssl or client ssl
 */
void Socket::startSSL(bool server)
{
  int retval;

  retval=server? SSL_accept(ssl) : SSL_connect(ssl);

  //SSL_accept and SSL_connect have the same semantics so we handle them together
  if(1!=retval)
    throw Exception(_("Error doing SSL handshake on the socket"),__FILE__,__LINE__);

  //only set ssl_enabled if we have suceeded with everything
  ssl_enabled=true;
}
#endif //HAVE_SSL

bool Socket::isClosed()
{
  return -1==fd;
}

/**
 * read lon bytes from the socket to buf buffer
 *
 * @param buf buffer to fill(must be previously reserved)
 * @param lon number of bytes to read
 * @return number of bytes read
 */
ssize_t Socket::readBytes(void *buf,ssize_t lon)
{
  ssize_t retval=0; //shut compiler up
  ssize_t readed=0;

  while(readed<lon)
  {
    if(-1==fd)
      throw Exception(_("Trying to read a non-opened or already closed socket"),__FILE__,__LINE__);

    #ifdef HAVE_SSL
    if(ssl_enabled)
      retval=SSL_read(ssl,buf,lon);
    else
    #endif //HAVE_SSL
      retval=recv(fd,(char *)buf,lon,MSG_NOSIGNAL);

    if(!retval)
      throw NetworkException(_("Peer closed connection"),__FILE__,__LINE__);

    if(retval<0)
      #ifdef HAVE_SSL
      if(ssl_enabled)
        throw NetworkException(_("SSL error number: ")+Utils::inttostr(SSL_get_error(ssl,retval)),__FILE__,__LINE__);
      else
      #endif //HAVE_SSL
        throw NetworkException(_(Utils::errnotostrerror(errno)),__FILE__,__LINE__);
    readed+=lon;
  }

  return retval;
}

/**
 * read a single byte from the socket
 *
 * @return the read byte(char)
 */
char Socket::readByte()
{
  char c=0;

  readBytes(&c,1);

  return c;
}

/**
 * read a full line and return a string with it
 *
 * @return the read string
 */
string Socket::readLine()
{
  char c=0;
  stringstream s;

  do
  {
    c=readByte();

    if(c!=10&&c!=13&&c!=0)
      s<<c;
  }
  while(c!=10&&!isClosed());

  LDEB("r" + string(ssl_enabled?"s":"") + ">" + s.str());

  return s.str();
}

void Socket::writeBytes(void *bytes,ssize_t len)
{
  int retval;
  ssize_t written=0;

  if(fd==-1)
    throw Exception(_("Trying to write to a non-opened socket"),__FILE__,__LINE__);

  while(written<len)
  {
    #ifdef HAVE_SSL
    if(ssl_enabled)
      retval=SSL_write(ssl,bytes,len);
    else
    #endif //HAVE_SSL
      retval=send(fd,(char *)bytes,len,MSG_NOSIGNAL);

    if(!retval)
      throw NetworkException(_("Peer closed connection"),__FILE__,__LINE__);

    if(retval<0)
      #ifdef HAVE_SSL
      if(ssl_enabled)
        throw NetworkException(_("SSL error number: ")+Utils::inttostr(SSL_get_error(ssl,retval)),__FILE__,__LINE__);
      else
      #endif //HAVE_SSL
        throw NetworkException(_(Utils::errnotostrerror(errno)),__FILE__,__LINE__);
    written+=len;
  }
}

void Socket::writeByte(char c)
{
  writeBytes(&c,sizeof(char));
}

void Socket::writeLine(string s)
{

  LDEB("w" + string(ssl_enabled?"s":"") + ">" + s);
  s+="\r\n";

  writeBytes((void *)s.c_str(),s.length());
}

void Socket::setFD(int p_fd)
{
  if(fd>0)
    close();

  if(p_fd>0)
  {
    fd=p_fd;
    setTimeout(60,60);
  }
  else
    throw Exception(_("Error: fd not valid"),__FILE__,__LINE__);
}

/**
 * returns true if there's data waiting to be read on the socket
 * if it's a serversocket means that a new connection is waiting
 *
 * @param unsigned int seconds to wait before returning true or false
 *
 * @return bool true if there's data(or a connection waiting) and false if there's not
 *
 */
bool Socket::canRead(float time)
{
  fd_set rfd;
  struct timeval timeout;
  int seconds=0;
  int useconds=0;

  //calculate seconds and useconds
  seconds=int(time);
  useconds=int((time-seconds)*1000);

  //set rfd to the fd of our connection
  FD_ZERO(&rfd);
  FD_SET(fd,&rfd);

  //we wait x seconds for an incoming connection
  timeout.tv_usec=useconds;
  timeout.tv_sec=seconds;
  if(select(fd+1,&rfd,NULL,NULL,&timeout)>0)
    return true;
  else
  #ifdef HAVE_SSL
  if(ssl_enabled)
    if(SSL_pending(ssl))
      return true;
    else
      return false;
  else
    return false;
  #else
    return false;
  #endif //HAVE_SSL
}

bool Socket::connect(string host,unsigned int port)
{
  struct sockaddr address;
  struct sockaddr_in *inetaddress;

  address=(sockaddr)Socket::resolve(host);
  inetaddress=(sockaddr_in *)&address;
  inetaddress->sin_port=htons(port);

  int retval=::connect(fd,&address,sizeof(address));
  if(retval==-1)
    throw Exception(string(_("Error connecting to "))+host+":"+Utils::inttostr(port)+" "+string("(")+Socket::resolveToString(host)+string(")"),__FILE__,__LINE__);
  if(!retval)
    return true;
  else
    return false;
}

#ifdef HAVE_GETADDRINFO
struct sockaddr Socket::resolve(string host)
{
  struct addrinfo *hostinfo=NULL;
  struct addrinfo hints;
  struct sockaddr resolvedip;
  int error;

  //configure hints to use IPv4 and IPv6, and resolve ips to name
  memset(&hints,0,sizeof(hints));
  hints.ai_flags=AI_ADDRCONFIG;
  hints.ai_family=AF_UNSPEC;
  hints.ai_socktype=SOCK_STREAM;
  hints.ai_protocol=IPPROTO_TCP;
  hints.ai_addrlen=0;
  hints.ai_addr=0;
  hints.ai_canonname=NULL;

  error=getaddrinfo(host.c_str(),NULL,&hints,&hostinfo);
  if(error)
    #ifdef HAVE_GAI_STRERROR
      throw Exception(gai_strerror(error),__FILE__,__LINE__);
    #else
      #ifdef WIN32
        throw Exception("Winsock error "+Utils::inttostr(WSAGetLastError()),__FILE__,__LINE__);
      #else
        throw Exception("Socket error number "+Utils::inttostr(error),__FILE__,__LINE__);
      #endif //WIN32
    #endif //HAVE_GAI_STRERROR

  resolvedip=*(hostinfo->ai_addr);
  freeaddrinfo(hostinfo);
  return resolvedip;
}

string Socket::resolveToString(string host)
{
  struct sockaddr hostinfo;
  struct sockaddr_in *inetip;
  string strip;

  hostinfo=Socket::resolve(host);
  inetip=(sockaddr_in*)&hostinfo;
  strip=string(inet_ntoa(inetip->sin_addr));
  
  return strip;
}

string Socket::resolveInverselyToString(string ip)
{
  int error;
  char hostname[NI_MAXHOST];
  struct sockaddr addr;

  addr=resolve(ip);
  error=getnameinfo(&addr,sizeof(struct sockaddr),hostname,NI_MAXHOST,NULL,0,NI_NAMEREQD);

  if(error)
    if(error==EAI_NONAME)  //if the problem is that we didn't get a hostname, return empty string
      hostname[0]='\0';
    else
      #ifdef HAVE_GAI_STRERROR
        throw Exception(gai_strerror(error)+Utils::inttostr(error),__FILE__,__LINE__);
      #else
        #ifdef WIN32
          throw Exception("Winsock error "+Utils::inttostr(WSAGetLastError()),__FILE__,__LINE__);
        #else
          throw Exception("Socket error number "+Utils::inttostr(error),__FILE__,__LINE__);
        #endif //WIN32
      #endif //HAVE_GAI_STRERROR

  return string(hostname);
}

#else

/*
 * WARNING!!! WARNING!!! WARNING!!!
 * the following 3 functions are NOT thread-safe UNLESS used on a platform
 * that is using thread-local storage (i.e. windows), so be VERY careful with
 * them
 */
struct sockaddr Socket::resolve(string host)
{
  struct sockaddr_in *addr_in;
  struct sockaddr addr;

  addr_in=(sockaddr_in *)&addr;
  addr_in->sin_addr.s_addr=inet_addr(Socket::resolveToString(host).c_str());
  addr_in->sin_family=AF_INET;

  return addr;
}

string Socket::resolveToString(string host)
{
  struct hostent *hostinfo;
  struct in_addr addr;

  hostinfo=gethostbyname(host.c_str());

  if(NULL==hostinfo)
    throw Exception("Error resolving "+host,__FILE__,__LINE__);

  memcpy(&addr,hostinfo->h_addr,sizeof(addr));
  return string(inet_ntoa(addr));
}

string Socket::resolveInverselyToString(string ip)
{
  struct hostent *hostinfo;
  unsigned long addr;

  assert(ip.length()<16);

  addr=inet_addr(ip.c_str());
  hostinfo=gethostbyaddr((char *)&addr,4,AF_INET);

  if(NULL==hostinfo)
    throw Exception("Error resolving "+ip,__FILE__,__LINE__);

  return string(hostinfo->h_name);
}
#endif //HAVE_GETADDRINFO

int Socket::getFD()
{
  return fd;
}

/**
 * this function sets timeouts for a socket on receive and send
 * if either recv or send is -1, the timeout is not set, so for example
 * if you want to set recv timeout but NOT send timeout, you could call
 * this function like this:
 *   Socket::setTimeout(fd,3,-1);  <-- set 3 seconds receive timeout and
 *                                            don't change send timeout
 *
 * setting timeout of either one to 0 disables the timeout, socket will
 * block forever for data
 *
 * this function is needed because setting these timeouts is one of the
 * less portable setsockopt functions, and lot's of operating systems
 * do it differently
 *
 * @see setsockopt(2), socket(7) $LINUX_SRC/net/core/sock.c:{sock_setsockopt,sock_set_timeout}
 *
 * @todo check procedure on other operating systems like Solaris, *BSD and others
 *
 * @param recv timeout for receiving, a number in the format of 1.5 (one second and 500 milliseconds)
 * @param send same as recv but for sending
 */
void Socket::setTimeout(float recv,float send)
{
  if(fd<=0)
    throw Exception("Socket invalid: "+Utils::inttostr(fd)+" ",__FILE__,__LINE__);
  #ifdef WIN32
    //set timeout for receiving
    if(recv)
    {
      unsigned timeout=int(recv*1000);
      if(-1==setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(timeout)))
        throw Exception(Utils::errnotostrerror(errno),__FILE__,__LINE__);
    }

    //set timeout for sending
    if(send)
    {
      unsigned timeout=int(send*1000);
      if(-1==setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,(char *)&timeout,sizeof(timeout)))
        throw Exception(Utils::errnotostrerror(errno),__FILE__,__LINE__);
    }
  #else
    struct timeval timeout;
    int seconds=0;
    int useconds=0;

    //calculate seconds and useconds
    if(recv)
    {
      seconds=int(recv);
      useconds=int((recv-seconds)*1000);
      timeout.tv_usec=useconds;
      timeout.tv_sec=seconds;
      if(-1==setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(timeout)))
        throw Exception(Utils::errnotostrerror(errno),__FILE__,__LINE__);
    }

    if(send)
    {
      seconds=int(send);
      useconds=int((send-seconds)*1000);
      timeout.tv_usec=useconds;
      timeout.tv_sec=seconds;
      if(-1==setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,(char *)&timeout,sizeof(timeout)))
        throw Exception(Utils::errnotostrerror(errno),__FILE__,__LINE__);
    }
  #endif
}
