/* 
 * Https server created with Gnutls, and some example code is used here.
 * 
 * Copyright 2007, 2008 Free Software Foundation
 *
 * Copying and distribution of this file, with or without modification,
 * are permitted in any medium without royalty provided the copyright
 * notice and this notice are preserved.
 */

// TODO: find and fix memoryleaks

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <resolv.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gcrypt.h>

#include "httpsserver.h"
#include "httpreadwrite.h"
#include "upnpapi.h"
#include "miniserver.h"
#include "statcodes.h"


#define MAX_BUF 1024
#define DH_BITS 1024

static gnutls_certificate_credentials_t x509_cred;
static gnutls_priority_t priority_cache;
static gnutls_dh_params_t dh_params;

static int RUNNING = 0;
static int PORT = 0;

/* Static function declarations */
static SOCKET get_listener_socket(int port);
static gnutls_session_t initialize_tls_session (void);
static int generate_dh_params (void);
static void RunHttpsServer( SOCKET listen_sd );
static int parseHttpMessage(char *buf, int buflen, http_parser_t *parser, http_method_t request_method, int *timeout_secs, int *http_error_code);
static int tcp_connect (void);
static void tcp_close (int sd);


/* Make libgrypt (gnutls) thread save. This assumes that we are using pthred for threading.
 * Check http://www.gnu.org/software/gnutls/manual/gnutls.html#Multi_002dthreaded-applications
 * Also see StartHttpsServer
 */
GCRY_THREAD_OPTION_PTHREAD_IMPL;



 
/************************************************************************
 * Function: verify_certificate
 *
 * Parameters:
 *  IN gnutls_session_t session - Gnutls session
 *  IN const char *hostname - Value of Common Name (CN) element in peer certificate.
 *
 * Description:
 *  This function will try to verify the peer's certificate, and
 *  also check if the hostname matches, and the activation, expiration dates.
 *
 * Return: int
 *  GNU TLS error codes or -1
 *  GNUTLS_E_SUCCESS - on success
 ************************************************************************/ 
static int verify_certificate (gnutls_session_t session, const char *hostname)
{
    unsigned int status;
    const gnutls_datum_t *cert_list;
    unsigned int cert_list_size;
    int ret;
    gnutls_x509_crt_t cert;


    /* This verification function uses the trusted CAs in the credentials
     * structure. So you must have installed one or more CA certificates.
     */
    ret = gnutls_certificate_verify_peers2 (session, &status);

    if (ret != GNUTLS_E_SUCCESS)
    {
        UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
            "Error verifying peer certificates: %s\n", gnutls_strerror(ret) );
        return ret;
    }

    if (status & GNUTLS_CERT_INVALID)
    {
        UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
            "Peer certificate is not trusted\n");        
        return GNUTLS_CERT_INVALID;
    }

    if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
    {
        UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
            "Peer certificate hasn't got a known issuer\n");           
        return GNUTLS_CERT_SIGNER_NOT_FOUND;
    }

    if (status & GNUTLS_CERT_REVOKED)
    {
        UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
            "Peer certificate has been revoked\n");       
        return GNUTLS_CERT_REVOKED;
    }


    /* Up to here the process is the same for X.509 certificates and
     * OpenPGP keys. From now on X.509 certificates are assumed. This can
     * be easily extended to work with openpgp keys as well.
     */
    if ((ret = gnutls_certificate_type_get (session)) != GNUTLS_CRT_X509)
    {
        UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
            "Peer certificate type must be X.509. Wrong type received.\n");          
        return GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
    }

    if ((ret = gnutls_x509_crt_init (&cert)) != GNUTLS_E_SUCCESS)
    {
        UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
            "Peer certificate failed to initialize: %s\n",gnutls_strerror(ret) );
        return ret;
    }

    cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
    if (cert_list == NULL)
    {
        UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
            "No Peer certificate was found\n");
        return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }

    int i;
    for (i = 0; i < cert_list_size; i++)
    {   
        if ((ret = gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER)) != GNUTLS_E_SUCCESS)
        {
            UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
                "Error parsing Peer certificate: %s\n",gnutls_strerror(ret) );
            gnutls_x509_crt_deinit (cert);    
            return ret;
        }
    
        /* Beware here we do not check for errors.
         */
        if (gnutls_x509_crt_get_expiration_time (cert) < time (0))
        {
            UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
                "Peer certificate has expired\n");
            gnutls_x509_crt_deinit (cert);
            return GNUTLS_E_X509_CERTIFICATE_ERROR;
        }
    
        if (gnutls_x509_crt_get_activation_time (cert) > time (0))
        {
            UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
                "Peer certificate is not yet activated\n");
            gnutls_x509_crt_deinit (cert);
            return GNUTLS_E_X509_CERTIFICATE_ERROR;
        }
    
        if (!gnutls_x509_crt_check_hostname (cert, hostname))
        {
            UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
                "Peer certificate's owner does not match hostname '%s'\n",hostname);
            gnutls_x509_crt_deinit (cert);
            return GNUTLS_E_X509_CERTIFICATE_ERROR;
        }
    
        gnutls_x509_crt_deinit (cert);
    }

    return GNUTLS_E_SUCCESS;
}



/************************************************************************
 * Function: get_listener_socket
 *
 * Parameters:
 *  IN int port - Port number which is binded for socket
 *
 * Description:
 *  Create listener socket for https-server. 
 *
 * Return: int
 *  Created socket on success, else:
 *  UPNP_E_OUTOF_SOCKET - Failed to create a socket
 *  UPNP_E_SOCKET_BIND - Bind() failed
 *  UPNP_E_LISTEN   - Listen() failed   
 *  UPNP_E_SOCKET_ERROR - Setsockopt() failed
 ************************************************************************/
static SOCKET get_listener_socket(int port)
{
    struct sockaddr_in sa_serv;
    SOCKET listen_sd;
    int err;
    int optval = 1;
    
    listen_sd = socket (AF_INET, SOCK_STREAM, 0);
    if (listen_sd == -1)
    {
        UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
            "Error in creating HTTPS socket!!!\n" );
        return UPNP_E_OUTOF_SOCKET;   
    }  

    memset (&sa_serv, '\0', sizeof (sa_serv));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port = htons (port);  /* Server Port number */

    err = setsockopt (listen_sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
    if (err == -1)
    {
        UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
            "Error in setsockopt() HTTPS socket!!!\n" );        
        return UPNP_E_SOCKET_ERROR;   
    }  

    err = bind (listen_sd, (struct sockaddr *) & sa_serv, sizeof (sa_serv));
    if (err == -1)
    {
        UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
            "Error in binding HTTPS socket!!!\n" );        
        return UPNP_E_SOCKET_BIND;   
    }  
    err = listen (listen_sd, 1024);
    if (err == -1)
    {
        UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
            "Error in listen() HTTPS socket!!!\n" );        
        return UPNP_E_LISTEN;   
    }  
   
    return listen_sd;
}

/************************************************************************
 * Function: get_listener_socket
 *
 * Parameters:
 *  void
 *
 * Description:
 *  Create and initialize new gnutls session object for https-server
 *
 * Return: gnutls_session_t
 *  Created session.
 ************************************************************************/
static gnutls_session_t initialize_tls_session (void)
{
    gnutls_session_t session;
    int ret;

    ret = gnutls_init (&session, GNUTLS_SERVER);
    if (ret != GNUTLS_E_SUCCESS)
        return ( gnutls_session_t ) ret;

    ret = gnutls_priority_set (session, priority_cache);
    if (ret != GNUTLS_E_SUCCESS)
        return ( gnutls_session_t ) ret;
        
    ret = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
    if (ret != GNUTLS_E_SUCCESS)
        return ( gnutls_session_t ) ret;

    /* request client certificate if any. */
    gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);

    return session;
}


/************************************************************************
 * Function: generate_dh_params
 *
 * Parameters:
 *  void
 *
 * Description:
 *  Generate Diffie Hellman parameters - for use with DHE
 *  kx algorithms. When short bit length is used, it might
 *  be wise to regenerate parameters.
 *
 *  Check the ex-serv-export.c example for using static
 *  parameters.
 *
 * Return: int
 *  Return alway 0.
 ************************************************************************/
static int
generate_dh_params (void)
{
    gnutls_dh_params_init (&dh_params);
    gnutls_dh_params_generate2 (dh_params, DH_BITS);

    return 0;
}

/************************************************************************
 * Function: parseHttpMessage
 *
 * Parameters :
 *  char *buf - String containing HTTP packet
 *  int buflen - Length of buf
 *  http_parser_t *parser - Parser
 *  http_method_t request_method - HTTP method
 *  int *timeout_secs - Timeout
 *  int *http_error_code - HTTP error code
 *
 * Description:
 *  Parse http message from string into parser.
 *
 * Return: int
 *  PARSE_SUCCESS - On Success
 *  Error code - On Error
 ************************************************************************/
static int 
parseHttpMessage(
    IN char *buf,
    IN int buflen,
    OUT http_parser_t *parser,
    IN http_method_t request_method,
    IN OUT int *timeout_secs,
    OUT int *http_error_code)
{
    int ret = UPNP_E_SUCCESS;
    int line = 0;
    parse_status_t status;
    xboolean ok_on_close = FALSE;


    if (request_method == HTTPMETHOD_UNKNOWN) {
        parser_request_init(parser);
    } else {
        parser_response_init(parser, request_method);
    }    
    
    status = parser_append(parser, buf, buflen);
    if (status == PARSE_SUCCESS) {
        UpnpPrintf( UPNP_INFO, HTTP, __FILE__, __LINE__,
            "<<< (RECVD) <<<\n%s\n-----------------\n",
            parser->msg.msg.buf );
        print_http_headers( &parser->msg );
        if (parser->content_length > (unsigned int)g_maxContentLength) {
            *http_error_code = HTTP_REQ_ENTITY_TOO_LARGE;
            line = __LINE__;
            ret = UPNP_E_OUTOF_BOUNDS;
            goto ExitFunction;
        }
        line = __LINE__;
        ret = 0;
        goto ExitFunction;
    } else if (status == PARSE_FAILURE) {
        *http_error_code = parser->http_error_code;
        line = __LINE__;
        ret = UPNP_E_BAD_HTTPMSG;
        goto ExitFunction;
    } else if (status == PARSE_INCOMPLETE_ENTITY) {
        /* read until close */
        ok_on_close = TRUE;
    } else if (status == PARSE_CONTINUE_1) {
        /* Web post request. */
        line = __LINE__;
        ret = PARSE_SUCCESS;
        goto ExitFunction;
    }
    
ExitFunction:
    if (ret != UPNP_E_SUCCESS) {
        UpnpPrintf(UPNP_ALL, HTTP, __FILE__, line,
            "(http_RecvMessage): Error %d, http_error_code = %d.\n",
            ret,
            *http_error_code);
    }

    return ret;
}

/************************************************************************
 * Function: free_handle_https_request_arg
 *
 * Parameters:
 *  void *args - Request Message to be freed
 *
 * Description:
 *  Free memory assigned for handling request and unitialize socket
 *  functionality
 *
 * Return: void
 ************************************************************************/
static void
free_handle_https_request_arg( void *args )
{
    SOCKET sock = ( SOCKET )args;
    shutdown( sock, SD_BOTH );
    UpnpCloseSocket( sock );
}

/************************************************************************
 * Function: handle_https_request
 *
 * Parameters:
 *  void *args - Socket Descriptor on which connection is accepted
 *
 * Description:
 *  Create tls session, receive the request and dispatch it for handling
 *
 * Return: void
 ************************************************************************/
static void 
handle_https_request(void *args)
{   
    char buffer[MAX_BUF];
    int bytes;
    int http_error_code = 0;
    int ret_code;
    int major = 1;
    int minor = 1;
    http_parser_t parser;
    http_message_t *hmsg = NULL;
    int timeout = HTTP_DEFAULT_TIMEOUT;
    int ret;
    gnutls_session_t session;
    SOCKET sock = ( SOCKET )args;
    
    /* create session */
    session = initialize_tls_session();
    if (session < 0)
    {
        UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
            "Error initialising tls session: %s\n", gnutls_strerror(( int )session) );
        goto error_handler;        
    }

    /* require that client provide a certificate */
    gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
    
    gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sock);

    ret = gnutls_handshake (session);

    if (ret != GNUTLS_E_SUCCESS) {
        UpnpPrintf( UPNP_CRITICAL, MSERV, __FILE__, __LINE__,
            "Handshake has failed: %s\n", gnutls_strerror(ret) );
        goto error_handler;
    }

    // TODO: what is hostname value?????????! Is this even needed?
    // check client certificate. Is it trusted and such
    if ((ret = verify_certificate(session, "TestDevice")) != GNUTLS_E_SUCCESS) {
        
        //goto error_handler;
    }

    SOCKINFO info;
    info.tls_session = session;
    info.socket = sock;

    // serve session until peer closes connection or corrupted data is received
    // should here be some sort of expiration time, if no bye is received?
    while (TRUE)
    {
        memset (buffer, 0, MAX_BUF + 1);
        bytes = gnutls_record_recv (session, buffer, MAX_BUF);

        if (bytes == 0)
        {
            UpnpPrintf( UPNP_INFO, MSERV, __FILE__, __LINE__,
                "Peer has closed the GNUTLS connection\n");
            break;
        }
        else if (bytes < 0)
        {
            UpnpPrintf( UPNP_INFO, MSERV, __FILE__, __LINE__,
                "Https Received corrupted data. Closing the connection.\n");
            break;
        }
         else if (bytes > 0)
        {                                              
            if ( bytes > 0 && NULL == strstr( buffer, "ShutDown" )) /* if buf is ShutDown, then program is exiting */
            {
                ret_code = parseHttpMessage(buffer, bytes, &parser, HTTPMETHOD_UNKNOWN, &timeout, &http_error_code);
                /* dispatch as normal http packet, which it is */
                http_error_code = dispatch_request( &info, &parser );
                if( http_error_code != 0 ) {
                    goto error_handler;
                }
                http_error_code = 0;
            }
            else
                break;
        }
    }

error_handler:
    if( http_error_code > 0 ) {
        if( hmsg ) {
            major = hmsg->major_version;
            minor = hmsg->minor_version;
        }
        handle_error( &info, http_error_code, major, minor );
    }

    gnutls_bye (session, GNUTLS_SHUT_WR);
    close (sock);
    gnutls_deinit (session);       
}

/************************************************************************
 * Function: schedule_https_request_job
 *
 * Parameters:
 *  IN int sock - Socket Descriptor on which connection is accepted
 *
 * Description:
 *  Initilize the thread pool to handle a request.
 *  Sets priority for the job and adds the job to the thread pool
 *
 * Return: void
 ************************************************************************/
static UPNP_INLINE void
schedule_https_request_job( IN SOCKET sock )
{
    ThreadPoolJob job;
    
    TPJobInit( &job, ( start_routine ) handle_https_request, ( void * ) sock );
    TPJobSetFreeFunction( &job, free_handle_https_request_arg );
    TPJobSetPriority( &job, MED_PRIORITY );

    if( ThreadPoolAdd( &gHttpsServerThreadPool, &job, NULL ) != 0 ) {
        UpnpPrintf( UPNP_INFO, MSERV, __FILE__, __LINE__,
            "https: cannot schedule request\n" );
        shutdown( sock, SD_BOTH );
        UpnpCloseSocket( sock );
        return;
    }
}

/************************************************************************
 * Function: RunHttpsServer
 *
 * Parameters:
 *  SOCKET listen_sd - Socket Descriptor on which Https-server is listening
 *
 * Description:
 *  Function runs the https server. The HttpsServer accepts a 
 *  new request and schedules a thread to handle the new request.
 *  Checks for socket state and invokes appropriate read and shutdown 
 *  actions for the https server 
 *
 * Return: void
 ************************************************************************/
static void
RunHttpsServer( SOCKET listen_sd )
{
    
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    SOCKET sd;
        
    RUNNING = 1;
   
    while (RUNNING) {
        sd = accept(listen_sd, ( struct sockaddr * )&addr, &len);
        UpnpPrintf( UPNP_INFO, MSERV, __FILE__, __LINE__,
            "Https Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                    
        schedule_https_request_job(sd);
    } 

    close (listen_sd);
}

/************************************************************************
 * Function: StartHttpsServer
 *
 * Parameters :
 *  unsigned short listen_port - Port on which the server listens for incoming connections
 *  char* CertFile - Certification file of server
 *  char* PrivKeyFile - Private key file of server
 *  char* TrustFile - Trust list of certificates we trust. May be NULL
 *  char* CRLFile - Certificate Revocation List, aka. Blacklist of certificates which we don't trust (use PEM format...). May be NULL
 *
 * Description:
 *  Initialize gnutls for the https server. Initialize a thread pool job to run the server
 *  and the job to the thread pool.
 *
 * Return: int
 *  Actual port socket is bound to - On Success
 *  A negative number, either UPNP or gnutls error - On Error
 ************************************************************************/
int
StartHttpsServer( IN unsigned short listen_port,
                  IN const char *CertFile,
                  IN const char *PrivKeyFile,
                  IN const char *TrustFile,
                  IN const char *CRLFile)
{   
    /* for shutdown purposes */
    PORT = listen_port;
       
    SOCKET listen_sd;
    int ret;    
    
    /* Make libgrypt (gnutls) thread save. This assumes that we are using pthred for threading.
     * Check http://www.gnu.org/software/gnutls/manual/gnutls.html#Multi_002dthreaded-applications
     */
    gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    
    /* to disallow usage of the blocking /dev/random  */
    gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

    /* this must be called once in the program */
    // create gnutls session
    ret = gnutls_global_init ();
    if ( ret != GNUTLS_E_SUCCESS ) {
        UpnpPrintf( UPNP_INFO, MSERV, __FILE__, __LINE__,
            "StartHttpsServer: gnutls_global_init failed. (%s) \n\n", gnutls_strerror(ret) );        
        return ret;       
    }
    
    ret = gnutls_certificate_allocate_credentials (&x509_cred);
    if ( ret != GNUTLS_E_SUCCESS ) {
        UpnpPrintf( UPNP_INFO, MSERV, __FILE__, __LINE__,
            "StartHttpsServer: gnutls_certificate_allocate_credentials failed. (%s) \n\n", gnutls_strerror(ret) );        
        return ret;    
    }    
    
    ret = gnutls_certificate_set_x509_trust_file (x509_cred, TrustFile, GNUTLS_X509_FMT_PEM); // white list
    if (ret < 0) {
        UpnpPrintf( UPNP_INFO, MSERV, __FILE__, __LINE__,
            "StartHttpsServer: gnutls_certificate_set_x509_trust_file failed (%s)\n\n", gnutls_strerror (ret));
        return ret;       
    }
    
    if (CRLFile) {
        ret = gnutls_certificate_set_x509_crl_file (x509_cred, CRLFile, GNUTLS_X509_FMT_PEM); // black list    
        if (ret < 0) {
            UpnpPrintf( UPNP_INFO, MSERV, __FILE__, __LINE__,
                "StartHttpsServer: gnutls_certificate_set_x509_crl_file failed. (%s)\n\n", gnutls_strerror (ret));
            return ret;                   
        }
    }

    ret = gnutls_certificate_set_x509_key_file (x509_cred, CertFile, PrivKeyFile, GNUTLS_X509_FMT_PEM);                    
    if (ret != GNUTLS_E_SUCCESS) {
        UpnpPrintf( UPNP_INFO, MSERV, __FILE__, __LINE__,
            "StartHttpsServer: gnutls_certificate_set_x509_key_file failed. (%s)\n\n", gnutls_strerror (ret));
        return ret;    
    }
                        
    generate_dh_params ();
    
    ret = gnutls_priority_init (&priority_cache, "NORMAL", NULL);
    if (ret != GNUTLS_E_SUCCESS) {
        UpnpPrintf( UPNP_INFO, MSERV, __FILE__, __LINE__,
            "StartHttpsServer: gnutls_priority_init failed. (%s)\n\n", gnutls_strerror (ret));
        return ret;    
    }  
      
    gnutls_certificate_set_dh_params (x509_cred, dh_params);

    /* create listen socket */
    listen_sd = get_listener_socket(listen_port);

    if (listen_sd < 0) {
        return listen_sd; /* failure in creating socket */   
    }
   
    ThreadPoolJob job;
 
    TPJobInit( &job, (start_routine)RunHttpsServer, (void *)listen_sd );
    TPJobSetPriority( &job, MED_PRIORITY );
    TPJobSetFreeFunction( &job, ( free_routine ) free );

    int success = ThreadPoolAddPersistent( &gHttpsServerThreadPool, &job, NULL );
    if ( success < 0 ) {
        StopHttpsServer();
        return UPNP_E_OUTOF_MEMORY;
    }
 
    return listen_port;
}

/************************************************************************
 * Function: StopHttpsServer
 *
 * Parameters:
 *  void
 *
 * Description:
 *  Send ShutDown message for local https server. Creates ssl session for
 *  message sending.
 *
 * Return: int
 *      Always returns 0 
 ************************************************************************/
int
StopHttpsServer(void)
{  
    RUNNING = 0; /* this stops RunHttpsServer() */
    char *msg = "ShutDown";
    int ret, sd;
    gnutls_session_t session;
    const char *err;  

    gnutls_init (&session, GNUTLS_CLIENT);
    /* Use default priorities. Don't care errors anymore. */
    ret = gnutls_priority_set_direct (session, "PERFORMANCE", &err);

    /* put the x509 credentials to the current session */
    gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);

    /* connect to the peer */
    sd = tcp_connect ();
    if (sd < 0)
    {
        goto end;   
    }

    gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);

    /* Perform the TLS handshake */
    ret = gnutls_handshake (session);

    if (ret < 0)
    {
        UpnpPrintf( UPNP_INFO, MSERV, __FILE__, __LINE__,
            "Https shutdown client handshake failed: %s\n", gnutls_strerror(ret));
        goto end;
    }

    gnutls_record_send (session, msg, strlen (msg));

    gnutls_bye (session, GNUTLS_SHUT_RDWR);

end:    
    tcp_close (sd);
    
    gnutls_certificate_free_credentials (x509_cred);
    gnutls_priority_deinit (priority_cache);
    gnutls_global_deinit ();

    return 0;
}

/************************************************************************
 * Function: StopHttpsServer
 *
 * Parameters:
 *  void
 *
 * Description:
 *  Create socket and connect it to local https server.
 *  Code from gnutls examples.
 *
 * Return: int
 *      Created socket descriptor 
 ************************************************************************/
static int
tcp_connect (void)
{
    const char *SERVER = "127.0.0.1";
    int err, sd;
    struct sockaddr_in sa;

    /* connects to server */
    sd = socket (AF_INET, SOCK_STREAM, 0);

    memset (&sa, '\0', sizeof (sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons (PORT);
    inet_pton (AF_INET, SERVER, &sa.sin_addr);

    err = connect (sd, (struct sockaddr *) & sa, sizeof (sa));
    if (err < 0)
    {
        UpnpPrintf( UPNP_INFO, MSERV, __FILE__, __LINE__,
            "Https shutdown client failed to create socket\n");
        return UPNP_E_OUTOF_SOCKET;
    }

    return sd;
}

/************************************************************************
 * Function: tcp_close
 *
 * Parameters:
 *  int sd - Socket descriptor
 *
 * Description:
 *  Close given socket descriptor.
 *  Code from gnutls examples.
 *
 * Return: void 
 ************************************************************************/
static void
tcp_close (int sd)
{
    shutdown (sd, SHUT_RDWR); /* no more receptions */
    close (sd);
}
