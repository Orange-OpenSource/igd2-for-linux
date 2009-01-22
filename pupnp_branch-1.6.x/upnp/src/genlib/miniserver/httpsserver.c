/* 
 * Https server created with Gnutls, and some example code is used here.
 * 
 * Copyright 2007, 2008 Free Software Foundation
 *
 * Copying and distribution of this file, with or without modification,
 * are permitted in any medium without royalty provided the copyright
 * notice and this notice are preserved.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <resolv.h>
#include <gnutls/gnutls.h>
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

//static SSL *ssl = NULL;
static int RUNNING = 0;

static int PORT = 0;

// Static function declarations
static SOCKET get_listener_socket(int port);
static gnutls_session_t initialize_tls_session (void);
static int generate_dh_params (void);
static void Servlet(gnutls_session_t session, SOCKET sock);
static void RunHttpsServer( SOCKET listen_sd );
static int parseHttpMessage(char *buf, int buflen, http_parser_t *parser, http_method_t request_method, int *timeout_secs, int *http_error_code);
static int tcp_connect (void);
static void tcp_close (int sd);

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

static gnutls_session_t initialize_tls_session (void)
{
    gnutls_session_t session;

    gnutls_init (&session, GNUTLS_SERVER);

    gnutls_priority_set (session, priority_cache);

    gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);

    /* request client certificate if any. */
    gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);

    return session;
}

static gnutls_dh_params_t dh_params;

static int
generate_dh_params (void)
{
    /* Generate Diffie Hellman parameters - for use with DHE
    * kx algorithms. When short bit length is used, it might
    * be wise to regenerate parameters.
    *
    * Check the ex-serv-export.c example for using static
    * parameters.
    */
    gnutls_dh_params_init (&dh_params);
    gnutls_dh_params_generate2 (dh_params, DH_BITS);

    return 0;
}


/*---------------------------------------------------------------------*/
/*--- Servlet - SSL servlet (contexts can be shared) ---*/
/*---------------------------------------------------------------------*/
static void 
Servlet(gnutls_session_t session, SOCKET sock)
{   
    char buffer[MAX_BUF];
    char reply[MAX_BUF];
    int bytes;
    
    int http_error_code;
    int ret_code;
    int major = 1;
    int minor = 1;
    http_parser_t parser;
    http_message_t *hmsg = NULL;
    int timeout = HTTP_DEFAULT_TIMEOUT;

    SOCKINFO info;
    info.ssl = session;
    info.socket = sock;

    while (TRUE)
    {
        memset (buffer, 0, MAX_BUF + 1);
        bytes = gnutls_record_recv (session, buffer, MAX_BUF);

        if (bytes == 0)
        {
            printf ("\n- Peer has closed the GNUTLS connection\n");
            break;
        }
        else if (bytes < 0)
        {
            fprintf (stderr, "\n*** Received corrupted "
                "data(%d). Closing the connection.\n\n", bytes);
            break;
        }
         else if (bytes > 0)
        {
            /* echo data back to the client
            */
            printf("%s\n",buffer);
            //gnutls_record_send (session, buffer, strlen (buffer));
                                              
            if ( bytes > 0 && NULL == strstr( buffer, "ShutDown" )) // if buf is ShutDown, then program is exiting
            {
                ret_code = parseHttpMessage(buffer, bytes, &parser, HTTPMETHOD_UNKNOWN, &timeout, &http_error_code);
                // dispatch
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

    //printf("Shutdown\n");
    //SSL_shutdown(ssl);
    //SSL_set_shutdown(con,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
    
    //sd = SSL_get_fd(ssl);                           
/* get socket connection */
    //SSL_free(ssl);                                  
/* release SSL state */
    //close(sd);                                      
/* close connection */
}

/************************************************************************
 * Function: parseHttpMessage
 *
 * Parameters :
 *  char *buf - String containing HTTP packet
 *  int buflen - Length of buf
 *  http_parser_t *parser - Parser
 *  http_method_t request_method - 
 *  int *timeout_secs - 
 *  int *http_error_code - 
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
        // read until close
        ok_on_close = TRUE;
    } else if (status == PARSE_CONTINUE_1) {
        // Web post request.
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
 * Function: RunHttpsServer
 *
 * Parameters:
 *  SSL_CTX *ctx - SSL_CTX object as framework for TLS/SSL enabled functions 
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
    int len = sizeof(addr);
    int ret;
    SOCKET sd;
    gnutls_session_t session;
        
    RUNNING = 1;
   
    while (RUNNING) {
        session = initialize_tls_session();
        sd = accept(listen_sd, &addr, &len);
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);
        ret = gnutls_handshake (session);

        if (ret < 0) {
            close (sd);
            gnutls_deinit (session);
            fprintf (stderr, "*** Handshake has failed (%s)\n\n", gnutls_strerror (ret));
            continue;
        }

        Servlet(session, sd);
        
        gnutls_bye (session, GNUTLS_SHUT_WR);
        close (sd);
        gnutls_deinit (session);        
    } 

    close (listen_sd);

    gnutls_certificate_free_credentials (x509_cred);
    gnutls_priority_deinit (priority_cache);

    gnutls_global_deinit ();
}

/************************************************************************
 * Function: StartHttpsServer
 *
 * Parameters :
 *  unsigned short listen_port - Port on which the server listens for 
 *      incoming connections
 *
 * Description:
 *  Initialize the sockets functionality for the 
 *  Miniserver. Initialize a thread pool job to run the MiniServer
 *  and the job to the thread pool. If listen port is 0, port is 
 *  dynamically picked
 *
 *  Use timer mechanism to start the MiniServer, failure to meet the 
 *  allowed delay aborts the attempt to launch the MiniServer.
 *
 * Return: int
 *  Actual port socket is bound to - On Success
 *  A negative number UPNP_E_XXX - On Error
 ************************************************************************/
int
StartHttpsServer( unsigned short listen_port, char* CertFile, char* PrivKeyFile )
{   
    // for shutdown purposes
    PORT = listen_port;
        
    SOCKET listen_sd;
    int ret;    


    /* to disallow usage of the blocking /dev/random  */
    gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

    /* this must be called once in the program */
    gnutls_global_init ();

    gnutls_certificate_allocate_credentials (&x509_cred);
    /*
    ret = gnutls_certificate_set_x509_trust_file (x509_cred, CAFILE, GNUTLS_X509_FMT_PEM); // white list?

    if (ret < 0)
        fprintf (stderr, "*** Trust file failed (%s)\n\n", gnutls_strerror (ret)); 

    ret = gnutls_certificate_set_x509_crl_file (x509_cred, CRLFILE, GNUTLS_X509_FMT_PEM); // black list, certificate revocation list

    if (ret < 0)
        fprintf (stderr, "*** CRL file failed (%s)\n\n", gnutls_strerror (ret));
    */

    ret = gnutls_certificate_set_x509_key_file (x509_cred, CertFile, PrivKeyFile, GNUTLS_X509_FMT_PEM);
                    
    if (ret != GNUTLS_E_SUCCESS)
        fprintf (stderr, "*** Cert and priv key failed (%s)\n\n", gnutls_strerror (ret));
                        
    generate_dh_params ();

    gnutls_priority_init (&priority_cache, "NORMAL", NULL);

    gnutls_certificate_set_dh_params (x509_cred, dh_params);

    // create listen socket
    listen_sd = get_listener_socket(listen_port);

    if (listen_sd < 0) {
        return listen_sd; // failure in creating socket   
    }
   
    ThreadPoolJob job;
 
    TPJobInit( &job, (start_routine)RunHttpsServer, (void *)listen_sd );
    TPJobSetPriority( &job, MED_PRIORITY );
    TPJobSetFreeFunction( &job, ( free_routine ) free );

    int success = ThreadPoolAddPersistent( &gMiniServerThreadPool, &job, NULL );
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
 *  Stop and Shutdown the HttpsServer and free socket 
 *  resources.
 *
 * Return: int
 *      Always returns 0 
 ************************************************************************/
int
StopHttpsServer()
{
    RUNNING = 0;
    
    char *msg = "ShutDown";
     int ret, sd, ii;
    gnutls_session_t session;
    char buffer[MAX_BUF + 1];
    const char *err;
    
    gnutls_init (&session, GNUTLS_CLIENT);
    /* Use default priorities. Don't care errors anymore. */
    ret = gnutls_priority_set_direct (session, "PERFORMANCE", &err);


    /* put the x509 credentials to the current session */
    gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);

    /* connect to the peer */
    sd = tcp_connect ();

    gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);

    /* Perform the TLS handshake */
    ret = gnutls_handshake (session);

    if (ret < 0)
    {
        fprintf (stderr, "*** Handshake failed\n");
        gnutls_perror (ret);
        goto end;
    }

    gnutls_record_send (session, msg, strlen (msg));

    gnutls_bye (session, GNUTLS_SHUT_RDWR);

end:

    tcp_close (sd);
    gnutls_deinit (session);

    return 0;
}

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
        fprintf (stderr, "Connect error\n");
        exit (1);
    }

    return sd;
}

/* closes the given socket descriptor.
 */
static void
tcp_close (int sd)
{
    shutdown (sd, SHUT_RDWR); /* no more receptions */
    close (sd);
}
