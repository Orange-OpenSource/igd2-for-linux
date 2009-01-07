#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "httpsserver.h"
#include "httpparser.h"
#include "httpreadwrite.h"
#include "upnpapi.h"
#include "statcodes.h"
#include "miniserver.h"

#define FAIL    -1

static int RUNNING = 0;

/*---------------------------------------------------------------------*/
/*--- OpenListener - create server socket                           ---*/
/*---------------------------------------------------------------------*/
int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, &addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        //abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        //abort();
    }
    return sd;
}

/*---------------------------------------------------------------------*/
/*--- InitServerCTX - initialize SSL server  and create context     
---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();

    OpenSSL_add_all_algorithms();       /* load & register all cryptos, etc. */
    SSL_load_error_strings();           /* load all error messages */
    method = TLSv1_server_method();     /* create new server-method instance */
    ctx = SSL_CTX_new(method);          /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        //abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        //abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        //abort();
    }
}

/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out certificates.                           ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);   /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

/*---------------------------------------------------------------------*/
/*--- Servlet - SSL servlet (contexts can be shared) ---*/
/*---------------------------------------------------------------------*/
void Servlet(SSL* ssl)  /* Serve the connection -- threadable Sessio? Jotain? */
{   
    int buflen = 1024;
    char buf[buflen];
    char reply[buflen];
    int sd, bytes;
    const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";
    
    int http_error_code;
    int ret_code;
    int major = 1;
    int minor = 1;
    http_parser_t parser;
    http_message_t *hmsg = NULL;
    int timeout = HTTP_DEFAULT_TIMEOUT;

    SOCKINFO info;
    info.ssl = ssl;
    info.socket = SSL_get_fd(ssl);
     
    if ( SSL_accept(ssl) == FAIL )                  
/* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);                             
/* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf));    /* get request */
        if ( bytes > 0 )
        {            
            // buf on suoraan HTTP paketti!! Suoraan vaan sinne minne muutkin http:t menee. Entäs vastaus...
            //buf[bytes] = 0;
            
            ret_code = parseHttpMessage(buf, bytes, &parser, HTTPMETHOD_UNKNOWN, &timeout, &http_error_code);
            printf("Parse returned %d\n%s\n",ret_code,parser.msg.msg.buf);
            // dispatch
            http_error_code = dispatch_request( &info, &parser );
            if( http_error_code != 0 ) {
                goto error_handler;
            }
            http_error_code = 0;

            printf("Client msg: \"%s\"\n%d\n", buf,ret_code);
            sprintf(reply, HTMLecho, buf);          /* construct reply */
            SSL_write(ssl, reply, strlen(reply));   /* send reply */
        }
        else
            ERR_print_errors_fp(stderr);
    }

error_handler:
    if( http_error_code > 0 ) {
        if( hmsg ) {
            major = hmsg->major_version;
            minor = hmsg->minor_version;
        }
        handle_error( &info, http_error_code, major, minor );
    }

    
    //SSL_shutdown(ssl);
    
    sd = SSL_get_fd(ssl);                           
/* get socket connection */
    SSL_free(ssl);                                  
/* release SSL state */
    close(sd);                                      
/* close connection */
}


int parseHttpMessage(
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
    SSL *ssl = NULL;
    SSL_CTX *ctx;
    int server;
   
    ctx = InitServerCTX();                              

    LoadCertificates(ctx, CertFile, PrivKeyFile);  /* load certs */
    server = OpenListener(listen_port);               

    struct sockaddr_in addr;
    int len = sizeof(addr);
    
    if (!fork())
    {
        RUNNING = 1;
        
        while (RUNNING) {
            printf("___ RUN HTTPS 2___\n");
            
            int sock = accept(server, &addr, &len);
            // fork here for multiple clients
            if(fork())
            {
                close(sock);
            }           
            else 
            {
                printf("Connection: %s:%d\n",
                    inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                ssl = SSL_new(ctx); 
                SSL_set_fd(ssl, sock); 
                Servlet(ssl);
            }
        }
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
/*        
    if (ssl != NULL)
    {
        SSL_shutdown(ssl);
        
        int sd;
        sd = SSL_get_fd(ssl);
        SSL_free(ssl);          
        close(sd);
    }         
*/
    return 0;
}
