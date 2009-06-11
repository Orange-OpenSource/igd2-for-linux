#include <sys/stat.h>
#include <netinet/in.h>
#include <libsoup/soup.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>


#include "pki.h"
#include "gupnp-ssl-client.h"



// these are now global variables, because this is the only way I can imagine 
// that clientCertCallback function can access these
gnutls_x509_crt_t client_crt = NULL;
gnutls_x509_privkey_t client_privkey = NULL;

/*
G_DEFINE_TYPE (GUPnPSSLClient,
               gupnp_ssl_client,
               GUPNP_CONTEXT);


static void
gupnp_ssl_client_init (GUPnPSSLClient *client)
{
}


static void
gupnp_ssl_client_class_init (GUPnPSSLClientClass *klass)
{
}
*/

/************************************************************************
*   Function :  ssl_create_https_url
*   Parameters:
*   IN const char *http_url: Https url which is turned into https usrl
*   IN int port: Port number used in https url
*   IN char **https_url: Pointer to created https url
*   
*   Description :   Create https url from http url. 
*               http://127.0.0.1:49152  => https://127.0.0.1:443
*
*   Return : void
*
*   Note : 
************************************************************************/
void ssl_create_https_url(const char *http_url, int port, char **https_url)
{
    SoupURI *uri;
    uri = soup_uri_new (http_url);
    uri->scheme = SOUP_URI_SCHEME_HTTPS;
    uri->port = port;
    
    *https_url = soup_uri_to_string(uri, FALSE);
    soup_uri_free (uri);    
}


/************************************************************************
*   Function :  clientCertCallback
*
*   Description :   Callback function which is called by gnutls when 
*         server asks client certificate at the tls handshake.
*         Function sets certificate and private key used by client for 
*         response.
*
*   Return : int
*
*   Note : Don't call this.
************************************************************************/
int clientCertCallback(gnutls_session_t session, const gnutls_datum_t* req_ca_dn, int nreqs, gnutls_pk_algorithm_t* pk_algos, int pk_algos_length, gnutls_retr_st* st)
{
    gnutls_certificate_type type;
       
    type = gnutls_certificate_type_get(session);
    if (type == GNUTLS_CRT_X509) {         
        st->type = type;
        st->ncerts = 1;        
        st->cert.x509 = &client_crt;  // these two are globals defined in upnpapi
        st->key.x509 = client_privkey;// 
        st->deinit_all = 0;
    } 
    else {
        return -1;
    }
    
    return 0;
}


/**************************************************************************
 * Function: ssl_init_client
 *
 * Parameters:
 *  IN const char *directory: Path to directory where files locate or where files are created
 *  IN const char *CertFile: Selfsigned certificate file of client. If NULL, new certificate and private key is created
 *  IN const char *PrivKeyFile: Private key file of client. If NULL, new private key is created
 *  IN const char *TrustFile: File containing trusted certificates. May be NULL
 *  IN const char *CRLFile: Certificate revocation list. Untrusted certificates. May be NULL
 *  IN const char *devName: Name of device. This is used as CN (common name) in certificate
 * 
 * Description:
 *  This function initializes gnutls and gnutls certificate credentials for 
 *  clients to use. If trust or CRL files are NULL, then they won't be used.
 *  If either certificate or private key file is NULL, then both will be
 *  neglected and new prvate key and certificate are created in upnp default files. 
 *  All files must be in PEM-format.
 *
 * Return Values: int
 *  GUPNP_E_SUCCESS on success, nonzero on failure. Less than zero values
 *  may be either libupnp own error codes, or gnutls error codes.
 *      
 ***************************************************************************/
int
ssl_init_client( GUPnPSSLClient *client,
                 const char *directory,
                 const char *CertFile,
                 const char *PrivKeyFile,
                 const char *TrustFile,
                 const char *CRLFile,
                 const char *devName)
{
    int retVal;

    retVal = init_crypto_libraries();
    if (retVal != 0) {
        g_warning("Error: %s", "Crypto library initialization failed");
        return retVal;    
    }  
    
    if (CertFile && PrivKeyFile) {
        // put certificate and private key in global variables for use in tls handshake
        retVal = load_x509_self_signed_certificate(&client_crt, &client_privkey, directory, CertFile, PrivKeyFile, devName, GUPNP_X509_CERT_MODULUS_SIZE, GUPNP_X509_CERT_LIFETIME);
        if ( retVal != GNUTLS_E_SUCCESS ) {
            g_warning("Error: %s", "Certificate loading failed");
            return retVal;    
        }        
        retVal = init_x509_certificate_credentials(&client->xcred, directory, CertFile, PrivKeyFile, TrustFile, CRLFile);
        if ( retVal != GNUTLS_E_SUCCESS ) {
            g_warning("Error: %s", "Certificate credentials creating failed");
            return retVal;    
        }          
    }
    else {
        // create own private key and self signed certificate or use default file
        retVal = load_x509_self_signed_certificate(&client_crt, &client_privkey, directory, GUPNP_X509_CLIENT_CERT_FILE, GUPNP_X509_CLIENT_PRIVKEY_FILE, devName, GUPNP_X509_CERT_MODULUS_SIZE, GUPNP_X509_CERT_LIFETIME);
        if ( retVal != GNUTLS_E_SUCCESS ) {
            g_warning("Error: %s", "Certificate loading failed");
            return retVal;    
        }          
        retVal = init_x509_certificate_credentials(&client->xcred, directory, GUPNP_X509_CLIENT_CERT_FILE, GUPNP_X509_CLIENT_PRIVKEY_FILE, TrustFile, CRLFile);
        if ( retVal != GNUTLS_E_SUCCESS ) {
            g_warning("Error: %s", "Certificate credentials creating failed");
            return retVal;    
        }   
    }    

    // set callback function for returning client certificate. (in default case server says in 
    // certificate request that who has to be the signer of cert. Our client may not be on that list)
    gnutls_certificate_client_set_retrieve_function(client->xcred, (gnutls_certificate_client_retrieve_function *)clientCertCallback);
    
    // init session to NULL
    client->session = NULL;
    
    return GUPNP_E_SUCCESS;     
}  /****************** End of ssl_init_client *********************/


/**************************************************************************
 * Function: ssl_finish_client
 *
 * Description:
 *  This function deinitializes gnutls and gnutls certificate credentials.
 *  Call this when SSL is no more needed. Propably at then end of program.
 *
 * Return Values: int
 *  GUPNP_E_SUCCESS on success, nonzero on failure. Less than zero values
 *  may be either libupnp own error codes, or gnutls error codes.
 *      
 ***************************************************************************/
int
ssl_finish_client( GUPnPSSLClient *client)
{
    gnutls_x509_crt_deinit(client_crt);
    gnutls_x509_privkey_deinit(client_privkey);    
    gnutls_certificate_free_credentials (client->xcred);
    gnutls_global_deinit ();
    
    return GUPNP_E_SUCCESS;
}  /****************** End of ssl_finish_client *********************/


/**************************************************************************
 * Function: ssl_create_client_session
 *
 * Parameters:  
 *  IN const char *ActionURL_const: The action URL of the service. Target IP is parsed from this.
 *  INOUT void *SSLSessionData:  Pointer to space where SSL session data may be saved.
 *  INOUT size_t *DataSize:  Pointer to value which will tell how much size SSLSessionData uses. Value is automatically set.
 *  INOUT UpnpClient_Handle Hnd: Handle to add the SSL Session.
 *
 * Description:
 *  This function creates new SSL session which client can use for secure
 *  data trasmission with secured device. Created SSL session can be terminated 
 *  with UpnpCloseClientSSLSession.
 *  Call UpnpInitClientSSL before using this function.
 *
 * Return Values: int
 *  GUPNP_E_SUCCESS on success, nonzero on failure. Less than zero values
 *  may be either libupnp own error codes, or gnutls error codes.
 *      
 ***************************************************************************/
int
ssl_create_client_session(  GUPnPSSLClient *client,
                            const char *ActionURL_const,
                            void *SSLSessionData,
                            size_t *DataSize)
{
    int retVal = 0;
    int sd;
    const char *err;
    struct sockaddr_in ip4addr;    
    gnutls_session_t session;

    SoupURI *uri;
    uri = soup_uri_new (ActionURL_const);
    
    // we could check that type of uri is SOUP_URI_SCHEME_HTTPS, but we are not so thight about that
    g_warning("SSL HOST: %s PORT: %d",uri->host, uri->port);   

    ip4addr.sin_family = AF_INET;
    ip4addr.sin_port = htons(uri->port);
    inet_pton(AF_INET, uri->host, &ip4addr.sin_addr);  

    soup_uri_free (uri);
    
    // connects to server
    sd = socket (AF_INET, SOCK_STREAM, 0);
    if (sd == -1) {
        return GUPNP_E_SOCKET_ERROR;   
    }

    retVal = connect (sd, (struct sockaddr*)&ip4addr, sizeof( struct sockaddr_in ));
    if (retVal < 0) {
        close (sd);        
        return GUPNP_E_SOCKET_CONNECT;
    }

    // Initialize and create TLS session 
    retVal = gnutls_init (&session, GNUTLS_CLIENT);
    if (retVal != GNUTLS_E_SUCCESS) {
        g_warning("Error: gnutls_init failed. %s", gnutls_strerror(retVal));
        return retVal;  
    }

    // Use default priorities 
    retVal = gnutls_priority_set_direct (session, "NORMAL", &err);
    if (retVal < 0) {
        g_warning("Error: gnutls_priority_set_direct failed. %s Error at: %s", 
            gnutls_strerror(retVal), err);
        return retVal;
    }

    // put the x509 credentials to the current session 
    retVal = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, client->xcred);
    if (retVal != GNUTLS_E_SUCCESS) {
        g_warning("Error: gnutls_credentials_set failed. %s", gnutls_strerror(retVal));
        return retVal;  
    }    

    // set socket for current session
    gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);

    // check if we can resume session
    if (SSLSessionData && *DataSize > 0) {
        retVal = gnutls_session_set_data(session, SSLSessionData, *DataSize);
        
        if (retVal != GNUTLS_E_SUCCESS) {
            g_warning("Error: Failed to set SSL session resumption data. %s", gnutls_strerror(retVal));
            return retVal;  
        }  
    }

    // Perform the TLS handshake 
    retVal = gnutls_handshake (session);
    if (retVal != GNUTLS_E_SUCCESS) {
        g_warning("Error: gnutls_handshake failed. %s", gnutls_strerror(retVal));
        return retVal;  
    }  

    if (SSLSessionData)
    {
        // check if session is resumed. If not and new session is created, save session data for next time
        if (gnutls_session_is_resumed(session) != 0)
        {
            g_message("Previous ssl session was resumed");
        }
        else
        {
            g_message("Previous ssl session was NOT resumed");
    
            if (SSLSessionData) free(SSLSessionData);
            // get the session data size 
            gnutls_session_get_data(session, NULL, DataSize);
            SSLSessionData = malloc(*DataSize);
        
            // put session data to the session variable
            retVal = gnutls_session_get_data (session, SSLSessionData, DataSize);
            if (retVal != GNUTLS_E_SUCCESS) {
                g_warning("Error: gnutls_session_get_data failed. %s", gnutls_strerror(retVal));
                return retVal;  
            }                
        }
    }
 
    // put sesison to client
    client->session = session;

    return GUPNP_E_SUCCESS;

}  /****************** End of ssl_create_client_session   *********************/
 
 
/**************************************************************************
 * Function: ssl_close_client_session
 *
 * Parameters:
 *  INOUT UpnpClient_Handle Hnd: Client handle
 *
 * Description:
 *  This function terminates SSL session which client can use for secure
 *  data trasmission with secured device.
 *
 * Return Values: int
 *      
 ***************************************************************************/
int
ssl_close_client_session( GUPnPSSLClient *client )
{
    int retVal = 0;
    int sd;

    // check if session even exist
    if (client->session == NULL) {

        return GUPNP_E_SUCCESS;             
    }

    // send bye to peer
    retVal = gnutls_bye (client->session, GNUTLS_SHUT_WR);
    if (retVal != GNUTLS_E_SUCCESS)
    {
        g_warning("Error: gnutls_bye failed. %s", gnutls_strerror(retVal));
        return retVal;  
    }     
    
    // close socket
    sd = (int)gnutls_transport_get_ptr(client->session);
    shutdown (sd, SHUT_RDWR); /* no more receptions */
    close (sd);
    
    gnutls_deinit (client->session);

    //gnutls_certificate_free_credentials (SInfo->SSLInfo->tls_cred);
 
    client->session = NULL;
    //SInfo->SSLInfo->tls_cred = NULL;

    return GUPNP_E_SUCCESS;

}  /****************** End of ssl_close_client_session   *********************/


/**************************************************************************
 * Function: parse_headers
 *
 * Parameters:
 *  OUT  SoupMessageHeaders *soup_headerst: Header name-value pairs are added to this struct
 *  IN  const char *headers: String containing headers
 * 
 * Description:
 *  Add headers parsed from string to given SoupMessageHeaders struct. Parse statuscode value
 *  from headers and return it.
 *
 * Return Values: int
 *      Statuscode value parsed from headers, 
 *      Negative value on error. 
 *      
 ***************************************************************************/
static int parse_headers(SoupMessageHeaders *soup_headers, const char *headers)
{
    char headers_copy[strlen(headers)];
    char *tmp;
    char *value;
    int status_code = -1;
    
    strcpy(headers_copy, headers);

    // Example header:
    // Accept-Language: en-us;q=1, en;q=0.5
    // 1. tokenize header string with '\r\n', different header-value pairs should be separated with that
    // 2. If token contains ":", we have a pair
    // 3. copy string after ":" as value and replace ':' with '\0'. This leaves only header name into token 
    char *token = strtok(headers_copy, "\r\n");
    if (token)
    {
        do 
        {
            if ( (tmp = strstr(token, ":")) != NULL )
            {
                value = strdup(tmp+1);
                *tmp = '\0';
                
                if (token && value)
                    soup_message_headers_append(soup_headers, token, value);
                free(value);
            }
            else if ( (tmp = strstr(token, "HTTP/")) != NULL ) // this row contains statuscode of message
            {
                // HTTP/1.1 200 OK
                // find last space and replace it with '\0'
                tmp = strrchr(token, ' ');
                *tmp = '\0';
                // find first space and all after that is status code as string (maybe some white spaces too)
                tmp = strstr(token, " ");
                status_code = atoi(tmp);
            }
            
                
        } while ((token = strtok(NULL, "\r\n")));

    } 
    
    return status_code;      
}


/**************************************************************************
 * Function: ssl_client_send_and_receive
 *
 * Parameters:
 *  IN  GUPnPSSLClient *client: Client used for sending message. This contains SSL-session
 *  IN  const char *message: Message which is send
 *  IN  char **response: Response for message is returned here as string
 *  IN  SoupMessage *msg: Into this SoupMessage, response information is inserted. This way we can mimic that normal soup-sending and receiving was used
 *
 * Description:
 *  Send and receive using SSL. Tries to mimic for the rest of gupnp normal soup.
 *  Puts response to SoupMessage as soup would have done.
 * 
 *  Problems with this implementation are:
 *      - doesn't support support chunked HTTP
 *      - doesn't support revival from Method Not Allowed status-code
 *      - not sure what happens if something goes wrong... 
 *
 * Return Values: int
 *      0 on success.
 *      
 ***************************************************************************/
int ssl_client_send_and_receive(  GUPnPSSLClient *client,
                                        const char *message,
                                        char **response,
                                        SoupMessage *msg)
{
    int headers_ready = 0;
    char *tmp, *body = NULL;
    int retVal = 0;
    int size = 0;
    int alloc = 1024;
    int len = 1024;
    char recv[len+1];
    int content_len = 0;

    *response = malloc((alloc+1)*sizeof( char* ));
    **response = '\0';

    if (client->session == NULL)
        return GUPNP_E_SESSION_FAIL;
   
    // Send the message
    retVal = gnutls_record_send(client->session, message, strlen(message));
     
    if (retVal < 0)
    {
        g_warning("Error: gnutls_record_send failed. %s", gnutls_strerror(retVal));
        return retVal;  
    }
    
    // Start receiving until error occurs or whole message is received.
    while (retVal > 0) // if retVal is negative, then gnutls have returned error
    {
        memset(recv, '\0',len+1);// earlier receivings doesn't bother after this
        retVal = gnutls_record_recv (client->session, recv, len);
               
        if (retVal < 0)
        {
            g_warning("Error: gnutls_record_recv failed. %s", gnutls_strerror(retVal));
            return retVal;
        }
        else
        { 
            //g_warning("Received %d bytes", retVal);
        }
       
        // does *response have enough space. If not realloc
        if ( (size + retVal) > alloc )
        {
            char *new_resp;
            alloc = alloc + retVal + 1;
            
            new_resp = realloc (*response, alloc);
            if (!new_resp) {
                return -1; // not enough memory
            }
  
            *response = new_resp;
        }
         
        strcat(*response, recv);
        size = strlen(*response);
       
        // receive data until empty line containing only \r\n is received (also previous line must end with \r\n). 
        // That means that headers are done
        // This "parser" doesn't support chunked encoding...    
        if (!headers_ready && (tmp = strstr(*response, "\r\n\r\n")) != NULL)
        {
            body = tmp + 4; // body of message is everything that comes after "\r\n\r\n"
            
            // add response header values to SoupMessage
            retVal = parse_headers(msg->response_headers, *response);
            if (retVal > 0)
                // set statuscode to SoupMessage
                soup_message_set_status (msg, retVal);
            else
                g_warning("Failed to parse response headers");
            
            const char *clen = soup_message_headers_get_one (msg->response_headers, "content-length");
            content_len = atoi(clen);            
            
            headers_ready = 1;
            
        }
        else if (headers_ready && body != NULL && strlen(body) >= content_len)
        {   
            body[content_len] = '\0';
            // body should be ready    
            
            // Put body to SoupMessage (soup_message_set_response() should do that also, but didn't get it working 
            msg->response_body->data = strdup(body);
            msg->response_body->length = strlen(body);
            
            return 0;
        }
        else
        {
            //g_warning("RESPONSE SO FAR\n %s", *response); 
            // whole message is not received yet...
        }
        
    }
            
    return retVal;   
}
