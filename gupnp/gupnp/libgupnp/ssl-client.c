#include <sys/stat.h>
#include <netinet/in.h>
#include <libsoup/soup.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>



#include "pki.h"
#include "ssl-client.h"


// these are now global variables, because this is the only way I can imagine 
// that clientCertCallback function can access these
gnutls_x509_crt_t client_crt = NULL;
gnutls_x509_privkey_t client_privkey = NULL;


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


int
ssl_client_send_and_receive(  GUPnPSSLClient *client,
                                        const char *message,
                                        char *response)
{
    char *tmp;
    int retVal = 0;
    int len = 1000;
    char recv[len+1];

    response = malloc(len*sizeof( char* ));
    memset(response,len,'\0');

    if (client->session == NULL)
        return GUPNP_E_SESSION_FAIL;
   
    retVal = gnutls_record_send(client->session, message, strlen(message));
     
    if (retVal < 0)
    {
        g_warning("Error: gnutls_record_send failed. %s", gnutls_strerror(retVal));
        return retVal;  
    }
    while (retVal > 0)
    {
        retVal = gnutls_record_recv (client->session, recv, len);
               
        if (retVal < 0)
        {
            g_warning("Error: gnutls_record_recv failed. %s", gnutls_strerror(retVal));
            return retVal;
        }
     
        g_warning("RECEIVED: %s",recv);
         
        strcat(response, recv);    
        // receive data until empty line containing only \r\n\r\n is received. That means that headers are done
        // This "parser" doesn't support chunked encoding...    
        if ((tmp = strstr(response, "\r\n\r\n")) != NULL)
        {
            // lisätään SoupMessageen header arvot, jotka on erotettu toisistaan \r\n
            // Nyt saadaan content-length soup_message_headers_get_one ()
            // Sitten luetaan kunnes on tullut täyteen c-l:n mukaiset tavut. Entä Chunked? Not my problem... 
            //soup_message_headers_append () 
            
            g_warning("END FOUND: ");//'%s'",tmp);
            //return 0;
        }
        else
        {   
  
        }
    }
        
    return retVal;   
}
                            

                            
                            