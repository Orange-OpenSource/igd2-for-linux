#ifndef SSLCLIENT_H_
#define SSLCLIENT_H_

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>


typedef struct {   
    // creadentials for ssl clients
    gnutls_certificate_credentials_t xcred;

    // ssl session
    gnutls_session_t session;

} GUPnPSSLClient;


void ssl_create_https_url(const char *http_url, int port, char **https_url);

int
ssl_init_client(  GUPnPSSLClient *client,
                  const char *directory,
                  const char *CertFile,
                  const char *PrivKeyFile,
                  const char *TrustFile,
                  const char *CRLFile,
                  const char *devName);
                 
int
ssl_finish_client( GUPnPSSLClient *client );

int
ssl_create_client_session(  GUPnPSSLClient *client,
                            const char *ActionURL_const,
                            void *SSLSessionData,
                            size_t *DataSize);
                            
int
ssl_close_client_session( GUPnPSSLClient *client );                                             


int
ssl_client_send_and_receive(  GUPnPSSLClient *client,
                            const char *message,
                            char *response);


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
int clientCertCallback(gnutls_session_t session, const gnutls_datum_t* req_ca_dn, int nreqs, gnutls_pk_algorithm_t* pk_algos, int pk_algos_length, gnutls_retr_st* st);

#endif /*SSLCLIENT_H_*/
