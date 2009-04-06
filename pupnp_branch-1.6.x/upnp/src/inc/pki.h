#ifndef PKI_H_
#define PKI_H_

#include <gnutls/gnutls.h>

/* default file for certificate and private key storing */
#ifndef UPNP_X509_CLIENT_CERT_FILE
#define UPNP_X509_CLIENT_CERT_FILE      "libupnpX509.pem"
#endif

/* default bit size of used modulus in created certificate */
#ifndef UPNP_X509_CERT_MODULUS_SIZE
#define UPNP_X509_CERT_MODULUS_SIZE      1024
#endif

/* how many seconds created certificate should last */
#ifndef UPNP_X509_CERT_LIFETIME
#define UPNP_X509_CERT_LIFETIME      7*24*60*60
#endif

/************************************************************************
*   Function :  init_gcrypt
*
*   Description :   Initialize libgcrypt for gnutls. Not sure should this rather 
*        be done in final program using this UPnP library?
*        Makes gcrypt thread save, and disables usage of blocking /dev/random.
*
*   Return : void
*
*   Note : assumes that libupnp uses pthreads.
************************************************************************/
void init_gcrypt(); 

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

/************************************************************************
*   Function :  load_x509_self_signed_certificate
*
*   Parameters :
*       OUT gnutls_x509_crt_t *crt     ;  Pointer to gnutls_x509_crt_t where certificate is created
*       OUT gnutls_x509_privkey_t *key ;  Pointer to gnutls_x509_privkey_t where private key is created
*       IN const char *certfile        ;  Name of file where certificate is exported in PEM format
*       IN const char *privkeyfile     ;  Name of file where private key is exported in PEM format
*       IN char *CN                    ;  Common Name velue in certificate
*       IN int modulusBits             ;  Size of modulus in certificate
*       IN int lifetime                ;  How many seconds until certificate will expire. Counted from now.
* 
*   Description :   Create self signed certificate. For this private key is also created.
*           If certfile already contains certificate and privkeyfile contains privatekey,
*           function uses that certificate. If only other is defined, then both will be created.
*
*   Return : int ;
*       UPNP or gnutls error code.
*
*   Note :
************************************************************************/
int load_x509_self_signed_certificate(gnutls_x509_crt_t *crt, gnutls_x509_privkey_t *key, const char *certfile, const char *privkeyfile, const char *CN, const int modulusBits, const int lifetime);

#endif /*PKI_H_*/
