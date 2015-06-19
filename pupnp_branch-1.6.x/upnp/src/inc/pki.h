///////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2009-2011  Nokia Corporation and/or its subsidiary(-ies).
// All rights reserved. 
//
// Contact: mika.saaranen@nokia.com
// Developer(s): jaakko.pasanen@tieto.com, opensource@tieto.com
//
// Redistribution and use in source and binary forms, with or without 
// modification, are permitted provided that the following conditions are met: 
//
// * Redistributions of source code must retain the above copyright notice, 
// this list of conditions and the following disclaimer. 
// * Redistributions in binary form must reproduce the above copyright notice, 
// this list of conditions and the following disclaimer in the documentation 
// and/or other materials provided with the distribution. 
// * Neither name of Nokia Corporation nor the names of its contributors 
// may be used to endorse or promote products derived from this software 
// without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NOKIA OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY 
// OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
///////////////////////////////////////////////////////////////////////////

// File : pki.h

#ifndef PKI_H_
#define PKI_H_

#include <gnutls/gnutls.h>

/* Maximum amount of certificates in one chain/file */
#define MAX_CRT 6

/* default default directory for certificate storing */
#ifndef UPNP_X509_CERTSTORE
#define UPNP_X509_CERTSTORE      "/etc/certstore/"
#endif

/* default file for CA certificate storing */
#ifndef UPNP_X509_CA_CERT_FILE
#define UPNP_X509_CA_CERT_FILE      "pupnpX509-CA-cert.pem"
#endif

/* default file for CA private key storing */
#ifndef UPNP_X509_CA_PRIVKEY_FILE
#define UPNP_X509_CA_PRIVKEY_FILE      "pupnpX509-CA-key.pem"
#endif

/* default file for client certificate storing */
#ifndef UPNP_X509_CLIENT_CERT_FILE
#define UPNP_X509_CLIENT_CERT_FILE      "pupnpX509-client-cert.pem"
#endif

/* default file for client private key storing */
#ifndef UPNP_X509_CLIENT_PRIVKEY_FILE
#define UPNP_X509_CLIENT_PRIVKEY_FILE      "pupnpX509-client-key.pem"
#endif

/* default file for server certificate storing */
#ifndef UPNP_X509_SERVER_CERT_FILE
#define UPNP_X509_SERVER_CERT_FILE      "pupnpX509-server-cert.pem"
#endif

/* default file for server private key storing */
#ifndef UPNP_X509_SERVER_PRIVKEY_FILE
#define UPNP_X509_SERVER_PRIVKEY_FILE      "pupnpX509-server-key.pem"
#endif

/* Used X.509 certificate version */
#ifndef UPNP_X509_CERT_VERSION
#define UPNP_X509_CERT_VERSION           3
#endif

/* Common name value used for CA certificate */
#ifndef UPNP_CA_CERT_CN
#define UPNP_CA_CERT_CN           "MyLocalCA"
#endif

/* default bit size of used modulus in created certificate (key size) */
#ifndef UPNP_X509_CERT_MODULUS_SIZE
#define UPNP_X509_CERT_MODULUS_SIZE      2048
#endif

/* how many seconds created certificate should last. Lets use 100 years to make sure that
 * no need for certificate renewal exists
 */
#ifndef UPNP_X509_CERT_LIFETIME   //(100*365*24*60*60)
#define UPNP_X509_CERT_LIFETIME   3153600000UL
#endif

/* This tries to solve Year 2038 problem with "too big" unix timestamps, for which
 * gnutls seems to be vulnerable.
 * http://en.wikipedia.org/wiki/Year_2038_problem 
 * 
 * Remove this definition and UPNP_X509_CERT_LIFETIME value will be used for
 * expiration time calculation.
 */
#ifndef UPNP_X509_CERT_ULTIMATE_EXPIRE_DATE   //Thu Dec 31 23:59:59 UTC 2037
#define UPNP_X509_CERT_ULTIMATE_EXPIRE_DATE   2145916799
#endif 

/************************************************************************
*   Function :  init_crypto_libraries
*
*   Description :   Initialize libgcrypt for gnutls. Not sure should this rather 
*        be done in final program using this UPnP library?
*        Makes gcrypt thread save, and disables usage of blocking /dev/random.
*        Initialize also gnutls.
*
*   Return : int ;
*       0 on succes, gnutls error else
*
*   Note : assumes that libupnp uses pthreads.
************************************************************************/
int init_crypto_libraries(); 

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
*   Function :  init_x509_certificate_credentials
*
*   Parameters :
*       OUT gnutls_certificate_credentials_t *x509_cred     ;  Pointer to gnutls_certificate_credentials_t where certificate credentials are inserted
*       IN const char *directory       ;  Path to directory where files locate or where files are created
*       IN const char *CertFile        ;  Selfsigned certificate file of client
*       IN const char *PrivKeyFile     ;  Private key file of client.
*       IN const char *TrustFile       ;  File containing trusted certificates. (PEM format)
*       IN const char *CRLFile         ;  Certificate revocation list. Untrusted certificates. (PEM format)
*
*   Description :   Init gnutls_certificate_credentials_t structure for use with 
*       input from given parameter files. All files may be NULL
*
*   Return : int ;
*       UPNP or gnutls error code.
*
*   Note :
************************************************************************/
int init_x509_certificate_credentials(gnutls_certificate_credentials_t *x509_cred, const char *directory, const char *CertFile, const char *PrivKeyFile, const char *TrustFile, const char *CRLFile);


/************************************************************************
*   Function :  load_x509_self_signed_certificate
*
*   Parameters :
*       OUT gnutls_x509_crt_t *crt     ;  Pointer to gnutls_x509_crt_t where certificate is created
*       OUT gnutls_x509_privkey_t *key ;  Pointer to gnutls_x509_privkey_t where private key is created
*       IN const char *directory       ;  Path to directory where files locate or where files are created
*       IN const char *certfile        ;  Name of file where certificate is exported in PEM format
*       IN const char *privkeyfile     ;  Name of file where private key is exported in PEM format
*       IN char *CN                    ;  Common Name velue in certificate
*       IN int modulusBits             ;  Size of modulus in certificate
*       IN unsigned long lifetime      ;  How many seconds until certificate will expire. Counted from now.
*       IN int is_client               ;  Is created certificate client certificate. Affects to purpose of certificate.
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
int load_x509_self_signed_certificate(gnutls_x509_crt_t *crt, unsigned int *crt_size, gnutls_x509_privkey_t *key, const char *directory, const char *certfile, const char *privkeyfile, const char *CN, const int modulusBits, const unsigned long lifetime, int is_client);


/************************************************************************
*   Function :  validate_x509_certificate
*
*   Parameters :
*       IN const gnutls_x509_crt_t *crt  ;  Pointer to certificate which is validated
*       IN const char *hostname          ;  Hostname to compare with certificates subject
*       IN const char *commonname        ;  CN value which is compared with subject CN value of certificate 
* 
*   Description :   Check that given certificate is activated (not before > now), certificate 
*       has not expired (not after < now). If hostname or commonname are defined check that
*       those values match values found from certificate. Hostname check is "a basic implementation 
*       of the matching described in RFC2818 (HTTPS), which takes into account wildcards, and the 
*       DNSName/IPAddress subject alternative name PKIX extension." (gnutls)
*       Commonname check just checks if commonname value equals CN found from certificates subject.
*
*   Return : int ;
*       UPNP or gnutls error code.
*
*   Note :
************************************************************************/
int validate_x509_certificate(const gnutls_x509_crt_t *crt, const char *hostname, const char *commonname);


/************************************************************************
*   Function :  get_peer_certificate
*
*   Parameters :
*       IN gnutls_session_t session  ;  SSL session
*       OUT unsigned char *data      ;  Certificate is returned in DER format here
*       OUT int *data_size           ;  Pointer to integer which represents length of certificate 
*       OUT char **CN                ;  Pointer to string where Common Name value from peer certificate is put. If NULL this is ignored. 
* 
*   Description :   Export peer certificate to given parameter. When calling this
*       data must have enough memory allocated and data_size must contain info
*       how much data has space.
*
*   Return : int ;
*       UPNP or gnutls error code.
*
*   Note :
************************************************************************/
int get_peer_certificate(gnutls_session_t session, unsigned char *data, int *data_size, char **CN);

#endif /*PKI_H_*/
