#ifndef PKI_H_
#define PKI_H_

#include <gnutls/gnutls.h>

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
*   Function :  read_binary_file
*
*   Parameters :
*       IN const char* filename ;    Name of the file to read
*       OUT size_t length       ;    Length of read data 
*
*   Description :   Read file contents and return contents as string.
*                   Size of content is returned in second function parameter.
*                   Copied and modified from gnutls read-file.c
*
*   Return : char* ;
*       Pointer to the string containing file contents.
*       NULL if failed to read file.
*
*   Note :
************************************************************************/
char* read_binary_file(const char *filename, size_t * length);


int load_x509_self_signed_certificate(gnutls_x509_crt_t *crt, gnutls_x509_privkey_t *key, char *file, char *CN, int modulusBits, int lifetime);

#endif /*PKI_H_*/
