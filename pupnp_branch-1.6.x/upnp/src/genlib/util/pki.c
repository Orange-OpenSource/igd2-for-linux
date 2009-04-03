/* read-file.c -- read file contents into a string
   Copyright (C) 2006 Free Software Foundation, Inc.
   Written by Simon Josefsson and Bruno Haible.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

/************************************************************************
* Purpose: This file contains functions that operate on X.509 Public-Key 
* Infrastructure.
* Certificate and private key creation and such. 
************************************************************************/

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gcrypt.h>

#include "upnpapi.h"
#include "pki.h"

/* Make libgrypt (gnutls) thread save. This assumes that we are using pthred for threading.
 * Check http://www.gnu.org/software/gnutls/manual/gnutls.html#Multi_002dthreaded-applications
 * Also see StartHttpsServer
 */
GCRY_THREAD_OPTION_PTHREAD_IMPL;

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
void init_gcrypt()
{
     /* Make libgrypt (gnutls) thread save. This assumes that we are using pthred for threading.
     * Check http://www.gnu.org/software/gnutls/manual/gnutls.html#Multi_002dthreaded-applications
     */
    gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);    
    /* to disallow usage of the blocking /dev/random  */
    gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
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
        st->cert.x509 = &client_crt;  // these two are globals 
        st->key.x509 = client_privkey;// 
        st->deinit_all = 0;
    } 
    else {
        return -1;
    }
    
    return 0;
}

int read_pem_data_file(const char *filename, gnutls_datum_t *pem_data)
{
    size_t size = 0;
    char *data = read_binary_file(filename,&size);
    
    if (data && size > 0) {
        pem_data->data = (unsigned char *)data;
        pem_data->size = (unsigned int)size; 
    }
    else {
        return -1;
    }
    
    return 0;
}

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
char* read_binary_file(const char *filename, size_t * length)
{
    FILE *stream = fopen(filename, "rb");
    
    if (!stream) return NULL;

    char *buf = NULL;
    size_t alloc = 0;
    size_t size = 0;

    for (;;) {
        size_t count;
        size_t requested;

        if (size + BUFSIZ + 1 > alloc) {
            char *new_buf;
    
            alloc += alloc / 2;
            if (alloc < size + BUFSIZ + 1)
                alloc = size + BUFSIZ + 1;
    
            new_buf = realloc (buf, alloc);
            if (!new_buf) {
                break;
            }
    
            buf = new_buf;
        }

        requested = alloc - size - 1;
        count = fread (buf + size, 1, requested, stream);
        size += count;

        if (count != requested) {
            if (ferror (stream))
                break;
            buf[size] = '\0';
            *length = size;
            return buf;
        }
    }

  free (buf);
  return NULL;     
}


int create_new_certificate(gnutls_x509_crt_t *crt, gnutls_x509_privkey_t *key, char *file, char *CN, int modulusBits, int lifetime)
{
    unsigned char buffer[10 * 1024];
    size_t buffer_size = sizeof (buffer);
    int ret, serial;
    
    ret = gnutls_x509_privkey_generate (*key, GNUTLS_PK_RSA, modulusBits, 0);
    if (ret < 0) {
        printf("error %d %d\n",2,ret);
        // do something
    }

    // set common name
    ret = gnutls_x509_crt_set_dn_by_oid (*crt, GNUTLS_OID_X520_COMMON_NAME, 0, CN, strlen(CN));
    if (ret < 0) {
        printf("error %d %d\n",4,ret);
        // do something
    }  
        
    // set private key for cert
    ret = gnutls_x509_crt_set_key (*crt, *key);
    if (ret < 0) {
        printf("error %d %d\n",5,ret);
        // do something
        //error (EXIT_FAILURE, 0, "crt_init: %s", gnutls_strerror (ret));
    }

    ret = gnutls_x509_crt_set_activation_time (*crt, time (NULL));
    if (ret < 0) {
        printf("error %d %d\n",6,ret);
        // do something
    }
    
    ret = gnutls_x509_crt_set_expiration_time (*crt, time (NULL) + lifetime);        
    if (ret < 0) {
        printf("error %d %d\n",7,ret);
        // do something
    }
        
    //serial
    serial = time (NULL);
    buffer[4] = serial & 0xff;
    buffer[3] = (serial >> 8) & 0xff;
    buffer[2] = (serial >> 16) & 0xff;
    buffer[1] = (serial >> 24) & 0xff;
    buffer[0] = 0;    
    
    ret = gnutls_x509_crt_set_serial (*crt, buffer, 5);
    if (ret < 0) {
        printf("error %d %d\n",8,ret);
        // do something
    }
        
    // sign certificate
    ret = gnutls_x509_crt_sign2 (*crt, *crt, *key, GNUTLS_DIG_SHA1, 0);
    if (ret < 0) {
        printf("error %d %d\n",9,ret);
        // do something
    }    

    // set version
    ret = gnutls_x509_crt_set_version(*crt, 1);
    if (ret < 0) {
        printf("error %d %d\n",90,ret);
        // do something
    }    
    

    
    
    FILE *fp;

    fp = fopen(file, "w");
    if (fp == NULL) {
        printf("I couldn't open results.dat for writing.\n");
    }

    
    
    
    // export private key and certificate    
    ret = gnutls_x509_privkey_export(*key, GNUTLS_X509_FMT_PEM, buffer, &buffer_size);
    if (ret < 0) {
        printf("error %d %d\n",10,ret);
        // do something
    }
    fprintf(fp, "%s", buffer);
    printf("%s\n",buffer);
    
    ret = gnutls_x509_crt_export(*crt, GNUTLS_X509_FMT_PEM, buffer, &buffer_size);
    if (ret < 0) {
        printf("error %d %d\n",11,ret);
        // do something
    }
    fprintf(fp, "%s", buffer);
    printf("%s\n",buffer);
    
    fclose(fp);
    
    return 0;        
}

/************************************************************************
*   Function :  load_x509_self_signed_certificate
*
*   Parameters :
*       OUT gnutls_x509_crt_t *crt ;    
*       OUT gnutls_x509_privkey_t *key ;
*       IN char *file    ;
*       IN char *CN      ;
*       IN int modulusBits   ;
*       IN int lifetime     ;
*
*   Description :   Create self signed certificate. For this private key is also created.
*           If file already contains certificate, function uses that certificate.
*
*   Return : int ;
*       UPNP or gnutls error code.
*
*   Note :
************************************************************************/
int load_x509_self_signed_certificate(gnutls_x509_crt_t *crt, gnutls_x509_privkey_t *key, char *file, char *CN, int modulusBits, int lifetime)
{    
    int ret = 0;
    gnutls_datum_t pem_data;
    
    
    // init private key
    ret = gnutls_x509_privkey_init (key);
    if (ret < 0) {
        printf("error %d %d\n",1,ret);
        // do something
    }
    
    //init certificate
    ret = gnutls_x509_crt_init (crt);
    if (ret < 0) {
        printf("error %d %d\n",3,ret);
        // do something
    }
    
    
    // check if file already exists and if it contains data
    ret = read_pem_data_file(file, &pem_data);
    if (ret == 0) { 
        ret = gnutls_x509_crt_import(*crt, &pem_data, GNUTLS_X509_FMT_PEM); //TODO check if still in force, is CN same?
        if (ret < 0) {
            printf("error %d %d\n",30,ret);
            // do something
        }        
        ret = gnutls_x509_privkey_import(*key, &pem_data, GNUTLS_X509_FMT_PEM);
          if (ret < 0) {
            printf("error %d %d\n",31,ret);
            // do something
        }        
    }
    else {
        ret = create_new_certificate(crt, key, file, CN, modulusBits, lifetime);
    }
       
    return ret;   
}


