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

#include <sys/stat.h>

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


// Local Certificate Authority certificate its and private key
static gnutls_x509_crt_t ca_crt = NULL;
static gnutls_x509_privkey_t ca_privkey = NULL;

/************************************************************************
*   Function :  initialize_gcrypt
*
*   Description :   Initialize libgcrypt for gnutls.
*
*   Return : int ;
*       0 on succes, -1 on error
*
*   Note : assumes that libupnp uses pthreads.
************************************************************************/
static int initialize_gcrypt()
{
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
    {
        fputs ("libgcrypt has not been initialized. pupnp tries to initialize it.\n", stderr);

        /* Version check should be the very first call because it
          makes sure that important subsystems are intialized. */
        if (!gcry_check_version (GCRYPT_VERSION))
        {
            return -1;
        }

        /* Make libgrypt (gnutls) thread save. This assumes that we are using pthred for threading.
           Check http://www.gnu.org/software/gnutls/manual/gnutls.html#Multi_002dthreaded-applications */
        gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

        /* to disallow usage of the blocking /dev/random  */
        gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

        /* Disable secure memory.  */
        gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

        /* Tell Libgcrypt that initialization has completed. */
        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    }
    return 0;
}

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
int init_crypto_libraries()
{
    int ret;

    ret = initialize_gcrypt();
    if ( ret != 0 ) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "Failed to initialize libgcrypt \n\n");
        return ret;
    }

    /* this must be called once in the program */
    ret = gnutls_global_init ();
    if ( ret != GNUTLS_E_SUCCESS ) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "Failed to initialize gnutls. (%s) \n\n", gnutls_strerror(ret) );
        return ret;
    }

    return 0;
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
        st->ncerts = client_crt_size;
        st->cert.x509 = client_crt;  // these two are globals defined in upnpapi
        st->key.x509 = client_privkey;//
        st->deinit_all = 0;
    }
    else {
        return -1;
    }

    return 0;
}


/************************************************************************
*   Function :  read_binary_file
*g_warning(
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
static char* read_binary_file(const char *filename, size_t * length)
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
            fclose(stream);
            return buf;
        }
    }

  fclose(stream);
  free (buf);
  return NULL;
}


/************************************************************************
*   Function :  read_pem_data_file
*
*   Parameters :
*       IN const char* filename ;    Name of the file to read
*       OUT gnutls_datum_t *pem_data  ;    Pointer to struct where read data is inserted 
*
*   Description :   Read file contents and return contents in gnutls_datum_t
*       struct.
*
*   Return : int ;
*       0 if all well, -1 if failure.
*
*   Note :
************************************************************************/
static int read_pem_data_file(const char *filename, gnutls_datum_t *pem_data)
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
*   Function :  export_certificate_to_file
*
*   Parameters :
*       IN const gnutls_x509_crt_t *crt     ;  Pointer to gnutls_x509_crt_t where certificate is created
*       IN const gnutls_x509_privkey_t *key ;  Pointer to gnutls_x509_privkey_t where private key is created
*       IN const char *certfile        ;  Name of file where certificate is exported in PEM format
*       IN const char *privkeyfile     ;  Name of file where private key is exported in PEM format
        IN const int append_CA    ;  Is CA certificate appended to the end of the certificate file
*
*   Description :   Export certificate and private key into file(s). Filenames may be same.
*
*   Return : int ;
*       UPNP or gnutls error code.
*
*   Note :
************************************************************************/
static int export_certificate_to_file(const gnutls_x509_crt_t *crt, const gnutls_x509_privkey_t *key, const char *certfile, const char *privkeyfile, int append_CA)
{
    unsigned char buffer[10 * 1024];
    size_t buffer_size = sizeof (buffer);
    size_t orig_size = buffer_size;
    FILE *fp;
    int ret;

    // certificate and privatekey files must be different files
    if (strcmp(certfile, privkeyfile) == 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "Error: Certificate and privatekey cannot be saved in the same file!\n");
        return -1;
    }

    fp = fopen(privkeyfile, "w");
    if (fp == NULL) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "Failed to open file %s \n", privkeyfile );
        return UPNP_E_FILE_NOT_FOUND;
    }

    // export private key and certificate
    ret = gnutls_x509_privkey_export(*key, GNUTLS_X509_FMT_PEM, buffer, &buffer_size);
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "gnutls_x509_privkey_export failed. %s \n", gnutls_strerror(ret) );
        fclose(fp);
        return ret;
    }
    fprintf(fp, "%s", buffer);
    fclose(fp);

    // export cert(s)
    fp = fopen(certfile, "w");
    if (fp == NULL) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
             "Error: Failed to open file %s \n", privkeyfile );
        return UPNP_E_FILE_NOT_FOUND;
    }

    ret = gnutls_x509_crt_export(*crt, GNUTLS_X509_FMT_PEM, buffer, &buffer_size);
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
             "Error: gnutls_x509_crt_export failed. %s\n", gnutls_strerror(ret) );
        return ret;
    }
    fprintf(fp, "%s", buffer);

    // Is CA certificate appended?
    if (append_CA)
    {
        *buffer = '\0';
        buffer_size = orig_size;
        ret = gnutls_x509_crt_export(ca_crt, GNUTLS_X509_FMT_PEM, buffer, &buffer_size);
        if (ret < 0) {
            UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "Error: gnutls_x509_crt_export failed. %s\n", gnutls_strerror(ret) );
            return ret;
        }
        fprintf(fp, "%s", buffer);
    }
    fclose(fp);

    return 0;
}

/************************************************************************
*   Function :  create_certificate
*
*   Parameters :
*       OUT gnutls_x509_crt_t *crt     ;  Pointer to gnutls_x509_crt_t where certificate is created
*       OUT gnutls_x509_privkey_t *key ;  Pointer to gnutls_x509_privkey_t where private key is created
*       IN char *CN                    ;  Common Name velue in certificate
*       IN int modulusBits             ;  Size of modulus in certificate
*       IN unsigned long lifetime      ;  How many seconds until certificate will expire. Counted from now.
*
*   Description :   Creates the certificate and private key
*
*   Return : int ;
*       UPNP or gnutls error code.
*
*   Note :
************************************************************************/
static int create_certificate(gnutls_x509_crt_t *crt, gnutls_x509_privkey_t *key, const char *CN, const int modulusBits, const unsigned long lifetime, const void *purpose, unsigned int key_usage, unsigned int is_ca)
{
    unsigned char buffer[10 * 1024];
    int ret, serial;

    // create private key
    ret = gnutls_x509_privkey_generate (*key, GNUTLS_PK_RSA, modulusBits, 0);
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
             "Error: gnutls_x509_privkey_generate failed. %s", gnutls_strerror(ret) );
        return ret;
    }

    // set common name
    ret = gnutls_x509_crt_set_dn_by_oid (*crt, GNUTLS_OID_X520_COMMON_NAME, 0, CN, strlen(CN));
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
             "Error: gnutls_x509_crt_set_dn_by_oid failed. %s", gnutls_strerror(ret) );
        return ret;
    }

    // set private key for cert
    ret = gnutls_x509_crt_set_key (*crt, *key);
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
             "Error: gnutls_x509_crt_set_key failed. %s", gnutls_strerror(ret) );
        return ret;
    }

    ret = gnutls_x509_crt_set_activation_time (*crt, time (NULL));
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
             "Error: gnutls_x509_crt_set_activation_time. %s", gnutls_strerror(ret) );
        return ret;
    }

// this tries to solve Year 2038 problem with "too big" unix timestamps http://en.wikipedia.org/wiki/Year_2038_problem
#ifdef UPNP_X509_CERT_ULTIMATE_EXPIRE_DATE
    ret = gnutls_x509_crt_set_expiration_time (*crt, UPNP_X509_CERT_ULTIMATE_EXPIRE_DATE);
#else
    ret = gnutls_x509_crt_set_expiration_time (*crt, time (NULL) + lifetime);
#endif
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
             "Error: gnutls_x509_crt_set_expiration_time failed. %s", gnutls_strerror(ret) );
        return ret;
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
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
             "Error: gnutls_x509_crt_set_serial failed. %s", gnutls_strerror(ret) );
        return ret;
    }

    if (purpose)
    {
        ret = gnutls_x509_crt_set_key_purpose_oid (*crt, purpose, 0);
        if (ret < 0) {
            UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "Error: gnutls_x509_crt_set_key_purpose_oid failed. %s", gnutls_strerror(ret) );
            return ret;
        }
    }

    ret = gnutls_x509_crt_set_key_usage (*crt, key_usage);
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
             "Error: gnutls_x509_crt_set_key_usage failed. %s", gnutls_strerror(ret) );
        return ret;
    }

    if (is_ca)
    {
        // if ceritficate is used as CA
        ret = gnutls_x509_crt_set_ca_status (*crt, is_ca);
        if (ret < 0) {
            UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "Error: gnutls_x509_crt_set_ca_status failed. %s", gnutls_strerror(ret) );
            return ret;
        }
    }

    // set version
    ret = gnutls_x509_crt_set_version(*crt, UPNP_X509_CERT_VERSION);
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
             "Error: gnutls_x509_crt_set_version failed. %s", gnutls_strerror(ret) );
        return ret;
    }

    return 0;
}

/************************************************************************
*   Function :  create_new_certificate
*
*   Parameters :
*       OUT gnutls_x509_crt_t *crt     ;  Pointer to gnutls_x509_crt_t where certificate is created
*       OUT gnutls_x509_privkey_t *key ;  Pointer to gnutls_x509_privkey_t where private key is created
*       IN const char directory        ;  Directory where files locate. If directory doesn't exist, tries to create. Must contain trailing '/'
*       IN const char *certfile        ;  Full path to file where certificate is exported in PEM format
*       IN const char *privkeyfile     ;  Full path to file where private key is exported in PEM format
*       IN char *CN                    ;  Common Name velue in certificate
*       IN int modulusBits             ;  Size of modulus in certificate
*       IN unsigned long lifetime      ;  How many seconds until certificate will expire. Counted from now.
*
*   Description :   Create new self signed certificate. Creates also new private key.
*           Some inspiration for this code is took from gnutls certtool.
*
*   Return : int ;
*       UPNP or gnutls error code.
*
*   Note :
************************************************************************/
static int create_new_certificate(gnutls_x509_crt_t *crt, gnutls_x509_privkey_t *key, const char *directory, const char *certfile, const char *privkeyfile, const char *CN, const int modulusBits, const unsigned long lifetime)
{
    int ret;

    // create dir if doesn't exist yet
    ret = mkdir(directory, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    if (ret != 0 && errno != EEXIST) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "Failed to create certificate directory %s \n", directory );
        return UPNP_E_FILE_NOT_FOUND;
    }

    // first we create CA certificate and key if those doesn't exist yet
    if (ca_crt == NULL || ca_privkey == NULL)
    {
        int dirlen = strlen(directory);

        // add trailing '/' if directory doesn't have it yet
        char tmpDir[dirlen+1];
        strcpy(tmpDir,directory);
        if (directory[dirlen-1] != '/')
        {
            strcat(tmpDir, "/");
            dirlen = strlen(tmpDir);
        }

        char tmp_certfile[dirlen+strlen(UPNP_X509_CA_CERT_FILE)];
        char tmp_privkeyfile[dirlen+strlen(UPNP_X509_CA_PRIVKEY_FILE)];

        strcpy(tmp_certfile, tmpDir);
        strcat(tmp_certfile,UPNP_X509_CA_CERT_FILE);

        strcpy(tmp_privkeyfile, tmpDir);
        strcat(tmp_privkeyfile,UPNP_X509_CA_PRIVKEY_FILE);

        // init private key
        ret = gnutls_x509_privkey_init (&ca_privkey);
        if (ret < 0) {
            UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "Error: gnutls_x509_privkey_init failed. %s", gnutls_strerror(ret) );
            return ret;
        }

        //init certificate
        ret = gnutls_x509_crt_init (&ca_crt);
        if (ret < 0) {
            UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "Error: gnutls_x509_crt_init failed. %s", gnutls_strerror(ret) );
            return ret;
        }
        int createNewCA = 1;
        gnutls_datum_t pem_data = {NULL, 0};
        //  import CA private key from file
        ret = read_pem_data_file(tmp_privkeyfile, &pem_data);
        if (ret == 0) {
            ret = gnutls_x509_privkey_import(ca_privkey, &pem_data, GNUTLS_X509_FMT_PEM);
            if (ret == GNUTLS_E_SUCCESS ) {
                // import CA certificate from file
                ret = read_pem_data_file(tmp_certfile, &pem_data);
                if (ret == 0) {
                    ret = gnutls_x509_crt_import(ca_crt, &pem_data, GNUTLS_X509_FMT_PEM);
                    if (ret == GNUTLS_E_SUCCESS) {
                        createNewCA = 0; // no need to create new CA certificate and key
                    }
                }
            }
        }

        if (createNewCA)
        {
            // create ca certificate
            ret = create_certificate(&ca_crt, &ca_privkey, UPNP_CA_CERT_CN, modulusBits, lifetime, NULL, GNUTLS_KEY_KEY_CERT_SIGN, 1);
            if (ret < 0) {
                UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                    "Error: CA cert, Failed to create certificate. %s", gnutls_strerror(ret) );
                return ret;
            }

            // self sign certificate
            ret = gnutls_x509_crt_sign2 (ca_crt, ca_crt, ca_privkey, GNUTLS_DIG_SHA1, 0);
            if (ret < 0) {
                UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                    "Error: CA cert, gnutls_x509_crt_sign2 failed. %s", gnutls_strerror(ret) );
                return ret;
            }

            ret = export_certificate_to_file(&ca_crt, &ca_privkey, tmp_certfile, tmp_privkeyfile, 0);
        }
    }

    // create the client certificate
    ret = create_certificate(crt, key, CN, modulusBits, lifetime, GNUTLS_KP_TLS_WWW_CLIENT, GNUTLS_KEY_DIGITAL_SIGNATURE, 0);
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "Error: Failed to create certificate. %s", gnutls_strerror(ret) );
        return ret;
    }

    // sign certificate
    ret = gnutls_x509_crt_sign2 (*crt, ca_crt, ca_privkey, GNUTLS_DIG_SHA256, 0);
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "Error: gnutls_x509_crt_sign2 failed. %s", gnutls_strerror(ret) );
        return ret;
    }

    ret = export_certificate_to_file(crt, key, certfile, privkeyfile, 1);

    return ret;
}


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
int init_x509_certificate_credentials(gnutls_certificate_credentials_t *x509_cred, const char *directory, const char *CertFile, const char *PrivKeyFile, const char *TrustFile, const char *CRLFile)
{
    int ret;
    int dirlen = strlen(directory);

    // add trailing '/' if directory doesn't have it yet
    char tmpDir[dirlen+1];
    strcpy(tmpDir,directory);
    if (directory[dirlen-1] != '/')
    {
        strcat(tmpDir, "/");
        dirlen = strlen(tmpDir);
    }

    ret = gnutls_certificate_allocate_credentials (x509_cred);
    if ( ret != GNUTLS_E_SUCCESS ) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "StartHttpsServer: gnutls_certificate_allocate_credentials failed. (%s) \n\n", gnutls_strerror(ret) );
        return ret;
    }

    if (TrustFile) {
        char tmp_trustfile[dirlen+strlen(TrustFile)];
        strcpy(tmp_trustfile, tmpDir);
        strcat(tmp_trustfile,TrustFile);

        ret = gnutls_certificate_set_x509_trust_file (*x509_cred, tmp_trustfile, GNUTLS_X509_FMT_PEM); // white list
        if (ret < 0) {
            UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "StartHttpsServer: gnutls_certificate_set_x509_trust_file failed (%s)\n\n", gnutls_strerror (ret));
            return ret;
        }
    }

    if (CRLFile) {
        char tmp_crlfile[dirlen+strlen(CRLFile)];
        strcpy(tmp_crlfile, tmpDir);
        strcat(tmp_crlfile,CRLFile);

        ret = gnutls_certificate_set_x509_crl_file (*x509_cred, tmp_crlfile, GNUTLS_X509_FMT_PEM); // black list
        if (ret < 0) {
            UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "StartHttpsServer: gnutls_certificate_set_x509_crl_file failed. (%s)\n\n", gnutls_strerror (ret));
            return ret;
        }
    }

    if (CertFile && PrivKeyFile) {
        char tmp_certfile[dirlen+strlen(CertFile)];
        char tmp_privkeyfile[dirlen+strlen(PrivKeyFile)];

        strcpy(tmp_certfile, tmpDir);
        strcat(tmp_certfile,CertFile);

        strcpy(tmp_privkeyfile, tmpDir);
        strcat(tmp_privkeyfile,PrivKeyFile);

        ret = gnutls_certificate_set_x509_key_file (*x509_cred, tmp_certfile, tmp_privkeyfile, GNUTLS_X509_FMT_PEM);
        if (ret != GNUTLS_E_SUCCESS) {
            UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "StartHttpsServer: gnutls_certificate_set_x509_key_file failed. (%s)\n\n", gnutls_strerror (ret));
            return ret;
        }
    }

    return 0;
}



/************************************************************************
*   Function :  load_x509_self_signed_certificate
*
*   Parameters :
*       OUT gnutls_x509_crt_t *crt     ;  Pointer to gnutls_x509_crt_t table where certificate(s) is created
        INOUT unsigned int *crt_size   ;  IN: how many certificates crt can have at maximum. OUT: How many certificates crt has.
*       OUT gnutls_x509_privkey_t *key ;  Pointer to gnutls_x509_privkey_t where private key is created
*       IN const char *directory       ;  Path to directory where files locate or where files are created.
*       IN const char *certfile        ;  Name of file where certificate is exported in PEM format
*       IN const char *privkeyfile     ;  Name of file where private key is exported in PEM format
*       IN char *CN                    ;  Common Name velue in certificate
*       IN int modulusBits             ;  Size of modulus in certificate
*       IN unsigned long lifetime      ;  How many seconds until certificate will expire. Counted from now.
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
int load_x509_self_signed_certificate(gnutls_x509_crt_t *crt, unsigned int *crt_size, gnutls_x509_privkey_t *key, const char *directory, const char *certfile, const char *privkeyfile, const char *CN, const int modulusBits, const unsigned long lifetime)
{
    int cert_ok = 0;
    int ret = 0;
    gnutls_datum_t pem_data = {NULL, 0};
    int dirlen = strlen(directory);

    // add trailing '/' if directory doesn't have it yet
    char tmpDir[dirlen+1];
    strcpy(tmpDir,directory);
    if (directory[dirlen-1] != '/')
    {
        strcat(tmpDir, "/");
        dirlen = strlen(tmpDir);
    }

    char tmp_certfile[dirlen+strlen(certfile)];
    char tmp_privkeyfile[dirlen+strlen(privkeyfile)];

    strcpy(tmp_certfile, tmpDir);
    strcat(tmp_certfile,certfile);

    strcpy(tmp_privkeyfile, tmpDir);
    strcat(tmp_privkeyfile,privkeyfile);

    // create temporary certificate.
    gnutls_x509_crt_t tmp_crt;
    //init certificate
    ret = gnutls_x509_crt_init (&tmp_crt);
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "Error: gnutls_x509_crt_init failed. %s", gnutls_strerror(ret) );
        return ret;
    }

    // init private key
    ret = gnutls_x509_privkey_init (key);
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "gnutls_x509_privkey_init failed. %s \n", gnutls_strerror(ret) );
        return ret;
    }

    // import private key from file
    ret = read_pem_data_file(tmp_privkeyfile, &pem_data);
    if (ret == 0) {
        ret = gnutls_x509_privkey_import(*key, &pem_data, GNUTLS_X509_FMT_PEM);
        if (ret < 0) {
            UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "gnutls_x509_privkey_import failed. %s \n", gnutls_strerror(ret) );
            if (pem_data.data) free(pem_data.data); //release privkey, it's not needed anymore
            return ret;
        }

        // import certificate from file
        ret = read_pem_data_file(tmp_certfile, &pem_data);
        if (ret == 0) {
            //ret = gnutls_x509_crt_import(*crt, &pem_data, GNUTLS_X509_FMT_PEM);
            gnutls_x509_crt_list_import (crt, crt_size, &pem_data,
                     GNUTLS_X509_FMT_PEM,
                     GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);
            if (ret < 0) {
                UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                    "Error: gnutls_x509_crt_list_import failed. %s", gnutls_strerror(ret) );
                if (pem_data.data) free(pem_data.data);
                return ret;
            }
            /* this validation was done when there was only one certificate not whole chain. 
            Now we should check validity of the certificate chain?
            ret = validate_x509_certificate(crt, NULL, CN);
            if (ret < 0) {
                UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                    "Error: X.509 certificate validation failed. %s", gnutls_strerror(ret) );
                if (pem_data.data) free(pem_data.data); 
                return ret;
            }
            */
            cert_ok = 1;
        }
        else {
            ret = create_new_certificate(&tmp_crt, key, tmpDir, tmp_certfile, tmp_privkeyfile, CN, modulusBits, lifetime);
        }
    }
    else {
        ret = create_new_certificate(&tmp_crt, key, tmpDir, tmp_certfile, tmp_privkeyfile, CN, modulusBits, lifetime);
    }

    if (!cert_ok)
    {
        // do the importing again so that we get the whole chain from the file
        // TODO improve this so that we dont need this import here
        ret = read_pem_data_file(tmp_certfile, &pem_data);
        if (ret == 0) {
            //ret = gnutls_x509_crt_import(*crt, &pem_data, GNUTLS_X509_FMT_PEM);
            gnutls_x509_crt_list_import (crt, crt_size, &pem_data,
                    GNUTLS_X509_FMT_PEM,
                    GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);
            if (ret < 0) {
                UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                    "Error: gnutls_x509_crt_list_import failed. %s", gnutls_strerror(ret) );
                if (pem_data.data) free(pem_data.data);
                return ret;
            }
        }
    }

    gnutls_x509_crt_deinit(tmp_crt);
    if (pem_data.data) free(pem_data.data);
    return ret;
}


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
int validate_x509_certificate(const gnutls_x509_crt_t *crt, const char *hostname, const char *commonname)
{
    int ret = 0;
    size_t buf_size = 20;
    char buf[buf_size];

    if (gnutls_x509_crt_get_expiration_time (*crt) < time (NULL)) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "Certificate has expired\n");
        return GNUTLS_E_X509_CERTIFICATE_ERROR;
    }

    if (gnutls_x509_crt_get_activation_time (*crt) > time (NULL))  {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "Certificate is not yet activated\n");
        return GNUTLS_E_X509_CERTIFICATE_ERROR;
    }

    if (hostname && (strlen(hostname) > 0)) {
        if (!gnutls_x509_crt_check_hostname (*crt, hostname)) {
            UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "Certificate's owner does not match hostname '%s'\n",hostname);
            return GNUTLS_E_X509_CERTIFICATE_ERROR;
        }
    }

    if (commonname) {
        ret = gnutls_x509_crt_get_dn_by_oid (*crt, GNUTLS_OID_X520_COMMON_NAME, 0, 0, buf, &buf_size);
        if (ret != 0) {
            UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "Failed to get certificates Common Name value\n"); 
            return ret;
        }

        if (strcmp(buf, commonname) != 0) {
            UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "Certificate's Common Name '%s' isn't what expected '%s'\n",buf,commonname);
            return GNUTLS_E_X509_CERTIFICATE_ERROR;
        }
    }

    return ret;
}


/************************************************************************
*   Function :  get_peer_certificate
*
*   Parameters :
*       IN gnutls_session_t session  ;  SSL session
*       OUT unsigned char *data      ;  Certificate is returned in DER format here
*       INOUT int *data_size         ;  Pointer to integer which represents length of certificate
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
int get_peer_certificate(gnutls_session_t session, unsigned char *data, int *data_size, char **CN)
{
    const gnutls_datum_t *cert_list;
    unsigned int cert_list_size;
    int ret;
    gnutls_x509_crt_t cert;

    if ((ret = gnutls_certificate_type_get (session)) != GNUTLS_CRT_X509)
    {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "Peer certificate type must be X.509. Wrong type received.\n");
        return GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
    }

    // get certificate list. First in list is peers
    cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
    if (cert_list == NULL || cert_list_size < 1)
    {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "Could not get peers certificate\n");
        return GNUTLS_E_X509_CERTIFICATE_ERROR;
    }

    //init certificate
    ret = gnutls_x509_crt_init (&cert);
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "gnutls_x509_crt_init failed. %s \n", gnutls_strerror(ret) );
        return ret;
    }

    // first in the list is peers certificate
    ret = gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER);
    if (ret < 0)
    {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "gnutls_x509_crt_import failed. %s \n", gnutls_strerror(ret) );
        gnutls_x509_crt_deinit (cert);
        return ret;
    }

    // export certificate to data
    ret = gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, data, (size_t *)data_size);
    if (ret < 0) {
        UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
            "gnutls_x509_crt_export failed. %s \n", gnutls_strerror(ret) );
        gnutls_x509_crt_deinit (cert);
        return ret;
    }

    // get Common name value from certificate
    if (CN != NULL)
    {
        int CN_size = 50;
        *CN = (char *)malloc(CN_size);
        ret = gnutls_x509_crt_get_dn_by_oid (cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, *CN, (size_t *)&CN_size);
        if (ret != 0) {
            UpnpPrintf( UPNP_CRITICAL, X509, __FILE__, __LINE__,
                "Failed to get certificates Common Name value\n");
            gnutls_x509_crt_deinit (cert);
            return ret;
        }
    }

    gnutls_x509_crt_deinit (cert);

    return 0;
}
