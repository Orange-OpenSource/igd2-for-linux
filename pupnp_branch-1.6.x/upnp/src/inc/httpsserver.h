#ifndef HTTPSSERVER_H_
#define HTTPSSERVER_H_

#include <gnutls/gnutls.h>
#include "httpparser.h"

/*
typedef struct httpsServerRunParams {
    SSL *ssl;
    SSL_CTX *ctx;
    int server;
} httpsRunParams;
*/

int StartHttpsServer( unsigned short listen_port, char* CertFile, char* PrivKeyFile );
int StopHttpsServer();

#endif /*HTTPSSERVER_H_*/
