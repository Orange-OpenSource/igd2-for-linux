#ifndef HTTPSSERVER_H_
#define HTTPSSERVER_H_

#include <openssl/ssl.h>
#include "httpparser.h"

typedef struct httpsServerRunParams {
    SSL *ssl;
    SSL_CTX *ctx;
    int server;
} httpsRunParams;

static int OpenListener(int port);
static SSL_CTX* InitServerCTX(void);
static void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
static void ShowCerts(SSL* ssl);
static void Servlet(SSL* ssl);
static void RunHttpsServer( httpsRunParams *params );
static int parseHttpMessage(char *buf, int buflen, http_parser_t *parser, http_method_t request_method, int *timeout_secs, int *http_error_code);

int StartHttpsServer( unsigned short listen_port, char* CertFile, char* PrivKeyFile );
int StopHttpsServer();

#endif /*HTTPSSERVER_H_*/
