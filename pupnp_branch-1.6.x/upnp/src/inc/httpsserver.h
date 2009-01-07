#ifndef HTTPSSERVER_H_
#define HTTPSSERVER_H_

#include <openssl/ssl.h>

int OpenListener(int port);
SSL_CTX* InitServerCTX(void);
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void ShowCerts(SSL* ssl);
void Servlet(SSL* ssl);

int StartHttpsServer( unsigned short listen_port, char* CertFile, char* PrivKeyFile );
int StopHttpsServer();

#endif /*HTTPSSERVER_H_*/
