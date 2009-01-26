#ifndef HTTPSSERVER_H_
#define HTTPSSERVER_H_

int StartHttpsServer( unsigned short listen_port, char* CertFile, char* PrivKeyFile );
int StopHttpsServer();

#endif /*HTTPSSERVER_H_*/
