#ifndef HTTPSSERVER_H_
#define HTTPSSERVER_H_

int StartHttpsServer(unsigned short listen_port, const char *CertFile, const char *PrivKeyFile,const char *TrustFile, const char *CRLFile);
int StopHttpsServer();

#endif /*HTTPSSERVER_H_*/
