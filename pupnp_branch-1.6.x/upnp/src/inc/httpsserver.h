#ifndef HTTPSSERVER_H_
#define HTTPSSERVER_H_

int StartHttpsServer(unsigned short listen_port, const char *directory, const char *CertFile, const char *PrivKeyFile,const char *TrustFile, const char *CRLFile, const char *cn);
int StopHttpsServer();
int export_server_cert (unsigned char *data, int *data_size);

#endif /*HTTPSSERVER_H_*/
