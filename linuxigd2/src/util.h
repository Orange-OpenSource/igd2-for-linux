#ifndef _UTIL_H_
#define _UTIL_H_

int get_sockfd(void);
int GetIpAddressStr(char *address, char *ifname);
int ControlPointIP_equals_InternalClientIP(char *ICAddress);

void trace(int debuglevel, const char *format, ...);

int resolveBoolean(char *);

#endif //_UTIL_H_
