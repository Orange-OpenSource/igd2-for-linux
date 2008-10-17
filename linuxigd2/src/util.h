#ifndef _UTIL_H_
#define _UTIL_H_

#include <upnp/upnp.h>
#include <glib.h>

int get_sockfd(void);
int GetIpAddressStr(char *address, char *ifname);
int ControlPointIP_equals_InternalClientIP(char *ICAddress, struct in_addr *);
int checkForWildCard(const char *str);
void addErrorData(struct Upnp_Action_Request *ca_event, int errorCode, char* message);
void trace(int debuglevel, const char *format, ...);
int setEthernetLinkStatus(char *ethLinStatus, char *iface);

int resolveBoolean(char *);

char* GetFirstDocumentItem( IN IXML_Document * doc, const char *item );

void ParseResponse(struct Upnp_Action_Request *ca_event, GString *result);

#endif //_UTIL_H_
