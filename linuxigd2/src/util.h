#ifndef _UTIL_H_
#define _UTIL_H_

#include <upnp/upnp.h>

int get_sockfd(void);
char *toUpperCase(const char * str);
int GetIpAddressStr(char *address, char *ifname);
int GetMACAddressStr(unsigned char *address, int addressSize, char *ifname);
int GetConnectionStatus(char *conStatus, char *ifname);
int ControlPointIP_equals_InternalClientIP(char *ICAddress, struct in_addr *);
int checkForWildCard(const char *str);
void addErrorData(struct Upnp_Action_Request *ca_event, int errorCode, char* message);
void trace(int debuglevel, const char *format, ...);
int setEthernetLinkStatus(char *ethLinStatus, char *iface);
int resolveBoolean(char *);
int releaseIP(char *iface);
int killDHCPClient(char *iface);
int startDHCPClient(char *iface);
int readIntFromFile(char *file);

char* GetFirstDocumentItem( IN IXML_Document * doc, const char *item );
char* GetDocumentItem(IXML_Document * doc, const char *item, int index);

void ParseXMLResponse(struct Upnp_Action_Request *ca_event, const char *result);

// access level handling and parsing stuff
int initActionAccessLevels(const char *pathToFile);
void deinitActionAccessLevels();
char* getAccessLevel(const char *actionName, int manage);

#endif //_UTIL_H_
