#ifndef _PMLIST_H_
#define _PMLIST_H_
#include <arpa/inet.h>

#define DEST_LEN 100


typedef struct ExpirationEvent
{
    int eventId;
    char DevUDN[NAME_SIZE];
    char ServiceID[NAME_SIZE];
    struct portMap *mapping;
} expiration_event;

struct portMap
{
    int m_PortMappingEnabled;
    long int m_PortMappingLeaseDuration;
    char m_RemoteHost[INET6_ADDRSTRLEN];      // updated IPv6 addrss length 16 -> 46
    char m_ExternalPort[6];
    char m_InternalPort[6];
    char m_PortMappingProtocol[4];
    char m_InternalClient[INET6_ADDRSTRLEN];  // updated IPv6 addrss length 16 -> 46
    char m_PortMappingDescription[50];

    int expirationEventId;
    long int expirationTime;

    struct portMap* next;
    struct portMap* prev;
} *pmlist_Head, *pmlist_Tail, *pmlist_Current;

//struct portMap* pmlist_NewNode(void);
struct portMap* pmlist_NewNode(int enabled, long int duration, char *remoteHost,
                                           char *externalPort, char *internalPort,
                                           char *protocol, char *internalClient, char *desc);

struct portMap* pmlist_Find(char * remoteHost, char *externalPort, char *proto, char *internalClient);
struct portMap* pmlist_FindByIndex(int index);
struct portMap* pmlist_FindRangeAfter(int, int, char *, char *, struct portMap*);
struct portMap* pmlist_FindSpecific(char * remoteHost, char *externalPort, char *protocol);
struct portMap* pmlist_FindSpecificAfterIndex(char * remoteHost, char *externalPort, char *protocol, int index);
int pmlist_FindNextFreePort(char *protocol);
int pmlist_IsEmtpy(void);
int pmlist_Size(void);
int pmlist_FreeList(void);
int pmlist_PushBack(struct portMap* item);
int pmlist_Delete(struct portMap* item);
int pmlist_DeleteIndex(struct portMap* item, int index);
int pmlist_AddPortMapping (int enabled, char *protocol, char *remoteHost,
                           char *externalPort, char *internalClient, char *internalPort);
int pmlist_DeletePortMapping(int enabled, char *remoteHost, char *protocol,
                             char *externalPort, char *internalClient, char *internalPort);

#endif // _PMLIST_H_
