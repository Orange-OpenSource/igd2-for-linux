#ifndef _GATEDEVICE_H_
#define _GATEDEVICE_H_ 1

#include <upnp/upnp.h>

/* interface statistics */
typedef enum
{
    STATS_TX_BYTES,
    STATS_RX_BYTES,
    STATS_TX_PACKETS,
    STATS_RX_PACKETS,
    STATS_LIMIT
} stats_t;

#define IP_ADDRESS_LENGTH 20

// IGD Device Globals
UpnpDevice_Handle deviceHandle;
char *gateUDN;
char *wanUDN;
char *wanConnectionUDN;
long int startup_time;

// State Variables
char ConnectionType[50];
char PossibleConnectionTypes[50];
char ConnectionStatus[20];
long int StartupTime;
char LastConnectionError[35];
long int AutoDisconnectTime;
long int IdleDisconnectTime;
long int WarnDisconnectDelay;
int RSIPAvailable;
int NATEnabled;
char ExternalIPAddress[IP_ADDRESS_LENGTH];
int PortMappingNumberOfEntries;
int PortMappingEnabled;
char RemoteHost[16];
long int SystemUpdateID;
char ChangedPortMapping[100];

char EthernetLinkStatus[12];

// Linked list for portmapping entries
struct portMap *pmlist_Head;
struct portMap *pmlist_Current;

// WanIPConnection Actions
int EventHandler(Upnp_EventType EventType, void *Event, void *Cookie);
int StateTableInit(char *descDocUrl);
int HandleSubscriptionRequest(struct Upnp_Subscription_Request *sr_event);
int HandleGetVarRequest(struct Upnp_State_Var_Request *gv_event);
int HandleActionRequest(struct Upnp_Action_Request *ca_event);

int GetConnectionTypeInfo(struct Upnp_Action_Request *ca_event);
int GetNATRSIPStatus(struct Upnp_Action_Request *ca_event);
int SetConnectionType(struct Upnp_Action_Request *ca_event);
int RequestConnection(struct Upnp_Action_Request *ca_event);
int GetTotal(struct Upnp_Action_Request *ca_event, stats_t stat);
int GetCommonLinkProperties(struct Upnp_Action_Request *ca_event);
int InvalidAction(struct Upnp_Action_Request *ca_event);
int GetStatusInfo(struct Upnp_Action_Request *ca_event);
int AddPortMapping(struct Upnp_Action_Request *ca_event);
int GetGenericPortMappingEntry(struct Upnp_Action_Request *ca_event);
int GetSpecificPortMappingEntry(struct Upnp_Action_Request *ca_event);
int GetExternalIPAddress(struct Upnp_Action_Request *ca_event);
int DeletePortMapping(struct Upnp_Action_Request *ca_event);
int DeletePortMappingRange(struct Upnp_Action_Request *ca_event);
int AddAnyPortMapping(struct Upnp_Action_Request *ca_event);
int RetrieveListOfPortmappings(struct Upnp_Action_Request *ca_event);
int AuthorizeControlPoint(struct Upnp_Action_Request *ca_event);

// WANEthernetLinkConfig Actions
int GetEthernetLinkStatus (struct Upnp_Action_Request *ca_event);

// Definitions for mapping expiration timer thread
#define THREAD_IDLE_TIME 5000
#define JOBS_PER_THREAD 10
#define MIN_THREADS 2
#define MAX_THREADS 12


int ExpirationTimerThreadInit(void);
int ExpirationTimerThreadShutdown(void);
int ScheduleMappingExpiration(struct portMap *mapping, char *DevUDN, char *ServiceID);
int CancelMappingExpiration(int eventId);
void DeleteAllPortMappings(void);
int AddNewPortMapping(struct Upnp_Action_Request *ca_event, char* new_enabled, int leaseDuration,
                     char* new_remote_host, char* new_external_port, char* new_internal_port,
                     char* new_protocol, char* new_internal_client, char* new_port_mapping_description);

int createEventUpdateTimer(void);
void UpdateEvents(void *input);
int EthernetLinkStatusEventing(IXML_Document *propSet);
int ExternalIPAddressEventing(IXML_Document *propSet);


// Definition for authorizing control point
#define CONTROL_POINT_AUTHORIZED    0

#endif //_GATEDEVICE_H
